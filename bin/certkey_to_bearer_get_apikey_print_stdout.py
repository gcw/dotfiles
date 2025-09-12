#!/usr/bin/env python3
# certkey_to_bearer_get_apikey_print_stdout.py (auth-principal flow)
# Usage: python3 script.py <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>
# Always prints JSON to STDOUT with progress markers.

import sys, json, requests

# Progress/status JSON (always to STDOUT)
def status(stage, **kv):
    out = {"stage": stage, **kv}
    print(json.dumps(out), flush=True)

# Success / Error printers (to STDOUT)
def jout(obj, code=0):
    print(json.dumps(obj), flush=True)
    sys.exit(code)

def jerr(msg, extra=None, code=1):
    out = {"error": msg, "found": False}
    if extra:
        out.update(extra)
    print(json.dumps(out), flush=True)
    sys.exit(code)

# Strict HTTP + JSON handling with context
def get_json_or_die(r, where):
    sc = getattr(r, "status_code", None)
    try:
        r.raise_for_status()
    except Exception:
        body = r.text[:512] if hasattr(r, "text") else ""
        jerr(f"{where}: HTTP {sc}", {"body": body})
    try:
        return r.json()
    except Exception:
        jerr(f"{where}: non-JSON", {"content_type": r.headers.get("Content-Type",""), "body": r.text[:512]})

# Helper for schema variance
def name_from(obj, flat, nested, key):
    v = obj.get(flat)
    if v is not None:
        return v
    sub = obj.get(nested) or {}
    return sub.get(key)

# mTLS -> STS -> Bearer; return bearer AND login payload for id fields
def get_bearer_from_cert(host, cert_path, key_path, verify):
    status("rsts_request", host=host)
    r = requests.post(
        f"https://{host}/RSTS/oauth2/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "client_credentials", "scope": "rsts:sts:primaryproviderid:certificate"},
        cert=(cert_path, key_path),
        verify=verify,
        timeout=10,
    )
    sts = get_json_or_die(r, "RSTS token")
    access_token = sts.get("access_token")
    if not access_token:
        jerr("RSTS token missing access_token", sts)
    status("rsts_ok")

    status("exchange_request")
    r = requests.post(
        f"https://{host}/service/core/v4/Token/LoginResponse",
        json={"StsAccessToken": access_token},
        verify=verify,
        timeout=10,
    )
    login = get_json_or_die(r, "Core token exchange")
    bearer = login.get("UserToken") or login.get("user_token")
    if not bearer:
        jerr("Token exchange response missing UserToken", login)
    status("exchange_ok", login_keys=list(login.keys()))
    return bearer, login

# Attempt to identify the authenticated principal and a registration ID
# Tries multiple endpoints that commonly expose the current identity and app/registration

def get_auth_identity(host, bearer, verify):
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {bearer}", "Accept": "application/json"})

    # Try common self endpoints in order; return first JSON object
    candidates = [
        ("core_me", f"https://{host}/service/core/v4/Me"),
        ("core_whoami", f"https://{host}/service/core/v4/WhoAmI"),
        ("token_whoami", f"https://{host}/service/core/v4/Token/WhoAmI"),
    ]
    for tag, url in candidates:
        status("whoami_request", endpoint=tag)
        r = s.get(url, verify=verify, timeout=10)
        if r.status_code == 404:
            status("whoami_404", endpoint=tag)
            continue
        if r.status_code in (401,403):
            status("whoami_forbidden", endpoint=tag, code=r.status_code)
            continue
        try:
            obj = get_json_or_die(r, f"{tag}")
        except SystemExit:
            # get_json_or_die already emitted an error
            raise
        if isinstance(obj, dict):
            status("whoami_ok", endpoint=tag, keys=list(obj.keys()))
            return obj
    jerr("Unable to determine authenticated identity via self endpoints")

# Given an identity object, try to resolve the registration id

def resolve_registration_id(host, bearer, verify, ident):
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {bearer}", "Accept": "application/json"})

    # Potential id fields to try
    id_fields = ["Id", "ID", "UserId", "AppId", "ApplicationId", "RegistrationId"]
    ids = [ident.get(k) for k in id_fields if ident.get(k) is not None]

    # 1) Try direct fetch assuming identity id == registration id
    for rid in ids:
        status("try_reg_by_id", rid=rid)
        r = s.get(f"https://{host}/service/core/v4/A2ARegistrations/{rid}", verify=verify, timeout=10)
        if r.status_code == 200:
            reg = get_json_or_die(r, "A2ARegistrations/{id}")
            if isinstance(reg, dict) and (reg.get("Id") or reg.get("ID")):
                status("reg_by_id_ok", rid=rid)
                return reg.get("Id") or reg.get("ID")
        else:
            status("reg_by_id_fail", rid=rid, code=r.status_code)

    # 2) Try registrations by owner/application filters (if listing allowed)
    filters = []
    if ident.get("Id"):
        filters.append(f"Owner/Id eq {ident['Id']}")
        filters.append(f"RegisteredBy/Id eq {ident['Id']}")
    if ident.get("UserId"):
        filters.append(f"Owner/Id eq {ident['UserId']}")
        filters.append(f"RegisteredBy/Id eq {ident['UserId']}")
    if ident.get("AppId"):
        filters.append(f"Application/Id eq {ident['AppId']}")
    if ident.get("ApplicationId"):
        filters.append(f"Application/Id eq {ident['ApplicationId']}")

    for f in filters:
        status("regs_filter_try", filter=f)
        r = s.get(
            f"https://{host}/service/core/v4/A2ARegistrations",
            params={"filter": f, "limit": 1},
            verify=verify,
            timeout=10,
        )
        if r.status_code in (401,403):
            status("regs_filter_forbidden", code=r.status_code)
            continue
        regs = get_json_or_die(r, "A2ARegistrations filtered")
        if isinstance(regs, list) and regs:
            status("regs_filter_ok")
            rid = regs[0].get("Id") or regs[0].get("ID")
            if rid:
                return rid

    jerr("Could not resolve A2A registration id from authenticated identity")

# Enumerate retrievable accounts under a specific registration id and match system/account

def find_api_key_for_registration(host, bearer, verify, reg_id, system_name, account_name):
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {bearer}", "Accept": "application/json"})

    r_page, limit = 0, 100
    while True:
        status("list_ra", reg_id=reg_id, r_page=r_page)
        rr = s.get(
            f"https://{host}/service/core/v4/A2ARegistrations/{reg_id}/RetrievableAccounts",
            params={"page": r_page, "limit": limit},
            verify=verify,
            timeout=10,
        )
        if rr.status_code in (401,403):
            jerr("RetrievableAccounts forbidden", {"reg_id": reg_id, "code": rr.status_code, "body": rr.text[:200]})
        ras = get_json_or_die(rr, f"RetrievableAccounts reg={reg_id}")
        if not isinstance(ras, list) or not ras:
            break
        for ra in ras:
            asset_nm = name_from(ra, "AssetName", "Asset", "Name")
            acct_nm  = name_from(ra, "AccountName", "Account", "Name")
            if asset_nm == system_name and acct_nm == account_name:
                api_key = ra.get("ApiKey")
                if not api_key:
                    jerr("Match found but ApiKey missing", {"registration_id": reg_id, "ra": ra})
                jout({
                    "api_key": api_key,
                    "found": True,
                    "registration": {"id": reg_id},
                    "asset": asset_nm,
                    "account": acct_nm
                })
        r_page += 1

    jerr(f"No API key found for system='{system_name}' account='{account_name}' under registration {reg_id}")

# Orchestrate the flow the user requested

def run_flow(host, verify, cert, key, system_name, account_name):
    status("start")
    bearer, login = get_bearer_from_cert(host, cert, key, verify)
    ident = get_auth_identity(host, bearer, verify)
    reg_id = resolve_registration_id(host, bearer, verify, ident)
    find_api_key_for_registration(host, bearer, verify, reg_id, system_name, account_name)

if __name__ == "__main__":
    try:
        if len(sys.argv) != 7:
            jerr("Invalid arguments", {"usage": f"python {sys.argv[0]} <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>"})
        host, ca_arg, cert, key, system_name, account_name = sys.argv[1:7]
        verify = False if ca_arg.lower() == "false" else ca_arg
        status("parsed", host=host, system=system_name, account=account_name)
        run_flow(host, verify, cert, key, system_name, account_name)
    except Exception as e:
        jerr("unhandled", {"exception": str(e)})

