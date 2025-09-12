#!/usr/bin/env python
# certkey_to_bearer_get_apikey_print_stdout.py (debugging edition)
# Usage: script.py <host> <ca_bundle_or_False> <cert.pem> <key.pem> <domain_name> <account_name>
# Always prints JSON to STDOUT. Adds progress markers so you see output immediately.

import sys, json, requests, time

# Progress/status JSON (always to STDOUT)
def status(stage, **kv):
    out = {"stage": stage, **kv}
    print(json.dumps(out), flush=True)

# Unified success
def jout(obj, code=0):
    print(json.dumps(obj), flush=True)
    sys.exit(code)

# Unified error (to STDOUT, JSON)
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

# mTLS -> STS -> Bearer
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
    status("exchange_ok")
    return bearer

# Enumerate and match
def find_api_key_with_bearer(host, bearer, verify, domain_name, account_name):
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {bearer}"})
    page, limit = 0, 100

    while True:
        status("list_regs", page=page)
        r = s.get(
            f"https://{host}/service/core/v4/A2ARegistrations",
            params={"page": page, "limit": limit},
            verify=verify,
            timeout=10,
        )
        regs = get_json_or_die(r, "A2ARegistrations")
        if not isinstance(regs, list) or not regs:
            break

        for reg in regs:
            reg_id = reg.get("Id") or reg.get("ID") or reg.get("id")
            if not reg_id:
                continue

            r_page = 0
            while True:
                status("list_ra", reg_id=reg_id, r_page=r_page)
                rr = s.get(
                    f"https://{host}/service/core/v4/A2ARegistrations/{reg_id}/RetrievableAccounts",
                    params={"page": r_page, "limit": limit},
                    verify=verify,
                    timeout=10,
                )
                ras = get_json_or_die(rr, f"RetrievableAccounts reg={reg_id}")
                if not isinstance(ras, list) or not ras:
                    break

                for ra in ras:
                    asset_nm = name_from(ra, "AssetName", "Asset", "Name")
                    acct_nm  = name_from(ra, "AccountName", "Account", "Name")
                    if asset_nm == domain_name and acct_nm == account_name:
                        api_key = ra.get("ApiKey")
                        if not api_key:
                            jerr("Match found but ApiKey missing", {"registration": reg, "ra": ra})
                        jout({
                            "api_key": api_key,
                            "found": True,
                            "registration": {"id": reg_id, "app_name": reg.get("AppName")},
                            "asset": asset_nm,
                            "account": acct_nm
                        })
                r_page += 1
        page += 1

    jerr(f"No API key found for domain='{domain_name}' account='{account_name}'")

if __name__ == "__main__":
    status("start")
    try:
        if len(sys.argv) != 7:
            jerr("Invalid arguments", {"usage": f"python {sys.argv[0]} <host> <ca_bundle_or_False> <cert.pem> <key.pem> <domain_name> <account_name>"})
        host, ca_arg, cert, key, domain, account = sys.argv[1:7]
        verify = False if ca_arg.lower() == "false" else ca_arg
        status("parsed", host=host, domain=domain, account=account)

        bearer = get_bearer_from_cert(host, cert, key, verify)
        find_api_key_with_bearer(host, bearer, verify, domain, account)
    except Exception as e:
        jerr("unhandled", {"exception": str(e)})

