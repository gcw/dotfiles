#!/usr/bin/env python3
# get_apikey_via_pysafeguard.py
#
# CLI (same as before):
#   python3 get_apikey_via_pysafeguard.py <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>
#
# Behavior:
#   - Uses PySafeguard with client certificate+key.
#   - Resolves the authenticated principal via Token/WhoAmI.
#   - Selects the first A2A registration owned by that principal (content[0]["Id"]).
#   - Enumerates RetrievableAccounts for that registration, finds <system_name>/<account_name>.
#   - Prints only the API key (JSON) and exits. No password retrieval here.

import sys, json
from pysafeguard import PySafeguardConnection, HttpMethods, Services

def jout(obj, code=0):
    print(json.dumps(obj), flush=True)
    sys.exit(code)

def jerr(msg, extra=None, code=1):
    out = {"error": msg, "found": False}
    if extra: out.update(extra)
    print(json.dumps(out), flush=True)
    sys.exit(code)

def get_json_or_die(resp, where):
    sc = getattr(resp, "status_code", None)
    try:
        resp.raise_for_status()
    except Exception:
        body = resp.text[:512] if hasattr(resp, "text") else ""
        jerr(f"{where}: HTTP {sc}", {"body": body})
    try:
        return resp.json()
    except Exception:
        jerr(f"{where}: non-JSON",
             {"content_type": resp.headers.get("Content-Type",""),
              "body": resp.text[:512]})

def name_from(obj, flat, nested, key):
    v = obj.get(flat)
    if v is not None:
        return v
    sub = obj.get(nested) or {}
    return sub.get(key)

def main(host, verify, cert_path, key_path, system_name, account_name):
    # Connect using cert+key (mTLS → STS → bearer handled by PySafeguard)
    conn = PySafeguardConnection(host, verify=verify)
    try:
        conn.connect_certificate(cert_path, key_path)
    except Exception as e:
        jerr("certificate connect failed", {"exception": str(e)})

    # Auth principal (exact endpoint; case-sensitive)
    try:
        r = conn.invoke(HttpMethods.GET, Services.CORE, "Token/WhoAmI")
    except Exception as e:
        jerr("Token/WhoAmI request_error", {"exception": str(e)})
    ident = get_json_or_die(r, "Token/WhoAmI")

    # Owner ID resolution — prefer same shapes your working script uses
    owner_id = (
        ident.get("RegistrationId")
        or (ident.get("Application") or {}).get("Id")
        or ident.get("ApplicationId")
        or ident.get("UserId")
        or ident.get("Id")
        or ident.get("ID")
    )
    if owner_id is None:
        jerr("unable to determine owner id", {"whoami_keys": list(ident.keys())})

    # First A2A registration owned by this principal (content[0]['Id'])
    try:
        r = conn.invoke(
            HttpMethods.GET, Services.CORE, "A2ARegistrations",
            query={"filter": f"Owner/Id eq {owner_id}", "limit": 1}
        )
    except Exception as e:
        jerr("A2ARegistrations request_error", {"exception": str(e)})
    content = get_json_or_die(r, "A2ARegistrations")
    if not isinstance(content, list) or not content:
        jerr("no A2A registration found for owner", {"owner_id": owner_id})

    reg = content[0]
    reg_id = reg.get("Id") or reg.get("ID")
    if reg_id is None:
        jerr("registration missing Id", {"registration": reg})

    # Enumerate retrievable accounts for that registration; find the target
    page, limit = 0, 100
    while True:
        try:
            rr = conn.invoke(
                HttpMethods.GET, Services.CORE,
                f"A2ARegistrations/{reg_id}/RetrievableAccounts",
                query={"page": page, "limit": limit}
            )
        except Exception as e:
            jerr("RetrievableAccounts request_error",
                 {"registration_id": reg_id, "page": page, "exception": str(e)})

        if getattr(rr, "status_code", 200) in (401, 403):
            jerr("RetrievableAccounts forbidden",
                 {"registration_id": reg_id, "code": rr.status_code, "body": rr.text[:200]})

        ras = get_json_or_die(rr, f"RetrievableAccounts reg={reg_id}")
        if not isinstance(ras, list) or not ras:
            break

        for ra in ras:
            asset_nm = name_from(ra, "AssetName", "Asset", "Name")
            acct_nm  = name_from(ra, "AccountName", "Account", "Name")
            if asset_nm == system_name and acct_nm == account_name:
                api_key = ra.get("ApiKey")
                if not api_key:
                    jerr("match found but ApiKey missing", {"registration_id": reg_id, "ra": ra})
                jout({
                    "api_key": api_key,
                    "found": True,
                    "registration": {"id": reg_id, "app_name": reg.get("AppName")},
                    "asset": asset_nm,
                    "account": acct_nm
                })
        page += 1

    jerr("no match for provided system/account",
         {"registration_id": reg_id, "system": system_name, "account": account_name})

if __name__ == "__main__":
    if len(sys.argv) != 7:
        jerr("Invalid arguments", {
            "usage": f"python {sys.argv[0]} <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>"
        })
    host, ca_arg, cert_path, key_path, system_name, account_name = sys.argv[1:7]
    verify = False if ca_arg.lower() == "false" else ca_arg
    main(host, verify, cert_path, key_path, system_name, account_name)

