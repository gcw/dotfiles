#!/usr/bin/env python3
# certkey_to_bearer_get_apikey_print_stdout.py
# CLI:
#   python3 certkey_to_bearer_get_apikey_print_stdout.py <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>

import sys, json
from pysafeguard import PySafeguardConnection, HttpMethods, Services, A2ATypes

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

def find_api_key_and_password(host, verify, cert, key, system_name, account_name):
    # 1) Connect with certificate (mTLS → STS → bearer handled by PySafeguard)
    conn = PySafeguardConnection(host, verify=verify)
    try:
        conn.connect_certificate(cert, key)
    except Exception as e:
        jerr("certificate connect failed", {"exception": str(e)})

    # 2) Retrieve authenticated identity (user/app) to get owner id
    try:
        r = conn.invoke(HttpMethods.GET, Services.CORE, "Token/WhoAmI")
    except Exception as e:
        jerr("whoami request_error", {"exception": str(e)})
    ident = get_json_or_die(r, "Token/WhoAmI")
    owner_id = (
        ident.get("Id") or ident.get("ID") or
        ident.get("UserId") or ident.get("ApplicationId") or ident.get("AppId")
    )
    if owner_id is None:
        jerr("unable to determine owner id from Token/WhoAmI", {"whoami_keys": list(ident.keys())})

    # 3) Get the registration id the working script picks (first match by Owner/Id)
    try:
        r = conn.invoke(
            HttpMethods.GET, Services.CORE, "A2ARegistrations",
            query={"filter": f"Owner/Id eq {owner_id}", "limit": 1}
        )
    except Exception as e:
        jerr("list registrations request_error", {"exception": str(e)})
    content = get_json_or_die(r, "A2ARegistrations")
    if not isinstance(content, list) or not content:
        jerr("no A2A registration found for owner", {"owner_id": owner_id})
    reg_id = content[0].get("Id") or content[0].get("ID")
    if reg_id is None:
        jerr("registration missing Id", {"registration": content[0]})

    # 4) Enumerate retrievable accounts under that registration; find system/account
    page, limit = 0, 100
    while True:
        try:
            rr = conn.invoke(
                HttpMethods.GET, Services.CORE,
                f"A2ARegistrations/{reg_id}/RetrievableAccounts",
                query={"page": page, "limit": limit}
            )
        except Exception as e:
            jerr("list retrievable accounts request_error",
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
                # 5) Use api_key to retrieve password via A2A
                try:
                    secret = PySafeguardConnection.a2a_get_credential(
                        host, api_key, cert, key, verify, A2ATypes.PASSWORD
                    )
                except Exception as e:
                    jerr("a2a retrieval failed", {"exception": str(e)})
                jout({
                    "api_key": api_key,
                    "password": secret,
                    "found": True,
                    "registration": {"id": reg_id, "app_name": content[0].get("AppName")},
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
    find_api_key_and_password(host, verify, cert_path, key_path, system_name, account_name)

