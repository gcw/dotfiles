#!/usr/bin/env python3
# get_apikey_via_pysafeguard.py
#
# EXACT workflow match to your working script:
#  1) GET /service/core/v4/A2ARegistrations
#  2) id = content[0]["Id"]
#  3) GET /service/core/v4/A2ARegistrations/{id}/RetrievableAccounts
#  4) Find (system_name, account_name) → ApiKey
#
# CLI (unchanged):
#   python3 get_apikey_via_pysafeguard.py <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>

import sys, json
from pysafeguard import PySafeguardConnection, HttpMethods, Services

def out(d, code=0):
    print(json.dumps(d), flush=True)
    sys.exit(code)

def err(msg, extra=None, code=1):
    d = {"error": msg, "found": False}
    if extra: d.update(extra)
    print(json.dumps(d), flush=True)
    sys.exit(code)

def j(resp, where):
    sc = getattr(resp, "status_code", None)
    try:
        resp.raise_for_status()
    except Exception:
        err(f"{where}: HTTP {sc}", {"body": getattr(resp, "text", "")[:512]})
    try:
        return resp.json()
    except Exception:
        err(f"{where}: non-JSON", {
            "content_type": resp.headers.get("Content-Type",""),
            "body": getattr(resp, "text", "")[:512]
        })

def name_from(o, flat, nested, key):
    v = o.get(flat)
    if v is not None: return v
    return (o.get(nested) or {}).get(key)

def main(host, verify, cert_path, key_path, system_name, account_name):
    conn = PySafeguardConnection(host, verify=verify)
    try:
        conn.connect_certificate(cert_path, key_path)
    except Exception as e:
        err("certificate connect failed", {"exception": str(e)})

    # 1) First call: list registrations (no filters), like your curl
    try:
        r = conn.invoke(HttpMethods.GET, Services.CORE, "A2ARegistrations")
    except Exception as e:
        err("A2ARegistrations request_error", {"exception": str(e)})
    content = j(r, "A2ARegistrations")
    if not isinstance(content, list) or not content:
        err("no registrations returned")

    # 2) Take the first object's Id (exactly: content[0]['Id'])
    reg_id = content[0].get("Id") or content[0].get("ID")
    if reg_id is None:
        err("first registration missing Id", {"first_object": content[0]})

    # 3) Second call: list retrievable accounts under that registration
    page, limit = 0, 200
    while True:
        try:
            rr = conn.invoke(
                HttpMethods.GET, Services.CORE,
                f"A2ARegistrations/{reg_id}/RetrievableAccounts",
                query={"page": page, "limit": limit}
            )
        except Exception as e:
            err("RetrievableAccounts request_error", {"registration_id": reg_id, "page": page, "exception": str(e)})

        ras = j(rr, f"RetrievableAccounts reg={reg_id}")
        if not isinstance(ras, list) or not ras:
            break

        for ra in ras:
            asset_nm = name_from(ra, "AssetName", "Asset", "Name")
            acct_nm  = name_from(ra, "AccountName", "Account", "Name")
            if asset_nm == system_name and acct_nm == account_name:
                api_key = ra.get("ApiKey")
                if not api_key:
                    err("match found but ApiKey missing", {"registration_id": reg_id, "ra": ra})
                out({
                    "api_key": api_key,
                    "found": True,
                    "registration": {"id": reg_id, "app_name": content[0].get("AppName")},
                    "asset": asset_nm,
                    "account": acct_nm
                })
        page += 1

    err("no match for provided system/account",
        {"registration_id": reg_id, "system": system_name, "account": account_name})

if __name__ == "__main__":
    if len(sys.argv) != 7:
        err("Invalid arguments", {
            "usage": f"python {sys.argv[0]} <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>"
        })
    host, ca_arg, cert, key, system_name, account = sys.argv[1:7]
    verify = False if ca_arg.lower() == "false" else ca_arg
    main(host, verify, cert, key, system_name, account)

