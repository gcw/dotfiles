#!/usr/bin/env python3
# get_apikey_via_pysafeguard.py
# CLI (unchanged):
#   python3 get_apikey_via_pysafeguard.py <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>
#
# This version resolves the correct A2A Registration Id by trying, in order:
#   1) Token/WhoAmI -> RegistrationId (direct fetch)
#   2) Token/WhoAmI -> Application.Id (filter A2ARegistrations by Application/Id)
#   3) Token/WhoAmI -> Owner Id (Id/UserId) (filter A2ARegistrations by Owner/Id)
# Optional override: env REG_ID=<numeric id>
#
# Prints a single JSON object to stdout. On success: {"api_key": "...", "registration": {"id": ...,"source": "..."} ...}

import os, sys, json
from pysafeguard import PySafeguardConnection, HttpMethods, Services

def out(obj, code=0):
    print(json.dumps(obj), flush=True); sys.exit(code)

def err(msg, extra=None, code=1):
    d = {"error": msg, "found": False}
    if extra: d.update(extra)
    print(json.dumps(d), flush=True); sys.exit(code)

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

def try_get_registration_by_id(conn, rid):
    try:
        r = conn.invoke(HttpMethods.GET, Services.CORE, f"A2ARegistrations/{rid}")
    except Exception:
        return None
    if getattr(r, "status_code", 0) != 200:
        return None
    reg = j(r, f"A2ARegistrations/{rid}")
    if isinstance(reg, dict) and (reg.get("Id") or reg.get("ID")):
        return reg
    return None

def try_get_registration_by_filter(conn, flt):
    try:
        r = conn.invoke(HttpMethods.GET, Services.CORE, "A2ARegistrations", query={"filter": flt, "limit": 5})
    except Exception:
        return None
    if getattr(r, "status_code", 0) in (401, 403):
        return None
    regs = j(r, "A2ARegistrations(filter)")
    if isinstance(regs, list) and regs:
        return regs[0]
    return None

def determine_registration(conn, whoami):
    # 0) env override
    env_rid = os.environ.get("REG_ID")
    if env_rid:
        reg = try_get_registration_by_id(conn, env_rid)
        if reg: return reg, "env(REG_ID)"

    # 1) direct RegistrationId from WhoAmI
    reg_id = whoami.get("RegistrationId")
    if reg_id:
        reg = try_get_registration_by_id(conn, reg_id)
        if reg: return reg, "Token/WhoAmI.RegistrationId"

    # 2) Application.Id
    app_id = (whoami.get("Application") or {}).get("Id") or whoami.get("ApplicationId") or whoami.get("AppId")
    if app_id:
        reg = try_get_registration_by_filter(conn, f"Application/Id eq {app_id}")
        if reg: return reg, "Application/Id"

    # 3) Owner Id (user/principal)
    owner_id = whoami.get("Id") or whoami.get("UserId") or whoami.get("ID")
    if owner_id:
        reg = try_get_registration_by_filter(conn, f"Owner/Id eq {owner_id}")
        if reg: return reg, "Owner/Id"

    return None, None

def main(host, verify, cert_path, key_path, system_name, account_name):
    conn = PySafeguardConnection(host, verify=verify)
    try:
        conn.connect_certificate(cert_path, key_path)
    except Exception as e:
        err("certificate connect failed", {"exception": str(e)})

    # WhoAmI (case-sensitive)
    try:
        r = conn.invoke(HttpMethods.GET, Services.CORE, "Token/WhoAmI")
    except Exception as e:
        err("Token/WhoAmI request_error", {"exception": str(e)})
    whoami = j(r, "Token/WhoAmI")

    reg, source = determine_registration(conn, whoami)
    if not reg:
        err("unable to resolve A2A registration", {"whoami_keys": list(whoami.keys())})
    reg_id = reg.get("Id") or reg.get("ID")

    # Enumerate retrievable accounts under the resolved registration; find system/account
    page, limit = 0, 100
    while True:
        try:
            rr = conn.invoke(
                HttpMethods.GET, Services.CORE,
                f"A2ARegistrations/{reg_id}/RetrievableAccounts",
                query={"page": page, "limit": limit}
            )
        except Exception as e:
            err("RetrievableAccounts request_error",
                {"registration_id": reg_id, "page": page, "exception": str(e)})

        if getattr(rr, "status_code", 200) in (401, 403):
            err("RetrievableAccounts forbidden",
                {"registration_id": reg_id, "code": rr.status_code, "body": rr.text[:200]})

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
                    "registration": {"id": reg_id, "source": source, "app_name": reg.get("AppName")},
                    "asset": asset_nm,
                    "account": acct_nm
                })
        page += 1

    err("no match for provided system/account",
        {"registration_id": reg_id, "system": system_name, "account": account_name, "id_source": source})

if __name__ == "__main__":
    if len(sys.argv) != 7:
        err("Invalid arguments", {
            "usage": f"python {sys.argv[0]} <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>"
        })
    host, ca_arg, cert, key, system_name, account_name = sys.argv[1:7]
    verify = False if ca_arg.lower() == "false" else ca_arg
    main(host, verify, cert, key, system_name, account_name)

