#!/usr/bin/env python
# certkey_to_bearer_get_apikey_print_stdout.py
# Usage:
#   python certkey_to_bearer_get_apikey_print_stdout.py <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>
#
# Behavior:
#   - Uses PySafeguard with client certificate + key (mTLS) to obtain a bearer (vendor flow).
#   - Lists Core A2A registrations, then each registration’s RetrievableAccounts.
#   - Finds the entry matching <system_name>/<account_name>, extracts ApiKey.
#   - Uses that ApiKey to perform A2A password retrieval.
#   - Always prints JSON to STDOUT (progress + final result).

import sys
import json
from pysafeguard import PySafeguardConnection, HttpMethods, Services, A2ATypes

# ---------- JSON printers (stdout) ----------

def status(stage, **kv):
    print(json.dumps({"stage": stage, **kv}), flush=True)

def jout(obj, code=0):
    print(json.dumps(obj), flush=True)
    sys.exit(code)

def jerr(msg, extra=None, code=1):
    out = {"error": msg, "found": False}
    if extra:
        out.update(extra)
    print(json.dumps(out), flush=True)
    sys.exit(code)

# ---------- helpers ----------

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
             {"content_type": resp.headers.get("Content-Type", ""), "body": resp.text[:512]})

def name_from(obj, flat, nested, key):
    v = obj.get(flat)
    if v is not None:
        return v
    sub = obj.get(nested) or {}
    return sub.get(key)

# ---------- connection (vendor-approved) ----------

def get_connection_from_cert(host, cert_path, key_path, verify):
    status("rsts_request", host=host)
    conn = PySafeguardConnection(host, verify=verify)
    conn.connect_certificate(cert_path, key_path)  # performs mTLS → STS → bearer internally
    status("exchange_ok", login_keys=["(managed by PySafeguard)"])
    return conn

# ---------- main flow ----------

def find_api_key_and_password(host, verify, cert, key, system_name, account_name):
    status("start")
    conn = get_connection_from_cert(host, cert, key, verify)

    # 1) List registrations (paged)
    page, limit = 0, 100
    while True:
        status("list_regs", page=page)
        try:
            r = conn.invoke(HttpMethods.GET, Services.CORE, "A2ARegistrations",
                            query={"page": page, "limit": limit})
        except Exception as e:
            jerr("list_regs request_error", {"page": page, "exception": str(e)})
        regs = get_json_or_die(r, "A2ARegistrations")
        if not isinstance(regs, list) or not regs:
            break

        # 2) For each registration, enumerate retrievable accounts (paged)
        for reg in regs:
            reg_id = reg.get("Id") or reg.get("ID") or reg.get("id")
            if not reg_id:
                continue

            r_page = 0
            while True:
                status("list_ra", reg_id=reg_id, r_page=r_page)
                try:
                    rr = conn.invoke(
                        HttpMethods.GET,
                        Services.CORE,
                        f"A2ARegistrations/{reg_id}/RetrievableAccounts",
                        query={"page": r_page, "limit": limit},
                    )
                except Exception as e:
                    jerr("list_ra request_error", {"reg_id": reg_id, "r_page": r_page, "exception": str(e)})

                # If appliance blocks access, return the authorization detail
                if getattr(rr, "status_code", 200) in (401, 403):
                    jerr("RetrievableAccounts forbidden",
                         {"reg_id": reg_id, "code": rr.status_code, "body": rr.text[:200]})

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

                        # 3) Use ApiKey to retrieve the secret (A2A)
                        status("a2a_request")
                        try:
                            secret = PySafeguardConnection.a2a_get_credential(
                                host, api_key, cert, key, verify, A2ATypes.PASSWORD
                            )
                        except Exception as e:
                            jerr("a2a retrieval failed", {"exception": str(e)})
                        status("a2a_ok")

                        jout({
                            "api_key": api_key,
                            "password": secret,
                            "found": True,
                            "registration": {"id": reg_id, "app_name": reg.get("AppName")},
                            "asset": asset_nm,
                            "account": acct_nm
                        })
                r_page += 1
        page += 1

    jerr(f"No match for system='{system_name}' account='{account_name}'")

# ---------- entry ----------

if __name__ == "__main__":
    if len(sys.argv) != 7:
        jerr("Invalid arguments", {
            "usage": f"python {sys.argv[0]} <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>"
        })
    host, ca_arg, cert, key, system_name, account_name = sys.argv[1:7]
    verify = False if ca_arg.lower() == "false" else ca_arg

    status("parsed", host=host, system=system_name, account=account_name)
    find_api_key_and_password(host, verify, cert, key, system_name, account_name)

