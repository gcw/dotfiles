#!/usr/bin/env python3
# get_apikey_wrapper.py
#
# CLI (same as your built script):
#   python3 get_apikey_wrapper.py <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>
#
# This is a thin wrapper that imports YOUR working library (from the images)
# and calls a function to return the API key. By default it looks for:
#   module:  safeguard_lib        (override with env SAFE_MODULE or SAFE_MODULE_PATH)
#   func:    get_api_key          (override with env SAFE_FUNC)
#
# Expected callable signature in your library:
#   get_api_key(host, verify, cert_path, key_path, system_name, account_name) -> str
#
# Always prints a single JSON object to STDOUT.

import os
import sys
import json
import importlib
import importlib.util

def jout(obj, code=0):
    print(json.dumps(obj), flush=True)
    sys.exit(code)

def jerr(msg, extra=None, code=1):
    out = {"error": msg, "found": False}
    if extra:
        out.update(extra)
    print(json.dumps(out), flush=True)
    sys.exit(code)

def load_module():
    mod_name = os.environ.get("SAFE_MODULE", "safeguard_lib")
    mod_path = os.environ.get("SAFE_MODULE_PATH", "").strip()

    if mod_path:
        spec = importlib.util.spec_from_file_location(mod_name, mod_path)
        if spec is None or spec.loader is None:
            jerr("failed to load module from SAFE_MODULE_PATH", {"SAFE_MODULE_PATH": mod_path})
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            jerr("exception while importing SAFE_MODULE_PATH", {"exception": str(e), "SAFE_MODULE_PATH": mod_path})
        return mod

    try:
        return importlib.import_module(mod_name)
    except Exception as e:
        jerr("exception while importing SAFE_MODULE", {"exception": str(e), "SAFE_MODULE": mod_name})

def main():
    if len(sys.argv) != 7:
        jerr("Invalid arguments", {
            "usage": f"python {sys.argv[0]} <host> <ca_bundle_or_False> <cert.pem> <key.pem> <system_name> <account_name>"
        })

    host, ca_arg, cert, key, system_name, account_name = sys.argv[1:7]
    verify = False if ca_arg.lower() == "false" else ca_arg

    mod = load_module()
    func_name = os.environ.get("SAFE_FUNC", "get_api_key")

    if not hasattr(mod, func_name):
        # Helpful introspection to show available callables
        exported = sorted([n for n in dir(mod) if not n.startswith("_")])
        jerr("function not found in module", {
            "SAFE_FUNC": func_name,
            "available": exported[:50]  # cap to keep output small
        })

    func = getattr(mod, func_name)

    try:
        api_key = func(host, verify, cert, key, system_name, account_name)
    except TypeError as te:
        # Signature mismatch—show caller expectation
        jerr("call signature error", {
            "exception": str(te),
            "expected_signature": "get_api_key(host, verify, cert_path, key_path, system_name, account_name)"
        })
    except Exception as e:
        jerr("library raised exception", {"exception": str(e)})

    if not api_key:
        jerr("library returned empty api_key")

    jout({"api_key": api_key, "found": True,
          "host": host, "system": system_name, "account": account_name})

if __name__ == "__main__":
    main()

