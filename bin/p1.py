# SPDX-License-Identifier: MIT
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ansible.module_utils.urls import open_url
import json

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        # required kwargs
        host   = kwargs.get("host")
        cert   = kwargs.get("cert")
        key    = kwargs.get("key")
        cacert = kwargs.get("cacert")     # path to CA bundle
        system = kwargs.get("system")     # system_name to match
        account = kwargs.get("account")   # account_name to match

        if not all([host, cert, key, cacert, system, account]):
            raise AnsibleError("required: host, cert, key, cacert, system, account")

        validate_certs = kwargs.get("validate_certs", True)
        reg_index = int(kwargs.get("registration_index", 0))
        return_format = kwargs.get("return", "api_key")  # 'api_key'|'dict'

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        def _get_json(url):
            try:
                r = open_url(
                    url,
                    method="GET",
                    headers=headers,
                    client_cert=cert,
                    client_key=key,
                    validate_certs=validate_certs,
                    ca_path=cacert,
                    follow_redirects="all",
                    timeout=30,
                )
                raw = r.read()
            except Exception as e:
                raise AnsibleError(f"GET {url} failed: {e}")

            try:
                return json.loads(raw)
            except Exception:
                raise AnsibleError(f"Non-JSON from {url}: {raw[:256]!r}")

        base = f"https://{host}/service/core/v4"

        # 1) list registrations, take content[reg_index]['Id']
        regs = _get_json(f"{base}/A2ARegistrations")
        if not isinstance(regs, list) or not regs:
            raise AnsibleError("A2ARegistrations returned empty list")

        try:
            reg = regs[reg_index]
        except IndexError:
            raise AnsibleError(f"registration_index {reg_index} out of range (len={len(regs)})")

        reg_id = reg.get("Id") or reg.get("ID")
        if reg_id is None:
            raise AnsibleError(f"registration missing Id: {reg}")

        # 2) list retrievable accounts under that registration
        api_key = None
        page, limit = 0, 200
        while True:
            ras = _get_json(f"{base}/A2ARegistrations/{reg_id}/RetrievableAccounts?page={page}&limit={limit}")
            if not isinstance(ras, list) or not ras:
                break
            for ra in ras:
                asset_nm  = ra.get("AssetName") or (ra.get("Asset") or {}).get("Name")
                account_nm = ra.get("AccountName") or (ra.get("Account") or {}).get("Name")
                if asset_nm == system and account_nm == account:
                    api_key = ra.get("ApiKey")
                    if not api_key:
                        raise AnsibleError(f"match found but no ApiKey in {ra}")
                    if return_format == "dict":
                        return [{
                            "api_key": api_key,
                            "registration_id": reg_id,
                            "app_name": reg.get("AppName"),
                            "asset": asset_nm,
                            "account": account_nm
                        }]
                    return [api_key]
            page += 1

        raise AnsibleError(f"No ApiKey match for system='{system}' account='{account}' (registration_id={reg_id})")

