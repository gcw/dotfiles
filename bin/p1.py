# collections path or project ansible.cfg lookup_plugins path
# file: spp_apikey.py

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ansible.module_utils.urls import open_url
import json

DOCUMENTATION = r"""
lookup: spp_apikey
author:
  - Your Name (@you)
short_description: Fetch Safeguard A2A ApiKey for a system/account via client-certificate auth
description:
  - Performs two HTTPS GETs against Safeguard Core:
  - 1) GET /service/core/v4/A2ARegistrations (takes the first item, or an index you specify)
  - 2) GET /service/core/v4/A2ARegistrations/<Id>/RetrievableAccounts
  - Finds the entry matching (system, account) and returns its ApiKey.
options:
  host:
    description: Safeguard hostname or IP.
    type: str
    required: true
  cert:
    description: Path to client certificate (PEM).
    type: str
    required: true
  key:
    description: Path to client private key (PEM).
    type: str
    required: true
  cacert:
    description: Path to CA bundle for TLS validation.
    type: str
    required: true
  system:
    description: System name to match (a.k.a. AssetName).
    type: str
    required: true
  account:
    description: Account name to match (a.k.a. AccountName).
    type: str
    required: true
  validate_certs:
    description: Validate TLS certs.
    type: bool
    default: true
  registration_index:
    description: Index into the registrations list to select the Id (content[index].Id).
    type: int
    default: 0
  return:
    description: Return format; C(api_key) returns the key (string), C(dict) returns a dict.
    type: str
    choices: [api_key, dict]
    default: api_key
notes:
  - Runs on the controller (lookup).
  - Requires controller-side network access to Safeguard.
"""

EXAMPLES = r"""
- name: Resolve ApiKey (short name)
  set_fact:
    spp_api_key: >-
      {{ lookup('spp_apikey',
                host=spp_host, cert=cert, key=key, cacert=cacert,
                system=system_name, account=account_name) }}

- name: Resolve ApiKey (FQCN inside a collection)
  set_fact:
    spp_api_key: >-
      {{ lookup('oneidentity.safeguardcollection.spp_apikey',
                host=spp_host, cert=cert, key=key, cacert=cacert,
                system=system_name, account=account_name,
                registration_index=0) }}
"""

RETURN = r"""
_raw:
  description: ApiKey string when return=api_key.
  type: str
dict:
  description: Returned when return=dict is set.
  type: dict
  contains:
    api_key:
      description: The A2A ApiKey.
      type: str
    registration_id:
      description: Registration Id used for the second request.
      type: int
    app_name:
      description: AppName of the selected registration, if present.
      type: str
    asset:
      description: Matched AssetName.
      type: str
    account:
      description: Matched AccountName.
      type: str
"""

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        host   = kwargs.get("host")
        cert   = kwargs.get("cert")
        key    = kwargs.get("key")
        cacert = kwargs.get("cacert")
        system = kwargs.get("system")
        account= kwargs.get("account")
        if not all([host, cert, key, cacert, system, account]):
            raise AnsibleError("required: host, cert, key, cacert, system, account")

        validate_certs = kwargs.get("validate_certs", True)
        reg_index = int(kwargs.get("registration_index", 0))
        retfmt = kwargs.get("return", "api_key")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        base = f"https://{host}/service/core/v4"

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
                preview = (raw[:256].decode("utf-8", "ignore") if isinstance(raw, (bytes, bytearray)) else str(raw))[:256]
                raise AnsibleError(f"Non-JSON from {url}: {preview!r}")

        # 1) registrations
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

        # 2) retrievable accounts
        api_key = None
        page, limit = 0, 200
        while True:
            ras = _get_json(f"{base}/A2ARegistrations/{reg_id}/RetrievableAccounts?page={page}&limit={limit}")
            if not isinstance(ras, list) or not ras:
                break
            for ra in ras:
                asset_nm  = ra.get("AssetName") or (ra.get("Asset") or {}).get("Name")
                account_nm= ra.get("AccountName") or (ra.get("Account") or {}).get("Name")
                if asset_nm == system and account_nm == account:
                    api_key = ra.get("ApiKey")
                    if not api_key:
                        raise AnsibleError(f"match found but ApiKey missing: {ra}")
                    if retfmt == "dict":
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

