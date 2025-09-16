# spp_apikey.py  — Ansible lookup plugin
# Fetch Safeguard A2A ApiKey using client-certificate auth.
#
# - Expands ~ and $VARS in file paths
# - Verifies files exist and are non-empty
# - Passes only valid args to open_url() (supports combined cert+key PEM)

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ansible.module_utils.urls import open_url
import os, json

DOCUMENTATION = r"""
lookup: spp_apikey
author:
  - Your Name
short_description: Fetch Safeguard A2A ApiKey for a system/account using client-certificate auth
description:
  - Performs two HTTPS GETs against Safeguard Core using client certificate authentication.
  - First request lists registrations and selects one by index.
  - Second request lists retrievable accounts for that registration and finds the matching system/account.
  - Returns the ApiKey for that match.
options:
  host:
    description: Safeguard hostname or IP address (no scheme).
    type: str
    required: true
  cert:
    description: Path to client certificate (PEM). Ignored if C(combined_cert) is provided.
    type: str
    required: false
  key:
    description: Path to client private key (PEM). Ignored if C(combined_cert) is provided.
    type: str
    required: false
  combined_cert:
    description: Path to a single PEM containing certificate followed by unencrypted private key.
    type: str
    required: false
  cacert:
    description: Path to CA bundle used for HTTPS server certificate validation.
    type: str
    required: true
  system:
    description: System name (AssetName) to match in the retrievable accounts list.
    type: str
    required: true
  account:
    description: Account name (AccountName) to match in the retrievable accounts list.
    type: str
    required: true
  validate_certs:
    description: Whether to validate the HTTPS server certificate.
    type: bool
    default: true
  registration_index:
    description: Zero-based index into the registrations list (selects content[registration_index].Id).
    type: int
    default: 0
  return_format:
    description: Output format; C(api_key) returns only the ApiKey string, C(dict) returns a metadata dict.
    type: str
    choices: [api_key, dict]
    default: api_key
notes:
  - Runs on the Ansible controller.
  - The controller must have network access to the Safeguard host.
"""

EXAMPLES = r"""
- name: Get ApiKey as string
  set_fact:
    spp_api_key: >-
      {{ lookup('spp_apikey',
                host=spp_host, cacert=cacert,
                combined_cert=combined_pem,    # OR cert=cert, key=key
                system=system_name, account=account_name) }}

- name: Get ApiKey with metadata dict
  set_fact:
    spp_info: >-
      {{ lookup('spp_apikey',
                host=spp_host, cacert=cacert,
                cert=cert, key=key,            # separate files
                system=system_name, account=account_name,
                return_format='dict') }}
"""

RETURN = r"""
_raw:
  description: The ApiKey string (when return_format=api_key).
  type: str
dict:
  description: Returned when return_format=dict is used; includes ApiKey and metadata.
  type: dict
  contains:
    api_key:
      description: The A2A ApiKey associated with the matched system/account.
      type: str
    registration_id:
      description: The registration Id used for the retrievable accounts query.
      type: int
    app_name:
      description: The AppName field from the chosen registration, if present.
      type: str
    asset:
      description: The matched AssetName.
      type: str
    account:
      description: The matched AccountName.
      type: str
"""

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        host        = kwargs.get("host")
        cacert      = kwargs.get("cacert")
        cert        = kwargs.get("cert")
        key         = kwargs.get("key")
        combined    = kwargs.get("combined_cert")
        system      = kwargs.get("system")
        account     = kwargs.get("account")
        validate    = kwargs.get("validate_certs", True)
        reg_index   = int(kwargs.get("registration_index", 0))
        retfmt      = kwargs.get("return_format", "api_key")

        if not all([host, cacert, system, account]):
            raise AnsibleError("required: host, cacert, system, account")

        client_cert, client_key = self._resolve_cert_paths(cert, key, combined)
        cacert_path = self._abs_ok(cacert, "cacert")

        base = f"https://{host}/service/core/v4"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        # 1) registrations
        regs = self._get_json(
            f"{base}/A2ARegistrations",
            headers, client_cert, client_key, cacert_path, validate
        )
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
        page, limit = 0, 200
        while True:
            ras = self._get_json(
                f"{base}/A2ARegistrations/{reg_id}/RetrievableAccounts?page={page}&limit={limit}",
                headers, client_cert, client_key, cacert_path, validate
            )
            if not isinstance(ras, list) or not ras:
                break

            for ra in ras:
                asset_nm  = ra.get("AssetName")  or (ra.get("Asset") or {}).get("Name")
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

    # --- helpers ---

    def _abs_ok(self, p, name):
        p = os.path.expanduser(os.path.expandvars(p or ""))
        if not (os.path.isfile(p) and os.path.getsize(p) > 0):
            raise AnsibleError(f"{name} not found or empty: {p!r}")
        return os.path.abspath(p)

    def _resolve_cert_paths(self, cert, key, combined):
        """
        Prefer a single combined PEM if provided; otherwise require separate cert+key.
        """
        if combined:
            combined_path = self._abs_ok(combined, "combined_cert")
            return combined_path, None
        # separate cert/key
        if not (cert and key):
            raise AnsibleError("provide either combined_cert, or both cert and key")
        cert_path = self._abs_ok(cert, "cert")
        key_path  = self._abs_ok(key,  "key")
        return cert_path, key_path

    def _get_json(self, url, headers, client_cert, client_key, cacert_path, validate):
        kwargs = {
            "method": "GET",
            "headers": headers,
            "client_cert": client_cert,
            "validate_certs": validate,
            "follow_redirects": "all",
            "timeout": 30,
        }
        if client_key:      # only include if we actually have a separate key
            kwargs["client_key"] = client_key
        if validate:        # only include CA path when validating
            kwargs["ca_path"] = cacert_path

        try:
            r = open_url(url, **kwargs)
            raw = r.read()
        except Exception as e:
            raise AnsibleError(f"GET {url} failed: {e}")

        try:
            return json.loads(raw)
        except Exception:
            preview = (raw[:256].decode("utf-8","ignore") if isinstance(raw,(bytes,bytearray)) else str(raw))[:256]
            raise AnsibleError(f"Non-JSON from {url}: {preview!r}")

