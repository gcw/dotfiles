# spp_bootstrap_find_get.py
# Lookup plugin: Bootstrap ApiKey (cert-bound) → enumerate registrations → match (AssetName,AccountName) → retrieve secret via A2A.

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ansible.module_utils.urls import open_url
import os, json

DOCUMENTATION = r"""
lookup: spp_bootstrap_find_get
author:
  - Your Name
short_description: Retrieve a Safeguard secret by bootstrapping an ApiKey from the client certificate, then selecting the target registration by AssetName/AccountName.
description:
  - Implements a four-step workflow:
  - 1) Bootstrap an ApiKey tied to the client certificate by reading retrievable accounts from a selected (or first) Core registration.
  - 2) Enumerate registrations using the bootstrap ApiKey via the A2A service (fallback to Core list if enumeration is not available).
  - 3) For each registration, search retrievable accounts for the exact (AssetName, AccountName) pair; take that entry's ApiKey.
  - 4) Retrieve the secret via A2A using C(Authorization: A2A <final_api_key>).
  - Returns the secret as a string.
requirements:
  - Controller network access to the Safeguard appliance.
  - Client certificate/key trusted by the targeted A2A registration(s).
notes:
  - The first positional term (I(terms[0])) is the secret type, e.g. C(Password). Defaults to C(Password) if omitted.
  - Provide either C(combined_cert) OR both C(cert) and C(key).
options:
  host:
    description: Safeguard appliance hostname or IP (no scheme).
    type: str
    required: true
  cacert:
    description: Path to CA bundle (PEM) used to validate the HTTPS server certificate.
    type: str
    required: true
  cert:
    description: Path to client certificate (PEM). Ignored if C(combined_cert) is provided.
    type: str
    required: false
  key:
    description: Path to client private key (PEM, unencrypted). Ignored if C(combined_cert) is provided.
    type: str
    required: false
  combined_cert:
    description: Path to a single PEM containing the client certificate followed by the unencrypted private key.
    type: str
    required: false
  system:
    description: Target AssetName to match when selecting the ApiKey.
    type: str
    required: true
  account:
    description: Target AccountName to match when selecting the ApiKey.
    type: str
    required: true
  validate_certs:
    description: Whether to validate the HTTPS server certificate.
    type: bool
    default: true
  bootstrap_registration_id:
    description: Registration Id to use for the bootstrap ApiKey (skips index selection).
    type: int
    required: false
  bootstrap_registration_index:
    description: Zero-based index into the Core registrations list for the bootstrap step (ignored if C(bootstrap_registration_id) is set).
    type: int
    default: 0
"""

EXAMPLES = r"""
- name: Get password using bootstrap→enumerate→match→retrieve (defaults to secret type 'Password')
  set_fact:
    spp_password: >-
      {{ lookup('spp_bootstrap_find_get',
                host=spp_host,
                cacert=cacert,
                cert=cert,
                key=key,
                system=system_name,
                account=account_name) }}
  no_log: true

- name: Pin bootstrap registration by id and request an SSH private key
  set_fact:
    ssh_key: >-
      {{ lookup('spp_bootstrap_find_get',
                'PrivateKey',
                host=spp_host,
                cacert=cacert,
                combined_cert=combined_pem,
                system=system_name,
                account=account_name,
                bootstrap_registration_id=1019) }}
  no_log: true
"""

RETURN = r"""
_raw:
  description: Secret material returned by the A2A credentials endpoint as a string.
  type: str
"""

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        secret_type = (terms[0] if terms else kwargs.get("secret_type") or "Password")

        host     = kwargs.get("host")
        cacert   = kwargs.get("cacert")
        cert     = kwargs.get("cert")
        key      = kwargs.get("key")
        combined = kwargs.get("combined_cert")
        system   = kwargs.get("system")
        account  = kwargs.get("account")
        validate = kwargs.get("validate_certs", True)

        boot_reg_id    = kwargs.get("bootstrap_registration_id")
        boot_reg_index = int(kwargs.get("bootstrap_registration_index", 0))

        if not all([host, cacert, system, account]):
            raise AnsibleError("required: host, cacert, system, account (+combined_cert OR cert+key)")

        client_cert, client_key = self._resolve_cert_paths(cert, key, combined)
        cacert_path = self._abs_ok(cacert, "cacert")

        base_core = f"https://{host}/service/core/v4"
        core_headers = {"Accept": "application/json", "Content-Type": "application/json"}

        # STEP 1: bootstrap ApiKey from Core retrievable accounts of a chosen registration
        if boot_reg_id is not None:
            reg_id_boot = int(boot_reg_id)
        else:
            regs = self._get_json(f"{base_core}/A2ARegistrations",
                                  core_headers, client_cert, client_key, cacert_path, validate)
            if not isinstance(regs, list) or not regs:
                raise AnsibleError("A2ARegistrations returned empty list")
            if boot_reg_index < 0 or boot_reg_index >= len(regs):
                raise AnsibleError(f"bootstrap_registration_index {boot_reg_index} out of range (len={len(regs)})")
            reg_id_boot = regs[boot_reg_index].get("Id") or regs[boot_reg_index].get("ID")
        if reg_id_boot is None:
            raise AnsibleError("could not determine bootstrap registration id")

        ra_boot = self._get_json(
            f"{base_core}/A2ARegistrations/{reg_id_boot}/RetrievableAccounts?page=0&limit=1",
            core_headers, client_cert, client_key, cacert_path, validate
        )
        if not isinstance(ra_boot, list) or not ra_boot or not ra_boot[0].get("ApiKey"):
            raise AnsibleError(f"no bootstrap ApiKey available under registration_id={reg_id_boot}")
        bootstrap_api_key = ra_boot[0]["ApiKey"]

        # STEP 2: enumerate registrations via A2A using bootstrap key (fallback to Core)
        regs_ids = self._list_regs_via_a2a(host, bootstrap_api_key, client_cert, client_key, cacert_path, validate)
        if not regs_ids:
            regs = self._get_json(f"{base_core}/A2ARegistrations",
                                  core_headers, client_cert, client_key, cacert_path, validate)
            regs_ids = [r.get("Id") or r.get("ID") for r in regs if (r.get("Id") or r.get("ID"))]
        if not regs_ids:
            raise AnsibleError("could not enumerate registrations")

        # STEP 3: find (system, account) → take that ApiKey
        sys_l = system.lower(); acct_l = account.lower()
        final_api_key = None
        for rid in regs_ids:
            ras = self._get_json(
                f"{base_core}/A2ARegistrations/{rid}/RetrievableAccounts?page=0&limit=500",
                core_headers, client_cert, client_key, cacert_path, validate
            )
            if not isinstance(ras, list) or not ras:
                continue
            for ra in ras:
                asset_nm   = (ra.get("AssetName")  or (ra.get("Asset")   or {}).get("Name") or "").lower()
                account_nm = (ra.get("AccountName") or (ra.get("Account") or {}).get("Name") or "").lower()
                if asset_nm == sys_l and account_nm == acct_l:
                    k = ra.get("ApiKey")
                    if not k:
                        raise AnsibleError(f"match found in registration_id={rid} but ApiKey missing")
                    final_api_key = k
                    break
            if final_api_key:
                break
        if not final_api_key:
            raise AnsibleError(f"No ApiKey match for system='{system}' account='{account}' in any registration")

        # STEP 4: retrieve secret via A2A
        secret = self._a2a_get_secret(host, secret_type, final_api_key,
                                      client_cert, client_key, cacert_path, validate)
        return [secret]

    # ---------- helpers ----------

    def _abs_ok(self, p, name):
        p = os.path.expanduser(os.path.expandvars(p or ""))
        if not (os.path.isfile(p) and os.path.getsize(p) > 0):
            raise AnsibleError(f"{name} not found or empty: {p!r}")
        return os.path.abspath(p)

    def _resolve_cert_paths(self, cert, key, combined):
        if combined:
            return self._abs_ok(combined, "combined_cert"), None
        if not (cert and key):
            raise AnsibleError("provide either combined_cert, or both cert and key")
        return self._abs_ok(cert, "cert"), self._abs_ok(key, "key")

    def _http_get(self, url, headers, client_cert, client_key, cacert_path, validate):
        kw = {
            "method": "GET",
            "headers": headers,
            "client_cert": client_cert,
            "validate_certs": validate,
            "follow_redirects": "all",
            "timeout": 30,
        }
        if client_key:
            kw["client_key"] = client_key
        if validate:
            kw["ca_path"] = cacert_path
        try:
            r = open_url(url, **kw)
            return r.read()
        except Exception as e:
            raise AnsibleError(f"GET {url} failed: {e}")

    def _get_json(self, url, headers, client_cert, client_key, cacert_path, validate):
        raw = self._http_get(url, headers, client_cert, client_key, cacert_path, validate)
        try:
            return json.loads(raw)
        except Exception:
            prev = (raw[:256].decode("utf-8", "ignore") if isinstance(raw, (bytes, bytearray)) else str(raw))[:256]
            raise AnsibleError(f"Non-JSON from {url}: {prev!r}")

    def _list_regs_via_a2a(self, host, api_key, client_cert, client_key, cacert_path, validate):
        headers = {"Accept": "application/json", "Authorization": f"A2A {api_key}"}
        for path in ("/service/a2a/v4/Registrations", "/service/a2a/v4/registrations"):
            url = f"https://{host}{path}"
            try:
                raw = self._http_get(url, headers, client_cert, client_key, cacert_path, validate)
                data = json.loads(raw)
                if isinstance(data, list) and data:
                    ids = []
                    for r in data:
                        rid = r.get("Id") or r.get("ID")
                        if rid is not None:
                            ids.append(rid)
                    if ids:
                        return ids
            except Exception:
                pass
        return []

    def _a2a_get_secret(self, host, secret_type, api_key, client_cert, client_key, cacert_path, validate):
        url = f"https://{host}/service/a2a/v4/Credentials?type={secret_type}"
        headers = {"Accept": "application/json", "Authorization": f"A2A {api_key}"}
        raw = self._http_get(url, headers, client_cert, client_key, cacert_path, validate)
        return raw.decode("utf-8", "ignore")

