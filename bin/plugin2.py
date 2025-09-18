# spp_apikey_authsecret.py — Ansible lookup plugin
# Combines: Core discovery (ApiKey) + A2A retrieval with custom header.
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ansible.module_utils.urls import open_url
import os, json

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        # secret type: accept first term (like vendor plugin) or kwarg
        secret_type = (terms[0] if terms else kwargs.get("secret_type") or "Password")

        host        = kwargs.get("host")
        cacert      = kwargs.get("cacert")
        cert        = kwargs.get("cert")
        key         = kwargs.get("key")
        combined    = kwargs.get("combined_cert")
        system      = kwargs.get("system")
        account     = kwargs.get("account")
        validate    = kwargs.get("validate_certs", True)
        reg_index   = int(kwargs.get("registration_index", 0))

        # A2A header controls (defaults to your requirement)
        header_name   = kwargs.get("header_name", "Authentication")
        header_scheme = kwargs.get("header_scheme", "")  # e.g., "A2A"; empty -> no prefix

        if not all([host, cacert, system, account]):
            raise AnsibleError("required: host, cacert, system, account (+cert/key or combined_cert)")

        client_cert, client_key = self._resolve_cert_paths(cert, key, combined)
        cacert_path = self._abs_ok(cacert, "cacert")

        base_core = f"https://{host}/service/core/v4"
        headers_core = {"Accept": "application/json", "Content-Type": "application/json"}

        # 1) registrations → take content[reg_index].Id
        regs = self._get_json(f"{base_core}/A2ARegistrations",
                              headers_core, client_cert, client_key, cacert_path, validate)
        if not isinstance(regs, list) or not regs:
            raise AnsibleError("A2ARegistrations returned empty list")
        try:
            reg = regs[reg_index]
        except IndexError:
            raise AnsibleError(f"registration_index {reg_index} out of range (len={len(regs)})")
        reg_id = reg.get("Id") or reg.get("ID")
        if reg_id is None:
            raise AnsibleError(f"registration missing Id: {reg}")

        # 2) retrievable accounts → match (system, account) → ApiKey
        api_key = None
        page, limit = 0, 200
        while True:
            ras = self._get_json(
                f"{base_core}/A2ARegistrations/{reg_id}/RetrievableAccounts?page={page}&limit={limit}",
                headers_core, client_cert, client_key, cacert_path, validate
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
                    break
            if api_key:
                break
            page += 1
        if not api_key:
            raise AnsibleError(f"No ApiKey match for system='{system}' account='{account}' (registration_id={reg_id})")

        # 3) A2A retrieval with custom header: "<header_name>: <api_key>" (no scheme by default)
        base_a2a = f"https://{host}/service/a2a/v4/credentials?type={secret_type}"
        a2a_headers = {"Accept": "application/json"}
        a2a_headers[header_name] = (f"{header_scheme} {api_key}".strip())

        secret = self._get_bytes(base_a2a, a2a_headers, client_cert, client_key, cacert_path, validate)

        # Return secret as a scalar (lookup returns list; Ansible will unwrap in most contexts)
        return [secret.decode("utf-8", "ignore")]

    # --- helpers ---

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

    def _get_json(self, url, headers, client_cert, client_key, cacert_path, validate):
        raw = self._http_get(url, headers, client_cert, client_key, cacert_path, validate)
        try:
            return json.loads(raw)
        except Exception:
            preview = (raw[:256].decode("utf-8","ignore") if isinstance(raw,(bytes,bytearray)) else str(raw))[:256]
            raise AnsibleError(f"Non-JSON from {url}: {preview!r}")

    def _get_bytes(self, url, headers, client_cert, client_key, cacert_path, validate):
        return self._http_get(url, headers, client_cert, client_key, cacert_path, validate)

    def _http_get(self, url, headers, client_cert, client_key, cacert_path, validate):
        kwargs = {
            "method": "GET",
            "headers": headers,
            "client_cert": client_cert,
            "validate_certs": validate,
            "follow_redirects": "all",
            "timeout": 30,
        }
        if client_key:
            kwargs["client_key"] = client_key
        if validate:
            kwargs["ca_path"] = cacert_path
        try:
            r = open_url(url, **kwargs)
            return r.read()
        except Exception as e:
            raise AnsibleError(f"GET {url} failed: {e}")

