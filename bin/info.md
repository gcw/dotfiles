# spp\_bootstrap\_find\_get — Ansible lookup plugin

Retrieve a Safeguard secret by:

1. bootstrapping an ApiKey tied to the client certificate,
2. enumerating registrations (via A2A, falling back to Core),
3. finding the `(AssetName, AccountName)` match to obtain the **final** ApiKey,
4. and retrieving the secret via A2A with `Authorization: A2A <final_api_key>`.

---

## Installation

Place the plugin file at one of the following:

**Option A (project-local path, short name):**

```
collection/oneidentity/safeguard/plugins/lookup/spp_bootstrap_find_get.py
```

Then:

```sh
export ANSIBLE_LOOKUP_PLUGINS="$PWD/collection/oneidentity/safeguard/plugins/lookup"
ansible-doc -t lookup spp_bootstrap_find_get
```

**Option B (collection-style, FQCN):**

```
collections/ansible_collections/oneidentity/safeguardcollection/plugins/lookup/spp_bootstrap_find_get.py
```

Then:

```sh
export ANSIBLE_COLLECTIONS_PATHS="$PWD/collections:${ANSIBLE_COLLECTIONS_PATHS}"
ansible-doc -t lookup oneidentity.safeguardcollection.spp_bootstrap_find_get
```

> Requires: controller can reach the SPP appliance; client cert/private key (PEM); CA bundle (PEM).

---

## Parameters

| Name                           | Type       | Required | Default    | Description                                                                                                                    |
| ------------------------------ | ---------- | :------: | ---------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `host`                         | str        |    yes   | —          | SPP appliance hostname or IP. **No scheme.**                                                                                   |
| `cacert`                       | str (path) |    yes   | —          | CA bundle (PEM) to validate the SPP server cert.                                                                               |
| `cert`                         | str (path) |   no\*   | —          | Client certificate (PEM). Use with `key`. Ignored if `combined_cert` is given.                                                 |
| `key`                          | str (path) |   no\*   | —          | **Unencrypted** client private key (PEM). Use with `cert`.                                                                     |
| `combined_cert`                | str (path) |    no    | —          | Single PEM containing certificate **then** unencrypted private key. Preferred if your key is encrypted.                        |
| `system`                       | str        |    yes   | —          | Asset name to match (aka `AssetName`). Case-insensitive match is not applied; pass exact name your SPP returns.                |
| `account`                      | str        |    yes   | —          | Account name to match (aka `AccountName`).                                                                                     |
| `validate_certs`               | bool       |    no    | `true`     | TLS server verification toggle.                                                                                                |
| `bootstrap_registration_id`    | int        |    no    | —          | Registration **Id** to use for the bootstrap ApiKey. Skips index selection.                                                    |
| `bootstrap_registration_index` | int        |    no    | `0`        | Registration index (0-based) in the Core list used only for the bootstrap step. Ignored if `bootstrap_registration_id` is set. |
| **positional term**            | str        |    no    | `Password` | Secret type to retrieve: pass `'Password'` or `'PrivateKey'` as the first positional argument to the lookup.                   |

\* Provide either `combined_cert` **or** both `cert` and `key`.

**Returns:** the secret as a string (lookup returns a single-element list that Ansible unwraps in most contexts).

---

## Workflow (implemented internally)

1. **Bootstrap ApiKey:**
   GET `/service/core/v4/A2ARegistrations` → pick registration by `bootstrap_registration_id` **or** `bootstrap_registration_index` (default 0).
   GET `/service/core/v4/A2ARegistrations/{reg}/RetrievableAccounts?page=0&limit=1` → take first entry’s `ApiKey`.

2. **Enumerate registrations (preferred via A2A):**
   GET `/service/a2a/v4/Registrations` with `Authorization: A2A <bootstrap_api_key>` to list registration Ids.
   If that fails, fallback to Core list from step 1.

3. **Select final ApiKey by asset/account:**
   For each registration Id:
   GET `/service/core/v4/A2ARegistrations/{reg}/RetrievableAccounts` → find exact `(AssetName, AccountName)`; take its `ApiKey`.

4. **Retrieve secret via A2A:**
   GET `/service/a2a/v4/Credentials?type=<Password|PrivateKey>` with `Authorization: A2A <final_api_key>`.

All file paths are expanded (`~`, `$VARS`) and checked for existence and non-zero size before use.

---

## Usage

### Minimal (separate cert + key)

```yaml
- hosts: localhost
  gather_facts: false
  vars:
    host: safeguard.example.com
    cacert: /path/ca_bundle.pem
    cert:   /path/appcert.pem
    key:    /path/appkey.pem
    system: CSDevExtDomain
    account: svc.aap_spe_win
  tasks:
    - name: Retrieve password
      set_fact:
        spp_password: >-
          {{ lookup('spp_bootstrap_find_get',
                    'Password',
                    host=host, cacert=cacert, cert=cert, key=key,
                    system=system, account=account) }}
      no_log: true
```

### Using a combined PEM (cert + key in one file)

```yaml
- set_fact:
    spp_password: >-
      {{ lookup('spp_bootstrap_find_get',
                'Password',
                host=host, cacert=cacert,
                combined_cert='/path/app_combined.pem',
                system=system, account=account) }}
  no_log: true
```

### Pin the bootstrap registration

```yaml
- set_fact:
    spp_password: >-
      {{ lookup('spp_bootstrap_find_get',
                'Password',
                host=host, cacert=cacert, cert=cert, key=key,
                system=system, account=account,
                bootstrap_registration_id=1019) }}
  no_log: true
```

### Retrieve an SSH private key

```yaml
- set_fact:
    ssh_private_key: >-
      {{ lookup('spp_bootstrap_find_get',
                'PrivateKey',
                host=host, cacert=cacert, cert=cert, key=key,
                system=system, account=account) }}
  no_log: true
```

---

## Quick verification

```sh
# Point Ansible to your plugin (Option A)
export ANSIBLE_LOOKUP_PLUGINS="$PWD/collection/oneidentity/safeguard/plugins/lookup"

# Confirm docs load
ansible-doc -t lookup spp_bootstrap_find_get
```

---

## Troubleshooting (concise)

* **`ValueError: Empty certificate data`** → your `cacert` (or cert/key) is not PEM or is empty. Convert to PEM and ensure files begin with `-----BEGIN ...-----`.
* **401 / 60108** on A2A → wrong/empty ApiKey or cert/key not trusted for the selected registration. Verify with curl:
  `curl -si --cacert "$cacert" --cert "$cert" --key "$key" -H "Authorization: A2A $API_KEY" "https://$host/service/a2a/v4/Credentials?type=Password"`
* **No ApiKey match** → `(system, account)` not present under any registration the principal can read. Double-check exact names as reported by SPP.
* **204 No Content** → policy gate (approval/ticket/time window). Not a client bug.

---

## Notes

* `host` must be a hostname or IP only (no `https://`).
* Keys must be **unencrypted** when passed separately; if encrypted, use `combined_cert` with an unencrypted key concatenated after the cert.
* Pagination limits in the plugin are set high (first page of bootstrap; up to 500 for selection). Adjust in code if your environment needs more.

