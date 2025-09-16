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
    description: Safeguard hostname or IP address.
    type: str
    required: true
  cert:
    description: Path to client certificate (PEM file).
    type: str
    required: true
  key:
    description: Path to client private key (PEM file).
    type: str
    required: true
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
  - This lookup runs on the Ansible controller.
  - The controller must have network access to the Safeguard host.
"""

EXAMPLES = r"""
- name: Get ApiKey as string
  set_fact:
    spp_api_key: >-
      {{ lookup('spp_apikey',
                host=spp_host, cert=cert, key=key, cacert=cacert,
                system=system_name, account=account_name) }}

- name: Get ApiKey with metadata dict
  set_fact:
    spp_info: >-
      {{ lookup('spp_apikey',
                host=spp_host, cert=cert, key=key, cacert=cacert,
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
