# MAAS / OpenStack Sync — Config and secrets

## Where to put URLs and secrets

**Recommendation: use environment variables for all secrets and URLs.** The sync module reads `os.environ` when a value is not set in plugin config, so you never need to put API keys in config files.

### Environment variables (recommended)

Set these in the environment of the NetBox process (e.g. systemd unit, Docker env, or shell):

| Variable | Description | Example |
|----------|-------------|---------|
| `MAAS_URL` | MAAS API base URL | `https://172.17.0.128:5443/MAAS` |
| `MAAS_API_KEY` | MAAS API key (key:token:secret) | `...` |
| `MAAS_INSECURE` | Skip TLS verify for MAAS | `true` or `false` |
| `OPENSTACK_AUTH_URL` | OpenStack Identity URL | `https://.../v3` |
| `OPENSTACK_USERNAME` | OpenStack user | `admin` |
| `OPENSTACK_PASSWORD` | OpenStack password | (secret) |
| `OPENSTACK_PROJECT_NAME` | OpenStack project/tenant | `admin` |
| `OPENSTACK_REGION_NAME` | Region | `RegionOne` |
| `OPENSTACK_USER_DOMAIN_NAME` | User domain | `Default` |
| `OPENSTACK_PROJECT_DOMAIN_NAME` | Project domain | `Default` |

Optional (application credentials instead of user/password):

- `OPENSTACK_APPLICATION_CREDENTIAL_ID`
- `OPENSTACK_APPLICATION_CREDENTIAL_SECRET`

**NetBox (drift audit vs MAAS):** By default the plugin reads **this NetBox’s database** (Django ORM), same idea as VLAN deployment — **no `NETBOX_URL`, token, or DNS** to yourself.

Only if you must compare MAAS to a **different** NetBox over HTTP:

| Variable | Description |
|----------|-------------|
| `NETBOX_SYNC_USE_REMOTE_API` | `true` to use pynetbox instead of local DB |
| `NETBOX_URL` | Remote API base |
| `NETBOX_TOKEN` | API token |
| `NETBOX_SSL_VERIFY` / `NETBOX_CA_BUNDLE` | TLS options for remote API |

**OpenStack from Docker:** If `birch.cloud.whitefiber.com` does not resolve inside the container, use an **internal auth URL** or add **`extra_hosts`** in Compose. `OPENSTACK_INSECURE=true` only skips TLS verification; it does not fix DNS.

| Variable | Description |
|----------|-------------|
| `OPENSTACK_INSECURE` | `true` to skip TLS verify for Keystone/API (e.g. dev CAs) |

### Plugin config (optional override)

In NetBox `configuration.py` you can put non-secret defaults or pass through env:

```python
import os

PLUGINS_CONFIG = {
    "netbox_automation_plugin": {
        "maas_openstack_sync": {
            "maas_url": os.environ.get("MAAS_URL", ""),
            "maas_api_key": os.environ.get("MAAS_API_KEY", ""),
            "maas_insecure": True,
            "site_mapping_fabric": {"birch-fabric": "birch"},
            "site_mapping_pool": {"birch": "birch"},
        }
    }
}
```

**Do not put real API keys or passwords in `configuration.py`.** Use env vars and `os.environ.get()` as above so secrets stay out of the repo.

### Site mapping (non-secret)

- `site_mapping_fabric`: dict mapping MAAS fabric name → NetBox site slug (e.g. `birch-fabric` → `birch`).
- `site_mapping_pool`: dict mapping MAAS pool name → NetBox site slug when pool names align with sites (e.g. `birch` → `birch`).

These can live in plugin config or in a dedicated config file; they are not secrets.
