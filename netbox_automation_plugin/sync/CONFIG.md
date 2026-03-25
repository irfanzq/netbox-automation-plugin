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

**Same MAAS as the UI:** `MAAS_URL` must be the API base for the MAAS instance where you see the machine in the web UI (e.g. spruce vs birch). If the URL points at a different region, hostnames can match while NICs look “missing.” **NIC list** uses REST + machine detail (`interface_set`) on MAAS 3.6+ when needed; ensure **`requests-oauthlib`** is installed in the NetBox venv.

Full reconciliation design: **`sync/DRIFT_DESIGN.md`**.

**Drift report — physical VLAN:** For each MAAS NIC that matches a NetBox interface by MAC, if both sides expose a numeric untagged VID, a mismatch sets status **`VLAN_DRIFT`** (see Phase 0 counts). If NetBox has VID but MAAS API does not return one (common vs machine summary UI), the row stays OK with a **VLAN unverified** note — manual check by fabric/VLAN name.

**MAAS BMC vs in-band IPs:** **BMC / OOB** comes from MAAS **power** (`power_address` on IPMI/Redfish/etc.). **Interface IPs** in the report are **in-band** NIC addresses — not the same. Matched-hosts table columns **MAAS BMC** and **NB OOB** (NetBox Device **OOB IP** when your version exposes `oob_ip`) compare those.

**MAAS API key for BMC:** Normal `GET .../machines/{id}/` often returns **`power_parameters: null`**. MAAS documents a separate **[machine power-parameters](https://maas.io/docs/machine)** operation (`op=power_parameters`) that returns full power fields; it is **admin-only** (403 for non-admin keys). The plugin tries that op after the standard read — use a **MAAS administrator** OAuth key in `MAAS_API_KEY` if you need **MAAS BMC** in the drift report. **python-libmaas** does not expose a different path; same API.

**NOT_IN_NETBOX on a device that exists:** The plugin matches NICs **by MAC** first. If NetBox interfaces have **no MAC filled in**, they never match — the report then says how many interfaces exist and how many have MACs. **Fallback:** same **interface name** as MAAS (e.g. `ens110f0`) with empty NB MAC → matched with a note to set the MAC. If MAAS and NetBox use **different names**, add MACs on NetBox so MAC matching works.

| `OPENSTACK_AUTH_URL` | OpenStack Identity URL | `https://.../v3` |
| `OPENSTACK_USERNAME` | OpenStack user | `admin` |
| `OPENSTACK_PASSWORD` | OpenStack password | (secret) |
| `OPENSTACK_PROJECT_NAME` | OpenStack project/tenant | `admin` |
| `OS_REGION_NAME` / `OPENSTACK_REGION_NAME` | Override Keystone region; default / plugin fallback is **`birch`** (`OPENSTACK_DEFAULT_REGION_NAME` in `sync/config/settings.py`). |
| `OS_INTERFACE` / `OPENSTACK_INTERFACE` | Usually `public` (from RC file) |
| `OS_PROJECT_ID` | Optional; from RC file if name auth fails |
| `OPENSTACK_USER_DOMAIN_NAME` | User domain | `Default` |
| `OPENSTACK_PROJECT_DOMAIN_NAME` | Project domain | `Default` |

Optional (application credentials instead of user/password):

- `OPENSTACK_APPLICATION_CREDENTIAL_ID`
- `OPENSTACK_APPLICATION_CREDENTIAL_SECRET`

**Second (or more) OpenStack clouds (optional):** set `OPENSTACK_2_AUTH_URL` to add another cloud. Data from all configured OpenStack clouds is **combined** into one dataset; the drift report and Excel show a single "OpenStack" view (one subnet gaps table, one FIP gaps table) compared to NetBox. Users do not see per-cloud sections. All second-cloud options use the `OPENSTACK_2_` prefix:

| Variable | Description |
|----------|-------------|
| `OPENSTACK_2_AUTH_URL` | **Required** to enable 2nd cloud. Identity URL (e.g. `https://cloud2.example.com/v3`). |
| `OPENSTACK_2_USERNAME` | OpenStack user for 2nd cloud |
| `OPENSTACK_2_PASSWORD` | OpenStack password (or use app cred below) |
| `OPENSTACK_2_PROJECT_NAME` | Project/tenant name |
| `OPENSTACK_2_REGION_NAME` | Region (default: same as `OPENSTACK_DEFAULT_REGION_NAME`) |
| `OPENSTACK_2_LABEL` | Display name in report (default: region name or "OpenStack 2") |
| `OPENSTACK_2_APPLICATION_CREDENTIAL_ID` / `OPENSTACK_2_APPLICATION_CREDENTIAL_SECRET` | Optional app cred for 2nd cloud |
| `OPENSTACK_2_INSECURE` | `true` to skip TLS verify for 2nd cloud |

**Drift audit — which OpenStack clouds to query:**

- **No NetBox site and no location** selected in the MAAS / OpenStack Sync form → the audit uses **every** cloud returned by `get_openstack_configs()` (primary `OS_*` plus optional `OPENSTACK_2_*`), merged into one report.
- **At least one site or location** selected → the plugin looks for **`birch`** and **`spruce`** (case-insensitive) in the selected **location display names**. If **no** locations are selected but **sites** are, it uses **site slugs** instead. Parent site slugs implied by a location choice are **not** used for cloud picking (so a site slug like `birch-dc` does not pull Birch when you only select child locations named Spruce). For each token found, it keeps only OpenStack configs whose **`openstack_region_name`** or **`label`** contains that substring. After fetch, **networks/subnets/FIPs** and **Ironic runtime rows** (`runtime_nics`, `runtime_bmc`, `subnet_consumers`) are further narrowed to the selected location names (name / `os_region` / attached network), so merged multi-cloud data does not leak the other region into LLDP-style tables. Example: `Spruce v2` → spruce cloud and spruce-scoped rows only. If the selection implies a token but no config matches, it **falls back to all clouds** and logs a warning. If names contain no `birch`/`spruce`, **all** configured clouds are used.

Ensure `OS_REGION_NAME` / `OPENSTACK_2_REGION_NAME` and optional labels align with those tokens (e.g. `birch`, `spruce`).

**NetBox (drift audit vs MAAS):** By default the plugin reads **this NetBox’s database** (Django ORM), same idea as VLAN deployment — **no `NETBOX_URL`, token, or DNS** to yourself.

**OpenStack from Docker:** If `birch.cloud.whitefiber.com` does not resolve inside the container, use an **internal auth URL** or add **`extra_hosts`** in Compose. `OPENSTACK_INSECURE=true` only skips TLS verification; it does not fix DNS.

| Variable | Description |
|----------|-------------|
| `OPENSTACK_INSECURE` | `true` to skip TLS verify for Keystone/API (e.g. dev CAs) |

**Multi-project Neutron audit (optional):** By default the plugin uses a single Keystone project (`OS_PROJECT_NAME` / `OS_PROJECT_ID`). To compare drift against **all projects** the user can access (networks/subnets/FIPs merged with dedupe by resource id), set:

| Variable | Description |
|----------|-------------|
| `OPENSTACK_AUDIT_ALL_PROJECTS` | `true` — list projects via Keystone, then run Neutron list APIs in each project scope. Shared resources appear once (deduped by id). |
| `OPENSTACK_PROJECT_ALLOWLIST` | Comma-separated **project names or UUIDs**. If set **without** `OPENSTACK_AUDIT_ALL_PROJECTS`, only these projects are scanned (no Keystone list). If set **with** `OPENSTACK_AUDIT_ALL_PROJECTS`, the Keystone list is filtered to this set. |

For the **second cloud** (`OPENSTACK_2_*`): `OPENSTACK_2_AUDIT_ALL_PROJECTS` and `OPENSTACK_2_PROJECT_ALLOWLIST` behave the same.

**Notes:** Listing projects requires a user/token that can call Keystone’s project API; **application credentials** are often single-project — if listing fails, the plugin falls back to one project from your existing `OS_PROJECT_NAME` / project id. Projects where Neutron returns 403 are skipped with a warning; partial data is still returned if at least one project succeeds.

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

### Adding a second OpenStack server (step-by-step)

1. **Set environment variables** for the 2nd cloud where the NetBox process runs (e.g. in `netbox.env`, Docker Compose `env_file`, or systemd `Environment=`):
   - `OPENSTACK_2_AUTH_URL` — Identity URL of the 2nd OpenStack (e.g. `https://cloud2.example.com:5000/v3`). **Required** to enable the 2nd cloud.
   - `OPENSTACK_2_USERNAME` — OpenStack user for the 2nd cloud.
   - `OPENSTACK_2_PASSWORD` — Password (or use application credentials below).
   - `OPENSTACK_2_PROJECT_NAME` — Project/tenant name.
   - Optional: `OPENSTACK_2_REGION_NAME` (e.g. `regionTwo`), `OPENSTACK_2_LABEL` (e.g. `oak` for display in the report), `OPENSTACK_2_INSECURE=true` if you skip TLS verify.

2. **Restart NetBox** (or the container/worker that runs the plugin) so it picks up the new env vars.

3. **Run the drift audit** (Automation → MAAS / OpenStack Sync → Run drift audit). The "Drift data sources" card shows one OpenStack row with **combined** counts (networks, subnets, FIPs from all clouds). The report and Excel show a single OpenStack vs NetBox view: one subnet gaps table and one FIP gaps table.
