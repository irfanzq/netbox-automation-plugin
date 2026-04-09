"""
Sync configuration for MAAS, OpenStack, and NetBox.

Best practice: keep URLs and non-secret options in plugin config; keep API keys
and tokens in environment variables so they are never committed.

Option A — Environment variables (recommended for secrets):
  Set in the NetBox process environment (e.g. in systemd, docker, or shell):
    MAAS_URL=https://maas.example.com/MAAS
    MAAS_API_KEY=key:token:secret
    MAAS_INSECURE=false
    OPENSTACK_AUTH_URL=https://...
    OPENSTACK_USERNAME=...
    OPENSTACK_PASSWORD=...   (or OPENSTACK_APPLICATION_CREDENTIAL_ID/SECRET)
    OPENSTACK_PROJECT_NAME=...
    OPENSTACK_REGION_NAME=birch
  NetBox uses the same process; the plugin reads os.environ when the key
  is not in PLUGINS_CONFIG.

Option B — Plugin config (NetBox configuration.py):
  In configuration.py you can set:
    PLUGINS_CONFIG = {
      "netbox_automation_plugin": {
        "maas_openstack_sync": {
          # Optional: limit drift audit pickers to these NetBox site slugs (and their locations).
          # Same as env DRIFT_AUDIT_SITE_SLUGS (comma-separated), e.g. "b52".
          # "drift_audit_site_slugs_allowlist": ["b52"],
          "maas_url": os.environ.get("MAAS_URL", ""),
          "maas_api_key": os.environ.get("MAAS_API_KEY", ""),
          "maas_insecure": True,
          "openstack_auth_url": os.environ.get("OPENSTACK_AUTH_URL", ""),
          ...
        }
      }
    }
  So secrets still come from env; config just passes them through.

Site mapping (fabric/pool -> NetBox site) is non-secret and can live in
plugin config or a dedicated mapping structure.
"""

import os
from django.conf import settings

# When OS_REGION_NAME / plugin openstack_region_name are unset (org default cloud)
OPENSTACK_DEFAULT_REGION_NAME = "birch"


def _parse_csv_allowlist(raw):
    """Comma-separated tokens (project names or UUIDs)."""
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(x).strip() for x in raw if str(x).strip()]
    s = str(raw).strip()
    if not s:
        return []
    return [p.strip() for p in s.split(",") if p.strip()]


def _bool_coerce(x):
    return str(x).lower() in ("1", "true", "yes")


def _openstack_project_allowlist_from_cfg(cfg, cfg_key, env_key):
    """Allowlist from plugin config (list/str) or env CSV."""
    raw = cfg.get(cfg_key)
    if raw is not None and raw != "":
        return _parse_csv_allowlist(raw)
    return _parse_csv_allowlist(os.environ.get(env_key, ""))


def _plugin_config():
    """Return the maas_openstack_sync section of plugin config."""
    plugins_config = getattr(settings, "PLUGINS_CONFIG", {}) or {}
    return plugins_config.get("netbox_automation_plugin", {}).get("maas_openstack_sync", {})


def _get(key: str, env_key: str, default=None):
    """Get value from plugin config, then env, then default."""
    cfg = _plugin_config()
    if key in cfg and cfg[key] not in (None, ""):
        return cfg[key]
    return os.environ.get(env_key, default)


def get_sync_config():
    """
    Return a single dict with all sync-related config.
    Secrets and URLs: prefer env vars so they are not in config files.
    """
    cfg = _plugin_config()

    def get_cfg(key, env_keys, default=None, coerce=None):
        """Get from plugin config, then first env key found (env_keys can be str or list)."""
        raw = cfg.get(key)
        if raw is None or raw == "":
            keys = [env_keys] if isinstance(env_keys, str) else env_keys
            for ek in keys:
                raw = os.environ.get(ek)
                if raw:
                    break
            if raw is None:
                raw = default
        if coerce and raw is not None:
            return coerce(raw)
        return raw

    return {
        # MAAS
        "maas_url": get_cfg("maas_url", "MAAS_URL", "").rstrip("/"),
        "maas_api_key": get_cfg("maas_api_key", "MAAS_API_KEY", ""),
        "maas_insecure": get_cfg("maas_insecure", "MAAS_INSECURE", "true", lambda x: str(x).lower() in ("1", "true", "yes")),
        # OpenStack (supports standard OS_* and OPENSTACK_* env vars)
        "openstack_auth_url": get_cfg("openstack_auth_url", ["OPENSTACK_AUTH_URL", "OS_AUTH_URL"], ""),
        "openstack_username": get_cfg("openstack_username", ["OPENSTACK_USERNAME", "OS_USERNAME"], ""),
        "openstack_password": get_cfg("openstack_password", ["OPENSTACK_PASSWORD", "OS_PASSWORD"], ""),
        "openstack_project_name": get_cfg("openstack_project_name", ["OPENSTACK_PROJECT_NAME", "OS_PROJECT_NAME"], ""),
        "openstack_project_id": get_cfg("openstack_project_id", ["OPENSTACK_PROJECT_ID", "OS_PROJECT_ID"], ""),
        # Env first, then plugin; final default matches org Keystone region
        "openstack_region_name": (
            (os.environ.get("OS_REGION_NAME") or os.environ.get("OPENSTACK_REGION_NAME") or "").strip()
            or (cfg.get("openstack_region_name") or "").strip()
            or OPENSTACK_DEFAULT_REGION_NAME
        ),
        "openstack_interface": get_cfg("openstack_interface", ["OPENSTACK_INTERFACE", "OS_INTERFACE"], "public"),
        "openstack_user_domain_name": get_cfg("openstack_user_domain_name", ["OPENSTACK_USER_DOMAIN_NAME", "OS_USER_DOMAIN_NAME"], "Default"),
        "openstack_project_domain_name": get_cfg("openstack_project_domain_name", ["OPENSTACK_PROJECT_DOMAIN_NAME", "OS_PROJECT_DOMAIN_NAME"], "Default"),
        # Application credentials (alternative to username/password)
        "openstack_application_credential_id": get_cfg("openstack_application_credential_id", "OPENSTACK_APPLICATION_CREDENTIAL_ID", ""),
        "openstack_application_credential_secret": get_cfg("openstack_application_credential_secret", "OPENSTACK_APPLICATION_CREDENTIAL_SECRET", ""),
        # NetBox (local ORM in this app). URL/token kept for compatibility with existing configs.
        "netbox_url": get_cfg("netbox_url", "NETBOX_URL", ""),
        "netbox_token": get_cfg("netbox_token", "NETBOX_TOKEN", ""),
        "netbox_ssl_verify": get_cfg(
            "netbox_ssl_verify",
            "NETBOX_SSL_VERIFY",
            "true",
            lambda x: str(x).lower() in ("1", "true", "yes"),
        ),
        "netbox_ca_bundle": get_cfg("netbox_ca_bundle", "NETBOX_CA_BUNDLE", "") or None,
        # OpenStack TLS (DNS must resolve inside Docker — use internal URL or extra_hosts)
        "openstack_insecure": get_cfg(
            "openstack_insecure",
            "OPENSTACK_INSECURE",
            "false",
            lambda x: str(x).lower() in ("1", "true", "yes"),
        ),
        # Multi-project Neutron audit: list all Keystone projects user can access, or only OPENSTACK_PROJECT_ALLOWLIST
        "openstack_audit_all_projects": get_cfg(
            "openstack_audit_all_projects",
            "OPENSTACK_AUDIT_ALL_PROJECTS",
            "false",
            _bool_coerce,
        ),
        "openstack_project_allowlist": _openstack_project_allowlist_from_cfg(
            cfg, "openstack_project_allowlist", "OPENSTACK_PROJECT_ALLOWLIST"
        ),
        # Site derivation: fabric -> NetBox site slug, pool -> site or tenant (optional)
        "site_mapping_fabric": cfg.get("site_mapping_fabric") or {},  # e.g. {"birch-fabric": "birch"}
        "site_mapping_pool": cfg.get("site_mapping_pool") or {},      # e.g. {"birch": "birch"}
        # Drift audit scope picker: if non-empty, only these NetBox site slugs (and their locations) appear.
        # Plugin config (list or comma string) or env DRIFT_AUDIT_SITE_SLUGS=e.g. b52,birch
        "drift_audit_site_slugs_allowlist": (
            _parse_csv_allowlist(cfg.get("drift_audit_site_slugs_allowlist"))
            if cfg.get("drift_audit_site_slugs_allowlist") not in (None, "")
            else _parse_csv_allowlist(os.environ.get("DRIFT_AUDIT_SITE_SLUGS", ""))
        ),
    }


def get_openstack_configs():
    """
    Return a list of OpenStack config dicts for drift audit (multi-cloud).
    First cloud: OPENSTACK_* / OS_* (same as get_sync_config()).
    Second cloud: OPENSTACK_2_AUTH_URL, OPENSTACK_2_USERNAME, OPENSTACK_2_PASSWORD, etc.
    Each dict has openstack_* keys plus "label" (display name). If OPENSTACK_2_AUTH_URL
    is not set, returns a single-element list (backward compatible).
    """
    full = get_sync_config()
    configs = []

    # First cloud (existing env)
    auth1 = (full.get("openstack_auth_url") or "").strip()
    if auth1:
        configs.append({
            "label": (
                (full.get("openstack_region_name") or "").strip()
                or os.environ.get("OPENSTACK_LABEL") or "OpenStack"
            ),
            "openstack_auth_url": full["openstack_auth_url"],
            "openstack_username": full["openstack_username"],
            "openstack_password": full["openstack_password"],
            "openstack_project_name": full["openstack_project_name"],
            "openstack_project_id": full["openstack_project_id"],
            "openstack_region_name": full["openstack_region_name"],
            "openstack_interface": full["openstack_interface"],
            "openstack_user_domain_name": full["openstack_user_domain_name"],
            "openstack_project_domain_name": full["openstack_project_domain_name"],
            "openstack_application_credential_id": full["openstack_application_credential_id"],
            "openstack_application_credential_secret": full["openstack_application_credential_secret"],
            "openstack_insecure": full["openstack_insecure"],
            "openstack_audit_all_projects": full["openstack_audit_all_projects"],
            "openstack_project_allowlist": list(full["openstack_project_allowlist"] or []),
        })

    # Second cloud (OPENSTACK_2_* env only)
    auth2 = (os.environ.get("OPENSTACK_2_AUTH_URL") or "").strip()
    if auth2:
        def _e2(k, default=None):
            return (os.environ.get("OPENSTACK_2_" + k) or default)

        region2 = (_e2("REGION_NAME") or "").strip() or OPENSTACK_DEFAULT_REGION_NAME
        label2 = (_e2("LABEL") or "").strip() or region2 or "OpenStack 2"
        audit2 = str(_e2("AUDIT_ALL_PROJECTS", "false")).lower() in ("1", "true", "yes")
        allow2 = _parse_csv_allowlist(_e2("PROJECT_ALLOWLIST", ""))
        configs.append({
            "label": label2,
            "openstack_auth_url": auth2.rstrip("/"),
            "openstack_username": _e2("USERNAME", ""),
            "openstack_password": _e2("PASSWORD", ""),
            "openstack_project_name": _e2("PROJECT_NAME", ""),
            "openstack_project_id": _e2("PROJECT_ID", ""),
            "openstack_region_name": region2,
            "openstack_interface": _e2("INTERFACE", "public"),
            "openstack_user_domain_name": _e2("USER_DOMAIN_NAME", "Default"),
            "openstack_project_domain_name": _e2("PROJECT_DOMAIN_NAME", "Default"),
            "openstack_application_credential_id": _e2("APPLICATION_CREDENTIAL_ID", ""),
            "openstack_application_credential_secret": _e2("APPLICATION_CREDENTIAL_SECRET", ""),
            "openstack_insecure": str(_e2("INSECURE", "false")).lower() in ("1", "true", "yes"),
            "openstack_audit_all_projects": audit2,
            "openstack_project_allowlist": allow2,
        })

    return configs
