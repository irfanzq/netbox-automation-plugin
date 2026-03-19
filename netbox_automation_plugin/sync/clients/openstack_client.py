"""
OpenStack client wrapper using openstacksdk.

Fetches networks, subnets, floating IPs. Used for drift audit and OpenStack visibility sync.
"""

import logging
import os

from netbox_automation_plugin.sync.config.settings import OPENSTACK_DEFAULT_REGION_NAME

logger = logging.getLogger("netbox_automation_plugin.sync")


def fetch_openstack_data(config: dict):
    """
    Fetch networks, subnets, floating IPs from OpenStack. config is the result of get_sync_config().
    Returns a dict with:
      - networks: list of {id, name}
      - subnets: list of {id, cidr, network_id}
      - floating_ips: list of {floating_ip_address, fixed_ip_address, id, project_id, project_name}
      - error: str if connection failed
    """
    return fetch_openstack_data_for_config(config)


def fetch_openstack_data_for_config(config: dict):
    """
    Fetch OpenStack data using a config dict that has openstack_* keys
    (e.g. one entry from get_openstack_configs()). Same return shape as fetch_openstack_data().
    """
    result = {"networks": [], "subnets": [], "floating_ips": [], "error": None}

    auth_url = config.get("openstack_auth_url") or ""
    if not auth_url:
        result["error"] = "OpenStack auth URL not set (OS_AUTH_URL or OPENSTACK_AUTH_URL)"
        return result

    try:
        import openstack
    except ImportError:
        result["error"] = "openstacksdk is not installed. Add it to plugin_requirements.txt and reinstall the plugin."
        return result

    try:
        verify_tls = not config.get("openstack_insecure", False)
        auth_url = (config["openstack_auth_url"] or "").rstrip("/")
        if auth_url and not auth_url.endswith("/v3"):
            auth_url = auth_url + "/v3"
        region = (
            (config.get("openstack_region_name") or "").strip()
            or OPENSTACK_DEFAULT_REGION_NAME
        )
        app_id = (config.get("openstack_application_credential_id") or "").strip()
        app_secret = (config.get("openstack_application_credential_secret") or "").strip()
        if app_id and app_secret:
            kwargs = {
                "auth_url": auth_url,
                "application_credential_id": app_id,
                "application_credential_secret": app_secret,
                "region_name": region,
                "interface": config.get("openstack_interface") or "public",
                "verify": verify_tls,
            }
            conn = openstack.connect(**kwargs)
        else:
            kwargs = {
                "auth_url": auth_url,
                "username": config.get("openstack_username") or "",
                "password": config.get("openstack_password") or "",
                "user_domain_name": config.get("openstack_user_domain_name") or "Default",
                "project_domain_name": config.get("openstack_project_domain_name") or "Default",
                "region_name": region,
                "interface": config.get("openstack_interface") or "public",
                "verify": verify_tls,
            }
            pid = (config.get("openstack_project_id") or "").strip()
            if pid:
                kwargs["project_id"] = pid
            else:
                kwargs["project_name"] = config.get("openstack_project_name") or ""
            conn = openstack.connect(**kwargs)
        project_label = (
            (config.get("openstack_project_name") or "").strip()
            or (config.get("openstack_project_id") or "").strip()[:12]
            or "-"
        )

        for net in conn.network.networks():
            result["networks"].append({"id": net.id, "name": net.name or net.id})

        for sn in conn.network.subnets():
            result["subnets"].append({
                "id": sn.id,
                "cidr": getattr(sn, "cidr", ""),
                "network_id": getattr(sn, "network_id", ""),
            })

        for fip in conn.network.ips(floating=True):
            tid = getattr(fip, "tenant_id", None) or getattr(fip, "project_id", None) or ""
            result["floating_ips"].append({
                "floating_ip_address": getattr(fip, "floating_ip_address", ""),
                "fixed_ip_address": getattr(fip, "fixed_ip_address", "") or "-",
                "id": getattr(fip, "id", ""),
                "project_id": str(tid)[:36] if tid else "",
                "project_name": project_label,
            })
    except Exception as e:
        logger.exception("OpenStack fetch failed")
        msg = str(e)
        if "region" in msg.lower() and "not found" in msg.lower():
            rn = locals().get("kwargs", {}).get("region_name", "?")
            msg += (
                f" — Using region_name={rn!r}. Set OS_REGION_NAME (or OPENSTACK_REGION_NAME) "
                "on the NetBox container to match `openstack region list` (e.g. birch), then restart."
            )
        result["error"] = msg

    return result


def fetch_all_openstack_data(configs: list):
    """
    Fetch from multiple OpenStack configs (e.g. from get_openstack_configs()).
    Returns list of {"label": str, "data": dict}; each data has networks, subnets, floating_ips, error.
    """
    out = []
    for c in configs:
        label = c.get("label") or "OpenStack"
        out.append({"label": label, "data": fetch_openstack_data_for_config(c)})
    return out
