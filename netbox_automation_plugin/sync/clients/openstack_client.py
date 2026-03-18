"""
OpenStack client wrapper using openstacksdk.

Fetches networks, subnets, floating IPs. Used for drift audit and OpenStack visibility sync.
"""

import logging

logger = logging.getLogger("netbox_automation_plugin.sync")


def fetch_openstack_data(config: dict):
    """
    Fetch networks, subnets, floating IPs from OpenStack. config is the result of get_sync_config().
    Returns a dict with:
      - networks: list of {id, name}
      - subnets: list of {id, cidr, network_id}
      - floating_ips: list of {floating_ip_address, fixed_ip_address, id}
      - error: str if connection failed
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
        conn = openstack.connect(
            auth_url=config["openstack_auth_url"],
            username=config.get("openstack_username") or "",
            password=config.get("openstack_password") or "",
            project_name=config.get("openstack_project_name") or "",
            user_domain_name=config.get("openstack_user_domain_name") or "Default",
            project_domain_name=config.get("openstack_project_domain_name") or "Default",
            region_name=config.get("openstack_region_name") or "RegionOne",
            verify=verify_tls,
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
            result["floating_ips"].append({
                "floating_ip_address": getattr(fip, "floating_ip_address", ""),
                "fixed_ip_address": getattr(fip, "fixed_ip_address", "") or "-",
                "id": getattr(fip, "id", ""),
            })
    except Exception as e:
        logger.exception("OpenStack fetch failed")
        result["error"] = str(e)

    return result
