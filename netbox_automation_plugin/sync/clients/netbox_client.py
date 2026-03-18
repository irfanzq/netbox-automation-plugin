"""
NetBox client wrapper using pynetbox.

Fetches devices, interfaces, sites. Used for drift audit and (later) branch-based writes.
When netbox_url is empty, uses base_url to build API URL (e.g. from request).
"""

import logging

logger = logging.getLogger("netbox_automation_plugin.sync")


def fetch_netbox_data(netbox_url: str, netbox_token: str, base_url_fallback: str = ""):
    """
    Fetch devices and sites from NetBox. Returns a dict with:
      - devices: list of {name, id, site_slug}
      - sites: list of {name, slug}
      - error: str if connection failed
    """
    result = {"devices": [], "sites": [], "error": None}

    url = (netbox_url or base_url_fallback or "").rstrip("/")
    if not url:
        result["error"] = "NetBox URL is required (set NETBOX_URL or pass base_url_fallback)"
        return result
    if not netbox_token:
        result["error"] = "NetBox API token is required (set NETBOX_TOKEN)"
        return result

    try:
        import pynetbox
    except ImportError:
        result["error"] = "pynetbox is not installed. Add it to plugin_requirements.txt and reinstall the plugin."
        return result

    try:
        nb = pynetbox.api(url, token=netbox_token)
        # Optional: skip SSL verify for dev (e.g. self-signed)
        if url.startswith("https://") and "insecure" in str(type(nb)).lower():
            try:
                nb.http_session.verify = False
            except Exception:
                pass

        # Sites
        for s in nb.dcim.sites.all():
            result["sites"].append({"name": getattr(s, "name", ""), "slug": getattr(s, "slug", "")})

        # Devices (name, id, site)
        for d in nb.dcim.devices.all():
            site_slug = ""
            site = getattr(d, "site", None)
            if site is not None:
                site_slug = getattr(site, "slug", "") or getattr(site, "name", "")
            result["devices"].append({
                "name": getattr(d, "name", ""),
                "id": getattr(d, "id", None),
                "site_slug": site_slug,
            })
    except Exception as e:
        logger.exception("NetBox fetch failed")
        result["error"] = str(e)

    return result
