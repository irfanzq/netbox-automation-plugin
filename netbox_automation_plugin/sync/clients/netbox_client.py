"""
NetBox data for sync / drift audit.

- **Local (ORM)**: Same process as NetBox — no HTTP, no NETBOX_URL/DNS/token. Use from UI/worker.
- **Remote (pynetbox)**: Optional; only if you must read another NetBox instance via API.
"""

import logging

logger = logging.getLogger("netbox_automation_plugin.sync")


def fetch_netbox_data_local():
    """
    Read sites and devices from this NetBox via Django ORM (like vlan_deployment).

    Returns same shape as fetch_netbox_data: devices [{name, id, site_slug}], sites [{name, slug}], error.
    """
    result = {"devices": [], "sites": [], "error": None}
    try:
        from dcim.models import Device, Site

        for s in Site.objects.only("name", "slug").iterator():
            result["sites"].append({"name": s.name or "", "slug": s.slug or ""})
        for d in Device.objects.select_related("site").only(
            "name", "id", "site_id", "site__slug", "site__name"
        ).iterator():
            site_slug = ""
            if d.site_id and d.site:
                site_slug = (d.site.slug or d.site.name or "")
            result["devices"].append({
                "name": d.name or "",
                "id": d.pk,
                "site_slug": site_slug,
            })
    except Exception as e:
        logger.exception("NetBox local ORM fetch failed")
        result["error"] = str(e)
    return result


def fetch_netbox_audit_detail_for_names(names: set):
    """
    Per-device fields for MAAS-matched hostnames only (avoids scanning all devices).
    names: set of device names (short hostnames).
    """
    out = {}
    if not names:
        return out
    try:
        from dcim.models import Device, Interface

        names_list = list(names)[:2000]
        devices = (
            Device.objects.filter(name__in=names_list)
            .select_related("site")
            .prefetch_related("interfaces")
        )
        for d in devices:
            site_slug = ""
            if d.site_id and d.site:
                site_slug = d.site.slug or d.site.name or ""
            try:
                status_val = d.get_status_display()
            except Exception:
                status_val = str(getattr(d, "status", "") or "")
            serial = (getattr(d, "serial", None) or "").strip()
            primary_mac = ""
            try:
                ifaces = [
                    i
                    for i in d.interfaces.all()
                    if i.mac_address
                ]
                mgmt = [i for i in ifaces if getattr(i, "mgmt_only", False)]
                pick = mgmt[0] if mgmt else (ifaces[0] if ifaces else None)
                if pick:
                    primary_mac = str(pick.mac_address).lower()
            except Exception:
                pass
            out[d.name] = {
                "site_slug": site_slug,
                "status": status_val,
                "serial": serial,
                "primary_mac": primary_mac,
            }
    except Exception:
        logger.exception("NetBox audit detail for names failed")
    return out


def fetch_netbox_interfaces_for_names(names: set):
    """
    Per-device interfaces for MAAS-matched hostnames.
    Returns: device_name -> [{name, mac, ips: [host-only str], mgmt_only}]
    """
    out = {}
    if not names:
        return out
    try:
        from django.db.models import Prefetch

        from dcim.models import Device, Interface

        names_list = list(names)[:2000]
        iface_qs = Interface.objects.prefetch_related("ip_addresses")
        devices = Device.objects.filter(name__in=names_list).prefetch_related(
            Prefetch("interfaces", queryset=iface_qs)
        )
        for d in devices:
            lst = []
            for iface in d.interfaces.all():
                mac = ""
                if iface.mac_address:
                    mac = str(iface.mac_address).lower().replace("-", ":")
                ips = []
                for ip in iface.ip_addresses.all():
                    ips.append(str(ip.address).split("/", 1)[0].strip().lower())
                lst.append({
                    "name": iface.name or "",
                    "mac": mac,
                    "ips": ips,
                    "mgmt_only": bool(getattr(iface, "mgmt_only", False)),
                })
            out[d.name or ""] = lst
    except Exception:
        logger.exception("NetBox interfaces for names failed")
    return out


def fetch_netbox_prefix_cidrs():
    """Set of prefix strings (CIDR) for coarse OpenStack subnet cross-check."""
    try:
        from ipam.models import Prefix

        return {str(p) for p in Prefix.objects.values_list("prefix", flat=True)}
    except Exception:
        logger.exception("NetBox prefix list failed")
        return set()


def fetch_netbox_data(
    netbox_url: str,
    netbox_token: str,
    base_url_fallback: str = "",
    *,
    ssl_verify: bool = True,
    ca_bundle: str | None = None,
):
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
        if url.startswith("https://"):
            if ca_bundle:
                nb.http_session.verify = ca_bundle
            elif not ssl_verify:
                nb.http_session.verify = False
                try:
                    import urllib3

                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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
