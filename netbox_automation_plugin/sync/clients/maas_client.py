"""
MAAS client wrapper using python-libmaas.

Fetches machines, interfaces (NICs), zones, resource pools.
Used for drift audit and (later) MAAS -> NetBox reconciliation.

MAAS uses FQDN (hostname + domain, e.g. se-h1-23-gpu.pxe.spruce.whitefiber.com).
NetBox devices use short hostname only (e.g. se-h1-23-gpu).
We normalize MAAS hostname to the short name (part before first dot) for matching.
"""

import asyncio
import logging

logger = logging.getLogger("netbox_automation_plugin.sync")


def hostname_short(name):
    """
    Return the short hostname (before first dot) for matching with NetBox.
    MAAS can return FQDN; NetBox has hostname only. e.g.:
      se-h1-23-gpu.pxe.spruce.whitefiber.com -> se-h1-23-gpu
      se-h1-23-gpu -> se-h1-23-gpu
    """
    if not name:
        return ""
    return str(name).split(".", 1)[0].strip()


async def fetch_maas_data(maas_url: str, maas_api_key: str, maas_insecure: bool):
    """
    Fetch machines, zones, and pools from MAAS. Returns a dict with:
      - machines: list of {hostname, system_id, zone_name, pool_name}
      - zones: list of {name, id}
      - pools: list of {name, id}
      - error: str if connection failed
    """
    result = {"machines": [], "zones": [], "pools": [], "error": None}
    if not maas_url or not maas_api_key:
        result["error"] = "MAAS_URL and MAAS_API_KEY are required"
        return result

    try:
        from maas.client import connect
    except ImportError:
        result["error"] = "python-libmaas is not installed. Add it to plugin_requirements.txt and reinstall the plugin."
        return result

    try:
        client = await connect(maas_url, apikey=maas_api_key, insecure=maas_insecure)
    except Exception as e:
        logger.exception("MAAS connection failed")
        result["error"] = str(e)
        return result

    try:
        # Zones
        zones = await client.zones.list()
        for z in zones:
            result["zones"].append({"name": z.name, "id": getattr(z, "id", None)})

        # Pools
        pools = await client.resource_pools.list()
        for p in pools:
            result["pools"].append({"name": p.name, "id": getattr(p, "id", None)})

        # Machines (with zone and pool)
        machines = await client.machines.list()
        for m in machines:
            zone_name = "-"
            pool_name = "-"
            try:
                z = getattr(m, "zone", None)
                if z is not None:
                    zone_name = getattr(z, "name", str(z))
            except Exception:
                pass
            try:
                p = getattr(m, "pool", None)
                if p is not None:
                    pool_name = getattr(p, "name", str(p))
            except Exception:
                pass
            # MAAS may give hostname or fqdn; normalize to short name for NetBox matching
            raw_name = getattr(m, "hostname", "") or getattr(m, "fqdn", "")
            short_name = hostname_short(raw_name)
            result["machines"].append({
                "hostname": short_name,
                "fqdn": raw_name if raw_name != short_name else "",
                "system_id": getattr(m, "system_id", ""),
                "zone_name": zone_name,
                "pool_name": pool_name,
            })
    except Exception as e:
        logger.exception("MAAS fetch failed")
        result["error"] = str(e)

    return result


def fetch_maas_data_sync(maas_url: str, maas_api_key: str, maas_insecure: bool):
    """Synchronous wrapper for fetch_maas_data (for use from Django view)."""
    return asyncio.run(fetch_maas_data(maas_url, maas_api_key, maas_insecure))
