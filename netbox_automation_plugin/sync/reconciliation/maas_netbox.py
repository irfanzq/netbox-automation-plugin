"""
MAAS vs NetBox drift comparison (Phase 1: read-only).

Compares MAAS machines with NetBox devices by hostname; reports missing in NetBox,
orphans in NetBox, and counts.

MAAS hostnames are already normalized to short name in the MAAS client (FQDN trimmed
to part before first dot) so they match NetBox device names (hostname only).
"""

import logging

logger = logging.getLogger("netbox_automation_plugin.sync")


def _hostname_short(name):
    """Ensure we compare short hostname only (defense in depth)."""
    if not name:
        return ""
    return str(name).split(".", 1)[0].strip()


def compute_maas_netbox_drift(maas_data: dict, netbox_data: dict):
    """
    Compute drift between MAAS machines and NetBox devices.

    maas_data: from fetch_maas_data (machines list with hostname already normalized to short name)
    netbox_data: from fetch_netbox_data (devices list with name = hostname)

    Returns dict:
      - maas_hostnames: set of short hostnames in MAAS
      - netbox_names: set of device names in NetBox
      - in_maas_not_netbox: list of hostnames (MAAS machines with no matching NetBox device)
      - in_netbox_not_maas: list of names (NetBox devices with no matching MAAS machine — orphan candidates)
      - matched_count: number of hostnames present in both
      - maas_count, netbox_count
    """
    # Use short hostname for MAAS (client already normalizes; trim again here for safety)
    maas_hostnames = {
        _hostname_short(m.get("hostname") or "")
        for m in (maas_data.get("machines") or [])
        if _hostname_short(m.get("hostname") or "")
    }
    # NetBox device name is already short hostname
    netbox_names = {
        _hostname_short(d.get("name") or "")
        for d in (netbox_data.get("devices") or [])
        if _hostname_short(d.get("name") or "")
    }

    in_maas_not_netbox = sorted(maas_hostnames - netbox_names)
    in_netbox_not_maas = sorted(netbox_names - maas_hostnames)
    matched_count = len(maas_hostnames & netbox_names)

    return {
        "maas_hostnames": maas_hostnames,
        "netbox_names": netbox_names,
        "in_maas_not_netbox": in_maas_not_netbox,
        "in_netbox_not_maas": in_netbox_not_maas,
        "matched_count": matched_count,
        "maas_count": len(maas_hostnames),
        "netbox_count": len(netbox_names),
    }
