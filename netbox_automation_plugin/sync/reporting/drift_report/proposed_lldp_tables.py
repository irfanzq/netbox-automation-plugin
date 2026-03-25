"""OpenStack Ironic local_link (LLDP-style) vs NetBox interface cabling — proposed rows."""

from __future__ import annotations


def _norm_peer(s: str) -> str:
    t = " ".join((s or "").lower().split())
    for ch in "·|":
        t = t.replace(ch, " ")
    return " ".join(t.split())


def _find_nb_iface_for_mac(
    netbox_ifaces: dict | None, hostname: str, mac: str
) -> dict | None:
    if not netbox_ifaces or not hostname or not mac:
        return None
    h = (hostname or "").strip().lower()
    m = (mac or "").strip().lower().replace("-", ":")
    for row in netbox_ifaces.get(hostname) or netbox_ifaces.get(h) or []:
        if not isinstance(row, dict):
            continue
        rm = (row.get("mac") or "").strip().lower().replace("-", ":")
        if rm == m:
            return row
    for key, lst in netbox_ifaces.items():
        if (key or "").strip().lower() != h:
            continue
        for row in lst or []:
            if not isinstance(row, dict):
                continue
            rm = (row.get("mac") or "").strip().lower().replace("-", ":")
            if rm == m:
                return row
    return None


def build_lldp_drift_rows(openstack_data: dict | None, netbox_ifaces: dict | None) -> tuple[list, list]:
    """
    Compare Ironic local_link_connection (serialized as os_lldp on runtime_nics) to NetBox
    interface peer/cable summary (peer_summary).

    Returns:
      lldp_new: OS has link data; NetBox has no peer summary for that host+MAC.
      lldp_update: both have data but normalized strings differ.
    """
    lldp_new: list[list] = []
    lldp_update: list[list] = []
    if not openstack_data or openstack_data.get("error"):
        return lldp_new, lldp_update

    seen: set[tuple[str, str]] = set()
    for r in openstack_data.get("runtime_nics") or []:
        if not isinstance(r, dict):
            continue
        host = str(r.get("hostname") or "").strip()
        mac = str(r.get("mac") or r.get("os_mac") or "").strip().lower().replace("-", ":")
        if not host or not mac:
            continue
        os_lldp = str(r.get("os_lldp") or "").strip()
        if not os_lldp:
            continue
        key = (host.lower(), mac)
        if key in seen:
            continue
        seen.add(key)

        os_reg = str(r.get("os_region") or openstack_data.get("openstack_region_name") or "—").strip() or "—"
        nb = _find_nb_iface_for_mac(netbox_ifaces, host, mac)
        nb_peer = str((nb or {}).get("peer_summary") or "").strip()
        nb_site = str((nb or {}).get("nb_site") or "—").strip() or "—"
        nb_loc = str((nb or {}).get("nb_location") or "—").strip() or "—"
        nb_iface = str((nb or {}).get("name") or "—").strip() or "—"
        nb_mac = str((nb or {}).get("mac") or mac).strip() or mac

        if not nb_peer:
            lldp_new.append([
                host,
                os_reg,
                mac,
                os_lldp,
                "Document switch/port in NetBox (cable or interface description) from Ironic local link",
            ])
            continue

        if _norm_peer(nb_peer) != _norm_peer(os_lldp):
            lldp_update.append([
                host,
                os_reg,
                nb_site,
                nb_loc,
                nb_iface,
                nb_mac,
                nb_peer,
                os_mac,
                os_lldp,
                f"Align NetBox peer/cable with OpenStack Ironic: set to «{os_lldp[:180]}»" + (
                    "…" if len(os_lldp) > 180 else ""
                ),
            ])

    lldp_new.sort(key=lambda row: ((row[0] or "").lower(), row[2] or ""))
    lldp_update.sort(key=lambda row: ((row[0] or "").lower(), row[5] or ""))
    return lldp_new, lldp_update
