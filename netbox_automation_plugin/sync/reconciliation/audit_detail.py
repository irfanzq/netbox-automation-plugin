"""
Richer drift detail: matched MAAS↔NetBox rows, OpenStack↔NetBox prefix hints.
"""

import logging

logger = logging.getLogger("netbox_automation_plugin.sync")


def _normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    s = str(mac).strip().lower().replace("-", ":")
    parts = [p for p in s.split(":") if p]
    if len(parts) == 6:
        try:
            return ":".join(f"{int(p, 16):02x}" for p in parts)
        except ValueError:
            pass
    return s


def build_maas_netbox_interface_audit(matched_hostnames: set, maas_data: dict, netbox_ifaces: dict):
    """
    Line-by-line MAAS NIC vs NetBox interface (match by MAC). One entry per matched hostname.

    netbox_ifaces: hostname -> list of {name, mac, ips, mgmt_only}
    """
    by_h = {}
    for m in maas_data.get("machines") or []:
        h = (m.get("hostname") or "").strip()
        if h:
            by_h[h] = m

    hosts_out = []
    for hostname in sorted(matched_hostnames):
        m = by_h.get(hostname) or {}
        maas_ifaces = m.get("interfaces") or []
        nb_list = netbox_ifaces.get(hostname) or []
        nb_by_mac = {}
        for nb in nb_list:
            k = _normalize_mac(nb.get("mac") or "")
            if k:
                nb_by_mac[k] = nb

        maas_macs_with_nic = set()
        rows = []
        for mi in maas_ifaces:
            mac = _normalize_mac(mi.get("mac") or "")
            maas_name = mi.get("name") or "—"
            maas_ips = mi.get("ips") or []
            maas_ip_str = ", ".join(maas_ips) if maas_ips else "—"
            itype = (mi.get("type") or "")[:12]

            if not mac:
                rows.append({
                    "maas_if": maas_name,
                    "maas_mac": "—",
                    "maas_ips": maas_ip_str,
                    "nb_if": "—",
                    "nb_mac": "—",
                    "nb_ips": "—",
                    "status": "MAAS_NO_MAC",
                    "notes": f"type={itype or '?'} (bond/vlan child — match parent MAC if needed)",
                })
                continue

            maas_macs_with_nic.add(mac)
            nb = nb_by_mac.get(mac)
            if not nb:
                rows.append({
                    "maas_if": maas_name,
                    "maas_mac": mac,
                    "maas_ips": maas_ip_str,
                    "nb_if": "—",
                    "nb_mac": "—",
                    "nb_ips": "—",
                    "status": "NOT_IN_NETBOX",
                    "notes": "No NetBox interface with this MAC",
                })
                continue

            nb_ips_set = set(nb.get("ips") or [])
            maas_ip_set = set(maas_ips)
            missing_nb = maas_ip_set - nb_ips_set
            nb_name = nb.get("name") or "—"
            nb_ip_str = ", ".join(nb.get("ips") or []) if nb.get("ips") else "—"
            mgmt = "mgmt" if nb.get("mgmt_only") else ""

            notes = []
            if (maas_name or "").lower() != (nb_name or "").lower():
                notes.append(f"name: MAAS={maas_name} NB={nb_name}")
            if missing_nb:
                notes.append(f"IP on MAAS not on NB iface: {', '.join(sorted(missing_nb))}")
            if mgmt:
                notes.append(mgmt)
            extra_nb = nb_ips_set - maas_ip_set
            if extra_nb and not missing_nb:
                notes.append(f"NB only IP: {', '.join(sorted(extra_nb)[:4])}")

            if missing_nb:
                status = "IP_GAP"
            elif notes and any("name:" in n for n in notes):
                status = "OK_NAME_DIFF"
            else:
                status = "OK"

            rows.append({
                "maas_if": maas_name,
                "maas_mac": mac,
                "maas_ips": maas_ip_str,
                "nb_if": nb_name,
                "nb_mac": mac,
                "nb_ips": nb_ip_str,
                "status": status,
                "notes": "; ".join(notes) if notes else "—",
            })

        netbox_only = []
        for nb in nb_list:
            k = _normalize_mac(nb.get("mac") or "")
            if k and k not in maas_macs_with_nic:
                netbox_only.append(nb)

        hosts_out.append({
            "hostname": hostname,
            "rows": rows,
            "netbox_only": netbox_only,
        })

    return {"hosts": hosts_out}


def build_maas_netbox_matched_rows(maas_data: dict, netbox_audit: dict):
    """
    For each hostname present in both MAAS and netbox_audit, emit comparison row + hints.

    netbox_audit: name -> {site_slug, status, serial, primary_mac}
    """
    rows = []
    for m in maas_data.get("machines") or []:
        h = (m.get("hostname") or "").strip()
        if not h or h not in netbox_audit:
            continue
        nb = netbox_audit[h]
        hints = []
        zone = (m.get("zone_name") or "").strip().lower()
        pool = (m.get("pool_name") or "").strip().lower()
        site = (nb.get("site_slug") or "").strip().lower()
        if site and pool and pool not in site and site not in pool and zone not in site:
            hints.append("site vs MAAS zone/pool — verify site_mapping / design intent")
        maas_st = (m.get("status_name") or "").lower()
        nb_st = (nb.get("status") or "").lower()
        if maas_st and nb_st:
            if "deployed" in maas_st and "staged" in nb_st:
                hints.append("MAAS deployed but NetBox status staged — consider active")
            if "ready" in maas_st and "active" in nb_st:
                pass
        if not nb.get("serial"):
            hints.append("NetBox serial empty — MAAS has system_id for correlation")
        rows.append({
            "hostname": h,
            "maas_zone": m.get("zone_name") or "-",
            "maas_pool": m.get("pool_name") or "-",
            "maas_status": m.get("status_name") or "-",
            "maas_system_id": (m.get("system_id") or "")[:12],
            "netbox_site": nb.get("site_slug") or "-",
            "netbox_status": nb.get("status") or "-",
            "netbox_serial": (nb.get("serial") or "") or "(empty)",
            "netbox_primary_mac": nb.get("primary_mac") or "(none)",
            "hints": hints,
        })
    return sorted(rows, key=lambda r: r["hostname"])


def openstack_subnet_prefix_hints(openstack_data: dict, netbox_prefixes: set):
    """
    For each OpenStack subnet CIDR, note if an exact matching Prefix exists in NetBox.
    """
    if not openstack_data or openstack_data.get("error"):
        return []
    net_by_id = {
        n.get("id"): (n.get("name") or "")[:56]
        for n in (openstack_data.get("networks") or [])
        if n.get("id")
    }
    hints = []
    for sn in openstack_data.get("subnets") or []:
        cidr = (sn.get("cidr") or "").strip()
        if not cidr:
            continue
        nid = sn.get("network_id") or ""
        exact = cidr in netbox_prefixes
        hints.append({
            "cidr": cidr,
            "network_id": nid[:36] if nid else "",
            "network_name": net_by_id.get(nid, "")[:48],
            "exact_prefix_in_netbox": exact,
        })
    return hints


def openstack_subnets_missing_prefixes(os_subnet_hints: list):
    """Subnets with no exact NetBox Prefix (design: OpenStack → NetBox IPAM)."""
    return [h for h in (os_subnet_hints or []) if not h.get("exact_prefix_in_netbox")]


def openstack_floating_ips_missing_from_netbox(openstack_data: dict):
    """
    Floating IPs with no matching IPAddress in NetBox (design: runtime allocation visibility).
    Uses exact /32 or /128 match on address field.
    """
    if not openstack_data or openstack_data.get("error"):
        return []
    try:
        import netaddr as na
        from ipam.models import IPAddress
    except Exception as e:
        logger.warning("Floating IP vs NetBox check skipped: %s", e)
        return []

    missing = []
    for f in openstack_data.get("floating_ips") or []:
        ip = (f.get("floating_ip_address") or "").strip()
        if not ip or ip == "-":
            continue
        try:
            if ":" in ip:
                net = na.IPNetwork(f"{ip}/128")
            else:
                net = na.IPNetwork(f"{ip}/32")
        except Exception:
            continue
        try:
            exists = IPAddress.objects.filter(address=str(net)).exists()
        except Exception:
            exists = IPAddress.objects.filter(address=net).exists()
        if not exists:
            missing.append({
                "floating_ip": ip,
                "fixed_ip_address": f.get("fixed_ip_address") or "-",
                "id": f.get("id", ""),
            })
    return missing
