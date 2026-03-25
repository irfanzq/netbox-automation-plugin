"""
Richer drift detail: matched MAAS↔NetBox rows, OpenStack↔NetBox prefix hints.
"""

import logging
from collections import defaultdict
from typing import Dict, Optional

logger = logging.getLogger("netbox_automation_plugin.sync")


def _parse_vid(val) -> Optional[int]:
    """Numeric VLAN ID for comparison, or None if missing/non-numeric."""
    if val is None:
        return None
    s = str(val).strip()
    if not s or s == "—":
        return None
    try:
        return int(s, 10)
    except (ValueError, TypeError):
        return None


def _maas_iface_row_fabric(m: dict, mi: dict) -> str:
    """Per-NIC MAAS fabric (iface_fabric) with fallback to machine fabric_name."""
    f = (mi.get("iface_fabric") or "").strip()
    if f and f != "-":
        return f
    return (m.get("fabric_name") or "").strip()


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


def build_maas_netbox_interface_audit(
    matched_hostnames: set,
    maas_data: dict,
    netbox_ifaces: dict,
    netbox_audit=None,
    maas_iface_filter=None,
    openstack_data=None,
):
    """
    Line-by-line MAAS NIC vs NetBox interface (match by MAC). One entry per matched hostname.

    netbox_ifaces: hostname -> list of {name, mac, ips, mgmt_only}
    netbox_audit: hostname -> {site_slug, location_name, ...} for per-device context columns.
    maas_iface_filter: optional (machine_dict, iface_dict) -> bool; False drops the MAAS NIC from
        this audit. Default from views keeps only interfaces with a MAC (L2 identity for NB match).
    openstack_data: combined OpenStack payload; when runtime NIC rows are present, OS is
        authoritative for MAC/IP/VLAN on that MAC and MAAS is fallback.
    """
    by_h = {}
    for m in maas_data.get("machines") or []:
        h = (m.get("hostname") or "").strip()
        if h:
            by_h[h] = m

    nb_audit = netbox_audit or {}

    # hostname -> mac -> runtime row
    os_runtime_by_host_mac: dict[str, dict[str, dict]] = defaultdict(dict)
    for r in (openstack_data or {}).get("runtime_nics") or []:
        h = (r.get("hostname") or "").strip().lower()
        m = _normalize_mac(r.get("mac") or r.get("os_mac") or "")
        if not h or not m:
            continue
        prev = os_runtime_by_host_mac[h].get(m)
        if prev is None:
            os_runtime_by_host_mac[h][m] = r
            continue
        # Prefer richer runtime rows (with IP and VLAN).
        prev_score = int(bool(prev.get("os_ip"))) + int(bool(prev.get("os_runtime_vlan")))
        cur_score = int(bool(r.get("os_ip"))) + int(bool(r.get("os_runtime_vlan")))
        if cur_score >= prev_score:
            os_runtime_by_host_mac[h][m] = r
    hosts_out = []
    for hostname in sorted(matched_hostnames):
        m = by_h.get(hostname) or {}
        maas_ifaces = m.get("interfaces") or []
        nb_list = netbox_ifaces.get(hostname) or []
        nb_ctx = nb_audit.get(hostname) or {}
        ctx_site = (nb_ctx.get("site_slug") or "-")[:14]
        ctx_loc = (nb_ctx.get("location_name") or "-")[:16]
        os_region_default = (
            (openstack_data or {}).get("openstack_region_name") or "—"
        )[:32]
        m_fab = (m.get("fabric_name") or "-")[:14]
        m_pool = (m.get("pool_name") or "-")[:12]
        nb_by_mac = {}
        for nb in nb_list:
            k = _normalize_mac(nb.get("mac") or "")
            if k:
                nb_by_mac[k] = nb

        maas_macs_with_nic = set()
        rows = []
        for mi in maas_ifaces:
            if maas_iface_filter is not None:
                try:
                    if not maas_iface_filter(m, mi):
                        continue
                except Exception:
                    continue
            mac = _normalize_mac(mi.get("mac") or "")
            maas_name = mi.get("name") or "—"
            maas_ips = mi.get("ips") or []
            maas_ip_str = ", ".join(maas_ips) if maas_ips else "—"
            itype = (mi.get("type") or "")[:12]
            maas_vlan = str(mi.get("vlan_vid") or "")[:8] or "—"
            row_fab = (_maas_iface_row_fabric(m, mi) or m.get("fabric_name") or "-")[:14]

            if not mac:
                rows.append({
                    "maas_fabric": row_fab,
                    "maas_pool": m_pool,
                    "nb_site": ctx_site,
                    "nb_location": ctx_loc,
                    "maas_if": maas_name,
                    "maas_vlan": maas_vlan,
                    "maas_mac": "—",
                    "maas_ips": maas_ip_str,
                    "nb_if": "—",
                    "nb_vlan": "—",
                    "nb_mac": "—",
                    "nb_ips": "—",
                    "status": "MAAS_NO_MAC",
                    "notes": f"type={itype or '?'} (bond/vlan child — match parent MAC if needed)",
                })
                continue

            maas_macs_with_nic.add(mac)
            nb = nb_by_mac.get(mac)
            matched_by_name = False
            mac_mismatch_done = False
            if not nb and maas_name and str(maas_name).strip() not in ("", "—"):
                mn = str(maas_name).strip().lower()
                for cand in nb_list:
                    if (cand.get("name") or "").strip().lower() != mn:
                        continue
                    cmac = _normalize_mac(cand.get("mac") or "")
                    if not cmac:
                        nb = cand
                        matched_by_name = True
                    elif cmac != mac:
                        rows.append({
                            "maas_fabric": row_fab,
                            "maas_pool": m_pool,
                            "nb_site": ctx_site,
                            "nb_location": ctx_loc,
                            "maas_if": maas_name,
                            "maas_vlan": maas_vlan,
                            "maas_mac": mac,
                            "maas_ips": maas_ip_str,
                            "nb_if": cand.get("name") or "—",
                            "nb_vlan": str(cand.get("untagged_vlan_vid") or "")[:8] or "—",
                            "nb_mac": cmac,
                            "nb_ips": ", ".join(cand.get("ips") or []) or "—",
                            "status": "MAC_MISMATCH",
                            "notes": (
                                f"Same iface name as NetBox but MAC differs "
                                f"(NB={cmac} MAAS={mac})"
                            ),
                        })
                        mac_mismatch_done = True
                    else:
                        nb = cand
                    break
            if mac_mismatch_done:
                continue

            if not nb:
                n_mac = sum(1 for x in nb_list if _normalize_mac(x.get("mac") or ""))
                os_nib = os_runtime_by_host_mac.get(hostname.lower(), {}).get(mac) or {}
                os_mac_n = _normalize_mac(os_nib.get("os_mac") or os_nib.get("mac") or "")
                os_ip_list_n = [str(x).strip() for x in (os_nib.get("os_ips") or []) if str(x).strip()]
                if not os_ip_list_n and (os_nib.get("os_ip") or "").strip():
                    os_ip_list_n = [
                        x.strip() for x in str(os_nib.get("os_ip") or "").split(",") if x.strip()
                    ]
                os_vlan_n = str(os_nib.get("os_runtime_vlan") or "").strip()
                os_auth_n = bool(os_mac_n or os_ip_list_n or os_vlan_n)
                os_region_nib = str(os_nib.get("os_region") or "").strip() or os_region_default
                rows.append({
                    "maas_fabric": row_fab,
                    "maas_pool": m_pool,
                    "nb_site": ctx_site,
                    "nb_location": ctx_loc,
                    "os_region": os_region_nib,
                    "maas_if": maas_name,
                    "maas_vlan": maas_vlan,
                    "maas_mac": mac,
                    "maas_ips": maas_ip_str,
                    "os_mac": os_mac_n or "—",
                    "os_ip": ", ".join(os_ip_list_n) if os_ip_list_n else "—",
                    "os_runtime_vlan": os_vlan_n or "—",
                    "authority": "openstack_runtime" if os_auth_n else "maas_fallback",
                    "nb_if": "—",
                    "nb_vlan": "—",
                    "nb_mac": "—",
                    "nb_ips": "—",
                    "status": "NOT_IN_NETBOX",
                    "notes": (
                        f"No NetBox interface with this MAC. "
                        f"Device has {len(nb_list)} interface(s) in NetBox, "
                        f"{n_mac} with MAC set — fill MACs on NB or rename to match MAAS."
                    ),
                })
                continue

            nb_ips_set = set(nb.get("ips") or [])
            maas_ip_set = set(maas_ips)
            os_row = os_runtime_by_host_mac.get(hostname.lower(), {}).get(mac) or {}
            os_mac = _normalize_mac(os_row.get("os_mac") or os_row.get("mac") or "")
            os_ip_list = [str(x).strip() for x in (os_row.get("os_ips") or []) if str(x).strip()]
            if not os_ip_list and (os_row.get("os_ip") or "").strip():
                os_ip_list = [x.strip() for x in str(os_row.get("os_ip") or "").split(",") if x.strip()]
            os_ip_set = set(os_ip_list)
            os_vlan = str(os_row.get("os_runtime_vlan") or "").strip()
            os_region = str(os_row.get("os_region") or "").strip() or os_region_default

            os_authoritative = bool(os_mac or os_ip_set or os_vlan)
            base_ip_set = os_ip_set if os_authoritative else maas_ip_set
            missing_nb = base_ip_set - nb_ips_set
            nb_name = nb.get("name") or "—"
            nb_ip_str = ", ".join(nb.get("ips") or []) if nb.get("ips") else "—"
            nb_vlan = str(nb.get("untagged_vlan_vid") or "")[:8] or "—"
            mgmt = "mgmt" if nb.get("mgmt_only") else ""

            maas_v = _parse_vid(maas_vlan)
            os_v = _parse_vid(os_vlan)
            nb_v = _parse_vid(nb_vlan)

            notes = []
            if matched_by_name:
                notes.append(
                    f"Matched by interface name; NetBox MAC empty — set to {mac} for MAC-based audit"
                )
            vlan_drift = False
            if os_authoritative:
                # Runtime VLAN/IP from OpenStack is authoritative when present.
                if os_v is not None and nb_v is not None:
                    if os_v != nb_v:
                        vlan_drift = True
                        notes.append(f"vlan-drift(os): OpenStack VID {os_v} != NetBox untagged {nb_v}")
                elif os_v is not None and nb_v is None:
                    vlan_drift = True
                    notes.append(f"vlan-drift(os): OpenStack VID {os_v}; NetBox iface has no untagged VLAN")
                elif os_v is None and nb_v is not None:
                    notes.append(
                        f"OpenStack runtime VLAN unavailable for MAC {os_mac or mac}; "
                        f"NetBox untagged VID={nb_v} (kept as-is)"
                    )
            else:
                # Physical untagged VLAN: MAAS vs NetBox (DRIFT_DESIGN — tag vlan-drift)
                if maas_v is not None and nb_v is not None:
                    if maas_v != nb_v:
                        vlan_drift = True
                        notes.append(f"vlan-drift: MAAS VID {maas_v} != NetBox untagged {nb_v}")
                elif maas_v is not None and nb_v is None:
                    vlan_drift = True
                    notes.append(
                        f"vlan-drift: MAAS VID {maas_v}; NetBox iface has no untagged VLAN"
                    )
                elif maas_v is None and nb_v is not None:
                    notes.append(
                        f"VLAN unverified: NetBox untagged VID={nb_v}; MAAS VID not in API "
                        f"(UI often name-only — confirm in MAAS API/subnets)"
                    )

            if (maas_name or "").lower() != (nb_name or "").lower():
                notes.append(f"name: MAAS={maas_name} NB={nb_name}")
            if missing_nb:
                if os_authoritative:
                    notes.append(
                        f"IP on OpenStack runtime not on NB iface: {', '.join(sorted(missing_nb))}"
                    )
                else:
                    notes.append(f"IP on MAAS not on NB iface: {', '.join(sorted(missing_nb))}")
            if mgmt:
                notes.append(mgmt)
            extra_nb = nb_ips_set - base_ip_set
            if extra_nb and not missing_nb:
                notes.append(f"NB only IP: {', '.join(sorted(extra_nb)[:4])}")

            mac_mismatch = False
            if os_authoritative and os_mac and _normalize_mac(nb.get("mac") or ""):
                if _normalize_mac(nb.get("mac") or "") != os_mac:
                    mac_mismatch = True
                    notes.append(f"mac-drift(os): OpenStack MAC {os_mac} != NetBox {nb.get('mac') or '-'}")
            elif (not os_authoritative) and _normalize_mac(nb.get("mac") or ""):
                if _normalize_mac(nb.get("mac") or "") != mac:
                    mac_mismatch = True
                    notes.append(f"mac-drift: MAAS MAC {mac} != NetBox {nb.get('mac') or '-'}")

            if vlan_drift and missing_nb:
                status = "OS_RUNTIME_VLAN_DRIFT+IP_GAP" if os_authoritative else "VLAN_DRIFT+IP_GAP"
            elif vlan_drift:
                status = "OS_RUNTIME_VLAN_DRIFT" if os_authoritative else "VLAN_DRIFT"
            elif mac_mismatch:
                status = "OS_RUNTIME_MAC_MISMATCH" if os_authoritative else "MAC_MISMATCH"
            elif missing_nb:
                status = "OS_RUNTIME_IP_GAP" if os_authoritative else "IP_GAP"
            elif notes and any("name:" in n for n in notes):
                status = "OK_NAME_DIFF"
            else:
                status = "OK"

            nb_mac_stored = _normalize_mac(nb.get("mac") or "")
            if nb_mac_stored:
                nb_mac_out = nb_mac_stored
            elif matched_by_name:
                nb_mac_out = "—"
            else:
                nb_mac_out = mac

            rows.append({
                "maas_fabric": row_fab,
                "maas_pool": m_pool,
                "nb_site": ctx_site,
                "nb_location": ctx_loc,
                "os_region": os_region,
                "maas_if": maas_name,
                "maas_vlan": maas_vlan,
                "maas_mac": mac,
                "maas_ips": maas_ip_str,
                "os_mac": os_mac or "—",
                "os_ip": ", ".join(os_ip_list) if os_ip_list else "—",
                "os_runtime_vlan": os_vlan or "—",
                "authority": "openstack_runtime" if os_authoritative else "maas_fallback",
                "nb_if": nb_name,
                "nb_mac": nb_mac_out,
                "nb_vlan": nb_vlan,
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
            "nb_site": ctx_site,
            "nb_location": ctx_loc,
            "maas_fabric": m_fab,
            "maas_pool": m_pool,
            "rows": rows,
            "netbox_only": netbox_only,
        })

    return {"hosts": hosts_out}


def _place_match(a: str, b: str) -> bool:
    """Loose match: a contained in b or vice versa (for fabric/location/pool/site hints)."""
    a = (a or "").strip().lower()
    b = (b or "").strip().lower()
    if not a or not b or a == "-" or b == "-":
        return False
    return a in b or b in a


def _openstack_fip_by_fixed_ip(openstack_data: Optional[dict]) -> Dict[str, list]:
    m: dict[str, list] = defaultdict(list)
    if not openstack_data or openstack_data.get("error"):
        return m
    for f in openstack_data.get("floating_ips") or []:
        fix = (f.get("fixed_ip_address") or "").strip().lower()
        pub = (f.get("floating_ip_address") or "").strip()
        if fix and pub:
            m[fix].append(pub)
    return m


def build_maas_netbox_matched_rows(
    maas_data: dict, netbox_audit: dict, openstack_data: Optional[dict] = None
):
    """
    For each hostname present in both MAAS and netbox_audit, emit comparison row + hints.

    netbox_audit: name -> site_slug, location, status, serial, primary_mac,
      primary_ip4_host, vrf_name, vlan_vids_summary, device_ips (for FIP join).
    """
    fip_map = _openstack_fip_by_fixed_ip(openstack_data)
    os_runtime_by_h = {}
    for rb in (openstack_data or {}).get("runtime_bmc") or []:
        h = (rb.get("hostname") or "").strip()
        if h:
            os_runtime_by_h[h] = rb
    rows = []
    for m in maas_data.get("machines") or []:
        h = (m.get("hostname") or "").strip()
        if not h or h not in netbox_audit:
            continue
        nb = netbox_audit[h]
        hints = []
        zone = (m.get("zone_name") or "").strip().lower()
        pool = (m.get("pool_name") or "").strip().lower()
        fab = (m.get("fabric_name") or "").strip().lower()
        site = (nb.get("site_slug") or "").strip().lower()
        loc = (nb.get("location_name") or "").strip().lower()
        if site and pool and pool not in site and site not in pool and zone not in site:
            hints.append("site vs MAAS zone/pool")
        if fab and loc and not _place_match(fab, loc) and not _place_match(pool, loc):
            hints.append("MAAS fabric vs NB location — verify mapping")
        elif fab and not loc:
            hints.append("NB location empty — MAAS has fabric")
        osr = os_runtime_by_h.get(h) or {}
        maas_st = (m.get("status_name") or "").lower()
        nb_st = (nb.get("status") or "").lower()
        if maas_st and nb_st:
            # Suppress MAAS lifecycle hints when OS runtime lifecycle data exists.
            if not osr and "deployed" in maas_st and "staged" in nb_st:
                hints.append("MAAS deployed / NB staged — consider active")
            if "ready" in maas_st and "active" in nb_st:
                pass
        os_prov = (osr.get("provision_state") or "").strip().lower()
        os_power = (osr.get("power_state") or "").strip().lower()
        os_maint = bool(osr.get("maintenance", False))
        os_instance_uuid = (osr.get("instance_uuid") or "").strip()
        os_authority = "openstack_runtime" if osr else "maas_fallback"
        if osr:
            # OS-first lifecycle hints.
            if os_maint and "maintenance" not in nb_st:
                hints.append("OS maintenance / NB not maintenance — consider maintenance")
            elif os_prov == "active" and os_instance_uuid and "staged" in nb_st:
                hints.append("OS active+instance / NB staged — consider active")
            elif os_prov in {"available", "clean failed"} and "active" in nb_st:
                hints.append(f"OS {os_prov} / NB active — review lifecycle")
        if not nb.get("serial"):
            hints.append("NB serial empty — compare with MAAS inventory")
        maas_bmc = (m.get("bmc_ip") or "").strip()
        nb_oob = (nb.get("oob_ip_host") or "").strip()
        if maas_bmc and nb_oob and maas_bmc.lower() != nb_oob.lower():
            hints.append(f"MAAS BMC {maas_bmc} vs NetBox OOB {nb_oob}")
        match_ok = not hints
        fips = []
        for dip in nb.get("device_ips") or []:
            fips.extend(fip_map.get((dip or "").lower(), []))
        os_fip = ",".join(dict.fromkeys(fips))
        if len(os_fip) > 48:
            os_fip = os_fip[:46] + ".."
        rows.append({
            "hostname": h,
            "maas_zone": m.get("zone_name") or "-",
            "maas_fabric": m.get("fabric_name") or "-",
            "maas_pool": m.get("pool_name") or "-",
            "maas_status": m.get("status_name") or "-",
            "maas_serial": (m.get("serial") or "") or "(empty)",
            "netbox_site": nb.get("site_slug") or "-",
            "netbox_location": nb.get("location_name") or "-",
            "netbox_status": nb.get("status") or "-",
            "netbox_serial": (nb.get("serial") or "") or "(empty)",
            "netbox_primary_mac": nb.get("primary_mac") or "(none)",
            "netbox_primary_ip": nb.get("primary_ip4_host") or "—",
            "netbox_vrf": nb.get("vrf_name") or "Global",
            "netbox_vlans": nb.get("vlan_vids_summary") or "—",
            "openstack_fip": os_fip or "—",
            "os_authority": os_authority,
            "os_provision_state": os_prov or "—",
            "os_power_state": os_power or "—",
            "os_maintenance": "true" if os_maint else "false",
            "os_instance_uuid": os_instance_uuid or "—",
            "maas_bmc": maas_bmc or "—",
            "netbox_oob": nb_oob or "—",
            "place_match": "OK" if match_ok else "CHECK",
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
        n.get("id"): n
        for n in (openstack_data.get("networks") or [])
        if n.get("id")
    }
    consumers_by_sid = {
        (c.get("subnet_id") or ""): c
        for c in (openstack_data.get("subnet_consumers") or [])
        if c.get("subnet_id")
    }
    hints = []
    for sn in openstack_data.get("subnets") or []:
        cidr = (sn.get("cidr") or "").strip()
        if not cidr:
            continue
        nid = sn.get("network_id") or ""
        exact = cidr in netbox_prefixes
        net = net_by_id.get(nid) or {}
        cons = consumers_by_sid.get((sn.get("id") or "")) or {}
        hints.append({
            "cidr": cidr,
            "os_region": (sn.get("os_region") or openstack_data.get("openstack_region_name") or "—")[:32],
            "subnet_id": (sn.get("id") or "")[:36],
            "network_id": nid[:36] if nid else "",
            "network_name": (net.get("name") or "")[:48],
            "project_name": (sn.get("project_name") or sn.get("project_id") or "-")[:56],
            "gateway_ip": sn.get("gateway_ip") or "-",
            "ip_version": sn.get("ip_version") or "-",
            "provider_network_type": (net.get("provider_network_type") or "")[:24],
            "provider_segmentation_id": str(net.get("provider_segmentation_id") or ""),
            "provider_physical_network": (net.get("provider_physical_network") or "")[:40],
            "consumer_role_bucket": cons.get("role_bucket") or "",
            "consumer_role_reason": cons.get("role_reason") or "",
            "consumer_confidence": cons.get("confidence") or "",
            "consumer_ports_total": int(cons.get("ports_total") or 0),
            "consumer_top_owners": cons.get("top_owners") or "",
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

    net_by_id = {
        (n.get("id") or ""): n
        for n in (openstack_data.get("networks") or [])
        if n.get("id")
    }
    subnet_by_id = {
        (s.get("id") or ""): s
        for s in (openstack_data.get("subnets") or [])
        if s.get("id")
    }
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
            fnid = f.get("floating_network_id") or ""
            fnet = net_by_id.get(fnid) or {}
            subnet_name = "-"
            subnet_ids = fnet.get("subnets") or []
            if isinstance(subnet_ids, list):
                for sid in subnet_ids:
                    sn = subnet_by_id.get(str(sid) or "")
                    if sn and (sn.get("name") or "").strip():
                        subnet_name = (sn.get("name") or "").strip()
                        break
            missing.append({
                "floating_ip": ip,
                "os_region": (f.get("os_region") or openstack_data.get("openstack_region_name") or "—")[:32],
                "fixed_ip_address": f.get("fixed_ip_address") or "-",
                "id": f.get("id", ""),
                "port_id": f.get("port_id") or "",
                "project_name": f.get("project_name") or "-",
                "project_id": f.get("project_id") or "",
                "floating_network_id": fnid,
                "floating_network_name": fnet.get("name") or "-",
                "floating_subnet_name": subnet_name,
            })
    return missing
