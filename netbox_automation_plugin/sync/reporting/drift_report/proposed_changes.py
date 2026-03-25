"""Proposed change buckets (NIC drift, new devices, prefixes, etc.)."""

from typing import Any

from netbox_automation_plugin.sync.reporting.drift_report.bmc_oob import (
    _build_proposed_mgmt_interface_rows,
    _suggested_netbox_mgmt_interface_name,
    _suggested_netbox_mgmt_interface_name_from_os,
)
from netbox_automation_plugin.sync.reporting.drift_report.device_types import (
    _build_device_type_match_index,
    _maas_vendor_product,
    _match_netbox_role_from_hostname,
    _resolve_device_type_display,
)
from netbox_automation_plugin.sync.reporting.drift_report.new_device_policy import (
    _new_device_candidate_policy,
    _new_device_fabric_display,
    _proposed_netbox_status_for_new_maas_device,
)
from netbox_automation_plugin.sync.reporting.drift_report.placement import (
    _maas_machine_by_hostname,
    _netbox_placement_from_maas_machine,
)
from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_drift import (
    _build_review_serial_rows,
    _build_update_nic_rows,
)
from netbox_automation_plugin.sync.reporting.drift_report.proposed_lldp_tables import (
    build_lldp_drift_rows,
)
from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_helpers import (
    _build_add_nb_interface_rows,
)


def _friendly_neutron_owners_line(owners: str) -> str:
    """Turn OpenStack top_owners like 'compute:nova:62, network:dhcp:3' into plain language."""
    o = (owners or "").strip()
    if not o or o == "-":
        return ""
    labels = {
        "compute:nova": "VM NICs (Nova)",
        "network:dhcp": "DHCP",
        "network:router_interface": "router link ports",
        "network:router_gateway": "internet gateway ports",
        "network:floatingip": "floating IP ports",
        "baremetal:none": "bare metal (Ironic)",
    }
    pieces = []
    for part in [p.strip() for p in o.split(",") if p.strip()][:3]:
        segs = part.split(":")
        if len(segs) < 2:
            continue
        try:
            n = int(segs[-1])
        except ValueError:
            continue
        key = ":".join(segs[:-1]).lower()
        label = labels.get(key, key.replace("_", " ").replace(":", " "))
        pieces.append(f"{label} ×{n}")
    if not pieces:
        return ""
    return "Port mix: " + ", ".join(pieces) + "."


def _friendly_prefix_role_summary(bucket: str, confidence: str, ports_total: int, owners: str) -> str:
    """Short, non-technical explanation for the proposed prefix role (HTML/XLSX)."""
    btxt = {
        "vm": "This looks like a normal tenant VM network.",
        "public": "This looks like a public or provider-external network.",
        "storage": "This looks storage-heavy (many storage-style instance names).",
        "admin": "This looks like an internal or admin-style network (DHCP/routers/services, not mainly VMs).",
    }.get((bucket or "").lower(), "Subnet type could not be summarized.")

    ctx = {
        "high": "We are fairly sure based on live OpenStack data.",
        "medium": "Reasonable default from OpenStack—verify if the role matters for your process.",
        "low": "Low certainty—treat the suggested role as a draft until you confirm.",
    }.get((confidence or "low").strip().lower(), "Certainty is limited.")

    if ports_total <= 0:
        port_bit = "No Neutron ports were counted for this subnet in the scan."
    else:
        port_bit = f"We counted {ports_total} Neutron port(s) on this subnet."

    extra = _friendly_neutron_owners_line(owners)
    return " ".join(x for x in (btxt, ctx, port_bit, extra) if x).strip()


def _openstack_ironic_bmc_row(openstack_data, hostname: str) -> dict | None:
    if not openstack_data or openstack_data.get("error"):
        return None
    h = (hostname or "").strip().lower()
    if not h:
        return None
    for row in openstack_data.get("runtime_bmc") or []:
        if (row.get("hostname") or "").strip().lower() == h:
            return row
    return None


# Sentinel: _maas_only_host_openstack_columns looks up Ironic row when not passed explicitly.
_IRONIC_BMC_ROW_LOOKUP = object()


def _maas_only_host_openstack_columns(
    openstack_data,
    hostname: str,
    *,
    ironic_bmc_row: Any = _IRONIC_BMC_ROW_LOOKUP,
) -> tuple[str, str, str, str]:
    """
    For MAAS-only new-device rows: Ironic lifecycle + catalog region when available.
    Returns: (os_region, os_provision, os_power, os_maintenance).
    Region falls back to any runtime NIC row, then merged openstack_region_name.
    Lifecycle fields are only filled when an Ironic (runtime_bmc) row exists for the host.
    Pass ironic_bmc_row=dict from _openstack_ironic_bmc_row to avoid a second runtime_bmc scan.
    Pass ironic_bmc_row=None when the caller already knows there is no Ironic row.
    """
    dash = "—"
    if ironic_bmc_row is _IRONIC_BMC_ROW_LOOKUP:
        osr = _openstack_ironic_bmc_row(openstack_data, hostname)
    else:
        osr = ironic_bmc_row  # dict | None
    if not openstack_data or openstack_data.get("error"):
        return dash, dash, dash, dash

    h = (hostname or "").strip().lower()
    region = dash
    if osr:
        region = str(osr.get("os_region") or "").strip() or region
    if region == dash and h:
        for nic in openstack_data.get("runtime_nics") or []:
            if (nic.get("hostname") or "").strip().lower() != h:
                continue
            r = str(nic.get("os_region") or "").strip()
            if r:
                region = r[:48]
                break
    if region == dash:
        top = str(openstack_data.get("openstack_region_name") or "").strip()
        region = top[:48] if top else dash

    if not osr:
        return region, dash, dash, dash

    prov = str(osr.get("provision_state") or "").strip().lower() or dash
    pwr = str(osr.get("power_state") or "").strip().lower() or dash
    maint = "true" if osr.get("maintenance") else "false"
    return region[:48], prov, pwr, maint


def _proposed_changes_rows(
    maas_data,
    netbox_data,
    drift,
    interface_audit,
    matched_rows,
    os_subnet_gaps,
    os_floating_gaps,
    openstack_data=None,
    netbox_ifaces=None,
):
    def _suggest_prefix_role(g: dict) -> tuple[str, str]:
        """
        Suggest best NetBox Prefix role from runtime consumer analysis.
        Returns: (role_name, reason)
        """
        roles = netbox_data.get("prefix_roles") or []
        bucket = (g.get("consumer_role_bucket") or "").strip().lower()
        confidence = (g.get("consumer_confidence") or "").strip().lower() or "low"
        ports_total = int(g.get("consumer_ports_total") or 0)
        owners = str(g.get("consumer_top_owners") or "-").strip()
        if bucket not in {"public", "storage", "vm", "admin"}:
            tail = ""
            if ports_total or (owners and owners != "-"):
                tail = f" ({ports_total} ports; top owners: {owners})"
            return (
                "REVIEW_REQUIRED",
                "OpenStack could not auto-sort this subnet into VM / public / storage / admin from port data. "
                "Pick a NetBox role manually after checking the network in OpenStack." + tail,
            )

        summary = _friendly_prefix_role_summary(bucket, confidence, ports_total, owners)

        wanted_tokens = {
            "public": ("openstack", "public"),
            "storage": ("openstack", "storage"),
            "vm": ("openstack", "vm"),
            "admin": ("openstack", "admin"),
        }.get(bucket, ("openstack", "vm"))

        def _score_role(role: dict) -> int:
            txt = f"{role.get('name', '')} {role.get('slug', '')}".lower()
            if not txt.strip():
                return -1
            score = 0
            if "openstack" in txt:
                score += 3
            for t in wanted_tokens:
                if t in txt:
                    score += 4
            return score

        ranked = sorted((r for r in roles), key=_score_role, reverse=True)
        if ranked and _score_role(ranked[0]) > 0:
            role = ranked[0].get("name") or ranked[0].get("slug") or "—"
            return role, summary
        fallback_name = {
            "public": "OpenStack Public",
            "storage": "OpenStack Storage",
            "vm": "OpenStack VM",
            "admin": "OpenStack Admin",
        }.get(bucket, "OpenStack VM")
        return fallback_name, summary

    def _cidr_start_end(cidr: str) -> tuple[str, str]:
        try:
            import ipaddress

            n = ipaddress.ip_network((cidr or "").strip(), strict=False)
            return str(n.network_address), str(n.broadcast_address)
        except Exception:
            return "-", "-"

    def _suggest_prefix_status(g: dict) -> str:
        """
        Suggested NetBox Prefix status for Detail — new prefixes rows.
        - reserved: zero Neutron ports counted for this subnet in the scan (unused, API gap, or not visible).
        - active: one or more ports seen (subnet in use in OpenStack).
        Role confidence belongs in Role reason only; never use deprecated here for "low confidence."
        """
        ports_total = int(g.get("consumer_ports_total") or 0)
        if ports_total <= 0:
            return "reserved"
        return "active"

    """Build user-friendly proposed change buckets (preview only)."""
    try:
        from netbox_automation_plugin.sync.config import get_sync_config

        _sync = get_sync_config()
        _fabric_site_map = _sync.get("site_mapping_fabric") or {}
        _pool_site_map = _sync.get("site_mapping_pool") or {}
    except Exception:
        _fabric_site_map, _pool_site_map = {}, {}

    def _build_vrf_lookup():
        try:
            import ipaddress
            from ipam.models import Prefix

            rows_v4 = []
            rows_v6 = []
            for p in Prefix.objects.select_related("vrf").only("prefix", "vrf_id", "vrf__name").iterator():
                pfx = str(getattr(p, "prefix", "") or "").strip()
                if not pfx:
                    continue
                try:
                    net = ipaddress.ip_network(pfx, strict=False)
                except Exception:
                    continue
                vrf_name = "Global"
                try:
                    if getattr(p, "vrf_id", None) and p.vrf:
                        vrf_name = (p.vrf.name or "Global").strip()
                except Exception:
                    vrf_name = "Global"
                rec = (net, vrf_name)
                if net.version == 4:
                    rows_v4.append(rec)
                else:
                    rows_v6.append(rec)
            rows_v4.sort(key=lambda r: r[0].prefixlen, reverse=True)
            rows_v6.sort(key=lambda r: r[0].prefixlen, reverse=True)
            return rows_v4, rows_v6
        except Exception:
            return [], []

    _vrf_lookup_v4, _vrf_lookup_v6 = _build_vrf_lookup()

    def _build_ipaddress_subnet_vrf_votes():
        """
        One pass over NetBox IPAddress rows: bucket by /24 (IPv4) or /64 (IPv6),
        tally VRF from each assignment (fallback when prefix data is thin).
        """
        from collections import Counter, defaultdict

        try:
            from ipam.models import IPAddress
        except Exception:
            return {}

        votes: dict[str, Counter] = defaultdict(Counter)
        try:
            for row in IPAddress.objects.select_related("vrf").only(
                "address", "vrf_id", "vrf__name"
            ).iterator(chunk_size=4000):
                addr_val = getattr(row, "address", None)
                if addr_val is None:
                    continue
                s = str(addr_val).strip()
                host = s.split("/", 1)[0].strip() if "/" in s else s
                try:
                    import ipaddress

                    ip_o = ipaddress.ip_address(host)
                except Exception:
                    continue
                if ip_o.version == 4:
                    net = ipaddress.ip_network(f"{ip_o}/24", strict=False)
                else:
                    net = ipaddress.ip_network(f"{ip_o}/64", strict=False)
                key = str(net)
                vrf_raw = "Global"
                try:
                    if getattr(row, "vrf_id", None) and row.vrf:
                        vrf_raw = (row.vrf.name or "Global").strip() or "Global"
                except Exception:
                    vrf_raw = "Global"
                votes[key][vrf_raw] += 1
        except Exception:
            return {}
        return dict(votes)

    _ip_subnet_vrf_votes = _build_ipaddress_subnet_vrf_votes()

    def _vrf_plurality_from_counter(ct):
        """Require either unanimous pair or 3+ assignments with a strict plurality."""
        from collections import Counter

        if not isinstance(ct, Counter) or not ct:
            return None
        total = sum(ct.values())
        if total < 2:
            return None
        ranked = ct.most_common()
        v1, n1 = ranked[0]
        n2 = ranked[1][1] if len(ranked) > 1 else 0
        if total >= 2 and n1 == total:
            return v1
        if total < 3:
            return None
        if n1 > n2:
            return v1
        return None

    def _adjacent_subnet_keys_v4(ip_obj):
        import ipaddress

        ip_int = int(ip_obj)
        center = ip_int & 0xFFFFFF00
        keys = []
        for delta in (-256, 0, 256):
            n = center + delta
            if n < 0 or n > 0xFFFFFFFF:
                continue
            keys.append(str(ipaddress.ip_network((n, 24))))
        return keys

    def _adjacent_subnet_keys_v6(ip_obj):
        import ipaddress

        ip_int = int(ip_obj)
        step = 1 << 64
        center = (ip_int // step) * step
        keys = []
        for delta in (-step, 0, step):
            v = center + delta
            if v < 0:
                continue
            try:
                keys.append(str(ipaddress.ip_network((ipaddress.IPv6Address(v), 64))))
            except Exception:
                continue
        return keys

    def _vrf_from_neighbor_ipaddresses(ip_obj):
        """
        Derive VRF from existing IPAddress objects in the same /24 (v4) or /64 (v6),
        merging the center subnet with immediately adjacent subnets so sparse segments
        can still reach 3+ samples when neighboring networks share the same routed context.
        """
        from collections import Counter

        merged = Counter()
        if ip_obj.version == 4:
            key_fn = _adjacent_subnet_keys_v4
        else:
            key_fn = _adjacent_subnet_keys_v6
        for k in key_fn(ip_obj):
            merged.update(_ip_subnet_vrf_votes.get(k, Counter()))
        picked = _vrf_plurality_from_counter(merged)
        return picked

    def _narrowest_containing_prefix_net(ip_obj):
        """Most specific NetBox prefix network containing ip_obj (IPv4Network / IPv6Network), or None."""
        rows = _vrf_lookup_v4 if ip_obj.version == 4 else _vrf_lookup_v6
        best_net = None
        best_pl = -1
        for net, _ in rows:
            if ip_obj not in net:
                continue
            pl = int(net.prefixlen)
            if pl > best_pl:
                best_pl = pl
                best_net = net
        return best_net

    def _vrf_from_longest_containing_prefix(ip_obj):
        """
        Most specific NetBox prefix that contains this IP (e.g. /25 wins over /22); uses that prefix's VRF.
        """
        from collections import Counter

        rows = _vrf_lookup_v4 if ip_obj.version == 4 else _vrf_lookup_v6
        best_pl = -1
        at_best = []
        for net, vrf_name in rows:
            if ip_obj not in net:
                continue
            pl = int(net.prefixlen)
            v = (vrf_name or "Global").strip() or "Global"
            if pl > best_pl:
                best_pl = pl
                at_best = [v]
            elif pl == best_pl:
                at_best.append(v)
        if best_pl < 0:
            return None
        return Counter(at_best).most_common(1)[0][0]

    def _netbox_ipaddress_vrf_for_host(ip_o):
        """VRF on the NetBox IPAddress row for this host, if any (/32 or /128 or host/prefix)."""
        try:
            import netaddr as na
            from ipam.models import IPAddress
        except Exception:
            return None
        host = str(ip_o)
        try:
            na_net = na.IPNetwork(f"{host}/32" if ip_o.version == 4 else f"{host}/128")
        except Exception:
            return None
        row = None
        try:
            row = IPAddress.objects.select_related("vrf").filter(address=str(na_net)).first()
        except Exception:
            pass
        if row is None:
            try:
                row = IPAddress.objects.select_related("vrf").filter(address=na_net).first()
            except Exception:
                row = None
        if row is None:
            try:
                row = IPAddress.objects.select_related("vrf").filter(address__startswith=f"{host}/").first()
            except Exception:
                row = None
        if not row:
            return None
        try:
            if getattr(row, "vrf_id", None) and row.vrf:
                return (row.vrf.name or "Global").strip() or "Global"
        except Exception:
            return "Global"
        return "Global"

    def _host_offsets_scan_v4(max_step: int):
        """Prefer lower neighbors first (.228 → .227, .226, …) then upward, as deployed ranges often cluster."""
        for d in range(-1, -max_step - 1, -1):
            yield d
        for d in range(1, max_step + 1):
            yield d

    def _host_offsets_scan_v6(max_step: int):
        for d in range(-1, -max_step - 1, -1):
            yield d
        for d in range(1, max_step + 1):
            yield d

    def _vrf_from_closest_netbox_ipaddresses(ip_obj, *, max_step: int = 24):
        """
        Walk numerically adjacent hosts (existing NetBox IPAddress rows), closest first.
        Neighbors must lie in the same narrowest NetBox prefix as ip_obj when that exists (e.g. stay in /25).
        Uses strict plurality when 2+ samples; a single existing neighbor still returns its VRF.
        """
        import ipaddress

        from collections import Counter

        boundary = _narrowest_containing_prefix_net(ip_obj)
        scanned = []
        if ip_obj.version == 4:
            gen = _host_offsets_scan_v4(max_step)
            vmax = 0xFFFFFFFF
        else:
            gen = _host_offsets_scan_v6(max_step)
            vmax = None
        for d in gen:
            try:
                n_int = int(ip_obj) + d
                if n_int < 0:
                    continue
                if vmax is not None and n_int > vmax:
                    continue
                n_ip = ipaddress.ip_address(n_int)
                if boundary is not None and n_ip not in boundary:
                    continue
            except Exception:
                continue
            vrf = _netbox_ipaddress_vrf_for_host(n_ip)
            if vrf is None:
                continue
            scanned.append(vrf)
            if len(scanned) >= 12:
                break
        if not scanned:
            return None
        if len(scanned) == 1:
            return scanned[0]
        c = Counter(scanned)
        v1, n1 = c.most_common(1)[0]
        n2 = c.most_common(2)[1][1] if len(c) > 1 else 0
        if n1 > n2:
            return v1
        return None

    def _vrf_from_seed_hosts_in_subnet(ip_obj):
        """
        Probe seeded hosts in the containing subnet before adjacency:
        first .1-.10, then .11-.20.
        """
        import ipaddress
        from collections import Counter

        boundary = _narrowest_containing_prefix_net(ip_obj)
        if boundary is None:
            # Fallback bucket when no prefix contains this IP.
            boundary = ipaddress.ip_network(
                f"{ip_obj}/24" if ip_obj.version == 4 else f"{ip_obj}/64",
                strict=False,
            )

        net_i = int(boundary.network_address)
        bcast_i = int(boundary.broadcast_address)
        for lo, hi in ((1, 10), (11, 20)):
            votes = []
            for off in range(lo, hi + 1):
                addr_i = net_i + off
                if addr_i >= bcast_i:
                    break
                try:
                    h = ipaddress.ip_address(addr_i)
                except Exception:
                    continue
                if h not in boundary:
                    continue
                vrf = _netbox_ipaddress_vrf_for_host(h)
                if vrf:
                    votes.append(vrf)
            if votes:
                return Counter(votes).most_common(1)[0][0]
        return None

    def _suggest_vrf_for_ip(ip_text: str) -> str:
        try:
            import ipaddress

            ip_obj = ipaddress.ip_address((ip_text or "").strip())
        except Exception:
            return "Global"
        lpm = _vrf_from_longest_containing_prefix(ip_obj)
        if lpm and lpm.lower() != "global":
            return lpm
        near = _vrf_from_closest_netbox_ipaddresses(ip_obj)
        if near:
            return near
        if lpm:
            return lpm
        nbr = _vrf_from_neighbor_ipaddresses(ip_obj)
        if nbr:
            return nbr
        return "Global"

    def _suggest_vrf_for_floating_ip_gap(g: dict) -> str:
        """
        Proposed FIP row VRF: prefer floating (public/WAN) IP first.
        For floating side, probe seeded subnet hosts first (.1-.10, then .11-.20),
        then fallback to longest-prefix / adjacent / bucket voting.
        """
        try:
            import ipaddress
        except Exception:
            ipaddress = None
        fip = str(g.get("floating_ip") or "").strip()
        fixed = str(g.get("fixed_ip_address") or "").strip()
        if fixed in {"", "-"}:
            fixed = ""
        if fip and ipaddress is not None:
            try:
                ip_o = ipaddress.ip_address(fip)
                vrf_seed = _vrf_from_seed_hosts_in_subnet(ip_o)
                if vrf_seed and vrf_seed != "Global":
                    return vrf_seed
            except Exception:
                pass
        vrf_pub = _suggest_vrf_for_ip(fip) if fip else "Global"
        if vrf_pub != "Global":
            return vrf_pub
        if not fixed:
            return vrf_pub
        vrf_fix = _suggest_vrf_for_ip(fixed)
        if vrf_fix != "Global":
            return vrf_fix
        return vrf_pub

    _prefix_vrf_names = [
        (v.get("name") or "").strip()
        for v in (netbox_data.get("vrfs") or [])
        if (v.get("name") or "").strip()
    ]

    def _suggest_vrf_for_prefix_gap(g: dict, selected_locations: list[str]) -> str:
        """
        Suggest VRF from OpenStack-side text first:
        network/subnet/project/region strings (plus selected location labels for tie-break).
        """
        blob = " ".join([
            str(g.get("network_name") or ""),
            str(g.get("project_name") or ""),
            str(g.get("os_region") or ""),
            str(g.get("cidr") or ""),
            " ".join(selected_locations or []),
        ]).lower()
        if not blob:
            return "Global"

        # Exact VRF-name substring in OS strings (preferred).
        for vrf in _prefix_vrf_names:
            vl = vrf.lower()
            if vl == "global":
                continue
            if vl and vl in blob:
                return vrf

        # Token fallback: any long VRF token appears in OS strings.
        for vrf in _prefix_vrf_names:
            vl = vrf.lower()
            if vl == "global":
                continue
            tokens = [t for t in vl.replace("-", " ").replace("_", " ").split() if len(t) >= 4]
            if tokens and any(t in blob for t in tokens):
                return vrf
        return "Global"

    def _primary_mac_from_maas(ifaces):
        rows = [r for r in (ifaces or []) if str(r.get("mac") or "").strip()]
        if not rows:
            return "—"
        with_ip = [r for r in rows if r.get("ips")]
        pick = with_ip[0] if with_ip else rows[0]
        return str(pick.get("mac") or "—")

    def _norm_mac_local(mac: str) -> str:
        s = (mac or "").strip().lower().replace("-", ":")
        parts = [p for p in s.split(":") if p]
        if len(parts) == 6:
            try:
                return ":".join(f"{int(p, 16):02x}" for p in parts)
            except ValueError:
                pass
        return s

    def _runtime_nic_index_by_host_mac(openstack_payload: dict | None) -> dict[tuple[str, str], dict]:
        idx: dict[tuple[str, str], dict] = {}
        for rr in (openstack_payload or {}).get("runtime_nics") or []:
            if not isinstance(rr, dict):
                continue
            h = (rr.get("hostname") or "").strip().lower()
            m = _norm_mac_local(rr.get("mac") or rr.get("os_mac") or "")
            if not h or not m:
                continue
            key = (h, m)
            prev = idx.get(key)
            if prev is None:
                idx[key] = rr
                continue
            prev_score = int(bool(prev.get("os_ip"))) + int(bool(prev.get("os_runtime_vlan")))
            cur_score = int(bool(rr.get("os_ip"))) + int(bool(rr.get("os_runtime_vlan")))
            if cur_score >= prev_score:
                idx[key] = rr
        return idx

    os_runtime_idx = _runtime_nic_index_by_host_mac(openstack_data)

    def _new_device_nic_rows():
        out = []
        for h in sorted(drift.get("in_maas_not_netbox") or []):
            m = by_h.get(h, {})
            _, nb_site, nb_loc = _netbox_placement_from_maas_machine(
                m, netbox_data, _fabric_site_map, _pool_site_map
            )
            for r in (m.get("interfaces") or []):
                mac = str(r.get("mac") or "").strip().lower()
                if not mac:
                    continue
                maas_if = str(r.get("name") or "").strip() or "—"
                maas_fab = str(r.get("iface_fabric") or m.get("fabric_name") or "—")
                ips = ", ".join(r.get("ips") or []) or "—"
                vlan = str(r.get("vlan_vid") or "—")
                suggested_name = (
                    maas_if
                    if maas_if != "—"
                    else f"maas-nic-{mac.replace(':', '')[-6:]}"
                )
                props = f"MAC {mac}; untagged VLAN {vlan} (from MAAS); IPs: {ips}"
                osr = os_runtime_idx.get(((h or "").strip().lower(), _norm_mac_local(mac))) or {}
                os_reg = str(
                    osr.get("os_region") or (openstack_data or {}).get("openstack_region_name") or "—"
                ).strip() or "—"
                os_mac = str(osr.get("os_mac") or osr.get("mac") or "—").strip() or "—"
                os_ip = str(osr.get("os_ip") or "").strip()
                if not os_ip:
                    _ips = [str(x).strip() for x in (osr.get("os_ips") or []) if str(x).strip()]
                    os_ip = ", ".join(_ips) if _ips else "—"
                os_vlan = str(osr.get("os_runtime_vlan") or "—").strip() or "—"
                os_has_runtime = bool(osr) and any(x not in {"", "—"} for x in [os_mac, os_ip, os_vlan])
                out.append(
                    [
                        h,
                        nb_site,
                        nb_loc,
                        maas_if,
                        maas_fab,
                        mac,
                        ips,
                        vlan,
                        os_reg,
                        os_mac,
                        os_ip,
                        os_vlan,
                        "[OS]" if os_has_runtime else "[MAAS]",
                        suggested_name,
                        props,
                        "Medium",
                    ]
                )
        return sorted(out, key=lambda x: (x[0] or "").lower())

    def _new_device_bmc_rows():
        out = []
        for h in sorted(drift.get("in_maas_not_netbox") or []):
            m = by_h.get(h, {})
            bmc_ip = str(m.get("bmc_ip") or "").strip()
            power_type = str(m.get("power_type") or "").strip()
            if not bmc_ip and not power_type:
                continue
            osr = _openstack_ironic_bmc_row(openstack_data, h) or {}
            os_bmc_ip = str(osr.get("os_bmc_ip") or "").strip()
            os_mgmt_type = str(
                osr.get("power_interface") or osr.get("management_interface") or osr.get("driver") or ""
            ).strip()
            maas_mgmt = _suggested_netbox_mgmt_interface_name(
                m.get("power_type"),
                m.get("hardware_vendor"),
                m.get("hardware_product"),
            )
            os_mgmt = _suggested_netbox_mgmt_interface_name_from_os(
                vendor=str(osr.get("vendor") or ""),
                driver=str(osr.get("driver") or ""),
                power_interface=str(osr.get("power_interface") or ""),
            )
            has_os_data = bool(osr) and bool(os_bmc_ip or os_mgmt_type)
            authority_badge = "[OS]" if has_os_data else "[MAAS]"
            mgmt = os_mgmt if bool(osr) else maas_mgmt
            action = (
                "CREATE_NETBOX_OOB_IFACE"
                + ("; SET_NETBOX_OOB_IP" if bmc_ip else "")
            )
            out.append(
                [
                    h,
                    os_bmc_ip or "—",
                    os_mgmt_type or "—",
                    bmc_ip or "—",
                    power_type or "—",
                    str(m.get("bmc_mac") or "—"),
                    mgmt,
                    bmc_ip or "—",
                    authority_badge,
                    action,
                    "Medium",
                ]
            )
        return sorted(out, key=lambda x: (x[0] or "").lower())

    by_h = _maas_machine_by_hostname(maas_data)
    _dtype_index = _build_device_type_match_index(netbox_data.get("device_types") or [])
    add_mgmt_iface = _build_proposed_mgmt_interface_rows(
        matched_rows, by_h, netbox_ifaces, openstack_data=openstack_data
    )
    add_mgmt_iface_new_devices = _new_device_bmc_rows()
    add_nb_interfaces = _build_add_nb_interface_rows(interface_audit) + _new_device_nic_rows()
    add_nb_interfaces = sorted(add_nb_interfaces, key=lambda x: (x[0] or "").lower())

    add_devices = []
    add_devices_review_only = []
    for h in sorted(drift.get("in_maas_not_netbox") or []):
        m = by_h.get(h, {})
        ifaces = m.get("interfaces") or []
        nic_count = sum(1 for r in ifaces if str(r.get("mac") or "").strip())
        primary_mac = _primary_mac_from_maas(ifaces)
        bmc_ip = str(m.get("bmc_ip") or "—")
        power_type = str(m.get("power_type") or "—")
        bmc_present = "Yes" if (bmc_ip not in {"", "—"} or power_type not in {"", "—"}) else "No"
        nb_region, nb_site, nb_loc = _netbox_placement_from_maas_machine(
            m, netbox_data, _fabric_site_map, _pool_site_map
        )
        mvendor, mproduct = _maas_vendor_product(m)
        nb_dtype = _resolve_device_type_display(mvendor, mproduct, _dtype_index)
        nb_role = _match_netbox_role_from_hostname(h, netbox_data)
        maas_fabric_disp = _new_device_fabric_display(str(m.get("fabric_name", "-")), nb_loc)
        is_candidate, note, status_rank = _new_device_candidate_policy(
            m, nic_count, vendor=mvendor, product=mproduct
        )
        osr = _openstack_ironic_bmc_row(openstack_data, h)
        os_reg, os_prov, os_pow, os_maint = _maas_only_host_openstack_columns(
            openstack_data, h, ironic_bmc_row=osr
        )
        # Ironic runtime_bmc row ⇒ correlated in OpenStack (any provision state). Active ⇒ [OS] authority.
        authority_badge = "[OS]" if os_prov == "active" else "[MAAS]"
        if is_candidate:
            proposed_tag = (
                "openstack+maas-discovered" if osr else "maas-discovered"
            )
        else:
            proposed_tag = "review-only"
        tail = [
            power_type,
            bmc_present,
            str(nic_count),
            primary_mac,
            authority_badge,
            proposed_tag,
            (
                "CREATE_NETBOX_DEVICE_AND_PORTS"
                if is_candidate
                else f"REVIEW_ONLY_NOT_SAFE_CANDIDATE ({note})"
            ),
        ]
        head_common = [
            h,
            nb_region,
            nb_site,
            nb_loc,
            os_reg,
            os_prov,
            os_pow,
            os_maint,
            nb_dtype,
            nb_role,
            maas_fabric_disp,
            str(m.get("status_name", "-")),
        ]
        serial = str(m.get("serial") or "—")
        if is_candidate:
            row = [
                *head_common,
                _proposed_netbox_status_for_new_maas_device(m),
                serial,
                *tail,
            ]
            add_devices.append((status_rank, h.lower(), row))
        else:
            row = [*head_common, serial, *tail]
            add_devices_review_only.append((status_rank, h.lower(), row))

    add_devices = [r for _, _, r in sorted(add_devices, key=lambda x: (x[0], x[1]))]
    add_devices_review_only = [
        r for _, _, r in sorted(add_devices_review_only, key=lambda x: (x[0], x[1]))
    ]

    scope_meta = (drift or {}).get("scope_meta") or {}
    selected_locations = list(scope_meta.get("selected_locations") or [])
    add_prefixes = []
    for g in (os_subnet_gaps or []):
        role_name, role_reason = _suggest_prefix_role(g)
        vrf_name = _suggest_vrf_for_prefix_gap(g, selected_locations)
        start_addr, end_addr = _cidr_start_end(g.get("cidr", ""))
        add_prefixes.append([
            g.get("os_region") or "—",
            g.get("cidr", ""),
            start_addr,
            end_addr,
            g.get("project_name", "-"),
            role_name,
            _suggest_prefix_status(g),
            vrf_name,
            role_reason,
            "[OS]",
            "CREATE_NETBOX_PREFIX_FROM_OS",
        ])

    add_fips = []
    for g in (os_floating_gaps or []):
        fip = g.get("floating_ip", "")
        fip_name = g.get("floating_subnet_name") or g.get("floating_network_name") or "-"
        nb_vrf = _suggest_vrf_for_floating_ip_gap(g)
        nb_status = "active" if str(g.get("port_id") or "").strip() else "reserved"
        add_fips.append([
            g.get("os_region") or "—",
            fip,
            fip_name,
            g.get("fixed_ip_address", "-"),
            g.get("project_name") or g.get("project_id") or "-",
            nb_status,
            "VIP",
            nb_vrf,
            "NetBox VRF: floating IP first (public side): probe .1-.10, then .11-.20 in that subnet; fallback longest prefix/adjacent IPs/subnet bucket; fixed IP only as fallback",
            "CREATE_NETBOX_IPADDRESS_FROM_OS_FIP",
        ])

    update_nic = _build_update_nic_rows(interface_audit)
    review_serial = _build_review_serial_rows(matched_rows)
    lldp_new, lldp_update = build_lldp_drift_rows(openstack_data, netbox_ifaces, maas_data)

    return {
        "add_devices": add_devices,
        "add_devices_review_only": add_devices_review_only,
        "add_prefixes": add_prefixes,
        "add_fips": add_fips,
        "lldp_new": lldp_new,
        "lldp_update": lldp_update,
        "update_nic": update_nic,
        "add_nb_interfaces": add_nb_interfaces,
        "add_mgmt_iface": add_mgmt_iface,
        "add_mgmt_iface_new_devices": add_mgmt_iface_new_devices,
        "review_serial": review_serial,
    }
