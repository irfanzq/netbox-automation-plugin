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
    proposed_netbox_status_for_new_maas_machine,
)
from netbox_automation_plugin.sync.reporting.drift_report.placement import (
    _maas_machine_by_hostname,
    _netbox_placement_from_maas_machine,
)
from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_derived import (
    NIC_DRIFT_AUTHORITY_COL_INDEX,
    bmc_row_proposed_defaults,
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
from netbox_automation_plugin.sync.clients.openstack_client import (
    DRIFT_TENANT_LABEL_REPLACING_ADMIN,
)
from netbox_automation_plugin.sync.reconciliation.audit_detail import (
    openstack_floating_ips_nat_inside_drift,
)


def _vm_project_label_for_proposals(inst: dict) -> str:
    """OpenStack project column for VM drift rows; map admin scope to operator default tenant."""
    raw = str(inst.get("project_name") or inst.get("project_id") or "-").strip()
    if raw.lower() == "admin":
        return DRIFT_TENANT_LABEL_REPLACING_ADMIN
    return raw if raw else "-"


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


def _first_meaningful_text(*vals: Any) -> str:
    for v in vals:
        s = str(v or "").strip()
        if s and s not in {"-", "—"}:
            return s
    return "-"


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


def _os_host_authority_map(openstack_data) -> dict[str, bool]:
    out: dict[str, bool] = {}
    for row in (openstack_data or {}).get("runtime_bmc") or []:
        if not isinstance(row, dict):
            continue
        h = (row.get("hostname") or "").strip().lower()
        if not h:
            continue
        out[h] = _os_is_authoritative_for_host(row)
    return out


def _os_is_authoritative_for_host(osr: dict | None) -> bool:
    """
    Host-level OpenStack authority gate for lifecycle/provisioning columns.

    Rule:
    - require instance_uuid (non-empty)
    - require provisioning_state in trusted set
    """
    if not osr:
        return False
    instance_uuid = str(osr.get("instance_uuid") or "").strip()
    if not instance_uuid:
        return False
    prov = str(osr.get("provision_state") or "").strip().lower()
    # Keep explicit and conservative: active is deployed; available with instance UUID
    # is treated as authoritative per operator policy for this environment.
    return prov in {"active", "available"}


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
    os_ip_range_gaps,
    os_floating_gaps,
    openstack_data=None,
    netbox_ifaces=None,
    os_subnet_hints=None,
):
    def _suggest_scope_location_from_os_region(os_region: str) -> str:
        reg = str(os_region or "").strip().lower()
        if not reg or reg in {"-", "—"}:
            return "—"
        locs = netbox_data.get("locations") or []
        exact = []
        fuzzy = []
        for row in locs:
            if not isinstance(row, dict):
                continue
            nm = str(row.get("name") or "").strip()
            ss = str(row.get("site_slug") or "").strip()
            if not nm:
                continue
            nl = nm.lower()
            sl = ss.lower()
            if nl == reg or sl == reg:
                exact.append(nm)
            elif reg in nl or nl in reg or reg in sl or sl in reg:
                fuzzy.append(nm)
        cand = exact or fuzzy
        return sorted(set(cand))[0] if cand else "—"

    def _suggest_netbox_site_name_from_os_region(os_region: str) -> str:
        """
        NetBox **Site** display name for VM placement (matches ``Site.name`` / apply_cells).

        OpenStack region strings often align with a **Location** name (e.g. Birch under site B52).
        ``_suggest_scope_location_from_os_region`` returns that location label — wrong for
        ``NB proposed site``. We match sites by name/slug first, then map matching locations
        to their parent site via ``site_slug`` → site name from ``netbox_data["sites"]``.
        """
        reg = str(os_region or "").strip().lower()
        if not reg or reg in {"-", "—"}:
            return "—"
        sites = netbox_data.get("sites") or []
        slug_to_site_name: dict[str, str] = {}
        for row in sites:
            if not isinstance(row, dict):
                continue
            nm = str(row.get("name") or "").strip()
            sl = str(row.get("slug") or "").strip()
            if sl and nm:
                slug_to_site_name[sl.lower()] = nm
        exact_site: list[str] = []
        fuzzy_site: list[str] = []
        for row in sites:
            if not isinstance(row, dict):
                continue
            nm = str(row.get("name") or "").strip()
            sl = str(row.get("slug") or "").strip()
            if not nm and not sl:
                continue
            nl = nm.lower()
            ssl = sl.lower()
            if nl == reg or ssl == reg:
                exact_site.append(nm)
            elif reg in nl or nl in reg or reg in ssl or ssl in reg:
                fuzzy_site.append(nm)
        cand_sites = exact_site or fuzzy_site
        if cand_sites:
            return sorted({x for x in cand_sites if x})[0]
        locs = netbox_data.get("locations") or []
        exact_loc: list[dict] = []
        fuzzy_loc: list[dict] = []
        for row in locs:
            if not isinstance(row, dict):
                continue
            nm = str(row.get("name") or "").strip()
            ss = str(row.get("site_slug") or "").strip()
            if not nm:
                continue
            nl = nm.lower()
            ssl = ss.lower()
            if nl == reg or ssl == reg:
                exact_loc.append(row)
            elif reg in nl or nl in reg or reg in ssl or ssl in reg:
                fuzzy_loc.append(row)
        loc_rows = exact_loc or fuzzy_loc
        parent_names: list[str] = []
        for row in loc_rows:
            ss = str(row.get("site_slug") or "").strip()
            if not ss:
                continue
            site_nm = slug_to_site_name.get(ss.lower())
            if site_nm:
                parent_names.append(site_nm)
        if parent_names:
            return sorted(set(parent_names))[0]
        return "—"

    def _suggest_vlan_from_os_segmentation_id(seg_id: Any) -> str:
        s = str(seg_id or "").strip()
        if not s or s in {"-", "—"}:
            return "—"
        try:
            vid = int(s)
        except Exception:
            return s
        for v in (netbox_data.get("vlans") or []):
            try:
                if int(v.get("vid")) == vid:
                    return str(v.get("display") or f"{v.get('name') or ''} ({vid})").strip()
            except Exception:
                continue
        return str(vid)

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

    def _floating_aligned_container_net(ip_obj):
        """
        For floating-IP VRF hints, align to classic routed blocks (IPv4 /24, IPv6 /64) so
        seeded .1-.10 are x.y.z.1-10 in the same /24 as the floating IP — not the narrowest
        NetBox Prefix (e.g. /25) whose *prefix* VRF may differ from host assignments.
        """
        import ipaddress

        if ip_obj.version == 4:
            return ipaddress.ip_network(f"{ip_obj}/24", strict=False)
        return ipaddress.ip_network(f"{ip_obj}/64", strict=False)

    def _vrf_counter_pick_winner(ct):
        """Plurality; on ties prefer a non-Global VRF."""
        from collections import Counter

        if not isinstance(ct, Counter) or not ct:
            return None
        mc = ct.most_common()
        top_n = mc[0][1]
        tops = [v for v, n in mc if n == top_n]
        if len(tops) == 1:
            return tops[0]
        for v in tops:
            if (v or "").strip().lower() != "global":
                return v
        return tops[0]

    def _vrf_from_floating_aligned_seed_ips(ip_obj):
        """
        Probe .1-.10 then .11-.20 inside the floating IP's /24 (v4) or /64 (v6).
        VRF comes only from existing NetBox IPAddress rows (not Prefix VRF).
        """
        import ipaddress
        from collections import Counter

        boundary = _floating_aligned_container_net(ip_obj)
        net_i = int(boundary.network_address)
        bcast_i = int(boundary.broadcast_address)
        for lo, hi in ((1, 10), (11, 20)):
            votes = []
            for off in range(lo, hi + 1):
                addr_i = net_i + off
                if addr_i > bcast_i:
                    break
                try:
                    h = ipaddress.ip_address(addr_i)
                except Exception:
                    continue
                if h not in boundary:
                    continue
                vrf = _netbox_ipaddress_vrf_for_host(h)
                if vrf is not None:
                    votes.append(vrf)
            if votes:
                picked = _vrf_counter_pick_winner(Counter(votes))
                if picked:
                    return picked
        return None

    def _vrf_from_longest_containing_prefix(ip_obj):
        """
        Longest-prefix match (LPM): most specific NetBox prefix containing this IP (/25 beats /24 beats /22).
        Not “shortest” aggregate — always the longest (tightest) matching mask; uses that prefix's VRF.
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

    _exact_aligned_prefix_vrf_memo: dict[str, str | None] = {}

    def _vrf_from_exact_aligned_prefix(align):
        """
        VRF from NetBox Prefix(es) whose CIDR exactly matches the floating-aligned /24 (v4)
        or /64 (v6)—not a parent /22. When NetBox has duplicate prefixes for the same CIDR
        (e.g. Spruce vs BGP), prefer the design row: tenant / VLAN / role / description set,
        then non-"BGP" VRF as a last tie-break.
        """
        key = str(align)
        if key in _exact_aligned_prefix_vrf_memo:
            return _exact_aligned_prefix_vrf_memo[key]
        try:
            from ipam.models import Prefix
        except Exception:
            _exact_aligned_prefix_vrf_memo[key] = None
            return None

        def _row_vrf_name(p):
            try:
                if getattr(p, "vrf_id", None) and p.vrf:
                    return (p.vrf.name or "Global").strip() or "Global"
            except Exception:
                pass
            return "Global"

        def _design_score(p):
            s = 0
            if getattr(p, "tenant_id", None):
                s += 8
            if getattr(p, "vlan_id", None):
                s += 4
            if getattr(p, "role_id", None):
                s += 4
            if (getattr(p, "description", None) or "").strip():
                s += 2
            return s

        try:
            rows = list(
                Prefix.objects.filter(prefix=key)
                .select_related("vrf", "tenant", "role", "vlan")[:64]
            )
        except Exception:
            _exact_aligned_prefix_vrf_memo[key] = None
            return None
        if not rows:
            _exact_aligned_prefix_vrf_memo[key] = None
            return None
        try:
            rows.sort(
                key=lambda p: (
                    -_design_score(p),
                    1 if _row_vrf_name(p).lower() == "bgp" else 0,
                    _row_vrf_name(p).lower(),
                )
            )
            vn = _row_vrf_name(rows[0])
            out = vn if vn.lower() != "global" else None
            _exact_aligned_prefix_vrf_memo[key] = out
            return out
        except Exception:
            _exact_aligned_prefix_vrf_memo[key] = None
            return None

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

    def _vrf_from_closest_netbox_ipaddresses(
        ip_obj, *, max_step: int = 24, boundary_net=None
    ):
        """
        Walk numerically adjacent hosts (existing NetBox IPAddress rows), closest first.
        When ``boundary_net`` is set, neighbors must stay inside it (e.g. /24 for floating hints).
        Otherwise use the narrowest NetBox Prefix containing ``ip_obj``.
        Uses strict plurality when 2+ samples; a single existing neighbor still returns its VRF.
        """
        import ipaddress

        from collections import Counter

        boundary = boundary_net if boundary_net is not None else _narrowest_containing_prefix_net(ip_obj)
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

    def _suggest_vrf_for_floating_address(ip_text: str) -> str:
        """
        Prefer NetBox IPAddress evidence in the floating /24|/64 first (seed .1-.20,
        then closest neighbors in-block). If the block has no usable host rows, use VRF
        from Prefix row(s) for that *exact* /24|/64 (duplicate CIDRs: prefer rich design
        row over bare BGP stub), then longest-prefix match (LPM) on the floating IP
        (/25 beats /24), then adjacent /24 or /64 bucket plurality.
        """
        try:
            import ipaddress
        except Exception:
            return "Global"
        t = (ip_text or "").strip()
        if not t:
            return "Global"
        try:
            ip_o = ipaddress.ip_address(t)
        except Exception:
            return "Global"
        align = _floating_aligned_container_net(ip_o)
        v = _vrf_from_floating_aligned_seed_ips(ip_o)
        if v:
            return v
        v = _vrf_from_closest_netbox_ipaddresses(ip_o, max_step=24, boundary_net=align)
        if v:
            return v
        v_exact = _vrf_from_exact_aligned_prefix(align)
        if v_exact and (v_exact or "").strip().lower() != "global":
            return v_exact
        lpm_host = _vrf_from_longest_containing_prefix(ip_o)
        if lpm_host and (lpm_host or "").strip().lower() != "global":
            return lpm_host
        v = _vrf_from_neighbor_ipaddresses(ip_o)
        if v:
            return v
        return "Global"

    def _suggest_vrf_for_floating_ip_gap(g: dict) -> str:
        """
        Proposed FIP row VRF: aligned-block IPAddress seeds and neighbors, then exact /24 or /64
        Prefix VRF (duplicate tie-break), then LPM on the floating IP (longest match,
        e.g. /25 over /24), adjacent bucket vote, then OpenStack name tokens vs NetBox VRFs.
        """
        fip = str(g.get("floating_ip") or "").strip()
        fixed = str(g.get("fixed_ip_address") or "").strip()
        if fixed in {"", "-"}:
            fixed = ""
        vrf_pub = _suggest_vrf_for_floating_address(fip) if fip else "Global"
        if vrf_pub != "Global":
            return vrf_pub
        if not fixed:
            return _suggest_vrf_from_floating_gap_os_names(g)
        vrf_fix = _suggest_vrf_for_floating_address(fixed)
        if vrf_fix != "Global":
            return vrf_fix
        return _suggest_vrf_from_floating_gap_os_names(g)

    _prefix_vrf_names = [
        (v.get("name") or "").strip()
        for v in (netbox_data.get("vrfs") or [])
        if (v.get("name") or "").strip()
    ]

    _FIP_OS_VRF_STOPWORDS = frozenset({
        "openstack",
        "network",
        "subnet",
        "neutron",
        "external",
        "public",
        "private",
        "floating",
        "pool",
        "the",
        "and",
        "for",
        "with",
        "from",
    })

    def _suggest_vrf_from_floating_gap_os_names(g: dict) -> str:
        """
        Match floating_network_name / floating_subnet_name / project_name (and region)
        against NetBox VRF names: full-name substring in OS text first, then score VRFs
        by how many distinct non-trivial tokens from the OS text appear in each VRF name.
        Ties: longer VRF name wins (typically more specific, e.g. Birch + WAN + BGP).
        """
        import re

        blob = " ".join([
            str(g.get("floating_network_name") or ""),
            str(g.get("floating_subnet_name") or ""),
            str(g.get("project_name") or ""),
            str(g.get("os_region") or ""),
        ]).lower()
        if not blob.strip():
            return "Global"
        for vrf in _prefix_vrf_names:
            vl = vrf.lower()
            if vl == "global":
                continue
            if vl and vl in blob:
                return vrf
        tokens = sorted({
            t
            for t in re.findall(r"[a-z0-9]+", blob)
            if len(t) >= 3 and t not in _FIP_OS_VRF_STOPWORDS
        })
        if not tokens:
            return "Global"
        best_score = 0
        best_vrfs = []
        for vrf in _prefix_vrf_names:
            vl = vrf.lower()
            if vl == "global":
                continue
            score = sum(1 for t in tokens if t in vl)
            if score > best_score:
                best_score = score
                best_vrfs = [vrf]
            elif score == best_score and score > 0:
                best_vrfs.append(vrf)
        if best_score <= 0 or not best_vrfs:
            return "Global"
        if len(best_vrfs) == 1:
            return best_vrfs[0]
        best_vrfs.sort(key=lambda v: (-len(v), v.lower()))
        return best_vrfs[0]

    def _suggest_vrf_for_prefix_gap(g: dict, selected_locations: list[str]) -> str:
        """
        Suggest VRF from OpenStack-side text first:
        network/subnet/project/region strings (plus selected location labels for tie-break).
        """
        blob = " ".join([
            str(g.get("subnet_name") or ""),
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
    os_host_authority = _os_host_authority_map(openstack_data)

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
                props = f"MAC {mac}; untagged VLAN {vlan}; IPs: {ips}"
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
                host_os_ok = os_host_authority.get((h or "").strip().lower(), False)
                os_has_runtime = (
                    bool(osr)
                    and host_os_ok
                    and any(x not in {"", "—"} for x in [os_mac, os_ip, os_vlan])
                )
                if os_has_runtime:
                    # OS authority: Proposed properties reflect runtime only (MAAS columns still show MAAS).
                    props = f"MAC {os_mac}; untagged VLAN {os_vlan}; IPs: {os_ip}"
                from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_derived import (
                    derive_nic_proposed_columns,
                    parse_os_lldp_structured,
                )

                vn = str(r.get("vlan_name") or "").strip()
                if not vn:
                    vv = r.get("vlan")
                    if isinstance(vv, dict):
                        vn = str(vv.get("name") or "").strip()
                os_parts = parse_os_lldp_structured(osr)
                audit_like = {
                    "maas_mac": mac,
                    "maas_link_speed": r.get("link_speed") or r.get("speed"),
                    "maas_nic_vendor": str(r.get("vendor") or ""),
                    "maas_nic_product": str(r.get("product") or ""),
                    "maas_vlan_name": vn,
                    "os_lldp_switch": os_parts.get("switch") or "—",
                    "maas_lldp_switch": (str(r.get("maas_lldp_switch") or "").strip() or "—"),
                    "os_switch_info": os_parts.get("switch") or "—",
                }
                ex = derive_nic_proposed_columns(
                    h, audit_like, bmc_mac=_norm_mac_local(str(m.get("bmc_mac") or ""))
                )
                out.append(
                    [
                        h,
                        maas_if,
                        maas_fab,
                        mac,
                        ips,
                        vlan,
                        ex["maas_link_speed_disp"],
                        ex["maas_nic_model"],
                        ex["os_lldp_switch_disp"],
                        ex["maas_lldp_switch_disp"],
                        os_reg,
                        os_mac,
                        os_ip,
                        os_vlan,
                        nb_site,
                        nb_loc,
                        ex["nb_proposed_intf_label"],
                        ex["nb_proposed_intf_type"],
                        suggested_name,
                        props,
                        "[OS]" if os_has_runtime else "[MAAS]",
                        "Medium",
                    ]
                )
        return sorted(out, key=lambda x: (x[0] or "").lower())

    def _new_device_bmc_rows():
        from netbox_automation_plugin.sync.reconciliation.audit_detail import _normalize_mac

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
            host_os_ok = os_host_authority.get((h or "").strip().lower(), False)
            has_os_data = bool(osr) and host_os_ok and bool(os_bmc_ip or os_mgmt_type)
            os_vendor = str(osr.get("vendor") or "").strip() or "—"
            os_model = str(osr.get("model") or osr.get("product") or osr.get("hardware_model") or "").strip() or "—"
            maas_vendor = str(m.get("hardware_vendor") or "").strip() or "—"
            maas_product = str(m.get("hardware_product") or "").strip() or "—"
            authority_badge = "[OS]" if has_os_data else "[MAAS]"
            mgmt = os_mgmt if bool(osr) else maas_mgmt
            target_ip = os_bmc_ip if has_os_data and os_bmc_ip else bmc_ip
            action_parts = [f"CREATE_NETBOX_OOB_IFACE={mgmt or 'mgmt0'}"]
            if target_ip:
                action_parts.append(f"SET_NETBOX_OOB_IP={target_ip}")
            action = "; ".join(action_parts)
            bmc_mac_hint = str(m.get("bmc_mac") or "").strip()
            mac_norm = _normalize_mac(bmc_mac_hint) if bmc_mac_hint else ""
            if mac_norm and "SET_NETBOX_OOB_MAC=" not in action:
                action += f"; SET_NETBOX_OOB_MAC={mac_norm}"
            bx = bmc_row_proposed_defaults(m)
            if maas_vendor not in ("—", "") and maas_product not in ("—", ""):
                bx["maas_nic_model"] = f"{maas_vendor[:32]} / {maas_product[:64]}"
            elif maas_vendor not in ("—", ""):
                bx["maas_nic_model"] = maas_vendor[:96]
            elif maas_product not in ("—", ""):
                bx["maas_nic_model"] = maas_product[:96]
            out.append(
                [
                    h,
                    bmc_ip or "—",
                    power_type or "—",
                    maas_vendor,
                    maas_product,
                    str(m.get("bmc_mac") or "—"),
                    bx["maas_link_speed_disp"],
                    bx["maas_nic_model"],
                    os_bmc_ip or "—",
                    os_mgmt_type or "—",
                    os_vendor,
                    os_model,
                    bx["os_lldp_switch_disp"],
                    bx["maas_lldp_switch_disp"],
                    bx["nb_proposed_intf_label"],
                    bx["nb_proposed_intf_type"],
                    mgmt,
                    str(target_ip or "").strip() or "—",
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
        hn = (h or "").strip().lower()
        primary_mac_os = "—"
        pmn = (
            _norm_mac_local(primary_mac)
            if str(primary_mac).strip() not in {"", "—", "-"}
            else ""
        )
        if pmn and hn:
            hit = os_runtime_idx.get((hn, pmn))
            if hit:
                primary_mac_os = (
                    str(hit.get("os_mac") or hit.get("mac") or "—").strip() or "—"
                )
        if str(primary_mac_os).strip() in {"", "—", "-"} and hn and openstack_data and not (
            openstack_data.get("error")
        ):
            for nic in openstack_data.get("runtime_nics") or []:
                if (nic.get("hostname") or "").strip().lower() != hn:
                    continue
                om = str(nic.get("os_mac") or nic.get("mac") or "").strip()
                if om and om not in {"—", "-"}:
                    primary_mac_os = om
                    break
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
        is_candidate, _, status_rank = _new_device_candidate_policy(
            m, nic_count, vendor=mvendor, product=mproduct
        )
        osr = _openstack_ironic_bmc_row(openstack_data, h)
        os_reg, os_prov, os_pow, os_maint = _maas_only_host_openstack_columns(
            openstack_data, h, ironic_bmc_row=osr
        )
        # OpenStack authority is state-gated and requires instance_uuid.
        authority_badge = "[OS]" if _os_is_authoritative_for_host(osr) else "[MAAS]"
        if is_candidate:
            proposed_tag = (
                "openstack+maas-discovered" if osr else "maas-discovered"
            )
        else:
            proposed_tag = "review-only"
        nb_prop_state = proposed_netbox_status_for_new_maas_machine(m, osr)
        serial = str(m.get("serial") or "—")
        action = (
            "CREATE_NETBOX_DEVICE_AND_PORTS"
            if is_candidate
            else "REVIEW_ONLY_NOT_SAFE_CANDIDATE"
        )
        row = [
            h,
            maas_fabric_disp,
            str(m.get("status_name", "-")),
            serial,
            power_type,
            bmc_present,
            str(nic_count),
            primary_mac,
            os_reg,
            os_prov,
            os_pow,
            os_maint,
            primary_mac_os,
            nb_region,
            nb_site,
            nb_loc,
            nb_dtype,
            nb_role,
            nb_prop_state,
            proposed_tag,
            authority_badge,
            action,
        ]
        if is_candidate:
            add_devices.append((status_rank, h.lower(), row))
        else:
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
        # Match CLI: `openstack subnet list` Name column (Neutron subnet name), not network name.
        os_desc = _first_meaningful_text(g.get("subnet_name"), g.get("network_name"))
        tenant_name = str(
            g.get("project_owner_name")
            or g.get("project_name")
            or g.get("project_id")
            or "-"
        )
        nb_scope = _suggest_scope_location_from_os_region(g.get("os_region") or "")
        nb_vlan = _suggest_vlan_from_os_segmentation_id(g.get("provider_segmentation_id"))
        add_prefixes.append([
            g.get("os_region") or "—",
            g.get("cidr", ""),
            os_desc,
            g.get("project_name", "-"),
            os_desc,
            tenant_name,
            nb_scope,
            nb_vlan,
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
        fip_name = _first_meaningful_text(
            g.get("floating_subnet_name"),
            g.get("floating_network_name"),
        )
        tenant_name = _first_meaningful_text(
            g.get("project_owner_name"),
            g.get("project_name"),
            g.get("project_id"),
        )
        nb_vrf = _suggest_vrf_for_floating_ip_gap(g)
        nb_status = "active" if str(g.get("port_id") or "").strip() else "reserved"
        add_fips.append([
            g.get("os_region") or "—",
            fip,
            fip_name,
            g.get("fixed_ip_address", "-"),
            g.get("project_name") or g.get("project_id") or "-",
            tenant_name,
            nb_status,
            "VIP",
            nb_vrf,
            "CREATE_NETBOX_IPADDRESS_FROM_OS_FIP",
        ])

    update_prefixes: list[list] = []
    try:
        from ipam.models import Prefix as _PrefixModel
    except Exception:
        _PrefixModel = None

    if _PrefixModel is not None and (os_subnet_hints or []) and openstack_data and not openstack_data.get(
        "error"
    ):
        for g in os_subnet_hints or []:
            if not g.get("exact_prefix_in_netbox"):
                continue
            cidr = (g.get("cidr") or "").strip()
            if not cidr:
                continue
            role_name, role_reason = _suggest_prefix_role(g)
            vrf_name = _suggest_vrf_for_prefix_gap(g, selected_locations)
            sugg_status = _suggest_prefix_status(g)
            os_desc = _first_meaningful_text(g.get("subnet_name"), g.get("network_name"))
            tenant_name = str(
                g.get("project_owner_name")
                or g.get("project_name")
                or g.get("project_id")
                or "-"
            )
            nb_scope = _suggest_scope_location_from_os_region(g.get("os_region") or "")
            nb_vlan = _suggest_vlan_from_os_segmentation_id(g.get("provider_segmentation_id"))
            try:
                candidates = list(
                    _PrefixModel.objects.filter(prefix=cidr).select_related("vrf", "role", "tenant")
                )
            except Exception:
                candidates = []
            if not candidates:
                continue
            p = None
            for cand in candidates:
                cv = "Global"
                if cand.vrf_id:
                    cv = (cand.vrf.name or "Global").strip() or "Global"
                if cv == vrf_name:
                    p = cand
                    break
            if p is None:
                p = candidates[0]
            cur_vrf = "Global"
            if p.vrf_id:
                cur_vrf = (p.vrf.name or "Global").strip() or "Global"
            cur_role = (p.role.name if getattr(p, "role_id", None) else "—")
            cur_status = str(getattr(p, "status", "") or "").strip()
            cur_tenant = "—"
            if hasattr(p, "tenant_id") and getattr(p, "tenant_id", None) and getattr(p, "tenant", None):
                cur_tenant = (p.tenant.name or "—").strip() or "—"
            cur_desc = ((p.description or "").strip())[:200]
            drift_parts: list[str] = []
            if cur_vrf != vrf_name:
                drift_parts.append(f"VRF {cur_vrf!r} → {vrf_name!r}")
            if cur_status.lower() != (sugg_status or "").lower():
                drift_parts.append(f"status {cur_status!r} → {sugg_status!r}")
            if (cur_role or "—") != (role_name or "—"):
                drift_parts.append(f"role {cur_role!r} → {role_name!r}")
            ct = (cur_tenant or "—").strip()
            tt = (tenant_name or "—").strip()
            if ct != tt and tt not in {"—", "-", ""}:
                drift_parts.append("tenant")
            if cur_desc != (os_desc or "").strip()[:200] and (os_desc or "").strip():
                drift_parts.append("description")
            if not drift_parts:
                continue
            drift_summary = "; ".join(drift_parts)
            update_prefixes.append([
                g.get("os_region") or "—",
                cidr,
                os_desc,
                g.get("project_name", "-"),
                cur_vrf,
                cur_status or "—",
                cur_role or "—",
                cur_tenant,
                cur_desc or "—",
                os_desc,
                tenant_name,
                nb_scope,
                nb_vlan,
                role_name,
                sugg_status,
                vrf_name,
                drift_summary,
                role_reason,
                "[OS]",
                "UPDATE_NETBOX_PREFIX_FROM_OS",
            ])

    update_fips: list[list] = []
    nat_rows = (
        openstack_floating_ips_nat_inside_drift(openstack_data or {})
        if openstack_data and not openstack_data.get("error")
        else []
    )
    for d in nat_rows:
        fip = d.get("floating_ip", "")
        fip_name = _first_meaningful_text(
            d.get("floating_subnet_name"),
            d.get("floating_network_name"),
        )
        tenant_name = _first_meaningful_text(
            d.get("project_owner_name"),
            d.get("project_name"),
            d.get("project_id"),
        )
        nb_vrf = _suggest_vrf_for_floating_ip_gap(d)
        nb_status = "active" if str(d.get("port_id") or "").strip() else "reserved"
        update_fips.append([
            d.get("nb_current_nat_inside") or "—",
            d.get("os_region") or "—",
            fip,
            fip_name,
            d.get("fixed_ip_address", "-"),
            d.get("project_name") or d.get("project_id") or "-",
            tenant_name,
            nb_status,
            "VIP",
            nb_vrf,
            "UPDATE_NETBOX_IPADDRESS_NAT_FROM_OS_FIP",
        ])

    add_openstack_vms: list[list] = []
    update_openstack_vms: list[list] = []

    def _ip_host_norm(s: str) -> str:
        t = (s or "").strip()
        if not t or t in {"—", "-"}:
            return ""
        return t.split("/", 1)[0].strip().lower()

    def _vm_netbox_primary_display(vm) -> str:
        try:
            if getattr(vm, "primary_ip4_id", None) and vm.primary_ip4:
                return str(vm.primary_ip4.address)
            if getattr(vm, "primary_ip6_id", None) and vm.primary_ip6:
                return str(vm.primary_ip6.address)
        except Exception:
            pass
        return "—"

    def _os_vm_status_nb_slug(os_status: str) -> str:
        m = {
            "ACTIVE": "active",
            "SHUTOFF": "offline",
            "PAUSED": "paused",
            "SUSPENDED": "suspended",
            "ERROR": "failed",
            "BUILD": "staging",
            "BUILDING": "staging",
            "DELETED": "decommissioning",
            "SOFT_DELETED": "decommissioning",
            "SHELVED": "decommissioning",
            "SHELVED_OFFLOADED": "decommissioning",
            "UNKNOWN": "offline",
            "RESCUE": "failed",
            "RESIZE": "active",
            "VERIFY_RESIZE": "active",
            "MIGRATING": "active",
            "HARD_REBOOT": "active",
            "REBOOT": "active",
            "PASSWORD": "active",
            "REBUILD": "staging",
        }
        return m.get((os_status or "").strip().upper(), "active")

    try:
        from virtualization.models import VirtualMachine as _VMModel
    except Exception:
        _VMModel = None

    instances = (openstack_data or {}).get("compute_instances") or []
    if _VMModel is not None and instances and openstack_data and not openstack_data.get("error"):
        for inst in instances:
            iname = str(inst.get("name") or "").strip()
            if not iname:
                continue
            os_reg = str(inst.get("os_region") or openstack_data.get("openstack_region_name") or "—")[:48]
            proj = _vm_project_label_for_proposals(inst)
            hv = str(inst.get("hypervisor_hostname") or "").strip() or "—"
            # Column "NB proposed device (VM)" is always the Nova instance name (same as VM name).
            # Hypervisor hostname column holds the compute host; apply tries that name if no Device matches the VM name.
            prop_dev = iname
            os_st = str(inst.get("status") or "").strip() or "—"
            nb_vm_status = _os_vm_status_nb_slug(os_st)
            reg_token = os_reg.replace(",", " ").strip().split()[0] if os_reg.strip() else ""
            prop_cluster = f"{reg_token}-openstack" if reg_token and reg_token not in {"—", "-"} else "openstack"
            os_pri = str(inst.get("os_primary_ip") or "").strip()
            prop_pri = os_pri if os_pri else "—"
            try:
                _VMModel._meta.get_field("site")
                _vm_rel = ("cluster", "tenant", "device", "site", "primary_ip4", "primary_ip6")
            except Exception:
                _vm_rel = ("cluster", "tenant", "device", "primary_ip4", "primary_ip6")
            vm = _VMModel.objects.filter(name=iname).select_related(*_vm_rel).first()
            nb_site = "—"
            if vm is not None and getattr(vm, "site_id", None) and getattr(vm, "site", None):
                nb_site = (vm.site.name or "").strip() or "—"
            if nb_site in {"—", ""}:
                nb_site = _suggest_netbox_site_name_from_os_region(os_reg)
            if vm is None:
                add_openstack_vms.append([
                    iname,
                    os_reg,
                    os_st,
                    proj,
                    hv,
                    prop_pri,
                    prop_cluster,
                    nb_site if nb_site not in {"—", ""} else "—",
                    proj if proj not in {"-", "—"} else "—",
                    nb_vm_status,
                    prop_dev if prop_dev not in {"—", ""} else "—",
                    "[OS]",
                    "CREATE_NETBOX_VM_FROM_OPENSTACK",
                ])
            else:
                cur_vc = str(vm.vcpus) if vm.vcpus is not None else "—"
                cur_mm = str(vm.memory) if vm.memory is not None else "—"
                cur_dg = str(vm.disk) if vm.disk is not None else "—"
                cur_pri_disp = _vm_netbox_primary_display(vm)
                cur_nb_host = _ip_host_norm(cur_pri_disp)
                os_pri_host = _ip_host_norm(os_pri)
                cur_cl = vm.cluster.name if vm.cluster_id else "—"
                cur_dev = "—"
                if getattr(vm, "device_id", None) and vm.device:
                    cur_dev = (vm.device.name or "—").strip() or "—"
                cur_vm_st = str(vm.status) if vm.status is not None else "—"
                drift_vm: list[str] = []
                iname_l = iname.strip().lower()
                hv_l = (hv or "").strip().lower()
                if hv_l in {"—", "-", ""}:
                    hv_l = ""
                valid_dev_names = {x for x in (iname_l, hv_l) if x}
                cur_dn = ""
                if getattr(vm, "device_id", None) and vm.device:
                    cur_dn = (vm.device.name or "").strip().lower()
                if valid_dev_names:
                    if not cur_dn or cur_dn not in valid_dev_names:
                        drift_vm.append("device")
                if str(vm.status).lower() != nb_vm_status.lower():
                    drift_vm.append("status")
                if prop_cluster and cur_cl != prop_cluster:
                    drift_vm.append("cluster")
                if os_pri_host:
                    if not cur_nb_host or os_pri_host != cur_nb_host:
                        drift_vm.append("primary_ip")
                if not drift_vm:
                    continue
                update_openstack_vms.append([
                    iname,
                    str(vm.pk),
                    os_reg,
                    os_st,
                    proj,
                    hv,
                    cur_vc,
                    cur_mm,
                    cur_dg,
                    cur_pri_disp,
                    cur_cl,
                    cur_dev,
                    cur_vm_st,
                    prop_pri,
                    prop_cluster,
                    nb_site if nb_site not in {"—", ""} else "—",
                    proj if proj not in {"-", "—"} else "—",
                    nb_vm_status,
                    prop_dev if prop_dev not in {"—", ""} else "—",
                    ", ".join(drift_vm),
                    "[OS]",
                    "UPDATE_NETBOX_VM_FROM_OPENSTACK",
                ])

    # Temporarily disabled per operator request: do not emit allocation-pool IPRange proposals.
    add_ip_ranges = []

    update_nic = _build_update_nic_rows(interface_audit)
    # Enforce host-level authority gate across NIC drift rows:
    # - non-authoritative OS host: never keep OS-only NIC rows
    # - remaining rows on that host are treated as MAAS fallback authority
    _nic_drift_auth_col = NIC_DRIFT_AUTHORITY_COL_INDEX
    filtered_update_nic = []
    for row in update_nic:
        if len(row) <= _nic_drift_auth_col:
            filtered_update_nic.append(row)
            continue
        host = (row[0] or "").strip().lower()
        host_os_ok = os_host_authority.get(host, False)
        if not host_os_ok:
            maas_mac = str(row[3] or "").strip().lower()
            maas_if = str(row[1] or "").strip()
            maas_seen = bool(maas_mac and maas_mac not in {"—", "-", "none"}) or bool(
                maas_if and maas_if not in {"—", "-", "none"}
            )
            if not maas_seen:
                # OS-only observation for non-authoritative host: skip from drift updates.
                continue
            row[_nic_drift_auth_col] = "[MAAS]"
        filtered_update_nic.append(row)
    update_nic = filtered_update_nic
    review_serial = _build_review_serial_rows(matched_rows)
    lldp_new, lldp_update = build_lldp_drift_rows(openstack_data, netbox_ifaces, maas_data)

    return {
        "add_devices": add_devices,
        "add_devices_review_only": add_devices_review_only,
        "add_prefixes": add_prefixes,
        "add_ip_ranges": add_ip_ranges,
        "add_fips": add_fips,
        "update_prefixes": update_prefixes,
        "update_fips": update_fips,
        "add_openstack_vms": add_openstack_vms,
        "update_openstack_vms": update_openstack_vms,
        "lldp_new": lldp_new,
        "lldp_update": lldp_update,
        "update_nic": update_nic,
        "add_nb_interfaces": add_nb_interfaces,
        "add_mgmt_iface": add_mgmt_iface,
        "add_mgmt_iface_new_devices": add_mgmt_iface_new_devices,
        "review_serial": review_serial,
    }
