"""Proposed change buckets (NIC drift, new devices, prefixes, etc.)."""

from netbox_automation_plugin.sync.reporting.drift_report.bmc_oob import (
    _build_proposed_mgmt_interface_rows,
    _suggested_netbox_mgmt_interface_name,
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
from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_helpers import (
    _build_add_nb_interface_rows,
)


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
        reason = (
            str(g.get("consumer_role_reason") or "").strip()
            or "consumer data unavailable; manual role review required"
        )
        if bucket not in {"public", "storage", "vm", "admin"}:
            return "REVIEW_REQUIRED", f"no reliable consumer bucket (owners: {owners})"

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
            return role, f"{reason}; confidence={confidence}; ports={ports_total}; owners={owners}"
        fallback_name = {
            "public": "OpenStack Public",
            "storage": "OpenStack Storage",
            "vm": "OpenStack VM",
            "admin": "OpenStack Admin",
        }.get(bucket, "OpenStack VM")
        return fallback_name, f"{reason}; confidence={confidence}; ports={ports_total}; owners={owners}"

    def _cidr_start_end(cidr: str) -> tuple[str, str]:
        try:
            import ipaddress

            n = ipaddress.ip_network((cidr or "").strip(), strict=False)
            return str(n.network_address), str(n.broadcast_address)
        except Exception:
            return "-", "-"

    def _suggest_prefix_status(g: dict) -> str:
        ports_total = int(g.get("consumer_ports_total") or 0)
        conf = str(g.get("consumer_confidence") or "").strip().lower()
        if ports_total <= 0:
            return "reserved"
        if conf in {"high", "medium"}:
            return "active"
        return "deprecated"

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

    def _suggest_vrf_for_ip(ip_text: str, *, context: str = "") -> str:
        try:
            import ipaddress

            ip_obj = ipaddress.ip_address((ip_text or "").strip())
        except Exception:
            return "Global"
        rows = _vrf_lookup_v4 if ip_obj.version == 4 else _vrf_lookup_v6
        for net, vrf_name in rows:
            if ip_obj in net:
                return vrf_name or "Global"
        # Fallback: map by context tokens to existing NetBox VRF names.
        ctx = (context or "").lower()
        vrfs = [str(v.get("name") or "").strip() for v in (netbox_data.get("vrfs") or []) if str(v.get("name") or "").strip()]
        def _pick(token: str):
            for n in vrfs:
                if token in n.lower():
                    return n
            return ""
        if any(t in ctx for t in ("bgp", "wan", "transit", "external")):
            picked = _pick("bgp") or _pick("wan")
            if picked:
                return picked
        return "Global"

    def _primary_mac_from_maas(ifaces):
        rows = [r for r in (ifaces or []) if str(r.get("mac") or "").strip()]
        if not rows:
            return "—"
        with_ip = [r for r in rows if r.get("ips")]
        pick = with_ip[0] if with_ip else rows[0]
        return str(pick.get("mac") or "—")

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
            mgmt = _suggested_netbox_mgmt_interface_name(
                m.get("power_type"),
                m.get("hardware_vendor"),
                m.get("hardware_product"),
            )
            action = (
                "CREATE_NETBOX_OOB_IFACE"
                + ("; SET_NETBOX_OOB_IP" if bmc_ip else "")
            )
            out.append(
                [
                    h,
                    bmc_ip or "—",
                    power_type or "—",
                    str(m.get("bmc_mac") or "—"),
                    mgmt,
                    bmc_ip or "—",
                    "—",
                    "—",
                    "—",
                    "[MAAS]",
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
        tail = [
            power_type,
            bmc_present,
            str(nic_count),
            primary_mac,
            "[MAAS]",
            ("maas-discovered" if is_candidate else "review-only"),
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

    add_prefixes = []
    for g in (os_subnet_gaps or []):
        role_name, role_reason = _suggest_prefix_role(g)
        start_addr, end_addr = _cidr_start_end(g.get("cidr", ""))
        add_prefixes.append([
            g.get("cidr", ""),
            start_addr,
            end_addr,
            g.get("project_name", "-"),
            role_name,
            _suggest_prefix_status(g),
            role_reason,
            "[OS]",
            "CREATE_NETBOX_PREFIX_FROM_OS",
        ])

    add_fips = []
    for g in (os_floating_gaps or []):
        fip = g.get("floating_ip", "")
        fip_name = g.get("floating_subnet_name") or g.get("floating_network_name") or "-"
        vrf_ctx = " ".join([
            str(g.get("floating_network_name") or ""),
            str(g.get("floating_subnet_name") or ""),
            str(g.get("project_name") or ""),
        ])
        nb_vrf = _suggest_vrf_for_ip(fip, context=vrf_ctx)
        nb_status = "active" if str(g.get("port_id") or "").strip() else "reserved"
        add_fips.append([
            fip,
            fip_name,
            g.get("fixed_ip_address", "-"),
            g.get("project_name") or g.get("project_id") or "-",
            nb_status,
            "VIP",
            nb_vrf,
            "OpenStack floating IP semantics + NetBox prefix/VRF context",
            "CREATE_NETBOX_IPADDRESS_FROM_OS_FIP",
        ])

    update_nic = _build_update_nic_rows(interface_audit)
    review_serial = _build_review_serial_rows(matched_rows)

    return {
        "add_devices": add_devices,
        "add_devices_review_only": add_devices_review_only,
        "add_prefixes": add_prefixes,
        "add_fips": add_fips,
        "update_nic": update_nic,
        "add_nb_interfaces": add_nb_interfaces,
        "add_mgmt_iface": add_mgmt_iface,
        "add_mgmt_iface_new_devices": add_mgmt_iface_new_devices,
        "review_serial": review_serial,
    }
