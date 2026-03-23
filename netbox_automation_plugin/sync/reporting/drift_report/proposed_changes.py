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
    netbox_ifaces=None,
):
    """Build user-friendly proposed change buckets (preview only)."""
    try:
        from netbox_automation_plugin.sync.config import get_sync_config

        _sync = get_sync_config()
        _fabric_site_map = _sync.get("site_mapping_fabric") or {}
        _pool_site_map = _sync.get("site_mapping_pool") or {}
    except Exception:
        _fabric_site_map, _pool_site_map = {}, {}

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
                f"Create OOB interface '{mgmt}' (management-only)"
                + (f"; set OOB/BMC IP {bmc_ip}" if bmc_ip else "")
            )
            out.append(
                [
                    h,
                    bmc_ip or "—",
                    power_type or "—",
                    str(m.get("bmc_mac") or "—"),
                    mgmt,
                    bmc_ip or "—",
                    action,
                    "Medium",
                ]
            )
        return sorted(out, key=lambda x: (x[0] or "").lower())

    by_h = _maas_machine_by_hostname(maas_data)
    _dtype_index = _build_device_type_match_index(netbox_data.get("device_types") or [])
    add_mgmt_iface = _build_proposed_mgmt_interface_rows(matched_rows, by_h, netbox_ifaces)
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
            ("maas-discovered" if is_candidate else "review-only"),
            (
                "Create device + ports"
                if is_candidate
                else f"Review only — not a safe NetBox add candidate ({note})"
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
        add_prefixes.append([
            g.get("cidr", ""),
            g.get("network_name", "-"),
            g.get("network_id", ""),
            "-",
            "Create Prefix",
        ])

    add_fips = []
    for g in (os_floating_gaps or []):
        add_fips.append([
            g.get("floating_ip", ""),
            g.get("fixed_ip_address", "-"),
            g.get("project_name") or g.get("project_id") or "-",
            "-",
            "Create IPAddress",
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
