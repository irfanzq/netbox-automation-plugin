"""PROPOSED CHANGES and summary tables for the drift HTML/ASCII report."""

from netbox_automation_plugin.sync.reporting.drift_report.maas_netbox_status import (
    maas_to_netbox_mapping_reference_rows,
)

# Header label → catalog key for drift_nb_picker_catalog (NB proposed tag excluded).
_PROPOSED_NB_PICK_DEVICE = {
    "NB proposed region": "region",
    "NB proposed site": "site",
    "NB proposed location": "location",
    "NB proposed device type": "device_type",
    "NB proposed role": "device_role",
    "NB proposed device status": "device_status",
}
_PROPOSED_NB_PICK_PREFIX = {
    "NB Proposed Tenant": "tenant",
    "NB Proposed Scope": "scope_location",
    "NB Proposed VLAN": "vlan",
    "NB proposed role": "prefix_role",
    "NB proposed status": "prefix_status",
    "NB proposed VRF": "vrf",
}
_PROPOSED_NB_PICK_FIP = {
    "NB Proposed Tenant": "tenant",
    "NB proposed status": "ip_status",
    "NB proposed role": "ip_role",
    "NB proposed VRF": "vrf",
}


def emit_proposed_change_tables(e, prop):
    e.spacer()
    e.banner("PROPOSED CHANGES", "-")
    e.paragraph(
        "Read-only. Possible NetBox updates from OpenStack runtime (authoritative when present) with MAAS fallback where OpenStack data is missing."
    )
    e.spacer()

    e.subtitle("A) Add to NetBox")
    e.spacer()
    e.table(
        ["What", "Count", "Note"],
        [
            ["New devices (MAAS fallback)", str(len(prop["add_devices"])), "Safe create candidates when not present in NetBox"],
            [
                "Review-only MAAS-only hosts",
                str(len(prop.get("add_devices_review_only", []))),
                "Not safe to auto-propose (status/data quality policy)",
            ],
            ["New prefixes (OpenStack authority)", str(len(prop["add_prefixes"])), "Subnet not in IPAM"],
            ["New floating IPs (OpenStack authority)", str(len(prop["add_fips"])), "FIP not in IPAM"],
        ],
    )
    e.spacer()
    e.subtitle("Reference — MAAS → NetBox device.status (fallback when no OS runtime)")
    e.paragraph(
        "Placement and new-device rows prefer OpenStack Ironic when a BMC row exists; "
        "this table is the MAAS-only mapping used when OS data is missing or does not map."
    )
    e.spacer()
    e.table(
        ["MAAS state (normalized)", "NetBox status slug"],
        maas_to_netbox_mapping_reference_rows(),
        dynamic_columns=True,
        wrap_max_width=None,
        selectable=False,
    )
    if prop["add_devices"]:
        e.spacer()
        e.subtitle("Detail — new devices")
        e.spacer()
        e.table(
            [
                "Hostname",
                "NB proposed region",
                "NB proposed site",
                "NB proposed location",
                "OS region",
                "OS provision",
                "OS power",
                "OS maintenance",
                "NB proposed device type",
                "NB proposed role",
                "MAAS fabric",
                "MAAS status",
                "Serial Number",
                "Power type",
                "BMC present",
                "NIC count",
                "Primary MAC (MAAS)",
                "Primary MAC (OS)",
                "Authority",
                "NB proposed device status",
                "NB proposed tag",
                "Proposed Action",
            ],
            prop["add_devices"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_new_devices",
            proposed_pick_columns=_PROPOSED_NB_PICK_DEVICE,
        )
    if prop.get("add_devices_review_only"):
        e.spacer()
        e.subtitle("Detail — MAAS-only hosts (manual review required)")
        e.spacer()
        e.table(
            [
                "Hostname",
                "NB proposed region",
                "NB proposed site",
                "NB proposed location",
                "OS region",
                "OS provision",
                "OS power",
                "OS maintenance",
                "NB proposed device type",
                "NB proposed role",
                "MAAS fabric",
                "MAAS status",
                "Serial Number",
                "Power type",
                "BMC present",
                "NIC count",
                "Primary MAC (MAAS)",
                "Primary MAC (OS)",
                "Authority",
                "NB proposed device status",
                "NB proposed tag",
                "Proposed Action",
            ],
            prop["add_devices_review_only"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_review_only_devices",
            proposed_pick_columns=_PROPOSED_NB_PICK_DEVICE,
        )
    if prop["add_prefixes"]:
        e.spacer()
        e.subtitle("Detail — new prefixes")
        e.paragraph(
            "Use each row as NetBox Prefix create input (CIDR + OpenStack network/project context). "
            "NB proposed status: reserved when no Neutron ports were counted on that subnet in this scan; "
            "active when at least one port was seen (role certainty is only in Role reason). "
            "NB proposed VRF is inferred from OpenStack naming signals (network/project/region text). "
            "Columns marked '(editable)' can be clicked and edited directly."
        )
        e.spacer()
        e.table(
            [
                "OS region",
                "CIDR",
                "OS Description",
                "Project",
                "NB Proposed Prefix description (editable)",
                "NB Proposed Tenant",
                "NB Proposed Scope",
                "NB Proposed VLAN",
                "NB proposed role",
                "NB proposed status",
                "NB proposed VRF",
                "Role reason",
                "Authority",
                "Proposed Action",
            ],
            prop["add_prefixes"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_new_prefixes",
            proposed_pick_columns=_PROPOSED_NB_PICK_PREFIX,
            editable_columns=["NB Proposed Prefix description (editable)"],
        )
    if prop.get("add_ip_ranges"):
        e.spacer()
        e.subtitle("Detail — new IP ranges (allocation pools)")
        e.paragraph(
            "OpenStack subnet allocation pools proposed as NetBox IPRanges. "
            "These rows represent assignable host windows inside the subnet CIDR."
        )
        e.spacer()
        e.table(
            [
                "OS region",
                "CIDR",
                "Start address",
                "End address",
                "OS Pool Description",
                "NB Proposed Description",
                "Project",
                "NB proposed status",
                "NB proposed role",
                "NB proposed VRF",
                "Authority",
                "Proposed Action",
            ],
            prop["add_ip_ranges"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_new_ip_ranges",
            proposed_pick_columns=_PROPOSED_NB_PICK_PREFIX,
            editable_columns=["NB Proposed Description"],
        )
    if prop["add_fips"]:
        e.spacer()
        e.subtitle("Detail — new floating IPs")
        e.spacer()
        e.table(
            [
                "OS region",
                "Floating IP",
                "Name",
                "NAT inside IP (from OpenStack fixed IP)",
                "Project",
                "NB Proposed Tenant",
                "NB proposed status",
                "NB proposed role",
                "NB proposed VRF",
                "Proposed Action",
            ],
            prop["add_fips"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_new_fips",
            proposed_pick_columns=_PROPOSED_NB_PICK_FIP,
        )

    e.spacer()
    e.subtitle("B) NICs and BMC / OOB")
    e.spacer()
    e.table(
        ["What", "Count", "Note"],
        [
            ["New NICs in NetBox", str(len(prop["add_nb_interfaces"])), "Runtime/MAAS fallback interface not modeled in NetBox"],
            ["NIC drift", str(len(prop["update_nic"])), "Runtime authority (OS first, MAAS fallback) differs from NetBox"],
            [
                "BMC / OOB",
                str(len(prop["add_mgmt_iface"]) + len(prop.get("add_mgmt_iface_new_devices", []))),
                "BMC runtime authority (OS first, MAAS fallback) vs NetBox",
            ],
        ],
    )
    if prop["add_nb_interfaces"]:
        e.spacer()
        e.subtitle("Detail — new NICs")
        e.spacer()
        headers = [
            "Host",
            "NB site",
            "NB location",
            "MAAS intf",
            "MAAS fabric",
            "MAAS MAC",
            "MAAS IPs",
            "MAAS VLAN",
            "OS region",
            "OS MAC",
            "OS runtime IP",
            "OS runtime VLAN",
            "Authority",
            "Suggested NB name",
            "Proposed properties",
            "Risk",
        ]
        os_rows = [r for r in prop["add_nb_interfaces"] if len(r) > 12 and str(r[12]).strip() == "[OS]"]
        maas_rows = [r for r in prop["add_nb_interfaces"] if len(r) <= 12 or str(r[12]).strip() != "[OS]"]
        e.paragraph(
            f"Authority split: OS runtime={len(os_rows)} row(s), MAAS fallback={len(maas_rows)} row(s)."
        )
        if os_rows:
            e.spacer()
            e.subtitle("Detail — new NICs (OS authority)")
            e.spacer()
            e.table(
                headers,
                os_rows,
                dynamic_columns=True,
                wrap_max_width=None,
                selectable=True,
                selection_key="detail_new_nics_os",
            )
        if maas_rows:
            e.spacer()
            e.subtitle("Detail — new NICs (MAAS authority)")
            e.spacer()
            e.table(
                headers,
                maas_rows,
                dynamic_columns=True,
                wrap_max_width=None,
                selectable=True,
                selection_key="detail_new_nics_maas",
            )
    if prop["update_nic"]:
        e.spacer()
        e.subtitle("Detail — NIC drift")
        e.spacer()
        headers = [
            "Host",
            "MAAS intf",
            "MAAS fabric",
            "MAAS MAC",
            "MAAS IPs",
            "MAAS VLAN",
            "OS region",
            "OS MAC",
            "OS runtime IP",
            "OS runtime VLAN",
            "Authority",
            "NB intf",
            "NB MAC",
            "NB IPs",
            "NB VLAN",
            "Proposed Action",
            "Risk",
        ]
        os_rows = [r for r in prop["update_nic"] if len(r) > 10 and str(r[10]).strip() == "[OS]"]
        maas_rows = [r for r in prop["update_nic"] if len(r) > 10 and str(r[10]).strip() != "[OS]"]
        e.paragraph(
            f"Authority split: OS runtime={len(os_rows)} row(s), MAAS fallback={len(maas_rows)} row(s)."
        )
        if os_rows:
            e.spacer()
            e.subtitle("Detail — NIC drift (OS runtime authority)")
            e.spacer()
            e.table(
                headers,
                os_rows,
                dynamic_columns=True,
                wrap_max_width=None,
                selectable=True,
                selection_key="detail_nic_drift_os",
            )
        if maas_rows:
            e.spacer()
            e.subtitle("Detail — NIC drift (MAAS fallback authority)")
            e.spacer()
            e.table(
                headers,
                maas_rows,
                dynamic_columns=True,
                wrap_max_width=None,
                selectable=True,
                selection_key="detail_nic_drift_maas",
            )

    if prop.get("add_mgmt_iface_new_devices"):
        e.spacer()
        e.subtitle("Detail — new BMC / OOB interfaces")
        e.spacer()
        e.table(
            [
                "Host",
                "OS BMC IP",
                "OS mgmt type",
                "OS vendor",
                "OS model",
                "MAAS BMC IP",
                "MAAS power_type",
                "MAAS vendor",
                "MAAS product",
                "MAAS BMC MAC",
                "Suggested NB mgmt iface",
                "NB mgmt iface IP",
                "Authority",
                "Proposed action",
                "Risk",
            ],
            prop["add_mgmt_iface_new_devices"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_bmc_new_devices",
        )

    if prop["add_mgmt_iface"]:
        e.spacer()
        e.subtitle("Detail — existing BMC / OOB")
        e.spacer()
        e.table(
            [
                "Host",
                "OS BMC IP",
                "OS mgmt type",
                "MAAS BMC IP",
                "MAAS power_type",
                "MAAS BMC MAC",
                "Suggested NB OOB Port",
                "NetBox OOB",
                "NB IP coverage",
                "Actual NB Port Carrying BMC IP",
                "NB OOB MAC",
                "Authority",
                "Status",
                "Proposed action",
                "Risk",
            ],
            prop["add_mgmt_iface"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_bmc_existing",
        )

    e.spacer()
    e.subtitle("C) Review")
    e.spacer()
    e.table(
        ["What", "Count", "Note"],
        [
            ["Serial check", str(len(prop["review_serial"])), "NetBox serial empty"],
        ],
    )
    if prop["review_serial"]:
        e.spacer()
        e.subtitle("Detail — serials")
        e.spacer()
        e.table(
            ["Hostname", "MAAS Serial", "NetBox Serial", "Proposed Action", "Risk"],
            prop["review_serial"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_serial_review",
        )
    e.spacer()
    e.subtitle("Summary")
    e.spacer()
    total_props = (
        len(prop["add_devices"]) + len(prop["add_prefixes"]) + len(prop["add_fips"]) +
        len(prop["update_nic"]) + len(prop["add_nb_interfaces"]) +
        len(prop["add_mgmt_iface"]) + len(prop.get("add_mgmt_iface_new_devices", [])) +
        len(prop["review_serial"])
    )
    e.table(
        ["Bucket", "Count"],
        [
            ["New devices", str(len(prop["add_devices"]))],
            ["New prefixes", str(len(prop["add_prefixes"]))],
            ["New floating IPs", str(len(prop["add_fips"]))],
            ["New NICs", str(len(prop["add_nb_interfaces"]))],
            ["NIC drift", str(len(prop["update_nic"]))],
            ["BMC / OOB", str(len(prop["add_mgmt_iface"]) + len(prop.get("add_mgmt_iface_new_devices", [])))],
            ["Serials (review)", str(len(prop["review_serial"]))],
            ["Total", str(total_props)],
        ],
    )
