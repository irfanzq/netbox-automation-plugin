"""PROPOSED CHANGES and summary tables for the drift HTML/ASCII report."""


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
    if prop["add_devices"]:
        e.spacer()
        e.subtitle("Detail — new devices")
        e.spacer()
        e.table(
            [
                "Hostname",
                "NB region",
                "NB site",
                "NB location",
                "NetBox device type",
                "NetBox role",
                "MAAS fabric",
                "MAAS status",
                "NB proposed state",
                "Serial Number",
                "Power type",
                "BMC present",
                "NIC count",
                "Primary MAC (MAAS)",
                "Authority",
                "Proposed Tag",
                "Proposed Action",
            ],
            prop["add_devices"],
            dynamic_columns=True,
            wrap_max_width=None,
        )
    if prop.get("add_devices_review_only"):
        e.spacer()
        e.subtitle("Detail — MAAS-only hosts (manual review required)")
        e.spacer()
        e.table(
            [
                "Hostname",
                "NB region",
                "NB site",
                "NB location",
                "NetBox device type",
                "NetBox role",
                "MAAS fabric",
                "MAAS status",
                "Serial Number",
                "Power type",
                "BMC present",
                "NIC count",
                "Primary MAC (MAAS)",
                "Authority",
                "Proposed Tag",
                "Proposed Action",
            ],
            prop["add_devices_review_only"],
            dynamic_columns=True,
            wrap_max_width=None,
        )
    if prop["add_prefixes"]:
        e.spacer()
        e.subtitle("Detail — new prefixes")
        e.paragraph("Use each row as NetBox Prefix create input (CIDR + OpenStack network/project context).")
        e.spacer()
        e.table(
            [
                "OS region",
                "CIDR",
                "Start address",
                "End address",
                "Project",
                "Suggested NB role",
                "NB status",
                "Role reason",
                "Authority",
                "Proposed Action",
            ],
            prop["add_prefixes"],
            dynamic_columns=True,
            wrap_max_width=None,
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
                "NB status",
                "NB role",
                "NB VRF",
                "Decision basis",
                "Proposed Action",
            ],
            prop["add_fips"],
            dynamic_columns=True,
            wrap_max_width=None,
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
        e.table(
            [
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
                "Proposed properties (from MAAS)",
                "Risk",
            ],
            prop["add_nb_interfaces"],
            dynamic_columns=True,
            wrap_max_width=None,
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
            "Status",
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
            )

    if prop.get("add_mgmt_iface_new_devices"):
        e.spacer()
        e.subtitle("Detail — new BMC / OOB interfaces")
        e.spacer()
        e.table(
            [
                "Host",
                "MAAS BMC IP",
                "MAAS power_type",
                "MAAS BMC MAC",
                "Suggested NB mgmt iface",
                "NB mgmt iface IP",
                "OS BMC IP",
                "OS mgmt type",
                "OS BMC endpoint",
                "Authority",
                "Proposed action",
                "Risk",
            ],
            prop["add_mgmt_iface_new_devices"],
            dynamic_columns=True,
            wrap_max_width=None,
        )

    if prop["add_mgmt_iface"]:
        e.spacer()
        e.subtitle("Detail — existing BMC / OOB")
        e.spacer()
        e.table(
            [
                "Host",
                "MAAS BMC IP",
                "MAAS power_type",
                "MAAS BMC MAC",
                "Suggested NB OOB Port",
                "NetBox OOB",
                "NB IP coverage",
                "Actual NB Port Carrying BMC IP",
                "NB OOB MAC",
                "OS BMC IP",
                "OS mgmt type",
                "OS BMC endpoint",
                "Authority",
                "Status",
                "Proposed action",
                "Risk",
            ],
            prop["add_mgmt_iface"],
            dynamic_columns=True,
            wrap_max_width=None,
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
            ["NIC drift", str(len(prop["update_nic"]))],
            ["New NICs", str(len(prop["add_nb_interfaces"]))],
            ["BMC / OOB", str(len(prop["add_mgmt_iface"]) + len(prop.get("add_mgmt_iface_new_devices", [])))],
            ["Serials (review)", str(len(prop["review_serial"]))],
            ["Total", str(total_props)],
        ],
    )
