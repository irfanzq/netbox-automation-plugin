"""Drift counts, severity triage, run metrics, and placement-alignment tables."""

from netbox_automation_plugin.sync.reporting.drift_report.fabric_alignment import (
    _alignment_review_rows,
)
from netbox_automation_plugin.sync.reporting.drift_report.metrics import (
    _count_hints,
    _phase0_category_counts,
    _severity_triage_rows,
)


def emit_drift_counts_and_alignment(
    e,
    drift,
    maas_data,
    netbox_data,
    openstack_data,
    matched_rows,
    interface_audit,
    os_subnet_gaps,
    os_floating_gaps,
    orphaned_nb_count,
):
    e.spacer()
    e.banner("DRIFT COUNTS")
    e.paragraph("Counts for this run (match by hostname and NIC MAC; OpenStack runtime authoritative when present).")
    e.spacer()
    pc = _phase0_category_counts(
        drift,
        matched_rows,
        interface_audit,
        os_subnet_gaps,
        os_floating_gaps,
    )
    serial_validation_needed = _count_hints(matched_rows, "NB serial empty")
    bmc_oob_mismatch = _count_hints(matched_rows, "BMC ")
    sub_txt = str(pc["sub_gaps"]) if pc["sub_gaps"] is not None else "N/A (local ORM)"
    outside_scope = drift.get("maas_in_netbox_outside_scope") or []
    outside_n = len(outside_scope)
    scope_meta = (drift or {}).get("scope_meta") or {}
    e.table(
        ["Category", "Count"],
        [
            ["In MAAS only (not in NetBox)", str(pc["maas_only"])],
            [
                "In MAAS scope but already in NetBox under another site/location (see detail below)",
                str(outside_n),
            ],
            [
                "Orphaned NetBox devices (not seen in MAAS this run; read-only here; "
                "tagging/cleanup deferred to a separate UI workflow because NetBox update sources include netbox-agent, scripts, and manual entries, not just MAAS)",
                str(orphaned_nb_count),
            ],
            ["Matched — review hints", str(pc["check_hosts"])],
            ["NetBox serial missing", str(serial_validation_needed)],
            ["NIC rows not OK", str(pc["iface_not_ok"])],
            ["MAAS NIC missing in NetBox", str(pc["maas_nic_missing_nb"])],
            ["VLAN mismatch (runtime authority vs NetBox)", str(pc["vlan_drift_nic"])],
            ["VLAN unverified from MAAS fallback", str(pc["vlan_unverified_nic"])],
            ["OpenStack subnet → no Prefix", sub_txt],
            ["OpenStack FIP → no IP record", str(pc["fip_gaps"])],
            ["BMC vs NetBox OOB differs (OS/MAAS fallback)", str(bmc_oob_mismatch)],
        ],
    )

    if outside_scope:
        e.spacer()
        e.subtitle("Detail — MAAS in scope, NetBox record outside selected site/location")
        e.paragraph(
            "These hostnames were counted as “MAAS-only” against the filtered NetBox inventory, "
            "but a full NetBox lookup shows an existing device (often Staging vs Spruce when MAAS "
            "DNS or fabric names still match the selected scope). They are not missing from NetBox."
        )
        e.spacer()
        e.table(
            ["Hostname", "NetBox region", "NetBox site", "NetBox location", "Note"],
            outside_scope,
            dynamic_columns=True,
            wrap_max_width=None,
        )

    e.spacer()
    e.banner("SEVERITY TRIAGE (why these matter)", "-")
    e.paragraph("Priority rules used in this report for review ordering.")
    e.spacer()
    sev_rows = _severity_triage_rows(
        pc,
        serial_validation_needed=serial_validation_needed,
        bmc_oob_mismatch=bmc_oob_mismatch,
        netbox_outside_scope=outside_n,
    )
    e.table(
        ["Severity", "Category", "Count", "Why this matters"],
        sev_rows,
        wrap_max_width=None,
    )

    e.spacer()
    e.banner("RUN METRICS", "-")
    e.spacer()
    nb_included = len(netbox_data.get("devices") or [])
    nb_fetched = int(scope_meta.get("netbox_devices_before") or nb_included)
    os_nics_included = len((openstack_data or {}).get("runtime_nics") or [])
    os_nics_fetched = int(scope_meta.get("openstack_runtime_nics_before") or os_nics_included)
    os_bmc_included = len((openstack_data or {}).get("runtime_bmc") or [])
    os_bmc_fetched = int(scope_meta.get("openstack_runtime_bmc_before") or os_bmc_included)
    e.table(
        ["Metric", "Value"],
        [
            ["MAAS machines", str(len(maas_data.get("machines") or []))],
            ["NetBox devices (included / fetched)", f"{nb_included} / {nb_fetched}"],
            ["OpenStack runtime NIC rows (included / fetched)", f"{os_nics_included} / {os_nics_fetched}"],
            ["OpenStack runtime BMC rows (included / fetched)", f"{os_bmc_included} / {os_bmc_fetched}"],
            ["Hosts present in both MAAS and NetBox", str(drift.get("matched_count", 0))],
            ["In MAAS only", str(pc["maas_only"])],
            ["NetBox serial missing", str(serial_validation_needed)],
            ["OpenStack subnet gaps", sub_txt],
            ["OpenStack FIP gaps", str(pc["fip_gaps"])],
            ["VLAN mismatch NICs (OS/MAAS authority)", str(pc["vlan_drift_nic"])],
            ["VLAN unverified NICs (MAAS fallback)", str(pc["vlan_unverified_nic"])],
            ["MAAS NIC missing in NetBox", str(pc["maas_nic_missing_nb"])],
        ],
    )

    align_rows = _alignment_review_rows(matched_rows)
    if align_rows:
        e.spacer()
        e.subtitle("Detail — placement & lifecycle alignment")
        e.spacer()
        e.table(
            [
                "Host",
                "MAAS fabric",
                "MAAS state",
                "OS region",
                "OS provision",
                "OS power",
                "OS maintenance",
                "NetBox site",
                "NetBox location",
                "NB state",
                "Authority",
                "Alignment issues",
            ],
            align_rows,
            dynamic_columns=True,
            notes_col_idx=11,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_placement_lifecycle_alignment",
        )
