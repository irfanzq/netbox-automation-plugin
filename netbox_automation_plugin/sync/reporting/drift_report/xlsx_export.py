"""Excel export for the drift audit (openpyxl)."""

from io import BytesIO

from netbox_automation_plugin.sync.reporting.drift_report.constants import (
    _PHASE0_FIELD_OWNERSHIP_BULLETS,
    _PHASE0_FIELD_OWNERSHIP_LEAD,
    _PHASE0_FIELD_OWNERSHIP_TITLE,
)
from netbox_automation_plugin.sync.reporting.drift_report.fabric_alignment import (
    _alignment_review_rows,
)
from netbox_automation_plugin.sync.reporting.drift_report.metrics import (
    _count_hints,
    _phase0_category_counts,
    _run_metadata_rows,
    _severity_triage_rows,
)
from netbox_automation_plugin.sync.reporting.drift_report.placement import _drift_for_user_reports
from netbox_automation_plugin.sync.reporting.drift_report.proposed_changes import (
    _proposed_changes_rows,
)

def build_drift_report_xlsx(
    maas_data,
    netbox_data,
    openstack_data,
    drift,
    *,
    matched_rows=None,
    os_subnet_hints=None,
    os_subnet_gaps=None,
    os_floating_gaps=None,
    netbox_prefix_count=0,
    interface_audit=None,
    netbox_ifaces=None,
):
    """
    Build an Excel (.xlsx) workbook from the same inputs as format_drift_report.
    Returns bytes suitable for HttpResponse(..., content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet").
    Google Sheets opens .xlsx files.
    """
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font
    except ImportError:
        raise RuntimeError("openpyxl is required for XLSX export. pip install openpyxl")

    orphaned_nb_count = len((drift or {}).get("in_netbox_not_maas") or [])
    drift = _drift_for_user_reports(drift)

    wb = Workbook()
    header_font = Font(bold=True)

    def _sheet(name, max_len=31):
        s = wb.create_sheet(title=name[:max_len])
        return s

    def _append_header(ws, row):
        ws.append(row)
        r = ws.max_row
        for c in range(1, len(row) + 1):
            ws.cell(row=r, column=c).font = header_font
        return r

    # --- Summary ---
    ws_sum = wb.active
    ws_sum.title = "Summary"
    ws_sum.append(["Drift audit summary"])
    ws_sum.cell(row=1, column=1).font = header_font
    ws_sum.append([])
    r_own = ws_sum.max_row + 1
    ws_sum.append([_PHASE0_FIELD_OWNERSHIP_TITLE, "", ""])
    ws_sum.cell(row=r_own, column=1).font = header_font
    ws_sum.append([_PHASE0_FIELD_OWNERSHIP_LEAD, "", ""])
    for b in _PHASE0_FIELD_OWNERSHIP_BULLETS:
        ws_sum.append([f"  • {b}", "", ""])
    ws_sum.append([])
    r_rm = ws_sum.max_row + 1
    ws_sum.append(["RUN METADATA", ""])
    ws_sum.cell(row=r_rm, column=1).font = header_font
    _append_header(ws_sum, ["Property", "Value"])
    for prop, val in _run_metadata_rows(maas_data, netbox_data, openstack_data):
        ws_sum.append([prop, val])
    ws_sum.append([])
    scope_meta = (drift or {}).get("scope_meta") or {}
    nb_devices_included = len(netbox_data.get("devices") or [])
    nb_devices_fetched = int(scope_meta.get("netbox_devices_before") or nb_devices_included)
    nb_sites_fetched = len(netbox_data.get("sites") or [])
    nb_sites_included = len({
        (d.get("site_slug") or "").strip()
        for d in (netbox_data.get("devices") or [])
        if (d.get("site_slug") or "").strip()
    })
    ws_sum.append(["MAAS", "OK" if not maas_data.get("error") else "Error", ""])
    ws_sum.append(["  Machines", str(len(maas_data.get("machines") or [])), ""])
    ws_sum.append(["NetBox", "OK" if not netbox_data.get("error") else "Error", ""])
    ws_sum.append(["  Devices (included / fetched)", f"{nb_devices_included} / {nb_devices_fetched}", ""])
    ws_sum.append(["  Sites (included / fetched)", f"{nb_sites_included} / {nb_sites_fetched}", ""])
    if netbox_prefix_count:
        ws_sum.append(["  IPAM Prefixes (included / fetched)", f"{netbox_prefix_count} / {netbox_prefix_count}", ""])
    ws_sum.append([])
    ws_sum.append([])
    pc = _phase0_category_counts(
        drift,
        matched_rows,
        interface_audit,
        os_subnet_gaps,
        os_floating_gaps or [],
    )
    serial_validation_needed = _count_hints(matched_rows, "NB serial empty")
    bmc_oob_mismatch = _count_hints(matched_rows, "BMC ")
    sub_txt = str(pc["sub_gaps"]) if pc["sub_gaps"] is not None else "N/A"
    if scope_meta:
        ws_sum.append([])
        ws_sum.append(["SCOPE", "", ""])
        _append_header(ws_sum, ["Check", "Value"])
        ws_sum.append(["Coverage status", str(scope_meta.get("coverage_status") or "PARTIAL")])
        ws_sum.append(["Selected sites", ", ".join(scope_meta.get("selected_sites") or []) or "(all)"])
        ws_sum.append(["Selected locations", ", ".join(scope_meta.get("selected_locations") or []) or "(all)"])
        ws_sum.append([
            "MAAS machines included / fetched",
            f"{scope_meta.get('maas_machines_after', 0)} / {scope_meta.get('maas_machines_before', 0)}",
        ])
        ws_sum.append([
            "NetBox devices included / fetched",
            f"{scope_meta.get('netbox_devices_after', 0)} / {scope_meta.get('netbox_devices_before', 0)}",
        ])
        ws_sum.append([
            "OpenStack nets included / fetched",
            f"{scope_meta.get('openstack_networks_after', 0)} / {scope_meta.get('openstack_networks_before', 0)}",
        ])
        ws_sum.append([
            "OpenStack subnets included / fetched",
            f"{scope_meta.get('openstack_subnets_after', 0)} / {scope_meta.get('openstack_subnets_before', 0)}",
        ])
        ws_sum.append([
            "OpenStack FIPs included / fetched",
            f"{scope_meta.get('openstack_fips_after', 0)} / {scope_meta.get('openstack_fips_before', 0)}",
        ])
        ws_sum.append([
            "OpenStack runtime NIC rows",
            str(len((openstack_data or {}).get("runtime_nics") or [])),
        ])
        ws_sum.append([
            "OpenStack runtime BMC rows",
            str(len((openstack_data or {}).get("runtime_bmc") or [])),
        ])
    ws_sum.append([])
    ws_sum.append(["DRIFT COUNTS", "", ""])
    _append_header(ws_sum, ["Category", "Count"])
    ws_sum.append(["In MAAS only (not in NetBox)", str(pc["maas_only"])])
    _outside_scope = (drift or {}).get("maas_in_netbox_outside_scope") or []
    _outside_n = len(_outside_scope)
    ws_sum.append(
        [
            "In MAAS scope but already in NetBox under another site/location (detail on Summary)",
            str(_outside_n),
        ]
    )
    ws_sum.append(
        [
            "Orphaned NetBox devices (not seen in MAAS this run; read-only here; tagging/cleanup deferred to a separate UI workflow because NetBox update sources include netbox-agent, scripts, and manual entries, not just MAAS)",
            str(orphaned_nb_count),
        ]
    )
    ws_sum.append(["Matched — review hints", str(pc["check_hosts"])])
    ws_sum.append(["NetBox serial missing", str(serial_validation_needed)])
    ws_sum.append(["NIC rows not OK", str(pc["iface_not_ok"])])
    ws_sum.append(["MAAS NIC missing in NetBox", str(pc["maas_nic_missing_nb"])])
    ws_sum.append(["VLAN mismatch (runtime authority vs NetBox)", str(pc["vlan_drift_nic"])])
    ws_sum.append(["VLAN unverified from MAAS fallback", str(pc["vlan_unverified_nic"])])
    ws_sum.append(["OpenStack subnet → no Prefix", sub_txt])
    ws_sum.append(["OpenStack FIP → no IP record", str(pc["fip_gaps"])])
    ws_sum.append(["BMC vs NetBox OOB differs (OS/MAAS fallback)", str(bmc_oob_mismatch)])
    ws_sum.append([])
    ws_sum.append(["SEVERITY TRIAGE (why these matter)", "", ""])
    _append_header(ws_sum, ["Severity", "Category", "Count", "Why this matters"])
    for row in _severity_triage_rows(
        pc,
        serial_validation_needed=serial_validation_needed,
        bmc_oob_mismatch=bmc_oob_mismatch,
        netbox_outside_scope=_outside_n,
    ):
        ws_sum.append(row)
    ws_sum.append([])
    ws_sum.append(["RUN METRICS", "", ""])
    _append_header(ws_sum, ["Metric", "Value"])
    os_nics_included = len((openstack_data or {}).get("runtime_nics") or [])
    os_nics_fetched = int(scope_meta.get("openstack_runtime_nics_before") or os_nics_included)
    os_bmc_included = len((openstack_data or {}).get("runtime_bmc") or [])
    os_bmc_fetched = int(scope_meta.get("openstack_runtime_bmc_before") or os_bmc_included)
    ws_sum.append(["MAAS machines", str(len(maas_data.get("machines") or []))])
    ws_sum.append(["NetBox devices (included / fetched)", f"{nb_devices_included} / {nb_devices_fetched}"])
    ws_sum.append(["OpenStack runtime NIC rows (included / fetched)", f"{os_nics_included} / {os_nics_fetched}"])
    ws_sum.append(["OpenStack runtime BMC rows (included / fetched)", f"{os_bmc_included} / {os_bmc_fetched}"])
    ws_sum.append(["Hosts present in both MAAS and NetBox", str(drift.get("matched_count", 0))])
    ws_sum.append(["In MAAS only", str(pc["maas_only"])])
    ws_sum.append(["NetBox serial missing", str(serial_validation_needed)])
    ws_sum.append(["OpenStack subnet gaps", sub_txt])
    ws_sum.append(["OpenStack FIP gaps", str(pc["fip_gaps"])])
    ws_sum.append(["VLAN mismatch NICs (OS/MAAS authority)", str(pc["vlan_drift_nic"])])
    ws_sum.append(["VLAN unverified NICs (MAAS fallback)", str(pc["vlan_unverified_nic"])])
    ws_sum.append(["MAAS NIC missing in NetBox", str(pc["maas_nic_missing_nb"])])
    ws_sum.append([])
    if _outside_scope:
        r_os = ws_sum.max_row + 1
        ws_sum.append(["Detail — MAAS in scope, NetBox outside selected site/location", ""])
        ws_sum.cell(row=r_os, column=1).font = header_font
        ws_sum.append([
            "These devices exist in NetBox; the scoped device list omitted them. Not new-device candidates.",
        ])
        _append_header(
            ws_sum,
            ["Hostname", "NetBox region", "NetBox site", "NetBox location", "Note"],
        )
        for row in _outside_scope:
            ws_sum.append(list(row))
        ws_sum.append([])
    align_rows_x = _alignment_review_rows(matched_rows)
    if align_rows_x:
        r_al = ws_sum.max_row + 1
        ws_sum.append(["Detail — placement & lifecycle alignment", ""])
        ws_sum.cell(row=r_al, column=1).font = header_font
        _append_header(
            ws_sum,
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
        )
        for row in align_rows_x:
            ws_sum.append(row)
        ws_sum.append([])

    prop = _proposed_changes_rows(
        maas_data,
        netbox_data,
        drift,
        interface_audit,
        matched_rows,
        os_subnet_gaps or [],
        os_floating_gaps or [],
        openstack_data=openstack_data,
        netbox_ifaces=netbox_ifaces,
    )
    ws_sum.append([])
    ws_sum.append(["PROPOSED CHANGES (read-only)", "", ""])
    _append_header(ws_sum, ["Bucket", "Count"])
    total_props_x = (
        len(prop["add_devices"])
        + len(prop["add_prefixes"])
        + len(prop["add_fips"])
        + len(prop["update_nic"])
        + len(prop["add_nb_interfaces"])
        + len(prop["add_mgmt_iface"])
        + len(prop.get("add_mgmt_iface_new_devices", []))
        + len(prop["review_serial"])
    )
    ws_sum.append(["New devices", str(len(prop["add_devices"]))])
    ws_sum.append(["Review-only MAAS-only hosts", str(len(prop.get("add_devices_review_only", [])))])
    ws_sum.append(["New prefixes", str(len(prop["add_prefixes"]))])
    ws_sum.append(["New floating IPs", str(len(prop["add_fips"]))])
    ws_sum.append(["New NICs", str(len(prop["add_nb_interfaces"]))])
    ws_sum.append(["NIC drift", str(len(prop["update_nic"]))])
    ws_sum.append(["BMC / OOB", str(len(prop["add_mgmt_iface"]) + len(prop.get("add_mgmt_iface_new_devices", [])))])
    ws_sum.append(["Serials (review)", str(len(prop["review_serial"]))])
    ws_sum.append(["Total", str(total_props_x)])

    # Matched-host drift worksheet intentionally suppressed to match on-screen report.

    # --- Proposed changes (full list) ---
    ws_prop = _sheet("Proposed changes")
    ws_prop.append(["Drift detail — read-only; OpenStack runtime is authoritative where present, MAAS is fallback."])
    ws_prop.cell(row=1, column=1).font = header_font
    ws_prop.append([])
    _append_header(ws_prop, ["Section", "Count"])
    nic_drift_os = [r for r in prop["update_nic"] if len(r) > 10 and str(r[10]).strip() == "[OS]"]
    nic_drift_maas = [r for r in prop["update_nic"] if len(r) <= 10 or str(r[10]).strip() != "[OS]"]
    ws_prop.append(["New devices (MAAS fallback)", len(prop["add_devices"])])
    ws_prop.append(["Review-only MAAS-only hosts", len(prop.get("add_devices_review_only", []))])
    ws_prop.append(["New prefixes (OpenStack authority)", len(prop["add_prefixes"])])
    ws_prop.append(["New floating IPs (OpenStack authority)", len(prop["add_fips"])])
    ws_prop.append(["New NICs", len(prop["add_nb_interfaces"])])
    ws_prop.append(["NIC drift (OS runtime authority)", len(nic_drift_os)])
    ws_prop.append(["NIC drift (MAAS fallback authority)", len(nic_drift_maas)])
    ws_prop.append(["BMC / OOB", len(prop["add_mgmt_iface"]) + len(prop.get("add_mgmt_iface_new_devices", []))])
    ws_prop.append(["Serials (review)", len(prop["review_serial"])])

    def _append_block(title, headers, rows, *, note=None):
        ws_prop.append([])
        ws_prop.append([title])
        ws_prop.cell(row=ws_prop.max_row, column=1).font = header_font
        if note:
            ws_prop.append([note])
        _append_header(ws_prop, headers)
        for row in rows:
            ws_prop.append(list(row))

    _append_block(
        "A) New devices",
        [
            "Hostname",
            "NB region",
            "NB site",
            "NB location",
            "OS region",
            "OS provision",
            "OS power",
            "OS maintenance",
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
    )
    _append_block(
        "A) MAAS-only hosts (manual review required)",
        [
            "Hostname",
            "NB region",
            "NB site",
            "NB location",
            "OS region",
            "OS provision",
            "OS power",
            "OS maintenance",
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
        prop.get("add_devices_review_only", []),
    )
    _append_block(
        "A) New prefixes",
        [
            "OS region",
            "CIDR",
            "Start address",
            "End address",
            "Project",
            "Suggested NB role",
            "NB status",
            "Suggested NB VRF",
            "Role reason",
            "Authority",
            "Proposed Action",
        ],
        prop["add_prefixes"],
        note=(
            "NB status: reserved when no Neutron ports were counted on that subnet in this scan; "
            "active when at least one port was seen (role certainty is only in Role reason). "
            "Suggested NB VRF is inferred from OpenStack naming signals (network/project/region text)."
        ),
    )
    _append_block(
        "A) New floating IPs",
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
    )
    _append_block(
        "B) New NICs",
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
    )
    _append_block(
        "B) NIC drift (OS runtime authority)",
        [
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
        ],
        nic_drift_os,
    )
    _append_block(
        "B) NIC drift (MAAS fallback authority)",
        [
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
        ],
        nic_drift_maas,
    )
    _append_block(
        "B) BMC / OOB",
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
            "Proposed action",
            "Risk",
        ],
        prop["add_mgmt_iface"],
    )
    _append_block(
        "B) New-device BMC / OOB interfaces",
        [
            "Host",
            "OS BMC IP",
            "OS mgmt type",
            "MAAS BMC IP",
            "MAAS power_type",
            "MAAS BMC MAC",
            "Suggested NB mgmt iface",
            "NB mgmt iface IP",
            "Authority",
            "Proposed action",
            "Risk",
        ],
        prop.get("add_mgmt_iface_new_devices", []),
    )
    _append_block(
        "C) Serials",
        ["Hostname", "MAAS Serial", "NetBox Serial", "Proposed Action", "Risk"],
        prop["review_serial"],
    )

    # Improve readability for long text cells in Excel/Sheets.
    for ws in wb.worksheets:
        for row in ws.iter_rows(min_row=1, max_row=ws.max_row, min_col=1, max_col=ws.max_column):
            for cell in row:
                if cell.value is None:
                    continue
                # Keep existing horizontal alignment if present, but always wrap long text.
                cur = cell.alignment or Alignment()
                cell.alignment = Alignment(
                    horizontal=cur.horizontal,
                    vertical=cur.vertical or "top",
                    text_rotation=cur.text_rotation,
                    wrap_text=True,
                    shrink_to_fit=cur.shrink_to_fit,
                    indent=cur.indent,
                )
        # Give common text-heavy columns more space so wrapped content is easier to scan.
        ws.column_dimensions["A"].width = max(float(ws.column_dimensions["A"].width or 0), 42.0)
        if ws.max_column >= 2:
            ws.column_dimensions["B"].width = max(float(ws.column_dimensions["B"].width or 0), 26.0)

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()
