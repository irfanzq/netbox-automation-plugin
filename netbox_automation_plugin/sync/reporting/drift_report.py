"""
Generate human-readable drift audit report from MAAS, NetBox, and OpenStack data.
Uses ASCII tables (+---+) for readability in <pre> or plain text.
XLSX export via build_drift_report_xlsx() for download (openpyxl); Google Sheets opens .xlsx.
"""

from io import BytesIO

_MAX_MAAS_MISSING_ROWS = 500
_MAX_OS_NETWORKS = 40
_MAX_OS_SUBNET_HINTS = 60
_MAX_COL = 24
_MAX_MATCHED_COL = 18
_MAX_NOTES_COL = 42
# Notes column: full text for scrollable HTML report (avoid truncation)
_NOTES_COL_MAX_WIDTH = 8000
# Matched-hosts style tables: full cell text per column (no mid-cell truncation)
_DYNAMIC_COL_CAP = 320


def _maas_machine_by_hostname(maas_data):
    out = {}
    for m in maas_data.get("machines") or []:
        h = (m.get("hostname") or "").strip()
        if h:
            out[h] = m
    return out


def _cell(s, w):
    s = str(s).replace("\n", " ").replace("\r", "") if s is not None else ""
    if len(s) > w:
        s = s[: max(1, w - 2)] + ".."
    return s.ljust(w)


def _ascii_table(
    headers,
    rows,
    indent="  ",
    *,
    max_col=None,
    notes_col_idx=None,
    dynamic_columns=False,
):
    """
    dynamic_columns: size every column to content (caps: notes col 8000, else 140).
    One ASCII line per data row — use with horizontal scroll in HTML.
    """
    if not headers:
        return []
    n = len(headers)
    widths = []
    for i in range(n):
        if dynamic_columns:
            w = max(len(str(headers[i])), 6)
            for r in rows:
                if i < len(r):
                    cell = str(r[i]).replace("\n", " ").replace("\r", "")
                    w = max(w, len(cell))
            if notes_col_idx is not None and i == notes_col_idx:
                widths.append(min(w, _NOTES_COL_MAX_WIDTH))
            else:
                widths.append(min(w, _DYNAMIC_COL_CAP))
            continue
        if notes_col_idx is not None and i == notes_col_idx:
            w = max(len(str(headers[i])), 8)
            for r in rows:
                if i < len(r):
                    cell = str(r[i]).replace("\n", " ").replace("\r", "")
                    w = max(w, len(cell))
            widths.append(min(w, _NOTES_COL_MAX_WIDTH))
            continue
        cap = max_col or _MAX_COL
        w = min(max(len(headers[i]), 5), cap)
        for r in rows:
            if i < len(r):
                w = min(max(w, min(len(str(r[i])), cap + 10)), cap)
        widths.append(w)
    sep = indent + "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    out = [sep]
    out.append(
        indent + "|" + "|".join(" " + _cell(headers[i], widths[i]) + " " for i in range(n)) + "|"
    )
    out.append(sep)
    for r in rows:
        padded = list(r[:n]) + [""] * (n - min(len(r), n))
        out.append(
            indent + "|" + "|".join(" " + _cell(padded[i], widths[i]) + " " for i in range(n)) + "|"
        )
    out.append(sep)
    return out


def _banner(title, char="=", width=72):
    line = char * width
    return [line, f"  {title}", line]


def _phase0_category_counts(
    drift,
    matched_rows,
    interface_audit,
    os_subnet_gaps,
    os_floating_gaps,
    use_remote_netbox,
):
    maas_only = len(drift.get("in_maas_not_netbox") or [])
    nb_only_dev = len(drift.get("in_netbox_not_maas") or [])
    check_hosts = sum(1 for r in (matched_rows or []) if r.get("place_match") == "CHECK")
    nb_only_nic = 0
    iface_not_ok = 0
    vlan_drift_nic = 0
    vlan_unverified_nic = 0
    for b in (interface_audit or {}).get("hosts") or []:
        nb_only_nic += len(b.get("netbox_only") or [])
        for row in b.get("rows") or []:
            st = row.get("status") or ""
            if st != "OK":
                iface_not_ok += 1
            if st.startswith("VLAN_DRIFT"):
                vlan_drift_nic += 1
            notes = row.get("notes") or ""
            if "VLAN unverified:" in notes:
                vlan_unverified_nic += 1
    if use_remote_netbox or os_subnet_gaps is None:
        sub_gaps = None
    else:
        sub_gaps = len(os_subnet_gaps or [])
    fip_gaps = len(os_floating_gaps or [])
    return {
        "maas_only": maas_only,
        "nb_only_dev": nb_only_dev,
        "check_hosts": check_hosts,
        "nb_only_nic": nb_only_nic,
        "iface_not_ok": iface_not_ok,
        "sub_gaps": sub_gaps,
        "fip_gaps": fip_gaps,
        "vlan_drift_nic": vlan_drift_nic,
        "vlan_unverified_nic": vlan_unverified_nic,
    }


def _matched_hosts_with_drift(matched_rows):
    """Rows that have placement CHECK or any hints (so we show only drifting hosts)."""
    if not matched_rows:
        return []
    return [
        r for r in matched_rows
        if r.get("place_match") == "CHECK" or (r.get("hints") or [])
    ]


def _nic_drift_flat_rows(interface_audit):
    """List of (host, maas_if, maas_mac, nb_if, status, note) for rows with status != OK."""
    out = []
    for block in (interface_audit or {}).get("hosts") or []:
        hn = block.get("hostname", "")
        for row in block.get("rows") or []:
            st = (row.get("status") or "").strip()
            if st != "OK":
                out.append((
                    hn,
                    (row.get("maas_if") or "")[:16],
                    (row.get("maas_mac") or "")[:17],
                    (row.get("nb_if") or "—")[:16],
                    st[:20],
                    (row.get("notes") or ""),
                ))
    return out


def _nb_only_nic_flat_rows(interface_audit):
    """List of (host, nb_intf, mac, ips, vlan) for NetBox-only NICs."""
    out = []
    for block in (interface_audit or {}).get("hosts") or []:
        hn = block.get("hostname", "")
        for x in block.get("netbox_only") or []:
            ips = x.get("ips") or []
            out.append((
                hn,
                (x.get("name") or "")[:14],
                (x.get("mac") or "")[:17],
                ", ".join(ips)[:24] if ips else "—",
                str(x.get("untagged_vlan_vid") or "")[:8],
            ))
    return out


def format_drift_report(
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
    use_remote_netbox=False,
    interface_audit=None,
):
    """
    Return {"drift": str, "reference": str}.
    drift = Phase 0 + drift-only tables (MAAS-only, matched with drift, NIC drift, OS gaps).
    reference = full matched hosts, full per-device NIC audit, OpenStack ref (collapsible in UI).
    OpenStack data is already combined from all configured clouds before being passed here.
    """
    drift_lines = []
    ref_lines = []

    # --- INVENTORY (compact) ---
    drift_lines.extend(_banner("INVENTORY"))
    drift_lines.append("")
    drift_lines.append("  MAAS")
    if maas_data.get("error"):
        drift_lines.append(f"    Error: {maas_data['error']}")
    else:
        drift_lines.extend(
            _ascii_table(
                ["Metric", "Count"],
                [
                    ["Zones", str(len(maas_data.get("zones") or []))],
                    ["Resource pools", str(len(maas_data.get("pools") or []))],
                    ["Machines", str(len(maas_data.get("machines") or []))],
                ],
            )
        )

    drift_lines.append("")
    drift_lines.append("  NetBox (this instance)")
    if netbox_data.get("error"):
        drift_lines.append(f"    Error: {netbox_data['error']}")
    else:
        inv_rows = [
            ["Sites", str(len(netbox_data.get("sites") or []))],
            ["Devices", str(len(netbox_data.get("devices") or []))],
        ]
        if netbox_prefix_count:
            inv_rows.append(["IPAM Prefix objects", str(netbox_prefix_count)])
        drift_lines.extend(_ascii_table(["Metric", "Count"], inv_rows))

    # --- Phase 0 (design doc) — counts only ---
    drift_lines.append("")
    drift_lines.extend(_banner("PHASE 0 — DRIFT CATEGORIES (design doc)"))
    drift_lines.append("  NetBox = design / IPAM; MAAS = bare-metal + MACs; OpenStack = runtime.  sync/DRIFT_DESIGN.md")
    drift_lines.append("  Identity: Device hostname (+ serial); Interface MAC (+ name); FIP = IP + project.")
    drift_lines.append("")
    pc = _phase0_category_counts(
        drift,
        matched_rows,
        interface_audit,
        os_subnet_gaps,
        os_floating_gaps,
        use_remote_netbox,
    )
    sub_txt = str(pc["sub_gaps"]) if pc["sub_gaps"] is not None else "N/A (local ORM)"
    nb_orphan_note = (
        f"{pc['nb_only_dev']} (names hidden in this report)"
        if pc["nb_only_dev"]
        else "0"
    )
    drift_lines.extend(
        _ascii_table(
            ["Drift category", "Count / note"],
            [
                ["MAAS machine → no NetBox Device", str(pc["maas_only"])],
                ["NetBox Device → no MAAS hostname (orphans)", nb_orphan_note],
                ["Matched: placement/lifecycle hints (CHECK)", str(pc["check_hosts"])],
                ["Interface rows not OK (excl. OK)", str(pc["iface_not_ok"])],
                [
                    "Physical NIC vlan-drift (MAAS VID vs NB untagged)",
                    str(pc["vlan_drift_nic"]),
                ],
                [
                    "VLAN unverified (NB VID set; MAAS API no VID)",
                    str(pc["vlan_unverified_nic"]),
                ],
                ["NetBox-only NICs (MAC not on MAAS)", str(pc["nb_only_nic"])],
                ["OpenStack subnet → no exact Prefix", sub_txt],
                ["OpenStack FIP → no NetBox IPAddress", str(pc["fip_gaps"])],
                ["LLDP vs cabling", "not in audit yet"],
            ],
        )
    )

    # --- GAPS: MAAS-only hosts ---
    drift_lines.append("")
    drift_lines.extend(_banner("GAPS — runtime not yet in NetBox", "-"))
    drift_lines.append(
        "  MAAS -> Device; OpenStack subnet CIDR -> Prefix; floating IP -> IPAddress."
    )
    drift_lines.append("")

    maas_only = sorted(drift.get("in_maas_not_netbox") or [])
    drift_lines.append(f"  [MAAS] Machines with no NetBox Device: {len(maas_only)}")
    if maas_data.get("error"):
        drift_lines.append("    (MAAS error)")
    elif maas_only:
        gap_rows = []
        by_h = _maas_machine_by_hostname(maas_data)
        for i, h in enumerate(maas_only):
            if i >= _MAX_MAAS_MISSING_ROWS:
                gap_rows.append([f"... +{len(maas_only) - i} more", "", "", "", ""])
                break
            m = by_h.get(h, {})
            gap_rows.append([
                h[:22],
                str(m.get("zone_name", "-"))[:14],
                str(m.get("pool_name", "-"))[:14],
                str(m.get("status_name", "-"))[:14],
                str(m.get("system_id", ""))[:14],
            ])
        drift_lines.extend(
            _ascii_table(
                ["hostname", "zone", "pool", "MAAS status", "system_id"],
                gap_rows,
            )
        )
    else:
        drift_lines.append("    (none)")

    # --- Matched hosts with drift only (CHECK or hints) ---
    matched_with_drift = _matched_hosts_with_drift(matched_rows)
    if matched_with_drift:
        drift_lines.append("")
        drift_lines.extend(_banner("MATCHED HOSTS WITH DRIFT (review needed)", "-"))
        drift_lines.append("  What sync would do: update site/role/serial from MAAS or flag for review.")
        drift_lines.append("")
        mrows = []
        for r in matched_with_drift:
            notes = "; ".join(r.get("hints") or []) or "—"
            if r.get("place_match") == "CHECK":
                notes = ("CHECK; " + notes) if notes != "—" else "CHECK"
            mrows.append([
                r.get("hostname", "")[:20],
                str(r.get("maas_zone", ""))[:14],
                str(r.get("netbox_site", ""))[:14],
                notes,
            ])
        drift_lines.extend(_ascii_table(
            ["host", "MAAS zone", "NB site", "drift note"],
            mrows,
            notes_col_idx=3,
            dynamic_columns=True,
        ))
        drift_lines.append(f"  ({len(matched_with_drift)} hosts with drift)")

    # --- NIC drift (flat: only status != OK) ---
    nic_drift_rows = _nic_drift_flat_rows(interface_audit)
    if nic_drift_rows:
        drift_lines.append("")
        drift_lines.extend(_banner("NIC DRIFT (interfaces not OK)", "-"))
        drift_lines.append("  What sync would do: align interface/VLAN/IP from MAAS.")
        drift_lines.append("")
        drift_lines.extend(_ascii_table(
            ["host", "MAAS intf", "MAAS MAC", "NB intf", "status", "note"],
            nic_drift_rows,
            notes_col_idx=5,
            dynamic_columns=True,
        ))
        drift_lines.append(f"  ({len(nic_drift_rows)} NIC rows with drift)")

    # --- NetBox-only NICs (MAC not on MAAS) ---
    nb_only_rows = _nb_only_nic_flat_rows(interface_audit)
    if nb_only_rows:
        drift_lines.append("")
        drift_lines.extend(_banner("NETBOX-ONLY NICs (MAC not on MAAS)", "-"))
        drift_lines.append("")
        drift_lines.extend(_ascii_table(
            ["host", "NB intf", "MAC", "IPs", "VLAN"],
            nb_only_rows,
            max_col=24,
        ))
        drift_lines.append(f"  ({len(nb_only_rows)} NetBox-only NICs)")

    # --- OpenStack subnet GAPs ---
    drift_lines.append("")
    if openstack_data and openstack_data.get("error"):
        drift_lines.append("  [OpenStack] Subnet / FIP gaps: API error")
    elif use_remote_netbox or os_subnet_gaps is None:
        drift_lines.append("  [OpenStack] Subnet vs Prefix: not evaluated (use local NetBox ORM).")
    else:
        drift_lines.append(f"  [OpenStack] Subnets without exact Prefix: {len(os_subnet_gaps or [])}")
        if os_subnet_gaps:
            srows = [
                [g.get("cidr", ""), g.get("network_name", "-")[:22], g.get("network_id", "")[:18]]
                for g in os_subnet_gaps
            ]
            drift_lines.extend(_ascii_table(["CIDR", "network", "net_id"], srows))
        else:
            drift_lines.append("    (all subnets have matching Prefix)")

    # --- OpenStack FIP GAPs ---
    drift_lines.append("")
    if openstack_data and not openstack_data.get("error"):
        fg = os_floating_gaps if os_floating_gaps is not None else []
        drift_lines.append(f"  [OpenStack] Floating IPs without NetBox IPAddress: {len(fg)}")
        if fg:
            frows = [
                [
                    g.get("floating_ip", ""),
                    g.get("fixed_ip_address", "-"),
                    str(g.get("project_name") or g.get("project_id") or "-")[:14],
                ]
                for g in fg
            ]
            drift_lines.extend(_ascii_table(["floating_ip", "fixed", "project"], frows))
        else:
            drift_lines.append("    (none)")
    elif not openstack_data:
        drift_lines.append("  [OpenStack] Floating IPs: (not configured)")

    drift_lines.append("")
    drift_lines.extend(_banner("END OF DRIFT AUDIT", "="))

    # ---------- REFERENCE (full data; collapsible in UI) ----------
    ref_lines.extend(_banner("REFERENCE — FULL DATA", "="))
    ref_lines.append("")
    ref_lines.extend(_banner("MAAS <-> NetBox SUMMARY"))
    if netbox_data.get("error"):
        ref_lines.append("  *** NetBox error — summary unreliable ***")
    matched = drift.get("matched_count", 0)
    ref_lines.extend(
        _ascii_table(
            ["Check", "Value"],
            [
                ["Hostnames in MAAS and NetBox", str(matched)],
                ["MAAS only (no Device)", str(len(maas_only))],
            ],
        )
    )

    if matched_rows:
        ref_lines.append("")
        ref_lines.extend(_banner("MATCHED HOSTS (all)"))
        ref_lines.append("  Full list: site / status / serial / BMC / notes.")
        ref_lines.append("")
        mh_headers = [
            "host", "MAAS zone", "MAAS pool", "MAAS st", "NB site", "NB st",
            "MAAS fab", "NB loc", "sys_id", "serial", "pri IP", "VRF", "VLANs",
            "OS FIP", "MAAS BMC", "NB OOB", "notes",
        ]
        mrows = []
        for r in matched_rows:
            notes = "; ".join(r.get("hints") or []) or "—"
            ser = str(r.get("netbox_serial", ""))
            if ser == "(empty)":
                ser = "—"
            mrows.append([
                r["hostname"],
                str(r.get("maas_zone", "")),
                str(r.get("maas_pool", "")),
                str(r.get("maas_status", "")),
                str(r.get("netbox_site", "")),
                str(r.get("netbox_status", "")),
                str(r.get("maas_fabric", "")),
                str(r.get("netbox_location", "")),
                str(r.get("maas_system_id", "")),
                ser,
                str(r.get("netbox_primary_ip", "")),
                str(r.get("netbox_vrf", "")),
                str(r.get("netbox_vlans", "")),
                str(r.get("openstack_fip", "")),
                str(r.get("maas_bmc", "")),
                str(r.get("netbox_oob", "")),
                notes,
            ])
        ref_lines.extend(
            _ascii_table(mh_headers, mrows, notes_col_idx=len(mh_headers) - 1, dynamic_columns=True)
        )
        ref_lines.append(f"  ({len(matched_rows)} matched hosts)")

    if interface_audit and interface_audit.get("hosts") and not use_remote_netbox:
        ref_lines.append("")
        ref_lines.extend(_banner("MAAS <-> NetBox INTERFACES (per device)"))
        ref_lines.append("  Each row: one MAAS NIC. NetBox columns when same MAC exists.")
        ref_lines.append("")
        for block in interface_audit["hosts"]:
            hn = block["hostname"]
            ref_lines.extend(_banner(f"DEVICE: {hn}", "-"))
            if block.get("rows"):
                irows = [
                    [
                        x.get("maas_fabric", "")[:10], x.get("maas_pool", "")[:8], x.get("maas_vlan", "")[:6],
                        x.get("nb_site", "")[:8], x.get("nb_location", "")[:10],
                        x["maas_if"][:12], x["maas_mac"][:17], x["maas_ips"][:22],
                        x["nb_if"][:12], x.get("nb_mac", "—")[:17], x.get("nb_vlan", "")[:6], x["nb_ips"][:22],
                        x["status"][:18], x["notes"],
                    ]
                    for x in block["rows"]
                ]
                ref_lines.extend(
                    _ascii_table(
                        ["MAAS fab", "MA pool", "MA VLAN", "NB site", "NB loc", "MAAS intf", "MAAS MAC", "MAAS IPs",
                         "NB intf", "NB MAC", "NB VLAN", "NB IPs", "status", "notes"],
                        irows, max_col=22, notes_col_idx=13,
                    )
                )
            else:
                ref_lines.append("    (no MAAS interfaces)")
            nb_only = block.get("netbox_only") or []
            if nb_only:
                ref_lines.append(f"  NetBox-only: {len(nb_only)}")
                nrows = [
                    [(x.get("name") or "")[:14], (x.get("mac") or "")[:17], (", ".join(x.get("ips") or [])[:24] or "—")]
                    for x in nb_only
                ]
                ref_lines.extend(_ascii_table(["NB intf", "MAC", "IPs"], nrows, max_col=20))
            ref_lines.append("")
    elif use_remote_netbox:
        ref_lines.append("")
        ref_lines.append("  (Interface audit requires local NetBox ORM.)")

    if openstack_data and not openstack_data.get("error"):
        ref_lines.append("")
        ref_lines.extend(_banner("OPENSTACK REFERENCE"))
        ref_lines.append("  Networks, subnets vs Prefix, full FIP list.")
        ref_lines.append("")
        nets = openstack_data.get("networks") or []
        subs = openstack_data.get("subnets") or []
        fips = openstack_data.get("floating_ips") or []
        ref_lines.extend(
            _ascii_table(
                ["Object", "Count"],
                [["Networks", str(len(nets))], ["Subnets", str(len(subs))], ["Floating IPs", str(len(fips))]],
            )
        )
        ref_lines.append("")
        nrows = [[(n.get("name") or n.get("id") or "")[:30], (n.get("id") or "")[:36]] for n in nets[:_MAX_OS_NETWORKS]]
        if nrows:
            ref_lines.extend(_ascii_table(["Network", "id"], nrows))
        if os_subnet_hints:
            ref_lines.append("")
            ref_lines.append("  Subnets vs NetBox Prefix (exact CIDR)")
            sh = [["OK" if h.get("exact_prefix_in_netbox") else "GAP", h.get("cidr", ""), (h.get("network_name") or "")[:20]] for h in os_subnet_hints[:_MAX_OS_SUBNET_HINTS]]
            ref_lines.extend(_ascii_table(["", "CIDR", "network"], sh))
        if fips:
            ref_lines.append("")
            frows = [[f.get("floating_ip_address", ""), f.get("fixed_ip_address", ""), str(f.get("project_name") or "-")[:14]] for f in fips[:25]]
            ref_lines.extend(_ascii_table(["floating_ip", "fixed_ip", "project"], frows))
            if len(fips) > 25:
                ref_lines.append(f"  ... {len(fips) - 25} more FIPs")

    ref_lines.append("")
    ref_lines.extend(_banner("END OF REFERENCE", "="))

    return {"drift": "\n".join(drift_lines), "reference": "\n".join(ref_lines)}


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
    use_remote_netbox=False,
    interface_audit=None,
):
    """
    Build an Excel (.xlsx) workbook from the same inputs as format_drift_report.
    Returns bytes suitable for HttpResponse(..., content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet").
    Google Sheets opens .xlsx files.
    """
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
    except ImportError:
        raise RuntimeError("openpyxl is required for XLSX export. pip install openpyxl")

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
    ws_sum.append(["MAAS", "OK" if not maas_data.get("error") else "Error", ""])
    ws_sum.append(["  Machines", str(len(maas_data.get("machines") or [])), ""])
    ws_sum.append(["NetBox", "OK" if not netbox_data.get("error") else "Error", ""])
    ws_sum.append(["  Devices", str(len(netbox_data.get("devices") or [])), ""])
    ws_sum.append(["  Sites", str(len(netbox_data.get("sites") or [])), ""])
    if netbox_prefix_count:
        ws_sum.append(["  IPAM Prefixes", str(netbox_prefix_count), ""])
    ws_sum.append([])
    if openstack_data is None:
        ws_sum.append(["OpenStack", "Not configured", ""])
    elif openstack_data.get("error"):
        ws_sum.append(["OpenStack", "Error", (openstack_data.get("error") or "")[:200]])
    else:
        nets = openstack_data.get("networks") or []
        subs = openstack_data.get("subnets") or []
        fips = openstack_data.get("floating_ips") or []
        ws_sum.append(["OpenStack", "OK", ""])
        ws_sum.append(["  Networks", str(len(nets)), ""])
        ws_sum.append(["  Subnets", str(len(subs)), ""])
        ws_sum.append(["  Floating IPs", str(len(fips)), ""])
    ws_sum.append([])
    pc = _phase0_category_counts(
        drift,
        matched_rows,
        interface_audit,
        os_subnet_gaps,
        os_floating_gaps or [],
        use_remote_netbox,
    )
    sub_txt = str(pc["sub_gaps"]) if pc["sub_gaps"] is not None else "N/A"
    ws_sum.append([])
    ws_sum.append(["Phase 0 — Drift categories", "", ""])
    _append_header(ws_sum, ["Category", "Count"])
    ws_sum.append(["MAAS only (no NetBox Device)", str(pc["maas_only"])])
    ws_sum.append(["NetBox only (no MAAS hostname)", str(pc["nb_only_dev"])])
    ws_sum.append(["Matched — CHECK (placement/lifecycle)", str(pc["check_hosts"])])
    ws_sum.append(["Interface rows not OK", str(pc["iface_not_ok"])])
    ws_sum.append(["VLAN drift NICs", str(pc["vlan_drift_nic"])])
    ws_sum.append(["VLAN unverified NICs", str(pc["vlan_unverified_nic"])])
    ws_sum.append(["NetBox-only NICs", str(pc["nb_only_nic"])])
    ws_sum.append(["OpenStack subnet gaps", sub_txt])
    ws_sum.append(["OpenStack FIP gaps", str(pc["fip_gaps"])])
    ws_sum.append([])
    ws_sum.append(["MAAS <-> NetBox matched hostnames", str(drift.get("matched_count", 0)), ""])

    # --- Matched hosts with drift only (same as on-screen report) ---
    matched_with_drift = _matched_hosts_with_drift(matched_rows)
    if matched_with_drift:
        ws_mh = _sheet("Matched hosts with drift")
        _append_header(ws_mh, ["host", "MAAS zone", "NB site", "drift note"])
        for r in matched_with_drift:
            notes = "; ".join(r.get("hints") or []) or "—"
            if r.get("place_match") == "CHECK":
                notes = ("CHECK; " + notes) if notes != "—" else "CHECK"
            ws_mh.append([
                r.get("hostname", ""),
                str(r.get("maas_zone", "")),
                str(r.get("netbox_site", "")),
                notes,
            ])

    # --- NIC drift (only status != OK; same as on-screen report) ---
    nic_drift_rows = _nic_drift_flat_rows(interface_audit)
    if nic_drift_rows:
        ws_nic = _sheet("NIC drift")
        _append_header(ws_nic, ["host", "MAAS intf", "MAAS MAC", "NB intf", "status", "note"])
        for row in nic_drift_rows:
            ws_nic.append(list(row))

    # --- NB-only NICs (same as on-screen report) ---
    nb_only_rows = _nb_only_nic_flat_rows(interface_audit)
    if nb_only_rows:
        ws_nb = _sheet("NB-only NICs")
        _append_header(ws_nb, ["host", "NB intf", "MAC", "IPs", "VLAN"])
        for row in nb_only_rows:
            ws_nb.append(list(row))

    # --- MAAS only (no NetBox Device) ---
    maas_only = sorted(drift.get("in_maas_not_netbox") or [])
    if maas_only is not None:
        ws_maas = _sheet("MAAS only")
        by_h = _maas_machine_by_hostname(maas_data)
        _append_header(ws_maas, ["hostname", "zone", "pool", "MAAS status", "system_id"])
        for h in maas_only:
            m = by_h.get(h, {})
            ws_maas.append([
                h,
                str(m.get("zone_name", "-")),
                str(m.get("pool_name", "-")),
                str(m.get("status_name", "-")),
                str(m.get("system_id", "")),
            ])

    # --- OpenStack subnet gaps ---
    if os_subnet_gaps:
        ws_sub = _sheet("OS subnet gaps")
        _append_header(ws_sub, ["CIDR", "network", "network_id"])
        for g in os_subnet_gaps:
            ws_sub.append([
                g.get("cidr", ""),
                (g.get("network_name") or "-")[:60],
                (g.get("network_id") or "")[:40],
            ])

    # --- OpenStack FIP gaps ---
    if os_floating_gaps:
        ws_fip = _sheet("OS FIP gaps")
        _append_header(ws_fip, ["floating_ip", "fixed_ip", "project"])
        for g in os_floating_gaps:
            ws_fip.append([
                g.get("floating_ip", ""),
                g.get("fixed_ip_address", "-"),
                str(g.get("project_name") or g.get("project_id") or "-")[:40],
            ])

    # --- OpenStack reference (networks) ---
    if openstack_data and not openstack_data.get("error"):
        nets = openstack_data.get("networks") or []
        if nets:
            ws_os = _sheet("OpenStack networks")
            _append_header(ws_os, ["name", "id"])
            for n in nets:
                ws_os.append([
                    (n.get("name") or n.get("id") or "")[:60],
                    (n.get("id") or "")[:40],
                ])

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()
