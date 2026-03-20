"""
Generate human-readable drift audit report from MAAS, NetBox, and OpenStack data.
Uses ASCII tables (+---+) for readability in <pre> or plain text.
XLSX export via build_drift_report_xlsx() for download (openpyxl); Google Sheets opens .xlsx.
"""

from io import BytesIO
import re

_MAX_MAAS_MISSING_ROWS = 500
_MAX_OS_NETWORKS = 40
_MAX_OS_SUBNET_HINTS = 60
_MAX_COL = 10000
_MAX_MATCHED_COL = 18
_MAX_NOTES_COL = 42
# Notes column: full text for scrollable HTML report (avoid truncation)
_NOTES_COL_MAX_WIDTH = 8000
# Matched-hosts style tables: full cell text per column (no mid-cell truncation)
_DYNAMIC_COL_CAP = 10000


def _dedupe_keep_order(items):
    seen = set()
    out = []
    for raw in (items or []):
        s = (str(raw or "")).strip()
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


def _format_inventory_list(items, *, noisy_regex=None, noisy_label="auto-generated", sample=20):
    vals = _dedupe_keep_order(items)
    if not vals:
        return "(none)"
    if not noisy_regex:
        return ", ".join(vals)
    pat = re.compile(noisy_regex)
    noisy = [v for v in vals if pat.match(v)]
    named = [v for v in vals if not pat.match(v)]
    parts = []
    if named:
        parts.append(f"named ({len(named)}): {', '.join(named)}")
    if noisy:
        show = noisy[:sample]
        more = len(noisy) - len(show)
        txt = ", ".join(show)
        if more > 0:
            txt = f"{txt}, ... +{more} more"
        parts.append(f"{noisy_label} ({len(noisy)}): {txt}")
    return " | ".join(parts) if parts else "(none)"


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
    dynamic_columns=True,
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
        cap = max_col if max_col is not None else _MAX_COL
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
    if os_subnet_gaps is None:
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


def _count_hints(matched_rows, needle: str) -> int:
    c = 0
    for r in (matched_rows or []):
        for h in (r.get("hints") or []):
            if needle in (h or ""):
                c += 1
                break
    return c


def _device_by_name(netbox_data):
    out = {}
    for d in (netbox_data or {}).get("devices") or []:
        n = (d.get("name") or "").strip()
        if n:
            out[n] = d
    return out


def _dedupe_note_parts(text: str) -> str:
    if not text:
        return ""
    parts = [p.strip() for p in str(text).replace("\n", " ").split(";")]
    seen = set()
    ordered = []
    for p in parts:
        if not p:
            continue
        k = p.lower()
        if k in seen:
            continue
        seen.add(k)
        ordered.append(p)
    return "; ".join(ordered)


def _friendly_note(raw: str) -> str:
    note = _dedupe_note_parts(raw or "")
    parts = [p.strip() for p in note.split(";") if p.strip()]
    low = note.lower()
    # Keep IP-alignment rows focused on IP only; VLAN/MAC details belong to other sections.
    for p in parts:
        pl = p.lower()
        if "ip on maas not on nb iface:" in pl:
            return p
    for p in parts:
        pl = p.lower()
        if "ip" in pl and ("missing" in pl or "not on" in pl or "gap" in pl):
            return p
    # Drop MAC-only details from IP table and keep user-facing wording clear.
    non_mac = [
        p for p in parts
        if ("mac" not in p.lower() and "interface name" not in p.lower())
    ]
    for p in non_mac:
        pl = p.lower()
        if "ip" in pl:
            return p
    if "mac" in low:
        return "IP mismatch detected on this interface; review interface IP assignment."
    if "ip gap" in low:
        return "IP found in MAAS but missing on matching NetBox interface."
    if "vlan drift" in low:
        return "VLAN mismatch between MAAS and NetBox interface."
    if "vlan unverified" in low:
        return "MAAS did not return VLAN ID; verify VLAN manually."
    if "mac mismatch" in low:
        return "Matching interface name found, but MAC differs."
    return note or "Review interface data."


def _proposed_changes_rows(
    maas_data,
    netbox_data,
    drift,
    interface_audit,
    matched_rows,
    os_subnet_gaps,
    os_floating_gaps,
):
    """Build user-friendly proposed change buckets (preview only)."""
    by_h = _maas_machine_by_hostname(maas_data)
    nb_by_name = _device_by_name(netbox_data)

    add_devices = []
    for h in sorted(drift.get("in_maas_not_netbox") or []):
        m = by_h.get(h, {})
        add_devices.append([
            h,
            str(m.get("zone_name", "-")),
            str(m.get("pool_name", "-")),
            str(m.get("status_name", "-")),
            str(m.get("system_id", "")),
            "maas-discovered",
            "Create device + interfaces",
        ])

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

    update_nic = []
    for b in (interface_audit or {}).get("hosts") or []:
        hn = b.get("hostname", "")
        for row in b.get("rows") or []:
            st = row.get("status") or ""
            if st == "OK":
                continue
            notes = row.get("notes") or ""
            maas_vlan = str(row.get("maas_vlan") or "—")
            nb_vlan = str(row.get("nb_vlan") or "—")
            statuses = []
            reasons = []
            actions = []
            risk = "Medium"

            if "VLAN_DRIFT" in st:
                if nb_vlan in {"", "—", "None", "none"}:
                    statuses.append("MISSING_NB_VLAN")
                    reasons.append("NetBox VLAN missing; MAAS VLAN present")
                    actions.append("Set NetBox untagged VLAN from MAAS VLAN")
                else:
                    statuses.append("VLAN_MISMATCH")
                    reasons.append("NetBox VLAN differs from MAAS VLAN")
                    actions.append("Change NetBox untagged VLAN to match MAAS VLAN")
                risk = "High"

            if "IP_GAP" in st:
                statuses.append("MISSING_NB_IP")
                reasons.append(_friendly_note(notes))
                actions.append("Add missing IP to NetBox interface")

            note_l = notes.lower()
            if ("netbox mac empty" in note_l) or ("mac mismatch" in note_l):
                if "mac mismatch" in note_l:
                    statuses.append("MAC_MISMATCH")
                else:
                    statuses.append("MISSING_NB_MAC")
                reasons.append("NetBox MAC missing or mismatched")
                actions.append("Set NetBox interface MAC from MAAS for reliable matching")

            if not statuses:
                statuses.append(st)
                reasons.append(_dedupe_note_parts(notes) or "Interface review needed")
                actions.append("Review interface alignment manually")

            update_nic.append([
                hn,
                row.get("maas_if") or "",
                row.get("maas_mac") or "",
                row.get("maas_ips") or "",
                row.get("nb_if") or "—",
                row.get("nb_mac") or "—",
                row.get("nb_ips") or "—",
                maas_vlan,
                nb_vlan,
                ", ".join(dict.fromkeys(statuses)),
                "; ".join(dict.fromkeys([r for r in reasons if r])),
                "; ".join(dict.fromkeys([a for a in actions if a])),
                risk,
            ])

    review_orphans = []
    for n in sorted(drift.get("in_netbox_not_maas") or []):
        d = nb_by_name.get(n, {})
        review_orphans.append([
            n,
            d.get("site_slug", "-"),
            d.get("status", "-"),
            "orphaned",
            "Review only; no automatic deletion",
            "Medium",
        ])

    review_serial = []
    review_bmc = []
    for r in (matched_rows or []):
        if "NB serial empty — correlate system_id" in (r.get("hints") or []):
            review_serial.append([
                r.get("hostname", ""),
                str(r.get("maas_serial", "")),
                str(r.get("maas_system_id", "")),
                str(r.get("netbox_serial", "")),
                "Manual validation",
                "High",
            ])
        maas_bmc = str(r.get("maas_bmc") or "—")
        nb_oob = str(r.get("netbox_oob") or "—")
        if maas_bmc != "—" and nb_oob != "—" and maas_bmc.lower() != nb_oob.lower():
            review_bmc.append([
                r.get("hostname", ""),
                maas_bmc,
                nb_oob,
                "Review/correct OOB field",
                "High",
            ])

    return {
        "add_devices": add_devices,
        "add_prefixes": add_prefixes,
        "add_fips": add_fips,
        "update_nic": update_nic,
        "review_orphans": review_orphans,
        "review_serial": review_serial,
        "review_bmc": review_bmc,
    }


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

    scope_meta = (drift or {}).get("scope_meta") or {}
    if scope_meta:
        drift_lines.append("")
        drift_lines.extend(_banner("SCOPE COVERAGE CHECK", "-"))
        sel_sites = ", ".join(scope_meta.get("selected_sites") or []) or "(all)"
        sel_locs = ", ".join(scope_meta.get("selected_locations") or []) or "(all)"
        os_unmatched = list(scope_meta.get("openstack_unmatched_network_names") or [])
        if scope_meta.get("openstack_unmatched_network_names_more"):
            os_unmatched.append(f"... +{scope_meta['openstack_unmatched_network_names_more']} more")
        maas_unmatched = list(scope_meta.get("maas_unmatched_fabrics") or [])
        if scope_meta.get("maas_unmatched_fabrics_more"):
            maas_unmatched.append(f"... +{scope_meta['maas_unmatched_fabrics_more']} more")
        drift_lines.extend(_ascii_table(
            ["Check", "Value"],
            [
                ["Coverage status", str(scope_meta.get("coverage_status") or "PARTIAL")],
                ["Selected sites", sel_sites],
                ["Selected locations", sel_locs],
                [
                    "MAAS machines included / fetched",
                    f"{scope_meta.get('maas_machines_after', 0)} / {scope_meta.get('maas_machines_before', 0)}",
                ],
                [
                    "NetBox devices included / fetched",
                    f"{scope_meta.get('netbox_devices_after', 0)} / {scope_meta.get('netbox_devices_before', 0)}",
                ],
                [
                    "OpenStack nets included / fetched",
                    f"{scope_meta.get('openstack_networks_after', 0)} / {scope_meta.get('openstack_networks_before', 0)}",
                ],
                [
                    "OpenStack subnets included / fetched",
                    f"{scope_meta.get('openstack_subnets_after', 0)} / {scope_meta.get('openstack_subnets_before', 0)}",
                ],
                [
                    "OpenStack FIPs included / fetched",
                    f"{scope_meta.get('openstack_fips_after', 0)} / {scope_meta.get('openstack_fips_before', 0)}",
                ],
                [
                    "MAAS all fabrics (pre-scope, summarized)",
                    _format_inventory_list(
                        scope_meta.get("maas_all_fabrics") or [],
                        noisy_regex=r"^fabric-\d+$",
                        noisy_label="fabric-<number>",
                    ),
                ],
                [
                    "MAAS fabrics fetched (in-scope)",
                    _format_inventory_list(
                        scope_meta.get("maas_fabrics_after") or [],
                        noisy_regex=r"^fabric-\d+$",
                        noisy_label="fabric-<number>",
                    ),
                ],
                [
                    "OpenStack all network names (pre-scope)",
                    _format_inventory_list(scope_meta.get("openstack_all_network_names") or []),
                ],
                [
                    "OpenStack network names fetched (in-scope)",
                    _format_inventory_list(scope_meta.get("openstack_network_names_after") or []),
                ],
                ["MAAS unmatched fabrics (sample)", ", ".join(maas_unmatched) or "(none)"],
                ["OpenStack unmatched network names (sample)", ", ".join(os_unmatched) or "(none)"],
            ],
            dynamic_columns=True,
        ))

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
    )
    serial_validation_needed = _count_hints(matched_rows, "NB serial empty")
    bmc_oob_mismatch = _count_hints(matched_rows, "MAAS BMC ")
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
                ["MAAS-only runtime-discovered (tag: maas-discovered)", str(pc["maas_only"])],
                ["NetBox-only orphan devices (tag: orphaned)", nb_orphan_note],
                ["Matched: placement/lifecycle hints (CHECK)", str(pc["check_hosts"])],
                ["Device serial validation needed (NB serial empty)", str(serial_validation_needed)],
                ["Interface rows not OK (excl. OK)", str(pc["iface_not_ok"])],
                [
                    "Physical NIC vlan-drift (MAAS VID vs NB untagged)",
                    str(pc["vlan_drift_nic"]),
                ],
                [
                    "VLAN unverified (NB VID set; MAAS API no VID)",
                    str(pc["vlan_unverified_nic"]),
                ],
                ["NetBox-only NICs (review signal, not auto-change)", str(pc["nb_only_nic"])],
                ["OpenStack subnet → no exact Prefix", sub_txt],
                ["OpenStack FIP → no NetBox IPAddress", str(pc["fip_gaps"])],
                ["MAAS BMC vs NetBox OOB mismatch", str(bmc_oob_mismatch)],
                ["LLDP vs cabling", "not in audit yet"],
            ],
        )
    )

    # --- High-risk summary (design doc: review-first deltas) ---
    drift_lines.append("")
    drift_lines.extend(_banner("HIGH-RISK DIFFERENCES (review first)", "-"))
    drift_lines.append("  Definition (v1): OS FIP/IPAM gaps, OS subnet/prefix gaps, VLAN_DRIFT, serial validation gaps, BMC/OOB mismatch.")
    hr_rows = []
    hr_total = 0
    for name, val in [
        ("OpenStack FIP not in NetBox IPAddress", pc["fip_gaps"]),
        ("OpenStack subnet without exact Prefix", pc["sub_gaps"] if pc["sub_gaps"] is not None else "N/A"),
        ("Physical NIC VLAN_DRIFT", pc["vlan_drift_nic"]),
        ("Serial validation needed (NB serial empty)", serial_validation_needed),
        ("MAAS BMC vs NetBox OOB mismatch", bmc_oob_mismatch),
    ]:
        hr_rows.append([name, str(val)])
        if isinstance(val, int):
            hr_total += val
    drift_lines.extend(_ascii_table(["High-risk category", "Count"], hr_rows))
    drift_lines.append(f"  High-risk total (numeric categories): {hr_total}")

    # --- Metrics (design doc summary statistics) ---
    drift_lines.append("")
    drift_lines.extend(_banner("METRICS (this run)", "-"))
    drift_lines.extend(_ascii_table(
        ["Metric", "Value"],
        [
            ["MAAS machines", str(len(maas_data.get("machines") or []))],
            ["NetBox devices", str(len(netbox_data.get("devices") or []))],
            ["Matched hostnames", str(drift.get("matched_count", 0))],
            ["MAAS-only runtime-discovered", str(pc["maas_only"])],
            ["NetBox-only orphan devices", str(pc["nb_only_dev"])],
            ["Serial validation needed", str(serial_validation_needed)],
            ["OpenStack subnet gaps", sub_txt],
            ["OpenStack FIP gaps", str(pc["fip_gaps"])],
            ["Physical NIC VLAN_DRIFT", str(pc["vlan_drift_nic"])],
            ["VLAN unverified NICs", str(pc["vlan_unverified_nic"])],
        ],
    ))

    # --- Proposed changes (preview only; full list, uncapped) ---
    prop = _proposed_changes_rows(
        maas_data,
        netbox_data,
        drift,
        interface_audit,
        matched_rows,
        os_subnet_gaps or [],
        os_floating_gaps or [],
    )
    drift_lines.append("")
    drift_lines.extend(_banner("PROPOSED CHANGES (PREVIEW ONLY)", "-"))
    drift_lines.append("  Important: Drift Audit does not apply these changes to NetBox.")
    drift_lines.append("  Safety: No automatic deletion is performed by this workflow.")
    drift_lines.append("")

    drift_lines.append("  A) Add to NetBox")
    drift_lines.extend(_ascii_table(
        ["Category", "Count", "Meaning"],
        [
            ["Devices from MAAS", str(len(prop["add_devices"])), "Machine in MAAS, missing in NetBox"],
            ["Prefixes from OpenStack", str(len(prop["add_prefixes"])), "Subnet in OpenStack, missing Prefix"],
            ["Floating IPs from OpenStack", str(len(prop["add_fips"])), "FIP in OpenStack, missing IPAddress"],
        ],
    ))
    if prop["add_devices"]:
        drift_lines.append("  Devices to create from MAAS (`maas-discovered`)")
        drift_lines.extend(_ascii_table(
            ["Hostname", "Zone", "Pool", "MAAS Status", "System ID", "Proposed Tag", "Proposed Action"],
            prop["add_devices"],
            dynamic_columns=True,
        ))
    if prop["add_prefixes"]:
        drift_lines.append("  Prefixes to create from OpenStack")
        drift_lines.extend(_ascii_table(
            ["CIDR", "Network Name", "Network ID", "Cloud", "Proposed Action"],
            prop["add_prefixes"],
            dynamic_columns=True,
        ))
    if prop["add_fips"]:
        drift_lines.append("  Floating IPs to create in NetBox IPAM")
        drift_lines.extend(_ascii_table(
            ["Floating IP", "Fixed IP", "Project", "Cloud", "Proposed Action"],
            prop["add_fips"],
            dynamic_columns=True,
        ))

    drift_lines.append("")
    drift_lines.append("  B) Update in NetBox")
    drift_lines.extend(_ascii_table(
        ["Category", "Count", "Meaning"],
        [
            ["NIC drift updates (per interface)", str(len(prop["update_nic"])), "Combined VLAN/IP/MAC interface alignment actions"],
        ],
    ))
    if prop["update_nic"]:
        drift_lines.append("  NIC drift updates (single per-interface table)")
        drift_lines.extend(_ascii_table(
            ["Host", "MAAS intf", "MAAS MAC", "MAAS IPs", "NB intf", "NB MAC", "NB IPs", "MAAS VLAN", "NB VLAN", "Status", "Reason", "Proposed Action", "Risk"],
            prop["update_nic"],
            dynamic_columns=True,
        ))

    drift_lines.append("")
    drift_lines.append("  C) Review required (no auto-apply)")
    drift_lines.extend(_ascii_table(
        ["Category", "Count", "Meaning"],
        [
            ["NetBox orphan devices", str(len(prop["review_orphans"])), "Device exists in NetBox but not in MAAS"],
            ["Serial validation required", str(len(prop["review_serial"])), "NetBox serial missing; validate identity"],
            ["BMC vs OOB mismatch", str(len(prop["review_bmc"])), "MAAS BMC differs from NetBox OOB"],
        ],
    ))
    if prop["review_orphans"]:
        drift_lines.append("  NetBox orphan devices (`orphaned`)")
        drift_lines.extend(_ascii_table(
            ["Hostname", "Site", "Status", "Proposed Tag", "Proposed Action", "Risk"],
            prop["review_orphans"],
            dynamic_columns=True,
        ))
        drift_lines.append("  Note: These are review-only records. No automatic deletion.")
    if prop["review_serial"]:
        drift_lines.append("  Serial validation required")
        drift_lines.extend(_ascii_table(
            ["Hostname", "MAAS Serial", "MAAS System ID", "NetBox Serial", "Proposed Action", "Risk"],
            prop["review_serial"],
            dynamic_columns=True,
        ))
    if prop["review_bmc"]:
        drift_lines.append("  BMC vs OOB mismatch")
        drift_lines.extend(_ascii_table(
            ["Hostname", "MAAS BMC", "NetBox OOB", "Proposed Action", "Risk"],
            prop["review_bmc"],
            dynamic_columns=True,
        ))

    drift_lines.append("")
    drift_lines.append("  PROPOSED CHANGES SUMMARY")
    total_props = (
        len(prop["add_devices"]) + len(prop["add_prefixes"]) + len(prop["add_fips"]) +
        len(prop["update_nic"]) +
        len(prop["review_orphans"]) + len(prop["review_serial"]) + len(prop["review_bmc"])
    )
    drift_lines.extend(_ascii_table(
        ["Bucket", "Count"],
        [
            ["Add: Devices", str(len(prop["add_devices"]))],
            ["Add: Prefixes", str(len(prop["add_prefixes"]))],
            ["Add: Floating IPs", str(len(prop["add_fips"]))],
            ["Update: NIC drift (combined)", str(len(prop["update_nic"]))],
            ["Review: Orphans", str(len(prop["review_orphans"]))],
            ["Review: Serial", str(len(prop["review_serial"]))],
            ["Review: BMC/OOB", str(len(prop["review_bmc"]))],
            ["Total proposed records", str(total_props)],
        ],
    ))

    # --- GAPS: MAAS-only hosts ---
    drift_lines.append("")
    drift_lines.extend(_banner("GAPS — runtime not yet in NetBox", "-"))
    drift_lines.append("  Concise view below; full proposed rows are shown in PROPOSED CHANGES.")
    drift_lines.append("")

    maas_only = sorted(drift.get("in_maas_not_netbox") or [])
    drift_lines.append(f"  [MAAS] MAAS-only runtime-discovered (no NetBox Device): {len(maas_only)}")
    if maas_data.get("error"):
        drift_lines.append("    (MAAS error)")
    elif maas_only:
        drift_lines.append("    (see A) Add to NetBox -> Devices to create from MAAS)")
    else:
        drift_lines.append("    (none)")

    # Matched-host drift reference table intentionally suppressed to keep report concise.

    # NIC drift is shown in Proposed Changes as a single combined per-interface table.

    # OpenStack details are intentionally hidden from on-screen drift output.

    drift_lines.append("")
    drift_lines.extend(_banner("END OF DRIFT AUDIT", "="))

    # ---------- REFERENCE ----------
    # Hidden intentionally for user-facing output.

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
    ws_sum.append([])
    pc = _phase0_category_counts(
        drift,
        matched_rows,
        interface_audit,
        os_subnet_gaps,
        os_floating_gaps or [],
    )
    serial_validation_needed = _count_hints(matched_rows, "NB serial empty")
    bmc_oob_mismatch = _count_hints(matched_rows, "MAAS BMC ")
    sub_txt = str(pc["sub_gaps"]) if pc["sub_gaps"] is not None else "N/A"
    ws_sum.append([])
    ws_sum.append(["Phase 0 — Drift categories", "", ""])
    _append_header(ws_sum, ["Category", "Count"])
    ws_sum.append(["MAAS-only runtime-discovered (maas-discovered)", str(pc["maas_only"])])
    ws_sum.append(["NetBox-only orphan devices (orphaned)", str(pc["nb_only_dev"])])
    ws_sum.append(["Matched — CHECK (placement/lifecycle)", str(pc["check_hosts"])])
    ws_sum.append(["Serial validation needed (NB serial empty)", str(serial_validation_needed)])
    ws_sum.append(["Interface rows not OK", str(pc["iface_not_ok"])])
    ws_sum.append(["VLAN drift NICs", str(pc["vlan_drift_nic"])])
    ws_sum.append(["VLAN unverified NICs", str(pc["vlan_unverified_nic"])])
    ws_sum.append(["NetBox-only NICs", str(pc["nb_only_nic"])])
    ws_sum.append(["OpenStack subnet gaps", sub_txt])
    ws_sum.append(["OpenStack FIP gaps", str(pc["fip_gaps"])])
    ws_sum.append(["MAAS BMC vs NetBox OOB mismatch", str(bmc_oob_mismatch)])
    ws_sum.append([])
    ws_sum.append(["High-risk differences (v1)", "", ""])
    _append_header(ws_sum, ["High-risk category", "Count"])
    ws_sum.append(["OpenStack FIP not in NetBox IPAddress", str(pc["fip_gaps"])])
    ws_sum.append(["OpenStack subnet without exact Prefix", sub_txt])
    ws_sum.append(["Physical NIC VLAN_DRIFT", str(pc["vlan_drift_nic"])])
    ws_sum.append(["Serial validation needed", str(serial_validation_needed)])
    ws_sum.append(["MAAS BMC vs NetBox OOB mismatch", str(bmc_oob_mismatch)])
    ws_sum.append([])
    ws_sum.append(["MAAS <-> NetBox matched hostnames", str(drift.get("matched_count", 0)), ""])

    scope_meta = (drift or {}).get("scope_meta") or {}
    if scope_meta:
        ws_sum.append([])
        ws_sum.append(["Scope coverage check", "", ""])
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
            "MAAS all fabrics (pre-scope, summarized)",
            _format_inventory_list(
                scope_meta.get("maas_all_fabrics") or [],
                noisy_regex=r"^fabric-\d+$",
                noisy_label="fabric-<number>",
            ),
        ])
        ws_sum.append([
            "MAAS fabrics fetched (in-scope)",
            _format_inventory_list(
                scope_meta.get("maas_fabrics_after") or [],
                noisy_regex=r"^fabric-\d+$",
                noisy_label="fabric-<number>",
            ),
        ])
        ws_sum.append([
            "OpenStack all network names (pre-scope)",
            _format_inventory_list(scope_meta.get("openstack_all_network_names") or []),
        ])
        ws_sum.append([
            "OpenStack network names fetched (in-scope)",
            _format_inventory_list(scope_meta.get("openstack_network_names_after") or []),
        ])
        maas_unmatched = list(scope_meta.get("maas_unmatched_fabrics") or [])
        if scope_meta.get("maas_unmatched_fabrics_more"):
            maas_unmatched.append(f"... +{scope_meta['maas_unmatched_fabrics_more']} more")
        os_unmatched = list(scope_meta.get("openstack_unmatched_network_names") or [])
        if scope_meta.get("openstack_unmatched_network_names_more"):
            os_unmatched.append(f"... +{scope_meta['openstack_unmatched_network_names_more']} more")
        ws_sum.append(["MAAS unmatched fabrics (sample)", ", ".join(maas_unmatched) or "(none)"])
        ws_sum.append(["OpenStack unmatched network names (sample)", ", ".join(os_unmatched) or "(none)"])

    prop = _proposed_changes_rows(
        maas_data,
        netbox_data,
        drift,
        interface_audit,
        matched_rows,
        os_subnet_gaps or [],
        os_floating_gaps or [],
    )
    ws_sum.append([])
    ws_sum.append(["Proposed changes (preview only)", "", ""])
    _append_header(ws_sum, ["Bucket", "Count"])
    ws_sum.append(["Add: Devices", str(len(prop["add_devices"]))])
    ws_sum.append(["Add: Prefixes", str(len(prop["add_prefixes"]))])
    ws_sum.append(["Add: Floating IPs", str(len(prop["add_fips"]))])
    ws_sum.append(["Update: NIC drift (combined)", str(len(prop["update_nic"]))])
    ws_sum.append(["Review: Orphans", str(len(prop["review_orphans"]))])
    ws_sum.append(["Review: Serial", str(len(prop["review_serial"]))])
    ws_sum.append(["Review: BMC/OOB", str(len(prop["review_bmc"]))])

    # Matched-host drift worksheet intentionally suppressed to match on-screen report.

    # --- Proposed changes (full list) ---
    ws_prop = _sheet("Proposed changes")
    ws_prop.append(["Preview only: Drift Audit does not apply changes to NetBox."])
    ws_prop.cell(row=1, column=1).font = header_font
    ws_prop.append(["Safety: No automatic deletion is performed by this workflow."])
    ws_prop.cell(row=2, column=1).font = header_font
    ws_prop.append([])
    _append_header(ws_prop, ["Section", "Count"])
    ws_prop.append(["Add: Devices from MAAS", len(prop["add_devices"])])
    ws_prop.append(["Add: Prefixes from OpenStack", len(prop["add_prefixes"])])
    ws_prop.append(["Add: Floating IPs from OpenStack", len(prop["add_fips"])])
    ws_prop.append(["Update: NIC drift (combined)", len(prop["update_nic"])])
    ws_prop.append(["Review: NetBox orphans", len(prop["review_orphans"])])
    ws_prop.append(["Review: Serial validation", len(prop["review_serial"])])
    ws_prop.append(["Review: BMC vs OOB mismatch", len(prop["review_bmc"])])

    def _append_block(title, headers, rows):
        ws_prop.append([])
        ws_prop.append([title])
        ws_prop.cell(row=ws_prop.max_row, column=1).font = header_font
        _append_header(ws_prop, headers)
        for row in rows:
            ws_prop.append(list(row))

    _append_block(
        "A) Devices to create from MAAS (maas-discovered)",
        ["Hostname", "Zone", "Pool", "MAAS Status", "System ID", "Proposed Tag", "Proposed Action"],
        prop["add_devices"],
    )
    _append_block(
        "A) Prefixes to create from OpenStack",
        ["CIDR", "Network Name", "Network ID", "Cloud", "Proposed Action"],
        prop["add_prefixes"],
    )
    _append_block(
        "A) Floating IPs to create in NetBox IPAM",
        ["Floating IP", "Fixed IP", "Project", "Cloud", "Proposed Action"],
        prop["add_fips"],
    )
    _append_block(
        "B) NIC drift updates (single per-interface table)",
        ["Host", "MAAS intf", "MAAS MAC", "MAAS IPs", "NB intf", "NB MAC", "NB IPs", "MAAS VLAN", "NB VLAN", "Status", "Reason", "Proposed Action", "Risk"],
        prop["update_nic"],
    )
    _append_block(
        "C) NetBox orphan devices (orphaned)",
        ["Hostname", "Site", "Status", "Proposed Tag", "Proposed Action", "Risk"],
        prop["review_orphans"],
    )
    _append_block(
        "C) Serial validation required",
        ["Hostname", "MAAS Serial", "MAAS System ID", "NetBox Serial", "Proposed Action", "Risk"],
        prop["review_serial"],
    )
    _append_block(
        "C) BMC vs OOB mismatch",
        ["Hostname", "MAAS BMC", "NetBox OOB", "Proposed Action", "Risk"],
        prop["review_bmc"],
    )

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()
