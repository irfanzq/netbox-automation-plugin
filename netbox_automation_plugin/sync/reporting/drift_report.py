"""
Generate human-readable drift audit report from MAAS, NetBox, and OpenStack data.
Uses ASCII tables (+---+) for readability in <pre> or plain text.
"""

# Cap table rows in UI (full export can be Phase 2 CSV)
_MAX_MATCHED_ROWS = 120
_MAX_MAAS_MISSING_ROWS = 500
_MAX_OS_NETWORKS = 40
_MAX_OS_SUBNET_HINTS = 60
_MAX_IFACE_AUDIT_HOSTS = 100
_MAX_COL = 28


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


def _ascii_table(headers, rows, indent="  "):
    """headers: list[str]. rows: list[list] same width as headers."""
    if not headers:
        return []
    n = len(headers)
    widths = []
    for i in range(n):
        w = min(max(len(headers[i]), 6), _MAX_COL)
        for r in rows:
            if i < len(r):
                w = min(max(w, min(len(str(r[i])), _MAX_COL + 6)), _MAX_COL)
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
    interface_audit: from build_maas_netbox_interface_audit (local NetBox + MAAS NICs).
    """
    lines = []

    lines.extend(_banner("INVENTORY"))
    lines.append("")
    lines.append("  MAAS")
    if maas_data.get("error"):
        lines.append(f"    Error: {maas_data['error']}")
    else:
        lines.extend(
            _ascii_table(
                ["Metric", "Count"],
                [
                    ["Zones", str(len(maas_data.get("zones") or []))],
                    ["Resource pools", str(len(maas_data.get("pools") or []))],
                    ["Machines", str(len(maas_data.get("machines") or []))],
                ],
            )
        )

    lines.append("")
    lines.append("  NetBox (this instance)")
    if netbox_data.get("error"):
        lines.append(f"    Error: {netbox_data['error']}")
    else:
        inv_rows = [
            ["Sites", str(len(netbox_data.get("sites") or []))],
            ["Devices", str(len(netbox_data.get("devices") or []))],
        ]
        if netbox_prefix_count:
            inv_rows.append(["IPAM Prefix objects", str(netbox_prefix_count)])
        lines.extend(_ascii_table(["Metric", "Count"], inv_rows))

    # --- Gaps ---
    lines.append("")
    lines.extend(_banner("GAPS — runtime not yet in NetBox", "-"))
    lines.append(
        "  MAAS -> Device; OpenStack subnet CIDR -> Prefix; floating IP -> IPAddress."
    )
    lines.append("")

    maas_only = sorted(drift.get("in_maas_not_netbox") or [])
    lines.append(f"  [MAAS] Machines with no NetBox Device: {len(maas_only)}")
    if maas_data.get("error"):
        lines.append("    (MAAS error)")
    elif maas_only:
        gap_rows = []
        by_h = _maas_machine_by_hostname(maas_data)
        for i, h in enumerate(maas_only):
            if i >= _MAX_MAAS_MISSING_ROWS:
                gap_rows.append([f"... +{len(maas_only) - i} more", "", "", "", ""])
                break
            m = by_h.get(h, {})
            gap_rows.append([
                h[:24],
                str(m.get("zone_name", "-"))[:20],
                str(m.get("pool_name", "-"))[:20],
                str(m.get("status_name", "-"))[:16],
                str(m.get("system_id", ""))[:14],
            ])
        lines.extend(
            _ascii_table(
                ["hostname", "zone", "pool", "MAAS status", "system_id"],
                gap_rows,
            )
        )
    else:
        lines.append("    (none)")

    lines.append("")
    if openstack_data and openstack_data.get("error"):
        lines.append("  [OpenStack] Subnet / FIP gaps: API error")
    elif use_remote_netbox or os_subnet_gaps is None:
        lines.append(
            "  [OpenStack] Subnet vs Prefix: not evaluated (use local NetBox ORM)."
        )
    else:
        lines.append(
            f"  [OpenStack] Subnets without exact Prefix: {len(os_subnet_gaps)}"
        )
        if os_subnet_gaps:
            srows = [
                [g.get("cidr", ""), g.get("network_name", "-")[:22], g.get("network_id", "")[:18]]
                for g in os_subnet_gaps
            ]
            lines.extend(_ascii_table(["CIDR", "network", "net_id"], srows))
        else:
            lines.append("    (all subnets have matching Prefix)")

    lines.append("")
    if openstack_data and not openstack_data.get("error"):
        fg = os_floating_gaps if os_floating_gaps is not None else []
        lines.append(f"  [OpenStack] Floating IPs without NetBox IPAddress: {len(fg)}")
        if fg:
            frows = [[g.get("floating_ip", ""), g.get("fixed_ip_address", "-")] for g in fg]
            lines.extend(_ascii_table(["floating_ip", "fixed (Neutron)"], frows))
        else:
            lines.append("    (none)")
    elif not openstack_data:
        lines.append("  [OpenStack] Floating IPs: (not configured)")
    else:
        pass

    # --- Summary ---
    lines.append("")
    lines.extend(_banner("MAAS <-> NetBox SUMMARY"))
    if netbox_data.get("error"):
        lines.append("  *** NetBox error — summary unreliable ***")
    matched = drift.get("matched_count", 0)
    lines.extend(
        _ascii_table(
            ["Check", "Value"],
            [
                ["Hostnames in MAAS and NetBox", str(matched)],
                ["MAAS only (no Device)", str(len(maas_only))],
            ],
        )
    )

    if matched_rows:
        lines.append("")
        lines.extend(_banner("MATCHED HOSTS — site / status / serial"))
        lines.append(
            "  Hint: verify NetBox site vs MAAS zone/pool; serial vs system_id."
        )
        lines.append("")
        mrows = []
        shown = 0
        for r in matched_rows:
            if shown >= _MAX_MATCHED_ROWS:
                mrows.append(["...", "...", "...", "...", "...", "...", "..."])
                break
            mrows.append([
                r["hostname"][:18],
                str(r.get("maas_zone", ""))[:10],
                str(r.get("maas_pool", ""))[:10],
                str(r.get("maas_status", ""))[:12],
                str(r.get("netbox_site", ""))[:10],
                str(r.get("netbox_status", ""))[:10],
                "; ".join(r.get("hints") or [])[:24] or "-",
            ])
            shown += 1
        lines.extend(
            _ascii_table(
                ["host", "MAAS zone", "MAAS pool", "MAAS st", "NB site", "NB st", "notes"],
                mrows,
            )
        )
        if len(matched_rows) > _MAX_MATCHED_ROWS:
            lines.append(f"  ... {len(matched_rows) - _MAX_MATCHED_ROWS} more hosts not shown")

    # --- Interface line-by-line ---
    if interface_audit and interface_audit.get("hosts"):
        lines.append("")
        lines.extend(_banner("MAAS <-> NetBox INTERFACES (by MAC)"))
        lines.append(
            "  Each row: one MAAS NIC. NetBox columns filled when the same MAC exists on the Device."
        )
        lines.append(
            "  Status: OK | OK_NAME_DIFF | IP_GAP | NOT_IN_NETBOX | MAAS_NO_MAC"
        )
        lines.append("")
        hosts = interface_audit["hosts"]
        total_h = len(hosts)
        if total_h > _MAX_IFACE_AUDIT_HOSTS:
            lines.append(
                f"  Showing first {_MAX_IFACE_AUDIT_HOSTS} of {total_h} matched hosts (cap)."
            )
            hosts = hosts[:_MAX_IFACE_AUDIT_HOSTS]

        for block in hosts:
            hn = block["hostname"]
            lines.extend(_banner(f"DEVICE: {hn}", "-"))
            if block.get("rows"):
                irows = [
                    [
                        x["maas_if"][:14],
                        x["maas_mac"][:16],
                        x["maas_ips"][:22],
                        x["nb_if"][:14],
                        x["nb_ips"][:22],
                        x["status"][:12],
                        x["notes"][:26],
                    ]
                    for x in block["rows"]
                ]
                lines.extend(
                    _ascii_table(
                        [
                            "MAAS if",
                            "MAC",
                            "MAAS IP(s)",
                            "NB intf",
                            "NB IP(s)",
                            "status",
                            "notes",
                        ],
                        irows,
                    )
                )
            else:
                lines.append("    (no MAAS interfaces returned for this machine)")

            nb_only = block.get("netbox_only") or []
            if nb_only:
                lines.append(f"  NetBox-only interfaces (MAC not on MAAS machine): {len(nb_only)}")
                nrows = [
                    [
                        (x.get("name") or "")[:16],
                        (x.get("mac") or "")[:18],
                        (", ".join(x.get("ips") or [])[:24] or "-"),
                        "mgmt" if x.get("mgmt_only") else "",
                    ]
                    for x in nb_only
                ]
                lines.extend(_ascii_table(["NB intf", "MAC", "NB IP(s)", ""], nrows))
            lines.append("")

    elif use_remote_netbox:
        lines.append("")
        lines.append("  (Interface audit requires local NetBox ORM — not available with remote API.)")

    if openstack_data:
        lines.append("")
        lines.extend(_banner("OPENSTACK REFERENCE"))
        if openstack_data.get("error"):
            lines.append(f"  Error: {openstack_data['error']}")
        else:
            nets = openstack_data.get("networks") or []
            subs = openstack_data.get("subnets") or []
            fips = openstack_data.get("floating_ips") or []
            lines.extend(
                _ascii_table(
                    ["Object", "Count"],
                    [
                        ["Networks", str(len(nets))],
                        ["Subnets", str(len(subs))],
                        ["Floating IPs", str(len(fips))],
                    ],
                )
            )
            lines.append("")
            nrows = [
                [(n.get("name") or n.get("id") or "")[:30], (n.get("id") or "")[:36]]
                for n in nets[:_MAX_OS_NETWORKS]
            ]
            if nrows:
                lines.extend(_ascii_table(["Network", "id"], nrows))
            if len(nets) > _MAX_OS_NETWORKS:
                lines.append(f"  ... {len(nets) - _MAX_OS_NETWORKS} more networks")

            if os_subnet_hints is not None and os_subnet_hints:
                lines.append("")
                lines.append("  Subnets vs NetBox Prefix (exact CIDR)")
                sh = [
                    [
                        "OK" if h.get("exact_prefix_in_netbox") else "GAP",
                        h.get("cidr", ""),
                        (h.get("network_name") or "")[:20],
                    ]
                    for h in os_subnet_hints[:_MAX_OS_SUBNET_HINTS]
                ]
                lines.extend(_ascii_table(["", "CIDR", "network"], sh))
                if len(os_subnet_hints) > _MAX_OS_SUBNET_HINTS:
                    lines.append(f"  ... {len(os_subnet_hints) - _MAX_OS_SUBNET_HINTS} more")

            if fips:
                lines.append("")
                frows = [
                    [f.get("floating_ip_address", ""), f.get("fixed_ip_address", "")]
                    for f in fips[:25]
                ]
                lines.extend(_ascii_table(["floating_ip", "fixed_ip"], frows))
                if len(fips) > 25:
                    lines.append(f"  ... {len(fips) - 25} more FIPs")

    lines.append("")
    lines.extend(_banner("END OF DRIFT AUDIT", "="))
    return "\n".join(lines)
