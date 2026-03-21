"""
Generate human-readable drift audit report from MAAS, NetBox, and OpenStack data.
Default UI output uses Bootstrap HTML tables; set use_html=False for ASCII (+---+) plain text.
XLSX export via build_drift_report_xlsx() for download (openpyxl); Google Sheets opens .xlsx.

Copy in this module distinguishes **host data NICs** (Ethernet MAC/IP/VLAN) from **BMC / OOB**
(IPMI, iDRAC, Redfish — baseboard management controllers, not “another NIC”). NetBox models OOB
as **device OOB IP** plus an optional **OOB port** marked management-only in NetBox,
which documents the management attachment — not the same as in-band NICs.
"""

from io import BytesIO
import html
import re
import textwrap

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
# ASCII tables: cap column width and wrap long cells so one outlier row does not pad every row.
_ASCII_COL_WRAP_DEFAULT = 96
_ASCII_NOTES_COL_WRAP = 200


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


def _format_inventory_list(
    items,
    *,
    noisy_regex=None,
    noisy_label="auto-generated",
    sample=20,
    max_named_display=35,
):
    vals = _dedupe_keep_order(items)
    if not vals:
        return "(none)"
    if not noisy_regex:
        if len(vals) <= max_named_display:
            return ", ".join(vals)
        show = vals[:max_named_display]
        more = len(vals) - len(show)
        return f"{', '.join(show)}, ... +{more} more unique"
    pat = re.compile(noisy_regex)
    noisy = [v for v in vals if pat.match(v)]
    named = [v for v in vals if not pat.match(v)]
    parts = []
    if named:
        show_n = named[:max_named_display]
        more_n = len(named) - len(show_n)
        txt_n = ", ".join(show_n)
        if more_n > 0:
            txt_n = f"{txt_n}, ... +{more_n} more named"
        parts.append(f"named ({len(named)} unique): {txt_n}")
    if noisy:
        show = noisy[:sample]
        more = len(noisy) - len(show)
        txt = ", ".join(show)
        if more > 0:
            txt = f"{txt}, ... +{more} more"
        parts.append(f"{noisy_label} ({len(noisy)} unique): {txt}")
    return " | ".join(parts) if parts else "(none)"


def _maas_machine_by_hostname(maas_data):
    out = {}
    for m in maas_data.get("machines") or []:
        h = (m.get("hostname") or "").strip()
        if h:
            out[h] = m
    return out


def _normalize_ascii_cell(s):
    return str(s).replace("\n", " ").replace("\r", "") if s is not None else ""


def _cell(s, w, *, truncate=True):
    s = _normalize_ascii_cell(s)
    if truncate and len(s) > w:
        s = s[: max(1, w - 2)] + ".."
    return s.ljust(w)


def _wrap_cell_lines(text: str, width: int) -> list[str]:
    """Word-wrap cell text to width; no truncation (long tokens split)."""
    if width < 1:
        width = 1
    t = _normalize_ascii_cell(text)
    if not t:
        return [""]
    lines = textwrap.wrap(
        t,
        width=width,
        break_long_words=True,
        break_on_hyphens=False,
        replace_whitespace=False,
    )
    return lines if lines else [""]


def _ascii_table(
    headers,
    rows,
    indent="  ",
    *,
    max_col=None,
    notes_col_idx=None,
    dynamic_columns=True,
    wrap_max_width=_ASCII_COL_WRAP_DEFAULT,
):
    """
    dynamic_columns: width per column from content, capped by wrap_max_width, with word wrap
    (avoids one long cell forcing huge padding on every row). Full text is kept on extra lines.
    After each logical row (including wrapped multi-line rows), a horizontal rule is printed so
    continuation lines are not confused with the next record.

    wrap_max_width: None disables wrap cap (legacy: single-line rows, wide columns, may truncate
    via _cell if over cap). Default 96 balances readability in <pre> without horizontal sprawl.
    """
    if not headers:
        return []
    n = len(headers)

    if dynamic_columns and wrap_max_width is not None:
        widths = []
        for i in range(n):
            w = max(len(_normalize_ascii_cell(headers[i])), 6)
            for r in rows:
                if i < len(r):
                    w = max(w, len(_normalize_ascii_cell(r[i])))
            cap = wrap_max_width
            if notes_col_idx is not None and i == notes_col_idx:
                cap = min(max(cap, _ASCII_NOTES_COL_WRAP), _NOTES_COL_MAX_WIDTH)
            widths.append(min(w, cap))

        def emit_wrapped_row(cells: list) -> list[str]:
            padded = list(cells[:n]) + [""] * (n - min(len(cells), n))
            col_lines = [_wrap_cell_lines(padded[i], widths[i]) for i in range(n)]
            h = max(len(cl) for cl in col_lines)
            col_lines = [cl + [""] * (h - len(cl)) for cl in col_lines]
            lines_out = []
            for li in range(h):
                parts = [col_lines[i][li].ljust(widths[i]) for i in range(n)]
                lines_out.append(
                    indent + "|" + "|".join(" " + parts[i] + " " for i in range(n)) + "|"
                )
            return lines_out

        sep = indent + "+" + "+".join("-" * (w + 2) for w in widths) + "+"
        out = [sep]
        out.extend(emit_wrapped_row(headers))
        out.append(sep)
        for r in rows:
            out.extend(emit_wrapped_row(r))
            out.append(sep)
        return out

    widths = []
    for i in range(n):
        if dynamic_columns:
            w = max(len(str(headers[i])), 6)
            for r in rows:
                if i < len(r):
                    cell = _normalize_ascii_cell(r[i])
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
                    cell = _normalize_ascii_cell(r[i])
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


def _html_cell_content(s) -> str:
    raw = _normalize_ascii_cell(s)
    return html.escape(raw, quote=False).replace("\n", "<br />")


def _html_col_is_mac(header) -> bool:
    """True for column headers that represent a MAC address (not substrings like 'machines')."""
    return re.search(r"(?i)\bMAC\b", str(header or "")) is not None


def _html_col_is_risk(header) -> bool:
    return str(header or "").strip().lower() == "risk"


def _html_th_class(header) -> str:
    h = str(header or "")
    base = "small align-bottom"
    if _html_col_is_mac(h):
        return f"{base} text-nowrap font-monospace"
    if _html_col_is_risk(h):
        return f"{base} text-nowrap"
    return base


def _html_td_class(header, col_idx, notes_col_idx=None) -> str:
    h = str(header or "")
    parts = []
    if _html_col_is_mac(h):
        parts.extend(["align-top", "text-nowrap", "font-monospace"])
    elif _html_col_is_risk(h):
        parts.extend(["align-top", "text-nowrap"])
    else:
        # Bootstrap text-break: wrap long strings so text columns stay reasonably narrow (early HTML behavior).
        parts.extend(["align-top", "text-break"])
    if notes_col_idx is not None and col_idx == notes_col_idx:
        parts.append("text-muted")
    return " ".join(parts)


def _html_table(headers, rows, *, notes_col_idx=None):
    if not headers:
        return ""
    n = len(headers)
    hdr_strs = [str(h) for h in headers]
    ths = "".join(
        f'<th scope="col" class="{_html_th_class(h)}">{_html_cell_content(h)}</th>'
        for h in hdr_strs
    )
    body_parts = []
    for r in rows:
        padded = list(r[:n]) + [""] * (n - min(len(r), n))
        tds = []
        for i, cell in enumerate(padded):
            h = hdr_strs[i] if i < len(hdr_strs) else ""
            cls = _html_td_class(h, i, notes_col_idx)
            tds.append(f'<td class="{cls}">{_html_cell_content(cell)}</td>')
        body_parts.append("<tr>" + "".join(tds) + "</tr>")
    return (
        '<div class="table-responsive mb-3">'
        '<table class="table table-sm table-bordered table-striped align-middle mb-0">'
        f'<thead class="table-light"><tr>{ths}</tr></thead><tbody>'
        + "".join(body_parts)
        + "</tbody></table></div>"
    )


class _DriftReportEmitter:
    __slots__ = ("_html", "_parts")

    def __init__(self, *, use_html: bool = True):
        self._html = use_html
        self._parts: list[str] = []

    def banner(self, title: str, char: str = "=") -> None:
        if self._html:
            major = char == "="
            cls = (
                "drift-rpt-title border-bottom border-2 pb-2 mb-3 mt-3 fw-bold text-body"
                if major
                else "drift-rpt-subtitle border-bottom pb-2 mb-2 mt-3 fw-semibold text-body"
            )
            self._parts.append(f'<div class="{cls}">{html.escape(title)}</div>')
        else:
            self._parts.extend(_banner(title, char))

    def spacer(self) -> None:
        if self._html:
            self._parts.append('<div class="drift-rpt-spacer mb-2" aria-hidden="true"></div>')
        else:
            self._parts.append("")

    def subtitle(self, text: str) -> None:
        t = (text or "").strip()
        if self._html:
            self._parts.append(
                f'<div class="text-body-secondary fw-semibold mb-1">{html.escape(t)}</div>'
            )
        else:
            self._parts.append(f"  {t}")

    def paragraph(self, text: str) -> None:
        t = (text or "").strip()
        if not t:
            return
        if self._html:
            self._parts.append(f'<p class="small text-body-secondary mb-2">{html.escape(t)}</p>')
        else:
            self._parts.append(f"  {t}")

    def error(self, message: str) -> None:
        if self._html:
            self._parts.append(
                '<div class="alert alert-danger py-2 px-3 small mb-2" role="alert">'
                f"{html.escape(str(message))}</div>"
            )
        else:
            self._parts.append(f"    Error: {message}")

    def line_total(self, text: str) -> None:
        t = (text or "").strip()
        if self._html:
            self._parts.append(f'<p class="small fw-semibold mb-2">{html.escape(t)}</p>')
        else:
            self._parts.append(f"  {t}")

    def table(self, headers, rows, **kw) -> None:
        if self._html:
            self._parts.append(
                _html_table(headers, rows, notes_col_idx=kw.get("notes_col_idx"))
            )
        else:
            self._parts.extend(_ascii_table(headers, rows, **kw))

    def render(self) -> str:
        if self._html:
            return (
                '<div class="drift-report-html" style="font-size:0.8125rem">'
                + "\n".join(self._parts)
                + "</div>"
            )
        return "\n".join(self._parts)


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
    maas_nic_missing_nb = 0
    vlan_drift_nic = 0
    vlan_unverified_nic = 0
    for b in (interface_audit or {}).get("hosts") or []:
        nb_only_nic += len(b.get("netbox_only") or [])
        for row in b.get("rows") or []:
            st = row.get("status") or ""
            if st != "OK":
                iface_not_ok += 1
            if st == "NOT_IN_NETBOX":
                maas_nic_missing_nb += 1
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
        "maas_nic_missing_nb": maas_nic_missing_nb,
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


def _ip_address_host(ip_str: str) -> str:
    """Host portion of an IP or CIDR string, lowercased."""
    if not ip_str or ip_str == "—":
        return ""
    return str(ip_str).split("/", 1)[0].strip().lower()


# NetBox **port names** operators use for BMC/OOB (heuristic coverage); *-nic here is a label, not “host NIC”.
_MGMT_INTERFACE_NAME_HINTS = frozenset({
    "ipmi",
    "idrac",
    "bmc",
    "ilo",
    "imm",
    "xcc",
    "drac",
    "oob",
    "mgmt",
    "mgnt",
    "ipmi-nic",
    "bmc-nic",
})


def _netbox_iface_name_suggests_oob(name: str) -> bool:
    """
    True if the NetBox interface *name* looks like an OOB / BMC port.

    Names are operator-defined in NetBox (manual, import, etc.) — MAAS does not supply
    interface labels. We match exact aliases (e.g. ``idrac``) or **substring** hits so
    values like ``e0 - idrac`` still count as OOB-style (exact-set-only would miss those
    and wrongly flag ``IP_OTHER_IFACE``).
    """
    n = (name or "").strip().lower()
    if not n:
        return False
    if n in _MGMT_INTERFACE_NAME_HINTS:
        return True
    return any(hint in n for hint in _MGMT_INTERFACE_NAME_HINTS)


def _suggested_netbox_mgmt_interface_name(
    power_type: str,
    hardware_vendor: str | None = None,
) -> str:
    """
    MAAS-only hint when **creating** a new OOB port — ``ipmi`` or ``idrac`` only.

    - ``power_type`` containing ``redfish`` or ``idrac`` → ``idrac``.
    - ``power_type`` containing ``ipmi``: if ``hardware_vendor`` contains ``dell``
      (case-insensitive), suggest ``idrac``; if vendor missing / placeholder → ``ipmi``;
      otherwise ``ipmi``.
    - Any other power type → ``ipmi`` (same as before).

    Prefer NetBox’s existing port name when the BMC IP is already on an interface
    (``_oob_port_hint_column``).
    """
    pl = (power_type or "").lower()
    if "redfish" in pl or "idrac" in pl:
        return "idrac"
    if "ipmi" in pl:
        v = (hardware_vendor or "").strip().lower()
        if v and "dell" in v:
            return "idrac"
        return "ipmi"
    return "ipmi"


def _oob_port_hint_column(cov: str, nb_ifn: str, maas_when_no_nb_port: str) -> str:
    """
    Value for the 'NB OOB port (hint)' column: prefer the NetBox port name when the BMC IP
    is already documented on a port (MGMT_IFACE / IP_OTHER_IFACE).
    """
    n = (nb_ifn or "").strip()
    if n and n != "—" and cov in ("MGMT_IFACE", "IP_OTHER_IFACE"):
        return n
    return maas_when_no_nb_port


def _nb_iface_carrying_ip(nb_ifaces: list, target_ip: str):
    """First NetBox interface dict whose ips[] contains target (host match)."""
    bh = _ip_address_host(target_ip)
    if not bh:
        return None
    for iface in nb_ifaces or []:
        for ip in iface.get("ips") or []:
            if _ip_address_host(ip) == bh:
                return iface
    return None


def _meaningful_maas_power_type(pt: str) -> bool:
    """True if MAAS reports a concrete power driver (not empty / manual / unknown)."""
    p = (pt or "").strip().lower()
    if not p or p in ("—", "-", "manual", "unknown"):
        return False
    return True


def _netbox_bmc_ip_coverage(nb_ifaces: list, bmc_ip: str):
    """
    How NetBox documents the MAAS BMC IP (on an OOB-dedicated port / Interface, or elsewhere).
    Returns (code, port_name_or_emdash, short_note).
    """
    bh = _ip_address_host(bmc_ip)
    if not bh:
        return "NO_BMC_MAAS", "—", ""
    mgmt_name = ""
    any_name = ""
    for iface in nb_ifaces or []:
        iname = (iface.get("name") or "").strip().lower()
        is_mgmt_named = _netbox_iface_name_suggests_oob(iname)
        is_mgmt_flag = bool(iface.get("mgmt_only"))
        for ip in iface.get("ips") or []:
            if _ip_address_host(ip) != bh:
                continue
            disp = (iface.get("name") or "?").strip()
            if is_mgmt_flag or is_mgmt_named:
                mgmt_name = disp
            if not any_name:
                any_name = disp
            break
    if mgmt_name:
        return "MGMT_IFACE", mgmt_name, "BMC IP on OOB-style NetBox port"
    if any_name:
        return "IP_OTHER_IFACE", any_name, "BMC IP present; port name not typical for OOB"
    return "NO_IFACE_IP", "—", "No NetBox port carries this BMC IP"


def _build_proposed_mgmt_interface_rows(
    matched_rows,
    maas_by_hostname: dict,
    netbox_ifaces,
):
    """
    Matched hosts: **BMC / OOB** from MAAS power (IPMI, iDRAC, Redfish — not host data NICs).

    Compares MAAS BMC IP to NetBox device OOB and to NetBox **OOB ports**.
    Rows also when power_type is set but BMC IP is missing from the MAAS API.
    """
    from netbox_automation_plugin.sync.reconciliation.audit_detail import (
        _normalize_mac,
    )

    nb_if = netbox_ifaces if isinstance(netbox_ifaces, dict) else {}
    out = []
    for r in matched_rows or []:
        h = (r.get("hostname") or "").strip()
        if not h:
            continue
        m = maas_by_hostname.get(h) or {}
        bmc = (m.get("bmc_ip") or "").strip()
        pt = (m.get("power_type") or "").strip() or "—"
        maas_oob_new = _suggested_netbox_mgmt_interface_name(
            pt, m.get("hardware_vendor")
        )
        nb_oob = (r.get("netbox_oob") or "").strip()
        maas_mac = (m.get("bmc_mac") or "").strip()
        maas_vlan = (m.get("bmc_vlan") or "").strip()
        nb_list = nb_if.get(h) or []

        if not bmc:
            if not _meaningful_maas_power_type(pt):
                continue
            cov = "NO_BMC_IP_MAAS"
            nb_ifn = "—"
            nb_mgmt_mac = "—"
            status = "NO_BMC_IP"
            action = (
                "MAAS power_type is set but no BMC IP in machine API — grant admin API key, "
                "use op=power_parameters, or configure power_address in MAAS; then re-run audit."
            )
            if maas_mac or maas_vlan:
                action += f" MAAS hints: MAC={maas_mac or '—'} VLAN={maas_vlan or '—'}."
            risk = "High"
            out.append([
                h,
                "—",
                pt,
                maas_mac or "—",
                maas_oob_new,
                nb_oob or "—",
                cov,
                nb_ifn,
                nb_mgmt_mac,
                status,
                action,
                risk,
            ])
            continue

        cov, nb_ifn, cov_note = _netbox_bmc_ip_coverage(nb_list, bmc)
        oob_port_hint = _oob_port_hint_column(cov, nb_ifn, maas_oob_new)
        oob_match = bool(nb_oob) and _ip_address_host(nb_oob) == _ip_address_host(bmc)
        nb_detail = _nb_iface_carrying_ip(nb_list, bmc)
        nb_mgmt_mac = (nb_detail.get("mac") or "—") if nb_detail else "—"
        nb_mgmt_vid = (
            str(nb_detail.get("untagged_vlan_vid") or "—") if nb_detail else "—"
        )

        if oob_match and cov == "MGMT_IFACE":
            status = "OK"
            action = (
                "Device OOB + OOB port align with MAAS BMC; keep NetBox port name "
                f"'{nb_ifn}' (source of truth)"
            )
            risk = "None"
        elif oob_match and cov == "NO_IFACE_IP":
            status = "ADD_MGMT_IFACE"
            action = (
                f"Add NetBox OOB port '{maas_oob_new}' (management-only), assign BMC IP "
                f"{bmc}/<prefix> (OOB, not a host NIC)"
            )
            risk = "Medium"
        elif oob_match and cov == "IP_OTHER_IFACE":
            status = "REVIEW"
            action = (
                f"BMC IP on NetBox port '{nb_ifn}'; mark as OOB/management-only if needed — "
                "do not rename to match MAAS power_type; NetBox name is source of truth"
            )
            risk = "Low"
        elif not oob_match and cov == "MGMT_IFACE":
            status = "SET_OOB"
            action = (
                f"Set device OOB IP to {bmc} (MAAS BMC); BMC IP already on port '{nb_ifn}' "
                "(keep NetBox port name)"
            )
            risk = "Low"
        elif cov == "NO_IFACE_IP":
            status = "ADD_OOB_AND_MGMT"
            action = (
                f"Set device OOB IP to {bmc}; add OOB port '{maas_oob_new}' "
                "(management-only) with BMC IP"
            )
            risk = "Medium"
        else:
            status = "REVIEW"
            action = cov_note or "Align device OOB / OOB port / MAAS BMC"
            risk = "Medium"

        status_before_mac = status
        if maas_mac and nb_mgmt_mac and nb_mgmt_mac != "—":
            mm = _normalize_mac(maas_mac)
            nm = _normalize_mac(nb_mgmt_mac)
            if mm and nm and mm != nm:
                if status == "OK":
                    status = "REVIEW"
                    risk = "Medium"
                # Do not keep “everything aligns” copy when MACs disagree.
                if status_before_mac == "OK":
                    action = (
                        f"BMC MAC mismatch: MAAS {maas_mac} vs NetBox port {nb_mgmt_mac} "
                        f"on '{nb_ifn}'. OOB IP matches MAAS; confirm which MAC is correct."
                    )
                else:
                    action += (
                        f" MAC mismatch: MAAS BMC MAC {maas_mac} vs NetBox port {nb_mgmt_mac}."
                    )
        if maas_vlan and nb_mgmt_vid not in ("", "—", "None"):
            if maas_vlan.strip() != str(nb_mgmt_vid).strip():
                action += (
                    f" VLAN hint: MAAS {maas_vlan} vs NetBox untagged {nb_mgmt_vid} on BMC port."
                )
                if status == "OK":
                    status = "REVIEW"
                    risk = "Low"

        out.append([
            h,
            bmc,
            pt,
            maas_mac or "—",
            oob_port_hint,
            nb_oob or "—",
            cov,
            nb_ifn,
            nb_mgmt_mac,
            status,
            action,
            risk,
        ])
    return sorted(out, key=lambda x: (x[0] or "").lower())


def _build_add_nb_interface_rows(interface_audit):
    """
    MAAS NICs with a MAC that do not match any NetBox port on the device.
    Preview: proposed new NetBox ports (+ VLAN, IPs from MAAS).
    """
    out = []
    for b in (interface_audit or {}).get("hosts") or []:
        hn = (b.get("hostname") or "").strip()
        if not hn:
            continue
        nb_site = (b.get("nb_site") or "—").strip()
        nb_loc = (b.get("nb_location") or "—").strip()
        for row in b.get("rows") or []:
            if (row.get("status") or "") != "NOT_IN_NETBOX":
                continue
            maas_if = (row.get("maas_if") or "").strip() or "—"
            maas_fab = str(row.get("maas_fabric") or "—")
            mac = (row.get("maas_mac") or "").strip()
            ips = (row.get("maas_ips") or "—").strip()
            vlan = str(row.get("maas_vlan") or "—")
            props = (
                f"MAC {mac}; untagged VLAN {vlan} (from MAAS); "
                f"IPs: {ips}"
            )
            out.append([
                hn,
                nb_site,
                nb_loc,
                maas_if,
                maas_fab,
                mac,
                ips,
                vlan,
                (
                    maas_if
                    if maas_if != "—"
                    else (f"maas-nic-{mac.replace(':', '')[-6:]}" if mac else "maas-nic")
                ),
                props,
                "Medium",
            ])
    return sorted(out, key=lambda x: (x[0] or "").lower())


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
    netbox_ifaces=None,
):
    """Build user-friendly proposed change buckets (preview only)."""
    by_h = _maas_machine_by_hostname(maas_data)
    nb_by_name = _device_by_name(netbox_data)
    add_mgmt_iface = _build_proposed_mgmt_interface_rows(
        matched_rows, by_h, netbox_ifaces
    )
    add_nb_interfaces = _build_add_nb_interface_rows(interface_audit)

    add_devices = []
    for h in sorted(drift.get("in_maas_not_netbox") or []):
        m = by_h.get(h, {})
        add_devices.append([
            h,
            str(m.get("zone_name", "-")),
            str(m.get("pool_name", "-")),
            str(m.get("status_name", "-")),
            "maas-discovered",
            "Create device + ports",
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
            notes = row.get("notes") or ""
            maas_vlan = str(row.get("maas_vlan") or "—")
            nb_vlan = str(row.get("nb_vlan") or "—")

            # NOT_IN_NETBOX: dedicated "create interface" table (add_nb_interfaces), not NIC drift.
            if st == "NOT_IN_NETBOX":
                continue

            # Full inventory for MAC’d interfaces only (with or without IP on MAAS); OK rows included.
            if st == "OK":
                update_nic.append([
                    hn,
                    row.get("maas_if") or "",
                    str(row.get("maas_fabric") or "—"),
                    row.get("maas_mac") or "",
                    row.get("maas_ips") or "—",
                    row.get("nb_if") or "—",
                    row.get("nb_mac") or "—",
                    row.get("nb_ips") or "—",
                    maas_vlan,
                    nb_vlan,
                    "OK",
                    "—",
                    "No change",
                    "None",
                ])
                continue

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
                actions.append("Add missing IP on NetBox port")

            note_l = notes.lower()
            if ("netbox mac empty" in note_l) or ("mac mismatch" in note_l):
                if "mac mismatch" in note_l:
                    statuses.append("MAC_MISMATCH")
                else:
                    statuses.append("MISSING_NB_MAC")
                reasons.append("NetBox MAC missing or mismatched")
                actions.append("Set NetBox port MAC from MAAS for reliable matching")

            if not statuses:
                statuses.append(st)
                reasons.append(_dedupe_note_parts(notes) or "Port review needed")
                actions.append("Review port alignment manually")

            update_nic.append([
                hn,
                row.get("maas_if") or "",
                str(row.get("maas_fabric") or "—"),
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
    for r in (matched_rows or []):
        if any("NB serial empty" in (h or "") for h in (r.get("hints") or [])):
            review_serial.append([
                r.get("hostname", ""),
                str(r.get("maas_serial", "")),
                str(r.get("netbox_serial", "")),
                "Manual validation",
                "High",
            ])

    return {
        "add_devices": add_devices,
        "add_prefixes": add_prefixes,
        "add_fips": add_fips,
        "update_nic": update_nic,
        "add_nb_interfaces": add_nb_interfaces,
        "add_mgmt_iface": add_mgmt_iface,
        "review_orphans": review_orphans,
        "review_serial": review_serial,
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
    netbox_ifaces=None,
    use_html=True,
):
    """
    Return {"drift": str, "reference": str, "drift_markup": "html"|"text"}.

    drift = Phase 0 + drift-only tables (MAAS-only, matched with drift, NIC drift, OS gaps).
    reference = full matched hosts, full per-device NIC audit, OpenStack ref (collapsible in UI).
    OpenStack data is already combined from all configured clouds before being passed here.

    When use_html is True (default), drift is a safe HTML fragment for |safe in templates.
    """
    e = _DriftReportEmitter(use_html=use_html)
    ref_lines = []

    # --- INVENTORY (compact) ---
    e.banner("INVENTORY")
    e.spacer()
    e.subtitle("MAAS")
    e.spacer()
    if maas_data.get("error"):
        e.error(f"Error: {maas_data['error']}")
    else:
        e.table(
            ["Metric", "Count"],
            [
                ["Zones", str(len(maas_data.get("zones") or []))],
                ["Resource pools", str(len(maas_data.get("pools") or []))],
                ["Machines", str(len(maas_data.get("machines") or []))],
            ],
        )

    e.spacer()
    e.subtitle("NetBox (this instance)")
    e.spacer()
    if netbox_data.get("error"):
        e.error(f"Error: {netbox_data['error']}")
    else:
        inv_rows = [
            ["Sites", str(len(netbox_data.get("sites") or []))],
            ["Devices", str(len(netbox_data.get("devices") or []))],
        ]
        if netbox_prefix_count:
            inv_rows.append(["IPAM Prefix objects", str(netbox_prefix_count)])
        e.table(["Metric", "Count"], inv_rows)

    scope_meta = (drift or {}).get("scope_meta") or {}
    if scope_meta:
        e.spacer()
        e.banner("SCOPE", "-")
        e.spacer()
        sel_sites = ", ".join(scope_meta.get("selected_sites") or []) or "(all)"
        sel_locs = ", ".join(scope_meta.get("selected_locations") or []) or "(all)"
        os_unmatched = list(scope_meta.get("openstack_unmatched_network_names") or [])
        if scope_meta.get("openstack_unmatched_network_names_more"):
            os_unmatched.append(f"... +{scope_meta['openstack_unmatched_network_names_more']} more")
        maas_unmatched = list(scope_meta.get("maas_unmatched_fabrics") or [])
        if scope_meta.get("maas_unmatched_fabrics_more"):
            maas_unmatched.append(f"... +{scope_meta['maas_unmatched_fabrics_more']} more")
        e.table(
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
                ["MAAS unmatched fabrics (sample)", ", ".join(maas_unmatched) or "(none)"],
                ["OpenStack unmatched network names (sample)", ", ".join(os_unmatched) or "(none)"],
            ],
            dynamic_columns=True,
        )

    # --- Phase 0 — drift category counts ---
    e.spacer()
    e.banner("DRIFT COUNTS")
    e.paragraph("Counts for this run (match by hostname and NIC MAC).")
    e.spacer()
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
    e.table(
        ["Category", "Count"],
        [
            ["In MAAS only (not in NetBox)", str(pc["maas_only"])],
            ["In NetBox only (orphaned tag)", str(pc["nb_only_dev"])],
            ["Matched — placement needs check", str(pc["check_hosts"])],
            ["NetBox serial missing", str(serial_validation_needed)],
            ["NIC rows not OK", str(pc["iface_not_ok"])],
            ["MAAS NIC missing in NetBox", str(pc["maas_nic_missing_nb"])],
            ["VLAN mismatch (MAAS vs NetBox)", str(pc["vlan_drift_nic"])],
            ["VLAN unverified from MAAS", str(pc["vlan_unverified_nic"])],
            ["NetBox-only NICs (review)", str(pc["nb_only_nic"])],
            ["OpenStack subnet → no Prefix", sub_txt],
            ["OpenStack FIP → no IP record", str(pc["fip_gaps"])],
            ["BMC vs NetBox OOB differs", str(bmc_oob_mismatch)],
            ["LLDP / cabling", "—"],
        ],
    )

    # --- High-risk summary ---
    e.spacer()
    e.banner("HIGH-RISK (review first)", "-")
    e.paragraph("Triage these before a sync.")
    e.spacer()
    hr_rows = []
    hr_total = 0
    for name, val in [
        ("OpenStack FIP → no IP record", pc["fip_gaps"]),
        ("OpenStack subnet → no Prefix", pc["sub_gaps"] if pc["sub_gaps"] is not None else "N/A"),
        ("VLAN mismatch (MAAS vs NetBox)", pc["vlan_drift_nic"]),
        ("NetBox serial missing", serial_validation_needed),
        ("BMC vs NetBox OOB differs", bmc_oob_mismatch),
    ]:
        hr_rows.append([name, str(val)])
        if isinstance(val, int):
            hr_total += val
    e.table(["Category", "Count"], hr_rows)
    e.line_total(f"Total: {hr_total}")

    # --- Run metrics ---
    e.spacer()
    e.banner("RUN METRICS", "-")
    e.spacer()
    e.table(
        ["Metric", "Value"],
        [
            ["MAAS machines", str(len(maas_data.get("machines") or []))],
            ["NetBox devices", str(len(netbox_data.get("devices") or []))],
            ["Matched hostnames", str(drift.get("matched_count", 0))],
            ["In MAAS only", str(pc["maas_only"])],
            ["NetBox orphans", str(pc["nb_only_dev"])],
            ["NetBox serial missing", str(serial_validation_needed)],
            ["OpenStack subnet gaps", sub_txt],
            ["OpenStack FIP gaps", str(pc["fip_gaps"])],
            ["VLAN mismatch NICs", str(pc["vlan_drift_nic"])],
            ["VLAN unverified NICs", str(pc["vlan_unverified_nic"])],
            ["MAAS NIC missing in NetBox", str(pc["maas_nic_missing_nb"])],
        ],
    )

    # --- Proposed changes (preview only; full list, uncapped) ---
    prop = _proposed_changes_rows(
        maas_data,
        netbox_data,
        drift,
        interface_audit,
        matched_rows,
        os_subnet_gaps or [],
        os_floating_gaps or [],
        netbox_ifaces=netbox_ifaces,
    )
    e.spacer()
    e.banner("PROPOSED CHANGES", "-")
    e.paragraph(
        "Read-only. Possible NetBox updates from MAAS and OpenStack — nothing is applied from this screen."
    )
    e.spacer()

    e.subtitle("A) Add to NetBox")
    e.spacer()
    e.table(
        ["What", "Count", "Note"],
        [
            ["New devices (MAAS)", str(len(prop["add_devices"])), "Not in NetBox yet"],
            ["New prefixes (OpenStack)", str(len(prop["add_prefixes"])), "Subnet not in IPAM"],
            ["New floating IPs (OpenStack)", str(len(prop["add_fips"])), "FIP not in IPAM"],
        ],
    )
    if prop["add_devices"]:
        e.spacer()
        e.subtitle("Detail — new devices")
        e.spacer()
        e.table(
            ["Hostname", "Zone", "Pool", "MAAS Status", "Proposed Tag", "Proposed Action"],
            prop["add_devices"],
            dynamic_columns=True,
        )
    if prop["add_prefixes"]:
        e.spacer()
        e.subtitle("Detail — new prefixes")
        e.spacer()
        e.table(
            ["CIDR", "Network Name", "Network ID", "Cloud", "Proposed Action"],
            prop["add_prefixes"],
            dynamic_columns=True,
        )
    if prop["add_fips"]:
        e.spacer()
        e.subtitle("Detail — new floating IPs")
        e.spacer()
        e.table(
            ["Floating IP", "Fixed IP", "Project", "Cloud", "Proposed Action"],
            prop["add_fips"],
            dynamic_columns=True,
        )

    e.spacer()
    e.subtitle("B) NICs and BMC / OOB")
    e.spacer()
    e.table(
        ["What", "Count", "Note"],
        [
            ["New NICs in NetBox", str(len(prop["add_nb_interfaces"])), "MAAS MAC not on device"],
            ["NIC drift", str(len(prop["update_nic"])), "MAAS vs NetBox differs"],
            ["BMC / OOB", str(len(prop["add_mgmt_iface"])), "Power / out-of-band vs NetBox"],
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
                "Suggested NB name",
                "Proposed properties (from MAAS)",
                "Risk",
            ],
            prop["add_nb_interfaces"],
            dynamic_columns=True,
        )
    if prop["update_nic"]:
        e.spacer()
        e.subtitle("Detail — NIC drift")
        e.spacer()
        e.table(
            [
                "Host",
                "MAAS intf",
                "MAAS fabric",
                "MAAS MAC",
                "MAAS IPs",
                "NB intf",
                "NB MAC",
                "NB IPs",
                "MAAS VLAN",
                "NB VLAN",
                "Status",
                "Reason",
                "Proposed Action",
                "Risk",
            ],
            prop["update_nic"],
            dynamic_columns=True,
        )

    if prop["add_mgmt_iface"]:
        e.spacer()
        e.subtitle("Detail — BMC / OOB")
        e.spacer()
        e.table(
            [
                "Host",
                "MAAS BMC IP",
                "MAAS power_type",
                "MAAS BMC MAC",
                "NB OOB port (hint)",
                "NetBox OOB",
                "NB IP coverage",
                "NB port w/ BMC IP",
                "NB OOB MAC",
                "Status",
                "Proposed action",
                "Risk",
            ],
            prop["add_mgmt_iface"],
            dynamic_columns=True,
        )

    e.spacer()
    e.subtitle("C) Review")
    e.spacer()
    e.table(
        ["What", "Count", "Note"],
        [
            ["Orphan devices", str(len(prop["review_orphans"])), "In NetBox, not in MAAS"],
            ["Serial check", str(len(prop["review_serial"])), "NetBox serial empty"],
        ],
    )
    if prop["review_orphans"]:
        e.spacer()
        e.subtitle("Detail — orphans")
        e.spacer()
        e.table(
            ["Hostname", "Site", "Status", "Proposed Tag", "Proposed Action", "Risk"],
            prop["review_orphans"],
            dynamic_columns=True,
        )
    if prop["review_serial"]:
        e.spacer()
        e.subtitle("Detail — serials")
        e.spacer()
        e.table(
            ["Hostname", "MAAS Serial", "NetBox Serial", "Proposed Action", "Risk"],
            prop["review_serial"],
            dynamic_columns=True,
        )
    e.spacer()
    e.subtitle("Summary")
    e.spacer()
    total_props = (
        len(prop["add_devices"]) + len(prop["add_prefixes"]) + len(prop["add_fips"]) +
        len(prop["update_nic"]) + len(prop["add_nb_interfaces"]) + len(prop["add_mgmt_iface"]) +
        len(prop["review_orphans"]) + len(prop["review_serial"])
    )
    e.table(
        ["Bucket", "Count"],
        [
            ["New devices", str(len(prop["add_devices"]))],
            ["New prefixes", str(len(prop["add_prefixes"]))],
            ["New floating IPs", str(len(prop["add_fips"]))],
            ["NIC drift", str(len(prop["update_nic"]))],
            ["New NICs", str(len(prop["add_nb_interfaces"]))],
            ["BMC / OOB", str(len(prop["add_mgmt_iface"]))],
            ["Orphans (review)", str(len(prop["review_orphans"]))],
            ["Serials (review)", str(len(prop["review_serial"]))],
            ["Total", str(total_props)],
        ],
    )

    e.spacer()
    e.banner("END OF DRIFT AUDIT", "=")

    # ---------- REFERENCE ----------
    # Hidden intentionally for user-facing output.

    return {
        "drift": e.render(),
        "reference": "\n".join(ref_lines),
        "drift_markup": "html" if use_html else "text",
    }


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
    scope_meta = (drift or {}).get("scope_meta") or {}
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
        maas_unmatched = list(scope_meta.get("maas_unmatched_fabrics") or [])
        if scope_meta.get("maas_unmatched_fabrics_more"):
            maas_unmatched.append(f"... +{scope_meta['maas_unmatched_fabrics_more']} more")
        os_unmatched = list(scope_meta.get("openstack_unmatched_network_names") or [])
        if scope_meta.get("openstack_unmatched_network_names_more"):
            os_unmatched.append(f"... +{scope_meta['openstack_unmatched_network_names_more']} more")
        ws_sum.append(["MAAS unmatched fabrics (sample)", ", ".join(maas_unmatched) or "(none)"])
        ws_sum.append(["OpenStack unmatched network names (sample)", ", ".join(os_unmatched) or "(none)"])
    ws_sum.append([])
    ws_sum.append(["DRIFT COUNTS", "", ""])
    _append_header(ws_sum, ["Category", "Count"])
    ws_sum.append(["In MAAS only (not in NetBox)", str(pc["maas_only"])])
    ws_sum.append(["In NetBox only (orphaned tag)", str(pc["nb_only_dev"])])
    ws_sum.append(["Matched — placement needs check", str(pc["check_hosts"])])
    ws_sum.append(["NetBox serial missing", str(serial_validation_needed)])
    ws_sum.append(["NIC rows not OK", str(pc["iface_not_ok"])])
    ws_sum.append(["MAAS NIC missing in NetBox", str(pc["maas_nic_missing_nb"])])
    ws_sum.append(["VLAN mismatch (MAAS vs NetBox)", str(pc["vlan_drift_nic"])])
    ws_sum.append(["VLAN unverified from MAAS", str(pc["vlan_unverified_nic"])])
    ws_sum.append(["NetBox-only NICs (review)", str(pc["nb_only_nic"])])
    ws_sum.append(["OpenStack subnet → no Prefix", sub_txt])
    ws_sum.append(["OpenStack FIP → no IP record", str(pc["fip_gaps"])])
    ws_sum.append(["BMC vs NetBox OOB differs", str(bmc_oob_mismatch)])
    ws_sum.append(["LLDP / cabling", "—"])
    ws_sum.append([])
    ws_sum.append(["HIGH-RISK (review first)", "", ""])
    _append_header(ws_sum, ["Category", "Count"])
    ws_sum.append(["OpenStack FIP → no IP record", str(pc["fip_gaps"])])
    ws_sum.append(
        [
            "OpenStack subnet → no Prefix",
            str(pc["sub_gaps"]) if pc["sub_gaps"] is not None else "N/A",
        ]
    )
    ws_sum.append(["VLAN mismatch (MAAS vs NetBox)", str(pc["vlan_drift_nic"])])
    ws_sum.append(["NetBox serial missing", str(serial_validation_needed)])
    ws_sum.append(["BMC vs NetBox OOB differs", str(bmc_oob_mismatch)])
    hr_total_x = 0
    for _hr_val in (
        pc["fip_gaps"],
        pc["sub_gaps"],
        pc["vlan_drift_nic"],
        serial_validation_needed,
        bmc_oob_mismatch,
    ):
        if isinstance(_hr_val, int):
            hr_total_x += _hr_val
    ws_sum.append(["Total", str(hr_total_x)])
    ws_sum.append([])
    ws_sum.append(["RUN METRICS", "", ""])
    _append_header(ws_sum, ["Metric", "Value"])
    ws_sum.append(["MAAS machines", str(len(maas_data.get("machines") or []))])
    ws_sum.append(["NetBox devices", str(len(netbox_data.get("devices") or []))])
    ws_sum.append(["Matched hostnames", str(drift.get("matched_count", 0))])
    ws_sum.append(["In MAAS only", str(pc["maas_only"])])
    ws_sum.append(["NetBox orphans", str(pc["nb_only_dev"])])
    ws_sum.append(["NetBox serial missing", str(serial_validation_needed)])
    ws_sum.append(["OpenStack subnet gaps", sub_txt])
    ws_sum.append(["OpenStack FIP gaps", str(pc["fip_gaps"])])
    ws_sum.append(["VLAN mismatch NICs", str(pc["vlan_drift_nic"])])
    ws_sum.append(["VLAN unverified NICs", str(pc["vlan_unverified_nic"])])
    ws_sum.append(["MAAS NIC missing in NetBox", str(pc["maas_nic_missing_nb"])])

    prop = _proposed_changes_rows(
        maas_data,
        netbox_data,
        drift,
        interface_audit,
        matched_rows,
        os_subnet_gaps or [],
        os_floating_gaps or [],
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
        + len(prop["review_orphans"])
        + len(prop["review_serial"])
    )
    ws_sum.append(["New devices", str(len(prop["add_devices"]))])
    ws_sum.append(["New prefixes", str(len(prop["add_prefixes"]))])
    ws_sum.append(["New floating IPs", str(len(prop["add_fips"]))])
    ws_sum.append(["NIC drift", str(len(prop["update_nic"]))])
    ws_sum.append(["New NICs", str(len(prop["add_nb_interfaces"]))])
    ws_sum.append(["BMC / OOB", str(len(prop["add_mgmt_iface"]))])
    ws_sum.append(["Orphans (review)", str(len(prop["review_orphans"]))])
    ws_sum.append(["Serials (review)", str(len(prop["review_serial"]))])
    ws_sum.append(["Total", str(total_props_x)])

    # Matched-host drift worksheet intentionally suppressed to match on-screen report.

    # --- Proposed changes (full list) ---
    ws_prop = _sheet("Proposed changes")
    ws_prop.append(["Drift detail — read-only; nothing is written to NetBox from this export."])
    ws_prop.cell(row=1, column=1).font = header_font
    ws_prop.append([])
    _append_header(ws_prop, ["Section", "Count"])
    ws_prop.append(["New devices (MAAS)", len(prop["add_devices"])])
    ws_prop.append(["New prefixes (OpenStack)", len(prop["add_prefixes"])])
    ws_prop.append(["New floating IPs (OpenStack)", len(prop["add_fips"])])
    ws_prop.append(["NIC drift", len(prop["update_nic"])])
    ws_prop.append(["New NICs", len(prop["add_nb_interfaces"])])
    ws_prop.append(["BMC / OOB", len(prop["add_mgmt_iface"])])
    ws_prop.append(["Orphans (review)", len(prop["review_orphans"])])
    ws_prop.append(["Serials (review)", len(prop["review_serial"])])

    def _append_block(title, headers, rows):
        ws_prop.append([])
        ws_prop.append([title])
        ws_prop.cell(row=ws_prop.max_row, column=1).font = header_font
        _append_header(ws_prop, headers)
        for row in rows:
            ws_prop.append(list(row))

    _append_block(
        "A) New devices",
        ["Hostname", "Zone", "Pool", "MAAS Status", "Proposed Tag", "Proposed Action"],
        prop["add_devices"],
    )
    _append_block(
        "A) New prefixes",
        ["CIDR", "Network Name", "Network ID", "Cloud", "Proposed Action"],
        prop["add_prefixes"],
    )
    _append_block(
        "A) New floating IPs",
        ["Floating IP", "Fixed IP", "Project", "Cloud", "Proposed Action"],
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
            "Suggested NB name",
            "Proposed properties (from MAAS)",
            "Risk",
        ],
        prop["add_nb_interfaces"],
    )
    _append_block(
        "B) NIC drift",
        [
            "Host",
            "MAAS intf",
            "MAAS fabric",
            "MAAS MAC",
            "MAAS IPs",
            "NB intf",
            "NB MAC",
            "NB IPs",
            "MAAS VLAN",
            "NB VLAN",
            "Status",
            "Reason",
            "Proposed Action",
            "Risk",
        ],
        prop["update_nic"],
    )
    _append_block(
        "B) BMC / OOB",
        [
            "Host",
            "MAAS BMC IP",
            "MAAS power_type",
            "MAAS BMC MAC",
            "NB OOB port (hint)",
            "NetBox OOB",
            "NB IP coverage",
            "NB port w/ BMC IP",
            "NB OOB MAC",
            "Status",
            "Proposed action",
            "Risk",
        ],
        prop["add_mgmt_iface"],
    )
    _append_block(
        "C) Orphans",
        ["Hostname", "Site", "Status", "Proposed Tag", "Proposed Action", "Risk"],
        prop["review_orphans"],
    )
    _append_block(
        "C) Serials",
        ["Hostname", "MAAS Serial", "NetBox Serial", "Proposed Action", "Risk"],
        prop["review_serial"],
    )

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()
