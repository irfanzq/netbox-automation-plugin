"""ASCII and HTML table rendering and drift report emitter."""

import html
import hashlib
import re
import textwrap

from netbox_automation_plugin.sync.reporting.drift_report.constants import (
    _ASCII_COL_WRAP_DEFAULT,
    _ASCII_NOTES_COL_WRAP,
    _DYNAMIC_COL_CAP,
    _MAX_COL,
    _MAX_MATCHED_COL,
    _MAX_NOTES_COL,
    _NOTES_COL_MAX_WIDTH,
    _PHASE0_FIELD_OWNERSHIP_BULLETS,
    _PHASE0_FIELD_OWNERSHIP_LEAD,
    _PHASE0_FIELD_OWNERSHIP_TITLE,
)

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


def _html_nb_picker_wrap(
    inner_safe_html: str,
    kind: str,
    *,
    col_header: str = "",
    selection_key: str = "",
    row_idx: str = "",
) -> str:
    """Wrap already-escaped cell HTML in a NetBox choice picker (search + scroll)."""
    safe_kind = html.escape(kind, quote=True)
    extra = ""
    if col_header and selection_key and row_idx != "":
        # Attributes must be quoted: unquoted values end at whitespace, so
        # "NB proposed device status" was parsed as "NB" and Excel merge skipped columns.
        ch_attr = html.escape(str(col_header), quote=True)
        sk_attr = html.escape(str(selection_key), quote=True)
        ri_attr = html.escape(str(row_idx), quote=True)
        extra = (
            f' data-drift-col-header="{ch_attr}"'
            f' data-drift-sel-key="{sk_attr}"'
            f' data-drift-row-idx="{ri_attr}"'
        )
    return (
        '<div class="drift-nb-pick position-relative d-inline-flex align-items-center gap-1 flex-nowrap text-start" '
        f'data-nb-pick-kind="{safe_kind}"{extra} role="group">'
        f'<span class="drift-nb-pick-visible align-self-center">{inner_safe_html}</span>'
        '<button type="button" class="btn btn-outline-secondary btn-sm py-0 px-1 drift-nb-pick-toggle" '
        'aria-expanded="false" title="Choose from NetBox" aria-label="Choose from NetBox">▾</button>'
        '<div class="drift-nb-pick-menu d-none border rounded shadow-sm bg-body p-0 text-start" '
        'style="min-width:11rem;">'
        '<input type="search" class="form-control form-control-sm border-0 border-bottom rounded-0 drift-nb-pick-q" '
        'placeholder="Search…" autocomplete="off">'
        '<div class="drift-nb-pick-options list-group list-group-flush overflow-auto" '
        'style="max-height:7.5rem"></div>'
        "</div></div>"
    )


def _html_nb_picker_bulk_column(kind: str, *, col_header: str, data_col_idx: int) -> str:
    """Header control: same ▾ menu as cells; JS applies choice to every row with Include checked."""
    safe_kind = html.escape(kind, quote=True)
    ch = html.escape(str(col_header), quote=True)
    return (
        '<div class="drift-nb-pick drift-nb-pick-bulk position-relative d-inline-flex align-items-center '
        'gap-1 flex-shrink-0 ms-auto text-start" '
        f'data-nb-pick-kind="{safe_kind}" data-drift-bulk="1" '
        f'data-drift-col-header="{ch}" data-drift-data-col-idx="{int(data_col_idx)}" role="group">'
        '<span class="drift-nb-pick-visible visually-hidden" aria-hidden="true">—</span>'
        '<button type="button" class="btn btn-outline-secondary btn-sm py-0 px-1 drift-nb-pick-toggle" '
        'aria-expanded="false" title="Apply NetBox choice to selected rows" '
        'aria-label="Apply NetBox choice to selected rows">▾</button>'
        '<div class="drift-nb-pick-menu d-none border rounded shadow-sm bg-body p-0 text-start" '
        'style="min-width:11rem;">'
        '<input type="search" class="form-control form-control-sm border-0 border-bottom rounded-0 drift-nb-pick-q" '
        'placeholder="Search…" autocomplete="off">'
        '<div class="drift-nb-pick-options list-group list-group-flush overflow-auto" '
        'style="max-height:7.5rem"></div>'
        "</div></div>"
    )


def _html_maas_fabric_cell_content(s) -> str:
    """
    One visual line per fabric so hyphenated names are never broken mid-token by CSS wrap.
    Comma-separated lists (e.g. spruce-*) stack with <br />.
    """
    raw = _normalize_ascii_cell(s)
    if not raw.strip():
        return ""
    parts = [html.escape(p.strip(), quote=False) for p in raw.split(",") if p.strip()]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return "<br />".join(parts)


def _html_col_is_mac(header) -> bool:
    """True for column headers that represent a MAC address (not substrings like 'machines')."""
    return re.search(r"(?i)\bMAC\b", str(header or "")) is not None


def _html_col_is_risk(header) -> bool:
    return str(header or "").strip().lower() == "risk"


def _html_col_is_role_reason(header) -> bool:
    """Long prose in proposed-prefix rows; wrap in HTML (not single-line nowrap)."""
    return str(header or "").strip().lower() == "role reason"


def _html_col_is_prefix_description(header) -> bool:
    h = str(header or "").strip().lower()
    return h in {"os description", "nb prefix description"}


def _html_col_is_maas_fabric(header) -> bool:
    """Cells may list many fabrics; stack on commas, keep each full name intact."""
    return str(header or "").strip().lower() == "maas fabric"


def _html_maas_fabric_col_extra_attrs(header, *, is_header: bool) -> str:
    if not _html_col_is_maas_fabric(header):
        return ""
    if is_header:
        return ' style="vertical-align:bottom"'
    # nowrap: each fabric stays one line; multiple lines come from <br /> only.
    return ' style="white-space:nowrap;vertical-align:top"'


def _html_col_is_ip(header) -> bool:
    """
    True for column headers representing IP addresses/lists.
    Matches labels like 'IP', 'IPs', 'OOB IP', 'MAAS BMC IP', etc.
    """
    h = str(header or "")
    return re.search(r"(?i)\bIP(?:s)?\b", h) is not None


def _html_th_class(header) -> str:
    h = str(header or "")
    if _html_col_is_prefix_description(h):
        return "small align-bottom"
    if _html_col_is_maas_fabric(h):
        return "small align-bottom text-nowrap"
    if _html_col_is_role_reason(h):
        return "small align-bottom drift-col-role-reason"
    base = "small align-bottom text-nowrap"
    if _html_col_is_mac(h):
        return f"{base} text-nowrap font-monospace"
    if _html_col_is_ip(h):
        return f"{base} text-nowrap"
    if _html_col_is_risk(h):
        return f"{base} text-nowrap"
    return base


def _html_td_class(header, col_idx, notes_col_idx=None) -> str:
    h = str(header or "")
    parts = []
    if _html_col_is_prefix_description(h):
        parts.extend(["align-top"])
    elif _html_col_is_role_reason(h):
        parts.extend(["align-top", "drift-col-role-reason"])
    elif _html_col_is_mac(h):
        parts.extend(["align-top", "text-nowrap", "font-monospace"])
    elif _html_col_is_ip(h):
        parts.extend(["align-top", "text-nowrap"])
    elif _html_col_is_risk(h):
        parts.extend(["align-top", "text-nowrap"])
    elif _html_col_is_maas_fabric(h):
        parts.extend(["align-top", "text-nowrap"])
    else:
        parts.extend(["align-top", "text-nowrap"])
    if notes_col_idx is not None and col_idx == notes_col_idx:
        parts.append("text-muted")
    return " ".join(parts)


def _selection_row_key(selection_key: str, row_idx: int, row_cells: list) -> str:
    """Stable key for a proposed row; used later for ingestion filtering."""
    norm = "|".join(_normalize_ascii_cell(c).strip() for c in row_cells)
    raw = f"{selection_key}|{row_idx}|{norm}".encode("utf-8", errors="ignore")
    return hashlib.sha1(raw).hexdigest()[:16]


def _html_table(
    headers,
    rows,
    *,
    notes_col_idx=None,
    selectable=False,
    selection_key=None,
    proposed_pick_columns=None,
    editable_columns=None,
):
    if not headers:
        return ""
    n = len(headers)
    hdr_strs = [str(h) for h in headers]
    pick_map = proposed_pick_columns if isinstance(proposed_pick_columns, dict) else None
    editable_set = {str(x).strip() for x in (editable_columns or []) if str(x).strip()}
    header_th_cells = []
    for col_i, h in enumerate(hdr_strs):
        label_html = _html_cell_content(h)
        inner = label_html
        if selectable and pick_map:
            pk = pick_map.get(h)
            if pk:
                bulk = _html_nb_picker_bulk_column(pk, col_header=h, data_col_idx=col_i)
                inner = (
                    '<div class="d-flex align-items-center justify-content-between gap-2 flex-nowrap w-100 drift-th-pick-row">'
                    f'<span class="drift-th-pick-label me-1 flex-grow-1">{label_html}</span>{bulk}</div>'
                )
        header_th_cells.append(
            f'<th scope="col" class="{_html_th_class(h)}"'
            f'{_html_maas_fabric_col_extra_attrs(h, is_header=True)}>{inner}</th>'
        )
    ths = "".join(header_th_cells)
    if selectable:
        ths = (
            '<th scope="col" class="small align-bottom text-nowrap drift-select-col-header">'
            '<label class="d-inline-flex align-items-center gap-1 mb-0">'
            '<input type="checkbox" class="form-check-input mt-0 drift-include-toggle-all" checked />'
            '<span class="drift-include-label">Include (all)</span>'
            "</label>"
            "</th>"
        ) + ths
    body_parts = []
    safe_selection_key = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(selection_key or "drift_rows"))
    for r in rows:
        padded = list(r[:n]) + [""] * (n - min(len(r), n))
        tds = []
        if selectable:
            row_idx = len(body_parts)
            row_key = _selection_row_key(safe_selection_key, row_idx, padded)
            tds.append(
                '<td class="align-top text-nowrap drift-select-col">'
                '<input type="checkbox" class="form-check-input drift-include-row" '
                f'value="{html.escape(row_key)}" data-row-key="{html.escape(row_key)}" checked />'
                "</td>"
            )
        for i, cell in enumerate(padded):
            h = hdr_strs[i] if i < len(hdr_strs) else ""
            cls = _html_td_class(h, i, notes_col_idx)
            fab_attrs = _html_maas_fabric_col_extra_attrs(h, is_header=False)
            kind = pick_map.get(h) if pick_map else None
            if kind:
                inner = (
                    _html_maas_fabric_cell_content(cell)
                    if _html_col_is_maas_fabric(h)
                    else _html_cell_content(cell)
                )
                if not (inner or "").strip():
                    inner = '<span class="text-muted">—</span>'
                v = _html_nb_picker_wrap(
                    inner,
                    kind,
                    col_header=h,
                    selection_key=safe_selection_key if selectable else "",
                    row_idx=str(row_idx) if selectable else "",
                )
            else:
                v = (
                    _html_maas_fabric_cell_content(cell)
                    if _html_col_is_maas_fabric(h)
                    else _html_cell_content(cell)
                )
                if selectable and h in editable_set:
                    val = _normalize_ascii_cell(cell).strip()
                    v = (
                        '<span class="drift-editable-text d-inline-block w-100" contenteditable="true" '
                        f'data-drift-col-header="{html.escape(h, quote=True)}" '
                        f'data-drift-sel-key="{html.escape(safe_selection_key, quote=True)}" '
                        f'data-drift-row-idx="{row_idx}">{html.escape(val)}</span>'
                    )
            tds.append(f'<td class="{cls}"{fab_attrs}>{v}</td>')
        tr_attrs = ""
        if selectable:
            tr_attrs = f' data-drift-sel-key="{html.escape(safe_selection_key)}" data-drift-row-idx="{row_idx}"'
        body_parts.append(f"<tr{tr_attrs}>" + "".join(tds) + "</tr>")
    if selectable:
        table_open = (
            '<div class="drift-selectable-table mb-3" '
            f'data-selection-key="{html.escape(safe_selection_key)}">'
            '<div class="drift-selection-toolbar d-flex justify-content-between align-items-center flex-wrap gap-2 mb-1">'
            '<div class="d-flex align-items-center gap-2">'
            '<button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2 drift-select-all-btn">Select all</button>'
            '<button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2 drift-clear-all-btn">Clear all</button>'
            "</div>"
            '<span class="small text-muted drift-selected-count"></span>'
            "</div>"
            '<div class="table-responsive drift-selectable-table-wrapper">'
        )
        table_close = "</div></div>"
    else:
        table_open = '<div class="table-responsive mb-3">'
        table_close = "</div>"
    return (
        table_open
        +
        '<table class="table table-sm table-bordered table-striped align-middle mb-0">'
        f'<thead class="table-light"><tr>{ths}</tr></thead><tbody>'
        + "".join(body_parts)
        + "</tbody></table>"
        + table_close
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
                _html_table(
                    headers,
                    rows,
                    notes_col_idx=kw.get("notes_col_idx"),
                    selectable=kw.get("selectable", False),
                    selection_key=kw.get("selection_key"),
                    proposed_pick_columns=kw.get("proposed_pick_columns"),
                    editable_columns=kw.get("editable_columns"),
                )
            )
        else:
            self._parts.extend(_ascii_table(headers, rows, **kw))

    def phase0_field_ownership(self) -> None:
        """Explain source-of-truth and why MAAS/OS columns feed proposed NetBox actions."""
        if self._html:
            lis = "".join(
                f"<li>{html.escape(b)}</li>" for b in _PHASE0_FIELD_OWNERSHIP_BULLETS
            )
            self._parts.append(
                '<div class="alert alert-info border py-2 px-3 mb-3 small drift-rpt-field-ownership" role="note">'
                f'<div class="fw-semibold mb-1">{html.escape(_PHASE0_FIELD_OWNERSHIP_TITLE)}</div>'
                f'<p class="small text-body-secondary mb-2">{html.escape(_PHASE0_FIELD_OWNERSHIP_LEAD)}</p>'
                f'<ul class="mb-0 ps-3">{lis}</ul></div>'
            )
        else:
            self._parts.extend(_banner(_PHASE0_FIELD_OWNERSHIP_TITLE, "-"))
            self._parts.append(f"  {_PHASE0_FIELD_OWNERSHIP_LEAD}")
            self._parts.append("")
            for b in _PHASE0_FIELD_OWNERSHIP_BULLETS:
                self._parts.append(f"  • {b}")
            self._parts.append("")

    def render(self) -> str:
        if self._html:
            return (
                '<div class="drift-report-html" style="font-size:0.8125rem">'
                + "\n".join(self._parts)
                + "</div>"
            )
        return "\n".join(self._parts)
