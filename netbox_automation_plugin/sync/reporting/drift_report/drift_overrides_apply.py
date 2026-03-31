"""Merge saved drift review overrides into proposed rows and alignment tables."""

from __future__ import annotations

import copy
import json
from typing import Any

# selection_key (HTML data-selection-key) -> prop dict key
SELECTION_KEY_TO_PROP_LIST: dict[str, str] = {
    "detail_new_devices": "add_devices",
    "detail_review_only_devices": "add_devices_review_only",
    "detail_new_prefixes": "add_prefixes",
    "detail_new_ip_ranges": "add_ip_ranges",
    "detail_new_fips": "add_fips",
    "detail_new_nics": "add_nb_interfaces",
    "detail_new_nics_os": "add_nb_interfaces",
    "detail_new_nics_maas": "add_nb_interfaces",
    "detail_bmc_new_devices": "add_mgmt_iface_new_devices",
    "detail_bmc_existing": "add_mgmt_iface",
    "detail_serial_review": "review_serial",
}

HEADERS_DETAIL_NEW_DEVICES: list[str] = [
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
]

HEADERS_DETAIL_NEW_PREFIXES: list[str] = [
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
]

HEADERS_DETAIL_NEW_FIPS: list[str] = [
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
]

HEADERS_DETAIL_NEW_IP_RANGES: list[str] = [
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
]

HEADERS_PLACEMENT_ALIGNMENT: list[str] = [
    "Host",
    "MAAS fabric",
    "MAAS state",
    "OS region",
    "OS provision",
    "OS power",
    "OS maintenance",
    "NetBox site",
    "NetBox location",
    "NB state (current)",
    "NB proposed device status",
    "Authority",
    "Alignment issues",
]

HEADERS_DETAIL_NEW_NICS: list[str] = [
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

HEADERS_DETAIL_NIC_DRIFT: list[str] = [
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

HEADERS_DETAIL_NIC_DRIFT_OS: list[str] = [
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
    "Risk",
]

HEADERS_BMC_NEW_DEVICES: list[str] = [
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
]

HEADERS_BMC_EXISTING: list[str] = [
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
]

HEADERS_SERIAL_REVIEW: list[str] = [
    "Hostname",
    "MAAS Serial",
    "NetBox Serial",
    "Proposed Action",
    "Risk",
]

SELECTION_KEY_TO_HEADERS: dict[str, list[str]] = {
    "detail_new_devices": HEADERS_DETAIL_NEW_DEVICES,
    "detail_review_only_devices": HEADERS_DETAIL_NEW_DEVICES,
    "detail_new_prefixes": HEADERS_DETAIL_NEW_PREFIXES,
    "detail_new_ip_ranges": HEADERS_DETAIL_NEW_IP_RANGES,
    "detail_new_fips": HEADERS_DETAIL_NEW_FIPS,
    "detail_new_nics": HEADERS_DETAIL_NEW_NICS,
    "detail_new_nics_os": HEADERS_DETAIL_NEW_NICS,
    "detail_new_nics_maas": HEADERS_DETAIL_NEW_NICS,
    "detail_nic_drift_os": HEADERS_DETAIL_NIC_DRIFT_OS,
    "detail_nic_drift_maas": HEADERS_DETAIL_NIC_DRIFT,
    "detail_bmc_new_devices": HEADERS_BMC_NEW_DEVICES,
    "detail_bmc_existing": HEADERS_BMC_EXISTING,
    "detail_serial_review": HEADERS_SERIAL_REVIEW,
    "detail_placement_lifecycle_alignment": HEADERS_PLACEMENT_ALIGNMENT,
}


def normalize_drift_review_overrides(raw: Any) -> dict[str, dict[str, dict[str, str]]]:
    """
    Return { selection_key: { row_index_str: { column_header: value } } }.
    Ignores unknown keys and non-dict leaves.
    """
    if raw is None:
        return {}
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return {}
        try:
            raw = json.loads(s)
        except (json.JSONDecodeError, TypeError):
            return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, dict[str, str]]] = {}
    for sel_key, section in raw.items():
        sk = str(sel_key).strip()
        if not sk or not isinstance(section, dict):
            continue
        inner: dict[str, dict[str, str]] = {}
        for ridx, cmap in section.items():
            if not isinstance(cmap, dict):
                continue
            rk = str(ridx).strip()
            if not rk:
                continue
            colmap: dict[str, str] = {}
            for col, val in cmap.items():
                ck = str(col).strip()
                if not ck:
                    continue
                colmap[ck] = "" if val is None else str(val).strip()
            if colmap:
                inner[rk] = colmap
        if inner:
            out[sk] = inner
    _remap_legacy_truncated_nb_placement_headers(out)
    return out


def _remap_legacy_truncated_nb_placement_headers(
    out: dict[str, dict[str, dict[str, str]]],
) -> None:
    """
    Older drift HTML used unquoted data-drift-col-header attributes; browsers then
    truncated values at the first space (e.g. \"NB proposed device status\" -> \"NB\").
    Remap a sole \"NB\" key in the placement table to the real header so merge,
    saved modified HTML, history \"view modified\", and Excel stay consistent.
    """
    sec = out.get("detail_placement_lifecycle_alignment")
    if not isinstance(sec, dict):
        return
    target = "NB proposed device status"
    for cmap in sec.values():
        if not isinstance(cmap, dict) or len(cmap) != 1:
            continue
        if "NB" not in cmap or target in cmap:
            continue
        cmap[target] = cmap.pop("NB")


def _update_nic_row_is_os_authority(row) -> bool:
    """Matches format_html_proposed split for NIC drift (OS vs MAAS) tables."""
    return len(row) > 10 and str(row[10]).strip() == "[OS]"


def _new_nic_row_is_os_authority(row) -> bool:
    """Matches format_html_proposed split for new NICs (OS vs MAAS) tables."""
    return len(row) > 12 and str(row[12]).strip() == "[OS]"


def _apply_new_nics_subset(
    rows: list,
    headers: list[str],
    section: dict[str, dict[str, str]],
    *,
    os_authority: bool,
) -> None:
    """
    HTML uses two tables with row indices 0..n-1 per subset; underlying prop is one add_nb_interfaces list.
    Map subset index -> global index before applying cell overrides.
    """
    h2i = {h: i for i, h in enumerate(headers)}
    global_indices = [
        i
        for i, r in enumerate(rows)
        if isinstance(r, (list, tuple)) and (_new_nic_row_is_os_authority(r) == os_authority)
    ]
    for ridx_str, cmap in section.items():
        try:
            sub_idx = int(ridx_str)
        except (TypeError, ValueError):
            continue
        if sub_idx < 0 or sub_idx >= len(global_indices):
            continue
        gi = global_indices[sub_idx]
        row = list(rows[gi])
        for col_header, val in cmap.items():
            j = h2i.get(col_header)
            if j is None:
                continue
            while len(row) <= j:
                row.append("")
            row[j] = "" if val is None else str(val).strip()
        rows[gi] = row


def _apply_update_nic_subset(
    update_nic: list,
    headers: list[str],
    section: dict[str, dict[str, str]],
    *,
    os_authority: bool,
) -> None:
    """
    HTML uses two tables with row indices 0..n-1 per subset; underlying prop is one update_nic list.
    Map subset index -> global index before applying cell overrides.
    """
    h2i = {h: i for i, h in enumerate(headers)}
    # OS authority table hides Status/Proposed Action; map visible columns back to full row indices.
    if headers == HEADERS_DETAIL_NIC_DRIFT_OS:
        h2i = {h: i for i, h in enumerate(HEADERS_DETAIL_NIC_DRIFT)}
        h2i["Risk"] = 17
    global_indices = [
        i
        for i, r in enumerate(update_nic)
        if isinstance(r, (list, tuple)) and (_update_nic_row_is_os_authority(r) == os_authority)
    ]
    for ridx_str, cmap in section.items():
        try:
            sub_idx = int(ridx_str)
        except (TypeError, ValueError):
            continue
        if sub_idx < 0 or sub_idx >= len(global_indices):
            continue
        gi = global_indices[sub_idx]
        row = list(update_nic[gi])
        for col_header, val in cmap.items():
            j = h2i.get(col_header)
            if j is None:
                continue
            while len(row) <= j:
                row.append("")
            row[j] = "" if val is None else str(val).strip()
        update_nic[gi] = row


def _apply_section(headers: list[str], rows: list, section: dict[str, dict[str, str]]) -> None:
    h2i = {h: i for i, h in enumerate(headers)}
    for ridx_str, cmap in section.items():
        try:
            idx = int(ridx_str)
        except (TypeError, ValueError):
            continue
        if idx < 0 or idx >= len(rows):
            continue
        row = list(rows[idx])
        for col_header, val in cmap.items():
            j = h2i.get(col_header)
            if j is None:
                continue
            while len(row) <= j:
                row.append("")
            row[j] = "" if val is None else str(val).strip()
        rows[idx] = row


def merge_drift_review_overrides(
    prop: dict,
    align_rows: list[list],
    overrides: dict[str, dict[str, dict[str, str]]] | None,
) -> tuple[dict, list[list]]:
    """Deep-copy prop, copy align_rows lists, apply overrides in place on copies."""
    p = copy.deepcopy(prop)
    a = [list(r) for r in align_rows]
    if not overrides:
        return p, a
    for sel_key, section in overrides.items():
        if sel_key == "detail_placement_lifecycle_alignment":
            hdrs = SELECTION_KEY_TO_HEADERS.get(sel_key)
            if hdrs:
                _apply_section(hdrs, a, section)
            continue
        if sel_key == "detail_nic_drift_os":
            un = p.get("update_nic")
            if isinstance(un, list):
                _apply_update_nic_subset(
                    un, HEADERS_DETAIL_NIC_DRIFT_OS, section, os_authority=True
                )
            continue
        if sel_key == "detail_nic_drift_maas":
            un = p.get("update_nic")
            if isinstance(un, list):
                _apply_update_nic_subset(
                    un, HEADERS_DETAIL_NIC_DRIFT, section, os_authority=False
                )
            continue
        if sel_key == "detail_new_nics_os":
            rows = p.get("add_nb_interfaces")
            if isinstance(rows, list):
                _apply_new_nics_subset(
                    rows, HEADERS_DETAIL_NEW_NICS, section, os_authority=True
                )
            continue
        if sel_key == "detail_new_nics_maas":
            rows = p.get("add_nb_interfaces")
            if isinstance(rows, list):
                _apply_new_nics_subset(
                    rows, HEADERS_DETAIL_NEW_NICS, section, os_authority=False
                )
            continue
        pk = SELECTION_KEY_TO_PROP_LIST.get(sel_key)
        hdrs = SELECTION_KEY_TO_HEADERS.get(sel_key)
        if not pk or not hdrs:
            continue
        rows = p.get(pk)
        if not isinstance(rows, list):
            continue
        _apply_section(hdrs, rows, section)
    return p, a
