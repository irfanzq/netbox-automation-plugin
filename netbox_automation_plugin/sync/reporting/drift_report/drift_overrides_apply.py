"""Merge saved drift review overrides into proposed rows and alignment tables."""

from __future__ import annotations

import copy
from typing import Any

# selection_key (HTML data-selection-key) -> prop dict key
SELECTION_KEY_TO_PROP_LIST: dict[str, str] = {
    "detail_new_devices": "add_devices",
    "detail_review_only_devices": "add_devices_review_only",
    "detail_new_prefixes": "add_prefixes",
    "detail_new_fips": "add_fips",
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
    "Authority",
    "NB proposed device status",
    "NB proposed tag",
    "Proposed Action",
]

HEADERS_DETAIL_NEW_PREFIXES: list[str] = [
    "OS region",
    "CIDR",
    "Start address",
    "End address",
    "Project",
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
    "NB proposed status",
    "NB proposed role",
    "NB proposed VRF",
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

SELECTION_KEY_TO_HEADERS: dict[str, list[str]] = {
    "detail_new_devices": HEADERS_DETAIL_NEW_DEVICES,
    "detail_review_only_devices": HEADERS_DETAIL_NEW_DEVICES,
    "detail_new_prefixes": HEADERS_DETAIL_NEW_PREFIXES,
    "detail_new_fips": HEADERS_DETAIL_NEW_FIPS,
    "detail_placement_lifecycle_alignment": HEADERS_PLACEMENT_ALIGNMENT,
}


def normalize_drift_review_overrides(raw: Any) -> dict[str, dict[str, dict[str, str]]]:
    """
    Return { selection_key: { row_index_str: { column_header: value } } }.
    Ignores unknown keys and non-dict leaves.
    """
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
    return out


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
            row[j] = val
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
        pk = SELECTION_KEY_TO_PROP_LIST.get(sel_key)
        hdrs = SELECTION_KEY_TO_HEADERS.get(sel_key)
        if not pk or not hdrs:
            continue
        rows = p.get(pk)
        if not isinstance(rows, list):
            continue
        _apply_section(hdrs, rows, section)
    return p, a
