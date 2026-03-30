"""Merged proposed rows from a persisted drift run — same data path as HTML/Excel."""

from __future__ import annotations

import re
from typing import Any

from netbox_automation_plugin.sync.reporting.drift_report.drift_overrides_apply import (
    HEADERS_DETAIL_NIC_DRIFT,
    SELECTION_KEY_TO_HEADERS,
    SELECTION_KEY_TO_PROP_LIST,
    merge_drift_review_overrides,
    normalize_drift_review_overrides,
    _update_nic_row_is_os_authority,
)
from netbox_automation_plugin.sync.reporting.drift_report.fabric_alignment import (
    _alignment_review_rows,
)
from netbox_automation_plugin.sync.reporting.drift_report.placement import (
    _drift_for_user_reports,
)
from netbox_automation_plugin.sync.reporting.drift_report.proposed_changes import (
    _proposed_changes_rows,
)
from netbox_automation_plugin.sync.reporting.drift_report.render_tables import (
    _selection_row_key,
)

from .history_models import MAASOpenStackDriftRun


def merged_proposed_from_drift_run(run: MAASOpenStackDriftRun) -> tuple[dict[str, Any], list]:
    """Snapshot + normalized overrides + merge — parity with modified drift HTML/XLSX."""
    payload = run.snapshot_payload if isinstance(run.snapshot_payload, dict) else {}
    drift = _drift_for_user_reports(payload.get("drift") or {})
    norm = normalize_drift_review_overrides(run.drift_review_overrides)
    align_rows = _alignment_review_rows(payload.get("matched_rows"))
    prop = _proposed_changes_rows(
        payload.get("maas_data") or {},
        payload.get("netbox_data") or {},
        drift,
        payload.get("interface_audit"),
        payload.get("matched_rows"),
        payload.get("os_subnet_gaps") or [],
        payload.get("os_floating_gaps") or [],
        openstack_data=payload.get("openstack_data"),
        netbox_ifaces=payload.get("netbox_ifaces"),
    )
    if norm:
        prop, align_rows = merge_drift_review_overrides(prop, align_rows, norm)
    return prop, align_rows


def _safe_selection_key(selection_key: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "_", str(selection_key or "drift_rows"))


def build_row_key_index(prop: dict, align_rows: list) -> dict[str, dict[str, Any]]:
    """
    Map HTML checkbox row_key (sha1 prefix) to row metadata.

    Must stay aligned with render_tables._html_table selectable rows.
    """
    index: dict[str, dict[str, Any]] = {}

    sk = "detail_placement_lifecycle_alignment"
    headers = SELECTION_KEY_TO_HEADERS.get(sk, [])
    safe = _safe_selection_key(sk)
    for idx, row in enumerate(align_rows or []):
        row_list = list(row) if isinstance(row, (list, tuple)) else []
        n = len(headers)
        padded = row_list[:n] + [""] * (n - min(len(row_list), n))
        rk = _selection_row_key(safe, idx, padded)
        index[rk] = {
            "selection_key": sk,
            "prop_list_key": None,
            "row_index": idx,
            "headers": headers,
            "row": padded,
        }

    update_nic = prop.get("update_nic")
    if isinstance(update_nic, list):
        for sk, want_os in (("detail_nic_drift_os", True), ("detail_nic_drift_maas", False)):
            headers = HEADERS_DETAIL_NIC_DRIFT
            safe = _safe_selection_key(sk)
            sub_indices = [
                i
                for i, r in enumerate(update_nic)
                if isinstance(r, (list, tuple)) and (_update_nic_row_is_os_authority(r) == want_os)
            ]
            for sub_idx, gi in enumerate(sub_indices):
                row_list = list(update_nic[gi])
                n = len(headers)
                padded = row_list[:n] + [""] * (n - min(len(row_list), n))
                rk = _selection_row_key(safe, sub_idx, padded)
                index[rk] = {
                    "selection_key": sk,
                    "prop_list_key": "update_nic",
                    "row_index": sub_idx,
                    "global_row_index": gi,
                    "headers": headers,
                    "row": padded,
                }

    for sk, pk in SELECTION_KEY_TO_PROP_LIST.items():
        if sk in ("detail_nic_drift_os", "detail_nic_drift_maas"):
            continue
        headers = SELECTION_KEY_TO_HEADERS.get(sk)
        if not headers:
            continue
        rows = prop.get(pk)
        if not isinstance(rows, list):
            continue
        safe = _safe_selection_key(sk)
        for idx, row in enumerate(rows):
            if not isinstance(row, (list, tuple)):
                continue
            row_list = list(row)
            n = len(headers)
            padded = row_list[:n] + [""] * (n - min(len(row_list), n))
            rk = _selection_row_key(safe, idx, padded)
            index[rk] = {
                "selection_key": sk,
                "prop_list_key": pk,
                "row_index": idx,
                "headers": headers,
                "row": padded,
            }

    return index


def all_registered_selection_keys() -> frozenset[str]:
    return frozenset(SELECTION_KEY_TO_HEADERS.keys())
