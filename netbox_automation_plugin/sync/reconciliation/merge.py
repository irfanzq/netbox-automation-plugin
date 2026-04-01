"""Merged proposed rows from a persisted drift run — same data path as HTML/Excel."""

from __future__ import annotations

import re
from typing import Any

from netbox_automation_plugin.sync.reporting.drift_report.drift_overrides_apply import (
    HEADERS_DETAIL_NIC_DRIFT,
    HEADERS_DETAIL_NEW_NICS,
    SELECTION_KEY_TO_HEADERS,
    SELECTION_KEY_TO_PROP_LIST,
    merge_drift_review_overrides,
    normalize_drift_review_overrides,
    _new_nic_row_is_os_authority,
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

from netbox_automation_plugin.workflows.maas_openstack_sync.history_models import (
    MAASOpenStackDriftRun,
)


def merge_review_override_layers(
    base: dict[str, dict[str, dict[str, str]]],
    overlay: dict[str, dict[str, dict[str, str]]],
) -> dict[str, dict[str, dict[str, str]]]:
    """Deep-merge overlay onto base (overlay wins). Values are normalized header maps."""
    out: dict[str, dict[str, dict[str, str]]] = {
        sk: {rk: dict(cols) for rk, cols in rows.items()} for sk, rows in base.items()
    }
    for sk, rows in overlay.items():
        if sk not in out:
            out[sk] = {}
        for ri, cols in rows.items():
            if ri not in out[sk]:
                out[sk][ri] = {}
            out[sk][ri].update(cols)
    return out


def effective_review_norm_for_run(
    run: MAASOpenStackDriftRun,
    posted_review_overrides: Any | None,
) -> dict[str, dict[str, dict[str, str]]]:
    """
    DB-saved review plus optional POST body from the audit page (unsaved picker state).
    posted_review_overrides=None: DB only. Otherwise normalize(posted) merged over DB.
    """
    db_norm = normalize_drift_review_overrides(run.drift_review_overrides)
    if posted_review_overrides is None:
        return db_norm
    post_norm = normalize_drift_review_overrides(posted_review_overrides)
    return merge_review_override_layers(db_norm, post_norm)


def merged_proposed_from_drift_run(
    run: MAASOpenStackDriftRun,
    *,
    review_norm: dict[str, dict[str, dict[str, str]]] | None = None,
) -> tuple[dict[str, Any], list]:
    """
    Snapshot + review merge — parity with modified drift HTML/XLSX.

    review_norm=None: use drift_run.drift_review_overrides from DB.
    review_norm=dict (possibly empty): use that normalized map only ({}
      = auto proposal before any review edits).
    """
    payload = run.snapshot_payload if isinstance(run.snapshot_payload, dict) else {}
    drift = _drift_for_user_reports(payload.get("drift") or {})
    if review_norm is None:
        norm = normalize_drift_review_overrides(run.drift_review_overrides)
    else:
        norm = dict(review_norm)
    align_rows = _alignment_review_rows(payload.get("matched_rows"))
    prop = _proposed_changes_rows(
        payload.get("maas_data") or {},
        payload.get("netbox_data") or {},
        drift,
        payload.get("interface_audit"),
        payload.get("matched_rows"),
        payload.get("os_subnet_gaps") or [],
        payload.get("os_ip_range_gaps") or [],
        payload.get("os_floating_gaps") or [],
        openstack_data=payload.get("openstack_data"),
        netbox_ifaces=payload.get("netbox_ifaces"),
        os_subnet_hints=payload.get("os_subnet_hints") or [],
    )
    if norm:
        prop, align_rows = merge_drift_review_overrides(prop, align_rows, norm)
    return prop, align_rows


def _safe_selection_key(selection_key: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "_", str(selection_key or "drift_rows"))


def build_row_key_index(
    prop: dict, align_rows: list
) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, int], dict[str, Any]]]:
    """
    Map HTML checkbox row_key (sha1 prefix) to row metadata, plus stable (safe_sk, row_idx).

    Checkbox values can become stale when cell text changes without a re-render; use stable map.
    Must stay aligned with render_tables._html_table selectable rows.
    """
    index: dict[str, dict[str, Any]] = {}
    stable: dict[tuple[str, int], dict[str, Any]] = {}

    sk = "detail_placement_lifecycle_alignment"
    headers = SELECTION_KEY_TO_HEADERS.get(sk, [])
    safe = _safe_selection_key(sk)
    for idx, row in enumerate(align_rows or []):
        row_list = list(row) if isinstance(row, (list, tuple)) else []
        n = len(headers)
        padded = row_list[:n] + [""] * (n - min(len(row_list), n))
        rk = _selection_row_key(safe, idx, padded)
        meta = {
            "selection_key": sk,
            "prop_list_key": None,
            "row_index": idx,
            "headers": headers,
            "row": padded,
        }
        index[rk] = meta
        stable[(safe, idx)] = meta

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
                meta = {
                    "selection_key": sk,
                    "prop_list_key": "update_nic",
                    "row_index": sub_idx,
                    "global_row_index": gi,
                    "headers": headers,
                    "row": padded,
                }
                index[rk] = meta
                stable[(safe, sub_idx)] = meta

    add_nb = prop.get("add_nb_interfaces")
    if isinstance(add_nb, list):
        for sk, want_os in (("detail_new_nics_os", True), ("detail_new_nics_maas", False)):
            headers = HEADERS_DETAIL_NEW_NICS
            safe = _safe_selection_key(sk)
            sub_indices = [
                i
                for i, r in enumerate(add_nb)
                if isinstance(r, (list, tuple))
                and (_new_nic_row_is_os_authority(r) == want_os)
            ]
            for sub_idx, gi in enumerate(sub_indices):
                row_list = list(add_nb[gi])
                n = len(headers)
                padded = row_list[:n] + [""] * (n - min(len(row_list), n))
                rk = _selection_row_key(safe, sub_idx, padded)
                meta = {
                    "selection_key": sk,
                    "prop_list_key": "add_nb_interfaces",
                    "row_index": sub_idx,
                    "global_row_index": gi,
                    "headers": headers,
                    "row": padded,
                }
                index[rk] = meta
                stable[(safe, sub_idx)] = meta

    for sk, pk in SELECTION_KEY_TO_PROP_LIST.items():
        if sk in ("detail_nic_drift_os", "detail_nic_drift_maas"):
            continue
        if sk in ("detail_new_nics_os", "detail_new_nics_maas"):
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
            meta = {
                "selection_key": sk,
                "prop_list_key": pk,
                "row_index": idx,
                "headers": headers,
                "row": padded,
            }
            index[rk] = meta
            stable[(safe, idx)] = meta

    return index, stable


def all_registered_selection_keys() -> frozenset[str]:
    return frozenset(SELECTION_KEY_TO_HEADERS.keys())
