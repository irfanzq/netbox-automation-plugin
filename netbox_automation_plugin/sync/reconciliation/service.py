"""Preview, signed acknowledgement, and frozen operations for branch reconciliation.

Each frozen op carries full audit ``cells`` for apply. The recon UI shows
``netbox_write_preview_cells`` per section: NetBox model field names (values from audit cells)
(see ``group_reconciliation_operation_tables`` and ``AUDIT_REPORT_APPLY_ORDER``).

New-NIC sections store a minimal frozen row (``new_nic_cells_for_reconciliation``); preview
still shows resolved MAC/VLAN/IP columns aligned with ``apply_create_interface``.

When any interface row is selected, ``build_frozen_operations`` auto-appends **every**
``detail_new_devices``, ``detail_review_only_devices``, and ``detail_proposed_missing_vlans``
row present in that audit index. For interface hosts that still have no ``create_device`` op,
it also injects a synthetic ``create_device`` from **placement** (NetBox site on the placement
row) when available — **only if** no ``dcim.Device`` with that host name already exists (matched
hosts are omitted; they are not listed under New devices but do not need a create op). Ops are
sorted by ``AUDIT_REPORT_APPLY_ORDER`` so device + VLAN creates run before ``create_interface``
/ ``update_interface`` without ticking those sections manually.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
from datetime import datetime, timezone as dt_timezone
from typing import Any

from django.core import signing
from django.db import connections, transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from netbox_automation_plugin.models import MAASOpenStackReconciliationRun
from netbox_automation_plugin.sync.reporting.drift_report.render_tables import (
    _selection_row_key,
)

from netbox_automation_plugin.workflows.maas_openstack_sync.history_models import (
    MAASOpenStackDriftRun,
)
from .branch import (
    branch_write_context,
    create_netbox_branch,
    delete_netbox_branch_instance,
    get_netbox_branch,
    netbox_branch_exists,
)
from .apply_cells import (
    NEW_NIC_SELECTION_KEYS,
    SUPPORTED_APPLY_ACTIONS,
    _interface_mac_vlan_ip_from_cells,
    apply_row_operation,
    netbox_write_preview_cells,
    netbox_write_preview_fieldnames,
    netbox_write_preview_ordered_fieldnames,
    new_nic_cells_for_reconciliation,
    recon_operation_display_cells,
    reconciliation_apply_snapshot_cells,
    synthetic_device_cells_from_placement_for_nic_prereq,
    validate_preview_mandatory_audit_fields,
)
from .merge import (
    _safe_selection_key,
    all_registered_selection_keys,
    build_row_key_index,
    effective_review_norm_for_run,
    merged_proposed_from_drift_run,
)
from .netbox_write_projection import (
    netbox_write_projection_for_op,
    netbox_write_preview_table_headers,
)

logger = logging.getLogger(__name__)

# NIC drift sections use NB column fallbacks like ``apply_update_interface``.
NIC_DRIFT_SELECTION_KEYS: frozenset[str] = frozenset(
    {"detail_nic_drift_os", "detail_nic_drift_maas"}
)

PREVIEW_TOKEN_SALT = "netbox_automation_plugin.ma_openstack_recon.preview.v1"

# Cap stored exception text for JSON / UI (full trace still in server logs).
_APPLY_EXCEPTION_MESSAGE_MAX = 4000
# Shorter cap for apply-handler prerequisite / validation detail (skip reasons).
_APPLY_SKIP_REASON_DETAIL_MAX = 2000
# Cap NetBox write preview string per apply row (matches recon preview projection).
_WRITE_PREVIEW_MAX = 4000


def _apply_result_write_preview(op: dict[str, Any]) -> str:
    """Human-readable NetBox-oriented fields for apply logs (same projection as recon tables)."""
    sk = str(op.get("selection_key") or "").strip()
    raw = op.get("cells")
    cells: dict[str, str] = {}
    if isinstance(raw, dict):
        cells = {str(k): "" if v is None else str(v) for k, v in raw.items()}
    if sk in NEW_NIC_SELECTION_KEYS:
        cells = new_nic_cells_for_reconciliation(cells)
    try:
        proj = netbox_write_projection_for_op({"selection_key": sk, "cells": cells})
    except Exception:
        logger.debug("apply row write_preview projection failed", exc_info=True)
        return ""
    parts: list[str] = []
    for k, v in proj.items():
        vv = (v or "").strip()
        if not vv or vv in ("—", "-"):
            continue
        parts.append(f"{k}={vv}")
    s = "; ".join(parts)
    if len(s) > _WRITE_PREVIEW_MAX:
        return s[: _WRITE_PREVIEW_MAX - 3] + "..."
    return s


def _finalize_apply_row(op: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    wp = _apply_result_write_preview(op)
    if wp:
        result["write_preview"] = wp
    return result


def _apply_result_row_shell(op: dict[str, Any]) -> dict[str, Any]:
    row_key = str(op.get("row_key") or "").strip()
    return {
        "row_key": row_key,
        "idempotency_key": row_key,
        "selection_key": str(op.get("selection_key") or ""),
        "action": str(op.get("action") or "unknown").strip(),
        "summary": str(op.get("summary") or ""),
        "applied_at": timezone.now().isoformat(),
    }


def _truncate_exc_message(msg: str, *, max_len: int = _APPLY_EXCEPTION_MESSAGE_MAX) -> str:
    s = (msg or "").strip()
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


def _failed_apply_row(op: dict[str, Any], exc: Exception) -> dict[str, Any]:
    """Row result for an unexpected exception (with type + message for UI and logs)."""
    result = _apply_result_row_shell(op)
    result["status"] = "failed"
    result["reason"] = "failed_exception"
    et = type(exc).__name__
    em = _truncate_exc_message(str(exc).strip() or repr(exc))
    result["exception_type"] = et
    result["exception_message"] = em
    result["reason_detail"] = _truncate_exc_message(f"{et}: {em}", max_len=_APPLY_EXCEPTION_MESSAGE_MAX + 64)
    return _finalize_apply_row(op, result)


def _execute_branch_apply_in_branch_transaction(branch_db: str, op: dict[str, Any]) -> dict[str, Any]:
    """
    Run one branch apply with a per-row transaction only when needed.

    ``branch_write_context`` (netbox-branching) often already wraps
    ``transaction.atomic(using=<branch schema alias>)``. Nesting another full ``atomic``
    for every row can break read-your-writes so a ``create_device`` is not visible to the
    next ``create_interface`` / BMC op. When already inside that outer atomic, use an
    explicit **savepoint** so rows still share one branch transaction (visibility) but a
    failing row can roll back without aborting the whole apply batch.
    """
    try:
        conn = connections[branch_db]
    except KeyError:
        with transaction.atomic(using=branch_db):
            return _execute_branch_apply(op)
    if getattr(conn, "in_atomic_block", False):
        sid = transaction.savepoint(using=branch_db)
        try:
            out = _execute_branch_apply(op)
            transaction.savepoint_commit(sid, using=branch_db)
            return out
        except Exception:
            transaction.savepoint_rollback(sid, using=branch_db)
            raise
    with transaction.atomic(using=branch_db):
        return _execute_branch_apply(op)


def _execute_branch_apply(op: dict[str, Any]) -> dict[str, Any]:
    """Run one apply; optional per-row ``atomic(using=…)`` is applied by the caller / helper above."""
    result = _apply_result_row_shell(op)
    action = result["action"]
    if action not in SUPPORTED_APPLY_ACTIONS:
        result["status"] = "failed"
        result["reason"] = "failed_not_implemented"
        return _finalize_apply_row(op, result)
    st, reason, skip_detail = apply_row_operation(op)
    result["status"] = st
    result["reason"] = reason
    if skip_detail:
        result["reason_detail"] = _truncate_exc_message(
            skip_detail, max_len=_APPLY_SKIP_REASON_DETAIL_MAX
        )
    return _finalize_apply_row(op, result)


def _first_failed_exception_snapshot(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """First row that failed with ``failed_exception`` (unexpected error / DB issue)."""
    for r in rows:
        if not isinstance(r, dict):
            continue
        if r.get("status") != "failed" or r.get("reason") != "failed_exception":
            continue
        return {
            "summary": r.get("summary"),
            "selection_key": r.get("selection_key"),
            "action": r.get("action"),
            "exception_type": r.get("exception_type"),
            "exception_message": r.get("exception_message"),
            "reason_detail": r.get("reason_detail"),
        }
    return None

SK_TO_ACTION = {
    "detail_new_devices": "create_device",
    "detail_review_only_devices": "review_device",
    "detail_new_prefixes": "create_prefix",
    "detail_existing_prefixes": "create_prefix",
    "detail_new_ip_ranges": "create_ip_range",
    "detail_new_fips": "create_floating_ip",
    "detail_existing_fips": "create_floating_ip",
    "detail_new_vms": "create_openstack_vm",
    "detail_existing_vms": "update_openstack_vm",
    "detail_new_nics": "create_interface",
    "detail_new_nics_os": "create_interface",
    "detail_new_nics_maas": "create_interface",
    "detail_nic_drift_os": "update_interface",
    "detail_nic_drift_maas": "update_interface",
    "detail_bmc_new_devices": "bmc_documentation",
    "detail_bmc_existing": "bmc_alignment",
    "detail_serial_review": "serial_review",
    "detail_placement_lifecycle_alignment": "placement_alignment",
    "detail_proposed_missing_vlans": "create_vlan",
}

# Reconciliation preview tables, frozen-op sorting, and branch apply all use this tuple (low index runs first).
# New devices + MAAS review hosts first, then proposed missing VLANs (IPAM) so VLANs exist before NICs attach
# untagged/tagged VIDs; then placement, VMs, NICs, OpenStack IPAM/FIP/VM drift, BMC, serial.
AUDIT_REPORT_APPLY_ORDER: tuple[str, ...] = (
    "detail_new_devices",
    "detail_review_only_devices",
    "detail_proposed_missing_vlans",
    "detail_placement_lifecycle_alignment",
    "detail_new_vms",
    "detail_new_nics",
    "detail_new_nics_os",
    "detail_new_nics_maas",
    "detail_nic_drift_os",
    "detail_nic_drift_maas",
    "detail_new_prefixes",
    "detail_existing_prefixes",
    "detail_new_ip_ranges",
    "detail_new_fips",
    "detail_existing_fips",
    "detail_existing_vms",
    "detail_bmc_new_devices",
    "detail_bmc_existing",
    "detail_serial_review",
)

_APPLY_ORDER_RANK: dict[str, int] = {sk: i for i, sk in enumerate(AUDIT_REPORT_APPLY_ORDER)}

# Tie-break when selection_key rank matches or is unknown: device → VLAN → placement → interfaces → IPAM → VMs → BMC → serial.
_ACTION_APPLY_PHASE: dict[str, int] = {
    "create_device": 1,
    "review_device": 1,
    "create_vlan": 2,
    "placement_alignment": 3,
    "create_interface": 4,
    "update_interface": 4,
    "create_prefix": 5,
    "create_ip_range": 5,
    "create_floating_ip": 5,
    "create_openstack_vm": 6,
    "update_openstack_vm": 6,
    "bmc_documentation": 7,
    "bmc_alignment": 7,
    "serial_review": 8,
    "unknown": 99,
}

# Human titles for reconciliation tables (same order as AUDIT_REPORT_APPLY_ORDER).
RECON_SECTION_TITLES: dict[str, str] = {
    "detail_placement_lifecycle_alignment": "Detail — placement & lifecycle alignment",
    "detail_new_devices": "New devices",
    "detail_review_only_devices": "MAAS only hosts",
    "detail_proposed_missing_vlans": "Proposed missing VLANs (IPAM)",
    "detail_new_prefixes": "New prefixes",
    "detail_existing_prefixes": "Existing prefixes",
    "detail_new_ip_ranges": "New IP ranges",
    "detail_new_fips": "New floating IPs",
    "detail_existing_fips": "Existing floating IPs",
    "detail_new_vms": "New VMs",
    "detail_existing_vms": "Existing VMs",
    "detail_new_nics": "New interfaces",
    "detail_new_nics_os": "New interfaces (OS authority)",
    "detail_new_nics_maas": "New interfaces (MAAS authority)",
    "detail_nic_drift_os": "Interface drift (OS authority)",
    "detail_nic_drift_maas": "Interface drift (MAAS authority)",
    "detail_bmc_new_devices": "BMC / mgmt (new devices)",
    "detail_bmc_existing": "BMC / OOB (existing devices)",
    "detail_serial_review": "Serial number review",
}

# When selection_key is missing from SK_TO_ACTION (e.g. stale plugin HTML), infer from row metadata.
_PROP_LIST_KEY_FALLBACK_ACTION: dict[str, str] = {
    "add_nb_interfaces": "create_interface",
    "add_proposed_missing_vlans": "create_vlan",
}


def _frozen_op_action(selection_key: str, meta: dict[str, Any]) -> str:
    sk = str(selection_key or "").strip()
    if sk in SK_TO_ACTION:
        return SK_TO_ACTION[sk]
    pk = meta.get("prop_list_key")
    if isinstance(pk, str) and pk in _PROP_LIST_KEY_FALLBACK_ACTION:
        return _PROP_LIST_KEY_FALLBACK_ACTION[pk]
    return "unknown"


def _canonical_selection_key(sk: str, allowed: frozenset[str]) -> str | None:
    if sk in allowed:
        return sk
    safe = _safe_selection_key(sk)
    for cand in allowed:
        if _safe_selection_key(cand) == safe:
            return cand
    return None


def _selected_keys_in_audit_order(
    selected: dict[str, list[dict[str, Any]]], allowed: frozenset[str]
) -> list[str]:
    tail = len(AUDIT_REPORT_APPLY_ORDER)

    def rank(k: str) -> tuple[int, str]:
        canon = _canonical_selection_key(k, allowed)
        r = _APPLY_ORDER_RANK.get(canon, tail) if canon else tail
        return (r, k)

    return sorted(selected.keys(), key=rank)


def _operation_apply_sort_key(op: dict[str, Any], *, allowed: frozenset[str]) -> tuple[int, int, int, str]:
    msk = str(op.get("selection_key") or "")
    canon = _canonical_selection_key(msk, allowed) or msk
    rank = _APPLY_ORDER_RANK.get(canon, len(AUDIT_REPORT_APPLY_ORDER))
    action = str(op.get("action") or "unknown")
    phase = _ACTION_APPLY_PHASE.get(action, 50)
    ri = op.get("row_index")
    try:
        ri_int = int(ri) if ri is not None and ri != "" else 0
    except (TypeError, ValueError):
        ri_int = 0
    return (rank, phase, ri_int, str(op.get("row_key") or ""))


def _cells_dict(headers: list, row: list) -> dict[str, str]:
    out: dict[str, str] = {}
    for i, h in enumerate(headers):
        key = str(h).strip()
        if not key:
            continue
        val = row[i] if i < len(row) else ""
        out[key] = "" if val is None else str(val).strip()
    return out


def _operation_summary(meta: dict[str, Any]) -> str:
    sk = meta["selection_key"]
    cells = _cells_dict(meta["headers"], meta["row"])
    host = (cells.get("Host") or cells.get("Hostname") or "").strip()
    if sk in ("detail_new_devices", "detail_review_only_devices"):
        return f"Device row: {host or '—'}"
    if sk == "detail_proposed_missing_vlans":
        vid = (cells.get("NB Proposed VLAN ID") or cells.get("Target VID") or "").strip()
        grp = (cells.get("NB proposed VLAN group") or "").strip()
        return f"Create VLAN VID {vid or '—'} in group {grp or '—'}"
    if sk == "detail_new_prefixes":
        cidr = cells.get("CIDR") or "—"
        vrf = cells.get("NB proposed VRF") or "—"
        return f"Prefix: {cidr} (VRF {vrf})"
    if sk == "detail_existing_prefixes":
        cidr = cells.get("CIDR") or "—"
        vrf = cells.get("NB proposed VRF") or "—"
        return f"Prefix update: {cidr} (VRF {vrf})"
    if sk == "detail_new_ip_ranges":
        s = cells.get("Start address") or "—"
        e = cells.get("End address") or "—"
        vrf = cells.get("NB proposed VRF") or "—"
        return f"IP range: {s} - {e} (VRF {vrf})"
    if sk == "detail_new_fips":
        fip = cells.get("Floating IP") or "—"
        return f"Floating IP: {fip}"
    if sk == "detail_existing_fips":
        fip = cells.get("Floating IP") or "—"
        return f"Floating IP (NAT drift): {fip}"
    if sk == "detail_new_vms":
        return f"New VM: {cells.get('VM name') or '—'}"
    if sk == "detail_existing_vms":
        return f"VM update: {cells.get('VM name') or '—'} (id {cells.get('NetBox VM ID') or '—'})"
    if sk in NEW_NIC_SELECTION_KEYS:
        base = f"New interface: {host or '—'}"
        if_name = (cells.get("Suggested NB name") or "").strip()
        if if_name:
            base += f" / {if_name}"
        # Match apply_create_interface + frozen op payload: same merge as
        # ``new_nic_cells_for_reconciliation`` and ``_interface_mac_vlan_ip_from_cells``
        # (raw row MAAS vs OS column order must not contradict Proposed Action / SET_NETBOX_*).
        rcells = new_nic_cells_for_reconciliation(cells)
        mac_res, vid_res, ip_blob = _interface_mac_vlan_ip_from_cells(
            rcells, include_nb_fallback=False
        )
        bits: list[str] = []
        if mac_res:
            bits.append(f"MAC {mac_res}")
        if vid_res is not None:
            bits.append(f"VLAN {vid_res}")
        ip_s = (ip_blob or "").strip()
        if ip_s:
            bits.append(f"IPs {ip_s}")
        props = (
            rcells.get("Proposed Action")
            or cells.get("Proposed Action")
            or cells.get("Proposed action")
            or cells.get("Proposed properties")
            or cells.get("Proposed properties (from MAAS)")
            or ""
        ).strip()
        if bits:
            base += " — " + "; ".join(bits)
        elif props:
            p = props if len(props) <= 160 else props[:157].rstrip() + "…"
            base += " — " + p
        return base
    if sk in ("detail_nic_drift_os", "detail_nic_drift_maas"):
        intf = cells.get("NB intf") or cells.get("MAAS intf") or "—"
        return f"NIC drift: {host or '—'} / {intf}"
    if sk in ("detail_bmc_new_devices", "detail_bmc_existing"):
        return f"BMC: {host or '—'}"
    if sk == "detail_serial_review":
        return f"Serial: {host or cells.get('Hostname') or '—'}"
    if sk == "detail_placement_lifecycle_alignment":
        return f"Placement: {host or '—'}"
    return f"{sk}: {host or '—'}"


def _append_frozen_op_from_meta(
    meta: dict[str, Any],
    ops: list[dict[str, Any]],
    seen: set[str],
) -> bool:
    """Append one frozen op if ``row_key`` not already in ``seen``. Returns whether appended."""
    msk = str(meta["selection_key"])
    safe_meta = _safe_selection_key(msk)
    row_key_final = _selection_row_key(safe_meta, meta["row_index"], list(meta["row"]))
    if row_key_final in seen:
        return False
    seen.add(row_key_final)
    summary = _operation_summary(meta)
    cells = _cells_dict(meta["headers"], meta["row"])
    if msk in NEW_NIC_SELECTION_KEYS:
        cells = new_nic_cells_for_reconciliation(cells)
    op: dict[str, Any] = {
        "row_key": row_key_final,
        "selection_key": msk,
        "prop_list_key": meta.get("prop_list_key"),
        "row_index": meta["row_index"],
        "cells": cells,
        "summary": summary,
        "action": _frozen_op_action(msk, meta),
    }
    if "global_row_index" in meta:
        op["global_row_index"] = meta["global_row_index"]
    ops.append(op)
    return True


def _host_key_from_recon_cells(cells: dict[str, str]) -> str:
    for k in ("Host", "Hostname"):
        v = str(cells.get(k) or "").strip().lower()
        if v:
            return v
    return ""


def _iface_host_keys_from_ops(ops: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for o in ops:
        if str(o.get("action") or "") not in ("create_interface", "update_interface"):
            continue
        raw = o.get("cells")
        if not isinstance(raw, dict):
            continue
        c = {str(k): "" if v is None else str(v).strip() for k, v in raw.items()}
        hk = _host_key_from_recon_cells(c)
        if hk:
            out.add(hk)
    return out


def _device_host_keys_from_ops(ops: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for o in ops:
        if str(o.get("action") or "") not in ("create_device", "review_device"):
            continue
        raw = o.get("cells")
        if not isinstance(raw, dict):
            continue
        c = {str(k): "" if v is None else str(v).strip() for k, v in raw.items()}
        hk = _host_key_from_recon_cells(c)
        if hk:
            out.add(hk)
    return out


def _netbox_existing_device_host_keys_lower(host_keys: set[str]) -> set[str]:
    """
    Subset of *host_keys* (lowercase short names from recon cells) that already exist as
    ``dcim.Device.name`` (case-insensitive). Used so NIC apply does not synthesize
    ``create_device`` for matched inventory that was never selected under New devices.
    """
    lowered = {str(k).strip().lower() for k in host_keys if k and str(k).strip()}
    if not lowered:
        return set()
    try:
        from django.db.models.functions import Lower
        from dcim.models import Device
    except Exception:
        return set()
    return set(
        Device.objects.annotate(_recon_hk=Lower("name"))
        .filter(_recon_hk__in=lowered)
        .values_list("_recon_hk", flat=True)
    )


def _inject_interface_prerequisite_ops(
    ops: list[dict[str, Any]],
    seen: set[str],
    row_index: dict[str, dict[str, Any]],
) -> None:
    """
    If the operator selected any new-interface or NIC-drift row, pull in **every** device,
    proposed missing-VLAN, and (when needed) synthetic ``create_device`` from **placement**
    for hosts that still have no device op. Final order is ``AUDIT_REPORT_APPLY_ORDER``.
    """
    iface_src = NEW_NIC_SELECTION_KEYS | NIC_DRIFT_SELECTION_KEYS
    if not any(str(o.get("selection_key") or "") in iface_src for o in ops):
        return
    sk_pull = frozenset({
        "detail_new_devices",
        "detail_review_only_devices",
        "detail_proposed_missing_vlans",
    })
    for meta in row_index.values():
        if str(meta.get("selection_key") or "") not in sk_pull:
            continue
        _append_frozen_op_from_meta(meta, ops, seen)

    missing_hosts = _iface_host_keys_from_ops(ops) - _device_host_keys_from_ops(ops)
    missing_hosts -= _netbox_existing_device_host_keys_lower(missing_hosts)
    for hk in sorted(missing_hosts):
        for meta in row_index.values():
            if str(meta.get("selection_key") or "") != "detail_placement_lifecycle_alignment":
                continue
            c = _cells_dict(meta["headers"], meta["row"])
            if _host_key_from_recon_cells(c) != hk:
                continue
            synth = synthetic_device_cells_from_placement_for_nic_prereq(c)
            if not synth:
                continue
            ri = meta.get("row_index")
            rk_raw = f"nic-prereq-dev|placement|{hk}|{ri}"
            rk = hashlib.sha1(rk_raw.encode("utf-8", errors="ignore")).hexdigest()[:16]
            if rk in seen:
                break
            seen.add(rk)
            host_disp = (c.get("Host") or c.get("Hostname") or hk or "—").strip()
            ops.append(
                {
                    "row_key": rk,
                    "selection_key": "detail_new_devices",
                    "prop_list_key": None,
                    "row_index": 10**9,
                    "cells": synth,
                    "summary": f"Device create (auto): {host_disp} — NIC prerequisite from placement",
                    "action": "create_device",
                }
            )
            break


def _normalize_selected(raw: Any) -> dict[str, list[dict[str, Any]]]:
    """Section -> list of {row_key, row_index} (from drift HTML); row_key may be stale after edits."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for k, v in raw.items():
        sk = str(k).strip()
        if not sk:
            continue
        items = v if isinstance(v, list) else [v]
        norm_items: list[dict[str, Any]] = []
        for x in items:
            if isinstance(x, dict):
                rk = str(x.get("row_key") or "").strip()
                ri_raw = x.get("row_index")
                ri_int: int | None
                try:
                    ri_int = int(ri_raw) if ri_raw is not None and ri_raw != "" else None
                except (TypeError, ValueError):
                    ri_int = None
                if rk or ri_int is not None:
                    norm_items.append({"row_key": rk, "row_index": ri_int})
            else:
                s = str(x).strip()
                if s:
                    norm_items.append({"row_key": s, "row_index": None})
        if norm_items:
            out[sk] = norm_items
    return out


def build_frozen_operations(
    selected: dict[str, list[dict[str, Any]]],
    row_index: dict[str, dict[str, Any]],
    stable_index: dict[tuple[str, int], dict[str, Any]],
) -> list[dict[str, Any]]:
    allowed = all_registered_selection_keys()
    ops: list[dict[str, Any]] = []
    seen: set[str] = set()

    for sk in selected:
        if sk not in allowed and _safe_selection_key(sk) not in {
            _safe_selection_key(x) for x in allowed
        }:
            raise ValueError(f"Unknown selection section: {sk}")

    for sk in _selected_keys_in_audit_order(selected, allowed):
        canon_sk = _canonical_selection_key(sk, allowed)
        if canon_sk is None:
            raise ValueError(f"Unknown selection section: {sk}")
        safe = _safe_selection_key(canon_sk)
        for item in selected[sk]:
            rk = str(item.get("row_key") or "").strip()
            ri = item.get("row_index")
            try:
                ri_int = int(ri) if ri is not None and ri != "" else None
            except (TypeError, ValueError):
                ri_int = None
            meta = None
            if rk and rk in row_index:
                meta = row_index[rk]
            if meta is None and ri_int is not None:
                meta = stable_index.get((safe, ri_int))
            if not meta:
                detail = rk or f"row_index={ri_int}"
                raise ValueError(f"Unknown row under {sk}: {detail}")
            if _safe_selection_key(str(meta["selection_key"])) != safe:
                raise ValueError(
                    f"Row {detail} belongs to section {meta['selection_key']}, not {sk}"
                )
            _append_frozen_op_from_meta(meta, ops, seen)

    _inject_interface_prerequisite_ops(ops, seen, row_index)
    ops.sort(key=lambda o: _operation_apply_sort_key(o, allowed=allowed))
    return ops


def group_reconciliation_operation_tables(
    operations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Group flat preview ops into tables ordered like the drift audit HTML / apply order.

    Each operation dict should have ``section`` (or ``selection_key``), ``action``, ``summary``, ``cells``.
    """
    by_sk: dict[str, list[dict[str, Any]]] = {}
    for op in operations:
        if not isinstance(op, dict):
            continue
        sk = str(op.get("section") or op.get("selection_key") or "").strip()
        if not sk:
            continue
        by_sk.setdefault(sk, []).append(op)
    tail = len(AUDIT_REPORT_APPLY_ORDER)

    def rank(sk: str) -> tuple[int, str]:
        return (_APPLY_ORDER_RANK.get(sk, tail + 1), sk)

    tables: list[dict[str, Any]] = []
    for sk in sorted(by_sk.keys(), key=rank):
        rows = by_sk[sk]
        display_rows: list[dict[str, Any]] = []
        projections: list[dict[str, str]] = []
        for op in rows:
            if not isinstance(op, dict):
                continue
            o2 = dict(op)
            c = o2.get("cells") if isinstance(o2.get("cells"), dict) else {}
            proj = netbox_write_preview_cells(sk, c)
            projections.append(proj)
            display_rows.append(o2)
        headers = list(netbox_write_preview_table_headers(sk, projections))
        for o2, proj in zip(display_rows, projections):
            o2["cell_values"] = [str(proj.get(h, "")).strip() for h in headers]
        tables.append(
            {
                "section_key": sk,
                "title": RECON_SECTION_TITLES.get(sk, sk),
                "apply_order": _APPLY_ORDER_RANK.get(sk, tail + 1),
                "headers": headers,
                "rows": display_rows,
            }
        )
    return tables


def _row_diffs_vs_baseline(
    frozen: list[dict[str, Any]],
    stable_baseline: dict[tuple[str, int], dict[str, Any]],
) -> list[dict[str, Any]]:
    """Per selected row: NetBox write preview after review vs auto-proposed snapshot (no overrides)."""
    out: list[dict[str, Any]] = []
    for op in frozen:
        msk = str(op.get("selection_key") or "")
        safe_m = _safe_selection_key(msk)
        ri = int(op["row_index"]) if op.get("row_index") is not None else 0
        bmeta = stable_baseline.get((safe_m, ri))
        cells_a = dict(op.get("cells") or {})
        if msk in NEW_NIC_SELECTION_KEYS:
            cells_a = new_nic_cells_for_reconciliation(cells_a)
        proj_a = netbox_write_preview_cells(msk, cells_a)
        fieldnames = list(netbox_write_preview_ordered_fieldnames(msk))
        if not fieldnames:
            fieldnames = sorted(proj_a.keys())
        if not bmeta:
            if any(str(proj_a.get(h, "")).strip() for h in fieldnames):
                out.append(
                    {
                        "summary": op.get("summary"),
                        "section": msk,
                        "action": op.get("action"),
                        "changes": [
                            {"header": h, "before": "", "after": str(proj_a.get(h, "")).strip()}
                            for h in fieldnames
                        ],
                    }
                )
            continue
        cells_b = _cells_dict(bmeta["headers"], bmeta["row"])
        if msk in NEW_NIC_SELECTION_KEYS:
            cells_b = new_nic_cells_for_reconciliation(cells_b)
        proj_b = netbox_write_preview_cells(msk, cells_b)
        _ord = list(netbox_write_preview_ordered_fieldnames(msk))
        _seen = set(_ord)
        for _k in sorted(set(proj_a.keys()) | set(proj_b.keys())):
            if _k not in _seen:
                _ord.append(_k)
                _seen.add(_k)
        fieldnames_cmp = _ord
        changed = [
            h
            for h in fieldnames_cmp
            if str(proj_b.get(h, "")).strip() != str(proj_a.get(h, "")).strip()
        ]
        if changed:
            out.append(
                {
                    "summary": op.get("summary"),
                    "section": msk,
                    "action": op.get("action"),
                    "changes": [
                        {
                            "header": h,
                            "before": str(proj_b.get(h, "")).strip(),
                            "after": str(proj_a.get(h, "")).strip(),
                        }
                        for h in changed
                    ],
                }
            )
    return out


def frozen_operations_for_display(frozen: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Shallow copy of frozen ops with ``cells`` reduced to NetBox-oriented preview fields.

    Rows are ordered like apply (section rank, then action phase, then row index) so the
    reconciliation page matches execution order even for older runs stored out of order.
    """
    allowed = all_registered_selection_keys()
    ordered = sorted(
        [o for o in frozen if isinstance(o, dict)],
        key=lambda op: _operation_apply_sort_key(op, allowed=allowed),
    )
    out: list[dict[str, Any]] = []
    for op in ordered:
        o2 = dict(op)
        o2["cells"] = recon_operation_display_cells(
            str(op.get("selection_key") or ""),
            dict(op.get("cells") or {}),
        )
        out.append(o2)
    return out


def frozen_operations_apply_snapshots(frozen: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    One entry per frozen op (apply order): attributes and values actually passed into
    ``apply_row_operation`` after scoping — for UI comparison with the write-preview tables.
    """
    allowed = all_registered_selection_keys()
    ordered = sorted(
        [o for o in frozen if isinstance(o, dict)],
        key=lambda op: _operation_apply_sort_key(op, allowed=allowed),
    )
    out: list[dict[str, Any]] = []
    for op in ordered:
        sk = str(op.get("selection_key") or "")
        snap = reconciliation_apply_snapshot_cells(sk, dict(op.get("cells") or {}))
        out.append(
            {
                "selection_key": sk,
                "action": op.get("action"),
                "summary": op.get("summary"),
                "row_key": op.get("row_key"),
                "attrs": sorted(snap.items(), key=lambda x: str(x[0]).lower()),
            }
        )
    return out


def group_apply_snapshot_tables(
    snapshots: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Group flat apply-snapshot rows (one dict per frozen op) into section tables like
    ``group_reconciliation_operation_tables``: one row per operation, columns = attribute
    names (union within the section), for compact viewing of large runs.
    """
    by_sk: dict[str, list[dict[str, Any]]] = {}
    for row in snapshots:
        if not isinstance(row, dict):
            continue
        sk = str(row.get("selection_key") or "").strip()
        if not sk:
            continue
        by_sk.setdefault(sk, []).append(row)
    tail = len(AUDIT_REPORT_APPLY_ORDER)

    def rank(sk: str) -> tuple[int, str]:
        return (_APPLY_ORDER_RANK.get(sk, tail + 1), sk)

    tables: list[dict[str, Any]] = []
    for sk in sorted(by_sk.keys(), key=rank):
        group = by_sk[sk]
        projected: list[dict[str, str]] = []
        for r in group:
            cells: dict[str, str] = {}
            for item in r.get("attrs") or []:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    k, v = str(item[0]).strip(), item[1]
                    cells[k] = "" if v is None else str(v).strip()
                elif isinstance(item, (list, tuple)) and len(item) == 1:
                    cells[str(item[0]).strip()] = ""
            projected.append(netbox_write_preview_cells(sk, cells))
        headers = list(netbox_write_preview_ordered_fieldnames(sk))
        _seen_h = set(headers)
        for p in projected:
            for k in p:
                if k not in _seen_h:
                    _seen_h.add(k)
                    headers.append(k)
        display_rows: list[dict[str, Any]] = []
        for r, p in zip(group, projected):
            display_rows.append(
                {
                    "action": r.get("action"),
                    "row_key": r.get("row_key"),
                    "cell_values": [str(p.get(h, "")).strip() for h in headers],
                }
            )
        tables.append(
            {
                "section_key": sk,
                "title": RECON_SECTION_TITLES.get(sk, sk),
                "apply_order": _APPLY_ORDER_RANK.get(sk, tail + 1),
                "headers": headers,
                "rows": display_rows,
            }
        )
    return tables


def operations_digest(frozen_ops: list[dict[str, Any]]) -> str:
    blob = json.dumps(frozen_ops, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def make_preview_token(*, drift_run_id: int, digest: str) -> str:
    return signing.dumps(
        {"drift_run_id": drift_run_id, "digest": digest},
        salt=PREVIEW_TOKEN_SALT,
    )


def verify_preview_token(
    token: str, *, drift_run_id: int, digest: str
) -> tuple[bool, str | None]:
    try:
        raw = signing.loads(token, salt=PREVIEW_TOKEN_SALT, max_age=3600 * 24)
    except signing.SignatureExpired:
        return False, "Preview acknowledgement expired; run Preview again."
    except signing.BadSignature:
        return False, "Invalid preview acknowledgement token."
    if not isinstance(raw, dict):
        return False, "Malformed preview token payload."
    if int(raw.get("drift_run_id", -1)) != int(drift_run_id):
        return False, "Preview token does not match this drift run."
    if str(raw.get("digest", "")) != digest:
        return False, "Preview token does not match current operation set (re-run Preview)."
    return True, None


def propose_branch_name(username: str) -> str:
    safe_user = re.sub(r"[^a-zA-Z0-9._-]+", "", (username or "user").strip())[:24] or "user"
    ts = datetime.now(dt_timezone.utc).strftime("%Y%m%d-%H%M%S")
    short = secrets.token_hex(3)
    return f"sync-{ts}-{safe_user}-{short}"


def propose_unique_branch_name(username: str) -> str | None:
    for _ in range(12):
        name = propose_branch_name(username)
        if not netbox_branch_exists(name=name):
            return name
    return None


def preview_reconciliation(
    *,
    drift_run: MAASOpenStackDriftRun,
    selected_raw: Any,
    posted_review_overrides_raw: Any | None = None,
) -> dict[str, Any]:
    drift_run.refresh_from_db(
        fields=["snapshot_payload", "drift_review_overrides", "drift_review_saved_at"]
    )
    selected = _normalize_selected(selected_raw)
    if not selected:
        raise ValueError("No rows selected. Check at least one Include box in the report.")

    final_norm = effective_review_norm_for_run(drift_run, posted_review_overrides_raw)
    prop_auto, align_auto = merged_proposed_from_drift_run(drift_run, review_norm={})
    prop_f, align_f = merged_proposed_from_drift_run(drift_run, review_norm=final_norm)
    _, stable_auto = build_row_key_index(prop_auto, align_auto)
    row_index_f, stable_f = build_row_key_index(prop_f, align_f)
    frozen = build_frozen_operations(selected, row_index_f, stable_f)
    validate_preview_mandatory_audit_fields(frozen)
    digest = operations_digest(frozen)
    token = make_preview_token(drift_run_id=int(drift_run.pk), digest=digest)
    row_diffs = _row_diffs_vs_baseline(frozen, stable_auto)

    counts: dict[str, int] = {}
    for op in frozen:
        a = op.get("action") or "unknown"
        counts[a] = counts.get(a, 0) + 1

    by_section: dict[str, int] = {}
    for op in frozen:
        sk = op.get("selection_key") or ""
        by_section[sk] = by_section.get(sk, 0) + 1

    unknown_sections = sorted(
        {str(o.get("selection_key") or "") for o in frozen if o.get("action") == "unknown"}
    )
    warnings: list[str] = []
    if unknown_sections:
        warnings.append(
            "No apply handler registered for section(s): "
            + ", ".join(s for s in unknown_sections if s)
            + "."
        )

    # Tables must see raw audit ``cells``; ``netbox_write_preview_cells`` maps those headers.
    # (``recon_operation_display_cells`` is only for the flat operations / payload disclosure.)
    operations_for_tables = [
        {
            "summary": o["summary"],
            "action": o["action"],
            "section": o["selection_key"],
            "selection_key": o["selection_key"],
            "cells": dict(o.get("cells") or {}),
        }
        for o in frozen
    ]
    operations = [
        {
            "summary": op["summary"],
            "action": op["action"],
            "section": op["section"],
            "cells": recon_operation_display_cells(
                str(op.get("selection_key") or op.get("section") or ""),
                dict(op.get("cells") or {}),
            ),
        }
        for op in operations_for_tables
    ]
    operation_tables = group_reconciliation_operation_tables(operations_for_tables)
    apply_snapshot_ops = frozen_operations_apply_snapshots(frozen)
    apply_snapshot_tables = group_apply_snapshot_tables(apply_snapshot_ops)

    return {
        "drift_run_id": drift_run.pk,
        "operation_count": len(frozen),
        "operations_digest": digest,
        "preview_ack_token": token,
        "operations": operations,
        "operation_tables": operation_tables,
        "apply_snapshot_ops": apply_snapshot_ops,
        "apply_snapshot_tables": apply_snapshot_tables,
        "counts_by_action": counts,
        "counts_by_section": by_section,
        "warnings": warnings,
        "row_diffs": row_diffs,
    }


def create_reconciliation_run(
    *,
    drift_run: MAASOpenStackDriftRun,
    selected_raw: Any,
    preview_ack_token: str,
    user,
    posted_review_overrides_raw: Any | None = None,
) -> MAASOpenStackReconciliationRun:
    drift_run.refresh_from_db(
        fields=["snapshot_payload", "drift_review_overrides", "drift_review_saved_at"]
    )
    selected = _normalize_selected(selected_raw)
    if not selected:
        raise ValueError("No rows selected.")

    final_norm = effective_review_norm_for_run(drift_run, posted_review_overrides_raw)
    prop_f, align_f = merged_proposed_from_drift_run(drift_run, review_norm=final_norm)
    row_index_f, stable_f = build_row_key_index(prop_f, align_f)
    frozen = build_frozen_operations(selected, row_index_f, stable_f)
    validate_preview_mandatory_audit_fields(frozen)
    digest = operations_digest(frozen)

    ok, err = verify_preview_token(
        preview_ack_token,
        drift_run_id=int(drift_run.pk),
        digest=digest,
    )
    if not ok:
        raise ValueError(err or "Preview acknowledgement failed.")

    uname = (
        getattr(user, "username", None)
        if user and getattr(user, "is_authenticated", False)
        else "user"
    )
    branch_name = propose_unique_branch_name(uname)
    if not branch_name:
        raise RuntimeError("Could not allocate a unique branch name.")

    with transaction.atomic():
        run = MAASOpenStackReconciliationRun.objects.create(
            drift_run=drift_run,
            status=MAASOpenStackReconciliationRun.STATUS_BRANCH_CREATING,
            created_by=user if getattr(user, "is_authenticated", False) else None,
            frozen_operations=frozen,
            operations_digest=digest,
            selection=selected,
            branch_name="",
        )
        bid, bname, berr = create_netbox_branch(
            name=branch_name,
            description=(
                f"MAAS/OpenStack drift reconciliation from drift run #{drift_run.pk}; "
                f"reconciliation run #{run.pk}."
            ),
        )
        if bid is None:
            run.status = MAASOpenStackReconciliationRun.STATUS_BRANCH_CREATE_FAILED
            run.error_message = berr or "Branch creation failed."
            run.save()
            return run
        run.branch_id = bid
        run.branch_name = bname or branch_name
        run.status = MAASOpenStackReconciliationRun.STATUS_BRANCH_CREATED
        run.save()

    return run


def _apply_result_from_operation(op: dict[str, Any], *, branch_context_ready: bool) -> dict[str, Any]:
    """Apply one row without an inner savepoint (fallback when branch DB alias is unknown)."""
    action = str(op.get("action") or "unknown").strip()
    result = _apply_result_row_shell(op)
    result["status"] = "failed"
    result["reason"] = "failed_not_implemented"
    if not branch_context_ready:
        result["reason"] = "failed_branch_context_unavailable"
        return _finalize_apply_row(op, result)
    if action in SUPPORTED_APPLY_ACTIONS:
        try:
            st, reason, skip_detail = apply_row_operation(op)
        except Exception as exc:
            logger.exception(
                "Reconciliation apply exception (no per-row savepoint): row_key=%s action=%s",
                result.get("row_key"),
                action,
            )
            return _failed_apply_row(op, exc)
        result["status"] = st
        result["reason"] = reason
        if skip_detail:
            result["reason_detail"] = _truncate_exc_message(
                skip_detail, max_len=_APPLY_SKIP_REASON_DETAIL_MAX
            )
        return _finalize_apply_row(op, result)
    return _finalize_apply_row(op, result)


def apply_reconciliation_run(
    *,
    run: MAASOpenStackReconciliationRun,
    actor,
    retry_failed_only: bool = False,
) -> MAASOpenStackReconciliationRun:
    """
    Execute frozen operations with explicit row results and status transitions.

    Operations are sorted by ``AUDIT_REPORT_APPLY_ORDER`` (same as reconciliation preview
    tables): new devices, MAAS review hosts, proposed missing VLANs (IPAM), placement, new VMs,
    new/drift interfaces, OpenStack prefixes/ranges/FIPs, existing VM drift, BMC, serial review.
    Tie-break uses ``_ACTION_APPLY_PHASE`` when needed.

    Apply handlers use full per-row ``cells`` (all audit columns) via
    ``apply_cells.apply_row_operation``; preview projection is
    ``netbox_write_projection.netbox_write_projection_for_op``.
    """
    allowed = {
        MAASOpenStackReconciliationRun.STATUS_BRANCH_CREATED,
        MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED_PARTIAL,
        MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED,
    }
    run.refresh_from_db(
        fields=["status", "frozen_operations", "apply_results", "branch_name", "branch_id"]
    )
    if run.status not in allowed:
        raise ValueError(f"Run status '{run.status}' cannot enter apply.")
    if not run.branch_name and not run.branch_id:
        raise ValueError("Cannot apply: run has no branch identity.")

    prior = run.apply_results if isinstance(run.apply_results, dict) else {}
    prior_rows = prior.get("rows") if isinstance(prior.get("rows"), list) else []
    latest_by_key: dict[str, dict[str, Any]] = {}
    for row in prior_rows:
        if not isinstance(row, dict):
            continue
        rk = str(row.get("row_key") or "").strip()
        if rk:
            latest_by_key[rk] = row

    ops = run.frozen_operations if isinstance(run.frozen_operations, list) else []
    if retry_failed_only:
        target_ops: list[dict[str, Any]] = []
        for op in ops:
            if not isinstance(op, dict):
                continue
            rk = str(op.get("row_key") or "").strip()
            if not rk:
                continue
            prev = latest_by_key.get(rk)
            if prev and str(prev.get("status")) == "failed":
                target_ops.append(op)
    else:
        target_ops = [op for op in ops if isinstance(op, dict)]

    if retry_failed_only and not target_ops:
        raise ValueError("No failed rows available to retry.")

    allowed_sk = all_registered_selection_keys()
    target_ops = sorted(
        target_ops,
        key=lambda o: _operation_apply_sort_key(o, allowed=allowed_sk),
    )

    with transaction.atomic():
        run = (
            MAASOpenStackReconciliationRun.objects.select_for_update()
            .filter(pk=run.pk)
            .first()
        ) or run
        run.status = MAASOpenStackReconciliationRun.STATUS_APPLY_IN_PROGRESS
        run.error_message = ""
        run.save(update_fields=["status", "error_message", "last_updated"])

        branch_obj, branch_err = get_netbox_branch(
            branch_id=run.branch_id,
            branch_name=run.branch_name,
        )
        applied_rows: list[dict[str, Any]] = []
        if branch_obj is not None:
            try:
                branch_db = getattr(branch_obj, "connection_name", None) or None
                with branch_write_context(branch=branch_obj):
                    for op in target_ops:
                        if branch_db:
                            try:
                                applied_rows.append(
                                    _execute_branch_apply_in_branch_transaction(branch_db, op)
                                )
                            except Exception as exc:
                                logger.exception(
                                    "Reconciliation apply row failed: row_key=%s action=%s",
                                    str(op.get("row_key") or ""),
                                    str(op.get("action") or ""),
                                )
                                applied_rows.append(_failed_apply_row(op, exc))
                        else:
                            applied_rows.append(
                                _apply_result_from_operation(op, branch_context_ready=True)
                            )
            except Exception as e:
                et = type(e).__name__
                em = _truncate_exc_message(str(e).strip() or repr(e))
                for op in target_ops:
                    row = _apply_result_from_operation(op, branch_context_ready=False)
                    row["exception_type"] = et
                    row["exception_message"] = em
                    row["reason_detail"] = _truncate_exc_message(
                        f"{et}: {em}", max_len=_APPLY_EXCEPTION_MESSAGE_MAX + 64
                    )
                    applied_rows.append(row)
        else:
            for op in target_ops:
                row = _apply_result_from_operation(op, branch_context_ready=False)
                if branch_err:
                    row["reason_detail"] = branch_err
                applied_rows.append(row)
        merged_rows = []
        seen_retry: set[str] = set()
        if retry_failed_only:
            for new_row in applied_rows:
                rk = str(new_row.get("row_key") or "").strip()
                if rk:
                    seen_retry.add(rk)
            for old in prior_rows:
                rk = str((old or {}).get("row_key") or "").strip()
                if rk and rk in seen_retry:
                    continue
                merged_rows.append(old)
            merged_rows.extend(applied_rows)
        else:
            merged_rows = applied_rows

        failed = sum(1 for r in applied_rows if r.get("status") == "failed")
        skipped = sum(1 for r in applied_rows if r.get("status") == "skipped")
        created = sum(1 for r in applied_rows if r.get("status") == "created")
        updated = sum(1 for r in applied_rows if r.get("status") == "updated")

        if failed == 0:
            final_status = MAASOpenStackReconciliationRun.STATUS_APPLIED
        elif failed == len(applied_rows):
            final_status = MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED
        else:
            final_status = MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED_PARTIAL

        first_fail = _first_failed_exception_snapshot(applied_rows)
        run.apply_results = {
            "attempted_at": timezone.now().isoformat(),
            "attempted_by": getattr(actor, "username", None) or "",
            "retry_failed_only": bool(retry_failed_only),
            "summary": {
                "attempted": len(applied_rows),
                "created": created,
                "updated": updated,
                "skipped": skipped,
                "failed": failed,
                **({"first_failed_exception": first_fail} if first_fail else {}),
            },
            "rows": merged_rows,
        }
        run.status = final_status
        if failed > 0:
            run.error_message = "Apply completed with failures. Review per-row results."
        run.save(update_fields=["apply_results", "status", "error_message", "last_updated"])

    return run


RECONCILIATION_DISCARD_BLOCKED_STATUSES = frozenset(
    {
        MAASOpenStackReconciliationRun.STATUS_DISCARDED,
        MAASOpenStackReconciliationRun.STATUS_MERGED,
        MAASOpenStackReconciliationRun.STATUS_BRANCH_CREATING,
        MAASOpenStackReconciliationRun.STATUS_APPLY_IN_PROGRESS,
        MAASOpenStackReconciliationRun.STATUS_VALIDATION_IN_PROGRESS,
        MAASOpenStackReconciliationRun.STATUS_MERGE_IN_PROGRESS,
    }
)


def discard_reconciliation_run(
    *, run: MAASOpenStackReconciliationRun, actor
) -> MAASOpenStackReconciliationRun:
    """
    Abandon the run: mark discarded and delete the NetBox branch when possible.

    Does not reverse row-level applies already written to the branch schema;
    deleting the branch removes that isolated dataset from NetBox.
    """
    run.refresh_from_db(
        fields=["status", "branch_id", "branch_name", "apply_results", "error_message"]
    )
    if run.status in RECONCILIATION_DISCARD_BLOCKED_STATUSES:
        raise ValueError(f"Run status '{run.status}' cannot be discarded.")

    branch_deleted: bool | None = None
    branch_delete_error: str | None = None

    branch_obj, branch_resolve_err = get_netbox_branch(
        branch_id=run.branch_id,
        branch_name=run.branch_name or "",
    )
    if branch_obj is not None:
        ok, err = delete_netbox_branch_instance(branch_obj)
        branch_deleted = ok
        branch_delete_error = err
    elif run.branch_id or (run.branch_name or "").strip():
        branch_deleted = False
        branch_delete_error = branch_resolve_err or "Branch not found."

    with transaction.atomic():
        run = (
            MAASOpenStackReconciliationRun.objects.select_for_update()
            .filter(pk=run.pk)
            .first()
        ) or run
        if run.status in RECONCILIATION_DISCARD_BLOCKED_STATUSES:
            raise ValueError(f"Run status '{run.status}' cannot be discarded.")

        prior = dict(run.apply_results) if isinstance(run.apply_results, dict) else {}
        prior["discarded_at"] = timezone.now().isoformat()
        prior["discarded_by"] = getattr(actor, "username", None) or ""
        prior["branch_deleted"] = branch_deleted
        prior["branch_delete_error"] = branch_delete_error
        run.apply_results = prior
        run.status = MAASOpenStackReconciliationRun.STATUS_DISCARDED
        if branch_deleted is False and branch_delete_error:
            run.error_message = (
                f"Discarded run; branch could not be deleted automatically: {branch_delete_error}"
            )
        else:
            run.error_message = ""
        run.save(update_fields=["apply_results", "status", "error_message", "last_updated"])

    return run
