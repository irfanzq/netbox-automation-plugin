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

from django.conf import settings
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
    reconciliation_apply_guard,
)
from .apply_cells import (
    NEW_NIC_SELECTION_KEYS,
    SUPPORTED_APPLY_ACTIONS,
    _interface_mac_vlan_ip_from_cells,
    _norm_header,
    apply_row_operation,
    consume_apply_routing_debug_snapshot,
    netbox_write_preview_cells,
    netbox_write_preview_fieldnames,
    netbox_write_preview_ordered_fieldnames,
    new_nic_cells_for_reconciliation,
    recon_operation_display_cells,
    reconciliation_apply_snapshot_cells,
    synthetic_device_cells_from_new_nic_for_prereq,
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


def _warn_if_netbox_branch_router_missing() -> None:
    """
    Reconciliation apply depends on netbox-branching's router + ``activate_branch``.

    If ``BranchAwareRouter`` is not installed, ORM writes can hit NetBox **main** while the UI
    shows an active branch — operators may see new prefixes/VLAN links on main without merging.
    """
    try:
        routers = list(getattr(settings, "DATABASE_ROUTERS", None) or [])
        joined = " ".join(str(r) for r in routers)
        if "netbox_branching.database.BranchAwareRouter" in joined:
            return
        if "BranchAwareRouter" in joined:
            return
        logger.warning(
            "Reconciliation apply: DATABASE_ROUTERS should include "
            "'netbox_branching.database.BranchAwareRouter'. Without DynamicSchemaDict + this "
            "router, ORM saves may write NetBox main even under activate_branch. Also ensure "
            "'netbox_branching' is the **last** PLUGINS entry so branching is registered."
        )
    except Exception:
        return


def _recon_explicit_orm_using(db_alias: str) -> str | None:
    """
    Django ``using=`` for reconciliation ORM only when the alias is not the literal ``default``.

    NetBox Branching often sets ``Branch.connection_name`` to the literal name ``default``.
    Passing that
    to ``.using()`` / ``save(using=)`` can bypass branching routers; return ``None`` to use
    the default manager so ``activate_branch`` routes like NetBox UI/API.
    """
    u = (db_alias or "").strip()
    if not u or u.lower() == "default":
        return None
    return u


def _apply_result_projection_dict(op: dict[str, Any]) -> dict[str, str]:
    """NetBox write projection (resolved FK labels) for one frozen op — same basis as preview tables."""
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
        logger.debug("apply row projection dict failed", exc_info=True)
        return {}
    return _resolve_fk_labels_in_proj(proj, sk)


def _apply_result_write_preview_from_proj(proj: dict[str, str]) -> str:
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


def _apply_result_write_preview(op: dict[str, Any]) -> str:
    """Human-readable NetBox-oriented fields for apply logs (same projection as recon tables)."""
    return _apply_result_write_preview_from_proj(_apply_result_projection_dict(op))


def _field_changes_nonempty_scalar(v: Any) -> bool:
    s = "" if v is None else str(v).strip()
    return bool(s) and s not in ("—", "-")


def _build_field_changes_from_proj_and_snapshot(
    st: str,
    proj: dict[str, str],
    snap: dict[str, str] | None,
) -> list[dict[str, str]]:
    """
    Build the field-changes list shown in the apply results log.

    Only projection fields (what the handler was asked to write) are included —
    never extra snap fields that were not part of the operation.  The snap value
    is used as the authoritative "after" value when available (it is the resolved
    FK label read back from the branch DB after the save).

    For "created": before="", after=snap value (or proj value as fallback).
    For "updated": before="—", after=snap value (or proj value as fallback).
    Both cases show every non-empty projection field so the log always reflects
    exactly what was sent to NetBox.
    """
    snap = snap or {}
    out: list[dict[str, str]] = []
    if st in ("created", "updated"):
        before = "" if st == "created" else "—"
        for k, v in proj.items():
            if not _field_changes_nonempty_scalar(v):
                continue
            # Prefer the snap value (resolved FK label from branch DB); fall back
            # to the raw projection string if the snap doesn't have this key.
            after = str(snap.get(k, v) or "").strip() or str(v).strip()
            if not after:
                continue
            out.append({"header": k, "before": before, "after": after})
        return out
    return []


def _attach_routing_debug_to_apply_result(result: dict[str, Any]) -> None:
    """Merge per-row routing snapshot (populated by :func:`apply_row_operation`) into result."""
    snap = consume_apply_routing_debug_snapshot()
    if not snap:
        return
    result["routing_debug"] = snap
    result["routing_debug_text"] = json.dumps(snap, indent=2, sort_keys=True, default=str)
    logger.debug(
        "reconciliation apply routing row_key=%s action=%s status=%s snapshot=%s",
        result.get("row_key"),
        result.get("action"),
        result.get("status"),
        json.dumps(snap, sort_keys=True, default=str),
    )


def _finalize_apply_row(op: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    proj = _apply_result_projection_dict(op)
    wp = _apply_result_write_preview_from_proj(proj)
    if wp:
        result["write_preview"] = wp
    st = str(result.get("status") or "")
    raw_snap = result.get("field_snapshot")
    if isinstance(raw_snap, dict):
        snap_n = {
            str(k): ("" if v is None else str(v).strip()) for k, v in raw_snap.items()
        }
    else:
        snap_n = None
    if st in ("created", "updated"):
        fc = _build_field_changes_from_proj_and_snapshot(st, proj, snap_n)
        if fc:
            result["field_changes"] = fc
    return result


def _with_apply_sequence(row: dict[str, Any], sequence: int) -> dict[str, Any]:
    """1-based position of this row in the current apply request's ``target_ops`` (execution order)."""
    row["apply_sequence"] = int(sequence)
    return row


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


def _apply_branch_prereq_failed_row(
    op: dict[str, Any], *, reason: str, detail: str
) -> dict[str, Any]:
    """Row result when apply cannot start (e.g. missing branch DB alias)."""
    result = _apply_result_row_shell(op)
    result["status"] = "failed"
    result["reason"] = reason
    result["reason_detail"] = _truncate_exc_message(
        detail, max_len=_APPLY_EXCEPTION_MESSAGE_MAX + 64
    )
    return _finalize_apply_row(op, result)


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


def _load_netbox_model_instance(label: str, pk: int, using: str) -> Any | None:
    from django.apps import apps

    try:
        Model = apps.get_model(label)
    except (LookupError, ValueError, TypeError):
        return None
    try:
        alias = _recon_explicit_orm_using(using)
        qs = Model.objects.using(alias).filter(pk=int(pk)) if alias is not None else Model.objects.filter(pk=int(pk))
        return qs.first()
    except Exception:
        return None


def _interface_assigned_ip_blob(iface: Any, using: str) -> str:
    alias = _recon_explicit_orm_using(using)
    try:
        from django.contrib.contenttypes.models import ContentType
        from ipam.models import IPAddress

        ct = ContentType.objects.get_for_model(iface.__class__)
        base = IPAddress.objects.using(alias) if alias is not None else IPAddress.objects
        qs = base.filter(
            assigned_object_type_id=ct.pk, assigned_object_id=iface.pk
        )
        parts = sorted(str(x.address) for x in qs if getattr(x, "address", None))
        if parts:
            return ", ".join(parts)
    except Exception:
        pass
    try:
        from ipam.models import IPAddress

        base = IPAddress.objects.using(alias) if alias is not None else IPAddress.objects
        qs = base.filter(interface_id=getattr(iface, "pk", None))
        return ", ".join(
            sorted(str(x.address) for x in qs if getattr(x, "address", None))
        )
    except Exception:
        return ""


def _orm_instance_field_snapshot(obj: Any, *, selection_key: str, using: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        opts = obj._meta
        n = 0
        for f in opts.concrete_fields:
            if n >= 48:
                break
            name = f.name
            if name == "id":
                continue
            if f.is_relation:
                if f.many_to_many:
                    continue
                try:
                    robj = getattr(obj, name, None)
                except Exception:
                    continue
                if robj is None:
                    continue
                disp = str(getattr(robj, "name", None) or "").strip()
                if not disp:
                    disp = str(robj).strip()
                if disp:
                    out[name] = disp
                    n += 1
                if name == "untagged_vlan" and robj is not None:
                    vid = getattr(robj, "vid", None)
                    if vid is not None:
                        out["untagged_vlan_vid"] = str(vid)
                continue
            try:
                val = getattr(obj, f.attname)
            except Exception:
                continue
            if val is None or val == "":
                continue
            s = str(val).strip()
            if not s:
                continue
            out[name] = s
            n += 1
        if str(opts.label_lower) == "dcim.interface":
            ips = _interface_assigned_ip_blob(obj, using)
            if ips:
                out["assigned_ips"] = ips
    except Exception:
        return {}
    sk = str(selection_key or "")
    return _resolve_fk_labels_in_proj(out, sk)


def _fetch_written_object_fallback(op: dict[str, Any], using: str) -> Any | None:
    action = str(op.get("action") or "").strip()
    sk = str(op.get("selection_key") or "").strip()
    cells = op.get("cells") if isinstance(op.get("cells"), dict) else {}
    try:
        proj = netbox_write_projection_for_op({"selection_key": sk, "cells": cells})
    except Exception:
        proj = {}
    try:
        alias = _recon_explicit_orm_using(using)

        def _orm(model_cls: Any):
            return model_cls.objects.using(alias) if alias is not None else model_cls.objects

        if action == "create_vlan":
            from ipam.models import VLAN

            vid_s = str(proj.get("vid") or "").strip()
            if not vid_s.isdigit():
                return None
            vid_i = int(vid_s)
            grp = str(proj.get("vlan_group") or "").strip()
            qs = _orm(VLAN).filter(vid=vid_i)
            if grp:
                qs = qs.filter(group__name=grp)
            return qs.first()
        if action in ("create_prefix",):
            from ipam.models import Prefix, VRF

            cidr = str(proj.get("prefix") or "").strip()
            if not cidr:
                return None
            vrf_name = str(proj.get("vrf") or "").strip()
            vrf = None
            if vrf_name:
                vrf = _orm(VRF).filter(name=vrf_name).first()
            qs = _orm(Prefix).filter(prefix=cidr)
            if vrf is not None:
                qs = qs.filter(vrf=vrf)
            elif not vrf_name:
                qs = qs.filter(vrf__isnull=True)
            return qs.first()
        if action in ("create_device", "review_device", "placement_alignment"):
            from dcim.models import Device

            host = str(proj.get("name") or "").strip()
            if host:
                return _orm(Device).filter(name=host).first()
        if action in (
            "create_interface",
            "update_interface",
            "bmc_documentation",
            "bmc_alignment",
        ):
            from dcim.models import Device, Interface

            host = str(proj.get("device") or "").strip()
            if_name = str(proj.get("name") or "").strip()
            if not host or not if_name:
                return None
            dev = _orm(Device).filter(name=host).first()
            if not dev:
                return None
            return _orm(Interface).filter(device=dev, name=if_name).first()
        if action == "update_openstack_vm":
            from virtualization.models import VirtualMachine

            raw_id = str(proj.get("id") or "").strip()
            if raw_id.isdigit():
                return _orm(VirtualMachine).filter(pk=int(raw_id)).first()
    except Exception:
        return None
    return None


def _capture_applied_object_snapshot(
    op: dict[str, Any], result: dict[str, Any], branch_db: str
) -> None:
    try:
        obj: Any | None = None
        wo = result.get("written_object")
        if isinstance(wo, dict) and wo.get("label") and wo.get("pk") is not None:
            obj = _load_netbox_model_instance(str(wo["label"]), int(wo["pk"]), branch_db)
        if obj is None:
            obj = _fetch_written_object_fallback(op, branch_db)
        if obj is None:
            return
        sk = str(op.get("selection_key") or "")
        snap = _orm_instance_field_snapshot(obj, selection_key=sk, using=branch_db)
        if snap:
            result["field_snapshot"] = snap
    except Exception:
        return


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
    txu = _recon_explicit_orm_using(branch_db)
    conn_key = txu if txu is not None else "default"
    try:
        conn = connections[conn_key]
    except KeyError:
        if txu is not None:
            with transaction.atomic(using=txu):
                return _execute_branch_apply(op, branch_db)
        with transaction.atomic():
            return _execute_branch_apply(op, branch_db)
    if getattr(conn, "in_atomic_block", False):
        if txu is not None:
            sid = transaction.savepoint(using=txu)
        else:
            sid = transaction.savepoint()
        try:
            out = _execute_branch_apply(op, branch_db)
            if txu is not None:
                transaction.savepoint_commit(sid, using=txu)
            else:
                transaction.savepoint_commit(sid)
            return out
        except Exception:
            if txu is not None:
                transaction.savepoint_rollback(sid, using=txu)
            else:
                transaction.savepoint_rollback(sid)
            raise
    if txu is not None:
        with transaction.atomic(using=txu):
            return _execute_branch_apply(op, branch_db)
    with transaction.atomic():
        return _execute_branch_apply(op, branch_db)


def _execute_branch_apply(op: dict[str, Any], branch_db: str | None = None) -> dict[str, Any]:
    """Run one apply; optional per-row ``atomic(using=…)`` is applied by the caller / helper above."""
    result = _apply_result_row_shell(op)
    action = result["action"]
    if action not in SUPPORTED_APPLY_ACTIONS:
        result["status"] = "failed"
        result["reason"] = "failed_not_implemented"
        return _finalize_apply_row(op, result)
    # Thread branch_db into the op dict so handlers and ``_ab()`` / savepoints stay aligned.
    # Always copy the op dict; set branch_db whenever the caller passed it (including the
    # literal alias ``default``).
    op = dict(op)
    if branch_db is not None:
        op["branch_db"] = str(branch_db).strip()
    # Accept 3- or 4-tuple from ``apply_row_operation`` (older plugin wheels / mixed deploys).
    _ar = apply_row_operation(op)
    if not isinstance(_ar, tuple) or len(_ar) not in (3, 4):
        result["status"] = "failed"
        result["reason"] = "failed_bad_apply_return"
        _attach_routing_debug_to_apply_result(result)
        return _finalize_apply_row(op, result)
    st, reason, skip_detail = _ar[0], _ar[1], _ar[2]
    written_meta = _ar[3] if len(_ar) == 4 and isinstance(_ar[3], dict) else None
    result["status"] = st
    result["reason"] = reason
    if written_meta:
        result["written_object"] = written_meta
    if skip_detail:
        result["reason_detail"] = _truncate_exc_message(
            skip_detail, max_len=_APPLY_SKIP_REASON_DETAIL_MAX
        )
    if branch_db and st in ("created", "updated"):
        _capture_applied_object_snapshot(op, result, branch_db)
    _attach_routing_debug_to_apply_result(result)
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


# Skipped rows with these reasons are “already aligned / no-op”, not operator attention items.
_APPLY_SUMMARY_BENIGN_SKIP_REASONS: frozenset[str] = frozenset({"skipped_already_desired"})


def _apply_row_comprehensive_sort_key(row: dict[str, Any]) -> tuple[int, str, str]:
    """
    Sort merged apply rows for the UI: outstanding issues first, then successes, benign skips last.
    """
    st = str(row.get("status") or "")
    reason = str(row.get("reason") or "")
    sk = str(row.get("selection_key") or "")
    summ = str(row.get("summary") or "")
    if st == "failed":
        tier = 0
    elif st == "skipped" and reason not in _APPLY_SUMMARY_BENIGN_SKIP_REASONS:
        tier = 1
    elif st == "updated":
        tier = 2
    elif st == "created":
        tier = 3
    elif st == "skipped":
        tier = 4
    else:
        tier = 5
    return (tier, sk, summ)


def _apply_result_rows_for_comprehensive_display(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    usable = [r for r in rows if isinstance(r, dict)]
    return sorted(usable, key=_apply_row_comprehensive_sort_key)


def apply_result_row_needs_attention(row: dict[str, Any] | None) -> bool:
    """Whether a merged apply row still needs operator follow-up (failed or non-benign skip)."""
    if not isinstance(row, dict):
        return False
    st = str(row.get("status") or "")
    if st == "failed":
        return True
    if st != "skipped":
        return False
    return str(row.get("reason") or "") not in _APPLY_SUMMARY_BENIGN_SKIP_REASONS


def _summarize_apply_result_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-status counts over merged ``apply_results[\"rows\"]`` (latest status per frozen row)."""
    n = 0
    failed = skipped = created = updated = other = 0
    skipped_benign = skipped_attention = 0
    for r in rows:
        if not isinstance(r, dict):
            continue
        n += 1
        st = str(r.get("status") or "")
        if st == "failed":
            failed += 1
        elif st == "skipped":
            skipped += 1
            reason = str(r.get("reason") or "")
            if reason in _APPLY_SUMMARY_BENIGN_SKIP_REASONS:
                skipped_benign += 1
            else:
                skipped_attention += 1
        elif st == "created":
            created += 1
        elif st == "updated":
            updated += 1
        else:
            other += 1
    succeeded = created + updated
    out: dict[str, Any] = {
        "rows": n,
        "created": created,
        "updated": updated,
        "succeeded": succeeded,
        "skipped": skipped,
        "skipped_benign": skipped_benign,
        "skipped_needs_attention": skipped_attention,
        "failed": failed,
        "needs_attention": failed + skipped_attention,
    }
    if other:
        out["other_status"] = other
    return out

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
# New devices + MAAS review hosts first, then proposed missing VLANs (IPAM), then new/existing
# prefix rows (VLAN FK), then placement, VMs, NICs, OpenStack IPAM/FIP/VM drift, BMC, serial.
AUDIT_REPORT_APPLY_ORDER: tuple[str, ...] = (
    "detail_new_devices",
    "detail_review_only_devices",
    "detail_proposed_missing_vlans",
    # Prefixes reference IPAM VLANs: run immediately after proposed VLAN creates so the
    # same apply batch resolves VLAN FKs before NIC / VM rows (ordering tie-break is still
    # phase-based; this keeps section order aligned with dependencies).
    "detail_new_prefixes",
    "detail_existing_prefixes",
    "detail_placement_lifecycle_alignment",
    "detail_new_vms",
    "detail_new_nics",
    "detail_new_nics_os",
    "detail_new_nics_maas",
    "detail_nic_drift_os",
    "detail_nic_drift_maas",
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
        site = (cells.get("NB site") or "").strip()
        return f"Create VLAN VID {vid or '—'} in group {grp or '—'} (site {site or '—'})"
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


_PARTIAL_RETRY_DEVICE_PREREQ_ACTIONS: frozenset[str] = frozenset(
    {
        "create_interface",
        "update_interface",
        "bmc_documentation",
        "bmc_alignment",
    }
)


def _expand_partial_retry_ops_with_device_creates(
    seed_ops: list[dict[str, Any]],
    all_ops: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    When re-applying skipped/failed NIC or BMC rows, match freeze-time prerequisites:

    - Pull frozen ``create_device`` and ``review_device`` rows for the same host.
    - If none exist but placement (or NIC ``NB site``) can supply a bootstrap, append a
      synthetic ``create_device`` op (same idea as NIC prerequisite inject at freeze time).
    - If the batch includes ``create_interface`` / ``update_interface``, also pull **every**
      frozen ``create_vlan`` row from this run (``detail_proposed_missing_vlans``), same as
      ``_inject_interface_prerequisite_ops`` on first apply — otherwise partial retry can
      run interfaces before VLAN 2249 exists in IPAM.

    Final sort uses ``AUDIT_REPORT_APPLY_ORDER`` so devices, VLANs, and interfaces run in the
    correct relative order.
    """
    seed_rks = {str(o.get("row_key") or "").strip() for o in seed_ops if isinstance(o, dict)}
    prereq_hosts: set[str] = set()
    host_sample_cells: dict[str, dict[str, str]] = {}
    for o in seed_ops:
        if not isinstance(o, dict):
            continue
        if str(o.get("action") or "") not in _PARTIAL_RETRY_DEVICE_PREREQ_ACTIONS:
            continue
        raw = o.get("cells")
        if not isinstance(raw, dict):
            continue
        c = {str(k): "" if v is None else str(v).strip() for k, v in raw.items()}
        hk = _host_key_from_recon_cells(c)
        if not hk:
            continue
        prereq_hosts.add(hk)
        if hk not in host_sample_cells:
            host_sample_cells[hk] = c
    if not prereq_hosts:
        return seed_ops

    extra_rks: set[str] = set()
    for o in all_ops:
        if not isinstance(o, dict):
            continue
        if str(o.get("action") or "") not in ("create_device", "review_device"):
            continue
        raw = o.get("cells")
        if not isinstance(raw, dict):
            continue
        c = {str(k): "" if v is None else str(v).strip() for k, v in raw.items()}
        hk = _host_key_from_recon_cells(c)
        if hk not in prereq_hosts:
            continue
        rk = str(o.get("row_key") or "").strip()
        if rk and rk not in seed_rks:
            extra_rks.add(rk)

    combined_rks = set(seed_rks) | extra_rks
    out = [
        o
        for o in all_ops
        if isinstance(o, dict) and str(o.get("row_key") or "").strip() in combined_rks
    ]

    def _hosts_covered_by_device_ops(ops: list[dict[str, Any]]) -> set[str]:
        found: set[str] = set()
        for o in ops:
            if not isinstance(o, dict):
                continue
            if str(o.get("action") or "") not in ("create_device", "review_device"):
                continue
            raw = o.get("cells")
            if not isinstance(raw, dict):
                continue
            c = {str(k): "" if v is None else str(v).strip() for k, v in raw.items()}
            hk = _host_key_from_recon_cells(c)
            if hk:
                found.add(hk)
        return found

    covered = _hosts_covered_by_device_ops(out)
    existing_nb = _netbox_existing_device_host_keys_lower(prereq_hosts)
    synth_ops: list[dict[str, Any]] = []
    for hk in sorted(prereq_hosts):
        if hk in covered or hk in existing_nb:
            continue
        synth_cells = None
        for o in all_ops:
            if not isinstance(o, dict):
                continue
            if str(o.get("selection_key") or "") != "detail_placement_lifecycle_alignment":
                continue
            raw = o.get("cells")
            if not isinstance(raw, dict):
                continue
            c = {str(k): "" if v is None else str(v).strip() for k, v in raw.items()}
            if _host_key_from_recon_cells(c) != hk:
                continue
            synth_cells = synthetic_device_cells_from_placement_for_nic_prereq(c)
            if synth_cells:
                break
        if synth_cells is None:
            nic_c = host_sample_cells.get(hk)
            if nic_c:
                host_disp = (nic_c.get("Host") or nic_c.get("Hostname") or hk).strip() or hk
                synth_cells = synthetic_device_cells_from_new_nic_for_prereq(nic_c, host_disp)
        if synth_cells is None:
            continue
        host_disp = (
            (synth_cells.get("Hostname") or synth_cells.get("Host") or hk).strip() or hk
        )
        rk_raw = f"nic-prereq-dev|partial-retry|{hk}|{host_disp}"
        rk = hashlib.sha1(rk_raw.encode("utf-8", errors="ignore")).hexdigest()[:16]
        synth_ops.append(
            {
                "row_key": rk,
                "selection_key": "detail_new_devices",
                "prop_list_key": None,
                "row_index": 10**9,
                "cells": synth_cells,
                "summary": f"Device create (retry prerequisite): {host_disp}",
                "action": "create_device",
            }
        )
        covered.add(hk)

    out.extend(synth_ops)
    if any(
        str(o.get("action") or "") in ("create_interface", "update_interface")
        for o in out
        if isinstance(o, dict)
    ):
        have_rk = {str(o.get("row_key") or "").strip() for o in out if isinstance(o, dict)}
        for o in all_ops:
            if not isinstance(o, dict):
                continue
            if str(o.get("action") or "") != "create_vlan":
                continue
            rk = str(o.get("row_key") or "").strip()
            if rk and rk not in have_rk:
                have_rk.add(rk)
                out.append(o)
    allowed_sk = all_registered_selection_keys()
    out.sort(key=lambda o: _operation_apply_sort_key(o, allowed=allowed_sk))
    return out


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
                raise ValueError(
                    f"Unknown row under {sk}: {detail}. "
                    "That checkbox id is not in the current drift snapshot — common after "
                    "regenerating the audit, changing row order, or updating NetBox so cells "
                    "no longer match. Regenerate the report and select rows again (or clear "
                    "saved reconciliation selection)."
                )
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
            proj = _resolve_fk_labels_in_proj(netbox_write_preview_cells(sk, c), sk)
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


_RE_BARE_INT = re.compile(r"^\d+$")

# Canonical (lowercase) projection **keys** from ``netbox_write_projection_cells`` /
# ``netbox_write_preview_cells`` — *not* drift audit column titles like "NB proposed role".
# Those headers are read by projection into short keys: ``proj.get("role")``, etc.
# (see ``apply_create_prefix`` in ``apply_cells.py`` and ``netbox_write_projection.py``).
_FK_FIELD_RESOLVERS: dict[str, list[tuple[str, str, str]]] = {
    "role": [
        ("ipam.models", "Role", "name"),
        ("dcim.models", "DeviceRole", "name"),
    ],
    "vlan": [
        ("ipam.models", "VLAN", "__vlan__"),
    ],
    "scope": [
        ("dcim.models", "Site", "name"),
        ("dcim.models", "Location", "name"),
        ("dcim.models", "Region", "name"),
    ],
    "tenant": [
        ("tenancy.models", "Tenant", "name"),
    ],
    "vrf": [
        ("ipam.models", "VRF", "name"),
    ],
    "site": [
        ("dcim.models", "Site", "name"),
    ],
    "cluster": [
        ("virtualization.models", "Cluster", "name"),
    ],
    "device": [
        ("dcim.models", "Device", "name"),
    ],
    "platform": [
        ("dcim.models", "Platform", "name"),
    ],
    "device_type": [
        ("dcim.models", "DeviceType", "__device_type__"),
    ],
    "nat_inside": [
        ("ipam.models", "IPAddress", "__ipaddress__"),
    ],
}

# Drift / apply-snapshot column headers (normalized) → same resolver family as *_FK_FIELD_RESOLVERS.
# Omit ``nb proposed vlan`` / ``nb proposed vlan id`` — values are often VIDs, not VLAN pks.
_AUDIT_HEADER_FK_CANON: dict[str, str] = {
    "nb proposed role": "role",
    "nb proposed vrf": "vrf",
    "nb proposed tenant": "tenant",
    "nb proposed scope": "scope",
    "nb current role": "role",
    "nb current vrf": "vrf",
    "nb current tenant": "tenant",
}


def _ci_dict_keys(d: dict[str, str]) -> dict[str, str]:
    return {str(k).strip().lower(): k for k in d if str(k).strip()}


def _apply_scope_gfk_to_dict(out: dict[str, str]) -> None:
    """In-place: resolve ``scope_type`` (ContentType pk) + ``scope_id`` (GFK pk) to labels."""
    km = _ci_dict_keys(out)
    k_sid = km.get("scope_id")
    k_st = km.get("scope_type")
    if not k_sid or not k_st:
        return
    raw_sid = str(out.get(k_sid) or "").strip()
    raw_st = str(out.get(k_st) or "").strip()
    if not _RE_BARE_INT.match(raw_sid) or not _RE_BARE_INT.match(raw_st):
        return
    try:
        from django.contrib.contenttypes.models import ContentType

        ct = ContentType.objects.filter(pk=int(raw_st)).first()
        if ct is None:
            return
        model = ct.model_class()
        out[k_st] = f"{ct.app_label}.{ct.model}"
        if model is None:
            return
        obj = model.objects.filter(pk=int(raw_sid)).first()
        if obj is None:
            return
        name = str(getattr(obj, "name", None) or "").strip()
        out[k_sid] = name or str(obj).strip() or out[k_sid]
    except Exception:
        return


def _fk_resolve_scalar(raw: str, resolvers: list[tuple[str, str, str]]) -> str | None:
    if not raw or not _RE_BARE_INT.match(raw):
        return None
    pk = int(raw)
    for mod_path, model_name, label_attr in resolvers:
        try:
            mod = __import__(mod_path, fromlist=[model_name])
            Model = getattr(mod, model_name, None)
            if Model is None:
                continue
            obj = Model.objects.filter(pk=pk).first()
            if obj is None:
                continue
            if label_attr == "__vlan__":
                vid = getattr(obj, "vid", None)
                name = getattr(obj, "name", None) or ""
                resolved = f"{vid} ({name})" if vid is not None else name
            elif label_attr == "__device_type__":
                man = getattr(obj, "manufacturer", None)
                mname = str(getattr(man, "name", None) or "").strip()
                model = str(getattr(obj, "model", None) or "").strip()
                resolved = f"{mname} {model}".strip() or str(obj).strip()
            elif label_attr == "__ipaddress__":
                addr = getattr(obj, "address", None)
                resolved = (str(addr).strip() if addr else "") or str(obj).strip()
            else:
                resolved = str(getattr(obj, label_attr, "") or "").strip()
            if resolved:
                return resolved
        except Exception:
            continue
    return None


def _resolve_fk_labels_in_proj(proj: dict[str, str], selection_key: str = "") -> dict[str, str]:
    """Copy of *proj* with bare-integer FK IDs replaced by human-readable labels."""
    out = dict(proj)
    sk = str(selection_key or "").strip()
    _apply_scope_gfk_to_dict(out)

    for field_key in list(out.keys()):
        lk = str(field_key).strip().lower()
        if lk in ("scope_id", "scope_type"):
            continue
        resolvers = _FK_FIELD_RESOLVERS.get(lk)
        if not resolvers:
            continue
        raw = str(out.get(field_key) or "").strip()
        resolved = _fk_resolve_scalar(raw, resolvers)
        if resolved:
            out[field_key] = resolved

    if sk == "detail_existing_vms":
        km = _ci_dict_keys(out)
        id_km = km.get("id")
        if id_km:
            raw_id = str(out.get(id_km) or "").strip()
            vm_res = [("virtualization.models", "VirtualMachine", "name")]
            got = _fk_resolve_scalar(raw_id, vm_res)
            if got:
                out[id_km] = got

    return out


def _resolve_fk_labels_in_audit_snap(snap: dict[str, str]) -> dict[str, str]:
    """Resolve numeric FKs in apply-snapshot dict keys (audit column titles)."""
    out = dict(snap)
    _apply_scope_gfk_to_dict(out)
    for k in list(out.keys()):
        canon = _AUDIT_HEADER_FK_CANON.get(_norm_header(k))
        if not canon:
            continue
        resolvers = _FK_FIELD_RESOLVERS.get(canon)
        if not resolvers:
            continue
        raw = str(out.get(k) or "").strip()
        resolved = _fk_resolve_scalar(raw, resolvers)
        if resolved:
            out[k] = resolved
    return out


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
        proj_a = _resolve_fk_labels_in_proj(netbox_write_preview_cells(msk, cells_a), msk)
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
        proj_b = _resolve_fk_labels_in_proj(netbox_write_preview_cells(msk, cells_b), msk)
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
        snap = _resolve_fk_labels_in_audit_snap(
            reconciliation_apply_snapshot_cells(sk, dict(op.get("cells") or {}))
        )
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
            projected.append(_resolve_fk_labels_in_proj(netbox_write_preview_cells(sk, cells), sk))
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
    """Row shell when apply cannot run (no branch / branch activation failed). Never calls ORM apply."""
    _ = branch_context_ready
    result = _apply_result_row_shell(op)
    result["status"] = "failed"
    result["reason"] = "failed_branch_context_unavailable"
    return _finalize_apply_row(op, result)


def apply_reconciliation_run(
    *,
    run: MAASOpenStackReconciliationRun,
    actor,
    retry_failed_only: bool = False,
    retry_skipped_only: bool = False,
) -> MAASOpenStackReconciliationRun:
    """
    Execute frozen operations with explicit row results and status transitions.

    The NetBox branch is always the one stored on this run (``run.branch_id`` /
    ``run.branch_name``): the UI “Apply selected changes to branch” button does not
    use NetBox’s global branch picker; it resolves ``Branch`` via
    :func:`get_netbox_branch` and opens :func:`branch_write_context` for that instance.

    If prefixes or VLANs show up on **main** without merging the branch, that is **not**
    expected from this plugin’s intent: verify NetBox has ``DynamicSchemaDict``,
    ``DATABASE_ROUTERS`` includes ``BranchAwareRouter``, and ``netbox_branching`` is **last**
    in ``PLUGINS`` (per netbox-branching docs). A warning is logged at apply time if the
    router is missing.

    Operations are sorted by ``AUDIT_REPORT_APPLY_ORDER`` (same as reconciliation preview
    tables): new devices, MAAS review hosts, proposed missing VLANs (IPAM), placement, new VMs,
    new/drift interfaces, OpenStack prefixes/ranges/FIPs, existing VM drift, BMC, serial review.
    Tie-break uses ``_ACTION_APPLY_PHASE`` when needed.

    Apply handlers use full per-row ``cells`` (all audit columns) via
    ``apply_cells.apply_row_operation``; preview projection is
    ``netbox_write_projection.netbox_write_projection_for_op``.

    Partial retries (``retry_failed_only`` / ``retry_skipped_only``) re-run only rows whose
    latest result status matches; results are merged into prior row history. Interface retries
    automatically pull in matching frozen ``create_device`` rows for the same host when present.
    """
    partial_retry = bool(retry_failed_only or retry_skipped_only)
    run.refresh_from_db(
        fields=["status", "frozen_operations", "apply_results", "branch_name", "branch_id"]
    )
    if partial_retry:
        allowed = {
            MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED_PARTIAL,
            MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED,
            MAASOpenStackReconciliationRun.STATUS_APPLIED,
        }
    else:
        allowed = {
            MAASOpenStackReconciliationRun.STATUS_BRANCH_CREATED,
            MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED_PARTIAL,
            MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED,
        }
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
    if partial_retry:
        want_failed = bool(retry_failed_only)
        want_skipped = bool(retry_skipped_only)
        target_ops = []
        for op in ops:
            if not isinstance(op, dict):
                continue
            rk = str(op.get("row_key") or "").strip()
            if not rk:
                continue
            prev = latest_by_key.get(rk)
            if not prev:
                continue
            st = str(prev.get("status") or "")
            if want_failed and st == "failed":
                target_ops.append(op)
            elif want_skipped and st == "skipped" and apply_result_row_needs_attention(prev):
                target_ops.append(op)
        target_ops = _expand_partial_retry_ops_with_device_creates(target_ops, ops)
    else:
        target_ops = [op for op in ops if isinstance(op, dict)]

    if partial_retry and not target_ops:
        if retry_failed_only and retry_skipped_only:
            msg = "No failed or skipped rows available to retry."
        elif retry_skipped_only:
            msg = "No skipped rows available to retry."
        else:
            msg = "No failed rows available to retry."
        raise ValueError(msg)

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
        run_routing_core: dict[str, Any] | None = None
        if branch_obj is not None:
            run_routing_core = {
                "reconciliation_run_branch_id": run.branch_id,
                "reconciliation_run_branch_name": (run.branch_name or "").strip(),
                "netbox_branch_model_pk": getattr(branch_obj, "pk", None),
                "netbox_branch_connection_name": str(
                    getattr(branch_obj, "connection_name", None) or ""
                ).strip(),
            }
            branch_db = str(getattr(branch_obj, "connection_name", None) or "").strip()
            if not branch_db:
                bd_msg = (
                    "Branch has no connection_name (database alias). Reconciliation apply "
                    "requires a branch-scoped DB connection so writes do not hit NetBox main. "
                    "Wait until the branch is ready / provisioned, then retry."
                )
                for seq_num, op in enumerate(target_ops, start=1):
                    applied_rows.append(
                        _with_apply_sequence(
                            _apply_branch_prereq_failed_row(
                                op,
                                reason="failed_branch_connection_alias",
                                detail=bd_msg,
                            ),
                            seq_num,
                        )
                    )
            else:
                try:
                    _warn_if_netbox_branch_router_missing()
                    with branch_write_context(branch=branch_obj):
                        with reconciliation_apply_guard(branch_obj, branch_db):
                            for seq_num, op in enumerate(target_ops, start=1):
                                try:
                                    applied_rows.append(
                                        _with_apply_sequence(
                                            _execute_branch_apply_in_branch_transaction(
                                                branch_db, op
                                            ),
                                            seq_num,
                                        )
                                    )
                                except Exception as exc:
                                    logger.exception(
                                        "Reconciliation apply row failed: row_key=%s action=%s",
                                        str(op.get("row_key") or ""),
                                        str(op.get("action") or ""),
                                    )
                                    applied_rows.append(
                                        _with_apply_sequence(_failed_apply_row(op, exc), seq_num)
                                    )
                except Exception as e:
                    et = type(e).__name__
                    em = _truncate_exc_message(str(e).strip() or repr(e))
                    for seq_num, op in enumerate(target_ops, start=1):
                        row = _apply_result_from_operation(op, branch_context_ready=False)
                        row["exception_type"] = et
                        row["exception_message"] = em
                        row["reason_detail"] = _truncate_exc_message(
                            f"{et}: {em}", max_len=_APPLY_EXCEPTION_MESSAGE_MAX + 64
                        )
                        applied_rows.append(_with_apply_sequence(row, seq_num))
        else:
            for seq_num, op in enumerate(target_ops, start=1):
                row = _apply_result_from_operation(op, branch_context_ready=False)
                if branch_err:
                    row["reason_detail"] = branch_err
                applied_rows.append(_with_apply_sequence(row, seq_num))
        merged_rows = []
        seen_retry: set[str] = set()
        if partial_retry:
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
        batch_summary = {
            "attempted": len(applied_rows),
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "failed": failed,
            **({"first_failed_exception": first_fail} if first_fail else {}),
        }
        apply_payload: dict[str, Any] = {
            "attempted_at": timezone.now().isoformat(),
            "attempted_by": getattr(actor, "username", None) or "",
            "retry_failed_only": bool(retry_failed_only),
            "retry_skipped_only": bool(retry_skipped_only),
            "summary": batch_summary,
            "cumulative_summary": _summarize_apply_result_rows(merged_rows),
            "rows": merged_rows,
            "display_rows": _apply_result_rows_for_comprehensive_display(merged_rows),
        }
        if run_routing_core is not None:
            apply_payload["run_routing_context"] = run_routing_core
            apply_payload["run_routing_context_text"] = json.dumps(
                run_routing_core, indent=2, sort_keys=True, default=str
            )
        # Partial re-apply: optional ``last_attempt_rows`` for a "this click only" drill-down.
        if partial_retry:
            apply_payload["last_attempt_rows"] = applied_rows
        run.apply_results = apply_payload
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
