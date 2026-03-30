"""Preview, signed acknowledgement, and frozen operations for branch reconciliation."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
from datetime import datetime, timezone as dt_timezone
from typing import Any

from django.core import signing
from django.db import transaction
from django.utils import timezone

from netbox_automation_plugin.models import MAASOpenStackReconciliationRun
from netbox_automation_plugin.sync.reporting.drift_report.render_tables import (
    _selection_row_key,
)

from .history_models import MAASOpenStackDriftRun
from .reconciliation_branch import (
    branch_write_context,
    create_netbox_branch,
    delete_netbox_branch_instance,
    get_netbox_branch,
    netbox_branch_exists,
)
from .reconciliation_merge import (
    _safe_selection_key,
    all_registered_selection_keys,
    build_row_key_index,
    effective_review_norm_for_run,
    merged_proposed_from_drift_run,
)

PREVIEW_TOKEN_SALT = "netbox_automation_plugin.ma_openstack_recon.preview.v1"

SK_TO_ACTION = {
    "detail_new_devices": "create_device",
    "detail_review_only_devices": "review_device",
    "detail_new_prefixes": "create_prefix",
    "detail_new_fips": "create_floating_ip",
    "detail_new_nics": "create_interface",
    "detail_nic_drift_os": "update_interface",
    "detail_nic_drift_maas": "update_interface",
    "detail_bmc_new_devices": "bmc_documentation",
    "detail_bmc_existing": "bmc_alignment",
    "detail_serial_review": "serial_review",
    "detail_placement_lifecycle_alignment": "placement_alignment",
}

SUPPORTED_APPLY_ACTIONS = {"create_prefix", "create_floating_ip", "create_device"}


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
    if sk == "detail_new_prefixes":
        cidr = cells.get("CIDR") or "—"
        vrf = cells.get("NB proposed VRF") or "—"
        return f"Prefix: {cidr} (VRF {vrf})"
    if sk == "detail_new_fips":
        fip = cells.get("Floating IP") or "—"
        return f"Floating IP: {fip}"
    if sk == "detail_new_nics":
        return f"New interface: {host or '—'}"
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

    for sk in sorted(selected.keys()):
        canon_sk = sk if sk in allowed else None
        if canon_sk is None:
            for cand in allowed:
                if _safe_selection_key(cand) == sk:
                    canon_sk = cand
                    break
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
            msk = str(meta["selection_key"])
            safe_meta = _safe_selection_key(msk)
            row_key_final = _selection_row_key(safe_meta, meta["row_index"], list(meta["row"]))
            if row_key_final in seen:
                continue
            seen.add(row_key_final)
            cells = _cells_dict(meta["headers"], meta["row"])
            op: dict[str, Any] = {
                "row_key": row_key_final,
                "selection_key": msk,
                "prop_list_key": meta.get("prop_list_key"),
                "row_index": meta["row_index"],
                "cells": cells,
                "summary": _operation_summary(meta),
                "action": SK_TO_ACTION.get(msk, "unknown"),
            }
            if "global_row_index" in meta:
                op["global_row_index"] = meta["global_row_index"]
            ops.append(op)

    ops.sort(key=lambda o: (o["selection_key"], o["row_index"], o["row_key"]))
    return ops


def _row_diffs_vs_baseline(
    frozen: list[dict[str, Any]],
    stable_baseline: dict[tuple[str, int], dict[str, Any]],
) -> list[dict[str, Any]]:
    """Per selected row: cells after review vs auto-proposed snapshot (no overrides)."""
    out: list[dict[str, Any]] = []
    for op in frozen:
        msk = str(op.get("selection_key") or "")
        safe_m = _safe_selection_key(msk)
        ri = int(op["row_index"]) if op.get("row_index") is not None else 0
        bmeta = stable_baseline.get((safe_m, ri))
        cells_a = dict(op.get("cells") or {})
        if not bmeta:
            headers = list(cells_a.keys())
            if headers:
                out.append(
                    {
                        "summary": op.get("summary"),
                        "section": msk,
                        "action": op.get("action"),
                        "changes": [
                            {"header": h, "before": "", "after": cells_a.get(h, "")}
                            for h in headers
                        ],
                    }
                )
            continue
        cells_b = _cells_dict(bmeta["headers"], bmeta["row"])
        keys = sorted(set(bmeta["headers"]) | set(cells_a.keys()))
        changed = [h for h in keys if cells_b.get(h, "") != cells_a.get(h, "")]
        if changed:
            out.append(
                {
                    "summary": op.get("summary"),
                    "section": msk,
                    "action": op.get("action"),
                    "changes": [
                        {
                            "header": h,
                            "before": cells_b.get(h, ""),
                            "after": cells_a.get(h, ""),
                        }
                        for h in changed
                    ],
                }
            )
    return out


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

    warnings: list[str] = []
    for op in frozen:
        if op.get("action") == "unknown":
            warnings.append(f"Unhandled action type for section {op.get('selection_key')}.")

    return {
        "drift_run_id": drift_run.pk,
        "operation_count": len(frozen),
        "operations_digest": digest,
        "preview_ack_token": token,
        "operations": [
            {"summary": o["summary"], "action": o["action"], "section": o["selection_key"]}
            for o in frozen
        ],
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


def _pick_choice_value(field, raw: str) -> Any:
    s = str(raw or "").strip()
    if not s:
        return None
    try:
        choices = list(getattr(field, "choices", []) or [])
    except Exception:
        return None
    sl = s.lower()
    for val, label in choices:
        if str(val).lower() == sl or str(label).strip().lower() == sl:
            return val
    return None


def _resolve_by_name(model, name: str):
    s = str(name or "").strip()
    if not s:
        return None
    for lookup in ("name", "slug", "model"):
        try:
            obj = model.objects.filter(**{lookup: s}).first()
        except Exception:
            obj = None
        if obj is not None:
            return obj
    for lookup in ("name__iexact", "slug__iexact", "model__iexact"):
        try:
            obj = model.objects.filter(**{lookup: s}).first()
        except Exception:
            obj = None
        if obj is not None:
            return obj
    return None


def _normalize_ip_for_netbox(raw_ip: str) -> str:
    s = str(raw_ip or "").strip()
    if not s:
        raise ValueError("empty address")
    if "/" in s:
        ipaddress.ip_interface(s)
        return s
    ip_obj = ipaddress.ip_address(s)
    return f"{s}/32" if ip_obj.version == 4 else f"{s}/128"


def _apply_create_prefix(op: dict[str, Any]) -> tuple[str, str]:
    from ipam.models import Prefix, VRF

    cells = op.get("cells") or {}
    cidr = str(cells.get("CIDR") or "").strip()
    vrf_name = str(cells.get("NB proposed VRF") or "").strip()
    status_name = str(cells.get("NB proposed status") or "").strip()
    if not cidr:
        return "skipped", "skipped_prerequisite_missing"
    vrf = _resolve_by_name(VRF, vrf_name) if vrf_name else None
    if vrf_name and vrf is None:
        return "skipped", "skipped_prerequisite_missing"
    existing = Prefix.objects.filter(prefix=cidr, vrf=vrf).first()
    if existing is not None:
        changed = False
        if status_name:
            val = _pick_choice_value(existing._meta.get_field("status"), status_name)
            if val is not None and existing.status != val:
                existing.status = val
                changed = True
        if changed:
            existing.save()
            return "updated", "ok_updated"
        return "skipped", "skipped_already_desired"
    obj = Prefix(prefix=cidr, vrf=vrf)
    if status_name:
        val = _pick_choice_value(obj._meta.get_field("status"), status_name)
        if val is not None:
            obj.status = val
    obj.save()
    return "created", "ok_created"


def _apply_create_floating_ip(op: dict[str, Any]) -> tuple[str, str]:
    from ipam.models import IPAddress, VRF

    cells = op.get("cells") or {}
    raw_ip = str(cells.get("Floating IP") or "").strip()
    status_name = str(cells.get("NB proposed status") or "").strip()
    vrf_name = str(cells.get("NB proposed VRF") or "").strip()
    if not raw_ip:
        return "skipped", "skipped_prerequisite_missing"
    try:
        address = _normalize_ip_for_netbox(raw_ip)
    except ValueError:
        return "failed", "failed_validation_bad_ip"
    vrf = _resolve_by_name(VRF, vrf_name) if vrf_name else None
    if vrf_name and vrf is None:
        return "skipped", "skipped_prerequisite_missing"
    existing = IPAddress.objects.filter(address=address, vrf=vrf).first()
    if existing is not None:
        changed = False
        if status_name:
            val = _pick_choice_value(existing._meta.get_field("status"), status_name)
            if val is not None and existing.status != val:
                existing.status = val
                changed = True
        if changed:
            existing.save()
            return "updated", "ok_updated"
        return "skipped", "skipped_already_desired"
    ip_obj = IPAddress(address=address, vrf=vrf)
    if status_name:
        val = _pick_choice_value(ip_obj._meta.get_field("status"), status_name)
        if val is not None:
            ip_obj.status = val
    ip_obj.save()
    return "created", "ok_created"


def _apply_create_device(op: dict[str, Any]) -> tuple[str, str]:
    from dcim.models import Device, DeviceRole, DeviceType, Location, Site

    cells = op.get("cells") or {}
    hostname = str(cells.get("Hostname") or "").strip()
    site_name = str(cells.get("NB proposed site") or "").strip()
    location_name = str(cells.get("NB proposed location") or "").strip()
    role_name = str(cells.get("NB proposed role") or "").strip()
    dtype_name = str(cells.get("NB proposed device type") or "").strip()
    status_name = str(cells.get("NB proposed device status") or "").strip()
    if not hostname or not site_name or not role_name or not dtype_name:
        return "skipped", "skipped_prerequisite_missing"
    site = _resolve_by_name(Site, site_name)
    role = _resolve_by_name(DeviceRole, role_name)
    dtype = _resolve_by_name(DeviceType, dtype_name)
    if site is None or role is None or dtype is None:
        return "skipped", "skipped_prerequisite_missing"
    location = None
    if location_name:
        location = _resolve_by_name(Location, location_name)
        if location is None:
            return "skipped", "skipped_prerequisite_missing"
    existing = Device.objects.filter(name=hostname).first()
    if existing is not None:
        changed = False
        for field_name, target in (
            ("site", site),
            ("location", location),
            ("role", role),
            ("device_type", dtype),
        ):
            if target is not None and getattr(existing, f"{field_name}_id", None) != target.pk:
                setattr(existing, field_name, target)
                changed = True
        if status_name:
            val = _pick_choice_value(existing._meta.get_field("status"), status_name)
            if val is not None and existing.status != val:
                existing.status = val
                changed = True
        if changed:
            existing.save()
            return "updated", "ok_updated"
        return "skipped", "skipped_already_desired"
    dev = Device(
        name=hostname,
        site=site,
        location=location,
        role=role,
        device_type=dtype,
    )
    if status_name:
        val = _pick_choice_value(dev._meta.get_field("status"), status_name)
        if val is not None:
            dev.status = val
    dev.save()
    return "created", "ok_created"


def _apply_known_operation(op: dict[str, Any]) -> tuple[str, str]:
    action = str(op.get("action") or "").strip()
    if action == "create_prefix":
        return _apply_create_prefix(op)
    if action == "create_floating_ip":
        return _apply_create_floating_ip(op)
    if action == "create_device":
        return _apply_create_device(op)
    return "failed", "failed_not_implemented"


def _apply_result_from_operation(op: dict[str, Any], *, branch_context_ready: bool) -> dict[str, Any]:
    action = str(op.get("action") or "unknown").strip()
    row_key = str(op.get("row_key") or "").strip()
    result = {
        "row_key": row_key,
        "idempotency_key": row_key,
        "selection_key": str(op.get("selection_key") or ""),
        "action": action,
        "summary": str(op.get("summary") or ""),
        "status": "failed",
        "reason": "failed_not_implemented",
        "applied_at": timezone.now().isoformat(),
    }
    if not branch_context_ready:
        result["status"] = "failed"
        result["reason"] = "failed_branch_context_unavailable"
        return result
    if action in SUPPORTED_APPLY_ACTIONS:
        try:
            st, reason = _apply_known_operation(op)
        except Exception:
            result["status"] = "failed"
            result["reason"] = "failed_exception"
            return result
        result["status"] = st
        result["reason"] = reason
        return result
    if action == "review_device":
        result["status"] = "skipped"
        result["reason"] = "skipped_already_desired"
        return result
    return result


def apply_reconciliation_run(
    *,
    run: MAASOpenStackReconciliationRun,
    actor,
    retry_failed_only: bool = False,
) -> MAASOpenStackReconciliationRun:
    """
    Execute frozen operations with explicit row results and status transitions.

    Current phase:
    - lifecycle and result semantics are enforced
    - operation handlers are scaffolded (writes are still not implemented)
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
                with branch_write_context(branch=branch_obj):
                    for op in target_ops:
                        applied_rows.append(
                            _apply_result_from_operation(op, branch_context_ready=True)
                        )
            except Exception as e:
                for op in target_ops:
                    row = _apply_result_from_operation(op, branch_context_ready=False)
                    row["reason_detail"] = str(e)
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
