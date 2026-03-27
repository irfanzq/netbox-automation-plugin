from __future__ import annotations

import json
from typing import Any

from .history_models import MAASOpenStackDriftRun


def _safe_json_dict(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    return _json_safe(value)


def _json_safe(value: Any):
    """
    Convert nested structures to JSON-safe primitives.
    Falls back to string conversion for unsupported objects.
    """
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return {}


def create_drift_run_snapshot(
    *,
    request,
    report_drift: str,
    report_drift_markup: str,
    report_reference: str,
    audit_summary: dict | None,
    scope_filters: dict | None,
    cache_key: str,
    payload: dict,
) -> MAASOpenStackDriftRun:
    """
    Persist a full drift run so users can reopen exact report output later.
    """
    return MAASOpenStackDriftRun.objects.create(
        status=MAASOpenStackDriftRun.STATUS_COMPLETED,
        created_by=getattr(request, "user", None),
        report_drift=report_drift or "",
        report_drift_markup=(report_drift_markup or "html")[:16],
        report_reference=report_reference or "",
        audit_summary=_safe_json_dict(audit_summary),
        scope_filters=_safe_json_dict(scope_filters),
        source_cache_key=(cache_key or "")[:200],
        snapshot_payload=_safe_json_dict(payload),
    )
