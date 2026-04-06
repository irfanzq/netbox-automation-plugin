#!/usr/bin/env python3
"""
Dry-run validator for MAAS/OpenStack reconciliation operations.

Purpose:
- Execute frozen reconciliation operations through real apply handlers
  without persisting any DB writes (transaction rollback).
- Report would-create / would-update / would-skip / would-fail counts.
- Surface skipped/failure reasons and unknown/extra cell columns.

Usage examples:
  python scripts/validate_reconciliation_values.py --run-id 42
  python scripts/validate_reconciliation_values.py --run-id 42 --verbose
  python scripts/validate_reconciliation_values.py --run-id 42 --json

Notes:
- This script does NOT modify NetBox data.
- Best run from inside NetBox runtime (where Django settings are available).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from typing import Any


def _setup_django() -> None:
    if os.environ.get("DJANGO_SETTINGS_MODULE"):
        pass
    else:
        # Common default for NetBox runtime.
        os.environ["DJANGO_SETTINGS_MODULE"] = "netbox.settings"
    import django

    django.setup()


def _normalize_cell_map(cells: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (cells or {}).items():
        key = str(k or "").strip()
        if not key:
            continue
        out[key] = "" if v is None else str(v).strip()
    return out


def _validate_run(run_id: int, *, verbose: bool = False) -> dict[str, Any]:
    from django.db import transaction

    from netbox_automation_plugin.models import MAASOpenStackReconciliationRun
    from netbox_automation_plugin.sync.reporting.drift_report.drift_overrides_apply import (
        SELECTION_KEY_TO_HEADERS,
    )
    from netbox_automation_plugin.sync.reconciliation.apply_cells import (
        SUPPORTED_APPLY_ACTIONS,
        apply_row_operation,
    )
    from netbox_automation_plugin.sync.reconciliation.service import (
        SK_TO_ACTION,
    )

    run = MAASOpenStackReconciliationRun.objects.filter(pk=run_id).first()
    if run is None:
        raise SystemExit(f"Reconciliation run not found: {run_id}")

    frozen = run.frozen_operations if isinstance(run.frozen_operations, list) else []
    result_rows: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    extras_counter: Counter[str] = Counter()
    mismatched_action_count = 0
    unknown_selection_count = 0
    unsupported_action_count = 0

    for idx, op in enumerate(frozen):
        if not isinstance(op, dict):
            status_counts["invalid_op"] += 1
            result_rows.append(
                {
                    "index": idx,
                    "status": "invalid_op",
                    "reason": "operation_not_dict",
                }
            )
            continue

        selection_key = str(op.get("selection_key") or "").strip()
        action = str(op.get("action") or "").strip()
        summary = str(op.get("summary") or "").strip()
        cells = _normalize_cell_map(op.get("cells") or {})
        action_counts[action or ""] += 1

        expected_headers = list(SELECTION_KEY_TO_HEADERS.get(selection_key) or [])
        expected_action = SK_TO_ACTION.get(selection_key, "")
        if not expected_headers:
            unknown_selection_count += 1
        if expected_action and action and expected_action != action:
            mismatched_action_count += 1

        extra_headers = sorted(
            h for h in cells.keys() if expected_headers and h not in expected_headers
        )
        for h in extra_headers:
            extras_counter[h] += 1

        status = "unknown"
        reason = ""
        if action not in SUPPORTED_APPLY_ACTIONS:
            unsupported_action_count += 1
            status = "unsupported_action"
            reason = "action_not_supported"
        else:
            # Run real apply logic with forced rollback (no persistent writes).
            try:
                with transaction.atomic():
                    status, reason, _skip_detail = apply_row_operation(op)
                    transaction.set_rollback(True)
            except Exception as e:
                status = "failed_exception"
                reason = f"{type(e).__name__}: {e}"

        status_counts[status] += 1
        if reason:
            reason_counts[reason] += 1

        row = {
            "index": idx,
            "row_key": str(op.get("row_key") or "").strip(),
            "selection_key": selection_key,
            "action": action,
            "status": status,
            "reason": reason,
            "summary": summary,
            "extra_headers": extra_headers,
        }
        result_rows.append(row)

        if verbose:
            extra_txt = f" extras={extra_headers}" if extra_headers else ""
            print(
                f"[{idx:03d}] {selection_key} :: {action} -> {status} ({reason or '-'}){extra_txt}"
            )

    payload = {
        "run_id": run_id,
        "run_status": run.status,
        "operation_count": len(frozen),
        "status_counts": dict(status_counts),
        "reason_counts": dict(reason_counts.most_common()),
        "action_counts": dict(action_counts),
        "unknown_selection_count": unknown_selection_count,
        "mismatched_action_count": mismatched_action_count,
        "unsupported_action_count": unsupported_action_count,
        "extra_header_counts": dict(extras_counter.most_common()),
        "rows": result_rows,
    }
    return payload


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Dry-run reconciliation validator (no DB writes)."
    )
    ap.add_argument("--run-id", type=int, required=True, help="Reconciliation run ID")
    ap.add_argument(
        "--json", action="store_true", help="Emit full JSON output (includes per-row data)"
    )
    ap.add_argument(
        "--verbose", action="store_true", help="Print one line per operation while validating"
    )
    args = ap.parse_args()

    _setup_django()
    report = _validate_run(args.run_id, verbose=bool(args.verbose))

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    print(f"Run #{report['run_id']} (status={report['run_status']})")
    print(f"Operations: {report['operation_count']}")
    print("")
    print("Status counts:")
    for k, v in sorted(report["status_counts"].items()):
        print(f"  - {k}: {v}")

    print("")
    print("Action counts:")
    for k, v in sorted(report["action_counts"].items()):
        print(f"  - {k or '(empty)'}: {v}")

    print("")
    print("Checks:")
    print(f"  - unknown_selection_count: {report['unknown_selection_count']}")
    print(f"  - mismatched_action_count: {report['mismatched_action_count']}")
    print(f"  - unsupported_action_count: {report['unsupported_action_count']}")

    if report["extra_header_counts"]:
        print("")
        print("Extra/unexpected headers in op cells:")
        for h, c in report["extra_header_counts"].items():
            print(f"  - {h}: {c}")

    if report["reason_counts"]:
        print("")
        print("Top reasons:")
        for r, c in list(report["reason_counts"].items())[:20]:
            print(f"  - {r}: {c}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

