"""
PostgreSQL session helpers for NetBox branch (``schema_*``) Django aliases.

When netbox-branching does not set ``search_path`` on a pooled connection,
``current_schema()`` can be NULL or ``public``. If
``RECONCILIATION_REPAIR_SEARCH_PATH_FROM_BRANCH_MODEL`` is True (default), we
issue ``SET search_path TO <Branch.schema_name>, public`` using a strictly
validated identifier, then re-read ``current_schema()``.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from django.conf import settings
from django.db import connections

logger = logging.getLogger(__name__)


def reconciliation_repair_search_path_from_branch_model_enabled() -> bool:
    return bool(getattr(settings, "RECONCILIATION_REPAIR_SEARCH_PATH_FROM_BRANCH_MODEL", True))


def postgresql_branch_schema_session_name_ok(raw: str) -> bool:
    """True when ``current_schema()`` is a non-empty, non-main schema name."""
    s = (raw or "").strip().lower()
    return bool(s) and s != "public"


def branch_model_postgresql_schema_name(branch_obj: Any) -> str:
    try:
        sn = getattr(branch_obj, "schema_name", None)
        if callable(sn):
            sn = sn()
        return str(sn or "").strip()
    except Exception:
        return ""


def _pg_safe_unquoted_schema_identifier(name: str) -> str | None:
    """Allow only PostgreSQL unquoted identifiers (branch_* style); no SQL injection."""
    s = (name or "").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s):
        return None
    return s


def try_set_search_path_to_branch_schema(cursor, branch_obj: Any) -> tuple[bool, str]:
    """
    ``SET search_path TO <schema>, public`` from ``branch_obj.schema_name`` if valid.

    Returns ``(True, "")`` if ``SET`` ran without exception; else ``(False, reason_code_or_message)``.
    """
    if not reconciliation_repair_search_path_from_branch_model_enabled():
        return False, "repair_disabled_by_setting"
    raw = branch_model_postgresql_schema_name(branch_obj)
    if not raw:
        return False, "branch_schema_name_empty"
    sid = _pg_safe_unquoted_schema_identifier(raw)
    if not sid:
        return False, "schema_name_not_unquoted_safe_ident"
    try:
        # ``sid`` is validated [A-Za-z0-9_]+ — safe to concatenate
        cursor.execute("SET search_path TO " + sid + ", public")
        return True, ""
    except Exception as exc:
        logger.debug(
            "reconciliation: SET search_path from Branch.schema_name failed schema=%r",
            sid,
            exc_info=True,
        )
        return False, f"{type(exc).__name__}: {exc}"


def _fetch_current_schema_and_search_path(cursor) -> tuple[str, str]:
    cursor.execute("SELECT current_schema()")
    row = cursor.fetchone()
    cur = (row[0] or "").strip() if row else ""
    sp = ""
    try:
        cursor.execute("SELECT current_setting('search_path', true)")
        row_sp = cursor.fetchone()
        sp = (row_sp[0] or "").strip() if row_sp else ""
    except Exception:
        sp = ""
    return cur, sp


def read_postgresql_current_schema_for_alias(
    alias: str, *, branch_obj: Any | None = None
) -> tuple[str, bool, str | None, str, dict[str, Any]]:
    """
    Return ``(current_schema, is_postgresql, error, search_path, diagnostics)``.

    When ``branch_obj`` is set and the first read is not a usable branch session
    (empty or ``public``), attempts :func:`try_set_search_path_to_branch_schema`
    on the same cursor and re-reads.

    ``diagnostics`` is JSON-serializable for staging UI (repair path, skip reasons).
    """
    diag: dict[str, Any] = {
        "repair_setting_enabled": reconciliation_repair_search_path_from_branch_model_enabled(),
        "vendor_reported": "",
        "first_current_schema": "",
        "first_search_path": "",
        "branch_schema_name_raw": "",
        "repair_attempted": False,
        "repair_set_ok": False,
        "repair_detail": "",
        "final_current_schema": "",
        "final_search_path": "",
    }
    try:
        conn = connections[alias]
        conn.ensure_connection()
        inner = getattr(conn, "connection", None)
        vendor = (getattr(inner, "vendor", None) or "").lower()
        # NetBox ``schema_*`` dynamic aliases often omit ``vendor`` on the inner wrapper; still
        # run ``current_schema()`` probes (same as apply row logging). Only skip when vendor is
        # explicitly a non-PostgreSQL backend.
        diag["vendor_reported"] = vendor if vendor else "unset"
        if vendor and vendor != "postgresql":
            diag["final_current_schema"] = ""
            diag["final_search_path"] = ""
            return "", False, None, "", diag
        with conn.cursor() as cursor:
            cur, sp = _fetch_current_schema_and_search_path(cursor)
            diag["first_current_schema"] = cur
            diag["first_search_path"] = sp
            if branch_obj is not None:
                diag["branch_schema_name_raw"] = branch_model_postgresql_schema_name(branch_obj)
            if branch_obj is not None and not postgresql_branch_schema_session_name_ok(cur):
                ok_set, detail = try_set_search_path_to_branch_schema(cursor, branch_obj)
                diag["repair_attempted"] = True
                diag["repair_set_ok"] = ok_set
                diag["repair_detail"] = detail or ""
                if ok_set:
                    cur, sp = _fetch_current_schema_and_search_path(cursor)
            diag["final_current_schema"] = cur
            diag["final_search_path"] = sp
            return cur, True, None, sp, diag
    except Exception as exc:
        diag["repair_detail"] = f"{type(exc).__name__}: {exc}"
        return "", True, f"{type(exc).__name__}: {exc}", "", diag


def preflight_current_schema_after_repair_attempt(cursor, branch_obj: Any) -> str:
    """
    Read ``current_schema()``; if unusable, try ``SET search_path`` from ``branch_obj`` and
    re-read. Returns final ``current_schema`` string (may still be empty).
    """
    cursor.execute("SELECT current_schema()")
    row = cursor.fetchone()
    cur = (row[0] or "").strip() if row else ""
    if (
        not postgresql_branch_schema_session_name_ok(cur)
        and branch_obj is not None
        and try_set_search_path_to_branch_schema(cursor, branch_obj)[0]
    ):
        cursor.execute("SELECT current_schema()")
        row = cursor.fetchone()
        cur = (row[0] or "").strip() if row else ""
    return cur
