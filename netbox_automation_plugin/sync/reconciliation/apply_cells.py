"""Apply frozen reconciliation rows using scoped audit cells.

NetBox-oriented fields shown on the recon page are defined in
:mod:`netbox_write_projection` (:func:`netbox_write_projection_cells`). Preview delegates
there; apply handlers should read those same projected strings where possible so UI and
writes stay aligned.

``apply_row_operation`` narrows each row to reconciliation-preview source columns (plus
workflow fields: Proposed Action, Status, Risk, Authority). Generic columns use a
non-placeholder heuristic. **NB Proposed Tenant** is coerced via the drift tenant picker
catalog for sections that still expose that column (e.g. floating IPs, VMs); values not in
the catalog are omitted from scoped cells.

Execution order (new devices → proposed missing VLANs → placement → NICs → IPAM/VMs, etc.)
is enforced in ``service.apply_reconciliation_run`` via ``AUDIT_REPORT_APPLY_ORDER`` and
action phase.

VLAN / IPAM reads during apply use ``_orm_qs`` / ``_orm_mgr`` so queries target the active
branch schema (not unscoped main). Interface rows align device site/location from drift
before resolving untagged VLAN so scope matches recon-created VLANs. Skipped VLAN rows
include ``apply_extra_debug.vlan_resolution`` on apply results (counts + troubleshoot text).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from typing import Any

from django.core.exceptions import FieldDoesNotExist
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.db import models as django_models
from django.utils.text import slugify

from netbox_automation_plugin.sync.reporting.drift_report.drift_nb_picker_catalog import (
    coerce_nb_proposed_tenant_cell,
)
from netbox_automation_plugin.sync.reconciliation.branch import (
    check_reconciliation_apply_safe_to_mutate,
    get_reconciliation_apply_guard_context,
    get_netbox_plugin_active_branch,
)
from netbox_automation_plugin.sync.reconciliation.netbox_write_projection import (
    netbox_write_projection_for_op,
)
from netbox_automation_plugin.sync.tenancy_netbox_compat import tenant_hierarchy_fk

logger = logging.getLogger(__name__)


def _log_reconciliation_orm_write(
    *,
    entity: str,
    apply_action: str,
    op: dict[str, Any],
    message: str,
) -> None:
    """
    INFO log for Docker / NetBox logs: which ORM alias each sensitive create/update used.

    Search: ``reconciliation_orm_write``
    """
    logger.info(
        "reconciliation_orm_write entity=%s apply_action=%s row_key=%s branch_db=%s %s",
        entity,
        apply_action,
        str(op.get("row_key") or ""),
        str(op.get("branch_db") or ""),
        message,
    )

_VID_FROM_PARENS_RE = re.compile(r"\((\d+)\)\s*$")
# Log once per model if snapshot() is missing (branch Diff will lack field deltas).
_SNAPSHOT_MISSING_LOGGED: set[str] = set()

# Actions with real NetBox writers (extend as handlers are filled in).
SUPPORTED_APPLY_ACTIONS: frozenset[str] = frozenset(
    {
        "create_prefix",
        "create_ip_range",
        "create_floating_ip",
        "create_device",
        "review_device",
        "create_interface",
        "update_interface",
        "placement_alignment",
        "serial_review",
        "bmc_documentation",
        "bmc_alignment",
        "create_openstack_vm",
        "update_openstack_vm",
        "create_vlan",
        "create_tenant",
    }
)


def _cell(cells: dict[str, str], *names: str) -> str:
    for n in names:
        for k, v in cells.items():
            if str(k).strip().lower() == str(n).strip().lower():
                return "" if v is None else str(v).strip()
    for n in names:
        key_l = str(n).strip().lower()
        for k, v in cells.items():
            if str(k).strip().lower() == key_l:
                return "" if v is None else str(v).strip()
    return ""


_SKIP_WORDS = (
    "skip",
    "no action",
    "none",
    "informational",
    "review only",
    "do not",
    "not required",
    "n/a",
)


def skip_reason_from_row_guides(cells: dict[str, str]) -> str | None:
    """
    Honour Proposed Action / Status-style columns so we do not write when the audit row says not to.
    """
    for label in ("Proposed Action", "Proposed action", "proposed action"):
        val = _cell(cells, label).lower()
        if not val or val in ("—", "-"):
            continue
        for w in _SKIP_WORDS:
            if w in val:
                return "skipped_policy_proposed_action"
    st = _cell(cells, "Status").lower()
    if st and ("no drift" in st or "fully aligned" in st) and not _cell(
        cells, "Proposed Action", "Proposed action"
    ):
        return "skipped_policy_status_unchanged"
    return None


def _skip_missing_prereq(detail: str) -> tuple[str, str, str]:
    """Stable reason code + human detail for troubleshooting (stored as apply row ``reason_detail``)."""
    d = (detail or "").strip() or "No further detail."
    if len(d) > 2000:
        d = d[:1997] + "..."
    return "skipped", "skipped_prerequisite_missing", d


# ---------------------------------------------------------------------------
# Branch-DB context for per-save transaction.atomic() savepoints
# ---------------------------------------------------------------------------
# Set by apply_row_operation from op["branch_db"] so every handler and helper
# can open correctly-aliased savepoints without needing an extra argument.
# Each snapshot+save block wraps itself in transaction.atomic (via _tx_branch) so
# netbox_branching sees a distinct transaction boundary per save and cannot
# collapse multiple saves on the same object into a single diff row.
_APPLY_BRANCH_DB: ContextVar[str] = ContextVar(
    "netbox_automation_apply_branch_db", default="default"
)

# Per-thread snapshot of ORM routing context for one apply_row_operation call (see service.py).
_apply_routing_debug_tls = threading.local()


def _reconciliation_apply_unscoped_allowed(op: dict[str, Any]) -> bool:
    if op.get("_allow_unscoped_apply"):
        return True
    flag = (os.environ.get("NETBOX_AUTOMATION_ALLOW_UNSCOPED_APPLY") or "").strip().lower()
    return flag in ("1", "true", "yes")


def _clear_tls_routing_snapshot() -> None:
    try:
        delattr(_apply_routing_debug_tls, "last_row_snapshot")
    except AttributeError:
        pass


def _set_tls_routing_snapshot(snap: dict[str, Any]) -> None:
    _apply_routing_debug_tls.last_row_snapshot = snap


def consume_apply_routing_debug_snapshot() -> dict[str, Any] | None:
    """Pop routing debug dict for the last :func:`apply_row_operation` (branch apply path)."""
    snap = getattr(_apply_routing_debug_tls, "last_row_snapshot", None)
    _clear_tls_routing_snapshot()
    return snap if isinstance(snap, dict) else None


def _build_reconciliation_apply_routing_snapshot(op: dict[str, Any]) -> dict[str, Any]:
    """
    JSON-friendly routing context at handler entry (after ``branch_db`` ContextVar is set).

    Explains how Django ORM will route saves for this row; does not prove PostgreSQL schema
    (that depends on NetBox Branching + ``activate_branch``).
    """
    from django.conf import settings

    out: dict[str, Any] = {}
    op_bd = str(op.get("branch_db") or "").strip()
    out["op_branch_db"] = op_bd
    ctx_eff = str(op.get("branch_db") or "default").strip() or "default"
    out["apply_contextvar_set_to"] = ctx_eff
    g = get_reconciliation_apply_guard_context()
    if g:
        out["reconciliation_guard_branch_pk"] = g.get("branch_pk")
        out["reconciliation_guard_connection_name"] = str(g.get("branch_db") or "").strip()
    else:
        out["reconciliation_guard_branch_pk"] = None
        out["reconciliation_guard_connection_name"] = ""
    active = get_netbox_plugin_active_branch()
    if active is not None:
        out["netbox_active_branch_pk"] = getattr(active, "pk", None)
        out["netbox_active_branch_name"] = str(getattr(active, "name", "") or "").strip()
    else:
        out["netbox_active_branch_pk"] = None
        out["netbox_active_branch_name"] = ""
    rab = (_ab() or "").strip() or "default"
    out["resolved_branch_db_alias"] = rab
    orm_u = _orm_alias()
    out["django_save_using_kwarg"] = orm_u
    routers = list(getattr(settings, "DATABASE_ROUTERS", None) or [])
    joined = " ".join(str(x) for x in routers)
    out["branch_router_configured"] = "netbox_branching.database.BranchAwareRouter" in joined
    gpk = out.get("reconciliation_guard_branch_pk")
    apk = out.get("netbox_active_branch_pk")
    try:
        out["guard_matches_netbox_active_branch"] = (
            gpk is not None and apk is not None and int(gpk) == int(apk)
        )
    except (TypeError, ValueError):
        out["guard_matches_netbox_active_branch"] = False
    if orm_u is None:
        out["how_writes_route"] = (
            "save() omits using=; ORM uses default manager (no reconciliation_apply_guard). "
            "Guarded reconciliation apply always uses an explicit schema_* alias."
        )
    else:
        out["how_writes_route"] = (
            f"save(using={orm_u!r}) / atomic(using={orm_u!r}) for nested savepoints; "
            "this connection alias should be the branch DB."
        )
    return out


def _ab() -> str:
    """
    Active reconciliation branch DB alias.

    Prefer the apply guard (set for the whole batch) so helpers still target the branch
    even if the ContextVar is wrong in edge cases; then the per-row ContextVar from
    ``apply_row_operation``.
    """
    try:
        ctx = get_reconciliation_apply_guard_context()
        if ctx:
            bd = str(ctx.get("branch_db") or "").strip()
            if bd:
                return bd
    except Exception:
        pass
    return str(_APPLY_BRANCH_DB.get() or "default").strip() or "default"


def _orm_alias() -> str | None:
    """
    Django ORM ``using=`` value for reconciliation writes.

    With an active :func:`reconciliation_apply_guard`, the alias must be a non-default
    ``schema_*`` key — we never return ``None`` in that mode (unscoped saves can hit NetBox main).

    Without a guard (e.g. unscoped tooling env), ``default`` still maps to ``None`` for reads.
    """
    u = (_ab() or "").strip()
    if not u or u.lower() == "default":
        if get_reconciliation_apply_guard_context() is not None:
            raise RuntimeError(
                "Reconciliation apply requires a non-default Django database alias (schema_*); "
                "resolved branch_db is empty or 'default' — refusing unscoped ORM writes."
            )
        return None
    return u


def _orm_qs(model_cls: Any):
    """``Model.objects`` for branch apply; omits ``using`` when alias is ``default``."""
    a = _orm_alias()
    m = model_cls.objects
    return m.using(a) if a is not None else m


def _orm_mgr(model_cls: Any):
    """Like ``_orm_qs`` but ``db_manager`` for custom managers (e.g. VLAN)."""
    a = _orm_alias()
    return model_cls.objects.db_manager(a) if a is not None else model_cls.objects


# Handler-populated diagnostics merged into apply result rows (``apply_extra_debug`` in service).
_apply_extra_debug_tls = threading.local()


def _clear_apply_extra_debug() -> None:
    try:
        delattr(_apply_extra_debug_tls, "payload")
    except AttributeError:
        pass


def _merge_apply_extra_debug(**kwargs: Any) -> None:
    cur = getattr(_apply_extra_debug_tls, "payload", None)
    if not isinstance(cur, dict):
        cur = {}
    for k, v in kwargs.items():
        if v is None:
            continue
        cur[k] = v
    _apply_extra_debug_tls.payload = cur


def consume_apply_extra_debug() -> dict[str, Any]:
    """Pop optional handler diagnostics (VLAN resolution, etc.) for the last apply row."""
    p = getattr(_apply_extra_debug_tls, "payload", None)
    _clear_apply_extra_debug()
    return dict(p) if isinstance(p, dict) else {}


def _vlan_gfk_name() -> str:
    from ipam.models import VLAN

    return "group" if any(f.name == "group" for f in VLAN._meta.fields) else "vlan_group"


def _vlan_resolution_snapshot_for_device(
    dev: Any,
    vid_i: int,
    vlan_group_hint: str | None,
) -> dict[str, Any]:
    """
    Branch-scoped counts/hints when interface untagged VLAN resolution fails.

    Historical fix context: VLAN reads/writes during apply use ``_orm_qs`` / ``_orm_mgr`` so
    queries hit the active branch schema (not unscoped main). Missing VLAN skips usually
    mean the VID is absent on the branch, out of scope for the device site/location, or
    ``create_vlan`` ran later in the batch than this interface row (see Run #).
    """
    from ipam.models import VLAN, VLANGroup

    gfk = _vlan_gfk_name()
    vlan_mgr = _orm_mgr(VLAN)
    out: dict[str, Any] = {
        "context": "interface_untagged_vlan",
        "requested_vid": vid_i,
        "device_name": getattr(dev, "name", None),
        "device_pk": getattr(dev, "pk", None),
        "device_site_id": getattr(dev, "site_id", None),
        "device_location_id": getattr(dev, "location_id", None),
        "nb_proposed_vlan_group": (vlan_group_hint or "").strip() or None,
        "django_save_using_kwarg": _orm_alias(),
        "resolved_branch_db_alias": _ab(),
        "vlan_rows_with_vid_in_branch_schema": vlan_mgr.filter(vid=vid_i).count(),
    }
    if getattr(dev, "site_id", None):
        out["vlan_rows_matching_vid_and_device_site"] = vlan_mgr.filter(
            vid=vid_i, site_id=dev.site_id
        ).count()
    gn = (vlan_group_hint or "").strip()
    if gn and gn not in {"—", "-"}:
        grp = _orm_qs(VLANGroup).filter(name__iexact=gn).first()
        out["vlan_group_name_found_in_branch"] = grp is not None
        if grp is not None:
            out["vlan_exists_in_named_group_with_vid"] = (
                _orm_qs(VLAN).filter(**{gfk: grp, "vid": vid_i}).exists()
            )
    out["troubleshoot"] = (
        "If a create_vlan row for this VID is in the same apply batch, its Run # should be "
        "lower than this interface row. Ensure the VLAN exists on this branch (not only on "
        "main) and that VLAN group scope matches the device site/location."
    )
    return out


def _vlan_resolution_snapshot_for_prefix(
    vlan_name: str,
    scope_obj: Any | None,
    vlan_group_hint: str | None,
) -> dict[str, Any]:
    """Branch-scoped hints when prefix VLAN FK resolution fails."""
    from ipam.models import VLAN, VLANGroup

    raw = str(vlan_name or "").strip()
    gfk = _vlan_gfk_name()
    vlan_mgr = _orm_mgr(VLAN)
    out: dict[str, Any] = {
        "context": "prefix_vlan_fk",
        "vlan_cell": raw,
        "nb_proposed_vlan_group": (vlan_group_hint or "").strip() or None,
        "prefix_scope_location_pk": getattr(scope_obj, "pk", None) if scope_obj is not None else None,
        "prefix_scope_location_name": (
            str(getattr(scope_obj, "name", "") or "").strip() if scope_obj is not None else None
        ),
        "prefix_scope_site_id": (
            getattr(scope_obj, "site_id", None) if scope_obj is not None else None
        ),
        "django_save_using_kwarg": _orm_alias(),
        "resolved_branch_db_alias": _ab(),
    }
    candidate_vid: int | None = None
    m = _VID_FROM_PARENS_RE.search(raw)
    if m:
        try:
            candidate_vid = int(m.group(1))
        except (TypeError, ValueError):
            candidate_vid = None
    elif raw.isdigit():
        try:
            candidate_vid = int(raw)
        except (TypeError, ValueError):
            candidate_vid = None
    out["parsed_vid_from_cell"] = candidate_vid
    if candidate_vid is not None:
        out["vlan_rows_with_vid_in_branch_schema"] = vlan_mgr.filter(vid=candidate_vid).count()
        if scope_obj is not None and getattr(scope_obj, "site_id", None):
            out["vlan_rows_matching_vid_and_scope_site"] = vlan_mgr.filter(
                vid=candidate_vid, site_id=scope_obj.site_id
            ).count()
    gh = (vlan_group_hint or "").strip()
    if gh and gh not in {"—", "-"}:
        grp = _orm_qs(VLANGroup).filter(name__iexact=gh).first()
        out["vlan_group_name_found_in_branch"] = grp is not None
        if grp is not None and candidate_vid is not None:
            out["vlan_exists_in_named_group_with_vid"] = (
                _orm_qs(VLAN).filter(**{gfk: grp, "vid": candidate_vid}).exists()
            )
    out["troubleshoot"] = (
        "If create_vlan for this VID is in the same apply batch, its Run # should be lower "
        "than this prefix row. Confirm the VLAN exists on the branch and matches scope/name."
    )
    return out


def _save_branch() -> dict[str, str]:
    """Keyword args for ``save()`` — includes ``using=`` whenever :func:`_orm_alias` returns an alias."""
    a = _orm_alias()
    if a is not None:
        return {"using": a}
    if get_reconciliation_apply_guard_context() is not None:
        raise RuntimeError(
            "_save_branch() called under reconciliation_apply_guard but _orm_alias() "
            "returned None — refusing unscoped save() to avoid writing NetBox main."
        )
    return {}


def _refresh_branch() -> dict[str, str]:
    """Keyword args for ``refresh_from_db()`` — same rules as ``_save_branch``."""
    return _save_branch()


@contextmanager
def _tx_branch():
    """``transaction.atomic(using=…)`` on the branch schema alias (required under apply guard)."""
    a = _orm_alias()
    if a is not None:
        with transaction.atomic(using=a):
            yield
    elif get_reconciliation_apply_guard_context() is not None:
        raise RuntimeError(
            "_tx_branch() called under reconciliation_apply_guard but _orm_alias() "
            "returned None — branch alias not set. Refusing transaction on default to avoid "
            "writing NetBox main."
        )
    else:
        with transaction.atomic():
            yield


@contextmanager
def _tx_op(alias: str):
    """Per-row transaction from ``op["branch_db"]`` (interface create/update)."""
    raw = (alias or "").strip()
    guard = get_reconciliation_apply_guard_context() is not None
    if guard:
        if not raw or raw.lower() == "default":
            raise RuntimeError(
                "Interface apply requires op['branch_db'] to be a non-default schema_* alias "
                "(_tx_op)."
            )
        with transaction.atomic(using=raw):
            yield
        return
    if not raw or raw.lower() == "default":
        with transaction.atomic():
            yield
    else:
        with transaction.atomic(using=raw):
            yield


def _iface_save_on_op(alias: str, iface: Any) -> None:
    raw = (alias or "").strip()
    guard = get_reconciliation_apply_guard_context() is not None
    if guard:
        if not raw or raw.lower() == "default":
            raise RuntimeError(
                "Interface apply requires op['branch_db'] to be a non-default schema_* alias "
                "(_iface_save_on_op)."
            )
        iface.save(using=raw)
        return
    if not raw or raw.lower() == "default":
        iface.save()
    else:
        iface.save(using=raw)


def _netbox_changelog_snapshot(instance: Any) -> None:
    """
    NetBox change-logging (and netbox-branching ChangeDiff field deltas) need a pre-save
    snapshot. The REST UI does this automatically; plugin ORM paths must call it before
    mutating an existing row or the branch Diff shows \"Updated\" with empty columns.

    Call again before *each* additional ``save()`` on the same instance in one request
    (e.g. field update then tag merge): otherwise only the first mutation gets a delta and
    MAC/VLAN/IP-style fields look missing while tags still appear.

    For **creates**, a single ``save()`` with every field often yields a branch row with an
    empty Difference column; prefer a minimal first ``save()``, then follow-up updates.

    Interface **scalar** fields (MAC, untagged VLAN, type, description) are applied in **one**
    ``snapshot()`` + ``save()`` per reconciliation row so branch Diff shows every changed
    field in one delta; multiple Interface saves in the same DB transaction are often
    collapsed in the Diff UI to a single sparse row (e.g. tags only).

    Ref: https://github.com/netboxlabs/netbox-branching/discussions/51
    """
    fn = getattr(instance, "snapshot", None)
    if not callable(fn):
        key = type(instance).__name__
        if key not in _SNAPSHOT_MISSING_LOGGED:
            _SNAPSHOT_MISSING_LOGGED.add(key)
            logger.warning(
                "NetBox change logging: %s has no snapshot(); branch Diff may omit field deltas for plugin ORM writes.",
                key,
            )
        return
    try:
        fn()
    except Exception:
        logger.debug(
            "snapshot() failed for %s pk=%s",
            type(instance).__name__,
            getattr(instance, "pk", None),
            exc_info=True,
        )


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


def _resolve_by_name(model, name: str, *, using: str | None = None):
    s = str(name or "").strip()
    if not s:
        return None
    mgr = model.objects.using(using) if using else model.objects
    for lookup in ("name", "slug", "model"):
        try:
            obj = mgr.filter(**{lookup: s}).first()
        except Exception:
            obj = None
        if obj is not None:
            return obj
    for lookup in ("name__iexact", "slug__iexact", "model__iexact"):
        try:
            obj = mgr.filter(**{lookup: s}).first()
        except Exception:
            obj = None
        if obj is not None:
            return obj
    return None


def _resolve_device_type(raw: str | None) -> Any:
    """
    Resolve ``DeviceType`` from drift / recon cells.

    The audit UI often shows ``"{manufacturer} {model}"`` (e.g. "Dell PowerEdge R660") while
    NetBox stores ``model`` (e.g. "PowerEdge R660") on ``DeviceType`` with a separate
    ``manufacturer`` FK—plain ``model__iexact`` on the full string therefore misses.
    """
    from dcim.models import DeviceType

    s = str(raw or "").strip()
    if not s or s in ("—", "-"):
        return None
    using = _orm_alias()
    dt = _resolve_by_name(DeviceType, s, using=using)
    if dt is not None:
        return dt
    qmod = _orm_qs(DeviceType).filter(model__iexact=s)
    n = qmod.count()
    if n == 1:
        return qmod.first()
    parts = s.split()
    if len(parts) >= 2:
        mfr_key, rest = parts[0], " ".join(parts[1:])
        hit = (
            _orm_qs(DeviceType)
            .filter(
                manufacturer__name__iexact=mfr_key,
                model__iexact=rest,
            )
            .first()
        )
        if hit is not None:
            return hit
        mfr = _orm_qs(Manufacturer).filter(name__iexact=mfr_key).first()
        if mfr is None:
            mslug = slugify(mfr_key)[:50]
            mfr = (
                _orm_qs(Manufacturer).filter(slug__iexact=mslug).first() if mslug else None
            )
        if mfr is not None:
            hit = _orm_qs(DeviceType).filter(manufacturer=mfr, model__iexact=rest).first()
            if hit is not None:
                return hit
    s_low = s.lower()
    tail_guesses: list[str] = []
    if len(parts) >= 2:
        tail_guesses.append(parts[-1])
    tail_guesses.append(s)
    seen: set[str] = set()
    for tail in tail_guesses:
        t = tail.strip()
        if len(t) < 2 or t.lower() in seen:
            continue
        seen.add(t.lower())
        qs = _orm_qs(DeviceType).select_related("manufacturer").filter(model__iexact=t)
        if qs.count() > 40:
            qs = _orm_qs(DeviceType).select_related("manufacturer").filter(model__istartswith=t)[
                :50
            ]
        for cand in qs:
            if f"{cand.manufacturer.name} {cand.model}".strip().lower() == s_low:
                return cand
    return None


def _resolve_tenant(raw: str | None, *, using: str | None = None) -> Any:
    """
    Resolve ``Tenant`` from drift / recon cells.

    Audit columns may use hyphenated or project-specific labels (e.g. ``whitefiber-internal``)
    while NetBox stores a shorter ``name`` (e.g. ``whitefiber``). Try slug and a unique
    prefix before the first hyphen when the full string does not match. Hierarchical picker
    labels ``Parent / Child`` (or ``Group / Tenant`` on NetBox 4.x) match hierarchy names.

    Pass ``using`` during reconciliation apply so lookups hit the active branch schema.
    """
    from tenancy.models import Tenant

    s = str(raw or "").strip()
    if not s or s in ("—", "-"):
        return None
    mgr = Tenant.objects.using(using) if using else Tenant.objects
    if " / " in s:
        parent_part, child_part = s.split(" / ", 1)
        parent_part = (parent_part or "").strip()
        child_part = (child_part or "").strip()
        if parent_part and child_part:
            rel = tenant_hierarchy_fk()
            if rel == "parent":
                try:
                    for cand in mgr.filter(name__iexact=child_part).select_related(
                        "parent"
                    ).iterator():
                        par = getattr(cand, "parent", None)
                        pn = (par.name or "").strip() if par else ""
                        if pn.lower() == parent_part.lower():
                            return cand
                except Exception:
                    pass
            elif rel == "group":
                try:
                    hit = mgr.filter(
                        name__iexact=child_part,
                        group__name__iexact=parent_part,
                    ).first()
                    if hit is not None:
                        return hit
                except Exception:
                    pass
    t = _resolve_by_name(Tenant, s, using=using)
    if t is not None:
        return t
    slug = slugify(s)
    if slug:
        t = mgr.filter(slug__iexact=slug).first()
        if t is not None:
            return t
    if "-" in s:
        head = s.split("-", 1)[0].strip()
        if head and head.lower() != s.lower():
            q = mgr.filter(name__iexact=head)
            if q.count() == 1:
                return q.first()
            hs = slugify(head)
            if hs:
                q2 = mgr.filter(slug__iexact=hs)
                if q2.count() == 1:
                    return q2.first()
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


def _normalize_floating_ip_host_mask(raw_ip: str) -> str:
    """Floating IPs are single addresses: always /32 (IPv4) or /128 (IPv6), ignoring any stray mask."""
    s = str(raw_ip or "").strip()
    if not s:
        raise ValueError("empty address")
    host = s.split("/", 1)[0].strip()
    ip_obj = ipaddress.ip_address(host)
    return f"{host}/32" if ip_obj.version == 4 else f"{host}/128"


def _ipaddress_value_prefixlen(addr_val) -> int | None:
    s = str(addr_val or "").strip()
    if "/" not in s:
        return None
    try:
        return ipaddress.ip_interface(s).network.prefixlen
    except Exception:
        return None


def _find_ipaddress_for_floating_host(
    host: str,
    vrf: Any | None,
    *,
    normalized_address: str,
) -> Any | None:
    """
    Match IPAddress by host + VRF even when the stored mask differs (e.g. existing /25 vs new /32).

    Prefer an exact ``normalized_address`` hit, else any same-host row with a subnet-style mask,
    else any same-host row.
    """
    from ipam.models import IPAddress

    try:
        want = ipaddress.ip_interface(normalized_address)
    except Exception:
        return None
    host_max = 32 if want.version == 4 else 128
    qs = _orm_qs(IPAddress).filter(address__startswith=f"{host}/")
    if vrf is None:
        qs = qs.filter(vrf__isnull=True)
    else:
        qs = qs.filter(vrf_id=getattr(vrf, "pk", None))
    exact = qs.filter(address=normalized_address).first()
    if exact is not None:
        return exact
    rows = list(qs.order_by("pk")[:120])
    if not rows:
        return None
    non_host = [
        r
        for r in rows
        if (pl := _ipaddress_value_prefixlen(getattr(r, "address", None))) is not None and pl < host_max
    ]
    if non_host:
        return max(non_host, key=lambda r: _ipaddress_value_prefixlen(r.address) or 0)
    return rows[0]


# NetBox ``VLAN.vid`` / ``Interface.untagged_vlan``: IEEE 802.1Q 1–4094. MAAS NIC rows must
# carry ``vlan.vid`` only, never ``vlan.id`` (see ``maas_client`` MAAS→NetBox VLAN mapping).
_NETBOX_IEEE_VLAN_VID_MAX = 4094


def _parse_vlan_vid(raw: str) -> int | None:
    """
    Parse a VLAN tag for NetBox apply: **1–4094** only.

    MAAS: ``vlan.vid == 0`` is untagged/native → returns ``None``. ``vlan.id`` must not appear
    in these strings (collection strips it). Values outside 1–4094 return ``None``.
    """
    s = str(raw or "").strip()
    if not s:
        return None
    m = re.search(r"\b(\d{1,4})\b", s)
    if not m:
        return None
    v = int(m.group(1))
    if 1 <= v <= _NETBOX_IEEE_VLAN_VID_MAX:
        return v
    return None


def _vlan_vid_over_ieee_max_from_proposed_body(body: str) -> int | None:
    """
    If Proposed Action names a VLAN integer above IEEE 802.1Q max, return that int.
    Used to fail loudly instead of ``ok_updated`` with no VLAN change (``_parse_vlan_vid`` drops it).
    """
    b = (body or "").strip()
    if not b:
        return None
    for pat in (
        r"\bSET_NETBOX_UNTAGGED_VLAN\s*=\s*(\d+)",
        r"\buntagged\s+VLAN\s+(\d+)",
    ):
        m = re.search(pat, b, flags=re.IGNORECASE)
        if not m:
            continue
        try:
            v = int(m.group(1))
        except ValueError:
            continue
        if v > _NETBOX_IEEE_VLAN_VID_MAX:
            return v
    return None


def _normalize_mac(raw: str) -> str | None:
    s = str(raw or "").strip().upper()
    if not s or s in ("—", "-"):
        return None
    s = s.replace("-", ":")
    parts = [p for p in s.split(":") if p]
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        try:
            int("".join(parts), 16)
        except ValueError:
            return None
        return ":".join(parts)
    # Cisco-style aabb.cc00.dd11 or bare 12 hex nibbles (MAAS / switch exports).
    dotless = s.replace(".", "").replace(":", "")
    if len(dotless) == 12:
        try:
            int(dotless, 16)
        except ValueError:
            return None
        return ":".join(dotless[i : i + 2] for i in range(0, 12, 2))
    return None


def _nic_proposed_property_segment_ok(val: str | None) -> bool:
    if val is None:
        return False
    t = str(val).strip()
    return bool(t) and t not in ("—", "-")


def _parse_set_netbox_interface_directives(raw: str) -> tuple[str | None, str | None, str | None]:
    """
    Workflow ``Proposed Action`` tokens: SET_NETBOX_MAC=…; SET_NETBOX_UNTAGGED_VLAN=…; SET_NETBOX_IP=…
    (semicolon-separated). Multiple IP directives are concatenated with comma+space.
    """
    s = (raw or "").strip()
    if not s:
        return None, None, None
    mac_val = vlan_val = None
    m = re.search(r"\bSET_NETBOX_MAC=([^;]+)", s, flags=re.IGNORECASE)
    if m:
        mac_val = m.group(1).strip()
    m = re.search(r"\bSET_NETBOX_UNTAGGED_VLAN=([^;]+)", s, flags=re.IGNORECASE)
    if m:
        vlan_val = m.group(1).strip()
    ip_chunks: list[str] = []
    for m in re.finditer(r"\bSET_NETBOX_IP=([^;]+)", s, flags=re.IGNORECASE):
        t = m.group(1).strip()
        if t:
            ip_chunks.append(t)
    ips_val = ", ".join(ip_chunks) if ip_chunks else None
    return mac_val, vlan_val, ips_val


def _parse_nic_proposed_properties_segments(raw: str) -> tuple[str | None, str | None, str | None]:
    """
    ``Proposed Action`` text with MAC / untagged VLAN / IPs clauses, e.g.
    ``MAC c4:cb:e1:e5:93:be; untagged VLAN 2148; IPs: 10.25.56.154``.
    Missing clauses or ``—`` segments are handled by the caller.
    """
    s = (raw or "").strip()
    if not s or s in ("—", "-"):
        return None, None, None
    mac_val = vlan_val = ips_val = None
    m = re.search(r"\bMAC\s+([^;]+)", s, flags=re.IGNORECASE)
    if m:
        mac_val = m.group(1).strip()
    m = re.search(r"\buntagged\s+VLAN\s+([^;]+)", s, flags=re.IGNORECASE)
    if m:
        vlan_val = m.group(1).strip()
    m = re.search(r"\bIPs:\s*(.+)", s, flags=re.IGNORECASE)
    if m:
        ips_val = m.group(1).strip()
    return mac_val, vlan_val, ips_val


def _cell_nic_proposed_body(cells: dict[str, str]) -> str:
    """Single column name in drift/recon UI; frozen rows may still use legacy headers."""
    return _cell(
        cells,
        "Proposed Action",
        "Proposed action",
        "Proposed properties",
        "Proposed properties (from MAAS)",
    )


def _set_netbox_mac_directive_present(body: str) -> bool:
    return bool(re.search(r"\bSET_NETBOX_MAC\s*=", body or "", flags=re.IGNORECASE))


def _set_netbox_vlan_directive_present(body: str) -> bool:
    return bool(re.search(r"\bSET_NETBOX_UNTAGGED_VLAN\s*=", body or "", flags=re.IGNORECASE))


def _set_netbox_ip_directive_present(body: str) -> bool:
    return bool(re.search(r"\bSET_NETBOX_IP\s*=", body or "", flags=re.IGNORECASE))


def _nic_use_inventory_column_fallbacks(
    body: str,
    p_mac: str | None,
    p_vlan: str | None,
    p_ips: str | None,
    s_mac: str | None,
    s_vlan: str | None,
    s_ips: str | None,
) -> tuple[bool, bool, bool]:
    """
    Whether MAAS/OS/NB (and Parsed *) columns may supply MAC / VLAN / IP for apply.

    **SET_NETBOX_ mode:** A field uses inventory columns only if that keyword appears
    (``SET_NETBOX_MAC``, ``SET_NETBOX_UNTAGGED_VLAN``, ``SET_NETBOX_IP``)—exactly the
    knobs listed in Proposed Action. Human ``MAC`` / ``untagged VLAN`` / ``IPs:`` text
    does not enable column fallback in that mode.

    **Human-clause-only mode:** Column fallback is limited to columns matching clauses
    present in the text. Empty or non-clause Proposed Action keeps legacy behavior
    (all column fallbacks).
    """
    b = (body or "").strip()
    set_nb = bool(re.search(r"\bSET_NETBOX_", b, re.IGNORECASE))
    if set_nb:
        return (
            _set_netbox_mac_directive_present(b),
            _set_netbox_vlan_directive_present(b),
            _set_netbox_ip_directive_present(b),
        )

    any_human = (
        _nic_proposed_property_segment_ok(p_mac)
        or _nic_proposed_property_segment_ok(p_vlan)
        or _nic_proposed_property_segment_ok(p_ips)
    )
    if b and any_human:
        return (
            _nic_proposed_property_segment_ok(p_mac),
            _nic_proposed_property_segment_ok(p_vlan),
            _nic_proposed_property_segment_ok(p_ips),
        )
    return True, True, True


def _text_has_derivable_nic_clauses(raw: str) -> bool:
    """True when Proposed Action carries human-readable or SET_NETBOX_* NIC intent."""
    mac, vlan, ips = _parse_nic_proposed_properties_segments(raw)
    if (
        _nic_proposed_property_segment_ok(mac)
        or _nic_proposed_property_segment_ok(vlan)
        or _nic_proposed_property_segment_ok(ips)
    ):
        return True
    sm, sv, si = _parse_set_netbox_interface_directives(raw)
    if _nic_proposed_property_segment_ok(sm):
        return True
    if sv and _parse_vlan_vid(sv) is not None:
        return True
    if _nic_proposed_property_segment_ok(si):
        return True
    return False


def _interface_mac_vlan_ip_from_cells(
    cells: dict[str, str], *, include_nb_fallback: bool
) -> tuple[str | None, int | None, str]:
    """
    Resolve MAC, untagged VLAN id, and IP blob for interface apply.

    * **Any** ``SET_NETBOX_`` in Proposed Action → **strict directive mode**: values come
      only from ``SET_NETBOX_MAC`` / ``SET_NETBOX_UNTAGGED_VLAN`` / ``SET_NETBOX_IP``
      (human ``MAC …`` / ``untagged VLAN …`` / ``IPs:`` clauses are ignored). Inventory
      columns fill a field only when that field’s ``SET_NETBOX_*`` keyword is present
      (e.g. ``SET_NETBOX_UNTAGGED_VLAN=1; SET_NETBOX_IP=172.17.0.6`` → VLAN + IP only).
    * Otherwise → human clauses first, then optional ``SET_NETBOX_*``, then columns as
      documented in ``_nic_use_inventory_column_fallbacks``.
    """
    body = _cell_nic_proposed_body(cells)
    p_mac, p_vlan, p_ips = _parse_nic_proposed_properties_segments(body)
    s_mac, s_vlan, s_ips = _parse_set_netbox_interface_directives(body)
    use_mac_cols, use_vlan_cols, use_ip_cols = _nic_use_inventory_column_fallbacks(
        body, p_mac, p_vlan, p_ips, s_mac, s_vlan, s_ips
    )
    set_nb = bool(re.search(r"\bSET_NETBOX_", body, re.IGNORECASE))

    if set_nb:
        mac = _normalize_mac(s_mac) if _nic_proposed_property_segment_ok(s_mac) else None
        if mac is None and use_mac_cols:
            if include_nb_fallback:
                mac = _normalize_mac(
                    _cell(cells, "MAAS MAC", "OS MAC", "NB MAC", "Parsed MAC")
                )
            else:
                mac = _normalize_mac(_cell(cells, "MAAS MAC", "OS MAC", "Parsed MAC"))

        vid: int | None = None
        if s_vlan:
            vid = _parse_vlan_vid(s_vlan)
        if vid is None and use_vlan_cols:
            if include_nb_fallback:
                vid = _parse_vlan_vid(
                    _cell(cells, "MAAS VLAN", "OS runtime VLAN", "NB VLAN", "Parsed untagged VLAN")
                )
            else:
                vid = _parse_vlan_vid(
                    _cell(cells, "MAAS VLAN", "OS runtime VLAN", "Parsed untagged VLAN")
                )

        ip_blob = ""
        if _nic_proposed_property_segment_ok(s_ips):
            ip_blob = str(s_ips).strip()
        if not ip_blob and use_ip_cols:
            if include_nb_fallback:
                ip_blob = _cell(cells, "MAAS IPs", "OS runtime IP", "NB IPs", "Parsed IPs")
            else:
                ip_blob = _cell(cells, "MAAS IPs", "OS runtime IP", "Parsed IPs")
    else:
        mac = _normalize_mac(p_mac) if _nic_proposed_property_segment_ok(p_mac) else None
        if mac is None and _nic_proposed_property_segment_ok(s_mac):
            mac = _normalize_mac(s_mac)
        if mac is None and use_mac_cols:
            if include_nb_fallback:
                mac = _normalize_mac(
                    _cell(cells, "MAAS MAC", "OS MAC", "NB MAC", "Parsed MAC")
                )
            else:
                mac = _normalize_mac(_cell(cells, "MAAS MAC", "OS MAC", "Parsed MAC"))

        vid = None
        if _nic_proposed_property_segment_ok(p_vlan):
            vid = _parse_vlan_vid(p_vlan)
        if vid is None and s_vlan:
            vid = _parse_vlan_vid(s_vlan)
        if vid is None and use_vlan_cols:
            if include_nb_fallback:
                vid = _parse_vlan_vid(
                    _cell(cells, "MAAS VLAN", "OS runtime VLAN", "NB VLAN", "Parsed untagged VLAN")
                )
            else:
                vid = _parse_vlan_vid(
                    _cell(cells, "MAAS VLAN", "OS runtime VLAN", "Parsed untagged VLAN")
                )

        ip_blob = ""
        if _nic_proposed_property_segment_ok(p_ips):
            ip_blob = str(p_ips).strip()
        if not ip_blob and _nic_proposed_property_segment_ok(s_ips):
            ip_blob = str(s_ips).strip()
        if not ip_blob and use_ip_cols:
            if include_nb_fallback:
                ip_blob = _cell(cells, "MAAS IPs", "OS runtime IP", "NB IPs", "Parsed IPs")
            else:
                ip_blob = _cell(cells, "MAAS IPs", "OS runtime IP", "Parsed IPs")

    ip_blob = str(ip_blob or "").strip()
    if ip_blob in ("—", "-"):
        ip_blob = ""

    return mac, vid, ip_blob


def _nic_mac_intent_raw(cells: dict[str, str], *, include_nb_fallback: bool) -> str | None:
    """
    Raw MAC string the row is asking to apply (before normalization).

    Used to avoid ``skipped_already_desired`` when the operator clearly set a MAC in
    Proposed Action or MAAS/OS/NB columns but the value is not a valid Ethernet MAC.
    """
    body = _cell_nic_proposed_body(cells)
    p_mac, p_vlan, p_ips = _parse_nic_proposed_properties_segments(body)
    s_mac, s_vlan, s_ips = _parse_set_netbox_interface_directives(body)
    use_mac_cols, _, _ = _nic_use_inventory_column_fallbacks(
        body, p_mac, p_vlan, p_ips, s_mac, s_vlan, s_ips
    )
    set_nb = bool(re.search(r"\bSET_NETBOX_", body, re.IGNORECASE))
    if set_nb:
        if _nic_proposed_property_segment_ok(s_mac):
            return str(s_mac).strip()
        if not use_mac_cols:
            return None
    else:
        if _nic_proposed_property_segment_ok(p_mac):
            return str(p_mac).strip()
        if _nic_proposed_property_segment_ok(s_mac):
            return str(s_mac).strip()
        if not use_mac_cols:
            return None
    cols = (
        _cell(cells, "MAAS MAC", "OS MAC", "NB MAC", "Parsed MAC")
        if include_nb_fallback
        else _cell(cells, "MAAS MAC", "OS MAC", "Parsed MAC")
    )
    return str(cols).strip() if _nic_proposed_property_segment_ok(cols) else None


def _nic_ip_blob_parse_stats(ip_blob: str) -> tuple[bool, bool]:
    """
    Whether the blob had IP tokens and whether at least one token is a valid NetBox address.

    No database access (safe before creating an interface row).
    """
    tokens = _split_ip_candidates(ip_blob)
    if not tokens:
        return False, False
    ok = False
    for raw in tokens:
        try:
            _normalize_ip_for_netbox(raw.split()[0])
            ok = True
        except Exception:
            continue
    return True, ok


# Core Frozen-action headers (first block copied in ``new_nic_cells_for_reconciliation``).
NEW_NIC_RECON_CORE_HEADERS: tuple[str, ...] = (
    "Host",
    "NB Proposed intf Label",
    "NB Proposed intf Type",
    "Suggested NB name",
    "Proposed Action",
)
# Site / scope / VLAN-group hints must survive freezing so ``apply_create_interface`` can
# align ``Device.site`` with recon-created VLANs (same NB site as IPAM rows) and resolve
# untagged VLAN by group+VID when device-scoped queries are ambiguous.
NEW_NIC_RECON_SCOPE_HEADERS: tuple[str, ...] = (
    "NB site",
    "NetBox site",
    "NB location",
    "NetBox location",
    "NB proposed VLAN group",
)
NEW_NIC_RECON_PAYLOAD_HEADERS: tuple[str, ...] = (
    *NEW_NIC_RECON_CORE_HEADERS,
    *NEW_NIC_RECON_SCOPE_HEADERS,
    "Parsed MAC",
    "Parsed untagged VLAN",
    "Parsed IPs",
)

# Selection keys for proposed-change "new interface" tables (frozen ops use minimal cells).
NEW_NIC_SELECTION_KEYS: frozenset[str] = frozenset(
    {"detail_new_nics", "detail_new_nics_os", "detail_new_nics_maas"}
)
# NIC drift sections (same as ``service.NIC_DRIFT_SELECTION_KEYS`` — avoid import cycle).
NIC_DRIFT_SELECTION_KEYS_LOCAL: frozenset[str] = frozenset(
    {"detail_nic_drift_os", "detail_nic_drift_maas"}
)


def new_nic_cells_for_reconciliation(full_cells: dict[str, str]) -> dict[str, str]:
    """
    Frozen reconciliation ops for new-NIC tables only carry these keys (plus parsed L2 fields).

    ``apply_create_interface`` reads MAC/VLAN/IPs from ``Proposed Action`` when clauses are present;
    ``Parsed *`` keys are for preview/diff and apply resolution (MAC/VLAN/IP).
    """
    out: dict[str, str] = {}
    for k in NEW_NIC_RECON_CORE_HEADERS:
        if k == "Proposed Action":
            v = (
                full_cells.get("Proposed Action")
                or full_cells.get("Proposed action")
                or full_cells.get("Proposed properties")
                or full_cells.get("Proposed properties (from MAAS)")
                or ""
            )
            out[k] = str(v).strip()
        else:
            out[k] = str(full_cells.get(k) or "").strip()
    for k in NEW_NIC_RECON_SCOPE_HEADERS:
        out[k] = str(full_cells.get(k) or "").strip()
    props = out["Proposed Action"]
    p_mac, p_vlan, p_ips = _parse_nic_proposed_properties_segments(props)
    s_mac, s_vlan, s_ips = _parse_set_netbox_interface_directives(props)
    if not _nic_proposed_property_segment_ok(p_mac) and _nic_proposed_property_segment_ok(s_mac):
        p_mac = s_mac
    if not _nic_proposed_property_segment_ok(p_vlan) and s_vlan and _parse_vlan_vid(s_vlan) is not None:
        p_vlan = s_vlan
    if not _nic_proposed_property_segment_ok(p_ips) and _nic_proposed_property_segment_ok(s_ips):
        p_ips = s_ips
    out["Parsed MAC"] = (p_mac or "").strip() if _nic_proposed_property_segment_ok(p_mac) else ""
    out["Parsed untagged VLAN"] = (p_vlan or "").strip() if _nic_proposed_property_segment_ok(p_vlan) else ""
    out["Parsed IPs"] = (p_ips or "").strip() if _nic_proposed_property_segment_ok(p_ips) else ""
    return out


def _split_ip_candidates(blob: str) -> list[str]:
    out: list[str] = []
    for chunk in re.split(r"[,;\s]+", str(blob or "").strip()):
        t = chunk.strip()
        if not t or t in ("—", "-"):
            continue
        out.append(t)
    return out


_DRIFT_AUDIT_MARKER = "\n=== Drift reconciliation (full row) ===\n"
# Legacy prefix apply embedded a row snapshot after this marker in Prefix.description.
_LEGACY_PREFIX_DRIFT_ROW_MARKER = "--- Drift row (reconciliation) ---"


def strip_prefix_description_audit_suffix(raw: str | None) -> str:
    """Strip reconciliation audit tails from Prefix.description or editable drift cells."""
    t = (raw or "").strip()
    if not t:
        return ""
    if _LEGACY_PREFIX_DRIFT_ROW_MARKER in t:
        t = t.split(_LEGACY_PREFIX_DRIFT_ROW_MARKER)[0].rstrip()
    m = _DRIFT_AUDIT_MARKER.strip()
    if m in t:
        t = t.split(m)[0].rstrip()
    return t.strip()


def _norm_header(k: str) -> str:
    return str(k or "").strip().lower()


def netbox_write_preview_cells(selection_key: str, cells: dict[str, str]) -> dict[str, str]:
    """
    Reconciliation / branch preview: delegates to :mod:`netbox_write_projection` (single source
    of truth). Column keys and values are unchanged from the historical implementation.
    """
    from netbox_automation_plugin.sync.reconciliation.netbox_write_projection import (
        netbox_write_projection_cells,
    )

    return netbox_write_projection_cells(selection_key, cells)


def netbox_write_preview_ordered_fieldnames(selection_key: str) -> tuple[str, ...]:
    """Ordered NetBox-style preview column keys for a reconciliation section (stable table headers)."""
    sk = str(selection_key or "").strip()
    return tuple(netbox_write_preview_cells(sk, {}).keys())


def netbox_write_preview_fieldnames(selection_key: str) -> frozenset[str]:
    """Set of preview headers (same order as ``netbox_write_preview_ordered_fieldnames``)."""
    return frozenset(netbox_write_preview_ordered_fieldnames(selection_key))


def recon_operation_display_cells(selection_key: str, cells: dict[str, str]) -> dict[str, str]:
    """NetBox write-oriented columns for reconciliation staging, run detail, and diffs."""
    return netbox_write_preview_cells(selection_key, cells)


def _interface_description_is_drift_audit_dump(s: str | None) -> bool:
    """True if description matches reconciliation audit text (never treat as operator intent)."""
    t = (s or "").strip()
    if not t:
        return False
    if _DRIFT_AUDIT_MARKER.strip() in t:
        return True
    # Legacy one-line / compact dumps from older apply paths
    if "NB Proposed intf Type:" in t and "Authority:" in t:
        return True
    if "Suggested NB name:" in t and "Risk:" in t and "Authority:" in t:
        return True
    return False


def _scrub_interface_drift_audit_description(iface: Any) -> bool:
    """Clear Interface.description when it holds drift audit junk. Returns True if the row was mutated."""
    if not hasattr(iface, "description"):
        return False
    if not _interface_description_is_drift_audit_dump(getattr(iface, "description", None)):
        return False
    iface.description = None
    return True


def _interface_scrub_audit_description_stepwise(iface: Any) -> bool:
    """Like _scrub_interface_drift_audit_description but snapshot/save so branching shows description delta."""
    if not hasattr(iface, "description"):
        return False
    if not _interface_description_is_drift_audit_dump(getattr(iface, "description", None)):
        return False
    _netbox_changelog_snapshot(iface)
    iface.description = None
    iface.save(**_save_branch())
    return True


def _interface_description_max_len() -> int:
    try:
        from dcim.models import Interface

        f = Interface._meta.get_field("description")
        ml = getattr(f, "max_length", None)
        return int(ml) if ml else 200
    except Exception:
        return 200


def _interface_description_from_cells(cells: dict[str, str]) -> str:
    return (
        _cell(
            cells,
            "Description",
            "NB proposed description",
            "NB intf description",
            "Interface description",
        )
        or ""
    ).strip()


def _interface_refresh_safe(iface: Any) -> None:
    try:
        explicit = _orm_alias()
        if explicit is not None:
            iface.refresh_from_db(using=explicit)
        else:
            iface.refresh_from_db()
    except Exception:
        logger.debug(
            "interface refresh_from_db failed (pk=%s)",
            getattr(iface, "pk", None),
            exc_info=True,
        )


def _interface_apply_physical_fields_batched(
    iface: Any,
    *,
    mac: str,
    untagged: Any,
    type_slug: Any,
    description: str = "",
) -> bool:
    """
    One ``snapshot()`` + one ``save()`` for MAC, untagged VLAN, type, and description.

    Several netbox-branching Diff UIs collapse multiple Interface saves that occur in the
    same database transaction into a single row, often showing only the last mutation (e.g.
    tags). Batching scalar fields yields one ObjectChange that includes every changed core
    field, aligned with recon apply lines (MAC / VLAN / type / description).
    """
    _interface_refresh_safe(iface)
    _netbox_changelog_snapshot(iface)
    changed = False
    if mac and str(iface.mac_address or "").upper() != mac.upper():
        iface.mac_address = mac
        changed = True
    if untagged is not None and iface.untagged_vlan_id != untagged.pk:
        iface.untagged_vlan = untagged
        changed = True
    if type_slug is not None and getattr(iface, "type", None) != type_slug:
        iface.type = type_slug
        changed = True
    ds = (description or "").strip()
    if ds and hasattr(iface, "description"):
        ml = _interface_description_max_len()
        if len(ds) > ml:
            ds = ds[: max(ml - 3, 0)] + "..."
        cur = (getattr(iface, "description", None) or "").strip()
        if cur != ds:
            iface.description = ds
            changed = True
    if changed:
        iface.save(**_save_branch())
    return changed


def _interface_apply_physical_fields_stepwise(
    iface: Any,
    *,
    mac: str,
    untagged: Any,
    type_slug: Any,
    description: str = "",
) -> bool:
    """
    One ``snapshot()`` + ``save()`` per changed attribute (MAC, untagged VLAN, type,
    description). Prefer :func:`_interface_apply_physical_fields_batched` for interface
    **updates** from reconciliation: netbox-branching often **collapses** multiple saves on
    the same Interface into one sparse Diff row, showing wrong before/after VLAN (e.g. MAAS
    VID vs true NetBox ``untagged_vlan``) or only tag deltas. Stepwise remains for callers
    that need per-field ObjectChange rows despite collapse risk.
    """
    _interface_refresh_safe(iface)
    any_save = False
    m = (mac or "").strip()
    if m and str(iface.mac_address or "").upper() != m.upper():
        _netbox_changelog_snapshot(iface)
        iface.mac_address = mac
        iface.save(**_save_branch())
        any_save = True
        _interface_refresh_safe(iface)
    if untagged is not None and iface.untagged_vlan_id != untagged.pk:
        _netbox_changelog_snapshot(iface)
        iface.untagged_vlan = untagged
        iface.save(**_save_branch())
        any_save = True
        _interface_refresh_safe(iface)
    if type_slug is not None and getattr(iface, "type", None) != type_slug:
        _netbox_changelog_snapshot(iface)
        iface.type = type_slug
        iface.save(**_save_branch())
        any_save = True
        _interface_refresh_safe(iface)
    ds = (description or "").strip()
    if ds and hasattr(iface, "description"):
        ml = _interface_description_max_len()
        if len(ds) > ml:
            ds = ds[: max(ml - 3, 0)] + "..."
        cur = (getattr(iface, "description", None) or "").strip()
        if cur != ds:
            _netbox_changelog_snapshot(iface)
            iface.description = ds
            iface.save(**_save_branch())
            any_save = True
    return any_save


def _interface_apply_role_tag_changelog(iface: Any, role_label: str | None) -> bool:
    """``snapshot()`` before M2M tag add, then ``save()`` so branch Diff records tag deltas."""
    rl = str(role_label or "").strip()
    if not rl or not hasattr(iface, "tags"):
        return False
    _interface_refresh_safe(iface)
    _netbox_changelog_snapshot(iface)
    if not _merge_interface_role_tag(iface, rl):
        return False
    iface.save(**_save_branch())
    return True


def _merge_audit_residual_onto_object(
    obj: Any,
    cells: dict[str, str],
    consumed_lower: set[str],
    *,
    attr_names: tuple[str, ...] = ("description",),
    max_len: int = 8000,
) -> bool:
    """Intentionally disabled: reconciliation does not append free-text drift row dumps to NetBox."""
    return False


def _resolve_interface_type_slug(cell_val: str):
    """NetBox Interface.type choice value from drift cell (slug or human label)."""
    try:
        from dcim.models import Interface
    except Exception:
        return None
    s = str(cell_val or "").strip()
    if not s or s in ("—", "-"):
        return None
    field = Interface._meta.get_field("type")
    ch = getattr(field, "choices", None) or []
    slow = s.lower()
    for val, lab in ch:
        if val is None or val == "":
            continue
        if str(val).strip().lower() == slow:
            return val
    for val, lab in ch:
        if str(lab).strip().lower() == slow:
            return val
    return None


def _ensure_tag_on_branch(slug: str, name: str) -> Any:
    """Get or create a Tag using the active branch alias so it lands in the branch schema."""
    from extras.models import Tag

    a = _orm_alias()
    mgr = Tag.objects.using(a) if a else Tag.objects
    nm = str(name or "")
    tag, _ = mgr.get_or_create(
        slug=slug,
        defaults={"name": nm[:100] if len(nm) <= 100 else nm[:97] + "..."},
    )
    return tag


def _merge_interface_role_tag(iface, label_cell: str) -> bool:
    """Attach a Tag named like the drift role (Management, Data, …) when non-empty."""
    from django.utils.text import slugify

    raw = str(label_cell or "").strip()
    if not raw or raw in ("—", "-"):
        return False
    if raw.upper() == "DATA":
        raw = "Data"
    slug_base = slugify(raw) or "tag"
    slug = slug_base[:50]
    disp = raw[:100] if len(raw) <= 100 else raw[:97] + "..."
    tag = _ensure_tag_on_branch(slug, disp)
    a = _orm_alias()
    rel = iface.tags
    # NetBox returns RestrictedQuerySet from rel.using(...); it has no .add(). Scope reads only.
    if a is not None:
        if rel.using(a).filter(pk=tag.pk).exists():
            return False
    else:
        if rel.filter(pk=tag.pk).exists():
            return False
    rel.add(tag)
    return True


def _merge_device_tags(device, tag_cell: str) -> bool:
    tag_cell = str(tag_cell or "").strip()
    if not tag_cell:
        return False
    changed = False
    names = [x.strip() for x in re.split(r"[,;]", tag_cell) if x.strip()]
    a = _orm_alias()
    rel = device.tags
    for name in names:
        slug_base = slugify(name) or "tag"
        slug = slug_base[:50]
        disp = name[:100] if len(name) <= 100 else name[:97] + "..."
        tag = _ensure_tag_on_branch(slug, disp)
        if a is not None:
            has_tag = rel.using(a).filter(pk=tag.pk).exists()
        else:
            has_tag = rel.filter(pk=tag.pk).exists()
        if not has_tag:
            rel.add(tag)
            changed = True
    return changed


# Detail — new devices: MAAS / OS / audit columns -> NetBox Device custom field `key` (first existing wins).
# Add Custom Fields on Device with any of these keys (type text is enough) to populate from drift apply.
_NEW_DEVICE_DRIFT_TO_CF_KEYS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("OS region", ("os_region", "drift_os_region")),
    ("OS provision", ("os_provision", "drift_os_provision")),
    ("OS power", ("os_power", "drift_os_power")),
    ("OS maintenance", ("os_maintenance", "drift_os_maintenance")),
    ("MAAS fabric", ("maas_fabric", "drift_maas_fabric")),
    ("MAAS status", ("maas_status", "drift_maas_status")),
    ("Authority", ("drift_authority", "authority")),
)


def _custom_field_targets_model(cf: Any, model_cls: type) -> bool:
    from django.contrib.contenttypes.models import ContentType

    try:
        ct = ContentType.objects.get_for_model(model_cls, for_concrete_model=False)
    except Exception:
        return False
    try:
        rel = getattr(cf, "content_types", None)
        if rel is not None and hasattr(rel, "filter"):
            if rel.filter(pk=ct.pk).exists():
                return True
    except Exception:
        pass
    try:
        rel = getattr(cf, "object_types", None)
        if rel is not None and hasattr(rel, "filter"):
            app, name = model_cls._meta.app_label, model_cls._meta.model_name
            if rel.filter(app_label=app, model=name).exists():
                return True
    except Exception:
        pass
    return False


@lru_cache(maxsize=1)
def _device_custom_field_keys_cached() -> frozenset[str]:
    try:
        from dcim.models import Device
        from extras.models import CustomField
    except Exception:
        return frozenset()
    keys: set[str] = set()
    for cf in CustomField.objects.iterator():
        if not _custom_field_targets_model(cf, Device):
            continue
        k = getattr(cf, "key", None)
        if k:
            keys.add(str(k))
    return frozenset(keys)


def _merge_new_device_row_into_custom_fields(device: Any, cells: dict[str, str]) -> tuple[bool, set[str]]:
    """
    Write drift source columns into Device.custom_field_data when matching Custom Field keys exist.

    Returns (device_custom_field_data_changed, drift_headers_applied).
    """
    valid = _device_custom_field_keys_cached()
    if not valid or not hasattr(device, "custom_field_data"):
        return False, set()
    data = dict(device.custom_field_data or {})
    changed = False
    applied_headers: set[str] = set()
    for header, slug_opts in _NEW_DEVICE_DRIFT_TO_CF_KEYS:
        val = _cell(cells, header)
        if not val or val in ("—", "-"):
            continue
        for slug in slug_opts:
            if slug not in valid:
                continue
            if data.get(slug) != val:
                data[slug] = val
                changed = True
            applied_headers.add(header)
            break
    if changed:
        device.custom_field_data = data
    return changed, applied_headers


def _meaningful_cell_val(v: str | None) -> bool:
    vv = "" if v is None else str(v).strip()
    return bool(vv and vv not in ("—", "-"))


# Detail — new prefixes: ordered snapshot lines (must match drift table headers).
_NEW_PREFIX_DRIFT_SNAPSHOT_HEADERS: tuple[str, ...] = (
    "OS region",
    "CIDR",
    "OS Description",
    "NB Proposed Prefix description (editable)",
    "NB Proposed Scope",
    "NB Proposed VLAN",
    "NB proposed role",
    "Role reason",
    "NB proposed status",
    "NB proposed VRF",
    "Authority",
)

_NEW_PREFIX_DRIFT_TO_CF_KEYS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("OS region", ("openstack_region", "os_region", "region")),
    ("OS Description", ("openstack_description", "os_description", "os_subnet_description")),
    ("Role reason", ("role_reason", "drift_role_reason")),
    ("Authority", ("drift_authority", "authority")),
)


@lru_cache(maxsize=16)
def _prefix_custom_field_keys_cached(router_key: str) -> frozenset[str]:
    try:
        from ipam.models import Prefix
        from extras.models import CustomField
    except Exception:
        return frozenset()
    keys: set[str] = set()
    if router_key == "__router__":
        qs = CustomField.objects
    else:
        qs = CustomField.objects.using(router_key)
    for cf in qs.iterator():
        if not _custom_field_targets_model(cf, Prefix):
            continue
        k = getattr(cf, "key", None)
        if k:
            keys.add(str(k))
    return frozenset(keys)


def _merge_prefix_row_into_custom_fields(prefix_obj: Any, cells: dict[str, str]) -> tuple[bool, set[str]]:
    """Map drift columns into Prefix.custom_field_data when matching Custom Field keys exist."""
    valid = _prefix_custom_field_keys_cached(_orm_cache_key_for_cf_lists())
    if not valid or not hasattr(prefix_obj, "custom_field_data"):
        return False, set()
    data = dict(prefix_obj.custom_field_data or {})
    changed = False
    applied_headers: set[str] = set()
    for header, slug_opts in _NEW_PREFIX_DRIFT_TO_CF_KEYS:
        val = _cell(cells, header)
        if not _meaningful_cell_val(val):
            continue
        for slug in slug_opts:
            if slug not in valid:
                continue
            if data.get(slug) != val:
                data[slug] = val
                changed = True
            applied_headers.add(header)
            break
    if changed:
        prefix_obj.custom_field_data = data
    return changed, applied_headers


def _prefix_description_max_len() -> int:
    from ipam.models import Prefix

    f = Prefix._meta.get_field("description")
    ml = getattr(f, "max_length", None)
    return int(ml) if ml else 4000


def _prefix_description_from_cells(cells: dict[str, str], *, max_len: int) -> str:
    """NetBox Prefix.description: operator-editable column only (drift lives in typed fields / CF)."""
    editable = strip_prefix_description_audit_suffix(
        _cell(cells, "NB Proposed Prefix description (editable)")
    )
    if max_len and len(editable) > max_len:
        return editable[: max_len - 3] + "..."
    return editable


def _prefix_apply_row_stepwise_changelog(
    prefix_obj: Any,
    *,
    vrf: Any,
    status_name: str,
    role: Any,
    scope_obj: Any,
    vlan_obj: Any,
    full_descr: str,
    cells: dict[str, str],
) -> bool:
    """
    Apply prefix row fields with one save per changed attribute so netbox-branching diffs
    list vrf/status/role/scope/vlan/description (not only the first delta).

    OpenStack prefix drift does not propose ``Prefix.tenant``; existing tenant on update is
    left unchanged.
    """
    from ipam.models import Prefix

    if not isinstance(prefix_obj, Prefix):
        return False
    any_save = False
    if vrf is not None and getattr(prefix_obj, "vrf_id", None) != vrf.pk:
        with _tx_branch():
            _netbox_changelog_snapshot(prefix_obj)
            prefix_obj.vrf = vrf
            prefix_obj.save(**_save_branch())
        any_save = True
    if status_name:
        val = _pick_choice_value(prefix_obj._meta.get_field("status"), status_name)
        if val is not None and prefix_obj.status != val:
            with _tx_branch():
                _netbox_changelog_snapshot(prefix_obj)
                prefix_obj.status = val
                prefix_obj.save(**_save_branch())
            any_save = True
    if role is not None and getattr(prefix_obj, "role_id", None) != role.pk:
        with _tx_branch():
            _netbox_changelog_snapshot(prefix_obj)
            prefix_obj.role = role
            prefix_obj.save(**_save_branch())
        any_save = True
    if scope_obj is not None and hasattr(prefix_obj, "scope"):
        cur = getattr(prefix_obj, "scope", None)
        if cur is None or getattr(cur, "pk", None) != scope_obj.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(prefix_obj)
                prefix_obj.scope = scope_obj
                prefix_obj.save(**_save_branch())
            any_save = True
    if vlan_obj is not None and hasattr(prefix_obj, "vlan_id"):
        if prefix_obj.vlan_id != vlan_obj.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(prefix_obj)
                prefix_obj.vlan = vlan_obj
                prefix_obj.save(**_save_branch())
            any_save = True
    if hasattr(prefix_obj, "description"):
        want = (full_descr or "").strip()
        if (prefix_obj.description or "").strip() != want:
            with _tx_branch():
                _netbox_changelog_snapshot(prefix_obj)
                prefix_obj.description = full_descr
                prefix_obj.save(**_save_branch())
            any_save = True
    cf_ch, _ = _merge_prefix_row_into_custom_fields(prefix_obj, cells)
    if cf_ch:
        with _tx_branch():
            _netbox_changelog_snapshot(prefix_obj)
            prefix_obj.save(**_save_branch())
        any_save = True
    return any_save


def _device_apply_row_stepwise_changelog(
    dev: Any,
    *,
    site: Any,
    location: Any,
    role: Any,
    dtype: Any,
    status_name: str,
    serial: str,
    platform_obj: Any,
    tag_cell: str,
    cells: dict[str, str],
    placement: bool,
) -> bool:
    """
    One netbox-branching save per changed device attribute (placement FKs, status, serial,
    platform, tags, custom fields) so the branch diff lists each column, not only the first.
    """
    from dcim.models import Device

    if not isinstance(dev, Device):
        return False
    any_save = False
    if placement:
        if site is not None and dev.site_id != site.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(dev)
                dev.site = site
                dev.save(**_save_branch())
            any_save = True
        if location is not None and getattr(dev, "location_id", None) != location.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(dev)
                dev.location = location
                dev.save(**_save_branch())
            any_save = True
        if role is not None and dev.role_id != role.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(dev)
                dev.role = role
                dev.save(**_save_branch())
            any_save = True
        if dtype is not None and dev.device_type_id != dtype.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(dev)
                dev.device_type = dtype
                dev.save(**_save_branch())
            any_save = True
    if status_name:
        val = _pick_choice_value(dev._meta.get_field("status"), status_name)
        if val is not None and dev.status != val:
            with _tx_branch():
                _netbox_changelog_snapshot(dev)
                dev.status = val
                dev.save(**_save_branch())
            any_save = True
    sn = (serial or "").strip()
    if sn and hasattr(dev, "serial") and (dev.serial or "") != sn[:50]:
        with _tx_branch():
            _netbox_changelog_snapshot(dev)
            dev.serial = sn[:50]
            dev.save(**_save_branch())
        any_save = True
    if platform_obj is not None and hasattr(dev, "platform_id"):
        if getattr(dev, "platform_id", None) != platform_obj.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(dev)
                dev.platform = platform_obj
                dev.save(**_save_branch())
            any_save = True
    if tag_cell and _merge_device_tags(dev, tag_cell):
        with _tx_branch():
            _netbox_changelog_snapshot(dev)
            dev.save(**_save_branch())
        any_save = True
    cf_changed, _ = _merge_new_device_row_into_custom_fields(dev, cells)
    if cf_changed:
        with _tx_branch():
            _netbox_changelog_snapshot(dev)
            dev.save(**_save_branch())
        any_save = True
    return any_save


def _vid_in_single_vlan_vid_range(vid_i: int, r) -> bool:
    """
    True if ``vid_i`` falls in one VLAN group range row.

    NetBox ``VLAN.clean`` uses ``vid in range``. Some drivers / range types do not
    implement ``__contains__`` reliably for plain ints, so we also use discrete bounds
    (same lower/upper_inc idea as NetBox's VLANGroup range validation).
    """
    try:
        if vid_i in r:
            return True
    except Exception:
        pass
    try:
        lo_raw = r.lower
        hi_raw = r.upper
        if lo_raw is None or hi_raw is None:
            return False
        lo_inc = getattr(r, "lower_inc", True)
        hi_inc = getattr(r, "upper_inc", True)
        lo = int(lo_raw) if lo_inc else int(lo_raw) + 1
        hi = int(hi_raw) if hi_inc else int(hi_raw) - 1
        return lo <= vid_i <= hi
    except (TypeError, ValueError, AttributeError):
        return False


def _vid_allowed_in_netbox_vlan_group(vid_i: int, grp) -> bool:
    """Mirror NetBox ``VLAN.clean``: VID must fall within at least one of the group's ``vid_ranges``."""
    if grp is None:
        return True
    ranges = getattr(grp, "vid_ranges", None)
    if ranges is None:
        return True
    if len(ranges) == 0:
        return False
    for vid_range in ranges:
        if _vid_in_single_vlan_vid_range(vid_i, vid_range):
            return True
    return False


def _format_django_validation_error(exc: DjangoValidationError) -> str:
    if hasattr(exc, "message_dict") and exc.message_dict:
        parts: list[str] = []
        for k, msgs in exc.message_dict.items():
            bits = [str(m) for m in msgs] if hasattr(msgs, "__iter__") and not isinstance(
                msgs, str
            ) else [str(msgs)]
            label = k if k != "__all__" else "validation"
            parts.append(f"{label}: {'; '.join(bits)}")
        return "; ".join(parts)
    if hasattr(exc, "messages"):
        return "; ".join(str(m) for m in exc.messages)
    return str(exc)


def apply_create_vlan(op: dict[str, Any]) -> tuple[str, str]:
    from ipam.models import VLAN, VLANGroup

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason

    group_name = _cell(cells, "NB proposed VLAN group").strip()
    vid_raw = _cell(cells, "NB Proposed VLAN ID", "Target VID").strip()
    vid_i = _parse_vlan_vid(vid_raw)
    if vid_i is None:
        return _skip_missing_prereq("NB Proposed VLAN ID missing or not an integer (1–4094).")
    if vid_i < 1 or vid_i > _NETBOX_IEEE_VLAN_VID_MAX:
        return _skip_missing_prereq(
            f"NB Proposed VLAN ID {vid_i} is outside IEEE 802.1Q 1–{_NETBOX_IEEE_VLAN_VID_MAX}."
        )
    if not group_name or group_name in {"—", "-"}:
        return _skip_missing_prereq(
            "NB proposed VLAN group is empty — pick a VLAN group scoped to the site/location for this VID."
        )

    grp = _orm_qs(VLANGroup).filter(name__iexact=group_name).first()
    if grp is None:
        return _skip_missing_prereq(f'VLAN group "{group_name}" not found in NetBox.')

    if not _vid_allowed_in_netbox_vlan_group(vid_i, grp):
        return _skip_missing_prereq(
            f'VID {vid_i} is not inside any VLAN ID range configured on NetBox VLAN group '
            f'"{group_name}". Edit the group in IPAM (VLAN ID ranges) to include {vid_i}, '
            f"or pick another group on the drift row."
        )

    from dcim.models import Site

    site_obj: Any | None = None
    try:
        VLAN._meta.get_field("site")
    except FieldDoesNotExist:
        pass
    else:
        raw_site = (_cell(cells, "NB site") or "").strip()
        if not raw_site or raw_site in {"—", "-"}:
            return _skip_missing_prereq(
                "NB site is required on proposed missing VLAN rows — set it (e.g. B52) so the "
                "VLAN is created with the same Site as your devices (needed for interface "
                "untagged VLAN resolution)."
            )
        site_obj = _resolve_by_name(Site, raw_site, using=_orm_alias())
        if site_obj is None:
            return _skip_missing_prereq(
                f'NB site "{raw_site}" not found in NetBox — create the Site or fix the cell.'
            )

    gfk = "group" if any(f.name == "group" for f in VLAN._meta.fields) else "vlan_group"
    existing = _orm_qs(VLAN).filter(**{gfk: grp, "vid": vid_i}).first()
    if existing is not None:
        return "skipped", "skipped_already_desired"

    name = _cell(
        cells, "NB proposed VLAN name (editable)", "NB proposed VLAN name"
    ).strip()
    if not name or name in ("—", "-"):
        name = f"VLAN-{vid_i}"

    dup_name = (
        _orm_qs(VLAN).filter(**{gfk: grp}).filter(name__iexact=name).exclude(vid=vid_i).first()
    )
    if dup_name is not None:
        return _skip_missing_prereq(
            f'In VLAN group "{group_name}", name "{name}" is already used by VID {dup_name.vid}. '
            f"NetBox requires unique names per group. Rename this proposed VLAN or edit the existing one."
        )

    tenant_name = (_cell(cells, "NB Proposed Tenant") or "").strip()
    status_name = (_cell(cells, "NB proposed status") or "").strip() or "active"

    tenant = None
    if tenant_name and tenant_name not in {"—", "-"}:
        tenant = _resolve_tenant(tenant_name, using=_orm_alias())
        if tenant is None:
            return _skip_missing_prereq(
                f'Tenant "{tenant_name}" not resolved — fix NB Proposed Tenant or create the tenant.'
            )

    # Phase 1: minimal identity save — NetBox branching records "Created" with VID/name/group.
    vlan = VLAN(vid=vid_i, name=name)
    setattr(vlan, gfk, grp)
    try:
        # validate_unique=False: our branch-scoped existence checks above already guard
        # against duplicates in the branch schema; passing False avoids full_clean() querying
        # the default (main) DB for uniqueness, which would raise a false ValidationError for
        # VLANs that exist in main from a prior bad run but are absent from the branch.
        # The branch DB enforces the real constraint — any true duplicate triggers IntegrityError below.
        vlan.full_clean(validate_unique=False)
        # First insert under ``atomic(using=branch)`` like VM/interface creates — matches
        # netbox-branching expectations for routed writes (bare save was associated with main leaks).
        with _tx_branch():
            vlan.save(**_save_branch())
    except DjangoValidationError as e:
        detail = _format_django_validation_error(e)
        logger.info("apply_create_vlan validation (vid=%s group=%s): %s", vid_i, group_name, detail)
        return _skip_missing_prereq(f"NetBox rejected the VLAN: {detail}")
    except IntegrityError as e:
        em = str(e).strip() or repr(e)
        logger.info("apply_create_vlan integrity (vid=%s group=%s): %s", vid_i, group_name, em)
        return _skip_missing_prereq(
            f"VLAN save hit a database constraint (often duplicate name or VID in this group): {em}"
        )
    except Exception as e:
        logger.exception("apply_create_vlan: save failed (vid=%s group=%s)", vid_i, group_name)
        et = type(e).__name__
        em = (str(e) or "").strip() or et
        detail = f"{et}: {em}"
        if len(detail) > 2000:
            detail = detail[:1997] + "..."
        return "failed", "failed_validation_save", detail

    # Phase 2: one save per metadata field, each in its own savepoint so netbox_branching
    # cannot collapse them into a single diff row (status / site / tenant show separately).
    st_f = vlan._meta.get_field("status")
    st_val = _pick_choice_value(st_f, status_name)
    if st_val is not None and vlan.status != st_val:
        with _tx_branch():
            _netbox_changelog_snapshot(vlan)
            vlan.status = st_val
            vlan.save(**_save_branch())
    if site_obj is not None and hasattr(vlan, "site_id") and getattr(vlan, "site_id", None) != site_obj.pk:
        with _tx_branch():
            _netbox_changelog_snapshot(vlan)
            vlan.site = site_obj
            vlan.save(**_save_branch())
    if tenant is not None and hasattr(vlan, "tenant_id") and getattr(vlan, "tenant_id", None) != tenant.pk:
        with _tx_branch():
            _netbox_changelog_snapshot(vlan)
            vlan.tenant = tenant
            vlan.save(**_save_branch())
    _log_reconciliation_orm_write(
        entity="vlan",
        apply_action="create_vlan",
        op=op,
        message=f"created pk={getattr(vlan, 'pk', None)} vid={vid_i} name={name!r} group={group_name!r}",
    )
    return "created", "ok_created"


def apply_create_tenant(op: dict[str, Any]) -> tuple[str, str]:
    from tenancy.models import Tenant

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason

    proj = netbox_write_projection_for_op(op)
    name = (proj.get("name") or "").strip()
    if not name or name in {"—", "-"}:
        return _skip_missing_prereq(
            "Tenant name empty — set NB proposed tenant name (defaults from OpenStack project on the row)."
        )
    if _resolve_tenant(name, using=_orm_alias()) is not None:
        return "skipped", "skipped_already_desired"

    descr = (proj.get("description") or "").strip()
    base = slugify(name)[:80] or "tenant"
    slug = base
    mgr = Tenant.objects.using(_orm_alias()) if _orm_alias() else Tenant.objects
    n = 2
    while mgr.filter(slug=slug).exists():
        suffix = f"-{n}"
        slug = (base[: max(1, 80 - len(suffix))] + suffix)[:80]
        n += 1

    tenant = Tenant(name=name, slug=slug)
    if descr:
        try:
            df = Tenant._meta.get_field("description")
            ml = int(getattr(df, "max_length", None) or 4000)
            tenant.description = descr[:ml]
        except FieldDoesNotExist:
            pass
    try:
        tenant.full_clean(validate_unique=False)
        with _tx_branch():
            tenant.save(**_save_branch())
    except DjangoValidationError as e:
        detail = _format_django_validation_error(e)
        return _skip_missing_prereq(f"NetBox rejected the tenant: {detail}")
    except IntegrityError as e:
        em = str(e).strip() or repr(e)
        return _skip_missing_prereq(f"Tenant save hit a database constraint: {em}")
    except Exception as e:
        logger.exception("apply_create_tenant: save failed (name=%s)", name)
        et = type(e).__name__
        em = (str(e) or "").strip() or et
        detail = f"{et}: {em}"
        if len(detail) > 2000:
            detail = detail[:1997] + "..."
        return "failed", "failed_validation_save", detail

    try:
        from netbox_automation_plugin.sync.reporting.drift_report.drift_nb_picker_catalog import (
            drift_picker_tenant_label_allowlist,
        )

        drift_picker_tenant_label_allowlist.cache_clear()
    except Exception:
        pass
    return "created", "ok_created"


def apply_create_prefix(op: dict[str, Any]) -> tuple[str, str]:
    from ipam.models import Prefix, Role, VRF

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    cidr = (proj.get("prefix") or "").strip()
    vrf_name = (proj.get("vrf") or "").strip()
    status_name = (proj.get("status") or "").strip()
    role_name = (proj.get("role") or "").strip()
    scope_name = (proj.get("scope") or "").strip()
    vlan_name = (proj.get("vlan") or "").strip()
    full_descr = (proj.get("description") or "").strip()
    # Drift columns map to typed fields / CF; description is editable column only (no audit dump).
    if not cidr:
        return _skip_missing_prereq("Prefix/CIDR empty in row projection (expected from drift NB/OS prefix columns).")
    vrf = _resolve_by_name(VRF, vrf_name, using=_orm_alias()) if vrf_name else None
    if vrf_name and vrf is None:
        return _skip_missing_prereq(f'VRF "{vrf_name}" not found in NetBox (create it or fix NB proposed VRF).')
    role = _resolve_by_name(Role, role_name, using=_orm_alias()) if role_name else None
    if role_name and role is None:
        return _skip_missing_prereq(f'IPAM role "{role_name}" not found in NetBox (create it or fix NB proposed role).')
    scope_obj = None
    if scope_name and scope_name not in {"—", "-"}:
        try:
            from dcim.models import Location

            scope_obj = _resolve_by_name(Location, scope_name, using=_orm_alias())
        except Exception:
            scope_obj = None
        if scope_obj is None:
            return _skip_missing_prereq(
                f'Prefix scope location "{scope_name}" not found in NetBox (Location for prefix scope).'
            )
    vlan_obj = None
    if vlan_name and vlan_name not in {"—", "-"}:
        vg_hint = (_cell(cells, "NB proposed VLAN group") or "").strip()
        try:
            vlan_obj = _resolve_vlan_for_prefix_scope(
                vlan_name,
                scope_obj,
                vlan_group_hint=vg_hint or None,
            )
        except Exception:
            vlan_obj = None
        if vlan_obj is None:
            try:
                pfx_dbg = _vlan_resolution_snapshot_for_prefix(
                    vlan_name, scope_obj, vg_hint or None
                )
            except Exception as ex:
                pfx_dbg = {"vlan_snapshot_error": f"{type(ex).__name__}: {ex}"}
            _merge_apply_extra_debug(vlan_resolution=pfx_dbg)
            return _skip_missing_prereq(
                f'VLAN "{vlan_name}" not resolved for this prefix scope '
                f'(create/link VLAN under site/location or fix name/VID in drift).'
            )
    prefix_pk_raw = _cell(cells, "NetBox prefix ID")
    existing = None
    if prefix_pk_raw and str(prefix_pk_raw).strip().isdigit():
        existing = _orm_qs(Prefix).filter(pk=int(str(prefix_pk_raw).strip())).first()
    if existing is None:
        existing = _orm_qs(Prefix).filter(prefix=cidr, vrf=vrf).first()
    if existing is not None:
        if _prefix_apply_row_stepwise_changelog(
            existing,
            vrf=vrf,
            status_name=status_name,
            role=role,
            scope_obj=scope_obj,
            vlan_obj=vlan_obj,
            full_descr=full_descr,
            cells=cells,
        ):
            _log_reconciliation_orm_write(
                entity="prefix",
                apply_action="create_prefix",
                op=op,
                message=f"updated pk={getattr(existing, 'pk', None)} prefix={cidr!r}",
            )
            return "updated", "ok_updated"
        return "skipped", "skipped_already_desired"
    obj = Prefix(prefix=cidr, vrf=vrf)
    try:
        obj.full_clean(validate_unique=False)
    except DjangoValidationError as e:
        return _skip_missing_prereq(
            f"NetBox rejected the prefix: {_format_django_validation_error(e)}"
        )
    try:
        obj.save(**_save_branch())
    except Exception:
        logger.debug(
            "Prefix two-phase create: initial minimal save failed; retry minimal then stepwise or single save (prefix=%s)",
            cidr,
            exc_info=True,
        )
        pfx = Prefix(prefix=cidr, vrf=vrf)
        try:
            pfx.full_clean(validate_unique=False)
        except DjangoValidationError as e:
            return _skip_missing_prereq(
                f"NetBox rejected the prefix: {_format_django_validation_error(e)}"
            )
        try:
            pfx.save(**_save_branch())
        except Exception:
            logger.debug(
                "Prefix minimal save failed again; single create with all fields (prefix=%s)",
                cidr,
                exc_info=True,
            )
            pfx = Prefix(prefix=cidr, vrf=vrf)
            if status_name:
                val = _pick_choice_value(pfx._meta.get_field("status"), status_name)
                if val is not None:
                    pfx.status = val
            if role is not None:
                pfx.role = role
            if scope_obj is not None and hasattr(pfx, "scope"):
                pfx.scope = scope_obj
            if vlan_obj is not None and hasattr(pfx, "vlan"):
                pfx.vlan = vlan_obj
            if hasattr(pfx, "description"):
                pfx.description = full_descr
            _merge_prefix_row_into_custom_fields(pfx, cells)
            try:
                pfx.full_clean(validate_unique=False)
            except DjangoValidationError as e:
                return _skip_missing_prereq(
                    f"NetBox rejected the prefix: {_format_django_validation_error(e)}"
                )
            pfx.save(**_save_branch())
            _log_reconciliation_orm_write(
                entity="prefix",
                apply_action="create_prefix",
                op=op,
                message=f"created pk={getattr(pfx, 'pk', None)} prefix={cidr!r} (fallback path)",
            )
            return "created", "ok_created"
        _prefix_apply_row_stepwise_changelog(
            pfx,
            vrf=None,
            status_name=status_name,
            role=role,
            scope_obj=scope_obj,
            vlan_obj=vlan_obj,
            full_descr=full_descr,
            cells=cells,
        )
        _log_reconciliation_orm_write(
            entity="prefix",
            apply_action="create_prefix",
            op=op,
            message=f"created pk={getattr(pfx, 'pk', None)} prefix={cidr!r}",
        )
        return "created", "ok_created"

    _prefix_apply_row_stepwise_changelog(
        obj,
        vrf=None,
        status_name=status_name,
        role=role,
        scope_obj=scope_obj,
        vlan_obj=vlan_obj,
        full_descr=full_descr,
        cells=cells,
    )
    _log_reconciliation_orm_write(
        entity="prefix",
        apply_action="create_prefix",
        op=op,
        message=f"created pk={getattr(obj, 'pk', None)} prefix={cidr!r}",
    )
    return "created", "ok_created"


def apply_create_ip_range(op: dict[str, Any]) -> tuple[str, str]:
    from ipam.models import IPRange, Role, VRF

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    start_addr = (proj.get("start_address") or "").strip()
    end_addr = (proj.get("end_address") or "").strip()
    status_name = (proj.get("status") or "").strip()
    role_name = (proj.get("role") or "").strip()
    vrf_name = (proj.get("vrf") or "").strip()
    descr = (proj.get("description") or "").strip()
    if status_name in {"—", "-"}:
        status_name = ""
    if role_name in {"—", "-"}:
        role_name = ""
    if vrf_name in {"—", "-"}:
        vrf_name = ""
    consumed = {
        _norm_header("OS region"),
        _norm_header("CIDR"),
        _norm_header("Start address"),
        _norm_header("End address"),
        _norm_header("OS Pool Description"),
        _norm_header("NB Proposed Description"),
        _norm_header("Project"),
        _norm_header("NB proposed status"),
        _norm_header("NB proposed role"),
        _norm_header("NB proposed VRF"),
        _norm_header("Authority"),
        _norm_header("Proposed Action"),
    }
    if not start_addr or not end_addr:
        return _skip_missing_prereq("IP range start/end address empty in row projection.")
    vrf = _resolve_by_name(VRF, vrf_name, using=_orm_alias()) if vrf_name else None
    if vrf_name and vrf is None:
        return _skip_missing_prereq(f'VRF "{vrf_name}" not found in NetBox (NB proposed VRF).')
    role = _resolve_by_name(Role, role_name, using=_orm_alias()) if role_name else None
    if role_name and role is None:
        return _skip_missing_prereq(f'IPAM role "{role_name}" not found in NetBox (NB proposed role).')
    existing = _orm_qs(IPRange).filter(
        start_address=start_addr,
        end_address=end_addr,
        vrf=vrf,
    ).first()
    if existing is not None:
        _netbox_changelog_snapshot(existing)
        changed = False
        if status_name:
            val = _pick_choice_value(existing._meta.get_field("status"), status_name)
            if val is not None and existing.status != val:
                existing.status = val
                changed = True
        if role is not None and getattr(existing, "role_id", None) != role.pk:
            existing.role = role
            changed = True
        if descr and hasattr(existing, "description"):
            if (existing.description or "") != descr[:2000]:
                existing.description = descr[:2000]
                changed = True
        merge_ch = _merge_audit_residual_onto_object(
            existing, cells, consumed, attr_names=("description",), max_len=4000
        )
        if changed or merge_ch:
            existing.save(**_save_branch())
            return "updated", "ok_updated"
        return "skipped", "skipped_already_desired"
    obj = IPRange(start_address=start_addr, end_address=end_addr, vrf=vrf)
    try:
        obj.save(**_save_branch())
    except Exception:
        logger.debug(
            "IPRange two-phase create: initial minimal save failed; retry minimal then field saves or single save (%s–%s)",
            start_addr,
            end_addr,
            exc_info=True,
        )
        rng = IPRange(start_address=start_addr, end_address=end_addr, vrf=vrf)
        try:
            rng.save(**_save_branch())
        except Exception:
            logger.debug(
                "IPRange minimal save failed again; single create with all fields (%s–%s)",
                start_addr,
                end_addr,
                exc_info=True,
            )
            rng = IPRange(start_address=start_addr, end_address=end_addr, vrf=vrf)
            if status_name:
                val = _pick_choice_value(rng._meta.get_field("status"), status_name)
                if val is not None:
                    rng.status = val
            if role is not None and hasattr(rng, "role"):
                rng.role = role
            if descr and hasattr(rng, "description"):
                rng.description = descr[:2000]
            rng.save(**_save_branch())
            return "created", "ok_created"
        _netbox_changelog_snapshot(rng)
        phase2_fb = False
        if status_name:
            val = _pick_choice_value(rng._meta.get_field("status"), status_name)
            if val is not None:
                rng.status = val
                phase2_fb = True
        if role is not None and hasattr(rng, "role"):
            rng.role = role
            phase2_fb = True
        if descr and hasattr(rng, "description"):
            rng.description = descr[:2000]
            phase2_fb = True
        if _merge_audit_residual_onto_object(rng, cells, consumed, attr_names=("description",), max_len=4000):
            phase2_fb = True
        if phase2_fb:
            rng.save(**_save_branch())
        return "created", "ok_created"

    _netbox_changelog_snapshot(obj)
    phase2 = False
    if status_name:
        val = _pick_choice_value(obj._meta.get_field("status"), status_name)
        if val is not None:
            obj.status = val
            phase2 = True
    if role is not None and hasattr(obj, "role"):
        obj.role = role
        phase2 = True
    if descr and hasattr(obj, "description"):
        obj.description = descr[:2000]
        phase2 = True
    if _merge_audit_residual_onto_object(obj, cells, consumed, attr_names=("description",), max_len=4000):
        phase2 = True
    if phase2:
        obj.save(**_save_branch())
    return "created", "ok_created"


# Detail — new floating IPs (headers must match format_html_proposed / xlsx_export).
_NEW_FIP_DRIFT_SNAPSHOT_HEADERS: tuple[str, ...] = (
    "OS region",
    "Floating IP",
    "Name",
    "NAT inside IP (from OpenStack fixed IP)",
    "NB Proposed Tenant",
    "NB proposed status",
    "NB proposed role",
    "NB proposed VRF",
    "NB proposed parent prefix",
)

_NEW_FIP_DRIFT_TO_CF_KEYS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("OS region", ("openstack_region", "os_region", "region")),
    ("Name", ("floating_ip_name", "fip_name")),
    ("Project", ("openstack_project", "project")),
    ("NAT inside IP (from OpenStack fixed IP)", ("nat_inside_hint", "fixed_ip", "openstack_fixed_ip")),
    (
        "NB proposed parent prefix",
        ("floating_pool_prefix", "openstack_floating_pool_prefix", "parent_prefix", "fip_parent_prefix"),
    ),
)

# VM custom fields: projection key -> NetBox custom_field keys (single source with preview + apply).
_VM_PROJECTION_CF_KEYS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "nova_compute_host",
        (
            "nova_compute_host",
            "openstack_hypervisor_hostname",
            "hypervisor_hostname",
            "os_hypervisor_host",
        ),
    ),
)
# When projection omits a value, fall back to this drift header (same cells as op).
_VM_CF_DRIFT_FALLBACK: dict[str, str] = {
    "nova_compute_host": "Hypervisor hostname",
}


def _orm_cache_key_for_cf_lists() -> str:
    """Stable cache key for branch-scoped extras queries (matches ``_orm_alias()`` routing)."""
    a = _orm_alias()
    return "__router__" if a is None else a


@lru_cache(maxsize=1)
def _vm_custom_field_keys_cached() -> frozenset[str]:
    """
    CustomField definitions are global NetBox metadata; use the default manager.

    Do **not** use ``.using(branch_alias)`` here — ``extras.CustomField`` is not written on
    branch shards the same way as IPAM/VM rows; a wrong alias can yield empty keys or odd
    routing side effects during VM apply.
    """
    try:
        from extras.models import CustomField
        from virtualization.models import VirtualMachine
    except Exception:
        return frozenset()
    keys: set[str] = set()
    for cf in CustomField.objects.iterator():
        if not _custom_field_targets_model(cf, VirtualMachine):
            continue
        k = getattr(cf, "key", None)
        if k:
            keys.add(str(k))
    return frozenset(keys)


def _merge_vm_row_into_custom_fields(
    vm: Any, cells: dict[str, str], proj: dict[str, str]
) -> tuple[bool, set[str]]:
    """Write VM custom fields from ``proj`` (preferred) with drift fallback; keys from ``_VM_PROJECTION_CF_KEYS``."""
    valid = _vm_custom_field_keys_cached()
    if not valid or not hasattr(vm, "custom_field_data"):
        return False, set()
    data = dict(vm.custom_field_data or {})
    changed = False
    applied_proj_keys: set[str] = set()
    for proj_key, slug_opts in _VM_PROJECTION_CF_KEYS:
        val = (proj.get(proj_key) or "").strip()
        if not _meaningful_cell_val(val):
            fb = _VM_CF_DRIFT_FALLBACK.get(proj_key)
            if fb:
                val = _cell(cells, fb)
        if not _meaningful_cell_val(val):
            continue
        for slug in slug_opts:
            if slug not in valid:
                continue
            if data.get(slug) != val:
                data[slug] = val
                changed = True
            applied_proj_keys.add(proj_key)
            break
    if changed:
        vm.custom_field_data = data
    return changed, applied_proj_keys


@lru_cache(maxsize=1)
def _ip_address_custom_field_keys_cached() -> frozenset[str]:
    try:
        from extras.models import CustomField
        from ipam.models import IPAddress
    except Exception:
        return frozenset()
    keys: set[str] = set()
    for cf in CustomField.objects.iterator():
        if not _custom_field_targets_model(cf, IPAddress):
            continue
        k = getattr(cf, "key", None)
        if k:
            keys.add(str(k))
    return frozenset(keys)


def _merge_ip_address_row_into_custom_fields(ip_obj: Any, cells: dict[str, str]) -> tuple[bool, set[str]]:
    valid = _ip_address_custom_field_keys_cached()
    if not valid or not hasattr(ip_obj, "custom_field_data"):
        return False, set()
    data = dict(ip_obj.custom_field_data or {})
    changed = False
    applied_headers: set[str] = set()
    for header, slug_opts in _NEW_FIP_DRIFT_TO_CF_KEYS:
        val = _cell(cells, header)
        if not _meaningful_cell_val(val):
            continue
        for slug in slug_opts:
            if slug not in valid:
                continue
            if data.get(slug) != val:
                data[slug] = val
                changed = True
            applied_headers.add(header)
            break
    if changed:
        ip_obj.custom_field_data = data
    return changed, applied_headers


def _ip_address_description_max_len() -> int:
    from ipam.models import IPAddress

    f = IPAddress._meta.get_field("description")
    ml = getattr(f, "max_length", None)
    return int(ml) if ml else 4000


def _fip_description_from_cells(cells: dict[str, str], *, max_len: int) -> str:
    """NetBox IPAddress.description: mirror the drift report Name column only (typed fields hold the rest)."""
    body = (_cell(cells, "Name") or "").strip()
    if max_len and len(body) > max_len:
        return body[: max_len - 3] + "..."
    return body


def _resolve_nat_inside_ipaddress(inside_raw: str, vrf_preferred: Any) -> Any:
    """
    NetBox: public / floating side stores NAT inside on IPAddress.nat_inside (inside address object).
    Prefer same VRF as the floating IP, then Global (null VRF), then any single match.
    """
    from ipam.models import IPAddress

    if not _meaningful_cell_val(inside_raw):
        return None
    try:
        inside_addr = _normalize_ip_for_netbox(inside_raw)
    except ValueError:
        return None
    qs = _orm_qs(IPAddress).filter(address=inside_addr)
    if vrf_preferred is not None:
        hit = qs.filter(vrf=vrf_preferred).first()
        if hit is not None:
            return hit
    hit = qs.filter(vrf__isnull=True).first()
    if hit is not None:
        return hit
    if qs.count() == 1:
        return qs.first()
    return None


def _apply_fip_nat_inside(ip_obj: Any, cells: dict[str, str], vrf: Any) -> bool:
    if not hasattr(ip_obj, "nat_inside_id"):
        return False
    inside_raw = _cell(
        cells,
        "NAT inside IP (from OpenStack fixed IP)",
        "NAT inside IP",
    )
    inner = _resolve_nat_inside_ipaddress(inside_raw, vrf)
    if inner is None:
        return False
    if getattr(ip_obj, "nat_inside_id", None) == inner.pk:
        return False
    ip_obj.nat_inside = inner
    return True


def _resolve_floating_ip_role_value(role_name: str) -> tuple[Any | None, str | None]:
    """
    NetBox 4+: ``IPAddress.role`` is a CharField (:class:`~ipam.choices.IPAddressRoleChoices`).
    Older releases used an FK to ``ipam.Role`` (prefix/VLAN-style organizational roles).

    Returns ``(value_or_Role_instance, None)`` or ``(None, error_message)``.
    """
    from ipam.models import IPAddress

    s = (role_name or "").strip()
    if not s or s in {"—", "-"}:
        return None, None
    field = IPAddress._meta.get_field("role")
    if isinstance(field, django_models.CharField):
        val = _pick_choice_value(field, s)
        if val is None:
            return None, (
                f'IP address role "{s}" is not a valid built-in role (NB proposed role). '
                f"Use a standard label such as VIP, Secondary, Anycast, Loopback, VRRP, etc."
            )
        return val, None
    try:
        from ipam.models import Role as IpamRole
    except Exception:
        return None, "ipam.Role could not be imported for legacy IP address role FK."
    obj = _resolve_by_name(IpamRole, s, using=_orm_alias())
    if obj is None:
        return None, f'IPAM role "{s}" not found in NetBox (NB proposed role).'
    return obj, None


def _floating_ip_apply_row_stepwise(
    ip_obj: Any,
    *,
    status_name: str,
    role_value: Any | None,
    tenant_obj: Any,
    full_descr: str,
    cells: dict[str, str],
    vrf: Any,
) -> bool:
    """One branching save per changed IPAddress field (status, role, tenant, description, NAT, CF)."""
    any_save = False
    if status_name:
        val = _pick_choice_value(ip_obj._meta.get_field("status"), status_name)
        if val is not None and ip_obj.status != val:
            with _tx_branch():
                _netbox_changelog_snapshot(ip_obj)
                ip_obj.status = val
                ip_obj.save(**_save_branch())
            any_save = True
    if role_value is not None and hasattr(ip_obj, "role"):
        role_field = ip_obj._meta.get_field("role")
        role_changed = False
        if isinstance(role_field, django_models.CharField):
            role_changed = getattr(ip_obj, "role", None) != role_value
        elif isinstance(role_field, django_models.ForeignKey):
            role_changed = getattr(ip_obj, "role_id", None) != getattr(role_value, "pk", None)
        else:
            role_changed = getattr(ip_obj, "role", None) != role_value
        if role_changed:
            with _tx_branch():
                _netbox_changelog_snapshot(ip_obj)
                ip_obj.role = role_value
                ip_obj.save(**_save_branch())
            any_save = True
    if tenant_obj is not None and hasattr(ip_obj, "tenant_id") and ip_obj.tenant_id != tenant_obj.pk:
        with _tx_branch():
            _netbox_changelog_snapshot(ip_obj)
            ip_obj.tenant = tenant_obj
            ip_obj.save(**_save_branch())
        any_save = True
    if hasattr(ip_obj, "description"):
        cur = (ip_obj.description or "").strip()
        if cur != full_descr.strip():
            with _tx_branch():
                _netbox_changelog_snapshot(ip_obj)
                ip_obj.description = full_descr
                ip_obj.save(**_save_branch())
            any_save = True
    inside_raw = _cell(
        cells,
        "NAT inside IP (from OpenStack fixed IP)",
        "NAT inside IP",
    )
    inner = _resolve_nat_inside_ipaddress(inside_raw, vrf)
    if inner is not None and getattr(ip_obj, "nat_inside_id", None) != inner.pk:
        with _tx_branch():
            _netbox_changelog_snapshot(ip_obj)
            ip_obj.nat_inside = inner
            ip_obj.save(**_save_branch())
        any_save = True
    with _tx_branch():
        _netbox_changelog_snapshot(ip_obj)
        cf_ch, _ = _merge_ip_address_row_into_custom_fields(ip_obj, cells)
        if cf_ch:
            ip_obj.save(**_save_branch())
            any_save = True
    return any_save


def apply_create_floating_ip(op: dict[str, Any]) -> tuple[str, str]:
    from ipam.models import IPAddress, VRF

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    raw_ip = (proj.get("address") or "").strip()
    status_name = (proj.get("status") or "").strip()
    vrf_name = (proj.get("vrf") or "").strip()
    role_name = (proj.get("role") or "").strip()
    tenant_name = (proj.get("tenant") or "").strip()
    full_descr = (proj.get("description") or "").strip()
    dmax = _ip_address_description_max_len()
    consumed = {
        _norm_header("NB current NAT inside"),
        _norm_header("OS region"),
        _norm_header("Floating IP"),
        _norm_header("Name"),
        _norm_header("NAT inside IP (from OpenStack fixed IP)"),
        _norm_header("NB Proposed Tenant"),
        _norm_header("NB proposed status"),
        _norm_header("NB proposed role"),
        _norm_header("NB proposed VRF"),
        _norm_header("NB proposed parent prefix"),
        # Proposed Action: workflow hint only; consume so it is not merged into description.
        _norm_header("Proposed Action"),
    }
    if not raw_ip:
        return _skip_missing_prereq("Floating IP address empty in row (Floating IP column / projection).")
    vrf = _resolve_by_name(VRF, vrf_name, using=_orm_alias()) if vrf_name else None
    if vrf_name and vrf is None:
        return _skip_missing_prereq(f'VRF "{vrf_name}" not found in NetBox (NB proposed VRF for floating IP).')
    try:
        address = _normalize_floating_ip_host_mask(raw_ip)
    except ValueError:
        return "failed", "failed_validation_bad_ip"
    role_value = None
    if role_name:
        role_value, role_err = _resolve_floating_ip_role_value(role_name)
        if role_err:
            return _skip_missing_prereq(role_err)
    tenant_obj = None
    if tenant_name and tenant_name not in {"—", "-"}:
        tenant_obj = _resolve_tenant(tenant_name, using=_orm_alias())
        if tenant_obj is None:
            return _skip_missing_prereq(f'Tenant "{tenant_name}" not found in NetBox (NB Proposed Tenant).')
    elif not tenant_name:
        nb_raw = _cell(cells, "NB Proposed Tenant").strip()
        if nb_raw and nb_raw not in {"—", "-"}:
            tenant_obj = _resolve_tenant(nb_raw, using=_orm_alias())
    host_only = str(ipaddress.ip_interface(address).ip)
    existing = _find_ipaddress_for_floating_host(host_only, vrf, normalized_address=address)
    if existing is not None:
        merge_ch = _merge_audit_residual_onto_object(
            existing, cells, consumed, attr_names=("description",), max_len=max(dmax, 8000)
        )
        tenant_cleared = False
        if tenant_obj is None and getattr(existing, "tenant_id", None):
            _netbox_changelog_snapshot(existing)
            existing.tenant = None
            existing.save(**_save_branch())
            tenant_cleared = True
        any_save = _floating_ip_apply_row_stepwise(
            existing,
            status_name=status_name,
            role_value=role_value,
            tenant_obj=tenant_obj,
            full_descr=full_descr,
            cells=cells,
            vrf=vrf,
        )
        if any_save or merge_ch or tenant_cleared:
            return "updated", "ok_updated"
        return "skipped", "skipped_already_desired"
    ip_obj = IPAddress(address=address, vrf=vrf)
    try:
        ip_obj.save(**_save_branch())
    except Exception:
        logger.debug(
            "Floating IP two-phase create: initial minimal save failed; retry minimal then stepwise or single save (address=%s)",
            address,
            exc_info=True,
        )
        ip_fb = IPAddress(address=address, vrf=vrf)
        try:
            ip_fb.save(**_save_branch())
        except Exception:
            logger.debug(
                "Floating IP minimal save failed again; giving up on two-phase create (address=%s)",
                address,
                exc_info=True,
            )
            return "failed", "failed_validation_save"
        _floating_ip_apply_row_stepwise(
            ip_fb,
            status_name=status_name,
            role_value=role_value,
            tenant_obj=tenant_obj,
            full_descr=full_descr,
            cells=cells,
            vrf=vrf,
        )
        _netbox_changelog_snapshot(ip_fb)
        _merge_audit_residual_onto_object(
            ip_fb, cells, consumed, attr_names=("description",), max_len=max(dmax, 8000)
        )
        return "created", "ok_created"

    _floating_ip_apply_row_stepwise(
        ip_obj,
        status_name=status_name,
        role_value=role_value,
        tenant_obj=tenant_obj,
        full_descr=full_descr,
        cells=cells,
        vrf=vrf,
    )
    _netbox_changelog_snapshot(ip_obj)
    _merge_audit_residual_onto_object(
        ip_obj, cells, consumed, attr_names=("description",), max_len=max(dmax, 8000)
    )
    return "created", "ok_created"


def _resolve_ipaddress_for_vm_primary(raw: str):
    """Match NetBox IPAddress rows from drift cell (full prefix or host-only from OpenStack)."""
    from ipam.models import IPAddress

    raw = (raw or "").strip()
    if not raw or raw in {"—", "-"}:
        return None
    o = _orm_qs(IPAddress).filter(address=raw).first()
    if o is not None:
        return o
    host = raw.split("/", 1)[0].strip()
    try:
        ver = ipaddress.ip_address(host).version
    except ValueError:
        return None
    suffix = "/32" if ver == 4 else "/128"
    o = _orm_qs(IPAddress).filter(address=host + suffix).first()
    if o is not None:
        return o
    try:
        return _orm_qs(IPAddress).filter(address__startswith=host + "/").order_by("pk").first()
    except Exception:
        return None


def _apply_vm_primary_ip_link(vm, raw: str) -> bool:
    ip_obj = _resolve_ipaddress_for_vm_primary(raw)
    if ip_obj is None:
        return False
    try:
        ver = int(ip_obj.address.version)
    except Exception:
        try:
            ver = ipaddress.ip_address(str(ip_obj.address).split("/", 1)[0]).version
        except Exception:
            return False
    changed = False
    if ver == 4 and hasattr(vm, "primary_ip4_id"):
        if getattr(vm, "primary_ip4_id", None) != ip_obj.pk:
            vm.primary_ip4 = ip_obj
            changed = True
    elif ver == 6 and hasattr(vm, "primary_ip6_id"):
        if getattr(vm, "primary_ip6_id", None) != ip_obj.pk:
            vm.primary_ip6 = ip_obj
            changed = True
    return changed


def _apply_vm_primary_ip_from_cell(vm, cells: dict[str, str]) -> bool:
    pri = _cell(cells, "NB proposed primary IP")
    return _apply_vm_primary_ip_link(vm, pri)


def _apply_vm_primary_ip_from_projection(
    vm, proj: dict[str, str], cells: dict[str, str]
) -> bool:
    """Set primary_ip4/6 from projection; if both empty, fall back to NB proposed primary IP cell."""
    changed = False
    for k in ("primary_ip4", "primary_ip6"):
        raw = (proj.get(k) or "").strip()
        if _meaningful_cell_val(raw) and _apply_vm_primary_ip_link(vm, raw):
            changed = True
    if not any(
        _meaningful_cell_val((proj.get(x) or "").strip()) for x in ("primary_ip4", "primary_ip6")
    ):
        return _apply_vm_primary_ip_from_cell(vm, cells)
    return changed


def _openstack_vm_apply_site_tenant_status_device_stepwise(vm: Any, proj: dict[str, str]) -> None:
    """After VM structural save, apply site/tenant/status/device with one branching delta each."""
    from dcim.models import Device, Site
    from tenancy.models import Tenant

    site_name = (proj.get("site") or "").strip()
    if site_name and site_name not in {"—", "-"}:
        site = _resolve_by_name(Site, site_name, using=_orm_alias())
        if site is not None and hasattr(vm, "site_id") and getattr(vm, "site_id", None) != site.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(vm)
                vm.site = site
                vm.save(**_save_branch())
    tenant_name = (proj.get("tenant") or "").strip()
    if tenant_name and tenant_name not in {"—", "-"}:
        tenant = _resolve_tenant(tenant_name, using=_orm_alias())
        if tenant is not None and hasattr(vm, "tenant_id") and getattr(vm, "tenant_id", None) != tenant.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(vm)
                vm.tenant = tenant
                vm.save(**_save_branch())
    status_name = (proj.get("status") or "").strip()
    if status_name and status_name not in {"—", "-"}:
        val = _pick_choice_value(vm._meta.get_field("status"), status_name)
        if val is not None and vm.status != val:
            with _tx_branch():
                _netbox_changelog_snapshot(vm)
                vm.status = val
                vm.save(**_save_branch())
    device_cell = (proj.get("device") or "").strip()
    if device_cell and device_cell not in {"—", "-"}:
        dev = _orm_qs(Device).filter(name=device_cell).first()
        if dev is not None and hasattr(vm, "device_id") and getattr(vm, "device_id", None) != dev.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(vm)
                vm.device = dev
                vm.save(**_save_branch())


def apply_create_openstack_vm(op: dict[str, Any]) -> tuple[str, str]:
    try:
        from virtualization.models import VirtualMachine, Cluster
    except Exception:
        return "failed", "failed_virtualization_not_available"

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    name = (proj.get("name") or "").strip()
    cluster_name = (proj.get("cluster") or "").strip()
    if not name:
        return _skip_missing_prereq("VM name empty in row projection (OS VM name / drift columns).")
    if not cluster_name or cluster_name in {"—", "-"}:
        return _skip_missing_prereq(
            "NB proposed cluster empty in row; OpenStack VM apply requires a NetBox cluster name."
        )
    cluster = _orm_qs(Cluster).filter(name=cluster_name).first()
    if cluster is None:
        return _skip_missing_prereq(
            f'Cluster "{cluster_name}" not found in NetBox (Virtualization → Clusters). '
            f"Create the cluster or align NB proposed cluster in drift."
        )
    tenant_name = (proj.get("tenant") or "").strip()
    tenant_obj = None
    if tenant_name and tenant_name not in {"—", "-"}:
        tenant_obj = _resolve_tenant(tenant_name, using=_orm_alias())
        if tenant_obj is None:
            return _skip_missing_prereq(
                f'Tenant "{tenant_name}" not found in NetBox (create it or fix NB Proposed Tenant).'
            )
    # NetBox: unique (name, cluster, tenant) / (name, cluster) when tenant is null — not global name.
    dup = _orm_qs(VirtualMachine).filter(cluster=cluster, name__iexact=name)
    if tenant_obj is not None:
        dup = dup.filter(tenant=tenant_obj)
    else:
        dup = dup.filter(tenant__isnull=True)
    if dup.exists():
        return "skipped", "skipped_already_desired"

    consumed = {
        _norm_header("OS region"),
        _norm_header("VM name"),
        _norm_header("OS status"),
        _norm_header("Project"),
        _norm_header("Hypervisor hostname"),
        _norm_header("NB proposed primary IP"),
        _norm_header("NB proposed cluster"),
        _norm_header("NB proposed site"),
        _norm_header("NB Proposed Tenant"),
        _norm_header("NB proposed VM status"),
        _norm_header("NB proposed device (VM)"),
        _norm_header("NB proposed device (hypervisor)"),
        _norm_header("Authority"),
        _norm_header("Proposed Action"),
    }

    # First save inside ``_tx_branch()`` like other apply creates (interfaces, etc.): nested
    # ``atomic()`` pairs with netbox-branching per-save boundaries. Do **not** mirror VLAN's
    # bare first ``save`` + ``full_clean`` here — ``VirtualMachine`` validation/signals differ
    # and that pattern was associated with VM rows landing on main in some installs.
    vm = VirtualMachine(name=name, cluster=cluster)
    if tenant_obj is not None:
        vm.tenant = tenant_obj
    try:
        with _tx_branch():
            vm.save(**_save_branch())
    except IntegrityError as e:
        em = str(e).strip() or repr(e)
        logger.info("apply_create_openstack_vm integrity (name=%s): %s", name, em)
        return _skip_missing_prereq(
            f"VM save hit a database constraint (often duplicate name in cluster): {em}"
        )
    except Exception as e:
        logger.exception("apply_create_openstack_vm: save failed (name=%s)", name)
        et = type(e).__name__
        em = (str(e) or "").strip() or et
        detail = f"{et}: {em}"
        if len(detail) > 2000:
            detail = detail[:1997] + "..."
        return "failed", "failed_validation_save", detail
    _openstack_vm_apply_site_tenant_status_device_stepwise(vm, proj)
    _netbox_changelog_snapshot(vm)
    pri_ch = _apply_vm_primary_ip_from_projection(vm, proj, cells)
    if pri_ch:
        with _tx_branch():
            vm.save(**_save_branch())
    _netbox_changelog_snapshot(vm)
    vm_cf_ch, _ = _merge_vm_row_into_custom_fields(vm, cells, proj)
    if vm_cf_ch:
        with _tx_branch():
            vm.save(**_save_branch())
    _netbox_changelog_snapshot(vm)
    _merge_audit_residual_onto_object(
        vm, cells, consumed, attr_names=("description",), max_len=8000
    )
    _log_reconciliation_orm_write(
        entity="virtual_machine",
        apply_action="create_openstack_vm",
        op=op,
        message=f"created pk={getattr(vm, 'pk', None)} name={name!r} cluster={cluster_name!r}",
    )
    return "created", "ok_created"


def apply_update_openstack_vm(op: dict[str, Any]) -> tuple[str, str]:
    try:
        from virtualization.models import VirtualMachine, Cluster
        from dcim.models import Device, Site
    except Exception:
        return "failed", "failed_virtualization_not_available"

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    pk_raw = (proj.get("id") or "").strip()
    if not pk_raw or not str(pk_raw).strip().isdigit():
        return _skip_missing_prereq(
            "NetBox VM ID missing or not numeric in row (NetBox VM ID / projection id)."
        )
    vm = _orm_qs(VirtualMachine).filter(pk=int(str(pk_raw).strip())).select_related(
        "cluster", "device", "tenant", "primary_ip4", "primary_ip6"
    ).first()
    if vm is None:
        return _skip_missing_prereq(
            f"VirtualMachine id={pk_raw} not found in NetBox (wrong branch, deleted, or stale drift ID)."
        )

    cluster_name_req = (proj.get("cluster") or "").strip()
    if not cluster_name_req or cluster_name_req in {"—", "-"}:
        return _skip_missing_prereq(
            "NB proposed cluster is required — choose a NetBox cluster from the drift audit picker."
        )
    if _orm_qs(Cluster).filter(name=cluster_name_req).first() is None:
        return _skip_missing_prereq(
            f'Cluster "{cluster_name_req}" not found in NetBox (Virtualization → Clusters). '
            f"Create the cluster or align NB proposed cluster in drift."
        )

    consumed = {
        _norm_header("NetBox VM ID"),
        _norm_header("OS region"),
        _norm_header("VM name"),
        _norm_header("OS status"),
        _norm_header("Project"),
        _norm_header("Hypervisor hostname"),
        _norm_header("NB current vCPUs"),
        _norm_header("NB current Memory MB"),
        _norm_header("NB current Disk GB"),
        _norm_header("NB current primary IP"),
        _norm_header("NB current cluster"),
        _norm_header("NB current device"),
        _norm_header("NB current VM status"),
        _norm_header("Drift summary"),
        _norm_header("NB proposed primary IP"),
        _norm_header("NB proposed cluster"),
        _norm_header("NB proposed site"),
        _norm_header("NB Proposed Tenant"),
        _norm_header("NB proposed VM status"),
        _norm_header("NB proposed device (VM)"),
        _norm_header("NB proposed device (hypervisor)"),
        _norm_header("Authority"),
        _norm_header("Proposed Action"),
    }

    changed = False
    try:
        name_f = VirtualMachine._meta.get_field("name")
        nmax = int(getattr(name_f, "max_length", None) or 64)
    except Exception:
        nmax = 64
    name_new = (proj.get("name") or "").strip()
    if name_new and name_new not in {"—", "-"}:
        name_new = name_new[:nmax] if nmax > 0 else name_new
        if vm.name != name_new:
            with _tx_branch():
                _netbox_changelog_snapshot(vm)
                vm.name = name_new
                vm.save(**_save_branch())
            changed = True
    with _tx_branch():
        _netbox_changelog_snapshot(vm)
        if _apply_vm_primary_ip_from_projection(vm, proj, cells):
            vm.save(**_save_branch())
            changed = True
    cluster_name = (proj.get("cluster") or "").strip()
    if cluster_name and cluster_name not in {"—", "-"}:
        cl = _orm_qs(Cluster).filter(name=cluster_name).first()
        if cl is not None and vm.cluster_id != cl.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(vm)
                vm.cluster = cl
                vm.save(**_save_branch())
            changed = True
    site_name = (proj.get("site") or "").strip()
    if site_name and site_name not in {"—", "-"} and hasattr(vm, "site_id"):
        site = _resolve_by_name(Site, site_name, using=_orm_alias())
        if site is not None and getattr(vm, "site_id", None) != site.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(vm)
                vm.site = site
                vm.save(**_save_branch())
            changed = True
    tenant_name = (proj.get("tenant") or "").strip()
    if not tenant_name or tenant_name in {"—", "-"}:
        if getattr(vm, "tenant_id", None):
            with _tx_branch():
                _netbox_changelog_snapshot(vm)
                vm.tenant = None
                vm.save(**_save_branch())
            changed = True
    else:
        tenant = _resolve_tenant(tenant_name, using=_orm_alias())
        if tenant is None:
            return _skip_missing_prereq(
                f'Tenant "{tenant_name}" not found in NetBox (create it or fix NB Proposed Tenant).'
            )
        if getattr(vm, "tenant_id", None) != tenant.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(vm)
                vm.tenant = tenant
                vm.save(**_save_branch())
            changed = True
    status_name = (proj.get("status") or "").strip()
    if status_name and status_name not in {"—", "-"}:
        val = _pick_choice_value(vm._meta.get_field("status"), status_name)
        if val is not None and vm.status != val:
            with _tx_branch():
                _netbox_changelog_snapshot(vm)
                vm.status = val
                vm.save(**_save_branch())
            changed = True
    dev = None
    device_cell = (proj.get("device") or "").strip()
    if device_cell and device_cell not in {"—", "-"}:
        dev = _orm_qs(Device).filter(name=device_cell).first()
    if dev is not None and hasattr(vm, "device_id"):
        if getattr(vm, "device_id", None) != dev.pk:
            with _tx_branch():
                _netbox_changelog_snapshot(vm)
                vm.device = dev
                vm.save(**_save_branch())
            changed = True
    with _tx_branch():
        _netbox_changelog_snapshot(vm)
        vm_cf_ch, _ = _merge_vm_row_into_custom_fields(vm, cells, proj)
        if vm_cf_ch:
            vm.save(**_save_branch())
            changed = True
    merge_ch = _merge_audit_residual_onto_object(
        vm, cells, consumed, attr_names=("description",), max_len=8000
    )
    if changed or merge_ch:
        _log_reconciliation_orm_write(
            entity="virtual_machine",
            apply_action="update_openstack_vm",
            op=op,
            message=f"updated pk={getattr(vm, 'pk', None)} name={getattr(vm, 'name', '')!r}",
        )
        return "updated", "ok_updated"
    return "skipped", "skipped_already_desired"


def _cell_is_placeholder(val: str | None) -> bool:
    t = (val or "").strip()
    return not t or t in ("—", "-")


def _device_for_reconciliation_apply(hostname: str):
    """
    Resolve ``dcim.Device`` during reconciliation apply (branch-aware via NetBox router).

    Tries exact name, case-insensitive full name, then case-insensitive short label before
    the first ``.`` (FQDN in audit cells vs short NetBox ``Device.name``).
    """
    from dcim.models import Device

    n = (hostname or "").strip()
    if not n:
        return None
    dev = _orm_qs(Device).filter(name=n).first()
    if dev is not None:
        return dev
    dev = _orm_qs(Device).filter(name__iexact=n).first()
    if dev is not None:
        return dev
    short = n.split(".", 1)[0].strip()
    if short and short.casefold() != n.casefold():
        return _orm_qs(Device).filter(name__iexact=short).first()
    return None


def _cells_indicate_vyos(hostname: str, cells: dict[str, str]) -> bool:
    """True when hostname or common MAAS/OS columns suggest VyOS (router role must be chosen manually)."""
    hn = (hostname or "").strip().lower()
    if "vyos" in hn:
        return True
    blob = " ".join(
        _cell(cells, h)
        for h in (
            "NB proposed platform",
            "OS provision",
            "OS release",
            "MAAS OS",
            "OS",
            "MAAS status",
        )
    ).lower()
    return "vyos" in blob


def _fallback_device_role_for_create(hostname: str, cells: dict[str, str]):
    """
    When ``NB proposed role`` is empty, pick a safe default — except VyOS (operator must set role).
    """
    from dcim.models import DeviceRole

    if _cells_indicate_vyos(hostname, cells):
        return None

    rq = _orm_qs(DeviceRole)
    for slug in ("server", "compute", "network-device", "idc", "leaf", "spine"):
        r = rq.filter(slug=slug).first()
        if r is not None:
            return r
    for nm in ("Server", "Compute", "Network Device"):
        r = rq.filter(name__iexact=nm).first()
        if r is not None:
            return r
    return rq.order_by("pk").first()


def _apply_device_core(cells: dict[str, str], *, create_if_missing: bool) -> tuple[str, str]:
    from dcim.models import Device, DeviceRole, DeviceType, Location, Platform, Site

    hostname = _cell(cells, "Hostname", "Host")
    site_name = _cell(cells, "NB proposed site", "NetBox site")
    location_name = _cell(cells, "NB proposed location", "NetBox location")
    role_name = _cell(cells, "NB proposed role")
    dtype_name = _cell(cells, "NB proposed device type")
    status_name = _cell(cells, "NB proposed device status", "NB state (current)")
    serial = _cell(cells, "Serial Number", "MAAS Serial")
    tag_cell = _cell(cells, "NB proposed tag", "Suggested NetBox tags", "NetBox tags")
    region_name = _cell(cells, "NB proposed region")
    _pn_raw = _cell(
        cells, "NB proposed platform", "OS provision", "OS release", "MAAS OS", "OS"
    )
    _pn = str(_pn_raw or "").strip()
    if not _pn or _pn in ("—", "-") or _pn.lower() in ("(none)", "none", "n/a"):
        platform_name = ""
    else:
        platform_name = _pn
    platform_obj = (
        _resolve_by_name(Platform, platform_name, using=_orm_alias()) if platform_name else None
    )
    consumed_d = {
        _norm_header("Hostname"),
        _norm_header("Host"),
        _norm_header("NB proposed region"),
        _norm_header("NB proposed site"),
        _norm_header("NetBox site"),
        _norm_header("NB proposed location"),
        _norm_header("NetBox location"),
        _norm_header("NB proposed role"),
        _norm_header("NB proposed device type"),
        _norm_header("NB proposed device status"),
        _norm_header("NB state (current)"),
        _norm_header("Serial Number"),
        _norm_header("MAAS Serial"),
        _norm_header("NB proposed tag"),
        _norm_header("Suggested NetBox tags"),
        _norm_header("NetBox tags"),
        _norm_header("NB proposed platform"),
        _norm_header("OS provision"),
        _norm_header("OS release"),
        _norm_header("MAAS OS"),
        _norm_header("OS"),
        _norm_header("Proposed Action"),
    }
    if not hostname:
        return _skip_missing_prereq("Device hostname empty (Hostname / Host after scoping).")
    site = _resolve_by_name(Site, site_name, using=_orm_alias()) if site_name else None
    role = (
        _resolve_by_name(DeviceRole, role_name, using=_orm_alias()) if role_name else None
    )
    dtype = _resolve_device_type(dtype_name) if dtype_name else None
    location = None
    if location_name:
        location = _resolve_by_name(Location, location_name, using=_orm_alias())
        if location is None:
            return _skip_missing_prereq(
                f'Location "{location_name}" not found in NetBox (NB proposed location / NetBox location).'
            )
    existing = _device_for_reconciliation_apply(hostname)
    if existing is None:
        if not create_if_missing:
            return _skip_missing_prereq(
                f'Device "{hostname}" does not exist in NetBox. '
                f"Placement-only rows do not create devices; create the device first or include a new-device row."
            )
        role_raw = (role_name or "").strip()
        if _cells_indicate_vyos(hostname, cells):
            if _cell_is_placeholder(role_raw) or "ambiguous" in role_raw.lower():
                return _skip_missing_prereq(
                    "VyOS (vyos in hostname or OS columns): choose a specific NetBox device role "
                    "in NB proposed role on the drift audit (e.g. Edge Router, Cluster Edge Router, "
                    "Router Gateway — whichever your design uses). Save the drift review, "
                    "re-open reconciliation preview so the frozen ops pick it up, then apply again."
                )
        if _cell_is_placeholder(role_name):
            role_fb = _fallback_device_role_for_create(hostname, cells)
            if role_fb is not None:
                role = role_fb
                role_name = (getattr(role_fb, "name", None) or "").strip()
        if not site_name or _cell_is_placeholder(role_name) or _cell_is_placeholder(dtype_name):
            missing_bits = []
            if not site_name or _cell_is_placeholder(site_name):
                missing_bits.append("NB proposed site / NetBox site")
            if _cell_is_placeholder(role_name):
                missing_bits.append("NB proposed role")
            if _cell_is_placeholder(dtype_name):
                missing_bits.append("NB proposed device type")
            return _skip_missing_prereq(
                "Cannot create device; required fields empty in row: " + "; ".join(missing_bits) + "."
            )
        if site is None or role is None or dtype is None:
            bits = []
            if site is None and site_name:
                bits.append(f'site "{site_name}" not in NetBox')
            elif site is None:
                bits.append("site unresolved")
            if role is None and role_name:
                bits.append(f'role "{role_name}" not in NetBox')
            elif role is None:
                bits.append("role unresolved")
            if dtype is None and dtype_name:
                bits.append(f'device type "{dtype_name}" not in NetBox')
            elif dtype is None:
                bits.append("device type unresolved")
            return _skip_missing_prereq(
                f'Cannot create device "{hostname}"; ' + "; ".join(bits) + "."
            )
        # Structural create first, then one save per metadata field so netbox-branching lists each.
        dev = Device(name=hostname, site=site, location=location, role=role, device_type=dtype)
        dev.save(**_save_branch())
        _sync_site_region(dev.site, region_name)
        _device_apply_row_stepwise_changelog(
            dev,
            site=None,
            location=None,
            role=None,
            dtype=None,
            status_name=status_name,
            serial=serial or "",
            platform_obj=platform_obj,
            tag_cell=tag_cell or "",
            cells=cells,
            placement=False,
        )
        return "created", "ok_created"
    # Device exists in NetBox but has no role: fill from audit, or non-VyOS fallback; VyOS needs explicit pick.
    if getattr(existing, "role_id", None) in (None, 0):
        rr = (role_name or "").strip()
        if _cells_indicate_vyos(hostname, cells) and (
            _cell_is_placeholder(rr) or "ambiguous" in rr.lower()
        ):
            return _skip_missing_prereq(
                "Device exists in NetBox without a device role; for VyOS pick NB proposed role "
                "on the drift audit (e.g. Edge Router), save review, re-run reconciliation, then apply."
            )
        if role is None:
            role_fb = _fallback_device_role_for_create(hostname, cells)
            if role_fb is not None:
                role = role_fb
    any_dev = _device_apply_row_stepwise_changelog(
        existing,
        site=site,
        location=location,
        role=role,
        dtype=dtype,
        status_name=status_name,
        serial=serial or "",
        platform_obj=platform_obj,
        tag_cell=tag_cell or "",
        cells=cells,
        placement=True,
    )
    target_site = site if site is not None else existing.site
    _, site_saved = _sync_site_region(target_site, region_name)
    if any_dev or site_saved:
        return "updated", "ok_updated"
    return "skipped", "skipped_already_desired"


# Reconciliation preview must not proceed until these NetBox write-projection keys are filled
# (aligned with apply prerequisites / NetBox required semantics for each section).
_MANDATORY_NETBOX_PREVIEW_FIELDS: dict[str, tuple[str, ...]] = {
    "detail_placement_lifecycle_alignment": ("name", "site", "status"),
    "detail_new_devices": ("name", "site", "role", "device_type"),
    "detail_review_only_devices": ("name", "site", "role", "device_type"),
    "detail_proposed_missing_vlans": ("vid", "vlan_group", "site"),
    "detail_proposed_missing_tenants": ("name",),
    "detail_new_prefixes": ("prefix", "status"),
    "detail_existing_prefixes": ("prefix", "status"),
    "detail_new_ip_ranges": ("start_address", "end_address", "status"),
    "detail_new_fips": ("address", "status"),
    "detail_existing_fips": ("address", "status"),
    "detail_new_vms": ("name", "cluster"),
    "detail_existing_vms": ("id", "name", "cluster"),
    "detail_nic_drift_os": ("device", "name"),
    "detail_nic_drift_maas": ("device", "name"),
    "detail_bmc_new_devices": ("device", "name", "IPAddress.address"),
    "detail_bmc_existing": ("device", "name", "IPAddress.address"),
    "detail_serial_review": ("name", "serial"),
}

_PREVIEW_FIELD_LABELS: dict[str, str] = {
    "name": "Name",
    "id": "NetBox VM ID",
    "site": "Site",
    "site.region": "Site region",
    "location": "Location",
    "role": "Role (NB proposed role)",
    "device_type": "Device type",
    "status": "Status",
    "serial": "Serial number",
    "prefix": "Prefix (CIDR)",
    "vrf": "VRF",
    "tenant": "Tenant",
    "cluster": "Cluster",
    "device": "Device (host)",
    "type": "Interface type",
    "mac_address": "MAC address",
    "untagged_vlan_vid": "Untagged VLAN (802.1Q VID)",
    "description": "Description",
    "tags": "Tags / labels",
    "IPAddress.address": "IP address",
    "start_address": "Start address",
    "end_address": "End address",
    "address": "Address",
    "vid": "VLAN ID",
    "vlan_group": "VLAN group",
    "nat_inside": "NAT inside IP",
    "parent_prefix": "Parent prefix (OpenStack pool CIDR)",
}


def _mandatory_netbox_projection_keys(selection_key: str) -> tuple[str, ...]:
    sk = str(selection_key or "").strip()
    if sk in NEW_NIC_SELECTION_KEYS:
        return ("device", "name")
    return _MANDATORY_NETBOX_PREVIEW_FIELDS.get(sk, ())


def _preview_scalar_invalid(field_key: str, raw: str | None) -> bool:
    s = "" if raw is None else str(raw).strip()
    if _cell_is_placeholder(s):
        return True
    lk = str(field_key or "").lower()
    if lk == "role" and "ambiguous" in s.lower():
        return True
    if field_key == "vid":
        if not s.isdigit():
            return True
        v = int(s)
        return v < 1 or v > _NETBOX_IEEE_VLAN_VID_MAX
    if field_key == "id":
        return not s.isdigit()
    return False


def _nic_drift_interface_name_ok(cells: dict[str, str], proj: dict[str, str]) -> bool:
    pn = (proj.get("name") or "").strip()
    if not _cell_is_placeholder(pn):
        return True
    return not _cell_is_placeholder(_cell(cells, "MAAS intf"))


def _compact_preview_row_hint(summary: str) -> str:
    """Short label for grouping errors (strip common drift summary prefixes)."""
    s = (summary or "").strip()
    if not s:
        return "—"
    low = s.lower()
    for prefix in ("device row:", "device:", "vm row:", "row:"):
        if low.startswith(prefix):
            rest = s.split(":", 1)[1].strip()
            return rest or "—"
    return s


def validate_preview_mandatory_audit_fields(frozen: list[dict[str, Any]]) -> None:
    """
    Block reconciliation preview until NetBox-oriented audit columns required for apply
    are filled (empty, em-dash, or invalid VID / ambiguous role count as missing).

    Raises ValueError: one block per table; under each table, each row once with missing fields below it.
    """
    from collections import defaultdict

    from netbox_automation_plugin.sync.reconciliation.service import RECON_SECTION_TITLES

    # table -> row hint -> ordered unique field labels
    by_table_row: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    # first-seen row order within each table
    row_order: dict[str, list[str]] = defaultdict(list)
    row_seen: dict[str, set[str]] = defaultdict(set)
    nic_name_issue = False

    for op in frozen:
        if not isinstance(op, dict):
            continue
        sk = str(op.get("selection_key") or "").strip()
        keys = _mandatory_netbox_projection_keys(sk)
        if not keys:
            continue
        raw_cells = op.get("cells")
        if not isinstance(raw_cells, dict):
            raw_cells = {}
        cells: dict[str, str] = {
            str(k): "" if v is None else str(v) for k, v in raw_cells.items()
        }
        proj = netbox_write_projection_for_op(op)
        table_title = RECON_SECTION_TITLES.get(sk, sk)
        row_hint = _compact_preview_row_hint(str(op.get("summary") or ""))
        for field_key in keys:
            if field_key == "name" and sk in ("detail_nic_drift_os", "detail_nic_drift_maas"):
                if _nic_drift_interface_name_ok(cells, proj):
                    continue
                label = _PREVIEW_FIELD_LABELS.get("name", "Name")
                nic_name_issue = True
            else:
                val = proj.get(field_key)
                if not _preview_scalar_invalid(
                    field_key, val if val is None else str(val)
                ):
                    continue
                label = _PREVIEW_FIELD_LABELS.get(
                    field_key, str(field_key).replace("_", " ").title()
                )
            if row_hint not in row_seen[table_title]:
                row_seen[table_title].add(row_hint)
                row_order[table_title].append(row_hint)
            row_fields = by_table_row[table_title][row_hint]
            if label not in row_fields:
                row_fields.append(label)

    tables_with_errors = [t for t in by_table_row if row_order[t]]
    if not tables_with_errors:
        return

    lines: list[str] = [
        "Fill the missing audit fields, save the review, then continue.",
        "",
    ]
    for table in sorted(tables_with_errors, key=lambda t: t.lower()):
        lines.append(table)
        for row in row_order[table]:
            field_list = by_table_row[table][row]
            if not field_list:
                continue
            lines.append(f"  {row}")
            lines.append(f"    Missing: {', '.join(field_list)}")
        lines.append("")

    while lines and lines[-1] == "":
        lines.pop()

    if nic_name_issue:
        lines.extend(["", "NIC drift: set NB intf or MAAS intf where name is missing."])

    raise ValueError("\n".join(lines))


def apply_create_device(op: dict[str, Any]) -> tuple[str, str]:
    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    return _apply_device_core(cells, create_if_missing=True)


def apply_review_device(op: dict[str, Any]) -> tuple[str, str]:
    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    # Same creation path as new-device rows when the operator includes this row in apply:
    # review-only means the report flagged weak/unsafe MAAS state, not "never create in NB".
    return _apply_device_core(cells, create_if_missing=True)


def apply_placement_alignment(op: dict[str, Any]) -> tuple[str, str]:
    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    host = _cell(cells, "Host", "Hostname")
    if not host:
        return _skip_missing_prereq("Placement row missing Host / Hostname.")
    role_h = _norm_header("NB proposed role")
    cells_no_role = {
        k: v
        for k, v in cells.items()
        if _norm_header(str(k)) != role_h
    }
    fake = {
        "Hostname": host,
        "NB proposed site": _cell(cells, "NetBox site"),
        "NB proposed location": _cell(cells, "NetBox location"),
        "NB proposed device status": _cell(cells, "NB proposed device status"),
    }
    return _apply_device_core(
        {**cells_no_role, **{k: v for k, v in fake.items() if v}},
        create_if_missing=False,
    )


def apply_serial_review(op: dict[str, Any]) -> tuple[str, str]:
    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    host = (proj.get("name") or "").strip()
    serial = (proj.get("serial") or "").strip()
    consumed_sr = {
        _norm_header("Hostname"),
        _norm_header("Host"),
        _norm_header("MAAS Serial"),
        _norm_header("NetBox Serial"),
        _norm_header("Serial Number"),
        _norm_header("Proposed Action"),
    }
    if not host:
        return _skip_missing_prereq("Serial review row missing device name (Host / Hostname / projection).")
    dev = _device_for_reconciliation_apply(host)
    if not dev:
        return _skip_missing_prereq(f'Device "{host}" not found in NetBox.')
    if not serial:
        return _skip_missing_prereq(
            f'Proposed serial empty for device "{host}" (MAAS Serial / NetBox Serial / Serial Number).'
        )
    _netbox_changelog_snapshot(dev)
    changed = (dev.serial or "") != serial[:50]
    if changed:
        dev.serial = serial[:50]
    merge_ch = _merge_audit_residual_onto_object(
        dev, cells, consumed_sr, attr_names=("description",), max_len=8000
    )
    if changed or merge_ch:
        dev.save(**_save_branch())
        return "updated", "ok_updated"
    return "skipped", "skipped_already_desired"


def _iface_type_default():
    try:
        from dcim.choices import InterfaceTypeChoices

        return InterfaceTypeChoices.TYPE_OTHER
    except Exception:
        return "other"


def _sync_site_region(site_obj, region_name: str) -> tuple[bool, bool]:
    """
    Apply NB proposed region onto the device's Site.

    Returns (omit_from_residual, site_row_was_saved).
    """
    rn = str(region_name or "").strip()
    if not rn or rn in ("—", "-"):
        return True, False
    if site_obj is None or not getattr(site_obj, "pk", None):
        return False, False
    try:
        from dcim.models import Region, Site
    except Exception:
        return False, False
    reg = _resolve_by_name(Region, rn, using=_orm_alias())
    if reg is None:
        return False, False
    site_db = _orm_qs(Site).filter(pk=site_obj.pk).first()
    if site_db is None or not hasattr(site_db, "region_id"):
        return False, False
    if site_db.region_id == reg.pk:
        return True, False
    with _tx_branch():
        _netbox_changelog_snapshot(site_db)
        site_db.region = reg
        site_db.save(**_save_branch())
    return True, True


def _resolve_vlan_by_group_name_and_vid(group_name: str, vid: int):
    """
    Return the VLAN row for a NetBox VLAN group **name** + VID, or ``None``.

    Used when :func:`_resolve_vlan_for_device` returns nothing: VLANs with **no site** set
    may still exist in IPAM under a scoped group; ``get_for_device`` / site filters can miss
    them when VID is ambiguous globally or group scope does not match the device query path.
    """
    from ipam.models import VLAN, VLANGroup

    gn = (group_name or "").strip()
    if not gn or gn in {"—", "-"}:
        return None
    try:
        vid_i = int(vid)
    except (TypeError, ValueError):
        return None
    if vid_i < 1 or vid_i > _NETBOX_IEEE_VLAN_VID_MAX:
        return None
    grp = _orm_qs(VLANGroup).filter(name__iexact=gn).first()
    if grp is None:
        return None
    gfk = "group" if any(f.name == "group" for f in VLAN._meta.fields) else "vlan_group"
    return _orm_qs(VLAN).filter(**{gfk: grp, "vid": vid_i}).first()


def _resolve_vlan_for_device(device, vid: int):
    """
    Resolve a VLAN instance for ``device`` + numeric VID.

    NetBox often scopes VLANs via VLAN groups (location/site/region) without setting
    ``VLAN.site``.     Prefer ``VLAN.objects.get_for_device(device)`` when available
    (NetBox 3.5+ / 4.x) so VLAN group scope matches the same rules as the UI; fall back to
    explicit site/location queries for older releases.
    """
    from django.contrib.contenttypes.models import ContentType
    from ipam.models import VLAN

    if device is None or vid is None:
        return None
    try:
        vid_i = int(vid)
    except (TypeError, ValueError):
        return None

    # db_manager so NetBox VLANManager helpers (get_for_device / get_for_site) query the
    # branch schema — chaining .using() after get_for_* can still hit the wrong DB.
    vlan_mgr = _orm_mgr(VLAN)

    try:
        gfd = getattr(vlan_mgr, "get_for_device", None)
        if callable(gfd):
            dev_qs = gfd(device).filter(vid=vid_i)
            hits = list(dev_qs[:2])
            if len(hits) == 1:
                return hits[0]
            if len(hits) > 1:
                if getattr(device, "site_id", None):
                    hit = dev_qs.filter(site_id=device.site_id).first()
                    if hit is not None:
                        return hit
                    try:
                        ct_site = ContentType.objects.get_by_natural_key("dcim", "site")
                        hit = dev_qs.filter(
                            group__scope_type=ct_site,
                            group__scope_id=device.site_id,
                        ).first()
                        if hit is not None:
                            return hit
                    except Exception:
                        logger.debug(
                            "VLAN disambiguation by site-scoped group failed",
                            exc_info=True,
                        )
                # Do not return None here. Multiple get_for_device() hits (overlapping group
                # scope, recon-created rows, or sparse site on VLAN) are inconclusive; later
                # paths resolve by device.site + vid, location/region, and global VID
                # uniqueness — same paths that make legacy no-site VLANs work.
    except Exception:
        logger.debug("_resolve_vlan_for_device: get_for_device failed", exc_info=True)

    if device.site_id:
        hit = vlan_mgr.filter(site_id=device.site_id, vid=vid_i).first()
        if hit is not None:
            return hit
        site = getattr(device, "site", None)
        if site is not None:
            try:
                site_qs = vlan_mgr.get_for_site(site)
                hit = site_qs.filter(vid=vid_i).first()
                if hit is not None:
                    return hit
            except Exception:
                pass
            try:
                ct_site = ContentType.objects.get_by_natural_key("dcim", "site")
                hit = vlan_mgr.filter(
                    group__scope_type=ct_site,
                    group__scope_id=device.site_id,
                    vid=vid_i,
                ).first()
                if hit is not None:
                    return hit
            except Exception:
                pass

    loc = getattr(device, "location", None)
    if loc is not None:
        try:
            ct_loc = ContentType.objects.get_by_natural_key("dcim", "location")
            anc_ids = list(loc.get_ancestors(include_self=True).values_list("id", flat=True))
            hit = vlan_mgr.filter(
                group__scope_type=ct_loc,
                group__scope_id__in=anc_ids,
                vid=vid_i,
            ).first()
            if hit is not None:
                return hit
        except Exception:
            pass
        if getattr(loc, "site_id", None):
            hit = vlan_mgr.filter(site_id=loc.site_id, vid=vid_i).first()
            if hit is not None:
                return hit
            try:
                from dcim.models import Site

                s = _orm_qs(Site).filter(pk=loc.site_id).first()
                if s is not None:
                    site_qs = vlan_mgr.get_for_site(s)
                    hit = site_qs.filter(vid=vid_i).first()
                    if hit is not None:
                        return hit
            except Exception:
                pass

    reg = getattr(getattr(device, "site", None), "region", None)
    if reg is not None:
        try:
            ct_reg = ContentType.objects.get_by_natural_key("dcim", "region")
            anc_r = list(
                reg.get_ancestors(include_self=True).values_list("id", flat=True)
            )
            hit = vlan_mgr.filter(
                group__scope_type=ct_reg,
                group__scope_id__in=anc_r,
                vid=vid_i,
            ).first()
            if hit is not None:
                return hit
        except Exception:
            pass

    dup = list(vlan_mgr.filter(vid=vid_i)[:2])
    if len(dup) == 1:
        return dup[0]
    if len(dup) > 1 and device.site_id:
        hit = vlan_mgr.filter(vid=vid_i, site_id=device.site_id).first()
        if hit is not None:
            return hit
    return None


def _reuse_iface_untagged_vlan_if_vid_matches(iface: Any, vid: int) -> Any | None:
    """When resolution fails, still accept the interface's current untagged VLAN if its VID matches."""
    from ipam.models import VLAN

    uid = getattr(iface, "untagged_vlan_id", None)
    if not uid:
        return None
    cur = _orm_qs(VLAN).filter(pk=uid).first()
    if cur is None or getattr(cur, "vid", None) != vid:
        return None
    return cur


def _resolve_untagged_vlan_for_apply(
    device: Any,
    iface: Any | None,
    vid: int | None,
    *,
    vlan_group_name: str | None = None,
) -> Any | None:
    """
    Resolve VLAN for interface apply. Returns None when no VID requested (including MAAS
    native where ``vlan.vid`` is 0—handled upstream by :func:`_parse_vlan_vid`).
    Raises skip tuple via caller when VID requested but cannot be applied.
    """
    if vid is None:
        return None
    try:
        vid_i = int(vid)
    except (TypeError, ValueError):
        return None
    u = _resolve_vlan_for_device(device, vid_i)
    if u is None and iface is not None:
        u = _reuse_iface_untagged_vlan_if_vid_matches(iface, vid_i)
    if u is None:
        gn = (vlan_group_name or "").strip()
        if gn and gn not in {"—", "-"}:
            u = _resolve_vlan_by_group_name_and_vid(gn, vid_i)
    return u


def _skip_untagged_vlan_unresolved(
    host: str,
    vid: int,
    *,
    iface_name: str = "",
    device: Any | None = None,
    vlan_group_hint: str | None = None,
) -> tuple[str, str, str]:
    """
    Apply sets ``Interface.untagged_vlan`` (native/access VLAN on the port), not a field on
    Device. Resolution walks the device's site/location to pick a unique ``ipam.VLAN`` row.
    """
    dbg: dict[str, Any] = {"host": host, "interface_name": (iface_name or "").strip() or None}
    if device is not None:
        try:
            dbg.update(_vlan_resolution_snapshot_for_device(device, int(vid), vlan_group_hint))
        except Exception as ex:
            dbg["vlan_snapshot_error"] = f"{type(ex).__name__}: {ex}"
    _merge_apply_extra_debug(vlan_resolution=dbg)
    ifn = (iface_name or "").strip()
    loc = f'interface "{ifn}" on device "{host}"' if ifn else f'device "{host}" (interface)'
    n_branch = dbg.get("vlan_rows_with_vid_in_branch_schema")
    if n_branch == 0:
        msg = (
            f"Cannot apply untagged VLAN VID {vid} to {loc}: on the active branch there is "
            f"no IPAM VLAN with VID {vid} (count=0 in this schema). Routing is fine; the VLAN "
            f"row is missing. Add Proposed missing VLANs / create_vlan for VID {vid} (VLAN group "
            f"scoped to this device site/location) and run that row before this interface in apply "
            f"order (lower Run #). VLANs that exist only on NetBox main are not visible here."
        )
    elif n_branch == 1:
        msg = (
            f"Cannot apply untagged VLAN VID {vid} to {loc}: one VLAN with this VID exists on the "
            f"branch but is not in scope for this device (site/location vs VLAN group scope, "
            f"or VLAN.site). Fix the VLAN's group scope / site, or set NB proposed VLAN group "
            f"on the drift row if NetBox needs an explicit group+VID match."
        )
    elif isinstance(n_branch, int) and n_branch > 1:
        msg = (
            f"Cannot apply untagged VLAN VID {vid} to {loc}: {n_branch} VLANs share VID {vid} on "
            f"this branch; none could be tied unambiguously to this device. Narrow with VLAN "
            f"group scope, **NB proposed VLAN group**, or VLAN.site aligned to the device."
        )
    else:
        msg = (
            f"Cannot apply untagged VLAN VID {vid} to {loc}: no IPAM VLAN matches this "
            f"device's site or location (VLAN groups / get_for_site), or VID {vid} is ambiguous. "
            f"NetBox stores native VLAN on the interface; the VLAN object must exist in IPAM and "
            f"be in scope for the device. Create or scope VLAN {vid}, then re-run apply."
        )
    return _skip_missing_prereq(msg)


def _resolve_vlan_for_prefix_scope(
    vlan_name: str,
    scope_obj,
    *,
    vlan_group_hint: str | None = None,
) -> Any | None:
    from dcim.models import Site
    from ipam.models import VLAN

    raw = str(vlan_name or "").strip()
    if not raw or raw in {"—", "-"}:
        return None

    candidate_vid = None
    m = _VID_FROM_PARENS_RE.search(raw)
    if m:
        try:
            candidate_vid = int(m.group(1))
        except Exception:
            candidate_vid = None
    elif raw.isdigit():
        try:
            candidate_vid = int(raw)
        except Exception:
            candidate_vid = None

    vlan_mgr = _orm_mgr(VLAN)
    gh = (vlan_group_hint or "").strip()
    if gh and gh not in {"—", "-"} and candidate_vid is not None:
        hit = _resolve_vlan_by_group_name_and_vid(gh, candidate_vid)
        if hit is not None:
            return hit

    q_loc = None
    q_site = None
    if scope_obj is not None:
        try:
            from django.contrib.contenttypes.models import ContentType

            ct_loc = ContentType.objects.get_by_natural_key("dcim", "location")
            anc_ids = list(
                scope_obj.get_ancestors(include_self=True).values_list("id", flat=True)
            )
            q_loc = vlan_mgr.filter(
                group__scope_type=ct_loc,
                group__scope_id__in=anc_ids,
            )
            if getattr(scope_obj, "site_id", None):
                site_br = _orm_qs(Site).filter(pk=scope_obj.site_id).first()
                if site_br is not None:
                    try:
                        q_site = vlan_mgr.get_for_site(site_br)
                    except Exception:
                        q_site = None
        except Exception:
            q_loc = None
            q_site = None

    if candidate_vid is not None:
        if q_loc is not None:
            hit = q_loc.filter(vid=candidate_vid).first()
            if hit is not None:
                return hit
        if q_site is not None:
            try:
                hit = q_site.filter(vid=candidate_vid).first()
            except Exception:
                hit = None
            if hit is not None:
                return hit
        if scope_obj is not None and getattr(scope_obj, "site_id", None):
            hit = vlan_mgr.filter(vid=candidate_vid, site_id=scope_obj.site_id).first()
            if hit is not None:
                return hit
        hit = vlan_mgr.filter(vid=candidate_vid).first()
        if hit is not None:
            return hit

    by_name = _resolve_by_name(VLAN, raw, using=_orm_alias())
    if by_name is not None:
        return by_name
    if q_loc is not None:
        hit = q_loc.filter(name=raw).first()
        if hit is not None:
            return hit
    if q_site is not None:
        try:
            hit = q_site.filter(name=raw).first()
        except Exception:
            hit = None
        if hit is not None:
            return hit
    return vlan_mgr.filter(name=raw).first()


def _vrf_for_ip_from_row_cells(cells: dict[str, str] | None) -> Any:
    """Resolve optional VRF for IPAddress create/assign from NIC/BMC drift columns."""
    from ipam.models import VRF

    if not cells:
        return None
    raw = str(
        _cell(cells, "NB proposed VRF", "NB proposed vrf", "VRF", "NetBox VRF") or ""
    ).strip()
    if not raw or raw in ("—", "-"):
        return None
    return _resolve_by_name(VRF, raw, using=_orm_alias())


def _assign_ips_to_interface(iface, ip_blob: str, vrf) -> tuple[bool, bool, bool]:
    """
    Apply IP blob to interface.

    Returns ``(changed, row_had_ip_tokens, any_address_parse_ok)``. When the row lists IP
    text but nothing parses, callers must not report ``skipped_already_desired``.
    """
    from ipam.models import IPAddress

    tokens = _split_ip_candidates(ip_blob)
    row_had_ip_tokens = len(tokens) > 0
    changed = False
    any_parse_ok = False
    for raw in tokens:
        try:
            addr = _normalize_ip_for_netbox(raw.split()[0])
        except Exception:
            continue
        any_parse_ok = True
        existing = _orm_qs(IPAddress).filter(address=addr, vrf=vrf).first()
        if existing is None:
            # Two-phase: create address+VRF first, then snapshot + assign to interface so branch
            # changelog shows assignment (and VRF on the create row stays visible as its own delta).
            ip_obj = IPAddress(address=addr, vrf=vrf)
            try:
                ip_obj.save(**_save_branch())
            except Exception:
                logger.debug(
                    "IPAddress two-phase create: initial minimal save failed; retry minimal then assign or single save (address=%s)",
                    addr,
                    exc_info=True,
                )
                ip_fb = IPAddress(address=addr, vrf=vrf)
                try:
                    ip_fb.save(**_save_branch())
                except Exception:
                    logger.debug(
                        "IPAddress minimal save failed again; attempting two-phase create+assign (address=%s)",
                        addr,
                        exc_info=True,
                    )
                    ip_fb2 = IPAddress(address=addr, vrf=vrf)
                    try:
                        ip_fb2.save(**_save_branch())
                    except Exception:
                        logger.debug(
                            "IPAddress two-phase fallback: minimal save failed; skipping address=%s",
                            addr,
                            exc_info=True,
                        )
                        continue
                    _netbox_changelog_snapshot(ip_fb2)
                    if hasattr(ip_fb2, "assigned_object"):
                        ip_fb2.assigned_object = iface
                    elif hasattr(ip_fb2, "interface"):
                        ip_fb2.interface = iface
                    ip_fb2.save(**_save_branch())
                    changed = True
                    continue
                _netbox_changelog_snapshot(ip_fb)
                if hasattr(ip_fb, "assigned_object"):
                    ip_fb.assigned_object = iface
                elif hasattr(ip_fb, "interface"):
                    ip_fb.interface = iface
                ip_fb.save(**_save_branch())
                changed = True
                continue
            _netbox_changelog_snapshot(ip_obj)
            if hasattr(ip_obj, "assigned_object"):
                ip_obj.assigned_object = iface
            elif hasattr(ip_obj, "interface"):
                ip_obj.interface = iface
            ip_obj.save(**_save_branch())
            changed = True
        else:
            same = False
            if hasattr(existing, "assigned_object_id") and existing.assigned_object_id == iface.pk:
                same = True
            if hasattr(existing, "interface_id") and getattr(existing, "interface_id", None) == iface.pk:
                same = True
            if not same:
                _netbox_changelog_snapshot(existing)
                if hasattr(existing, "assigned_object"):
                    existing.assigned_object = iface
                elif hasattr(existing, "interface"):
                    existing.interface = iface
                existing.save(**_save_branch())
                changed = True
    return changed, row_had_ip_tokens, any_parse_ok


def _fallback_device_type_label_for_bootstrap() -> str:
    """
    Label for ``NB proposed device type`` when inferring a DCIM device from a NIC or placement row.
    """
    from dcim.models import DeviceType

    for slug in ("generic-1u-server", "server", "bare-metal-server"):
        dt = (
            _orm_qs(DeviceType)
            .select_related("manufacturer")
            .filter(slug=slug)
            .first()
        )
        if dt is not None:
            mname = getattr(dt.manufacturer, "name", "") or ""
            return f"{mname} {dt.model}".strip()
    dt = _orm_qs(DeviceType).select_related("manufacturer").order_by("pk").first()
    if dt is None:
        return ""
    mname = getattr(dt.manufacturer, "name", "") or ""
    return f"{mname} {dt.model}".strip()


def synthetic_device_cells_from_placement_for_nic_prereq(
    cells: dict[str, str],
) -> dict[str, str] | None:
    """
    ``detail_new_devices``-shaped cells from a placement row for prerequisite ``create_device``.
    """
    host = (_cell(cells, "Host", "Hostname") or "").strip()
    if not host:
        return None
    site = (_cell(cells, "NetBox site", "NB proposed site") or "").strip()
    if not site or _cell_is_placeholder(site):
        return None
    dtype_lbl = _fallback_device_type_label_for_bootstrap()
    if not dtype_lbl:
        return None
    out: dict[str, str] = {
        "Hostname": host,
        "Host": host,
        "NB proposed site": site,
        "NetBox site": site,
        "NB proposed device type": dtype_lbl,
    }
    loc = (_cell(cells, "NetBox location", "NB proposed location") or "").strip()
    if loc and not _cell_is_placeholder(loc):
        out["NB proposed location"] = loc
        out["NetBox location"] = loc
    st = (_cell(cells, "NB proposed device status", "NB state (current)") or "").strip()
    if st and not _cell_is_placeholder(st):
        out["NB proposed device status"] = st
    plat = (_cell(cells, "OS provision", "OS region") or "").strip()
    if plat:
        out["NB proposed platform"] = plat
    return out


def synthetic_device_cells_from_new_nic_for_prereq(
    cells: dict[str, str], host: str
) -> dict[str, str] | None:
    """Minimal new-device cells from a new-NIC row when ``NB site`` is set (apply-time fallback)."""
    site = (_cell(cells, "NB site") or "").strip()
    if not site or _cell_is_placeholder(site):
        return None
    dtype_lbl = _fallback_device_type_label_for_bootstrap()
    if not dtype_lbl:
        return None
    out: dict[str, str] = {
        "Hostname": host,
        "Host": host,
        "NB proposed site": site,
        "NetBox site": site,
        "NB proposed device type": dtype_lbl,
    }
    loc = (_cell(cells, "NB location") or "").strip()
    if loc and not _cell_is_placeholder(loc):
        out["NB proposed location"] = loc
        out["NetBox location"] = loc
    plat = (_cell(cells, "OS region", "OS provision", "OS") or "").strip()
    if plat:
        out["NB proposed platform"] = plat
    return out


def infer_vlan_group_name_for_interface_vlan_prereq(
    site_name: str,
    location_name: str,
    explicit_group: str | None,
    *,
    vid: int,
) -> str | None:
    """
    Pick a VLAN group name for a synthetic ``create_vlan`` frozen op.

    1. If the interface row sets **NB proposed VLAN group**, use it when the group exists
       and allows ``vid`` in its VLAN ID ranges.
    2. Else if exactly **one** ``ipam.VLANGroup`` is scoped to the **site**, use it (and VID range check).
    3. Else if **location** is set and exactly one group is scoped to that location (or an
       ancestor), use it.

    Uses :func:`_orm_qs` so reads follow the reconciliation branch when apply guard / branch
    alias is active; otherwise the default connection (e.g. main when freezing ops in the UI).
    If inference fails, returns ``None`` and no synthetic VLAN row is injected — operator can add
    Proposed missing VLANs.
    """
    from django.contrib.contenttypes.models import ContentType

    from dcim.models import Location, Site
    from ipam.models import VLANGroup

    def _group_ok(grp: Any) -> bool:
        return grp is not None and _vid_allowed_in_netbox_vlan_group(vid, grp)

    vgq = _orm_qs(VLANGroup)
    eg = (explicit_group or "").strip()
    if eg and eg not in {"—", "-"}:
        grp = vgq.filter(name__iexact=eg).first()
        if grp is not None:
            if _group_ok(grp):
                return str(grp.name)
            return None
        # Group name from drift but not visible on this ORM connection (e.g. branch-only): trust it.
        return eg

    sn = (site_name or "").strip()
    if not sn or _cell_is_placeholder(sn):
        return None
    site = _orm_qs(Site).filter(name__iexact=sn).first()
    if site is None:
        return None
    try:
        ct_site = ContentType.objects.get_by_natural_key("dcim", "site")
    except Exception:
        ct_site = None
    if ct_site is not None:
        qs = vgq.filter(scope_type=ct_site, scope_id=site.pk)
        if qs.count() == 1:
            g = qs.first()
            if _group_ok(g):
                return str(g.name)
    ln = (location_name or "").strip()
    if not ln or _cell_is_placeholder(ln):
        return None
    loc = _orm_qs(Location).filter(site=site, name__iexact=ln).first()
    if loc is None:
        return None
    try:
        ct_loc = ContentType.objects.get_by_natural_key("dcim", "location")
        anc = list(loc.get_ancestors(include_self=True).values_list("pk", flat=True))
        qs2 = vgq.filter(scope_type=ct_loc, scope_id__in=anc)
        if qs2.count() == 1:
            g2 = qs2.first()
            if _group_ok(g2):
                return str(g2.name)
    except Exception:
        pass
    return None


def synthetic_create_vlan_cells_from_interface_prereq(
    cells: dict[str, str],
    *,
    selection_key: str | None = None,
) -> dict[str, str] | None:
    """
    Build ``detail_proposed_missing_vlans``-shaped cells (for tooling or copy/paste).

    Reconciliation freeze no longer injects these automatically: the recon preview only includes
    VLAN rows explicitly selected from the audit "Proposed missing VLANs" table.

    Returns ``None`` when VID/site/group cannot be inferred safely.
    """
    c = {str(k): "" if v is None else str(v).strip() for k, v in cells.items()}
    sk = str(selection_key or "").strip()
    if sk in NEW_NIC_SELECTION_KEYS:
        c = new_nic_cells_for_reconciliation(c)
    elif sk and sk not in NIC_DRIFT_SELECTION_KEYS_LOCAL:
        return None
    _mac, vid, _ip = _interface_mac_vlan_ip_from_cells(c, include_nb_fallback=True)
    if vid is None or vid < 1 or vid > _NETBOX_IEEE_VLAN_VID_MAX:
        return None
    site = (_cell(c, "NB site", "NetBox site") or "").strip()
    if not site or _cell_is_placeholder(site):
        return None
    loc = (_cell(c, "NB location", "NetBox location") or "").strip()
    if _cell_is_placeholder(loc):
        loc = ""
    explicit_g = (_cell(c, "NB proposed VLAN group") or "").strip()
    gn = infer_vlan_group_name_for_interface_vlan_prereq(
        site, loc, explicit_g or None, vid=vid
    )
    if not gn:
        return None
    out = {
        "NB site": site,
        "NB location": loc,
        "NB Proposed VLAN ID": str(vid),
        "NB proposed VLAN group": gn,
        "NB proposed VLAN name (editable)": f"VLAN-{vid}",
    }
    return out


def _try_bootstrap_device_for_new_interface_apply(
    cells: dict[str, str], host: str
) -> tuple[str, str, str] | None:
    """
    Attempt :func:`_apply_device_core` from the NIC row when the device record is missing.
    Returns a skip triple if creation failed and the device is still absent; otherwise None.
    """
    if _device_for_reconciliation_apply(host):
        return None
    synth = synthetic_device_cells_from_new_nic_for_prereq(cells, host)
    if synth is None:
        return None
    res = _apply_device_core(synth, create_if_missing=True)
    detail = res[2] if len(res) > 2 else None
    reason = str(res[1])
    status = str(res[0])
    if _device_for_reconciliation_apply(host):
        return None
    if status in ("created", "updated"):
        return None
    if status == "skipped" and reason == "skipped_already_desired":
        return None
    msg = (str(detail).strip() if detail else "") or reason
    return _skip_missing_prereq(
        f'Device "{host}" is not in NetBox yet; inferred create from this interface row failed: {msg}'
    )


def apply_create_interface(op: dict[str, Any]) -> tuple[str, str]:
    from dcim.models import Device, Interface, Location, Site

    branch_db: str = (op.get("branch_db") or "default")
    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    host = _cell(cells, "Host")
    if_name = _cell(cells, "Suggested NB name", "MAAS intf")
    mac, vid, ip_blob = _interface_mac_vlan_ip_from_cells(cells, include_nb_fallback=False)
    proposed_body = _cell_nic_proposed_body(cells)
    if (bad_vid := _vlan_vid_over_ieee_max_from_proposed_body(proposed_body)) is not None:
        return _skip_missing_prereq(
            f"VLAN VID {bad_vid} in Proposed Action exceeds NetBox IEEE 802.1Q maximum "
            f"({_NETBOX_IEEE_VLAN_VID_MAX}); it cannot be set as Interface.untagged_vlan. "
            f"Values above {_NETBOX_IEEE_VLAN_VID_MAX} are often VXLAN VNIs or fabric ids—use a "
            f"1–{_NETBOX_IEEE_VLAN_VID_MAX} VLAN in NetBox or adjust the drift source."
        )
    site_hint = _cell(cells, "NB site", "NetBox site")
    loc_hint = _cell(cells, "NB location", "NetBox location")
    vlan_group_hint = _cell(cells, "NB proposed VLAN group")
    type_slug = _resolve_interface_type_slug(_cell(cells, "NB Proposed intf Type"))
    role_label = _cell(cells, "NB Proposed intf Label")
    if not host or not if_name:
        return _skip_missing_prereq(
            "Missing Host or interface name (Suggested NB name / MAAS intf) for create_interface."
        )
    mac_intent = _nic_mac_intent_raw(cells, include_nb_fallback=False)
    if mac_intent and not mac:
        mac_tail = "…" if len(mac_intent) > 80 else ""
        return _skip_missing_prereq(
            f'Cannot apply MAC for device "{host}" interface "{if_name}": '
            f"value is not a valid Ethernet MAC ({mac_intent[:80]!r}{mac_tail})."
        )
    dev = _device_for_reconciliation_apply(host)
    if not dev:
        boot_err = _try_bootstrap_device_for_new_interface_apply(cells, host)
        if boot_err is not None:
            return boot_err
        dev = _device_for_reconciliation_apply(host)
    if not dev:
        return _skip_missing_prereq(
            f'Device "{host}" not found in NetBox. Include a new-device row, or set NB site (and '
            f"role/type on the drift audit) so the reconciler can create the device before interfaces."
        )
    dev_geom_dirty = False
    if site_hint:
        site_obj = _resolve_by_name(Site, site_hint, using=_orm_alias())
        if site_obj and dev.site_id != site_obj.pk:
            _netbox_changelog_snapshot(dev)
            dev.site = site_obj
            dev.save(**_save_branch())
            dev_geom_dirty = True
    if loc_hint:
        loc_obj = _resolve_by_name(Location, loc_hint, using=_orm_alias())
        if loc_obj and getattr(dev, "location_id", None) != loc_obj.pk:
            _netbox_changelog_snapshot(dev)
            dev.location = loc_obj
            dev.save(**_save_branch())
            dev_geom_dirty = True
    if dev_geom_dirty:
        dev = (
            _orm_qs(Device)
            .filter(pk=dev.pk)
            .select_related("site", "location")
            .first()
        )
        if dev is None:
            return _skip_missing_prereq(
                f'Device "{host}" not found in NetBox after site/location update.'
            )
    else:
        dev.refresh_from_db(**_refresh_branch())
    iface = _orm_qs(Interface).filter(device=dev, name=if_name).first()
    untagged = _resolve_untagged_vlan_for_apply(
        dev, iface, vid, vlan_group_name=vlan_group_hint or None
    )
    if vid is not None and untagged is None:
        try:
            vnum = int(vid)
        except (TypeError, ValueError):
            return _skip_missing_prereq(f"Invalid VLAN id in row for device {host!r}.")
        return _skip_untagged_vlan_unresolved(
            host,
            vnum,
            iface_name=if_name,
            device=dev,
            vlan_group_hint=vlan_group_hint or None,
        )
    if_desc = _interface_description_from_cells(cells)
    if iface is None and ip_blob:
        ip_tok, ip_parse = _nic_ip_blob_parse_stats(ip_blob)
        if ip_tok and not ip_parse:
            return _skip_missing_prereq(
                f'Cannot apply IP address(es) for device "{host}" interface "{if_name}": '
                f"no valid IP parsed from row (MAAS IPs / OS runtime IP / Proposed Action)."
            )
    if iface is None:
        # Each save block gets its own transaction.atomic() savepoint so netbox_branching
        # cannot collapse them into a single diff row (which would show only the last
        # mutation — e.g. tags — and hide MAC / VLAN / type changes).
        with _tx_op(branch_db):
            iface = Interface(device=dev, name=if_name, type=_iface_type_default())
            _iface_save_on_op(branch_db, iface)
        # Reload from DB after the create savepoint: nested branching transactions can
        # leave an in-memory instance that refresh_from_db / snapshot cannot resolve
        # (DoesNotExist on Interface).
        iface = _orm_qs(Interface).filter(device=dev, name=if_name).first()
        if iface is None:
            return (
                "failed",
                "failed_interface_missing_after_create",
                f'Interface "{if_name}" on device "{host}" not found immediately after create.',
            )
        with _tx_op(branch_db):
            _interface_apply_physical_fields_batched(
                iface,
                mac=mac or "",
                untagged=untagged,
                type_slug=type_slug,
                description=if_desc,
            )
        with _tx_op(branch_db):
            _interface_apply_role_tag_changelog(iface, role_label)
        ip_vrf = _vrf_for_ip_from_row_cells(cells)
        if ip_blob:
            _assign_ips_to_interface(iface, ip_blob, ip_vrf)
        return "created", "ok_created"
    changed = _interface_scrub_audit_description_stepwise(iface)
    changed |= _interface_apply_physical_fields_stepwise(
        iface,
        mac=mac or "",
        untagged=untagged,
        type_slug=type_slug,
        description=if_desc,
    )
    if _interface_apply_role_tag_changelog(iface, role_label):
        changed = True
    ip_vrf = _vrf_for_ip_from_row_cells(cells)
    if ip_blob:
        ip_ch, ip_tok, ip_parse = _assign_ips_to_interface(iface, ip_blob, ip_vrf)
        if ip_tok and not ip_parse:
            return _skip_missing_prereq(
                f'Cannot apply IP address(es) for device "{host}" interface "{if_name}": '
                f"no valid IP parsed from row (MAAS IPs / OS runtime IP / Proposed Action)."
            )
        if ip_ch:
            changed = True
    if changed:
        return "updated", "ok_updated"
    return "skipped", "skipped_already_desired"


def apply_update_interface(op: dict[str, Any]) -> tuple[str, str]:
    from dcim.models import Device, Interface, Location, Site

    branch_db: str = (op.get("branch_db") or "default")
    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    host = _cell(cells, "Host")
    nb_name = _cell(cells, "NB intf")
    ma_name = _cell(cells, "MAAS intf")
    mac, vid, ip_blob = _interface_mac_vlan_ip_from_cells(cells, include_nb_fallback=True)
    type_slug = _resolve_interface_type_slug(_cell(cells, "NB Proposed intf Type"))
    role_label = _cell(cells, "NB Proposed intf Label")
    if not host:
        return _skip_missing_prereq("NIC drift row missing Host.")
    site_hint = _cell(cells, "NB site", "NetBox site")
    loc_hint = _cell(cells, "NB location", "NetBox location")
    vlan_group_hint = _cell(cells, "NB proposed VLAN group")
    mac_intent = _nic_mac_intent_raw(cells, include_nb_fallback=True)
    if mac_intent and not mac:
        mac_tail = "…" if len(mac_intent) > 80 else ""
        return _skip_missing_prereq(
            f'Cannot apply MAC for NIC drift row (device "{host}"): '
            f"value is not a valid Ethernet MAC ({mac_intent[:80]!r}{mac_tail})."
        )
    dev = _device_for_reconciliation_apply(host)
    if not dev:
        return _skip_missing_prereq(f'Device "{host}" not found in NetBox.')
    # Match apply_create_interface: align device site/location from drift row so VLAN
    # get_for_site / scoped group resolution sees the same scope as recon-created IPAM VLANs.
    dev_geom_dirty = False
    if site_hint:
        site_obj = _resolve_by_name(Site, site_hint, using=_orm_alias())
        if site_obj and dev.site_id != site_obj.pk:
            _netbox_changelog_snapshot(dev)
            dev.site = site_obj
            dev.save(**_save_branch())
            dev_geom_dirty = True
    if loc_hint:
        loc_obj = _resolve_by_name(Location, loc_hint, using=_orm_alias())
        if loc_obj and getattr(dev, "location_id", None) != loc_obj.pk:
            _netbox_changelog_snapshot(dev)
            dev.location = loc_obj
            dev.save(**_save_branch())
            dev_geom_dirty = True
    if dev_geom_dirty:
        dev = (
            _orm_qs(Device)
            .filter(pk=dev.pk)
            .select_related("site", "location")
            .first()
        )
        if dev is None:
            return _skip_missing_prereq(
                f'Device "{host}" not found in NetBox after site/location update.'
            )
    else:
        dev.refresh_from_db(**_refresh_branch())
    iface = None
    if nb_name:
        iface = (
            _orm_qs(Interface).filter(device=dev, name=nb_name)
            .select_related("untagged_vlan")
            .first()
        )
    if iface is None and ma_name:
        iface = (
            _orm_qs(Interface).filter(device=dev, name=ma_name)
            .select_related("untagged_vlan")
            .first()
        )
    if iface is None:
        return _skip_missing_prereq(
            f'No interface on device "{host}" matching NB intf "{nb_name}" or MAAS intf "{ma_name}".'
        )
    _interface_refresh_safe(iface)
    untagged = _resolve_untagged_vlan_for_apply(
        dev, iface, vid, vlan_group_name=vlan_group_hint or None
    )
    if vid is not None and untagged is None:
        try:
            vnum = int(vid)
        except (TypeError, ValueError):
            return _skip_missing_prereq(f"Invalid VLAN id in row for device {host!r}.")
        return _skip_untagged_vlan_unresolved(
            host,
            vnum,
            iface_name=iface.name or nb_name or ma_name,
            device=dev,
            vlan_group_hint=vlan_group_hint or None,
        )
    if_desc = _interface_description_from_cells(cells)
    changed = _interface_scrub_audit_description_stepwise(iface)
    # Each save block gets its own transaction.atomic() savepoint so netbox_branching
    # cannot collapse them into a single diff row (which would show only the last
    # mutation — e.g. tags — and hide MAC / VLAN / type changes).
    with _tx_op(branch_db):
        changed |= _interface_apply_physical_fields_batched(
            iface,
            mac=mac or "",
            untagged=untagged,
            type_slug=type_slug,
            description=if_desc,
        )
    with _tx_op(branch_db):
        if _interface_apply_role_tag_changelog(iface, role_label):
            changed = True
    ip_vrf = _vrf_for_ip_from_row_cells(cells)
    ip_ch, ip_tok, ip_parse = _assign_ips_to_interface(iface, ip_blob or "", ip_vrf)
    if ip_tok and not ip_parse:
        return _skip_missing_prereq(
            f'Cannot apply IP address(es) for device "{host}" (NIC drift): '
            f"no valid IP parsed from row (MAAS IPs / OS runtime IP / NB IPs / Proposed Action)."
        )
    if ip_ch:
        changed = True
    if changed:
        return "updated", "ok_updated"
    return "skipped", "skipped_already_desired"


def _bmc_apply(op: dict[str, Any], *, existing_oob: bool) -> tuple[str, str]:
    from dcim.models import Interface

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    host = _cell(cells, "Host")
    bmc_ip_maas = _cell(cells, "MAAS BMC IP")
    bmc_ip_os = _cell(cells, "OS BMC IP")
    bmc_ip_nb = _cell(cells, "NB mgmt iface IP")
    bmc_ip = bmc_ip_maas or bmc_ip_os or bmc_ip_nb
    bmc_mac = _normalize_mac(_cell(cells, "MAAS BMC MAC", "NB OOB MAC"))
    if_name = _cell(
        cells,
        "Suggested NB mgmt iface" if not existing_oob else "Suggested NB OOB Port",
    )
    type_slug = (
        None
        if existing_oob
        else _resolve_interface_type_slug(_cell(cells, "NB Proposed intf Type"))
    )
    role_label = _cell(cells, "NB Proposed intf Label")
    if not host or not if_name:
        return _skip_missing_prereq(
            "BMC row missing Host or management interface name "
            "(Suggested NB mgmt iface / Suggested NB OOB Port)."
        )
    if not bmc_ip:
        return _skip_missing_prereq(
            "BMC IP empty (MAAS BMC IP / OS BMC IP / NB mgmt iface IP); need an address to assign."
        )
    dev = _device_for_reconciliation_apply(host)
    if not dev:
        return _skip_missing_prereq(f'Device "{host}" not found in NetBox.')
    iface = _orm_qs(Interface).filter(device=dev, name=if_name).first()
    if iface is None:
        iface = Interface(device=dev, name=if_name, type=_iface_type_default())
        iface.save(**_save_branch())
        _interface_apply_physical_fields_batched(
            iface,
            mac=bmc_mac or "",
            untagged=None,
            type_slug=type_slug,
            description="",
        )
        created = True
    else:
        created = False
        _interface_apply_physical_fields_batched(
            iface,
            mac=bmc_mac or "",
            untagged=None,
            type_slug=type_slug,
            description="",
        )
    ip_vrf = _vrf_for_ip_from_row_cells(cells)
    combined_blob = (
        " ".join(x for x in (bmc_ip_maas, bmc_ip_os, bmc_ip_nb) if (x or "").strip())
        or str(bmc_ip).strip()
    )
    try:
        for raw in _split_ip_candidates(combined_blob):
            _normalize_ip_for_netbox(raw.split()[0])
    except Exception:
        return "failed", "failed_validation_bad_ip"
    ip_changed, _, _ = _assign_ips_to_interface(iface, combined_blob, ip_vrf)
    desc_changed = False
    if not created and _scrub_interface_drift_audit_description(iface):
        desc_changed = True
    tag_ch = _interface_apply_role_tag_changelog(iface, role_label)
    if desc_changed:
        _netbox_changelog_snapshot(iface)
        iface.save(**_save_branch())
    if ip_changed or desc_changed or created or tag_ch:
        return ("created", "ok_created") if created else ("updated", "ok_updated")
    return "skipped", "skipped_already_desired"


def apply_bmc_documentation(op: dict[str, Any]) -> tuple[str, str]:
    return _bmc_apply(op, existing_oob=False)


def apply_bmc_alignment(op: dict[str, Any]) -> tuple[str, str]:
    return _bmc_apply(op, existing_oob=True)


_APPLY_FUNCS: dict[str, Any] = {
    "create_vlan": apply_create_vlan,
    "create_tenant": apply_create_tenant,
    "create_prefix": apply_create_prefix,
    "create_ip_range": apply_create_ip_range,
    "create_floating_ip": apply_create_floating_ip,
    "create_device": apply_create_device,
    "review_device": apply_review_device,
    "create_interface": apply_create_interface,
    "update_interface": apply_update_interface,
    "placement_alignment": apply_placement_alignment,
    "serial_review": apply_serial_review,
    "bmc_documentation": apply_bmc_documentation,
    "bmc_alignment": apply_bmc_alignment,
    "create_openstack_vm": apply_create_openstack_vm,
    "update_openstack_vm": apply_update_openstack_vm,
}

_APPLY_WORKFLOW_HEADER_NORMS: frozenset[str] = frozenset(
    _norm_header(x)
    for x in (
        "Proposed Action",
        "Proposed action",
        "Proposed properties",
        "Proposed properties (from MAAS)",
        "Status",
        "Risk",
        "Authority",
    )
)


def _header_norms(*names: str) -> frozenset[str]:
    return frozenset(_norm_header(n) for n in names if str(n).strip())


def _netbox_preview_source_header_norms(selection_key: str) -> frozenset[str] | None:
    """
    Normalized audit headers that may feed apply for this section: recon preview sources,
    plus structural columns (description/CF snapshots) used by the same apply handlers.
    None = only strip placeholders; do not drop keys by name.
    """
    sk = str(selection_key or "").strip()
    if sk == "detail_placement_lifecycle_alignment":
        return _header_norms(
            "Host",
            "NetBox site",
            "NetBox location",
            "NB state (current)",
            "NB proposed device status",
        )
    if sk in ("detail_new_devices", "detail_review_only_devices"):
        return (
            _header_norms(
                "Hostname",
                "Host",
                "NB proposed region",
                "NB proposed site",
                "NB proposed location",
                "NB proposed role",
                "NB proposed device type",
                "NB proposed device status",
                "NB state (current)",
                "Serial Number",
                "MAAS Serial",
                "NB proposed tag",
                "Suggested NetBox tags",
                "NetBox tags",
                "NB proposed platform",
                "OS provision",
                "OS release",
                "MAAS OS",
                "OS",
                "NetBox site",
                "NetBox location",
            )
            | _header_norms(*(h for h, _ in _NEW_DEVICE_DRIFT_TO_CF_KEYS))
        )
    if sk == "detail_new_prefixes":
        return _header_norms(
            "NetBox prefix ID",
            "CIDR",
            "NB proposed VRF",
            "NB proposed status",
            "NB proposed role",
            "NB Proposed Scope",
            "NB Proposed VLAN",
            "NB Proposed Prefix description (editable)",
        ) | _header_norms(*_NEW_PREFIX_DRIFT_SNAPSHOT_HEADERS)
    if sk == "detail_existing_prefixes":
        # No NetBox prefix ID in drift rows; match apply path uses CIDR + VRF only.
        return _header_norms(
            "CIDR",
            "NB proposed VRF",
            "NB proposed status",
            "NB proposed role",
            "NB Proposed Scope",
            "NB Proposed VLAN",
            "NB Proposed Prefix description (editable)",
        ) | _header_norms(*_NEW_PREFIX_DRIFT_SNAPSHOT_HEADERS)
    if sk == "detail_new_ip_ranges":
        return _header_norms(
            "Start address",
            "End address",
            "NB proposed status",
            "NB proposed role",
            "NB proposed VRF",
            "NB Proposed Description",
            "OS Pool Description",
        )
    if sk in ("detail_new_fips", "detail_existing_fips"):
        return _header_norms(
            "Floating IP",
            "NB proposed status",
            "NB proposed role",
            "NB proposed VRF",
            "NB Proposed Tenant",
            "Name",
            "NAT inside IP (from OpenStack fixed IP)",
            "NAT inside IP",
            "NB current NAT inside",
        ) | _header_norms(*_NEW_FIP_DRIFT_SNAPSHOT_HEADERS) | _header_norms(
            *(h for h, _ in _NEW_FIP_DRIFT_TO_CF_KEYS)
        )
    if sk == "detail_new_vms":
        return _header_norms(
            "VM name",
            "NB proposed primary IP",
            "NB proposed cluster",
            "NB proposed site",
            "NB Proposed Tenant",
            "NB proposed VM status",
            "NB proposed device (VM)",
            "NB proposed device (hypervisor)",
            "Hypervisor hostname",
            "OS region",
            "OS status",
            "Project",
        )
    if sk == "detail_existing_vms":
        return _header_norms(
            "NetBox VM ID",
            "VM name",
            "NB proposed primary IP",
            "NB proposed cluster",
            "NB proposed site",
            "NB Proposed Tenant",
            "NB proposed VM status",
            "NB proposed device (VM)",
            "NB proposed device (hypervisor)",
            "Hypervisor hostname",
            "OS region",
            "OS status",
            "Project",
            "NB current vCPUs",
            "NB current Memory MB",
            "NB current Disk GB",
            "NB current primary IP",
            "NB current cluster",
            "NB current device",
            "NB current VM status",
            "Drift summary",
        )
    if sk in NEW_NIC_SELECTION_KEYS:
        return _header_norms(
            "Host",
            "Suggested NB name",
            "MAAS intf",
            "NB site",
            "NetBox site",
            "NB location",
            "NetBox location",
            "NB proposed VLAN group",
            "NB Proposed intf Label",
            "NB Proposed intf Type",
            "Parsed MAC",
            "Parsed untagged VLAN",
            "Parsed IPs",
            "MAAS MAC",
            "OS MAC",
            "MAAS VLAN",
            "OS runtime VLAN",
            "MAAS IPs",
            "OS runtime IP",
        )
    if sk in ("detail_nic_drift_os", "detail_nic_drift_maas"):
        return _header_norms(
            "Host",
            "NB intf",
            "MAAS intf",
            "NB site",
            "NetBox site",
            "NB location",
            "NetBox location",
            "NB Proposed intf Label",
            "NB Proposed intf Type",
            "MAAS MAC",
            "OS MAC",
            "NB MAC",
            "MAAS VLAN",
            "OS runtime VLAN",
            "NB VLAN",
            "NB proposed VLAN group",
            "MAAS IPs",
            "OS runtime IP",
            "NB IPs",
            "Parsed MAC",
            "Parsed untagged VLAN",
            "Parsed IPs",
        )
    if sk == "detail_bmc_new_devices":
        return _header_norms(
            "Host",
            "MAAS BMC IP",
            "OS BMC IP",
            "NB mgmt iface IP",
            "MAAS BMC MAC",
            "NB OOB MAC",
            "Suggested NB mgmt iface",
            "NB Proposed intf Label",
            "NB Proposed intf Type",
        )
    if sk == "detail_bmc_existing":
        return _header_norms(
            "Host",
            "MAAS BMC IP",
            "OS BMC IP",
            "NB mgmt iface IP",
            "MAAS BMC MAC",
            "NB OOB MAC",
            "Suggested NB OOB Port",
            "NB Proposed intf Label",
            "NetBox OOB",
        )
    if sk == "detail_serial_review":
        return _header_norms("Host", "Hostname", "MAAS Serial", "NetBox Serial", "Serial Number")
    if sk == "detail_proposed_missing_vlans":
        return _header_norms(
            "NB site",
            "NB location",
            "NB Proposed VLAN ID",
            "NB proposed VLAN group",
            "NB proposed VLAN name (editable)",
        )
    if sk == "detail_proposed_missing_tenants":
        return _header_norms(
            "OpenStack project",
            "NB proposed tenant name",
            "NB proposed tenant description",
        )
    return None


def reconciliation_apply_snapshot_cells(selection_key: str, cells: Any) -> dict[str, str]:
    """
    Column/value dict passed into apply handlers (same path as ``apply_row_operation``):
    recon-preview allowlist, workflow fields when set, empty and ``—`` placeholders removed.
    """
    return _cells_scoped_for_apply(selection_key, cells)


def _cells_scoped_for_apply(selection_key: str, cells: Any) -> dict[str, str]:
    sk = str(selection_key or "").strip()
    if not isinstance(cells, dict):
        return {}
    base: dict[str, str] = {}
    for k, v in cells.items():
        ks = str(k).strip()
        if not ks:
            continue
        base[ks] = "" if v is None else str(v).strip()
    if sk in NEW_NIC_SELECTION_KEYS:
        base = new_nic_cells_for_reconciliation(base)
    allowed = _netbox_preview_source_header_norms(sk)
    wf = _APPLY_WORKFLOW_HEADER_NORMS
    out: dict[str, str] = {}
    for k, v in base.items():
        kn = _norm_header(k)
        if allowed is not None and kn not in allowed and kn not in wf:
            continue
        if kn in wf:
            if v.strip():
                out[k] = v
            continue
        if kn == _norm_header("NB Proposed Tenant"):
            coerced = coerce_nb_proposed_tenant_cell(v)
            if coerced:
                out[k] = coerced
            continue
        if _meaningful_cell_val(v):
            out[k] = v
    return out


def apply_row_operation(
    op: dict[str, Any],
) -> tuple[str, str, str | None, dict[str, Any] | None]:
    """
    Returns ``(status, reason, reason_detail, written_object)``.

    Handlers may return:

    - 2-tuple ``(status, reason)``
    - 3-tuple with optional human ``reason_detail`` (skips/failures)
    - 4-tuple adding optional ``written_object`` (``{"label": ..., "pk": ...}`` for post-apply snapshot)
    """
    _clear_tls_routing_snapshot()
    _clear_apply_extra_debug()
    if (gerr := check_reconciliation_apply_safe_to_mutate(op)) is not None:
        return "failed", "failed_reconciliation_branch_guard", gerr, None

    branch_db_val = str(op.get("branch_db") or "").strip()
    if get_reconciliation_apply_guard_context() is not None:
        bdl = branch_db_val.lower()
        if not branch_db_val or bdl == "default":
            return (
                "failed",
                "failed_invalid_branch_db",
                "branch_db must be a non-default schema_* Django alias; empty or 'default' is not allowed.",
                None,
            )
    if not branch_db_val and not _reconciliation_apply_unscoped_allowed(op):
        logger.error(
            "apply_row_operation missing branch_db in op (ContextVar would fall back to "
            "'default'). row_key=%s action=%s selection_key=%s",
            op.get("row_key"),
            op.get("action"),
            op.get("selection_key"),
        )
        return (
            "failed",
            "failed_missing_branch_db",
            "branch_db missing from apply op — aborted to protect NetBox main.",
            None,
        )

    action = str(op.get("action") or "").strip()
    fn = _APPLY_FUNCS.get(action)
    if not fn:
        return "failed", "failed_not_implemented", None, None
    sk = str(op.get("selection_key") or "").strip()
    op_use = dict(op)
    op_use["cells"] = _cells_scoped_for_apply(sk, op.get("cells"))
    # Publish branch_db so all handlers and helpers can open correctly-aliased savepoints.
    _bdb_token = _APPLY_BRANCH_DB.set(str(op.get("branch_db") or "default"))
    _set_tls_routing_snapshot(_build_reconciliation_apply_routing_snapshot(op))
    try:
        raw = fn(op_use)
    finally:
        _APPLY_BRANCH_DB.reset(_bdb_token)
    if not isinstance(raw, tuple):
        return "failed", "failed_bad_apply_return", None, None
    if len(raw) == 2:
        return str(raw[0]), str(raw[1]), None, None
    if len(raw) == 3:
        det = raw[2]
        if det is None:
            return str(raw[0]), str(raw[1]), None, None
        ds = str(det).strip()
        return str(raw[0]), str(raw[1]), ds or None, None
    if len(raw) == 4:
        det = raw[2]
        if det is None:
            skip_detail: str | None = None
        else:
            ds = str(det).strip()
            skip_detail = ds or None
        meta = raw[3]
        written: dict[str, Any] | None = meta if isinstance(meta, dict) else None
        return str(raw[0]), str(raw[1]), skip_detail, written
    return "failed", "failed_bad_apply_return", None, None
