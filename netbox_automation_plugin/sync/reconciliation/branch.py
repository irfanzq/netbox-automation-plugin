"""Create a NetBox Branch when the branching app / model is available."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import logging
import os
from typing import Any, Iterator

from django.db import connections, transaction
from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)


def _branch_django_alias_candidates(raw: str) -> list[str]:
    """
    NetBox Branching may expose ``Branch.connection_name`` as ``schema_branch_<id>`` while
    ``DynamicSchemaDict`` registers the Django key as ``branch_<id>`` (schema name in UI is
    often ``branch_<id>``). Try both spellings.
    """
    s = (raw or "").strip()
    if not s:
        return []
    out: list[str] = [s]
    sl = s.lower()
    p_schema = "schema_branch_"
    p_branch = "branch_"
    if sl.startswith(p_schema):
        alt = p_branch + s[len(p_schema) :]
        if alt not in out:
            out.append(alt)
    elif sl.startswith(p_branch):
        alt = p_schema + s[len(p_branch) :]
        if alt not in out:
            out.append(alt)
    return out


def resolve_branch_django_database_alias(connection_name: str) -> tuple[str | None, str]:
    """
    Map ``Branch.connection_name`` to a Django ``DATABASES`` key that exists in
    ``django.db.connections`` and accepts connections.

    Returns ``(alias, "")`` on success, or ``(None, error_message)``.
    """
    raw = (connection_name or "").strip()
    low = raw.lower()
    if not raw or low == "default":
        return (
            None,
            _(
                "Branch connection_name is empty or 'default' — branch schema is not yet "
                "provisioned. Wait for NetBox branching to finish creating the branch schema, "
                "then retry."
            ),
        )
    last_detail = ""
    for cand in _branch_django_alias_candidates(raw):
        if cand not in connections:
            last_detail = _(
                "Branch DB alias '%(alias)s' is not registered in Django connections."
            ) % {"alias": cand}
            continue
        try:
            connections[cand].ensure_connection()
            return (cand, "")
        except Exception as exc:
            last_detail = _("Branch DB connection failed: %(err)s") % {"err": str(exc)}
    return (None, last_detail or _("No usable branch database alias found."))

# Set only during reconciliation apply (and branch-scoped validators) so ORM mutations
# cannot run against NetBox main by accident.
_RECONCILIATION_APPLY_GUARD: ContextVar[dict[str, Any] | None] = ContextVar(
    "netbox_automation_reconciliation_apply_guard",
    default=None,
)


@contextmanager
def reconciliation_apply_guard(branch: Any, branch_db: str) -> Iterator[None]:
    """
    Mark this thread as executing a reconciliation apply against ``branch`` / ``branch_db``.

    :func:`apply_cells.apply_row_operation` refuses to mutate NetBox unless this guard is
    active and ``netbox_branching``'s active-branch context matches ``branch``.
    """
    bdb = (branch_db or "").strip()
    if not bdb:
        raise ValueError("reconciliation_apply_guard requires a non-empty branch_db alias.")
    token = _RECONCILIATION_APPLY_GUARD.set(
        {"branch_pk": getattr(branch, "pk", None), "branch_db": bdb}
    )
    try:
        yield
    finally:
        _RECONCILIATION_APPLY_GUARD.reset(token)


def get_reconciliation_apply_guard_context() -> dict[str, Any] | None:
    return _RECONCILIATION_APPLY_GUARD.get()


def get_netbox_plugin_active_branch() -> Any | None:
    """Branch instance from netbox_branching contextvars, if any (unset outside activate_branch)."""
    try:
        from netbox_branching.contextvars import active_branch as _ab
    except ImportError:
        return None
    try:
        return _ab.get()
    except LookupError:
        return None


def check_reconciliation_apply_safe_to_mutate(op: dict[str, Any] | None = None) -> str | None:
    """
    Return an error message if :func:`apply_row_operation` must not run; otherwise ``None``.

    Escape hatch: set env ``NETBOX_AUTOMATION_ALLOW_UNSCOPED_APPLY=1`` for controlled tooling
    only (writes may hit NetBox main).
    """
    if op and op.get("_allow_unscoped_apply"):
        return None
    flag = (os.environ.get("NETBOX_AUTOMATION_ALLOW_UNSCOPED_APPLY") or "").strip().lower()
    if flag in ("1", "true", "yes"):
        return None

    ctx = _RECONCILIATION_APPLY_GUARD.get()
    if not ctx:
        return (
            "Reconciliation apply is not running inside a branch-scoped guard (missing "
            "reconciliation_apply_guard). Refusing ORM writes to avoid mutating NetBox main."
        )

    active = get_netbox_plugin_active_branch()
    if active is None:
        return (
            "No active NetBox branch in context (netbox_branching). Refusing apply ORM writes "
            "against the default database."
        )

    exp_pk = ctx.get("branch_pk")
    act_pk = getattr(active, "pk", None)
    if exp_pk is not None and act_pk is not None and int(exp_pk) != int(act_pk):
        return (
            f"Active branch (pk={act_pk}) does not match reconciliation run branch (pk={exp_pk}). "
            "Refusing apply."
        )
    return None


def create_netbox_branch(*, name: str, description: str = "") -> tuple[Any | None, str | None, str | None]:
    """
    Try ORM creation for NetBox's Branch model (import path varies by version).

    Returns (branch_pk, branch_name, error_message). branch_pk is None on failure.
    """
    last_err: str | None = None
    for mod_path in ("netbox_branching.models", "core.models"):
        try:
            mod = __import__(mod_path, fromlist=["Branch"])
        except ImportError:
            continue
        Branch = getattr(mod, "Branch", None)
        if Branch is None:
            continue
        try:
            kwargs: dict[str, Any] = {"name": name}
            desc = (description or "")[:4000]
            for field_name in ("description", "comments"):
                try:
                    field = Branch._meta.get_field(field_name)
                    max_len = getattr(field, "max_length", None)
                    if max_len:
                        kwargs[field_name] = desc[:max_len]
                    else:
                        kwargs[field_name] = desc
                    break
                except Exception:
                    continue
            br = Branch.objects.create(**kwargs)
            pk = br.pk
            bname = getattr(br, "name", None) or name
            return pk, str(bname), None
        except Exception as e:
            last_err = f"{mod_path}: {e}"
            logger.warning("Branch create via %s failed: %s", mod_path, e)
    if last_err:
        return None, None, last_err
    return None, None, (
        "NetBox Branching is not available in this installation "
        "(no Branch model found)."
    )


def netbox_branch_exists(*, name: str) -> bool:
    for mod_path in ("netbox_branching.models", "core.models"):
        try:
            mod = __import__(mod_path, fromlist=["Branch"])
        except ImportError:
            continue
        Branch = getattr(mod, "Branch", None)
        if Branch is None:
            continue
        try:
            return Branch.objects.filter(name=name).exists()
        except Exception:
            continue
    return False


def get_netbox_branch(*, branch_id: Any = None, branch_name: str = "") -> tuple[Any | None, str | None]:
    """Resolve Branch object by id/name. Returns (branch, error_message)."""
    for mod_path in ("netbox_branching.models", "core.models"):
        try:
            mod = __import__(mod_path, fromlist=["Branch"])
        except ImportError:
            continue
        Branch = getattr(mod, "Branch", None)
        if Branch is None:
            continue
        try:
            if branch_id is not None:
                br = Branch.objects.filter(pk=branch_id).first()
                if br is not None:
                    return br, None
            if branch_name:
                br = Branch.objects.filter(name=branch_name).first()
                if br is not None:
                    return br, None
        except Exception as e:
            return None, f"{mod_path}: {e}"
    return None, "Branch model not available."


@contextmanager
def branch_write_context(*, branch: Any) -> Iterator[None]:
    """
    Activate NetBox Branching context for ORM writes.

    For netboxlabs/netbox-branching: activate_branch plus a DB transaction. When
    ``connection_name`` is a dedicated branch alias, use ``atomic(using=…)``; when it is
    the literal ``default``, use plain ``atomic()`` so ORM routing stays branch-scoped.
    If no API fits, raises so callers do not write branch-aware models to main by accident.
    """
    # Prefer netboxlabs/netbox-branching: always pair activate_branch with atomic; avoid
    # atomic(using="default") which can bypass branching and hit NetBox main.
    try:
        from netbox_branching.utilities import activate_branch as _nb_activate_branch
    except ImportError:
        _nb_activate_branch = None
    if callable(_nb_activate_branch):
        using_raw = getattr(branch, "connection_name", None)
        using = str(using_raw or "").strip()
        if not using:
            raise RuntimeError(
                "NetBox branch has no connection_name (database alias). Cannot open "
                "transaction.atomic(using=…) for the branch schema — refusing ORM writes "
                "(would risk NetBox main). Wait until the branch is provisioned and ready."
            )
        # connection_name may be schema_branch_* while DynamicSchemaDict only registers branch_*.
        if using.lower() != "default" and using not in connections:
            resolved, rerr = resolve_branch_django_database_alias(using)
            if resolved:
                using = resolved
            else:
                raise RuntimeError(
                    rerr
                    or f"Branch database alias {using_raw!r} is not registered in Django connections."
                )
        # NetBox Branching often reports connection_name as the literal "default". Pairing
        # activate_branch with transaction.atomic(using="default") pins Django to the default
        # connection and can bypass branching routers — writes then land in main. Use a plain
        # atomic() on the default connection so routing matches NetBox UI/API under activate_branch.
        with _nb_activate_branch(branch):
            if using.lower() == "default":
                with transaction.atomic():
                    yield
            else:
                with transaction.atomic(using=using):
                    yield
        return

    # 1) Branch instance may provide a context manager method (non-netbox_branching).
    for method_name in ("as_context", "activate", "as_active", "scope"):
        fn = getattr(branch, method_name, None)
        if not callable(fn):
            continue
        try:
            ctx = fn()
            if hasattr(ctx, "__enter__") and hasattr(ctx, "__exit__"):
                with ctx:
                    yield
                return
        except TypeError:
            # Some implementations may return a simple token / bool, skip.
            continue
        except Exception:
            continue

    # 3) Legacy / alternate module paths.
    for mod_path, func_name in (
        ("netbox_branching.context", "branch_context"),
        ("netbox_branching.context", "activate_branch"),
        ("core.context", "branch_context"),
    ):
        try:
            mod = __import__(mod_path, fromlist=[func_name])
        except ImportError:
            continue
        fn = getattr(mod, func_name, None)
        if not callable(fn):
            continue
        try:
            ctx = fn(branch)
            if hasattr(ctx, "__enter__") and hasattr(ctx, "__exit__"):
                with ctx:
                    yield
                return
        except Exception:
            continue

    raise RuntimeError(
        "Cannot activate NetBox branch context for safe writes. "
        "No supported branch context API found."
    )


def delete_netbox_branch_instance(branch: Any) -> tuple[bool, str | None]:
    """Best-effort ORM delete of a Branch row. Returns (ok, error_message)."""
    if branch is None:
        return False, "No branch object."
    try:
        branch.delete()
        return True, None
    except Exception as e:
        logger.warning("Branch delete failed: %s", e)
        return False, str(e)
