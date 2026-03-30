"""Create a NetBox Branch when the branching app / model is available."""

from __future__ import annotations

from contextlib import contextmanager
import logging
from typing import Any, Iterator

from django.db import transaction

logger = logging.getLogger(__name__)


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

    For netboxlabs/netbox-branching, matches Branch.sync: activate_branch plus
    transaction.atomic(using=branch.connection_name). If no API fits, raises so
    callers do not write branch-aware models to main by accident.
    """
    # 1) Branch instance may provide a context manager method.
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

    # 2) NetBox Labs netbox-branching: same stack as models.Branch.sync — activate_branch plus
    # transaction.atomic(using=branch.connection_name) so ORM hits the branch schema reliably.
    try:
        from netbox_branching.utilities import activate_branch as _nb_activate_branch
    except ImportError:
        _nb_activate_branch = None
    if callable(_nb_activate_branch):
        using = getattr(branch, "connection_name", None)
        if using:
            with _nb_activate_branch(branch), transaction.atomic(using=using):
                yield
        else:
            with _nb_activate_branch(branch):
                yield
        return

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
