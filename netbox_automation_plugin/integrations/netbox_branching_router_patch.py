"""
Align ObjectChange writes with netbox-branching reads.

BranchAwareRouter sends ObjectChange *reads* to the active branch schema, but
*writes* fell through to the default DB because core.ObjectChange does not
``supports_branching``. Branch overview stats (Created / Updated / Deleted) use
``ObjectChange.objects.using(branch.connection_name)``, so they stayed empty
while ChangeDiff could still show rows.

This mirrors the router's db_for_read special-case for core.ObjectChange.
Upstream may fix this; the patch is idempotent.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_PATCH_ATTR = "_nap_automation_objectchange_write_patch"


def apply_branch_router_objectchange_write_patch() -> None:
    try:
        from netbox_branching.contextvars import active_branch
        from netbox_branching.database import BranchAwareRouter
    except ImportError:
        return

    if getattr(BranchAwareRouter, _PATCH_ATTR, False):
        return

    _orig = BranchAwareRouter.db_for_write

    def db_for_write(self, model, **hints):
        if model._meta.label == "core.ObjectChange":
            if branch := active_branch.get():
                return self._get_connection(branch)
            return None
        return _orig(self, model, **hints)

    BranchAwareRouter.db_for_write = db_for_write
    setattr(BranchAwareRouter, _PATCH_ATTR, True)
    logger.info(
        "Patched netbox_branching.database.BranchAwareRouter.db_for_write "
        "so core.ObjectChange writes use the active branch schema."
    )
