"""
Show parent device hostname in netbox-branching Diff / changelog object column.

The upstream ``OBJECTCHANGE_OBJECT`` template only renders ``record.object_repr``.
For ``dcim.Interface`` (and other components), NetBox's ``ComponentModel.__str__`` is
just the component name, so many devices share identical names (e.g. ``eno8303``).

We prefix ``device.name`` when the row's ``value`` (the NetBox instance) has a
``.device`` FK, without changing stored data or core models.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_PATCH_ATTR = "_nap_automation_branching_object_column_patch"

# Replaces netbox_branching.tables.tables.OBJECTCHANGE_OBJECT (shared by ChangeDiffTable
# and ChangesTable). Keep in sync with upstream if you upgrade netbox-branching.
_OBJECT_COLUMN_TEMPLATE = """
{% load helpers %}
{% load branching_ui %}
{% if value %}
{% with dname=value|branching_parent_device_name %}
{% if dname %}<span class="text-secondary">{{ dname }}</span><span class="text-muted"> · </span>{% endif %}
{{ value|linkify }}
{% endwith %}
{% else %}
{{ record.object_repr }}
{% endif %}
"""


def apply_branching_diff_object_column_patch() -> None:
    try:
        import netbox_branching.tables.tables as nbt
    except ImportError:
        return

    if getattr(nbt, _PATCH_ATTR, False):
        return

    nbt.OBJECTCHANGE_OBJECT = _OBJECT_COLUMN_TEMPLATE
    setattr(nbt, _PATCH_ATTR, True)
    logger.info(
        "Patched netbox_branching.tables.tables.OBJECTCHANGE_OBJECT "
        "to show parent device hostname for component objects in Diff/changelog tables."
    )
