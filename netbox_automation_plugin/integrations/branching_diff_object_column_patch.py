"""
Show parent device hostname in netbox-branching Diff / changelog object column.

The upstream ``OBJECTCHANGE_OBJECT`` template only renders ``record.object_repr``.
For ``dcim.Interface`` (and other components), NetBox's ``ComponentModel.__str__`` is
just the component name, so many devices share identical names (e.g. ``eno8303``).

We prefix ``device.name`` when the row's ``value`` (the NetBox instance) has a
``.device`` FK, or when an ``IPAddress`` is assigned to an interface (FIP rows).

**Important:** ``TemplateColumn(template_code=OBJECTCHANGE_OBJECT)`` binds the template
string at **class definition time**. Patching only ``nbt.OBJECTCHANGE_OBJECT`` after
import does **not** update existing columns — we must set ``template_code`` on
``ChangeDiffTable`` / ``ChangesTable`` column instances.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_PATCH_ATTR = "_nap_automation_branching_object_column_patch"

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


def _patch_template_column(module, table_cls_name: str, column_name: str, template: str) -> bool:
    tbl = getattr(module, table_cls_name, None)
    if tbl is None:
        return False
    cols = getattr(tbl, "base_columns", None)
    if cols is None:
        return False
    try:
        col = cols[column_name]
    except Exception:
        return False
    try:
        col.template_code = template
    except Exception:
        logger.debug(
            "Could not set template_code on %s.%s",
            table_cls_name,
            column_name,
            exc_info=True,
        )
        return False
    return True


def apply_branching_diff_object_column_patch() -> None:
    try:
        import netbox_branching.tables.tables as nbt
    except ImportError:
        return

    if getattr(nbt, _PATCH_ATTR, False):
        return

    nbt.OBJECTCHANGE_OBJECT = _OBJECT_COLUMN_TEMPLATE
    patched = []
    if _patch_template_column(nbt, "ChangeDiffTable", "object", _OBJECT_COLUMN_TEMPLATE):
        patched.append("ChangeDiffTable.object")
    if _patch_template_column(nbt, "ChangesTable", "object_repr", _OBJECT_COLUMN_TEMPLATE):
        patched.append("ChangesTable.object_repr")

    setattr(nbt, _PATCH_ATTR, True)
    if patched:
        logger.info(
            "Patched netbox-branching object column template for: %s "
            "(hostname prefix for interfaces, FIPs on interfaces, etc.)",
            ", ".join(patched),
        )
    else:
        logger.warning(
            "netbox_branching tables patch: no TemplateColumn was updated; "
            "Diff object column may not show hostnames."
        )
