"""
Template filters for netbox-branching UI tweaks loaded from netbox_automation_plugin.
"""

from __future__ import annotations

from django import template

register = template.Library()


@register.filter
def branching_parent_device_name(obj) -> str:
    """
    Hostname of the parent Device for component models (Interface, FrontPort, etc.).

    Used in the branch Diff table so rows show ``hostname · interface`` instead of only
    the interface name (which is ambiguous across devices).
    """
    if obj is None:
        return ""
    dev = getattr(obj, "device", None)
    if dev is None:
        return ""
    name = getattr(dev, "name", None)
    return (name or "").strip()
