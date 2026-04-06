"""
Template filters for netbox-branching UI tweaks loaded from netbox_automation_plugin.
"""

from __future__ import annotations

from django import template

register = template.Library()


@register.filter
def branching_parent_device_name(obj) -> str:
    """
    Hostname of the parent Device for component models (Interface, FrontPort, etc.),
    or the device of an interface an IPAddress is assigned to (floating / NIC IPs).

    Used in the branch Diff table so rows show ``hostname · object`` instead of only
    the short ``__str__`` (ambiguous across devices).
    """
    if obj is None:
        return ""
    dev = getattr(obj, "device", None)
    if dev is not None:
        name = getattr(dev, "name", None)
        return (name or "").strip()
    # IPAddress.assigned_object → Interface (or FHRP) → device
    ao = getattr(obj, "assigned_object", None)
    if ao is not None:
        dev2 = getattr(ao, "device", None)
        if dev2 is not None:
            name = getattr(dev2, "name", None)
            return (name or "").strip()
    return ""
