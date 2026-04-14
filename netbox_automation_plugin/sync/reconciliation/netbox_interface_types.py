"""
``dcim.Interface.type`` slugs from the running NetBox app's ``InterfaceTypeChoices``.

BMC **OOB** rows use :func:`netbox_oob_interface_type_when_unknown_slug` when link type is
unknown (honest ``other``). Generic new-interface creates still use
:func:`netbox_default_bmc_interface_type_slug` (1 GbE-style default). All slugs match this
NetBox instance’s ``InterfaceTypeChoices``.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any


@lru_cache(maxsize=1)
def _interface_type_slugs_from_netbox() -> frozenset[str]:
    try:
        from dcim.choices import InterfaceTypeChoices
        from utilities.choices import unpack_grouped_choices

        return frozenset(
            str(v).strip()
            for v, _ in unpack_grouped_choices(InterfaceTypeChoices.CHOICES)
            if v is not None and str(v).strip() != ""
        )
    except Exception:
        return frozenset()


def _normalize_interface_type_cell_text(cell_val: Any) -> str:
    """Strip HTML / odd whitespace so drift cells and pasted UI labels still resolve."""
    try:
        from django.utils.encoding import force_str
        from django.utils.html import strip_tags
    except Exception:
        force_str = str  # type: ignore[assignment]
        strip_tags = lambda x: x  # type: ignore[assignment,misc]
    s = strip_tags(force_str(cell_val or ""))
    s = s.replace("\u00a0", " ").replace("\u2007", " ").replace("\u202f", " ")
    s = " ".join(s.split()).strip()
    return s


def resolve_interface_type_slug(cell_val: Any) -> str | None:
    """
    Return the NetBox ``dcim.Interface.type`` **slug** for a drift/review cell value.

    Accepts canonical slugs (any casing), human labels from ``InterfaceTypeChoices`` (including
    translated ``gettext`` labels), and common noisy exports (HTML fragments, NBSPs).
    """
    s = _normalize_interface_type_cell_text(cell_val)
    if not s or s in ("—", "-"):
        return None
    slow = s.lower()
    try:
        from dcim.choices import InterfaceTypeChoices
        from django.utils.encoding import force_str
        from utilities.choices import unpack_grouped_choices
    except Exception:
        return None
    try:
        flat = unpack_grouped_choices(InterfaceTypeChoices.CHOICES)
    except Exception:
        return None
    for val, lab in flat:
        if val is None or str(val).strip() == "":
            continue
        vs = str(val).strip()
        if vs.lower() == slow:
            return vs
    for val, lab in flat:
        if val is None or str(val).strip() == "":
            continue
        try:
            lab_s = force_str(lab).strip()
        except Exception:
            lab_s = str(lab).strip()
        if lab_s.lower() == slow:
            return str(val).strip()
    return None


def coerce_interface_type_slug_for_orm(type_slug: Any) -> str | None:
    """
    Normalize a value intended for ``Interface.type`` to a valid choice slug, or ``None``.

    Use before ORM assignment so display strings (e.g. title-cased pasted labels) never reach
    the database when they are mappable to a slug.
    """
    if type_slug is None:
        return None
    t = str(type_slug).strip()
    if not t:
        return None
    resolved = resolve_interface_type_slug(t)
    if resolved is not None:
        return resolved
    valid = _interface_type_slugs_from_netbox()
    if valid and t in valid:
        return t
    return None


def netbox_default_bmc_interface_type_slug() -> str:
    """
    Default ``Interface.type`` for BMC / dedicated management (typically 1 GbE copper).

    Picks ``InterfaceTypeChoices.TYPE_1GE_FIXED`` (``1000base-t``) when present in the
    live choice set; otherwise first match from a short fallback list, else any sorted
    slug. If introspection fails, returns ``1000base-t``.
    """
    try:
        from dcim.choices import InterfaceTypeChoices
    except Exception:
        return "1000base-t"
    preferred = getattr(InterfaceTypeChoices, "TYPE_1GE_FIXED", None) or "1000base-t"
    valid = _interface_type_slugs_from_netbox()
    if valid:
        if preferred in valid:
            return preferred
        for p in ("1000base-t", "10gbase-t", "1000base-x-sfp"):
            if p in valid:
                return p
        return sorted(valid)[0]
    return str(preferred)


def netbox_oob_interface_type_when_unknown_slug() -> str:
    """
    ``Interface.type`` when BMC/OOB link technology is **not** known from MAAS, Redfish, etc.

    Uses ``other`` so NetBox does not claim a specific PHY (e.g. 1 GbE copper) without evidence.
    Falls back to :func:`netbox_default_bmc_interface_type_slug` only if ``other`` is absent
    from this NetBox version’s choice set.
    """
    valid = _interface_type_slugs_from_netbox()
    if valid and "other" in valid:
        return "other"
    return netbox_default_bmc_interface_type_slug()


def all_netbox_interface_type_slugs_sorted() -> list[str]:
    """Every ``Interface.type`` value slug, for drift HTML pickers."""
    s = _interface_type_slugs_from_netbox()
    if s:
        return sorted(s)
    return [netbox_default_bmc_interface_type_slug()]
