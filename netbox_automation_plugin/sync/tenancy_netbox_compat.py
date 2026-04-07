"""NetBox version differences: Tenant.parent (legacy) vs Tenant.group (4.x+)."""

from __future__ import annotations


def tenant_hierarchy_fk() -> str | None:
    from django.core.exceptions import FieldDoesNotExist
    from tenancy.models import Tenant

    for name in ("parent", "group"):
        try:
            Tenant._meta.get_field(name)
            return name
        except FieldDoesNotExist:
            continue
    return None


def vlan_tenant_select_related_paths() -> tuple[str, ...]:
    rel = tenant_hierarchy_fk()
    if rel:
        return ("tenant", f"tenant__{rel}")
    return ("tenant",)
