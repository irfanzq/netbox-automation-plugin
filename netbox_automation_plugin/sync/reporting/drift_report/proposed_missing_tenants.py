"""Propose NetBox Tenant rows for OpenStack projects referenced by floating IPs only in NetBox."""

from __future__ import annotations

from typing import Any

from netbox_automation_plugin.sync.reporting.drift_report.proposed_action_format import (
    SET_NETBOX_ACTION_CREATE_TENANT,
)


def _fip_openstack_project_cell(g: dict[str, Any]) -> str:
    s = str(
        g.get("project_name")
        or g.get("project_owner_name")
        or g.get("project_id")
        or ""
    ).strip()
    if not s or s in {"-", "—"}:
        return "—"
    return s


def _openstack_projects_for_floating_ip_gaps(gap_dicts: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for g in gap_dicts or []:
        if not isinstance(g, dict):
            continue
        p = _fip_openstack_project_cell(g)
        if not p or p in {"—", "-"}:
            continue
        if p.lower() in seen:
            continue
        seen.add(p.lower())
        out.append(p)
    return out


def build_proposed_missing_tenant_rows(
    *,
    os_floating_gap_dicts: list[dict[str, Any]] | None,
    fip_nat_drift_dicts: list[dict[str, Any]] | None,
) -> list[list[Any]]:
    """
    One row per distinct OpenStack project name on floating-IP drift that does not yet resolve
    to a NetBox :class:`~tenancy.models.Tenant` via :func:`apply_cells._resolve_tenant`.
    """
    names: list[str] = []
    seen: set[str] = set()
    for bucket in (os_floating_gap_dicts or [], fip_nat_drift_dicts or []):
        for p in _openstack_projects_for_floating_ip_gaps(list(bucket)):
            if p.lower() in seen:
                continue
            seen.add(p.lower())
            names.append(p)

    if not names:
        return []

    from netbox_automation_plugin.sync.reconciliation.apply_cells import _resolve_tenant

    rows: list[list[Any]] = []
    for project in sorted(names, key=str.lower):
        if _resolve_tenant(project) is not None:
            continue
        rows.append(
            [
                project,
                project,
                "",
                SET_NETBOX_ACTION_CREATE_TENANT,
            ]
        )
    return rows
