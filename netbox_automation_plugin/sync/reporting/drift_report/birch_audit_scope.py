"""
Birch-only MAAS/OpenStack audit rules.

When the operator scopes an audit to NetBox locations (or sites) whose names/slugs all
contain ``birch``, stricter filtering applies: MAAS machines must be Deployed, proposed
new devices must appear in OpenStack inventory, and MAAS-authority NIC rows without OS
MAC are dropped.
"""

from __future__ import annotations


def birch_audit_rules_active(scope_meta: dict | None) -> bool:
    """
    True when the run is scoped to Birch-only NetBox context (substring match, case-insensitive).

    - If specific **locations** were selected: every selected location name must contain ``birch``.
    - Else if only **sites** were selected (no location keys): every site slug must contain ``birch``.
    - Unscoped / all-locations audits: False.
    """
    if not scope_meta:
        return False
    locs = [str(x).strip() for x in (scope_meta.get("selected_locations") or []) if str(x).strip()]
    sites = [str(x).strip() for x in (scope_meta.get("selected_sites") or []) if str(x).strip()]
    if locs:
        return all("birch" in x.casefold() for x in locs)
    if sites:
        return all("birch" in x.casefold() for x in sites)
    return False


def _host_short_lower(name: str) -> str:
    s = (name or "").strip()
    if not s:
        return ""
    return s.split(".", 1)[0].strip().lower()


def openstack_hostnames_short(openstack_data: dict | None) -> set[str]:
    """
    Short hostnames (lowercase) from merged OpenStack data: Ironic ``runtime_bmc``,
    ``runtime_nics``, and Nova ``name`` / ``hypervisor_hostname``.
    """
    out: set[str] = set()
    if not openstack_data or openstack_data.get("error"):
        return out
    for key in ("runtime_bmc", "runtime_nics"):
        for row in openstack_data.get(key) or []:
            if not isinstance(row, dict):
                continue
            h = _host_short_lower(str(row.get("hostname") or ""))
            if h:
                out.add(h)
    for row in openstack_data.get("compute_instances") or []:
        if not isinstance(row, dict):
            continue
        for fld in ("name", "hypervisor_hostname"):
            h = _host_short_lower(str(row.get(fld) or ""))
            if h:
                out.add(h)
    return out
