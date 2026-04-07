"""
Birch-only MAAS/OpenStack audit rules.

When the operator scopes an audit to NetBox locations (or sites) whose names/slugs all
contain ``birch``, stricter filtering applies: MAAS machines must be Deployed, proposed
new devices must appear in OpenStack inventory, and MAAS-authority NIC rows without OS
MAC are dropped.

**Exception:** hostnames containing ``-weka-`` (case-insensitive) are treated like
pre-Birch behavior for MAAS inclusion, OpenStack membership checks, placement alignment,
and MAAS-only NIC rows so Weka storage nodes stay in the audit when not Deployed or
not present in OpenStack inventory.
"""

from __future__ import annotations

# Birch audit: include these MAAS hosts even when Deployed-only / OpenStack gates would drop them.
_BIRCH_AUDIT_WILDCARD_HOST_SUBSTRING = "-weka-"


def birch_audit_hostname_is_weka_storage(hostname: str | None) -> bool:
    """
    True when the hostname should bypass strict Birch MAAS/OpenStack/NIC filters.

    Matches short or FQDN host labels containing ``-weka-`` (case-insensitive), e.g.
    ``b1-r2-weka-1``.
    """
    h = (hostname or "").strip().casefold()
    if not h:
        return False
    return _BIRCH_AUDIT_WILDCARD_HOST_SUBSTRING in h.split(".", 1)[0].strip()


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
