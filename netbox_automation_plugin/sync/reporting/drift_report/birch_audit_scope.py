"""
Legacy Birch-scoped audit helpers (disabled).

Historically, when an audit was scoped to NetBox locations/sites whose names contained
``birch``, extra rules applied: MAAS was filtered to Deployed machines plus a ``-weka-``
hostname carve-out, OpenStack-gated MAAS-only hosts were skipped in some proposed tables,
and placement alignment omitted MAAS-only rows.

**Current behavior:** :func:`birch_audit_rules_active` is always false so Birch-scoped
runs use the **same** MAAS machine inventory and report logic as any other location
(full ``fetch_maas_data_sync`` list; no Deployed-only filter; no Weka substring gate).

The hostname helper and :func:`openstack_hostnames_short` remain for API compatibility
and tests; they are unused when Birch rules are inactive.
"""

from __future__ import annotations

# Legacy Birch carve-out (no longer used when rules are inactive).
_BIRCH_AUDIT_WILDCARD_HOST_SUBSTRING = "-weka-"


def birch_audit_hostname_is_weka_storage(hostname: str | None) -> bool:
    """
    True when the hostname label contains ``-weka-`` (case-insensitive), e.g. ``b1-r2-weka-1``.

    Retained for callers/tests; Birch audit rules no longer consult this by default.
    """
    h = (hostname or "").strip().casefold()
    if not h:
        return False
    return _BIRCH_AUDIT_WILDCARD_HOST_SUBSTRING in h.split(".", 1)[0].strip()


def birch_audit_rules_active(scope_meta: dict | None) -> bool:
    """
    Birch-only stricter audit rules are **disabled** (always false).

    ``scope_meta`` is ignored. Birch NetBox scope therefore uses the same MAAS and
    proposed-change behavior as other sites/locations.
    """
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
