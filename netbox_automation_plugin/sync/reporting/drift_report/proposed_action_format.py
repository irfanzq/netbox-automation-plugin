"""
Canonical ``SET_NETBOX_*`` strings for drift / proposed-change **Proposed Action** cells.

Apply/reconciliation reads interface directives ``SET_NETBOX_MAC``, ``SET_NETBOX_UNTAGGED_VLAN``,
and ``SET_NETBOX_IP`` from this column (see ``apply_cells``). Workflow rows use ``SET_NETBOX_ACTION=…``
or ``SET_NETBOX_WORKFLOW=…`` so operators and automation share one vocabulary.
When a host IP collides with a Nova VM primary in the same audit, omit ``SET_NETBOX_IP`` for that
address and surface the explanation in the drift table **Reason** column (not in Proposed Action).

MAAS VLAN: use ``vlan.vid`` for directives, never ``vlan.id``. Numeric **0** omits
``SET_NETBOX_UNTAGGED_VLAN`` (MAAS native / untagged). See ``maas_client`` for the full mapping.
"""

from __future__ import annotations

import re

_PLACEHOLDER = frozenset({"", "—", "-", "None", "none", "NONE"})


def _ip_token_host_only(token: str) -> str | None:
    t = (token or "").strip().split()[0] if token else ""
    if not t or t in _PLACEHOLDER:
        return None
    return t.split("/", 1)[0].strip().lower() or None


def nova_vm_primary_ip_host_set(openstack_data: dict | None) -> frozenset[str]:
    """
    Host-only IPv4/IPv6 strings from each Nova instance's ``os_primary_ip`` (same pick as VM drift rows).

    Used to avoid proposing ``SET_NETBOX_IP`` on DCIM interfaces when that address is already the
    audited VM primary (Ironic overlap).
    """
    hosts: set[str] = set()
    for inst in (openstack_data or {}).get("compute_instances") or []:
        raw = str(inst.get("os_primary_ip") or "").strip()
        if not raw or raw in _PLACEHOLDER:
            continue
        h = _ip_token_host_only(raw)
        if h:
            hosts.add(h)
    return frozenset(hosts)


def vm_primary_ip_defer_reason(deferred_hosts: list[str]) -> str:
    """Operator text for the NIC **Reason** column when device-interface IPs overlap VM primaries."""
    if not deferred_hosts:
        return "—"
    uniq = ", ".join(dict.fromkeys(deferred_hosts))
    if len(uniq) > 220:
        uniq = uniq[:217] + "…"
    return (
        "Address(es) "
        + uniq
        + " match a Nova VM primary IP in this audit; NetBox cannot attach the same IP to this "
        "device interface (duplicate)—model the IP on the Virtual Machine (Ironic overlap)."
    )


def format_set_netbox_nic_directives(
    *,
    mac: str = "",
    vlan: str = "",
    ips: str = "",
    vm_primary_hosts: frozenset[str] | None = None,
) -> tuple[str, str]:
    """
    Build ``SET_NETBOX_*`` directives for new-NIC **Proposed Action** only.

    Returns ``(proposed_action, reason)`` where *reason* is ``vm_primary_ip_defer_reason`` when any
    IP was omitted, else ``"—"``.
    """
    parts: list[str] = []
    vm_primary_hosts = vm_primary_hosts or frozenset()
    deferred_hosts: list[str] = []
    m = str(mac or "").strip()
    if m and m not in _PLACEHOLDER:
        parts.append(f"SET_NETBOX_MAC={m}")
    v = str(vlan or "").strip()
    if v and v not in _PLACEHOLDER:
        # MAAS ``vlan.vid`` 0 = untagged/native (not 1–4094); omit ``SET_NETBOX_UNTAGGED_VLAN``.
        try:
            if int(v, 10) == 0:
                v = ""
        except ValueError:
            pass
        if v:
            parts.append(f"SET_NETBOX_UNTAGGED_VLAN={v}")
    raw_ips = str(ips or "").strip()
    if raw_ips and raw_ips not in _PLACEHOLDER:
        for chunk in re.split(r"[,;\s]+", raw_ips):
            t = chunk.strip()
            if not t or t in _PLACEHOLDER:
                continue
            h = _ip_token_host_only(t)
            if h and h in vm_primary_hosts:
                if h not in deferred_hosts:
                    deferred_hosts.append(h)
                continue
            parts.append(f"SET_NETBOX_IP={t}")
    reason = vm_primary_ip_defer_reason(deferred_hosts) if deferred_hosts else "—"
    return "; ".join(parts), reason


# --- Reconciliation routing / row labels (with existing handler semantics) ---

SET_NETBOX_ACTION_CREATE_DEVICE = "SET_NETBOX_ACTION=CREATE_DEVICE_AND_PORTS"
SET_NETBOX_ACTION_REVIEW_DEVICE = "SET_NETBOX_ACTION=REVIEW_ONLY_NOT_SAFE_CANDIDATE"
SET_NETBOX_ACTION_CREATE_PREFIX = "SET_NETBOX_ACTION=CREATE_PREFIX_FROM_OS"
SET_NETBOX_ACTION_CREATE_FIP = "SET_NETBOX_ACTION=CREATE_FLOATING_IP_FROM_OS"
SET_NETBOX_ACTION_UPDATE_PREFIX = "SET_NETBOX_ACTION=UPDATE_PREFIX_FROM_OS"
SET_NETBOX_ACTION_UPDATE_FIP_NAT = "SET_NETBOX_ACTION=UPDATE_FLOATING_IP_NAT_FROM_OS"
SET_NETBOX_ACTION_CREATE_VM = "SET_NETBOX_ACTION=CREATE_VM_FROM_OPENSTACK"
SET_NETBOX_ACTION_UPDATE_VM = "SET_NETBOX_ACTION=UPDATE_VM_FROM_OPENSTACK"
SET_NETBOX_ACTION_SERIAL_REVIEW = "SET_NETBOX_ACTION=SERIAL_REVIEW_MANUAL"
SET_NETBOX_ACTION_REVIEW_PORT_ALIGNMENT = "SET_NETBOX_ACTION=REVIEW_PORT_ALIGNMENT"
SET_NETBOX_WORKFLOW_PLACEMENT = "SET_NETBOX_WORKFLOW=PLACEMENT_DEVICE_ALIGNMENT"
SET_NETBOX_ACTION_LLDP_REVIEW = "SET_NETBOX_ACTION=REVIEW_LLDP_CABLING"
SET_NETBOX_ACTION_CREATE_VLAN = "SET_NETBOX_ACTION=CREATE_VLAN_FROM_DRIFT"
SET_NETBOX_ACTION_CREATE_TENANT = "SET_NETBOX_ACTION=CREATE_TENANT_FROM_OPENSTACK_PROJECT"
SET_NETBOX_ACTION_CREATE_NAT_INSIDE_IP = "SET_NETBOX_ACTION=CREATE_NAT_INSIDE_IP_FROM_OPENSTACK_FIXED"


def format_placement_proposed_action(human_hints: str) -> str:
    """Placement/lifecycle table: workflow token plus operator-visible hint text."""
    h = (human_hints or "").strip()
    if not h or h in _PLACEHOLDER:
        return SET_NETBOX_WORKFLOW_PLACEMENT
    return f"{SET_NETBOX_WORKFLOW_PLACEMENT}; {h}"


def prefix_lldp_proposed_action(detail: str) -> str:
    t = (detail or "").strip()
    if not t:
        return SET_NETBOX_ACTION_LLDP_REVIEW
    return f"{SET_NETBOX_ACTION_LLDP_REVIEW}; {t}"
