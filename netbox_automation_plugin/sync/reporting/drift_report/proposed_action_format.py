"""
Canonical ``SET_NETBOX_*`` strings for drift / proposed-change **Proposed Action** cells.

Apply/reconciliation reads interface directives ``SET_NETBOX_MAC``, ``SET_NETBOX_UNTAGGED_VLAN``,
and ``SET_NETBOX_IP`` from this column (see ``apply_cells``). Workflow rows use ``SET_NETBOX_ACTION=…``
or ``SET_NETBOX_WORKFLOW=…`` so operators and automation share one vocabulary.

MAAS VLAN: use ``vlan.vid`` for directives, never ``vlan.id``. Numeric **0** omits
``SET_NETBOX_UNTAGGED_VLAN`` (MAAS native / untagged). See ``maas_client`` for the full mapping.
"""

from __future__ import annotations

import re

_PLACEHOLDER = frozenset({"", "—", "-", "None", "none", "NONE"})


def format_set_netbox_nic_directives(
    *,
    mac: str = "",
    vlan: str = "",
    ips: str = "",
) -> str:
    """``SET_NETBOX_MAC`` / ``SET_NETBOX_UNTAGGED_VLAN`` / ``SET_NETBOX_IP`` for new-NIC rows."""
    parts: list[str] = []
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
            if t and t not in _PLACEHOLDER:
                parts.append(f"SET_NETBOX_IP={t}")
    return "; ".join(parts)


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
