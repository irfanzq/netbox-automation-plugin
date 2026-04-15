"""NIC-row builders and drift-note helpers for proposed-change buckets."""

from __future__ import annotations

from netbox_automation_plugin.sync.reporting.drift_report.misc_utils import _dedupe_note_parts
from netbox_automation_plugin.sync.reporting.drift_report.proposed_action_format import (
    SET_NETBOX_ACTION_REVIEW_PORT_ALIGNMENT,
    _PLACEHOLDER,
    format_set_netbox_nic_directives,
)
from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_derived import (
    derive_nic_proposed_columns,
)

def _nic_directive_field(os_val: str, maas_val: str, *, authority: str) -> str:
    """
    MAC / VLAN / IP blob to feed ``format_set_netbox_nic_directives`` for new-NIC rows.

    Matches NIC drift semantics: ``openstack_runtime`` uses OS only (no silent MAAS substitute
    when OS is empty); ``maas_fallback`` prefers MAAS then OS.
    """
    os_v = str(os_val or "").strip()
    maas_v = str(maas_val or "").strip()
    if authority == "openstack_runtime":
        if os_v and os_v not in _PLACEHOLDER:
            return os_v
        return ""
    if maas_v and maas_v not in _PLACEHOLDER:
        return maas_v
    if os_v and os_v not in _PLACEHOLDER:
        return os_v
    return ""


def _build_add_nb_interface_rows(
    interface_audit,
    vm_primary_hosts: frozenset[str] | None = None,
):
    """
    MAAS NICs with a MAC that do not match any NetBox port on the device.

    ``SET_NETBOX_*`` directives use MAAS inventory when authority is MAAS fallback; when
    authority is OpenStack runtime they use **OS** MAC / VLAN / IP only (no silent MAAS
    substitute if OS fields are empty). Reconciliation preview uses the same ``Authority``
    column via :func:`apply_cells._interface_mac_vlan_ip_from_cells`.
    """
    out = []
    for b in (interface_audit or {}).get("hosts") or []:
        hn = (b.get("hostname") or "").strip()
        if not hn:
            continue
        nb_site = (b.get("nb_site") or "—").strip()
        nb_loc = (b.get("nb_location") or "—").strip()
        for row in b.get("rows") or []:
            if (row.get("status") or "") != "NOT_IN_NETBOX":
                continue
            maas_if = (row.get("maas_if") or "").strip() or "—"
            maas_fab = str(row.get("maas_fabric") or "—")
            mac = (row.get("maas_mac") or "").strip()
            ips = (row.get("maas_ips") or "—").strip()
            vlan = str(row.get("maas_vlan") or "—")
            os_mac = (row.get("os_mac") or "—").strip()
            os_ip = (row.get("os_ip") or "—").strip()
            os_vlan = str(row.get("os_runtime_vlan") or "—")
            authority = str(row.get("authority") or "maas_fallback").strip()
            authority_badge = "[OS]" if authority == "openstack_runtime" else "[MAAS]"
            os_region = str(row.get("os_region") or "—").strip() or "—"
            dir_mac = _nic_directive_field(os_mac, mac, authority=authority)
            dir_vlan = _nic_directive_field(os_vlan, vlan, authority=authority)
            dir_ips = _nic_directive_field(os_ip, ips, authority=authority)
            props, nic_reason = format_set_netbox_nic_directives(
                mac=dir_mac,
                vlan=dir_vlan,
                ips=dir_ips,
                vm_primary_hosts=vm_primary_hosts,
            )
            if authority == "openstack_runtime" and not (props or "").strip():
                props = SET_NETBOX_ACTION_REVIEW_PORT_ALIGNMENT
                if nic_reason in _PLACEHOLDER or not (nic_reason or "").strip():
                    nic_reason = (
                        "OpenStack authority but runtime MAC/VLAN/IP not yet present for this "
                        "NIC; re-run audit when Neutron/Ironic data is available, or apply from MAAS "
                        "after switching authority."
                    )
            ex = derive_nic_proposed_columns(
                hn, row, bmc_mac=str(row.get("host_bmc_mac") or "")
            )
            out.append([
                hn,
                str(row.get("maas_status") or "—").strip() or "—",
                maas_if,
                maas_fab,
                mac,
                ips,
                vlan,
                ex["maas_link_speed_disp"],
                ex["maas_nic_model"],
                ex["maas_lldp_switch_disp"],
                ex["os_lldp_switch_disp"],
                os_region,
                os_mac or "—",
                os_ip or "—",
                os_vlan or "—",
                nb_site,
                nb_loc,
                ex["nb_proposed_intf_label"],
                ex["nb_proposed_intf_type"],
                (
                    maas_if
                    if maas_if != "—"
                    else (f"maas-nic-{mac.replace(':', '')[-6:]}" if mac else "maas-nic")
                ),
                authority_badge,
                props,
                nic_reason,
            ])
    return sorted(out, key=lambda x: (x[0] or "").lower())


def _friendly_note(raw: str) -> str:
    note = _dedupe_note_parts(raw or "")
    parts = [p.strip() for p in note.split(";") if p.strip()]
    low = note.lower()
    for p in parts:
        pl = p.lower()
        if "ip on maas not on nb iface:" in pl:
            return p
    for p in parts:
        pl = p.lower()
        if "ip" in pl and ("missing" in pl or "not on" in pl or "gap" in pl):
            return p
    non_mac = [
        p for p in parts
        if ("mac" not in p.lower() and "interface name" not in p.lower())
    ]
    for p in non_mac:
        pl = p.lower()
        if "ip" in pl:
            return p
    if "mac" in low:
        return "IP mismatch detected on this interface; review interface IP assignment."
    if "ip gap" in low:
        return "IP found in MAAS but missing on matching NetBox interface."
    if "vlan drift" in low:
        return "VLAN mismatch between MAAS and NetBox interface."
    if "vlan unverified" in low:
        return "MAAS did not return VLAN ID; verify VLAN manually."
    if "mac mismatch" in low:
        return "Matching interface name found, but MAC differs."
    return note or "Review interface data."


def _drift_table_status_is_ok_only(display_status: str) -> bool:
    """
    True when the drift Status column is only OK (after comma-split).
    e.g. "OK" or "OK, OK" -> skip; "MISSING_NB_VLAN, OK" -> False (still drifting).
    """
    parts = [p.strip().upper() for p in (display_status or "").split(",") if p.strip()]
    if not parts:
        return False
    return all(p in {"OK", "OK_NAME_DIFF", "NAME_DIFF_ONLY"} for p in parts)
