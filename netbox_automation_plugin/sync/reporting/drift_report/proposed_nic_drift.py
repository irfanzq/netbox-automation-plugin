"""NIC drift and serial-review rows for proposed-change buckets."""

from __future__ import annotations

import re

from netbox_automation_plugin.sync.reporting.drift_report.proposed_action_format import (
    SET_NETBOX_ACTION_REVIEW_PORT_ALIGNMENT,
    SET_NETBOX_ACTION_SERIAL_REVIEW,
    vm_primary_ip_defer_reason,
)
from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_derived import (
    derive_nic_proposed_columns,
)
from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_helpers import (
    _drift_table_status_is_ok_only,
)


def _drift_row_nb_placement_cells(row: dict) -> tuple[str, str, str]:
    """NetBox site / location / VLAN group from interface audit (for apply + missing-VLAN hints)."""
    _sentinel = frozenset({"", "—", "-", "(none)", "None", "none"})

    def _clean(x: str) -> str:
        s = str(x or "").strip()
        return "" if s in _sentinel else s

    return (
        _clean(row.get("nb_site")),
        _clean(row.get("nb_location")),
        _clean(row.get("nb_proposed_vlan_group")),
    )


def _vlan_vid_token_ok(v: str) -> bool:
    t = str(v or "").strip()
    if not t or t in ("—", "-", "None", "none"):
        return False
    try:
        n = int(t)
    except ValueError:
        return False
    return 1 <= n <= 4094


def _mac_token_ok(v: str) -> bool:
    t = str(v or "").strip().lower().replace("-", ":")
    if not t or t in ("—", "-", "none", "n/a"):
        return False
    parts = [p for p in t.split(":") if p]
    if len(parts) != 6:
        return False
    try:
        for p in parts:
            int(p, 16)
    except ValueError:
        return False
    return True


def _build_update_nic_rows(
    interface_audit,
    vm_primary_hosts: frozenset[str] | None = None,
):
    update_nic = []
    vm_primary_hosts = vm_primary_hosts or frozenset()
    for b in (interface_audit or {}).get("hosts") or []:
        hn = b.get("hostname", "")
        for row in b.get("rows") or []:
            st = str(row.get("status") or "").strip()
            notes = row.get("notes") or ""
            maas_vlan = str(row.get("maas_vlan") or "—")
            nb_vlan = str(row.get("nb_vlan") or "—")
            os_vlan = str(row.get("os_runtime_vlan") or "—")
            os_ip = row.get("os_ip") or "—"
            os_mac = row.get("os_mac") or "—"
            authority = str(row.get("authority") or "maas_fallback")
            authority_badge = "[OS]" if authority == "openstack_runtime" else "[MAAS]"
            os_region = str(row.get("os_region") or "—").strip() or "—"

            if st == "NOT_IN_NETBOX":
                continue

            if st.upper() == "OK":
                continue

            statuses = []
            actions = []
            reason_cell = "—"
            maas_mac = str(row.get("maas_mac") or "").strip() or "—"
            maas_ips = str(row.get("maas_ips") or "").strip() or "—"

            def _preferred_value(os_val: str, maas_val: str) -> str:
                """
                Runtime target for SET_NETBOX_* tokens.

                When ``authority`` is OpenStack runtime, MAAS must not silently substitute
                for missing OS fields (Neutron/Ironic can lag one audit behind host-level
                ``openstack_runtime``). MAAS fallback applies only for ``maas_fallback`` rows.
                """
                os_v = str(os_val or "").strip()
                maas_v = str(maas_val or "").strip()
                if authority == "openstack_runtime":
                    if os_v not in {"", "—", "-", "None", "none"}:
                        return os_v
                    return "—"
                if maas_v not in {"", "—", "-", "None", "none"}:
                    return maas_v
                if os_v:
                    return os_v
                return "—"

            if "VLAN_DRIFT" in st:
                if nb_vlan in {"", "—", "None", "none"}:
                    statuses.append("MISSING_NB_VLAN")
                else:
                    statuses.append("VLAN_MISMATCH")
                vlan_target = _preferred_value(os_vlan, maas_vlan)
                if _vlan_vid_token_ok(vlan_target):
                    actions.append(f"SET_NETBOX_UNTAGGED_VLAN={vlan_target}")

            if "IP_GAP" in st:
                statuses.append("MISSING_NB_IP")
                ip_target = _preferred_value(os_ip, maas_ips)
                deferred_hosts: list[str] = []
                kept_set: list[str] = []
                if ip_target and ip_target not in {"", "—", "-", "None", "none"}:
                    for chunk in re.split(r"[,;\s]+", str(ip_target)):
                        t = chunk.strip()
                        if not t or t in {"", "—", "-", "None", "none"}:
                            continue
                        host = t.split("/", 1)[0].strip().lower()
                        if vm_primary_hosts and host in vm_primary_hosts:
                            if host not in deferred_hosts:
                                deferred_hosts.append(host)
                        else:
                            kept_set.append(f"SET_NETBOX_IP={t}")
                if deferred_hosts:
                    reason_cell = vm_primary_ip_defer_reason(deferred_hosts)
                actions.extend(kept_set)

            note_l = notes.lower()
            if ("netbox mac empty" in note_l) or ("mac mismatch" in note_l) or ("mac-drift" in note_l):
                if "mac mismatch" in note_l:
                    statuses.append("MAC_MISMATCH")
                else:
                    statuses.append("MISSING_NB_MAC")
                mac_target = _preferred_value(os_mac, maas_mac)
                if _mac_token_ok(mac_target):
                    actions.append(f"SET_NETBOX_MAC={mac_target}")

            # VLAN drift with no safe SET_NETBOX_UNTAGGED_VLAN (e.g. OS authority but runtime VID
            # not yet in the row): keep a review row instead of dropping the proposed line entirely.
            if statuses and not actions and "VLAN_DRIFT" in st and "IP_GAP" not in st:
                actions.append(SET_NETBOX_ACTION_REVIEW_PORT_ALIGNMENT)

            if not statuses:
                statuses.append(st)
                actions.append(SET_NETBOX_ACTION_REVIEW_PORT_ALIGNMENT)

            status_cell = ", ".join(dict.fromkeys(statuses))
            if _drift_table_status_is_ok_only(status_cell):
                continue

            action_str = "; ".join(dict.fromkeys([a for a in actions if a]))
            if not action_str.strip():
                # Drift is informational only (e.g. IP_GAP where every runtime IP is deferred
                # because it matches a Nova VM primary elsewhere); nothing is safe to apply.
                continue

            ex = derive_nic_proposed_columns(
                hn, row, bmc_mac=str(row.get("host_bmc_mac") or "")
            )
            nb_site_c, nb_loc_c, nb_vg_c = _drift_row_nb_placement_cells(row)
            update_nic.append([
                hn,
                str(row.get("maas_status") or "—").strip() or "—",
                row.get("maas_if") or "",
                str(row.get("maas_fabric") or "—"),
                row.get("maas_mac") or "",
                row.get("maas_ips") or "",
                maas_vlan,
                ex["maas_link_speed_disp"],
                ex["maas_nic_model"],
                ex["maas_lldp_switch_disp"],
                ex["os_lldp_switch_disp"],
                os_region,
                os_mac,
                os_ip,
                os_vlan,
                nb_site_c,
                nb_loc_c,
                nb_vg_c,
                row.get("nb_if") or "—",
                row.get("nb_mac") or "—",
                row.get("nb_ips") or "—",
                nb_vlan,
                ex["nb_proposed_intf_label"],
                ex["nb_proposed_intf_type"],
                authority_badge,
                action_str,
                reason_cell,
            ])
    return update_nic


def _build_review_serial_rows(matched_rows):
    review_serial = []
    for r in (matched_rows or []):
        if any("NB serial empty" in (h or "") for h in (r.get("hints") or [])):
            review_serial.append([
                r.get("hostname", ""),
                str(r.get("maas_serial", "")),
                str(r.get("netbox_serial", "")),
                SET_NETBOX_ACTION_SERIAL_REVIEW,
            ])
    return review_serial
