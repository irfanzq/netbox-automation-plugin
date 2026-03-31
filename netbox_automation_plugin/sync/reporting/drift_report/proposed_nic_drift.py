"""NIC drift and serial-review rows for proposed-change buckets."""

from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_helpers import (
    _drift_table_status_is_ok_only,
)


def _build_update_nic_rows(interface_audit):
    update_nic = []
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
            risk = "Medium"
            maas_mac = str(row.get("maas_mac") or "").strip() or "—"
            maas_ips = str(row.get("maas_ips") or "").strip() or "—"

            def _preferred_value(os_val: str, maas_val: str) -> tuple[str, str]:
                os_v = str(os_val or "").strip()
                maas_v = str(maas_val or "").strip()
                if authority == "openstack_runtime" and os_v not in {"", "—", "-", "None", "none"}:
                    return os_v, "OS runtime"
                if maas_v not in {"", "—", "-", "None", "none"}:
                    return maas_v, "MAAS"
                if os_v:
                    return os_v, "OS runtime"
                return "—", "MAAS"

            def _format_set_action(name: str, value: str, source: str) -> str:
                # MAAS-fallback table should not carry "(from ...)" suffixes.
                if authority == "openstack_runtime":
                    return f"{name}={value} (from {source})"
                return f"{name}={value}"

            if "VLAN_DRIFT" in st:
                if nb_vlan in {"", "—", "None", "none"}:
                    statuses.append("MISSING_NB_VLAN")
                else:
                    statuses.append("VLAN_MISMATCH")
                vlan_target, vlan_src = _preferred_value(os_vlan, maas_vlan)
                actions.append(_format_set_action("SET_NETBOX_UNTAGGED_VLAN", vlan_target, vlan_src))
                risk = "High"

            if "IP_GAP" in st:
                statuses.append("MISSING_NB_IP")
                ip_target, ip_src = _preferred_value(os_ip, maas_ips)
                actions.append(_format_set_action("SET_NETBOX_IP", ip_target, ip_src))

            note_l = notes.lower()
            if ("netbox mac empty" in note_l) or ("mac mismatch" in note_l) or ("mac-drift" in note_l):
                if "mac mismatch" in note_l:
                    statuses.append("MAC_MISMATCH")
                else:
                    statuses.append("MISSING_NB_MAC")
                mac_target, mac_src = _preferred_value(os_mac, maas_mac)
                actions.append(_format_set_action("SET_NETBOX_MAC", mac_target, mac_src))

            if not statuses:
                statuses.append(st)
                actions.append("REVIEW_PORT_ALIGNMENT")

            status_cell = ", ".join(dict.fromkeys(statuses))
            if _drift_table_status_is_ok_only(status_cell):
                continue

            update_nic.append([
                hn,
                row.get("maas_if") or "",
                str(row.get("maas_fabric") or "—"),
                row.get("maas_mac") or "",
                row.get("maas_ips") or "",
                maas_vlan,
                os_region,
                os_mac,
                os_ip,
                os_vlan,
                authority_badge,
                row.get("nb_if") or "—",
                row.get("nb_mac") or "—",
                row.get("nb_ips") or "—",
                nb_vlan,
                status_cell,
                "; ".join(dict.fromkeys([a for a in actions if a])),
                risk,
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
                "Manual validation",
                "High",
            ])
    return review_serial
