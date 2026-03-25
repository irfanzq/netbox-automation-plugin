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

            if "VLAN_DRIFT" in st:
                if nb_vlan in {"", "—", "None", "none"}:
                    statuses.append("MISSING_NB_VLAN")
                    if authority == "openstack_runtime":
                        actions.append("SET_NETBOX_UNTAGGED_VLAN")
                    else:
                        actions.append("SET_NETBOX_UNTAGGED_VLAN")
                else:
                    statuses.append("VLAN_MISMATCH")
                    if authority == "openstack_runtime":
                        actions.append("SET_NETBOX_UNTAGGED_VLAN")
                    else:
                        actions.append("SET_NETBOX_UNTAGGED_VLAN")
                risk = "High"

            if "IP_GAP" in st:
                statuses.append("MISSING_NB_IP")
                if authority == "openstack_runtime":
                    actions.append("SET_NETBOX_IP")
                else:
                    actions.append("SET_NETBOX_IP")

            note_l = notes.lower()
            if ("netbox mac empty" in note_l) or ("mac mismatch" in note_l) or ("mac-drift" in note_l):
                if "mac mismatch" in note_l:
                    statuses.append("MAC_MISMATCH")
                else:
                    statuses.append("MISSING_NB_MAC")
                if authority == "openstack_runtime":
                    actions.append("SET_NETBOX_MAC")
                else:
                    actions.append("SET_NETBOX_MAC")

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
