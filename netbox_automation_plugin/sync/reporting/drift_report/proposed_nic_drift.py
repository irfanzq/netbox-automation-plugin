"""NIC drift and serial-review rows for proposed-change buckets."""

from netbox_automation_plugin.sync.reporting.drift_report.misc_utils import _dedupe_note_parts
from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_helpers import (
    _drift_table_status_is_ok_only,
    _friendly_note,
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

            if st == "NOT_IN_NETBOX":
                continue

            if st.upper() == "OK":
                continue

            statuses = []
            reasons = []
            actions = []
            risk = "Medium"

            if "VLAN_DRIFT" in st:
                if nb_vlan in {"", "—", "None", "none"}:
                    statuses.append("MISSING_NB_VLAN")
                    reasons.append("NetBox VLAN missing; MAAS VLAN present")
                    actions.append("Set NetBox untagged VLAN from MAAS VLAN")
                else:
                    statuses.append("VLAN_MISMATCH")
                    reasons.append("NetBox VLAN differs from MAAS VLAN")
                    actions.append("Change NetBox untagged VLAN to match MAAS VLAN")
                risk = "High"

            if "IP_GAP" in st:
                statuses.append("MISSING_NB_IP")
                reasons.append(_friendly_note(notes))
                actions.append("Add missing IP on NetBox port")

            note_l = notes.lower()
            if ("netbox mac empty" in note_l) or ("mac mismatch" in note_l):
                if "mac mismatch" in note_l:
                    statuses.append("MAC_MISMATCH")
                else:
                    statuses.append("MISSING_NB_MAC")
                reasons.append("NetBox MAC missing or mismatched")
                actions.append("Set NetBox port MAC from MAAS for reliable matching")

            if not statuses:
                statuses.append(st)
                reasons.append(_dedupe_note_parts(notes) or "Port review needed")
                actions.append("Review port alignment manually")

            status_cell = ", ".join(dict.fromkeys(statuses))
            if _drift_table_status_is_ok_only(status_cell):
                continue

            update_nic.append([
                hn,
                row.get("maas_if") or "",
                str(row.get("maas_fabric") or "—"),
                row.get("maas_mac") or "",
                row.get("maas_ips") or "",
                row.get("nb_if") or "—",
                row.get("nb_mac") or "—",
                row.get("nb_ips") or "—",
                maas_vlan,
                nb_vlan,
                status_cell,
                "; ".join(dict.fromkeys([r for r in reasons if r])),
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
