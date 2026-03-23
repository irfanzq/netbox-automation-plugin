"""NIC-row builders and drift-note helpers for proposed-change buckets."""

from netbox_automation_plugin.sync.reporting.drift_report.misc_utils import _dedupe_note_parts


def _build_add_nb_interface_rows(interface_audit):
    """
    MAAS NICs with a MAC that do not match any NetBox port on the device.
    Preview: proposed new NetBox ports (+ VLAN, IPs from MAAS).
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
            props = (
                f"MAC {mac}; untagged VLAN {vlan} (from MAAS); "
                f"IPs: {ips}"
            )
            out.append([
                hn,
                nb_site,
                nb_loc,
                maas_if,
                maas_fab,
                mac,
                ips,
                vlan,
                (
                    maas_if
                    if maas_if != "—"
                    else (f"maas-nic-{mac.replace(':', '')[-6:]}" if mac else "maas-nic")
                ),
                props,
                "Medium",
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
    return all(p == "OK" for p in parts)
