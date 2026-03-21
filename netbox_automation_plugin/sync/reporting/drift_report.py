"""
Generate human-readable drift audit report from MAAS, NetBox, and OpenStack data.
Uses ASCII tables (+---+) for readability in <pre> or plain text.
XLSX export via build_drift_report_xlsx() for download (openpyxl); Google Sheets opens .xlsx.

Copy in this module distinguishes **host data NICs** (Ethernet MAC/IP/VLAN) from **BMC / OOB**
(IPMI, iDRAC, Redfish — baseboard management controllers, not “another NIC”). NetBox models OOB
as **device OOB IP** plus an optional **OOB port** marked management-only in NetBox,
which documents the management attachment — not the same as in-band NICs.
"""

from io import BytesIO
import re

_MAX_MAAS_MISSING_ROWS = 500
_MAX_OS_NETWORKS = 40
_MAX_OS_SUBNET_HINTS = 60
_MAX_COL = 10000
_MAX_MATCHED_COL = 18
_MAX_NOTES_COL = 42
# Notes column: full text for scrollable HTML report (avoid truncation)
_NOTES_COL_MAX_WIDTH = 8000
# Matched-hosts style tables: full cell text per column (no mid-cell truncation)
_DYNAMIC_COL_CAP = 10000


def _dedupe_keep_order(items):
    seen = set()
    out = []
    for raw in (items or []):
        s = (str(raw or "")).strip()
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


def _format_inventory_list(
    items,
    *,
    noisy_regex=None,
    noisy_label="auto-generated",
    sample=20,
    max_named_display=35,
):
    vals = _dedupe_keep_order(items)
    if not vals:
        return "(none)"
    if not noisy_regex:
        if len(vals) <= max_named_display:
            return ", ".join(vals)
        show = vals[:max_named_display]
        more = len(vals) - len(show)
        return f"{', '.join(show)}, ... +{more} more unique"
    pat = re.compile(noisy_regex)
    noisy = [v for v in vals if pat.match(v)]
    named = [v for v in vals if not pat.match(v)]
    parts = []
    if named:
        show_n = named[:max_named_display]
        more_n = len(named) - len(show_n)
        txt_n = ", ".join(show_n)
        if more_n > 0:
            txt_n = f"{txt_n}, ... +{more_n} more named"
        parts.append(f"named ({len(named)} unique): {txt_n}")
    if noisy:
        show = noisy[:sample]
        more = len(noisy) - len(show)
        txt = ", ".join(show)
        if more > 0:
            txt = f"{txt}, ... +{more} more"
        parts.append(f"{noisy_label} ({len(noisy)} unique): {txt}")
    return " | ".join(parts) if parts else "(none)"


def _maas_machine_by_hostname(maas_data):
    out = {}
    for m in maas_data.get("machines") or []:
        h = (m.get("hostname") or "").strip()
        if h:
            out[h] = m
    return out


def _cell(s, w):
    s = str(s).replace("\n", " ").replace("\r", "") if s is not None else ""
    if len(s) > w:
        s = s[: max(1, w - 2)] + ".."
    return s.ljust(w)


def _ascii_table(
    headers,
    rows,
    indent="  ",
    *,
    max_col=None,
    notes_col_idx=None,
    dynamic_columns=True,
):
    """
    dynamic_columns: size every column to content (caps: notes col 8000, else 140).
    One ASCII line per data row — use with horizontal scroll in HTML.
    """
    if not headers:
        return []
    n = len(headers)
    widths = []
    for i in range(n):
        if dynamic_columns:
            w = max(len(str(headers[i])), 6)
            for r in rows:
                if i < len(r):
                    cell = str(r[i]).replace("\n", " ").replace("\r", "")
                    w = max(w, len(cell))
            if notes_col_idx is not None and i == notes_col_idx:
                widths.append(min(w, _NOTES_COL_MAX_WIDTH))
            else:
                widths.append(min(w, _DYNAMIC_COL_CAP))
            continue
        if notes_col_idx is not None and i == notes_col_idx:
            w = max(len(str(headers[i])), 8)
            for r in rows:
                if i < len(r):
                    cell = str(r[i]).replace("\n", " ").replace("\r", "")
                    w = max(w, len(cell))
            widths.append(min(w, _NOTES_COL_MAX_WIDTH))
            continue
        cap = max_col if max_col is not None else _MAX_COL
        w = min(max(len(headers[i]), 5), cap)
        for r in rows:
            if i < len(r):
                w = min(max(w, min(len(str(r[i])), cap + 10)), cap)
        widths.append(w)
    sep = indent + "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    out = [sep]
    out.append(
        indent + "|" + "|".join(" " + _cell(headers[i], widths[i]) + " " for i in range(n)) + "|"
    )
    out.append(sep)
    for r in rows:
        padded = list(r[:n]) + [""] * (n - min(len(r), n))
        out.append(
            indent + "|" + "|".join(" " + _cell(padded[i], widths[i]) + " " for i in range(n)) + "|"
        )
    out.append(sep)
    return out


def _banner(title, char="=", width=72):
    line = char * width
    return [line, f"  {title}", line]


def _phase0_category_counts(
    drift,
    matched_rows,
    interface_audit,
    os_subnet_gaps,
    os_floating_gaps,
):
    maas_only = len(drift.get("in_maas_not_netbox") or [])
    nb_only_dev = len(drift.get("in_netbox_not_maas") or [])
    check_hosts = sum(1 for r in (matched_rows or []) if r.get("place_match") == "CHECK")
    nb_only_nic = 0
    iface_not_ok = 0
    maas_nic_missing_nb = 0
    vlan_drift_nic = 0
    vlan_unverified_nic = 0
    for b in (interface_audit or {}).get("hosts") or []:
        nb_only_nic += len(b.get("netbox_only") or [])
        for row in b.get("rows") or []:
            st = row.get("status") or ""
            if st != "OK":
                iface_not_ok += 1
            if st == "NOT_IN_NETBOX":
                maas_nic_missing_nb += 1
            if st.startswith("VLAN_DRIFT"):
                vlan_drift_nic += 1
            notes = row.get("notes") or ""
            if "VLAN unverified:" in notes:
                vlan_unverified_nic += 1
    if os_subnet_gaps is None:
        sub_gaps = None
    else:
        sub_gaps = len(os_subnet_gaps or [])
    fip_gaps = len(os_floating_gaps or [])
    return {
        "maas_only": maas_only,
        "nb_only_dev": nb_only_dev,
        "check_hosts": check_hosts,
        "nb_only_nic": nb_only_nic,
        "iface_not_ok": iface_not_ok,
        "maas_nic_missing_nb": maas_nic_missing_nb,
        "sub_gaps": sub_gaps,
        "fip_gaps": fip_gaps,
        "vlan_drift_nic": vlan_drift_nic,
        "vlan_unverified_nic": vlan_unverified_nic,
    }


def _matched_hosts_with_drift(matched_rows):
    """Rows that have placement CHECK or any hints (so we show only drifting hosts)."""
    if not matched_rows:
        return []
    return [
        r for r in matched_rows
        if r.get("place_match") == "CHECK" or (r.get("hints") or [])
    ]


def _count_hints(matched_rows, needle: str) -> int:
    c = 0
    for r in (matched_rows or []):
        for h in (r.get("hints") or []):
            if needle in (h or ""):
                c += 1
                break
    return c


def _device_by_name(netbox_data):
    out = {}
    for d in (netbox_data or {}).get("devices") or []:
        n = (d.get("name") or "").strip()
        if n:
            out[n] = d
    return out


def _dedupe_note_parts(text: str) -> str:
    if not text:
        return ""
    parts = [p.strip() for p in str(text).replace("\n", " ").split(";")]
    seen = set()
    ordered = []
    for p in parts:
        if not p:
            continue
        k = p.lower()
        if k in seen:
            continue
        seen.add(k)
        ordered.append(p)
    return "; ".join(ordered)


def _ip_address_host(ip_str: str) -> str:
    """Host portion of an IP or CIDR string, lowercased."""
    if not ip_str or ip_str == "—":
        return ""
    return str(ip_str).split("/", 1)[0].strip().lower()


# NetBox **port names** operators use for BMC/OOB (heuristic coverage); *-nic here is a label, not “host NIC”.
_MGMT_INTERFACE_NAME_HINTS = frozenset({
    "ipmi",
    "idrac",
    "bmc",
    "ilo",
    "imm",
    "xcc",
    "drac",
    "oob",
    "mgmt",
    "mgnt",
    "ipmi-nic",
    "bmc-nic",
})


def _netbox_iface_name_suggests_oob(name: str) -> bool:
    """
    True if the NetBox interface *name* looks like an OOB / BMC port.

    Names are operator-defined in NetBox (manual, import, etc.) — MAAS does not supply
    interface labels. We match exact aliases (e.g. ``idrac``) or **substring** hits so
    values like ``e0 - idrac`` still count as OOB-style (exact-set-only would miss those
    and wrongly flag ``IP_OTHER_IFACE``).
    """
    n = (name or "").strip().lower()
    if not n:
        return False
    if n in _MGMT_INTERFACE_NAME_HINTS:
        return True
    return any(hint in n for hint in _MGMT_INTERFACE_NAME_HINTS)


def _suggested_netbox_mgmt_interface_name(
    power_type: str,
    hardware_vendor: str | None = None,
) -> str:
    """
    MAAS-only hint when **creating** a new OOB port — ``ipmi`` or ``idrac`` only.

    - ``power_type`` containing ``redfish`` or ``idrac`` → ``idrac``.
    - ``power_type`` containing ``ipmi``: if ``hardware_vendor`` contains ``dell``
      (case-insensitive), suggest ``idrac``; if vendor missing / placeholder → ``ipmi``;
      otherwise ``ipmi``.
    - Any other power type → ``ipmi`` (same as before).

    Prefer NetBox’s existing port name when the BMC IP is already on an interface
    (``_oob_port_hint_column``).
    """
    pl = (power_type or "").lower()
    if "redfish" in pl or "idrac" in pl:
        return "idrac"
    if "ipmi" in pl:
        v = (hardware_vendor or "").strip().lower()
        if v and "dell" in v:
            return "idrac"
        return "ipmi"
    return "ipmi"


def _oob_port_hint_column(cov: str, nb_ifn: str, maas_when_no_nb_port: str) -> str:
    """
    Value for the 'NB OOB port (hint)' column: prefer the NetBox port name when the BMC IP
    is already documented on a port (MGMT_IFACE / IP_OTHER_IFACE).
    """
    n = (nb_ifn or "").strip()
    if n and n != "—" and cov in ("MGMT_IFACE", "IP_OTHER_IFACE"):
        return n
    return maas_when_no_nb_port


def _nb_iface_carrying_ip(nb_ifaces: list, target_ip: str):
    """First NetBox interface dict whose ips[] contains target (host match)."""
    bh = _ip_address_host(target_ip)
    if not bh:
        return None
    for iface in nb_ifaces or []:
        for ip in iface.get("ips") or []:
            if _ip_address_host(ip) == bh:
                return iface
    return None


def _meaningful_maas_power_type(pt: str) -> bool:
    """True if MAAS reports a concrete power driver (not empty / manual / unknown)."""
    p = (pt or "").strip().lower()
    if not p or p in ("—", "-", "manual", "unknown"):
        return False
    return True


def _netbox_bmc_ip_coverage(nb_ifaces: list, bmc_ip: str):
    """
    How NetBox documents the MAAS BMC IP (on an OOB-dedicated port / Interface, or elsewhere).
    Returns (code, port_name_or_emdash, short_note).
    """
    bh = _ip_address_host(bmc_ip)
    if not bh:
        return "NO_BMC_MAAS", "—", ""
    mgmt_name = ""
    any_name = ""
    for iface in nb_ifaces or []:
        iname = (iface.get("name") or "").strip().lower()
        is_mgmt_named = _netbox_iface_name_suggests_oob(iname)
        is_mgmt_flag = bool(iface.get("mgmt_only"))
        for ip in iface.get("ips") or []:
            if _ip_address_host(ip) != bh:
                continue
            disp = (iface.get("name") or "?").strip()
            if is_mgmt_flag or is_mgmt_named:
                mgmt_name = disp
            if not any_name:
                any_name = disp
            break
    if mgmt_name:
        return "MGMT_IFACE", mgmt_name, "BMC IP on OOB-style NetBox port"
    if any_name:
        return "IP_OTHER_IFACE", any_name, "BMC IP present; port name not typical for OOB"
    return "NO_IFACE_IP", "—", "No NetBox port carries this BMC IP"


def _build_proposed_mgmt_interface_rows(
    matched_rows,
    maas_by_hostname: dict,
    netbox_ifaces,
):
    """
    Matched hosts: **BMC / OOB** from MAAS power (IPMI, iDRAC, Redfish — not host data NICs).

    Compares MAAS BMC IP to NetBox device OOB and to NetBox **OOB ports**.
    Rows also when power_type is set but BMC IP is missing from the MAAS API.
    """
    from netbox_automation_plugin.sync.reconciliation.audit_detail import (
        _normalize_mac,
    )

    nb_if = netbox_ifaces if isinstance(netbox_ifaces, dict) else {}
    out = []
    for r in matched_rows or []:
        h = (r.get("hostname") or "").strip()
        if not h:
            continue
        m = maas_by_hostname.get(h) or {}
        bmc = (m.get("bmc_ip") or "").strip()
        pt = (m.get("power_type") or "").strip() or "—"
        maas_oob_new = _suggested_netbox_mgmt_interface_name(
            pt, m.get("hardware_vendor")
        )
        nb_oob = (r.get("netbox_oob") or "").strip()
        maas_mac = (m.get("bmc_mac") or "").strip()
        maas_vlan = (m.get("bmc_vlan") or "").strip()
        nb_list = nb_if.get(h) or []

        if not bmc:
            if not _meaningful_maas_power_type(pt):
                continue
            cov = "NO_BMC_IP_MAAS"
            nb_ifn = "—"
            nb_mgmt_mac = "—"
            status = "NO_BMC_IP"
            action = (
                "MAAS power_type is set but no BMC IP in machine API — grant admin API key, "
                "use op=power_parameters, or configure power_address in MAAS; then re-run audit."
            )
            if maas_mac or maas_vlan:
                action += f" MAAS hints: MAC={maas_mac or '—'} VLAN={maas_vlan or '—'}."
            risk = "High"
            out.append([
                h,
                "—",
                pt,
                maas_mac or "—",
                maas_oob_new,
                nb_oob or "—",
                cov,
                nb_ifn,
                nb_mgmt_mac,
                status,
                action,
                risk,
            ])
            continue

        cov, nb_ifn, cov_note = _netbox_bmc_ip_coverage(nb_list, bmc)
        oob_port_hint = _oob_port_hint_column(cov, nb_ifn, maas_oob_new)
        oob_match = bool(nb_oob) and _ip_address_host(nb_oob) == _ip_address_host(bmc)
        nb_detail = _nb_iface_carrying_ip(nb_list, bmc)
        nb_mgmt_mac = (nb_detail.get("mac") or "—") if nb_detail else "—"
        nb_mgmt_vid = (
            str(nb_detail.get("untagged_vlan_vid") or "—") if nb_detail else "—"
        )

        if oob_match and cov == "MGMT_IFACE":
            status = "OK"
            action = (
                "Device OOB + OOB port align with MAAS BMC; keep NetBox port name "
                f"'{nb_ifn}' (source of truth)"
            )
            risk = "None"
        elif oob_match and cov == "NO_IFACE_IP":
            status = "ADD_MGMT_IFACE"
            action = (
                f"Add NetBox OOB port '{maas_oob_new}' (management-only), assign BMC IP "
                f"{bmc}/<prefix> (OOB, not a host NIC)"
            )
            risk = "Medium"
        elif oob_match and cov == "IP_OTHER_IFACE":
            status = "REVIEW"
            action = (
                f"BMC IP on NetBox port '{nb_ifn}'; mark as OOB/management-only if needed — "
                "do not rename to match MAAS power_type; NetBox name is source of truth"
            )
            risk = "Low"
        elif not oob_match and cov == "MGMT_IFACE":
            status = "SET_OOB"
            action = (
                f"Set device OOB IP to {bmc} (MAAS BMC); BMC IP already on port '{nb_ifn}' "
                "(keep NetBox port name)"
            )
            risk = "Low"
        elif cov == "NO_IFACE_IP":
            status = "ADD_OOB_AND_MGMT"
            action = (
                f"Set device OOB IP to {bmc}; add OOB port '{maas_oob_new}' "
                "(management-only) with BMC IP"
            )
            risk = "Medium"
        else:
            status = "REVIEW"
            action = cov_note or "Align device OOB / OOB port / MAAS BMC"
            risk = "Medium"

        status_before_mac = status
        if maas_mac and nb_mgmt_mac and nb_mgmt_mac != "—":
            mm = _normalize_mac(maas_mac)
            nm = _normalize_mac(nb_mgmt_mac)
            if mm and nm and mm != nm:
                if status == "OK":
                    status = "REVIEW"
                    risk = "Medium"
                # Do not keep “everything aligns” copy when MACs disagree.
                if status_before_mac == "OK":
                    action = (
                        f"BMC MAC mismatch: MAAS {maas_mac} vs NetBox port {nb_mgmt_mac} "
                        f"on '{nb_ifn}'. OOB IP matches MAAS; confirm which MAC is correct."
                    )
                else:
                    action += (
                        f" MAC mismatch: MAAS BMC MAC {maas_mac} vs NetBox port {nb_mgmt_mac}."
                    )
        if maas_vlan and nb_mgmt_vid not in ("", "—", "None"):
            if maas_vlan.strip() != str(nb_mgmt_vid).strip():
                action += (
                    f" VLAN hint: MAAS {maas_vlan} vs NetBox untagged {nb_mgmt_vid} on BMC port."
                )
                if status == "OK":
                    status = "REVIEW"
                    risk = "Low"

        out.append([
            h,
            bmc,
            pt,
            maas_mac or "—",
            oob_port_hint,
            nb_oob or "—",
            cov,
            nb_ifn,
            nb_mgmt_mac,
            status,
            action,
            risk,
        ])
    return sorted(out, key=lambda x: (x[0] or "").lower())


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
            action = (
                f"Add NetBox port named like MAAS '{maas_if}'; set MAC {mac}; "
                f"untagged VLAN from MAAS VID {vlan} where applicable; "
                f"assign MAAS IPs on this port (or device primary if policy prefers)"
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
                action,
                "Medium",
            ])
    return sorted(out, key=lambda x: (x[0] or "").lower())


def _friendly_note(raw: str) -> str:
    note = _dedupe_note_parts(raw or "")
    parts = [p.strip() for p in note.split(";") if p.strip()]
    low = note.lower()
    # Keep IP-alignment rows focused on IP only; VLAN/MAC details belong to other sections.
    for p in parts:
        pl = p.lower()
        if "ip on maas not on nb iface:" in pl:
            return p
    for p in parts:
        pl = p.lower()
        if "ip" in pl and ("missing" in pl or "not on" in pl or "gap" in pl):
            return p
    # Drop MAC-only details from IP table and keep user-facing wording clear.
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


def _proposed_changes_rows(
    maas_data,
    netbox_data,
    drift,
    interface_audit,
    matched_rows,
    os_subnet_gaps,
    os_floating_gaps,
    netbox_ifaces=None,
):
    """Build user-friendly proposed change buckets (preview only)."""
    by_h = _maas_machine_by_hostname(maas_data)
    nb_by_name = _device_by_name(netbox_data)
    add_mgmt_iface = _build_proposed_mgmt_interface_rows(
        matched_rows, by_h, netbox_ifaces
    )
    add_nb_interfaces = _build_add_nb_interface_rows(interface_audit)

    add_devices = []
    for h in sorted(drift.get("in_maas_not_netbox") or []):
        m = by_h.get(h, {})
        add_devices.append([
            h,
            str(m.get("zone_name", "-")),
            str(m.get("pool_name", "-")),
            str(m.get("status_name", "-")),
            "maas-discovered",
            "Create device + ports",
        ])

    add_prefixes = []
    for g in (os_subnet_gaps or []):
        add_prefixes.append([
            g.get("cidr", ""),
            g.get("network_name", "-"),
            g.get("network_id", ""),
            "-",
            "Create Prefix",
        ])

    add_fips = []
    for g in (os_floating_gaps or []):
        add_fips.append([
            g.get("floating_ip", ""),
            g.get("fixed_ip_address", "-"),
            g.get("project_name") or g.get("project_id") or "-",
            "-",
            "Create IPAddress",
        ])

    update_nic = []
    for b in (interface_audit or {}).get("hosts") or []:
        hn = b.get("hostname", "")
        for row in b.get("rows") or []:
            st = row.get("status") or ""
            notes = row.get("notes") or ""
            maas_vlan = str(row.get("maas_vlan") or "—")
            nb_vlan = str(row.get("nb_vlan") or "—")

            # NOT_IN_NETBOX: dedicated "create interface" table (add_nb_interfaces), not NIC drift.
            if st == "NOT_IN_NETBOX":
                continue

            # Full inventory for MAC’d interfaces only (with or without IP on MAAS); OK rows included.
            if st == "OK":
                update_nic.append([
                    hn,
                    row.get("maas_if") or "",
                    str(row.get("maas_fabric") or "—"),
                    row.get("maas_mac") or "",
                    row.get("maas_ips") or "—",
                    row.get("nb_if") or "—",
                    row.get("nb_mac") or "—",
                    row.get("nb_ips") or "—",
                    maas_vlan,
                    nb_vlan,
                    "OK",
                    "—",
                    "No change",
                    "None",
                ])
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
                ", ".join(dict.fromkeys(statuses)),
                "; ".join(dict.fromkeys([r for r in reasons if r])),
                "; ".join(dict.fromkeys([a for a in actions if a])),
                risk,
            ])

    review_orphans = []
    for n in sorted(drift.get("in_netbox_not_maas") or []):
        d = nb_by_name.get(n, {})
        review_orphans.append([
            n,
            d.get("site_slug", "-"),
            d.get("status", "-"),
            "orphaned",
            "Review only; no automatic deletion",
            "Medium",
        ])

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

    return {
        "add_devices": add_devices,
        "add_prefixes": add_prefixes,
        "add_fips": add_fips,
        "update_nic": update_nic,
        "add_nb_interfaces": add_nb_interfaces,
        "add_mgmt_iface": add_mgmt_iface,
        "review_orphans": review_orphans,
        "review_serial": review_serial,
    }


def format_drift_report(
    maas_data,
    netbox_data,
    openstack_data,
    drift,
    *,
    matched_rows=None,
    os_subnet_hints=None,
    os_subnet_gaps=None,
    os_floating_gaps=None,
    netbox_prefix_count=0,
    interface_audit=None,
    netbox_ifaces=None,
):
    """
    Return {"drift": str, "reference": str}.
    drift = Phase 0 + drift-only tables (MAAS-only, matched with drift, NIC drift, OS gaps).
    reference = full matched hosts, full per-device NIC audit, OpenStack ref (collapsible in UI).
    OpenStack data is already combined from all configured clouds before being passed here.
    """
    drift_lines = []
    ref_lines = []

    # --- INVENTORY (compact) ---
    drift_lines.extend(_banner("INVENTORY"))
    drift_lines.append("")
    drift_lines.append("  MAAS")
    drift_lines.append("")
    if maas_data.get("error"):
        drift_lines.append(f"    Error: {maas_data['error']}")
    else:
        drift_lines.extend(
            _ascii_table(
                ["Metric", "Count"],
                [
                    ["Zones", str(len(maas_data.get("zones") or []))],
                    ["Resource pools", str(len(maas_data.get("pools") or []))],
                    ["Machines", str(len(maas_data.get("machines") or []))],
                ],
            )
        )

    drift_lines.append("")
    drift_lines.append("  NetBox (this instance)")
    drift_lines.append("")
    if netbox_data.get("error"):
        drift_lines.append(f"    Error: {netbox_data['error']}")
    else:
        inv_rows = [
            ["Sites", str(len(netbox_data.get("sites") or []))],
            ["Devices", str(len(netbox_data.get("devices") or []))],
        ]
        if netbox_prefix_count:
            inv_rows.append(["IPAM Prefix objects", str(netbox_prefix_count)])
        drift_lines.extend(_ascii_table(["Metric", "Count"], inv_rows))

    scope_meta = (drift or {}).get("scope_meta") or {}
    if scope_meta:
        drift_lines.append("")
        drift_lines.extend(_banner("SCOPE", "-"))
        drift_lines.append("")
        sel_sites = ", ".join(scope_meta.get("selected_sites") or []) or "(all)"
        sel_locs = ", ".join(scope_meta.get("selected_locations") or []) or "(all)"
        os_unmatched = list(scope_meta.get("openstack_unmatched_network_names") or [])
        if scope_meta.get("openstack_unmatched_network_names_more"):
            os_unmatched.append(f"... +{scope_meta['openstack_unmatched_network_names_more']} more")
        maas_unmatched = list(scope_meta.get("maas_unmatched_fabrics") or [])
        if scope_meta.get("maas_unmatched_fabrics_more"):
            maas_unmatched.append(f"... +{scope_meta['maas_unmatched_fabrics_more']} more")
        _maas_fabric_noisy = r"(?i)^fabric-\d+$"
        # scope_meta["maas_fabrics_after"]: distinct per-NIC MAAS fabrics for MAC'd interfaces on scoped hosts.
        _maas_fab_in_scope_label = "MAAS fabrics fetched (in-scope)"
        drift_lines.extend(_ascii_table(
            ["Check", "Value"],
            [
                ["Coverage status", str(scope_meta.get("coverage_status") or "PARTIAL")],
                ["Selected sites", sel_sites],
                ["Selected locations", sel_locs],
                [
                    "MAAS machines included / fetched",
                    f"{scope_meta.get('maas_machines_after', 0)} / {scope_meta.get('maas_machines_before', 0)}",
                ],
                [
                    "NetBox devices included / fetched",
                    f"{scope_meta.get('netbox_devices_after', 0)} / {scope_meta.get('netbox_devices_before', 0)}",
                ],
                [
                    "OpenStack nets included / fetched",
                    f"{scope_meta.get('openstack_networks_after', 0)} / {scope_meta.get('openstack_networks_before', 0)}",
                ],
                [
                    "OpenStack subnets included / fetched",
                    f"{scope_meta.get('openstack_subnets_after', 0)} / {scope_meta.get('openstack_subnets_before', 0)}",
                ],
                [
                    "OpenStack FIPs included / fetched",
                    f"{scope_meta.get('openstack_fips_after', 0)} / {scope_meta.get('openstack_fips_before', 0)}",
                ],
                [
                    "MAAS all fabrics (pre-scope, summarized)",
                    _format_inventory_list(
                        scope_meta.get("maas_all_fabrics") or [],
                        noisy_regex=_maas_fabric_noisy,
                        noisy_label="fabric-<number>",
                    ),
                ],
                [
                    _maas_fab_in_scope_label,
                    _format_inventory_list(
                        scope_meta.get("maas_fabrics_after") or [],
                        noisy_regex=_maas_fabric_noisy,
                        noisy_label="fabric-<number>",
                    ),
                ],
                [
                    "OpenStack all network names (pre-scope)",
                    _format_inventory_list(scope_meta.get("openstack_all_network_names") or []),
                ],
                [
                    "OpenStack network names fetched (in-scope)",
                    _format_inventory_list(scope_meta.get("openstack_network_names_after") or []),
                ],
                ["MAAS unmatched fabrics (sample)", ", ".join(maas_unmatched) or "(none)"],
                ["OpenStack unmatched network names (sample)", ", ".join(os_unmatched) or "(none)"],
            ],
            dynamic_columns=True,
        ))

    # --- Phase 0 — drift category counts ---
    drift_lines.append("")
    drift_lines.extend(_banner("DRIFT COUNTS"))
    drift_lines.append(
        "  Counts for this run (match by hostname and NIC MAC)."
    )
    drift_lines.append("")
    pc = _phase0_category_counts(
        drift,
        matched_rows,
        interface_audit,
        os_subnet_gaps,
        os_floating_gaps,
    )
    serial_validation_needed = _count_hints(matched_rows, "NB serial empty")
    bmc_oob_mismatch = _count_hints(matched_rows, "MAAS BMC ")
    sub_txt = str(pc["sub_gaps"]) if pc["sub_gaps"] is not None else "N/A (local ORM)"
    nb_orphan_note = (
        f"{pc['nb_only_dev']} (names hidden in this report)"
        if pc["nb_only_dev"]
        else "0"
    )
    drift_lines.extend(
        _ascii_table(
            ["Category", "Count"],
            [
                ["In MAAS only (not in NetBox)", str(pc["maas_only"])],
                ["In NetBox only (orphaned tag)", nb_orphan_note],
                ["Matched — placement needs check", str(pc["check_hosts"])],
                ["NetBox serial missing", str(serial_validation_needed)],
                ["NIC rows not OK", str(pc["iface_not_ok"])],
                ["MAAS NIC missing in NetBox", str(pc["maas_nic_missing_nb"])],
                ["VLAN mismatch (MAAS vs NetBox)", str(pc["vlan_drift_nic"])],
                ["VLAN unverified from MAAS", str(pc["vlan_unverified_nic"])],
                ["NetBox-only NICs (review)", str(pc["nb_only_nic"])],
                ["OpenStack subnet → no Prefix", sub_txt],
                ["OpenStack FIP → no IP record", str(pc["fip_gaps"])],
                ["BMC vs NetBox OOB differs", str(bmc_oob_mismatch)],
                ["LLDP / cabling", "—"],
            ],
        )
    )

    # --- High-risk summary ---
    drift_lines.append("")
    drift_lines.extend(_banner("HIGH-RISK (review first)", "-"))
    drift_lines.append("  Triage these before a sync.")
    drift_lines.append("")
    hr_rows = []
    hr_total = 0
    for name, val in [
        ("OpenStack FIP → no IP record", pc["fip_gaps"]),
        ("OpenStack subnet → no Prefix", pc["sub_gaps"] if pc["sub_gaps"] is not None else "N/A"),
        ("VLAN mismatch (MAAS vs NetBox)", pc["vlan_drift_nic"]),
        ("NetBox serial missing", serial_validation_needed),
        ("BMC vs NetBox OOB differs", bmc_oob_mismatch),
    ]:
        hr_rows.append([name, str(val)])
        if isinstance(val, int):
            hr_total += val
    drift_lines.extend(_ascii_table(["Category", "Count"], hr_rows))
    drift_lines.append(f"  Total: {hr_total}")

    # --- Run metrics ---
    drift_lines.append("")
    drift_lines.extend(_banner("RUN METRICS", "-"))
    drift_lines.append("")
    drift_lines.extend(_ascii_table(
        ["Metric", "Value"],
        [
            ["MAAS machines", str(len(maas_data.get("machines") or []))],
            ["NetBox devices", str(len(netbox_data.get("devices") or []))],
            ["Matched hostnames", str(drift.get("matched_count", 0))],
            ["In MAAS only", str(pc["maas_only"])],
            ["NetBox orphans", str(pc["nb_only_dev"])],
            ["NetBox serial missing", str(serial_validation_needed)],
            ["OpenStack subnet gaps", sub_txt],
            ["OpenStack FIP gaps", str(pc["fip_gaps"])],
            ["VLAN mismatch NICs", str(pc["vlan_drift_nic"])],
            ["VLAN unverified NICs", str(pc["vlan_unverified_nic"])],
            ["MAAS NIC missing in NetBox", str(pc["maas_nic_missing_nb"])],
        ],
    ))

    # --- Proposed changes (preview only; full list, uncapped) ---
    prop = _proposed_changes_rows(
        maas_data,
        netbox_data,
        drift,
        interface_audit,
        matched_rows,
        os_subnet_gaps or [],
        os_floating_gaps or [],
        netbox_ifaces=netbox_ifaces,
    )
    drift_lines.append("")
    drift_lines.extend(_banner("PROPOSED CHANGES", "-"))
    drift_lines.append(
        "  Read-only. Possible NetBox updates from MAAS and OpenStack — nothing is applied from this screen."
    )
    drift_lines.append("")

    drift_lines.append("  A) Add to NetBox")
    drift_lines.append("")
    drift_lines.extend(_ascii_table(
        ["What", "Count", "Note"],
        [
            ["New devices (MAAS)", str(len(prop["add_devices"])), "Not in NetBox yet"],
            ["New prefixes (OpenStack)", str(len(prop["add_prefixes"])), "Subnet not in IPAM"],
            ["New floating IPs (OpenStack)", str(len(prop["add_fips"])), "FIP not in IPAM"],
        ],
    ))
    if prop["add_devices"]:
        drift_lines.append("")
        drift_lines.append("  Detail — new devices")
        drift_lines.append("")
        drift_lines.extend(_ascii_table(
            ["Hostname", "Zone", "Pool", "MAAS Status", "Proposed Tag", "Proposed Action"],
            prop["add_devices"],
            dynamic_columns=True,
        ))
    if prop["add_prefixes"]:
        drift_lines.append("")
        drift_lines.append("  Detail — new prefixes")
        drift_lines.append("")
        drift_lines.extend(_ascii_table(
            ["CIDR", "Network Name", "Network ID", "Cloud", "Proposed Action"],
            prop["add_prefixes"],
            dynamic_columns=True,
        ))
    if prop["add_fips"]:
        drift_lines.append("")
        drift_lines.append("  Detail — new floating IPs")
        drift_lines.append("")
        drift_lines.extend(_ascii_table(
            ["Floating IP", "Fixed IP", "Project", "Cloud", "Proposed Action"],
            prop["add_fips"],
            dynamic_columns=True,
        ))

    drift_lines.append("")
    drift_lines.append("  B) NICs and BMC / OOB")
    drift_lines.append("")
    drift_lines.extend(_ascii_table(
        ["What", "Count", "Note"],
        [
            ["New NICs in NetBox", str(len(prop["add_nb_interfaces"])), "MAAS MAC not on device"],
            ["NIC drift", str(len(prop["update_nic"])), "MAAS vs NetBox differs"],
            ["BMC / OOB", str(len(prop["add_mgmt_iface"])), "Power / out-of-band vs NetBox"],
        ],
    ))
    if prop["add_nb_interfaces"]:
        drift_lines.append("")
        drift_lines.append("  Detail — new NICs")
        drift_lines.append("")
        drift_lines.extend(_ascii_table(
            [
                "Host",
                "NB site",
                "NB location",
                "MAAS intf",
                "MAAS fabric",
                "MAAS MAC",
                "MAAS IPs",
                "MAAS VLAN",
                "Suggested NB name",
                "Proposed properties (from MAAS)",
                "Proposed action",
                "Risk",
            ],
            prop["add_nb_interfaces"],
            dynamic_columns=True,
        ))
    if prop["update_nic"]:
        drift_lines.append("")
        drift_lines.append("  Detail — NIC drift")
        drift_lines.append("")
        drift_lines.extend(_ascii_table(
            [
                "Host",
                "MAAS intf",
                "MAAS fabric",
                "MAAS MAC",
                "MAAS IPs",
                "NB intf",
                "NB MAC",
                "NB IPs",
                "MAAS VLAN",
                "NB VLAN",
                "Status",
                "Reason",
                "Proposed Action",
                "Risk",
            ],
            prop["update_nic"],
            dynamic_columns=True,
        ))

    if prop["add_mgmt_iface"]:
        drift_lines.append("")
        drift_lines.append("  Detail — BMC / OOB")
        drift_lines.append("")
        drift_lines.extend(_ascii_table(
            [
                "Host",
                "MAAS BMC IP",
                "MAAS power_type",
                "MAAS BMC MAC",
                "NB OOB port (hint)",
                "NetBox OOB",
                "NB IP coverage",
                "NB port w/ BMC IP",
                "NB OOB MAC",
                "Status",
                "Proposed action",
                "Risk",
            ],
            prop["add_mgmt_iface"],
            dynamic_columns=True,
        ))

    drift_lines.append("")
    drift_lines.append("  C) Review")
    drift_lines.append("")
    drift_lines.extend(_ascii_table(
        ["What", "Count", "Note"],
        [
            ["Orphan devices", str(len(prop["review_orphans"])), "In NetBox, not in MAAS"],
            ["Serial check", str(len(prop["review_serial"])), "NetBox serial empty"],
        ],
    ))
    if prop["review_orphans"]:
        drift_lines.append("")
        drift_lines.append("  Detail — orphans")
        drift_lines.append("")
        drift_lines.extend(_ascii_table(
            ["Hostname", "Site", "Status", "Proposed Tag", "Proposed Action", "Risk"],
            prop["review_orphans"],
            dynamic_columns=True,
        ))
    if prop["review_serial"]:
        drift_lines.append("")
        drift_lines.append("  Detail — serials")
        drift_lines.append("")
        drift_lines.extend(_ascii_table(
            ["Hostname", "MAAS Serial", "NetBox Serial", "Proposed Action", "Risk"],
            prop["review_serial"],
            dynamic_columns=True,
        ))
    drift_lines.append("")
    drift_lines.append("  Summary")
    drift_lines.append("")
    total_props = (
        len(prop["add_devices"]) + len(prop["add_prefixes"]) + len(prop["add_fips"]) +
        len(prop["update_nic"]) + len(prop["add_nb_interfaces"]) + len(prop["add_mgmt_iface"]) +
        len(prop["review_orphans"]) + len(prop["review_serial"])
    )
    drift_lines.extend(_ascii_table(
        ["Bucket", "Count"],
        [
            ["New devices", str(len(prop["add_devices"]))],
            ["New prefixes", str(len(prop["add_prefixes"]))],
            ["New floating IPs", str(len(prop["add_fips"]))],
            ["NIC drift", str(len(prop["update_nic"]))],
            ["New NICs", str(len(prop["add_nb_interfaces"]))],
            ["BMC / OOB", str(len(prop["add_mgmt_iface"]))],
            ["Orphans (review)", str(len(prop["review_orphans"]))],
            ["Serials (review)", str(len(prop["review_serial"]))],
            ["Total", str(total_props)],
        ],
    ))

    drift_lines.append("")
    drift_lines.extend(_banner("END OF DRIFT AUDIT", "="))

    # ---------- REFERENCE ----------
    # Hidden intentionally for user-facing output.

    return {"drift": "\n".join(drift_lines), "reference": "\n".join(ref_lines)}


def build_drift_report_xlsx(
    maas_data,
    netbox_data,
    openstack_data,
    drift,
    *,
    matched_rows=None,
    os_subnet_hints=None,
    os_subnet_gaps=None,
    os_floating_gaps=None,
    netbox_prefix_count=0,
    interface_audit=None,
    netbox_ifaces=None,
):
    """
    Build an Excel (.xlsx) workbook from the same inputs as format_drift_report.
    Returns bytes suitable for HttpResponse(..., content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet").
    Google Sheets opens .xlsx files.
    """
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
    except ImportError:
        raise RuntimeError("openpyxl is required for XLSX export. pip install openpyxl")

    wb = Workbook()
    header_font = Font(bold=True)

    def _sheet(name, max_len=31):
        s = wb.create_sheet(title=name[:max_len])
        return s

    def _append_header(ws, row):
        ws.append(row)
        r = ws.max_row
        for c in range(1, len(row) + 1):
            ws.cell(row=r, column=c).font = header_font
        return r

    # --- Summary ---
    ws_sum = wb.active
    ws_sum.title = "Summary"
    ws_sum.append(["Drift audit summary"])
    ws_sum.cell(row=1, column=1).font = header_font
    ws_sum.append([])
    ws_sum.append(["MAAS", "OK" if not maas_data.get("error") else "Error", ""])
    ws_sum.append(["  Machines", str(len(maas_data.get("machines") or [])), ""])
    ws_sum.append(["NetBox", "OK" if not netbox_data.get("error") else "Error", ""])
    ws_sum.append(["  Devices", str(len(netbox_data.get("devices") or [])), ""])
    ws_sum.append(["  Sites", str(len(netbox_data.get("sites") or [])), ""])
    if netbox_prefix_count:
        ws_sum.append(["  IPAM Prefixes", str(netbox_prefix_count), ""])
    ws_sum.append([])
    ws_sum.append([])
    pc = _phase0_category_counts(
        drift,
        matched_rows,
        interface_audit,
        os_subnet_gaps,
        os_floating_gaps or [],
    )
    serial_validation_needed = _count_hints(matched_rows, "NB serial empty")
    bmc_oob_mismatch = _count_hints(matched_rows, "MAAS BMC ")
    sub_txt = str(pc["sub_gaps"]) if pc["sub_gaps"] is not None else "N/A"
    nb_orphan_note_x = (
        f"{pc['nb_only_dev']} (names hidden in this report)"
        if pc["nb_only_dev"]
        else "0"
    )
    scope_meta = (drift or {}).get("scope_meta") or {}
    if scope_meta:
        ws_sum.append([])
        ws_sum.append(["SCOPE", "", ""])
        _append_header(ws_sum, ["Check", "Value"])
        ws_sum.append(["Coverage status", str(scope_meta.get("coverage_status") or "PARTIAL")])
        ws_sum.append(["Selected sites", ", ".join(scope_meta.get("selected_sites") or []) or "(all)"])
        ws_sum.append(["Selected locations", ", ".join(scope_meta.get("selected_locations") or []) or "(all)"])
        ws_sum.append([
            "MAAS machines included / fetched",
            f"{scope_meta.get('maas_machines_after', 0)} / {scope_meta.get('maas_machines_before', 0)}",
        ])
        ws_sum.append([
            "NetBox devices included / fetched",
            f"{scope_meta.get('netbox_devices_after', 0)} / {scope_meta.get('netbox_devices_before', 0)}",
        ])
        ws_sum.append([
            "OpenStack nets included / fetched",
            f"{scope_meta.get('openstack_networks_after', 0)} / {scope_meta.get('openstack_networks_before', 0)}",
        ])
        ws_sum.append([
            "OpenStack subnets included / fetched",
            f"{scope_meta.get('openstack_subnets_after', 0)} / {scope_meta.get('openstack_subnets_before', 0)}",
        ])
        ws_sum.append([
            "OpenStack FIPs included / fetched",
            f"{scope_meta.get('openstack_fips_after', 0)} / {scope_meta.get('openstack_fips_before', 0)}",
        ])
        _x_maas_fabric_noisy = r"(?i)^fabric-\d+$"
        _x_maas_fab_in_scope_label = "MAAS fabrics fetched (in-scope)"
        ws_sum.append([
            "MAAS all fabrics (pre-scope, summarized)",
            _format_inventory_list(
                scope_meta.get("maas_all_fabrics") or [],
                noisy_regex=_x_maas_fabric_noisy,
                noisy_label="fabric-<number>",
            ),
        ])
        ws_sum.append([
            _x_maas_fab_in_scope_label,
            _format_inventory_list(
                scope_meta.get("maas_fabrics_after") or [],
                noisy_regex=_x_maas_fabric_noisy,
                noisy_label="fabric-<number>",
            ),
        ])
        ws_sum.append([
            "OpenStack all network names (pre-scope)",
            _format_inventory_list(scope_meta.get("openstack_all_network_names") or []),
        ])
        ws_sum.append([
            "OpenStack network names fetched (in-scope)",
            _format_inventory_list(scope_meta.get("openstack_network_names_after") or []),
        ])
        maas_unmatched = list(scope_meta.get("maas_unmatched_fabrics") or [])
        if scope_meta.get("maas_unmatched_fabrics_more"):
            maas_unmatched.append(f"... +{scope_meta['maas_unmatched_fabrics_more']} more")
        os_unmatched = list(scope_meta.get("openstack_unmatched_network_names") or [])
        if scope_meta.get("openstack_unmatched_network_names_more"):
            os_unmatched.append(f"... +{scope_meta['openstack_unmatched_network_names_more']} more")
        ws_sum.append(["MAAS unmatched fabrics (sample)", ", ".join(maas_unmatched) or "(none)"])
        ws_sum.append(["OpenStack unmatched network names (sample)", ", ".join(os_unmatched) or "(none)"])
    ws_sum.append([])
    ws_sum.append(["DRIFT COUNTS", "", ""])
    _append_header(ws_sum, ["Category", "Count"])
    ws_sum.append(["In MAAS only (not in NetBox)", str(pc["maas_only"])])
    ws_sum.append(["In NetBox only (orphaned tag)", nb_orphan_note_x])
    ws_sum.append(["Matched — placement needs check", str(pc["check_hosts"])])
    ws_sum.append(["NetBox serial missing", str(serial_validation_needed)])
    ws_sum.append(["NIC rows not OK", str(pc["iface_not_ok"])])
    ws_sum.append(["MAAS NIC missing in NetBox", str(pc["maas_nic_missing_nb"])])
    ws_sum.append(["VLAN mismatch (MAAS vs NetBox)", str(pc["vlan_drift_nic"])])
    ws_sum.append(["VLAN unverified from MAAS", str(pc["vlan_unverified_nic"])])
    ws_sum.append(["NetBox-only NICs (review)", str(pc["nb_only_nic"])])
    ws_sum.append(["OpenStack subnet → no Prefix", sub_txt])
    ws_sum.append(["OpenStack FIP → no IP record", str(pc["fip_gaps"])])
    ws_sum.append(["BMC vs NetBox OOB differs", str(bmc_oob_mismatch)])
    ws_sum.append(["LLDP / cabling", "—"])
    ws_sum.append([])
    ws_sum.append(["HIGH-RISK (review first)", "", ""])
    _append_header(ws_sum, ["Category", "Count"])
    ws_sum.append(["OpenStack FIP → no IP record", str(pc["fip_gaps"])])
    ws_sum.append(
        [
            "OpenStack subnet → no Prefix",
            str(pc["sub_gaps"]) if pc["sub_gaps"] is not None else "N/A",
        ]
    )
    ws_sum.append(["VLAN mismatch (MAAS vs NetBox)", str(pc["vlan_drift_nic"])])
    ws_sum.append(["NetBox serial missing", str(serial_validation_needed)])
    ws_sum.append(["BMC vs NetBox OOB differs", str(bmc_oob_mismatch)])
    hr_total_x = 0
    for _hr_val in (
        pc["fip_gaps"],
        pc["sub_gaps"],
        pc["vlan_drift_nic"],
        serial_validation_needed,
        bmc_oob_mismatch,
    ):
        if isinstance(_hr_val, int):
            hr_total_x += _hr_val
    ws_sum.append(["Total", str(hr_total_x)])
    ws_sum.append([])
    ws_sum.append(["RUN METRICS", "", ""])
    _append_header(ws_sum, ["Metric", "Value"])
    ws_sum.append(["MAAS machines", str(len(maas_data.get("machines") or []))])
    ws_sum.append(["NetBox devices", str(len(netbox_data.get("devices") or []))])
    ws_sum.append(["Matched hostnames", str(drift.get("matched_count", 0))])
    ws_sum.append(["In MAAS only", str(pc["maas_only"])])
    ws_sum.append(["NetBox orphans", str(pc["nb_only_dev"])])
    ws_sum.append(["NetBox serial missing", str(serial_validation_needed)])
    ws_sum.append(["OpenStack subnet gaps", sub_txt])
    ws_sum.append(["OpenStack FIP gaps", str(pc["fip_gaps"])])
    ws_sum.append(["VLAN mismatch NICs", str(pc["vlan_drift_nic"])])
    ws_sum.append(["VLAN unverified NICs", str(pc["vlan_unverified_nic"])])
    ws_sum.append(["MAAS NIC missing in NetBox", str(pc["maas_nic_missing_nb"])])

    prop = _proposed_changes_rows(
        maas_data,
        netbox_data,
        drift,
        interface_audit,
        matched_rows,
        os_subnet_gaps or [],
        os_floating_gaps or [],
        netbox_ifaces=netbox_ifaces,
    )
    ws_sum.append([])
    ws_sum.append(["PROPOSED CHANGES (read-only)", "", ""])
    _append_header(ws_sum, ["Bucket", "Count"])
    total_props_x = (
        len(prop["add_devices"])
        + len(prop["add_prefixes"])
        + len(prop["add_fips"])
        + len(prop["update_nic"])
        + len(prop["add_nb_interfaces"])
        + len(prop["add_mgmt_iface"])
        + len(prop["review_orphans"])
        + len(prop["review_serial"])
    )
    ws_sum.append(["New devices", str(len(prop["add_devices"]))])
    ws_sum.append(["New prefixes", str(len(prop["add_prefixes"]))])
    ws_sum.append(["New floating IPs", str(len(prop["add_fips"]))])
    ws_sum.append(["NIC drift", str(len(prop["update_nic"]))])
    ws_sum.append(["New NICs", str(len(prop["add_nb_interfaces"]))])
    ws_sum.append(["BMC / OOB", str(len(prop["add_mgmt_iface"]))])
    ws_sum.append(["Orphans (review)", str(len(prop["review_orphans"]))])
    ws_sum.append(["Serials (review)", str(len(prop["review_serial"]))])
    ws_sum.append(["Total", str(total_props_x)])

    # Matched-host drift worksheet intentionally suppressed to match on-screen report.

    # --- Proposed changes (full list) ---
    ws_prop = _sheet("Proposed changes")
    ws_prop.append(["Drift detail — read-only; nothing is written to NetBox from this export."])
    ws_prop.cell(row=1, column=1).font = header_font
    ws_prop.append([])
    _append_header(ws_prop, ["Section", "Count"])
    ws_prop.append(["New devices (MAAS)", len(prop["add_devices"])])
    ws_prop.append(["New prefixes (OpenStack)", len(prop["add_prefixes"])])
    ws_prop.append(["New floating IPs (OpenStack)", len(prop["add_fips"])])
    ws_prop.append(["NIC drift", len(prop["update_nic"])])
    ws_prop.append(["New NICs", len(prop["add_nb_interfaces"])])
    ws_prop.append(["BMC / OOB", len(prop["add_mgmt_iface"])])
    ws_prop.append(["Orphans (review)", len(prop["review_orphans"])])
    ws_prop.append(["Serials (review)", len(prop["review_serial"])])

    def _append_block(title, headers, rows):
        ws_prop.append([])
        ws_prop.append([title])
        ws_prop.cell(row=ws_prop.max_row, column=1).font = header_font
        _append_header(ws_prop, headers)
        for row in rows:
            ws_prop.append(list(row))

    _append_block(
        "A) New devices",
        ["Hostname", "Zone", "Pool", "MAAS Status", "Proposed Tag", "Proposed Action"],
        prop["add_devices"],
    )
    _append_block(
        "A) New prefixes",
        ["CIDR", "Network Name", "Network ID", "Cloud", "Proposed Action"],
        prop["add_prefixes"],
    )
    _append_block(
        "A) New floating IPs",
        ["Floating IP", "Fixed IP", "Project", "Cloud", "Proposed Action"],
        prop["add_fips"],
    )
    _append_block(
        "B) New NICs",
        [
            "Host",
            "NB site",
            "NB location",
            "MAAS intf",
            "MAAS fabric",
            "MAAS MAC",
            "MAAS IPs",
            "MAAS VLAN",
            "Suggested NB name",
            "Proposed properties (from MAAS)",
            "Proposed action",
            "Risk",
        ],
        prop["add_nb_interfaces"],
    )
    _append_block(
        "B) NIC drift",
        [
            "Host",
            "MAAS intf",
            "MAAS fabric",
            "MAAS MAC",
            "MAAS IPs",
            "NB intf",
            "NB MAC",
            "NB IPs",
            "MAAS VLAN",
            "NB VLAN",
            "Status",
            "Reason",
            "Proposed Action",
            "Risk",
        ],
        prop["update_nic"],
    )
    _append_block(
        "B) BMC / OOB",
        [
            "Host",
            "MAAS BMC IP",
            "MAAS power_type",
            "MAAS BMC MAC",
            "NB OOB port (hint)",
            "NetBox OOB",
            "NB IP coverage",
            "NB port w/ BMC IP",
            "NB OOB MAC",
            "Status",
            "Proposed action",
            "Risk",
        ],
        prop["add_mgmt_iface"],
    )
    _append_block(
        "C) Orphans",
        ["Hostname", "Site", "Status", "Proposed Tag", "Proposed Action", "Risk"],
        prop["review_orphans"],
    )
    _append_block(
        "C) Serials",
        ["Hostname", "MAAS Serial", "NetBox Serial", "Proposed Action", "Risk"],
        prop["review_serial"],
    )

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()
