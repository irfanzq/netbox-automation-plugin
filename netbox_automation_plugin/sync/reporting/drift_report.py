"""
Generate human-readable drift audit report from MAAS, NetBox, and OpenStack data.
Uses ASCII tables (+---+) for readability in <pre> or plain text.
XLSX export via build_drift_report_xlsx() for download (openpyxl); Google Sheets opens .xlsx.

Copy in this module explains that MAAS→NetBox reconciliation/sync (when run, using this drift
as the source of truth) is intended to cover data NICs and OOB/management from MAAS power
(IPMI, Redfish, iDRAC-class, etc.), not only the read-only audit UI.
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


# NetBox interface names often used for out-of-band (for coverage heuristics).
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


def _suggested_netbox_mgmt_interface_name(power_type: str) -> str:
    """Default interface name to create from MAAS power driver (operator can rename)."""
    pl = (power_type or "").lower()
    if "redfish" in pl or "idrac" in pl:
        return "idrac"
    if "ipmi" in pl:
        return "ipmi"
    return "bmc"


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
    How NetBox documents the MAAS BMC IP on interfaces.
    Returns (code, iface_name_or_emdash, short_note).
    """
    bh = _ip_address_host(bmc_ip)
    if not bh:
        return "NO_BMC_MAAS", "—", ""
    mgmt_name = ""
    any_name = ""
    for iface in nb_ifaces or []:
        iname = (iface.get("name") or "").strip().lower()
        is_mgmt_named = iname in _MGMT_INTERFACE_NAME_HINTS
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
        return "MGMT_IFACE", mgmt_name, "IP on mgmt-style interface"
    if any_name:
        return "IP_OTHER_IFACE", any_name, "IP present; name not typical for OOB"
    return "NO_IFACE_IP", "—", "No interface carries this IP"


def _build_proposed_mgmt_interface_rows(
    matched_rows,
    maas_by_hostname: dict,
    netbox_ifaces,
):
    """
    Matched hosts: OOB / IPMI / iDRAC alignment from MAAS power (BMC IP, optional MAC/VLAN hints).

    Rows when MAAS has BMC IP (compare to NetBox OOB + interfaces), or when MAAS has a power
    driver but no BMC IP in the API (admin/permissions/config gap).
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
        suggest = _suggested_netbox_mgmt_interface_name(pt)
        nb_oob = (r.get("netbox_oob") or "").strip()
        maas_mac = (m.get("bmc_mac") or "").strip()
        maas_vlan = (m.get("bmc_vlan") or "").strip()
        sid = str(m.get("system_id") or "")[:16] or "—"
        nb_list = nb_if.get(h) or []

        if not bmc:
            if not _meaningful_maas_power_type(pt):
                continue
            cov = "NO_BMC_IP_MAAS"
            nb_ifn = "—"
            nb_mgmt_mac = "—"
            nb_mgmt_vid = "—"
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
                sid,
                "—",
                pt,
                maas_mac or "—",
                maas_vlan or "—",
                suggest,
                nb_oob or "—",
                cov,
                nb_ifn,
                nb_mgmt_mac,
                nb_mgmt_vid,
                status,
                action,
                risk,
            ])
            continue

        cov, nb_ifn, cov_note = _netbox_bmc_ip_coverage(nb_list, bmc)
        oob_match = bool(nb_oob) and _ip_address_host(nb_oob) == _ip_address_host(bmc)
        nb_detail = _nb_iface_carrying_ip(nb_list, bmc)
        nb_mgmt_mac = (nb_detail.get("mac") or "—") if nb_detail else "—"
        nb_mgmt_vid = (
            str(nb_detail.get("untagged_vlan_vid") or "—") if nb_detail else "—"
        )

        if oob_match and cov == "MGMT_IFACE":
            status = "OK"
            action = "OOB + mgmt interface align with MAAS BMC"
            risk = "None"
        elif oob_match and cov == "NO_IFACE_IP":
            status = "ADD_MGMT_IFACE"
            action = (
                f"Create interface '{suggest}', mgmt_only=True, type e.g. 1000BASE-T; "
                f"assign {bmc}/<prefix>; cable in NetBox as needed"
            )
            risk = "Medium"
        elif oob_match and cov == "IP_OTHER_IFACE":
            status = "REVIEW"
            action = (
                f"BMC IP on '{nb_ifn}'; consider mgmt_only + rename to '{suggest}' or IPMI/iDRAC"
            )
            risk = "Low"
        elif not oob_match and cov == "MGMT_IFACE":
            status = "SET_OOB"
            action = f"Set device OOB IP to {bmc} (matches MAAS); mgmt on {nb_ifn}"
            risk = "Low"
        elif cov == "NO_IFACE_IP":
            status = "ADD_OOB_AND_MGMT"
            action = (
                f"Set device oob_ip to {bmc}; create '{suggest}' mgmt interface + assign IP"
            )
            risk = "Medium"
        else:
            status = "REVIEW"
            action = cov_note or "Align OOB / mgmt interface / MAAS BMC"
            risk = "Medium"

        if maas_mac and nb_mgmt_mac and nb_mgmt_mac != "—":
            mm = _normalize_mac(maas_mac)
            nm = _normalize_mac(nb_mgmt_mac)
            if mm and nm and mm != nm:
                action += (
                    f" MAC mismatch: MAAS BMC MAC {maas_mac} vs NetBox iface {nb_mgmt_mac}."
                )
                if status == "OK":
                    status = "REVIEW"
                    risk = "Medium"
        if maas_vlan and nb_mgmt_vid not in ("", "—", "None"):
            if maas_vlan.strip() != str(nb_mgmt_vid).strip():
                action += (
                    f" VLAN hint: MAAS {maas_vlan} vs NetBox untagged {nb_mgmt_vid} on BMC iface."
                )
                if status == "OK":
                    status = "REVIEW"
                    risk = "Low"

        out.append([
            h,
            sid,
            bmc,
            pt,
            maas_mac or "—",
            maas_vlan or "—",
            suggest,
            nb_oob or "—",
            cov,
            nb_ifn,
            nb_mgmt_mac,
            nb_mgmt_vid,
            status,
            action,
            risk,
        ])
    return sorted(out, key=lambda x: (x[0] or "").lower())


def _build_add_nb_interface_rows(interface_audit):
    """
    MAAS physical/logical NICs with a MAC that do not match any NetBox interface on the device.
    Preview: proposed new dcim.Interface (+ untagged VLAN, IP assignments from MAAS).
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
                f"Create NetBox interface named like MAAS '{maas_if}'; set MAC {mac}; "
                f"set untagged VLAN to MAAS VID {vlan} where applicable; "
                f"assign MAAS IPs on this interface (or device primary if policy prefers)"
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
            str(m.get("system_id", "")),
            "maas-discovered",
            "Create device + interfaces",
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
                actions.append("Add missing IP to NetBox interface")

            note_l = notes.lower()
            if ("netbox mac empty" in note_l) or ("mac mismatch" in note_l):
                if "mac mismatch" in note_l:
                    statuses.append("MAC_MISMATCH")
                else:
                    statuses.append("MISSING_NB_MAC")
                reasons.append("NetBox MAC missing or mismatched")
                actions.append("Set NetBox interface MAC from MAAS for reliable matching")

            if not statuses:
                statuses.append(st)
                reasons.append(_dedupe_note_parts(notes) or "Interface review needed")
                actions.append("Review interface alignment manually")

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
    review_bmc = []
    for r in (matched_rows or []):
        if "NB serial empty — correlate system_id" in (r.get("hints") or []):
            review_serial.append([
                r.get("hostname", ""),
                str(r.get("maas_serial", "")),
                str(r.get("maas_system_id", "")),
                str(r.get("netbox_serial", "")),
                "Manual validation",
                "High",
            ])
        maas_bmc = str(r.get("maas_bmc") or "—")
        nb_oob = str(r.get("netbox_oob") or "—")
        if maas_bmc != "—" and nb_oob != "—" and maas_bmc.lower() != nb_oob.lower():
            review_bmc.append([
                r.get("hostname", ""),
                maas_bmc,
                nb_oob,
                "Review/correct OOB field",
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
        "review_bmc": review_bmc,
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
        drift_lines.extend(_banner("SCOPE COVERAGE CHECK", "-"))
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

    # --- Phase 0 (design doc) — counts only ---
    drift_lines.append("")
    drift_lines.extend(_banner("PHASE 0 — DRIFT CATEGORIES (design doc)"))
    drift_lines.append(
        "  NetBox = design / IPAM; MAAS = bare-metal + MACs + power/OOB (IPMI/Redfish/iDRAC-class); "
        "OpenStack = runtime.  sync/DRIFT_DESIGN.md"
    )
    drift_lines.append(
        "  MAAS→NetBox sync based on this drift is intended to update data NICs and "
        "out-of-band/management (device OOB IP, mgmt interfaces) from MAAS, not only hosts."
    )
    drift_lines.append("  Identity: Device hostname (+ serial); Interface MAC (+ name); FIP = IP + project.")
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
            ["Drift category", "Count / note"],
            [
                ["MAAS-only runtime-discovered (tag: maas-discovered)", str(pc["maas_only"])],
                ["NetBox-only orphan devices (tag: orphaned)", nb_orphan_note],
                ["Matched: placement/lifecycle hints (CHECK)", str(pc["check_hosts"])],
                ["Device serial validation needed (NB serial empty)", str(serial_validation_needed)],
                ["Interface rows not OK (excl. OK)", str(pc["iface_not_ok"])],
                [
                    "MAAS NIC with no NetBox interface (NOT_IN_NETBOX)",
                    str(pc["maas_nic_missing_nb"]),
                ],
                [
                    "Physical NIC vlan-drift (MAAS VID vs NB untagged)",
                    str(pc["vlan_drift_nic"]),
                ],
                [
                    "VLAN unverified (NB VID set; MAAS API no VID)",
                    str(pc["vlan_unverified_nic"]),
                ],
                ["NetBox-only NICs (review signal, not auto-change)", str(pc["nb_only_nic"])],
                ["OpenStack subnet → no exact Prefix", sub_txt],
                ["OpenStack FIP → no NetBox IPAddress", str(pc["fip_gaps"])],
                ["MAAS BMC vs NetBox OOB mismatch", str(bmc_oob_mismatch)],
                ["LLDP vs cabling", "not in audit yet"],
            ],
        )
    )

    # --- High-risk summary (design doc: review-first deltas) ---
    drift_lines.append("")
    drift_lines.extend(_banner("HIGH-RISK DIFFERENCES (review first)", "-"))
    drift_lines.append("  Definition (v1): OS FIP/IPAM gaps, OS subnet/prefix gaps, VLAN_DRIFT, serial validation gaps, BMC/OOB mismatch.")
    hr_rows = []
    hr_total = 0
    for name, val in [
        ("OpenStack FIP not in NetBox IPAddress", pc["fip_gaps"]),
        ("OpenStack subnet without exact Prefix", pc["sub_gaps"] if pc["sub_gaps"] is not None else "N/A"),
        ("Physical NIC VLAN_DRIFT", pc["vlan_drift_nic"]),
        ("Serial validation needed (NB serial empty)", serial_validation_needed),
        ("MAAS BMC vs NetBox OOB mismatch", bmc_oob_mismatch),
    ]:
        hr_rows.append([name, str(val)])
        if isinstance(val, int):
            hr_total += val
    drift_lines.extend(_ascii_table(["High-risk category", "Count"], hr_rows))
    drift_lines.append(f"  High-risk total (numeric categories): {hr_total}")

    # --- Metrics (design doc summary statistics) ---
    drift_lines.append("")
    drift_lines.extend(_banner("METRICS (this run)", "-"))
    drift_lines.extend(_ascii_table(
        ["Metric", "Value"],
        [
            ["MAAS machines", str(len(maas_data.get("machines") or []))],
            ["NetBox devices", str(len(netbox_data.get("devices") or []))],
            ["Matched hostnames", str(drift.get("matched_count", 0))],
            ["MAAS-only runtime-discovered", str(pc["maas_only"])],
            ["NetBox-only orphan devices", str(pc["nb_only_dev"])],
            ["Serial validation needed", str(serial_validation_needed)],
            ["OpenStack subnet gaps", sub_txt],
            ["OpenStack FIP gaps", str(pc["fip_gaps"])],
            ["Physical NIC VLAN_DRIFT", str(pc["vlan_drift_nic"])],
            ["VLAN unverified NICs", str(pc["vlan_unverified_nic"])],
            ["MAAS NICs missing in NetBox (new interface)", str(pc["maas_nic_missing_nb"])],
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
    drift_lines.extend(_banner("PROPOSED CHANGES (DRIFT → MAAS→NETBOX SYNC)", "-"))
    drift_lines.append("  Read-only here: this Drift Audit screen does not write to NetBox.")
    drift_lines.append(
        "  MAAS→NetBox reconciliation/sync that uses this drift as its source of truth is "
        "intended to apply the categories below, including:"
    )
    drift_lines.append(
        "    • Data NICs — create missing NetBox interfaces; update MAC, untagged VLAN, and "
        "interface IP assignments from MAAS where this report shows gaps or drift."
    )
    drift_lines.append(
        "    • Out-of-band / management — from MAAS power (IPMI, Redfish, iDRAC-class, …): "
        "align Device OOB IP with MAAS BMC; create or update dedicated management interfaces "
        "(e.g. ipmi / idrac / bmc), mgmt_only, and IP from MAAS (no credentials in this report)."
    )
    drift_lines.append(
        "    • OpenStack → NetBox IPAM rows in section A when your sync workflow enables them."
    )
    drift_lines.append(
        "  Safety: this audit UI performs no writes and no automatic deletion; your sync "
        "policies apply at reconciliation time."
    )
    drift_lines.append("")

    drift_lines.append("  A) Add to NetBox")
    drift_lines.extend(_ascii_table(
        ["Category", "Count", "Meaning"],
        [
            ["Devices from MAAS", str(len(prop["add_devices"])), "Machine in MAAS, missing in NetBox"],
            ["Prefixes from OpenStack", str(len(prop["add_prefixes"])), "Subnet in OpenStack, missing Prefix"],
            ["Floating IPs from OpenStack", str(len(prop["add_fips"])), "FIP in OpenStack, missing IPAddress"],
        ],
    ))
    if prop["add_devices"]:
        drift_lines.append("  Devices to create from MAAS (`maas-discovered`)")
        drift_lines.extend(_ascii_table(
            ["Hostname", "Zone", "Pool", "MAAS Status", "System ID", "Proposed Tag", "Proposed Action"],
            prop["add_devices"],
            dynamic_columns=True,
        ))
    if prop["add_prefixes"]:
        drift_lines.append("  Prefixes to create from OpenStack")
        drift_lines.extend(_ascii_table(
            ["CIDR", "Network Name", "Network ID", "Cloud", "Proposed Action"],
            prop["add_prefixes"],
            dynamic_columns=True,
        ))
    if prop["add_fips"]:
        drift_lines.append("  Floating IPs to create in NetBox IPAM")
        drift_lines.extend(_ascii_table(
            ["Floating IP", "Fixed IP", "Project", "Cloud", "Proposed Action"],
            prop["add_fips"],
            dynamic_columns=True,
        ))

    drift_lines.append("")
    drift_lines.append("  B) Interfaces in NetBox (create + update)")
    drift_lines.extend(_ascii_table(
        ["Category", "Count", "Meaning"],
        [
            [
                "New NetBox interfaces (MAAS NIC, no NB MAC match)",
                str(len(prop["add_nb_interfaces"])),
                "Sync: create dcim.Interface from MAAS name/MAC/IP/VLAN — table below",
            ],
            [
                "NIC drift (MAAS MAC matched an existing NB interface)",
                str(len(prop["update_nic"])),
                "Sync: update existing NB interfaces (MAC/VLAN/IP/name) per MAAS where drift",
            ],
            [
                "OOB / BMC from MAAS power (IPMI, Redfish, iDRAC, …)",
                str(len(prop["add_mgmt_iface"])),
                "Sync target: device OOB + mgmt dcim.Interface from MAAS bmc_ip / power_type",
            ],
        ],
    ))
    if prop["add_nb_interfaces"]:
        drift_lines.append(
            "  Interfaces missing in NetBox — proposed new dcim.Interface (from MAAS; preview only)"
        )
        drift_lines.append(
            "    MAAS reported this MAC on no NetBox interface (by MAC or name+empty MAC)."
        )
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
        drift_lines.append("  NIC inventory + drift (existing NetBox interfaces only; IP may be empty)")
        drift_lines.append(
            "    Not-OK examples: MAC_MISMATCH, IP_GAP, VLAN_DRIFT, OK_NAME_DIFF, combined statuses. "
            "(Rows with no NB interface are in the table above.)"
        )
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
        drift_lines.append(
            "  OOB / IPMI / iDRAC / management — from MAAS power (no credentials in this report)"
        )
        drift_lines.append(
            "    Intended sync: for each host, bring NetBox in line with MAAS BMC IP and "
            "power driver (create mgmt interface + assign IP, set OOB, mgmt_only, naming) "
            "per Status / Proposed action below."
        )
        drift_lines.append(
            "    Includes hosts with power_type but no BMC IP in MAAS API (NO_BMC_IP); "
            "MAAS BMC MAC/VLAN when present in power_parameters; NetBox mgmt MAC/VLAN on iface w/ BMC IP."
        )
        drift_lines.extend(_ascii_table(
            [
                "Host",
                "MAAS system_id",
                "MAAS BMC IP",
                "MAAS power_type",
                "MAAS BMC MAC",
                "MAAS BMC VLAN hint",
                "Suggested NB iface",
                "NetBox OOB",
                "NB IP coverage",
                "NB iface w/ IP",
                "NB mgmt MAC",
                "NB mgmt VLAN",
                "Status",
                "Proposed action",
                "Risk",
            ],
            prop["add_mgmt_iface"],
            dynamic_columns=True,
        ))

    drift_lines.append("")
    drift_lines.append("  C) Review required (sync may skip or flag per policy)")
    drift_lines.extend(_ascii_table(
        ["Category", "Count", "Meaning"],
        [
            ["NetBox orphan devices", str(len(prop["review_orphans"])), "Device exists in NetBox but not in MAAS"],
            ["Serial validation required", str(len(prop["review_serial"])), "NetBox serial missing; validate identity"],
            ["BMC vs OOB mismatch", str(len(prop["review_bmc"])), "MAAS BMC differs from NetBox OOB — often merged into mgmt sync above"],
        ],
    ))
    if prop["review_orphans"]:
        drift_lines.append("  NetBox orphan devices (`orphaned`)")
        drift_lines.extend(_ascii_table(
            ["Hostname", "Site", "Status", "Proposed Tag", "Proposed Action", "Risk"],
            prop["review_orphans"],
            dynamic_columns=True,
        ))
        drift_lines.append("  Note: These are review-only records. No automatic deletion.")
    if prop["review_serial"]:
        drift_lines.append("  Serial validation required")
        drift_lines.extend(_ascii_table(
            ["Hostname", "MAAS Serial", "MAAS System ID", "NetBox Serial", "Proposed Action", "Risk"],
            prop["review_serial"],
            dynamic_columns=True,
        ))
    if prop["review_bmc"]:
        drift_lines.append("  BMC vs OOB mismatch")
        drift_lines.extend(_ascii_table(
            ["Hostname", "MAAS BMC", "NetBox OOB", "Proposed Action", "Risk"],
            prop["review_bmc"],
            dynamic_columns=True,
        ))

    drift_lines.append("")
    drift_lines.append("  PROPOSED CHANGES SUMMARY")
    total_props = (
        len(prop["add_devices"]) + len(prop["add_prefixes"]) + len(prop["add_fips"]) +
        len(prop["update_nic"]) + len(prop["add_nb_interfaces"]) + len(prop["add_mgmt_iface"]) +
        len(prop["review_orphans"]) + len(prop["review_serial"]) + len(prop["review_bmc"])
    )
    drift_lines.extend(_ascii_table(
        ["Bucket", "Count"],
        [
            ["Add: Devices", str(len(prop["add_devices"]))],
            ["Add: Prefixes", str(len(prop["add_prefixes"]))],
            ["Add: Floating IPs", str(len(prop["add_fips"]))],
            ["NIC drift (existing NB interface)", str(len(prop["update_nic"]))],
            ["New NetBox interfaces (MAAS NIC, no NB match)", str(len(prop["add_nb_interfaces"]))],
            ["OOB/BMC from MAAS power", str(len(prop["add_mgmt_iface"]))],
            ["Review: Orphans", str(len(prop["review_orphans"]))],
            ["Review: Serial", str(len(prop["review_serial"]))],
            ["Review: BMC/OOB", str(len(prop["review_bmc"]))],
            ["Total proposed records", str(total_props)],
        ],
    ))

    # --- GAPS: MAAS-only hosts ---
    drift_lines.append("")
    drift_lines.extend(_banner("GAPS — runtime not yet in NetBox", "-"))
    drift_lines.append("  Concise view below; full proposed rows are shown in PROPOSED CHANGES.")
    drift_lines.append("")

    maas_only = sorted(drift.get("in_maas_not_netbox") or [])
    drift_lines.append(f"  [MAAS] MAAS-only runtime-discovered (no NetBox Device): {len(maas_only)}")
    if maas_data.get("error"):
        drift_lines.append("    (MAAS error)")
    elif maas_only:
        drift_lines.append("    (see A) Add to NetBox -> Devices to create from MAAS)")
    else:
        drift_lines.append("    (none)")

    # Matched-host drift reference table intentionally suppressed to keep report concise.

    # Full NIC inventory (all MAC’d interfaces + statuses) is in Proposed Changes section B.

    # OpenStack details are intentionally hidden from on-screen drift output.

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
    ws_sum.append([])
    ws_sum.append(["Phase 0 — Drift categories", "", ""])
    _append_header(ws_sum, ["Category", "Count"])
    ws_sum.append(["MAAS-only runtime-discovered (maas-discovered)", str(pc["maas_only"])])
    ws_sum.append(["NetBox-only orphan devices (orphaned)", str(pc["nb_only_dev"])])
    ws_sum.append(["Matched — CHECK (placement/lifecycle)", str(pc["check_hosts"])])
    ws_sum.append(["Serial validation needed (NB serial empty)", str(serial_validation_needed)])
    ws_sum.append(["Interface rows not OK", str(pc["iface_not_ok"])])
    ws_sum.append(["MAAS NIC no NetBox interface (NOT_IN_NETBOX)", str(pc["maas_nic_missing_nb"])])
    ws_sum.append(["VLAN drift NICs", str(pc["vlan_drift_nic"])])
    ws_sum.append(["VLAN unverified NICs", str(pc["vlan_unverified_nic"])])
    ws_sum.append(["NetBox-only NICs", str(pc["nb_only_nic"])])
    ws_sum.append(["OpenStack subnet gaps", sub_txt])
    ws_sum.append(["OpenStack FIP gaps", str(pc["fip_gaps"])])
    ws_sum.append(["MAAS BMC vs NetBox OOB mismatch", str(bmc_oob_mismatch)])
    ws_sum.append([])
    ws_sum.append(["High-risk differences (v1)", "", ""])
    _append_header(ws_sum, ["High-risk category", "Count"])
    ws_sum.append(["OpenStack FIP not in NetBox IPAddress", str(pc["fip_gaps"])])
    ws_sum.append(["OpenStack subnet without exact Prefix", sub_txt])
    ws_sum.append(["Physical NIC VLAN_DRIFT", str(pc["vlan_drift_nic"])])
    ws_sum.append(["Serial validation needed", str(serial_validation_needed)])
    ws_sum.append(["MAAS BMC vs NetBox OOB mismatch", str(bmc_oob_mismatch)])
    ws_sum.append([])
    ws_sum.append(["MAAS <-> NetBox matched hostnames", str(drift.get("matched_count", 0)), ""])

    scope_meta = (drift or {}).get("scope_meta") or {}
    if scope_meta:
        ws_sum.append([])
        ws_sum.append(["Scope coverage check", "", ""])
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
    ws_sum.append(["Proposed changes: audit read-only; basis for MAAS→NetBox sync", "", ""])
    _append_header(ws_sum, ["Bucket", "Count"])
    ws_sum.append(["Add: Devices", str(len(prop["add_devices"]))])
    ws_sum.append(["Add: Prefixes", str(len(prop["add_prefixes"]))])
    ws_sum.append(["Add: Floating IPs", str(len(prop["add_fips"]))])
    ws_sum.append(["NIC drift (existing NB interface)", str(len(prop["update_nic"]))])
    ws_sum.append(["New NetBox interfaces (MAAS NIC, no NB match)", str(len(prop["add_nb_interfaces"]))])
    ws_sum.append(["OOB/BMC from MAAS power", str(len(prop["add_mgmt_iface"]))])
    ws_sum.append(["Review: Orphans", str(len(prop["review_orphans"]))])
    ws_sum.append(["Review: Serial", str(len(prop["review_serial"]))])
    ws_sum.append(["Review: BMC/OOB", str(len(prop["review_bmc"]))])

    # Matched-host drift worksheet intentionally suppressed to match on-screen report.

    # --- Proposed changes (full list) ---
    ws_prop = _sheet("Proposed changes")
    ws_prop.append(["This sheet lists drift; the audit UI does not write to NetBox."])
    ws_prop.cell(row=1, column=1).font = header_font
    ws_prop.append([
        "MAAS→NetBox sync driven by this drift is intended to apply: data NICs (create/update), "
        "and OOB/mgmt from MAAS power (IPMI, Redfish, iDRAC-class): OOB IP + mgmt interfaces.",
    ])
    ws_prop.cell(row=2, column=1).font = header_font
    ws_prop.append(["Safety: no automatic deletion in this audit; sync policies apply at reconcile time."])
    ws_prop.cell(row=3, column=1).font = header_font
    ws_prop.append([])
    _append_header(ws_prop, ["Section", "Count"])
    ws_prop.append(["Add: Devices from MAAS", len(prop["add_devices"])])
    ws_prop.append(["Add: Prefixes from OpenStack", len(prop["add_prefixes"])])
    ws_prop.append(["Add: Floating IPs from OpenStack", len(prop["add_fips"])])
    ws_prop.append(["NIC drift (existing NB interface)", len(prop["update_nic"])])
    ws_prop.append(["New NetBox interfaces (MAAS NIC, no NB match)", len(prop["add_nb_interfaces"])])
    ws_prop.append(["OOB/BMC from MAAS power", len(prop["add_mgmt_iface"])])
    ws_prop.append(["Review: NetBox orphans", len(prop["review_orphans"])])
    ws_prop.append(["Review: Serial validation", len(prop["review_serial"])])
    ws_prop.append(["Review: BMC vs OOB mismatch", len(prop["review_bmc"])])

    def _append_block(title, headers, rows):
        ws_prop.append([])
        ws_prop.append([title])
        ws_prop.cell(row=ws_prop.max_row, column=1).font = header_font
        _append_header(ws_prop, headers)
        for row in rows:
            ws_prop.append(list(row))

    _append_block(
        "A) Devices to create from MAAS (maas-discovered)",
        ["Hostname", "Zone", "Pool", "MAAS Status", "System ID", "Proposed Tag", "Proposed Action"],
        prop["add_devices"],
    )
    _append_block(
        "A) Prefixes to create from OpenStack",
        ["CIDR", "Network Name", "Network ID", "Cloud", "Proposed Action"],
        prop["add_prefixes"],
    )
    _append_block(
        "A) Floating IPs to create in NetBox IPAM",
        ["Floating IP", "Fixed IP", "Project", "Cloud", "Proposed Action"],
        prop["add_fips"],
    )
    _append_block(
        "B) Interfaces missing in NetBox — proposed new dcim.Interface (MAAS NIC, no NB match)",
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
        "B) NIC inventory + drift (existing NetBox interfaces; MAAS MAC matched NB)",
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
        "B) OOB / IPMI / iDRAC / mgmt — MAAS power → NetBox sync targets (no credentials here)",
        [
            "Host",
            "MAAS system_id",
            "MAAS BMC IP",
            "MAAS power_type",
            "MAAS BMC MAC",
            "MAAS BMC VLAN hint",
            "Suggested NB iface",
            "NetBox OOB",
            "NB IP coverage",
            "NB iface w/ IP",
            "NB mgmt MAC",
            "NB mgmt VLAN",
            "Status",
            "Proposed action",
            "Risk",
        ],
        prop["add_mgmt_iface"],
    )
    _append_block(
        "C) NetBox orphan devices (orphaned)",
        ["Hostname", "Site", "Status", "Proposed Tag", "Proposed Action", "Risk"],
        prop["review_orphans"],
    )
    _append_block(
        "C) Serial validation required",
        ["Hostname", "MAAS Serial", "MAAS System ID", "NetBox Serial", "Proposed Action", "Risk"],
        prop["review_serial"],
    )
    _append_block(
        "C) BMC vs OOB mismatch",
        ["Hostname", "MAAS BMC", "NetBox OOB", "Proposed Action", "Risk"],
        prop["review_bmc"],
    )

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()
