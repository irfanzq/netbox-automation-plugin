"""BMC / OOB comparison and proposed management interface rows."""

import re

from netbox_automation_plugin.sync.reporting.drift_report.misc_utils import _ip_address_host

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
    hardware_product: str | None = None,
) -> str:
    """
    MAAS-only hint when **creating** a new OOB port — ``ipmi`` or ``idrac`` only.

    - ``power_type`` containing ``redfish`` or ``idrac`` → ``idrac``.
    - ``power_type`` containing ``ipmi``: if vendor **or** product text contains
      ``dell`` (case-insensitive), suggest ``idrac`` (Dell BMC is iDRAC even when
      MAAS uses the generic IPMI driver); otherwise ``ipmi``.
    - Any other power type → ``ipmi``.

    Prefer NetBox’s existing port name when the BMC IP is already on an interface
    (``_oob_port_hint_column``).
    """
    pl = (power_type or "").lower()
    if "redfish" in pl or "idrac" in pl:
        return "idrac"
    if "ipmi" in pl:
        combined = (
            f"{(hardware_vendor or '').strip()} {(hardware_product or '').strip()}"
        ).lower()
        if "dell" in combined:
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
    Rows when power_type is set but BMC IP is missing from the MAAS API, or when OOB/BMC is not OK.
    Aligned BMC/OOB (status OK) is omitted — drift report lists issues only.
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
            pt, m.get("hardware_vendor"), m.get("hardware_product")
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

        if str(status).strip().upper() == "OK":
            continue
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
