"""BMC / OOB comparison and proposed management interface rows."""

import re

from netbox_automation_plugin.sync.reporting.drift_report.misc_utils import _ip_address_host
from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_derived import (
    bmc_row_proposed_defaults,
)


def _bmc_drift_extra_columns(maas_machine: dict) -> dict[str, str]:
    ex = bmc_row_proposed_defaults(maas_machine)
    v = str(maas_machine.get("hardware_vendor") or "").strip()
    p = str(maas_machine.get("hardware_product") or "").strip()
    if v and p:
        ex["maas_nic_model"] = f"{v[:32]} / {p[:64]}"
    elif v:
        ex["maas_nic_model"] = v[:96]
    elif p:
        ex["maas_nic_model"] = p[:96]
    return ex

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

    - ``power_type`` containing ``idrac`` → ``idrac``.
    - ``power_type`` containing ``redfish``: if vendor/product contains ``dell`` then
      ``idrac`` else ``ipmi``.
    - ``power_type`` containing ``ipmi``: if vendor **or** product text contains
      ``dell`` (case-insensitive), suggest ``idrac`` (Dell BMC is iDRAC even when
      MAAS uses the generic IPMI driver); otherwise ``ipmi``.
    - Any other power type → ``ipmi``.

    Prefer NetBox’s existing port name when the BMC IP is already on an interface
    (``_oob_port_hint_column``).
    """
    pl = (power_type or "").lower()
    combined = (
        f"{(hardware_vendor or '').strip()} {(hardware_product or '').strip()}"
    ).lower()
    if "idrac" in pl:
        return "idrac"
    if "redfish" in pl:
        if "dell" in combined:
            return "idrac"
        return "ipmi"
    if "ipmi" in pl:
        if "dell" in combined:
            return "idrac"
        return "ipmi"
    return "ipmi"


def _suggested_netbox_mgmt_interface_name_from_os(
    *,
    vendor: str = "",
    driver: str = "",
    power_interface: str = "",
) -> str:
    """
    Operator convention:
      - Dell -> idrac
      - all non-Dell -> ipmi
    Uses OS vendor first when available; falls back to driver hints.
    """
    v = (vendor or "").strip().lower()
    if "dell" in v:
        return "idrac"
    d = f"{(driver or '').lower()} {(power_interface or '').lower()}"
    if "idrac" in d:
        return "idrac"
    return "ipmi"


def _os_runtime_bmc_by_hostname(openstack_data: dict | None) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in (openstack_data or {}).get("runtime_bmc") or []:
        h = (r.get("hostname") or "").strip().lower()
        if h:
            out[h] = r
    return out


def _os_is_authoritative_for_host(os_row: dict | None) -> bool:
    """
    Host-level OpenStack authority gate:
    - require instance_uuid
    - require provisioning state in trusted set
    """
    if not os_row:
        return False
    instance_uuid = str(os_row.get("instance_uuid") or "").strip()
    if not instance_uuid:
        return False
    prov = str(os_row.get("provision_state") or "").strip().lower()
    return prov in {"active", "available"}


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


def _first_nb_oob_iface(nb_ifaces: list):
    """
    First NetBox interface that looks like OOB (mgmt_only or OOB-like name).
    Used when BMC IP is not found on any interface, so the table can still show
    the existing OOB port context instead of empty placeholders.
    """
    for iface in nb_ifaces or []:
        if bool(iface.get("mgmt_only")):
            return iface
    for iface in nb_ifaces or []:
        if _netbox_iface_name_suggests_oob(iface.get("name") or ""):
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
    openstack_data=None,
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
    os_bmc_by_h = _os_runtime_bmc_by_hostname(openstack_data)
    out = []
    for r in matched_rows or []:
        h = (r.get("hostname") or "").strip()
        if not h:
            continue
        m = maas_by_hostname.get(h) or {}
        bmc = (m.get("bmc_ip") or "").strip()
        pt = (m.get("power_type") or "").strip() or "—"
        maas_vendor = str(m.get("hardware_vendor") or "").strip() or "—"
        maas_product = str(m.get("hardware_product") or "").strip() or "—"
        os_row = os_bmc_by_h.get(h.lower()) or {}
        os_bmc_ip = (os_row.get("os_bmc_ip") or "").strip()
        os_drv = (os_row.get("driver") or "").strip()
        os_pif = (os_row.get("power_interface") or "").strip()
        os_vendor = (os_row.get("vendor") or "").strip()
        os_model = (
            str(os_row.get("model") or os_row.get("product") or os_row.get("hardware_model") or "")
            .strip() or "—"
        )
        authority = "openstack_runtime" if _os_is_authoritative_for_host(os_row) else "maas_fallback"
        authority_badge = "[OS]" if authority == "openstack_runtime" else "[MAAS]"
        bmc_effective = os_bmc_ip or bmc
        maas_oob_new = _suggested_netbox_mgmt_interface_name(
            pt, m.get("hardware_vendor"), m.get("hardware_product")
        )
        os_oob_new = _suggested_netbox_mgmt_interface_name_from_os(
            vendor=os_vendor, driver=os_drv, power_interface=os_pif
        )
        mgmt_suggested = os_oob_new if authority == "openstack_runtime" else maas_oob_new
        nb_oob = (r.get("netbox_oob") or "").strip()
        maas_mac = (m.get("bmc_mac") or "").strip()
        maas_vlan = (m.get("bmc_vlan") or "").strip()
        nb_list = nb_if.get(h) or []

        if not bmc_effective:
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
            bx = _bmc_drift_extra_columns(m)
            out.append([
                h,
                "—",
                pt,
                maas_vendor,
                maas_product,
                maas_mac or "—",
                bx["maas_link_speed_disp"],
                bx["maas_nic_model"],
                "—",
                "—",
                "—",
                "—",
                bx["os_link_speed_disp"],
                bx["os_switch_disp"],
                bx["nb_proposed_intf_label"],
                bx["nb_proposed_intf_type"],
                maas_oob_new,
                nb_oob or "—",
                cov,
                nb_ifn,
                nb_mgmt_mac,
                authority_badge,
                status,
                action,
                risk,
            ])
            continue

        cov, nb_ifn, cov_note = _netbox_bmc_ip_coverage(nb_list, bmc_effective)
        cov_ip_used = bmc_effective
        # If OS runtime BMC IP is authoritative but NB still carries MAAS BMC IP,
        # show the existing NB coverage/port instead of a misleading NO_IFACE_IP.
        if (
            authority == "openstack_runtime"
            and cov == "NO_IFACE_IP"
            and bmc
            and _ip_address_host(bmc) != _ip_address_host(bmc_effective)
        ):
            cov2, nb_ifn2, cov_note2 = _netbox_bmc_ip_coverage(nb_list, bmc)
            if cov2 != "NO_IFACE_IP":
                cov, nb_ifn, cov_note = cov2, nb_ifn2, cov_note2
                cov_ip_used = bmc
        # If no interface currently carries the target BMC IP, still show existing OOB port context.
        nb_oob_iface = _first_nb_oob_iface(nb_list)
        if cov == "NO_IFACE_IP" and nb_oob_iface:
            cov = "OOB_IFACE_IP_MISMATCH"
            nb_ifn = (nb_oob_iface.get("name") or "—").strip() or "—"
            cov_note = (
                "NetBox has an OOB-style interface, but it does not carry the target BMC IP"
            )

        oob_port_hint = _oob_port_hint_column(cov, nb_ifn, mgmt_suggested)
        oob_match = bool(nb_oob) and _ip_address_host(nb_oob) == _ip_address_host(cov_ip_used)
        nb_detail = _nb_iface_carrying_ip(nb_list, cov_ip_used)
        if nb_detail is None and cov == "OOB_IFACE_IP_MISMATCH":
            nb_detail = nb_oob_iface
        nb_mgmt_mac = (nb_detail.get("mac") or "—") if nb_detail else "—"
        nb_mgmt_vid = (
            str(nb_detail.get("untagged_vlan_vid") or "—") if nb_detail else "—"
        )

        target_ip = str(cov_ip_used or bmc_effective or bmc or "—").strip() or "—"

        risk_rank = {"None": 0, "Low": 1, "Medium": 2, "High": 3}

        def _bump_risk(cur: str, want: str) -> str:
            c = cur if cur in risk_rank else "Low"
            w = want if want in risk_rank else "Low"
            return w if risk_rank[w] > risk_rank[c] else c

        if oob_match and cov == "MGMT_IFACE":
            status = "OK"
            action = "NO_CHANGE"
            risk = "None"
        elif oob_match and cov == "NO_IFACE_IP":
            status = "ADD_MGMT_IFACE"
            action = "ADD_NETBOX_OOB_IFACE; SET_NETBOX_OOB_IP"
            risk = "Medium"
        elif oob_match and cov == "IP_OTHER_IFACE":
            status = "REVIEW"
            action = "REVIEW_OOB_PORT_CLASSIFICATION"
            risk = "Low"
        elif not oob_match and cov == "MGMT_IFACE":
            status = "SET_OOB"
            action = "SET_NETBOX_OOB_IP"
            risk = "Low"
        elif not oob_match and cov == "OOB_IFACE_IP_MISMATCH":
            status = "SET_OOB"
            action = "SET_NETBOX_OOB_IP; REVIEW_OOB_IFACE_IP"
            risk = "Medium"
        elif cov == "NO_IFACE_IP":
            status = "ADD_OOB_AND_MGMT"
            action = "SET_NETBOX_OOB_IP; ADD_NETBOX_OOB_IFACE"
            risk = "Medium"
        else:
            status = "REVIEW"
            action = "REVIEW_BMC_ALIGNMENT"
            risk = "Medium"

        if action != "NO_CHANGE":
            if "SET_NETBOX_OOB_IP" in action:
                action = action.replace(
                    "SET_NETBOX_OOB_IP",
                    f"SET_NETBOX_OOB_IP={target_ip}",
                )
            if "ADD_NETBOX_OOB_IFACE" in action:
                action = action.replace(
                    "ADD_NETBOX_OOB_IFACE",
                    f"ADD_NETBOX_OOB_IFACE={mgmt_suggested or 'mgmt0'}",
                )

        status_before_mac = status
        maas_mac_norm = _normalize_mac(maas_mac) if maas_mac else ""
        nb_mgmt_mac_norm = _normalize_mac(nb_mgmt_mac) if nb_mgmt_mac and nb_mgmt_mac != "—" else ""
        if maas_mac and nb_mgmt_mac and nb_mgmt_mac != "—":
            if maas_mac_norm and nb_mgmt_mac_norm and maas_mac_norm != nb_mgmt_mac_norm:
                if status == "OK":
                    status = "REVIEW"
                    risk = "Medium"
                # Emit concrete target/current MAC values for mismatch.
                if status_before_mac == "OK":
                    action = (
                        f"SET_NETBOX_OOB_MAC={maas_mac_norm} "
                        f"(current NB MAC {nb_mgmt_mac})"
                    )
                else:
                    action += (
                        f"; SET_NETBOX_OOB_MAC={maas_mac_norm} "
                        f"(current NB MAC {nb_mgmt_mac})"
                    )
                risk = _bump_risk(risk, "High")
        elif maas_mac_norm and (
            (not nb_mgmt_mac) or str(nb_mgmt_mac).strip() in {"", "—", "-", "None", "none"}
        ):
            # Missing NetBox OOB MAC: populate from MAAS hardware MAC.
            action += f"; SET_NETBOX_OOB_MAC={maas_mac_norm} (current NB MAC —)"
            risk = _bump_risk(risk, "Medium")
        if maas_vlan and nb_mgmt_vid not in ("", "—", "None"):
            if maas_vlan.strip() != str(nb_mgmt_vid).strip():
                action += (
                    "; REVIEW_BMC_VLAN_HINT"
                )
                if status == "OK":
                    status = "REVIEW"
                risk = _bump_risk(risk, "Medium")

        if authority == "openstack_runtime":
            # OS generally does not expose BMC MAC reliably; suppress MAAS MAC-only drift here.
            if "MAC mismatch:" in action:
                action = action.replace(
                    " MAC mismatch: MAAS BMC MAC " + maas_mac + f" vs NetBox port {nb_mgmt_mac}.",
                    "",
                )
            if "BMC MAC mismatch:" in action:
                action = f"SET_NETBOX_OOB_IP={target_ip}; SKIP_BMC_MAC_VALIDATION_OS"
                if status == "REVIEW":
                    status = "SET_OOB_OS"

        if authority == "openstack_runtime" and _ip_address_host(cov_ip_used) != _ip_address_host(bmc_effective):
            action += "; REPLACE_MAAS_BMC_IP_WITH_OS_BMC_IP"

        if action != "NO_CHANGE":
            if "REVIEW_OOB_IFACE_IP" in action:
                action = action.replace(
                    "REVIEW_OOB_IFACE_IP",
                    f"REVIEW_OOB_IFACE_IP=target {target_ip} not on NetBox OOB iface {nb_ifn or '—'}",
                )
            if "REVIEW_BMC_VLAN_HINT" in action:
                action = action.replace(
                    "REVIEW_BMC_VLAN_HINT",
                    f"REVIEW_BMC_VLAN_HINT=MAAS VLAN {maas_vlan or '—'} vs NetBox VLAN {nb_mgmt_vid or '—'}",
                )
            if "REPLACE_MAAS_BMC_IP_WITH_OS_BMC_IP" in action:
                action = action.replace(
                    "REPLACE_MAAS_BMC_IP_WITH_OS_BMC_IP",
                    f"REPLACE_MAAS_BMC_IP_WITH_OS_BMC_IP={bmc or '—'} -> {bmc_effective or target_ip}",
                )

        # When NetBox OOB port has no MAC but MAAS (or MAAS hardware on OS-authority rows) has one, spell it out in Proposed action.
        mac_src = _normalize_mac(maas_mac) if maas_mac else ""
        nb_mac_empty = (not nb_mgmt_mac) or str(nb_mgmt_mac).strip() in ("", "—", "-", "None", "none")
        if (
            mac_src
            and nb_mac_empty
            and str(status).strip().upper() != "OK"
            and "SET_NETBOX_OOB_MAC=" not in action
            and "SKIP_BMC_MAC_VALIDATION_OS" not in action
        ):
            action += f"; SET_NETBOX_OOB_MAC={mac_src}"

        if str(status).strip().upper() == "OK":
            continue
        bx = _bmc_drift_extra_columns(m)
        out.append([
            h,
            bmc or "—",
            pt,
            maas_vendor,
            maas_product,
            maas_mac or "—",
            bx["maas_link_speed_disp"],
            bx["maas_nic_model"],
            os_bmc_ip or "—",
            (os_drv or os_pif or "—"),
            os_vendor or "—",
            os_model,
            bx["os_link_speed_disp"],
            bx["os_switch_disp"],
            bx["nb_proposed_intf_label"],
            bx["nb_proposed_intf_type"],
            oob_port_hint,
            nb_oob or "—",
            cov,
            nb_ifn,
            nb_mgmt_mac,
            authority_badge,
            status,
            action,
            risk,
        ])
    return sorted(out, key=lambda x: (x[0] or "").lower())
