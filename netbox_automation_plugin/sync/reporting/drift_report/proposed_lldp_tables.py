"""OpenStack Ironic local_link (LLDP-style) vs NetBox interface cabling — proposed rows."""

from __future__ import annotations

import re

_OS_LLDP_SWITCH_MAC_RE = re.compile(r"\bswitch\s+([0-9a-fA-F:.-]+)", re.I)
_OS_LLDP_PORT_RE = re.compile(r"\bport\s+([^·|]+)", re.I)


def _norm_mac(m: str) -> str:
    return (m or "").strip().lower().replace("-", ":")


def _norm_peer(s: str) -> str:
    t = " ".join((s or "").lower().split())
    for ch in "·|":
        t = t.replace(ch, " ")
    return " ".join(t.split())


def lldp_switch_hostnames_for_netbox_fetch(openstack_data: dict | None) -> set[str]:
    """Device names to load from NetBox so LLDP rows can resolve switch interface names."""
    out: set[str] = set()
    for r in (openstack_data or {}).get("runtime_nics") or []:
        if not isinstance(r, dict):
            continue
        ll = r.get("local_link") if isinstance(r.get("local_link"), dict) else {}
        sinfo = (ll.get("switch_info") or "").strip()
        if not sinfo:
            continue
        if ":" in sinfo:
            _, _, name = sinfo.partition(":")
            name = name.strip()
            if name:
                out.add(name)
        else:
            out.add(sinfo)
    return out


def _parse_os_lldp_fallback(line: str) -> tuple[str, str, str]:
    """Best-effort parse when local_link dict is missing but os_lldp string exists."""
    line = (line or "").strip()
    if not line:
        return "—", "—", "—"
    first = line.split("·")[0].strip()
    if ":" in first:
        _, _, sw = first.partition(":")
        sw_name = (sw.strip() or first.strip() or "—")
    else:
        sw_name = first or "—"
    m_mac = _OS_LLDP_SWITCH_MAC_RE.search(line)
    sw_mac = _norm_mac(m_mac.group(1)) if m_mac else "—"
    m_pt = _OS_LLDP_PORT_RE.search(line)
    port = (m_pt.group(1) or "").strip() if m_pt else "—"
    return sw_name, sw_mac or "—", port or "—"


def _fields_from_local_link(ll: dict, os_lldp_line: str) -> tuple[str, str, str]:
    if ll:
        sinfo = (ll.get("switch_info") or "").strip()
        sw_name = sinfo
        if ":" in sinfo:
            _, _, rest = sinfo.partition(":")
            sw_name = (rest.strip() or sinfo)
        sid = (ll.get("switch_id") or ll.get("switch_chassis_id") or "").strip()
        pid = (ll.get("port_id") or "").strip()
        return (
            sw_name or "—",
            _norm_mac(sid) if sid else "—",
            pid or "—",
        )
    return _parse_os_lldp_fallback(os_lldp_line)


def _ifaces_for_switch(netbox_ifaces: dict | None, os_switch: str):
    if not netbox_ifaces or not os_switch or os_switch == "—":
        return None
    if os_switch in netbox_ifaces:
        return netbox_ifaces[os_switch]
    osl = os_switch.strip().lower()
    for k, v in netbox_ifaces.items():
        if (k or "").strip().lower() == osl:
            return v
    return None


def _find_nb_iface_for_mac(
    netbox_ifaces: dict | None, hostname: str, mac: str
) -> dict | None:
    if not netbox_ifaces or not hostname or not mac:
        return None
    h = (hostname or "").strip().lower()
    m = _norm_mac(mac)
    for row in netbox_ifaces.get(hostname) or netbox_ifaces.get(h) or []:
        if not isinstance(row, dict):
            continue
        rm = _norm_mac(row.get("mac") or "")
        if rm == m:
            return row
    for key, lst in netbox_ifaces.items():
        if (key or "").strip().lower() != h:
            continue
        for row in lst or []:
            if not isinstance(row, dict):
                continue
            rm = _norm_mac(row.get("mac") or "")
            if rm == m:
                return row
    return None


def _is_explicit_os_port_id(port_id: str) -> bool:
    """
    OS port strings that already name a real interface style (bond/swp/Ethernet/…).
    For these we only exact-match NetBox; we do not infer Ethernet<N> from bare numbers.
    """
    p = (port_id or "").strip()
    if not p or p == "—":
        return False
    pl = p.lower()
    if "bond" in pl:
        return True
    if "swp" in pl:
        return True
    if "port-channel" in pl or "portchannel" in pl:
        return True
    if pl.startswith("ethernet"):
        return True
    if pl.startswith("gigabitethernet") or pl.startswith("gigabit ethernet"):
        return True
    if re.match(r"^(gi|te|tw|fo|fa|hu)\d", pl):
        return True
    if re.match(r"^xe\d", pl):
        return True
    if re.match(r"^po\d+$", pl):
        return True
    return False


def _switch_iface_rows(switch_ifaces: list | None) -> list[dict]:
    return [x for x in (switch_ifaces or []) if isinstance(x, dict)]


def _exact_name_match_netbox(switch_ifaces: list | None, port_id: str) -> str | None:
    lst = _switch_iface_rows(switch_ifaces)
    pid = (port_id or "").strip()
    if not pid:
        return None
    pid_l = pid.lower()
    for row in lst:
        nm = (row.get("name") or "").strip()
        if nm == pid or nm.lower() == pid_l:
            return nm
    return None


def _generic_resolve_netbox_name(
    switch_ifaces: list | None, port_id: str, switch_mac: str
) -> str | None:
    """
    Map abbreviated LLDP port ids (digits, port<N>, etc.) to NetBox Interface.name.
    Returns None if no match (caller falls back to OS port id).
    """
    lst = _switch_iface_rows(switch_ifaces)
    pid = (port_id or "").strip()
    if not pid or pid == "—":
        return None

    hit = _exact_name_match_netbox(switch_ifaces, port_id)
    if hit:
        return hit

    bare = pid.lower()
    if bare.startswith("port") and bare[4:].isdigit():
        bare = bare[4:]
    elif bare.startswith("port ") and bare[5:].strip().isdigit():
        bare = bare[5:].strip()

    if bare.isdigit():
        n = int(bare)
        eth = f"Ethernet{n}"
        for row in lst:
            nm = (row.get("name") or "").strip()
            nl = nm.lower()
            if nl == eth.lower() or nm == str(n):
                return nm
        for row in lst:
            nm = (row.get("name") or "").strip()
            nl = nm.lower()
            if nl == f"eth{n}" or nl == f"e{n}":
                return nm
        for row in lst:
            nm = (row.get("name") or "").strip()
            if nm.endswith(bare) and any(
                nm.lower().startswith(p)
                for p in ("ethernet", "eth", "gi", "gigabitethernet", "xe", "swp")
            ):
                return nm

    sm = _norm_mac(switch_mac)
    if sm and sm != "—":
        for row in lst:
            rm = _norm_mac(row.get("mac") or "")
            if rm and rm == sm:
                nm = (row.get("name") or "").strip()
                return nm or None

    return None


def _netbox_switch_port_display_and_status(
    nb_sw_ifaces,
    os_port: str,
    os_switch_mac: str,
) -> tuple[str, str]:
    """
    NetBox switch port column + short status.
    - Explicit OS ids (bond/swp/Ethernet/…): exact NetBox match only; else port column "—"
      and status switch port missing in NetBox.
    - Generic ids: resolve to NetBox name if possible; else NetBox column shows OS value
      and status explains.
    """
    pid = (os_port or "").strip()
    if not pid or pid == "—":
        return "—", "—"

    if not nb_sw_ifaces:
        if _is_explicit_os_port_id(pid):
            return "—", "Switch missing in NetBox"
        return pid, "Switch missing in NetBox"

    explicit = _is_explicit_os_port_id(pid)
    if explicit:
        hit = _exact_name_match_netbox(nb_sw_ifaces, pid)
        if hit:
            return hit, "Matched"
        return "—", "Switch port missing in NetBox"

    hit = _generic_resolve_netbox_name(nb_sw_ifaces, pid, os_switch_mac)
    if hit:
        return hit, "Resolved in NetBox"
    return pid, "Using OS port id (not in NetBox)"


def _maas_iface_name(maas_data: dict | None, hostname: str, mac: str) -> str:
    if not maas_data or not hostname or not mac:
        return "—"
    h = hostname.strip().lower()
    m = _norm_mac(mac)
    for machine in maas_data.get("machines") or []:
        if not isinstance(machine, dict):
            continue
        if (machine.get("hostname") or "").strip().lower() != h:
            continue
        for iface in machine.get("interfaces") or []:
            if not isinstance(iface, dict):
                continue
            if _norm_mac(iface.get("mac") or "") == m:
                nm = (iface.get("name") or "").strip()
                return nm or "—"
        return "—"
    return "—"


def build_lldp_drift_rows(
    openstack_data: dict | None,
    netbox_ifaces: dict | None,
    maas_data: dict | None = None,
) -> tuple[list, list]:
    """
    Compare Ironic local_link_connection (serialized as os_lldp on runtime_nics) to NetBox
    interface peer/cable summary (peer_summary).

    Returns:
      lldp_new: OS has link data; NetBox has no peer summary for that host+MAC.
      lldp_update: both have data but normalized strings differ.
    """
    lldp_new: list[list] = []
    lldp_update: list[list] = []
    if not openstack_data or openstack_data.get("error"):
        return lldp_new, lldp_update

    seen: set[tuple[str, str]] = set()
    for r in openstack_data.get("runtime_nics") or []:
        if not isinstance(r, dict):
            continue
        host = str(r.get("hostname") or "").strip()
        mac = _norm_mac(str(r.get("mac") or r.get("os_mac") or ""))
        if not host or not mac:
            continue
        ll = r.get("local_link") if isinstance(r.get("local_link"), dict) else {}
        os_lldp = str(r.get("os_lldp") or "").strip()
        if not ll and not os_lldp:
            continue
        key = (host.lower(), mac)
        if key in seen:
            continue
        seen.add(key)

        os_switch, os_switch_mac, os_port = _fields_from_local_link(ll, os_lldp)
        nb_sw_ifaces = _ifaces_for_switch(netbox_ifaces, os_switch)

        nb_port_disp, nb_port_status = _netbox_switch_port_display_and_status(
            nb_sw_ifaces, os_port, os_switch_mac
        )
        maas_int = _maas_iface_name(maas_data, host, mac)

        os_reg = str(r.get("os_region") or openstack_data.get("openstack_region_name") or "—").strip() or "—"
        nb = _find_nb_iface_for_mac(netbox_ifaces, host, mac)
        nb_peer = str((nb or {}).get("peer_summary") or "").strip()
        nb_site = str((nb or {}).get("nb_site") or "—").strip() or "—"
        nb_loc = str((nb or {}).get("nb_location") or "—").strip() or "—"
        nb_iface = str((nb or {}).get("name") or "—").strip() or "—"
        nb_mac = str((nb or {}).get("mac") or mac).strip() or mac

        peer_hint = nb_port_disp if nb_port_disp != "—" else os_port
        action_new = (
            "Document switch/port in NetBox (cable or interface description); "
            f"use peer «{os_switch}:{peer_hint}» if that matches the physical uplink."
        )
        if nb_port_status == "Switch port missing in NetBox":
            action_new = (
                f"Add or rename interface on NetBox device «{os_switch}» to match OS port «{os_port}» "
                "(bond/swp-style id is authoritative from OpenStack)."
            )
        elif nb_port_status.startswith("Switch missing"):
            action_new = (
                f"Model switch «{os_switch}» in NetBox (or fix name mismatch) so the port can be documented."
            )

        if not nb_peer:
            lldp_new.append([
                host,
                os_reg,
                mac,
                maas_int,
                os_switch,
                os_switch_mac,
                os_port,
                nb_port_disp,
                nb_port_status,
                action_new,
            ])
            continue

        if _norm_peer(nb_peer) != _norm_peer(os_lldp):
            snippet = os_lldp[:180] + ("…" if len(os_lldp) > 180 else "")
            lldp_update.append([
                host,
                os_reg,
                nb_site,
                nb_loc,
                nb_iface,
                nb_mac,
                nb_peer,
                mac,
                maas_int,
                os_switch,
                os_switch_mac,
                os_port,
                nb_port_disp,
                nb_port_status,
                (
                    "Align NetBox peer/cable with OS-discovered switch/port (OpenStack): "
                    f"«{os_switch}» port «{os_port}»"
                    + (
                        f" (NetBox port «{nb_port_disp}», {nb_port_status})"
                        if nb_port_disp != "—"
                        else f" ({nb_port_status})"
                    )
                    + f"; raw «{snippet}»"
                ),
            ])

    lldp_new.sort(key=lambda row: ((row[0] or "").lower(), row[2] or ""))
    lldp_update.sort(key=lambda row: ((row[0] or "").lower(), row[7] or ""))  # OS MAC
    return lldp_new, lldp_update
