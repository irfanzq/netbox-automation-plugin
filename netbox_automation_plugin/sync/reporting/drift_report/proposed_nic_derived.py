"""
Heuristic NB proposed intf Label / Type for drift NIC tables (review defaults).

Neighbor **switch** naming for heuristics follows the same authority as the audit row:
OpenStack/Ironic runtime (``local_link`` / ``os_lldp``) first; MAAS commissioning LLDP
switch name when OS does not supply one. MAAS VLAN name remains a further fallback for
peer-style naming hints. Report columns are grouped **MAAS** (incl. ``MAAS LLDP switch``),
then **OS** (``OS LLDP switch`` and runtime MAC/IP/VLAN), then **NetBox** / suggested name,
then **Authority** and **Proposed Action** (and **Reason** on new-NIC rows). Combined logic
uses OS-then-MAAS only for derivations (label, mgmt/data hints, etc.).
"""

from __future__ import annotations

import re
from typing import Any

# Authority column (0-based) for NIC drift vs new-NIC tables (headers differ).
# Drift: ``Reason`` after ``Proposed Action``. New NICs: ``Authority`` then ``Proposed Action`` then ``Reason``.
NIC_DRIFT_AUTHORITY_COL_INDEX = 24  # HEADERS_DETAIL_NIC_DRIFT
NIC_NEW_AUTHORITY_COL_INDEX = 20  # HEADERS_DETAIL_NEW_NICS (Authority before Proposed Action)
# "OS MAC" column (same index in new-NIC and NIC-drift detail tables).
NIC_OS_MAC_COL_INDEX = 12


def nic_row_os_mac_is_present(row: Any) -> bool:
    """
    True when the row's OS MAC cell holds a normalized 6-octet Ethernet address.
    Placeholders (—, -, _, n/a, none) and non-MAC text are treated as absent.
    """
    if not isinstance(row, (list, tuple)) or len(row) <= NIC_OS_MAC_COL_INDEX:
        return False
    raw = str(row[NIC_OS_MAC_COL_INDEX] or "").strip()
    if not raw or raw.casefold() in {"—", "-", "_", "none", "n/a"}:
        return False
    s = raw.lower().replace("-", ":")
    parts = [p for p in s.split(":") if p]
    if len(parts) != 6:
        return False
    try:
        for p in parts:
            int(p, 16)
    except ValueError:
        return False
    return True

# Drift picker + default suggestions must match these strings exactly.
INTF_ROLE_PICKLIST = ("BMC", "Management", "Data", "GPU", "CPU")

# MAAS link_speed is typically Mb/s (e.g. 400000 -> 400 Gbps).
_SPEED_MBPS_TO_LABEL: tuple[tuple[int, str], ...] = (
    (4_000_000, "4 Tbps"),
    (400_000, "400 Gbps"),
    (200_000, "200 Gbps"),
    (100_000, "100 Gbps"),
    (56_000, "56 Gbps"),
    (50_000, "50 Gbps"),
    (40_000, "40 Gbps"),
    (25_000, "25 Gbps"),
    (10_000, "10 Gbps"),
    (2_500, "2.5 Gbps"),
    (1_000, "1 Gbps"),
    (100, "100 Mbps"),
)


def intf_role_catalog_values() -> list[str]:
    return list(INTF_ROLE_PICKLIST)


def _norm_mac(m: str) -> str:
    return str(m or "").strip().lower().replace("-", ":")


def _compact_alnum(s: str) -> str:
    return "".join(c for c in (s or "").lower() if c.isalnum())


def _switch_info_display_name(raw: str) -> str:
    """
    Strip Ironic/Neutron type label before the first colon (e.g. genericswitch:b1-r2-mgmt-3
    -> b1-r2-mgmt-3). Matches proposed_lldp_tables._fields_from_local_link switch name parsing.
    """
    s = (raw or "").strip()
    if not s:
        return ""
    if ":" in s:
        _, _, rest = s.partition(":")
        rest = rest.strip()
        if rest:
            return rest
    return s


def parse_os_lldp_structured(os_row: dict | None) -> dict[str, str]:
    """
    OS runtime row -> clean neighbor switch name and remote port (no decorative text).

    ``local_link.switch_info`` may combine type prefix with hostname; ``port_id`` is the
    Neighbor port id when Ironic exposes it. ``os_lldp`` string may contain ``port …`` segments.
    """
    out = {"switch": "", "port": ""}
    if not os_row or not isinstance(os_row, dict):
        return out
    ll = os_row.get("local_link")
    if isinstance(ll, dict):
        si = str(ll.get("switch_info") or "").strip()
        if si:
            out["switch"] = _switch_info_display_name(si)[:200]
        pid = str(ll.get("port_id") or ll.get("switch_port_id") or "").strip()
        if pid:
            out["port"] = pid[:200]
    if not out["port"]:
        osl = str(os_row.get("os_lldp") or "").strip()
        if osl:
            for segment in osl.split(" · "):
                seg = segment.strip()
                low = seg.lower()
                if low.startswith("port "):
                    out["port"] = seg[5:].strip()[:200]
                    break
    return out


def format_os_switch_cell(os_row: dict | None) -> str:
    """Backward-compatible single cell: neighbor switch name only (no port suffix)."""
    sw = parse_os_lldp_structured(os_row).get("switch") or ""
    return sw[:160] if sw else "—"


def _switch_info_hints(switch_text: str) -> tuple[bool, bool]:
    """Returns (mgmt-ish, data-ish) from switch_info / LLDP text."""
    t = (switch_text or "").lower()
    if not t or t == "—":
        return False, False
    mgmt = any(
        x in t
        for x in ("-mgmt", "mgmt-", "_mgmt", "management", "mgt-", "-mgt")
    )
    data = any(x in t for x in ("-data", "data-", "_data", "-leaf", "leaf-", "dataleaf"))
    return mgmt, data


def _effective_peer_switch_name(audit_row: dict) -> str:
    """
    Single switch name for NB proposed intf Label and related heuristics.

    OpenStack runtime is authoritative: use ``os_lldp_switch`` / ``os_switch_info`` when
    present. MAAS ``maas_lldp_switch`` is the fallback when OS has no neighbor name.
    (Does not merge strings; first non-empty wins.)
    """
    for k in ("os_lldp_switch", "os_switch_info", "maas_lldp_switch"):
        v = str(audit_row.get(k) or "").strip()
        if v and v != "—":
            return v
    return ""


def _peer_label_haystack(switch_txt: str, vlan_name: str) -> str:
    """Prefer resolved switch text; fall back to MAAS VLAN name when switch is unknown."""
    sw = (switch_txt or "").strip()
    if sw and sw != "—":
        return sw.lower()
    return (vlan_name or "").strip().lower()


def _label_data_gpu_from_peer_naming(haystack: str) -> str | None:
    """
    If peer naming contains ``data`` → Data; if ``leaf`` without ``data`` → GPU.
    Otherwise None (caller uses speed / product heuristics).
    """
    h = (haystack or "").strip().lower()
    if not h:
        return None
    if "data" in h:
        return "Data"
    if "leaf" in h:
        return "GPU"
    return None


def _maas_nic_model(vendor: str, product: str) -> str:
    v = (vendor or "").strip()
    p = (product or "").strip()
    if v and v not in ("—", "-") and p and p not in ("—", "-"):
        return f"{v[:32]} / {p[:64]}"
    if p and p not in ("—", "-"):
        return p[:96]
    if v and v not in ("—", "-"):
        return v[:96]
    return "—"


def _link_speed_int(raw: Any) -> int | None:
    try:
        n = int(str(raw).strip())
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


def _mbps_from_parsed(value: float, unit: str) -> int | None:
    u = (unit or "").lower()
    if u in ("t", "tb", "tbps"):
        return int(round(value * 1_000_000))
    if u in ("g", "gb", "gbps"):
        return int(round(value * 1_000))
    if u in ("m", "mb", "mbps"):
        return int(round(value))
    if u in ("k", "kb", "kbps"):
        return int(round(value / 1_000))
    return None


def _label_for_mbps_int(n: int) -> str:
    if n <= 0:
        return "0 Mbps"
    for threshold, label in _SPEED_MBPS_TO_LABEL:
        if n == threshold:
            return label
    if n >= 1_000_000 and n % 1_000_000 == 0:
        return f"{n // 1_000_000} Tbps"
    if n >= 1_000 and n % 1_000 == 0:
        return f"{n // 1_000} Gbps"
    return f"{n} Mbps"


def format_link_speed_display(raw: Any) -> str:
    """
    Human-readable link speed for drift tables.

    - MAAS numeric values are treated as Mb/s.
    - Strings like ``400 Gbps``, ``10GBPS``, ``0 MBPS`` are normalized.
    """
    if raw is None:
        return "—"
    if isinstance(raw, (int, float)):
        n = int(raw)
        return _label_for_mbps_int(n)
    s = str(raw).strip()
    if not s or s in ("—", "-") or s.lower() in ("none", "null", "unknown"):
        return "—"
    if re.fullmatch(r"-?\d+", s):
        return _label_for_mbps_int(int(s))
    comp = s.lower().replace(" ", "")
    m = re.fullmatch(
        r"([0-9]+(?:\.[0-9]+)?)(tbps?|gbps?|mbps?|kbps?|t|g|m|k|b/s|/s)?",
        comp,
    )
    if m:
        val = float(m.group(1))
        u = (m.group(2) or "m").lower()
        u = u.replace("bps", "").replace("/s", "").replace("b", "")
        mbps = _mbps_from_parsed(val, u)
        if mbps is not None:
            return _label_for_mbps_int(mbps)
    return s[:64]


def _suggest_type_slug(
    link_mbps: int | None,
    product: str,
) -> str:
    p = _compact_alnum(product)
    if "10gbase-t" in p:
        return "10gbase-t"
    if "1000base-t" in p or "1gbase-t" in p:
        return "1000base-t"
    if link_mbps == 10_000:
        return "10gbase-t"
    if link_mbps == 1_000:
        return "1000base-t"
    if link_mbps is not None and link_mbps >= 100_000:
        if "connectx7" in p or "mt2910" in p:
            return "400gbase-x-osfp"
        return "100gbase-x-qsfp28"
    return ""


def _disp(v: str) -> str:
    s = (v or "").strip()
    return s if s else "—"


def derive_nic_proposed_columns(
    hostname: str,
    audit_row: dict,
    *,
    bmc_mac: str = "",
) -> dict[str, str]:
    """Display strings for drift NIC table columns from one interface_audit row dict."""
    hn = (hostname or "").strip().lower()
    product = str(audit_row.get("maas_nic_product") or "")
    vendor = str(audit_row.get("maas_nic_vendor") or "")
    vlan_name = str(audit_row.get("maas_vlan_name") or "").lower()
    ls_raw = audit_row.get("maas_link_speed")
    ls = _link_speed_int(ls_raw)
    mac = _norm_mac(str(audit_row.get("maas_mac") or ""))

    # Table cells: OS vs MAAS sources shown separately.
    os_sw = _disp(str(audit_row.get("os_lldp_switch") or "").strip() or audit_row.get("os_switch_info") or "")
    maas_sw = _disp(str(audit_row.get("maas_lldp_switch") or ""))

    maas_link_disp = format_link_speed_display(ls_raw)
    nic_model = _maas_nic_model(vendor, product)

    pl = product.lower()
    gpu_product = "gpu" in pl or "nvidia" in pl and "t4" in pl or "a100" in pl or "h100" in pl
    gpu_host = "gpu" in hn

    # Label / mgmt-data heuristics: OS neighbor name first, else MAAS LLDP switch.
    peer_switch = _effective_peer_switch_name(audit_row)
    mgmt_sw, data_sw = _switch_info_hints(peer_switch)

    label = ""
    if bmc_mac and mac and _norm_mac(bmc_mac) == mac:
        label = "BMC"
    elif mgmt_sw or "management" in vlan_name:
        label = "Management"
    elif (peer_lbl := _label_data_gpu_from_peer_naming(
        _peer_label_haystack(peer_switch, vlan_name)
    )):
        label = peer_lbl
    elif data_sw:
        if (gpu_product or gpu_host) and ls is not None and ls >= 100_000:
            label = "GPU"
        else:
            label = "Data"
    elif ls == 10_000 or "10gbase-t" in _compact_alnum(product):
        label = "Management"
    elif ls is not None and ls >= 100_000:
        if gpu_product or gpu_host:
            label = "GPU"
        else:
            label = "Data"
    elif "cpu" in hn:
        label = "CPU"

    type_slug = _suggest_type_slug(ls, product)

    return {
        "maas_link_speed_disp": maas_link_disp,
        "os_lldp_switch_disp": os_sw,
        "maas_lldp_switch_disp": maas_sw,
        "os_switch_disp": os_sw,
        "maas_nic_model": nic_model,
        "nb_proposed_intf_label": label,
        "nb_proposed_intf_type": type_slug,
    }


def bmc_row_proposed_defaults(_machine: dict | None) -> dict[str, str]:
    """Defaults for BMC / OOB drift table columns (label/type/LLDP display helpers)."""
    from netbox_automation_plugin.sync.reconciliation.netbox_interface_types import (
        netbox_oob_interface_type_when_unknown_slug,
    )

    return {
        "os_lldp_switch_disp": "—",
        "maas_lldp_switch_disp": "—",
        "os_switch_disp": "—",
        "maas_nic_model": "—",
        "nb_proposed_intf_label": "BMC",
        "nb_proposed_intf_type": netbox_oob_interface_type_when_unknown_slug(),
    }
