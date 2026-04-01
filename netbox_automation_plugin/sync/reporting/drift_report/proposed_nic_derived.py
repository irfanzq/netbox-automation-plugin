"""
Heuristic NB proposed intf Label / Type for drift NIC tables (review defaults).

Sources: MAAS link_speed, vendor, product, vlan name; OpenStack runtime link_speed;
local_link.switch_info; host/BMC MAC correlation. Operators override via drift pickers.
"""

from __future__ import annotations

import re
from typing import Any

# Column indices (0-based) after MAAS VLAN + link/OS context columns; used by proposed_changes.
NIC_DRIFT_AUTHORITY_COL_INDEX = 14
# add_nb row: Authority after OS VLAN (MAAS link/OS link/LLDP/NIC model + OS cols).
NIC_NEW_AUTHORITY_COL_INDEX = 16

# Drift picker + default suggestions must match these strings exactly.
INTF_ROLE_PICKLIST = ("BMC", "Management", "DATA", "GPU", "CPU")

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


def format_os_switch_cell(os_row: dict | None) -> str:
    if not os_row:
        return "—"
    ll = os_row.get("local_link")
    if isinstance(ll, dict):
        si = str(ll.get("switch_info") or "").strip()
        if si:
            return si[:160]
    osl = str(os_row.get("os_lldp") or "").strip()
    return osl[:160] if osl else "—"


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


def maas_machine_best_link_speed_display(machine: dict | None) -> str:
    """Single display cell for BMC rows: best-effort max link_speed from any MAAS NIC."""
    best_raw: Any = None
    best_n = 0
    for mi in (machine or {}).get("interfaces") or []:
        if not isinstance(mi, dict):
            continue
        raw = mi.get("link_speed")
        if raw in (None, ""):
            raw = mi.get("speed")
        n = _link_speed_int(raw)
        if n and n > best_n:
            best_n = n
            best_raw = raw
        elif not n and raw not in (None, "") and not best_raw:
            best_raw = raw
    if best_raw is None:
        return "—"
    return format_link_speed_display(best_raw)


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
    switch_txt = str(audit_row.get("os_switch_info") or "")
    ls_raw = audit_row.get("maas_link_speed")
    ls = _link_speed_int(ls_raw)
    mac = _norm_mac(str(audit_row.get("maas_mac") or ""))

    maas_link_disp = format_link_speed_display(ls_raw)
    os_ls_raw = audit_row.get("os_link_speed_raw")
    os_link_disp = format_link_speed_display(os_ls_raw) if os_ls_raw not in (None, "") else "—"
    os_sw = switch_txt if switch_txt.strip() else "—"
    nic_model = _maas_nic_model(vendor, product)

    pl = product.lower()
    gpu_product = "gpu" in pl or "nvidia" in pl and "t4" in pl or "a100" in pl or "h100" in pl
    gpu_host = "gpu" in hn

    mgmt_sw, data_sw = _switch_info_hints(os_sw)

    label = ""
    if bmc_mac and mac and _norm_mac(bmc_mac) == mac:
        label = "BMC"
    elif mgmt_sw or "management" in vlan_name:
        label = "Management"
    elif data_sw:
        if (gpu_product or gpu_host) and ls is not None and ls >= 100_000:
            label = "GPU"
        else:
            label = "DATA"
    elif ls == 10_000 or "10gbase-t" in _compact_alnum(product):
        label = "Management"
    elif ls is not None and ls >= 100_000:
        if gpu_product or gpu_host:
            label = "GPU"
        else:
            label = "DATA"
    elif "cpu" in hn:
        label = "CPU"

    type_slug = _suggest_type_slug(ls, product)

    return {
        "maas_link_speed_disp": maas_link_disp,
        "os_link_speed_disp": os_link_disp,
        "os_switch_disp": os_sw,
        "maas_nic_model": nic_model,
        "nb_proposed_intf_label": label,
        "nb_proposed_intf_type": type_slug,
    }


def bmc_row_proposed_defaults(machine: dict | None) -> dict[str, str]:
    """Defaults for BMC / OOB tables; MAAS link speed from any host NIC when present."""
    return {
        "maas_link_speed_disp": maas_machine_best_link_speed_display(machine),
        "os_link_speed_disp": "—",
        "os_switch_disp": "—",
        "maas_nic_model": "—",
        "nb_proposed_intf_label": "BMC",
        "nb_proposed_intf_type": "other",
    }
