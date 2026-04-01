#!/usr/bin/env python3
"""
Dump MAAS + OpenStack (Ironic/Neutron) data for one host to see what is available
for NIC Label / MTU / Type and simple derivation heuristics (Data vs Mgmt, BMC, GPU, etc.).

Heuristic labels from MAAS link_speed (Mb/s): 10000 -> 10GE -> Management-ish;
100000+ (100GE/200GE/400GE) -> Data-ish.
From MAAS interface product string: e.g. "10GBASE-T" -> Management-ish (10G copper class);
"Ethernet Controller" alone is not used (too generic).
From MAAS vlan.name on the NIC (e.g. "Birch Management Default"): substring "management" -> Management-ish.
suggested_netbox_interface_type: NetBox dcim.Interface type slug from product (e.g. 10gbase-t for 10GBASE-T);
use InterfaceTypeChoices in Django code with the same value. Adjust in-script if your site differs.

Uses the same environment variables as the NetBox plugin and other scripts in this folder:

  MAAS (required for MAAS section):
    MAAS_URL              e.g. https://maas.example.com/MAAS
    MAAS_API_KEY          consumer:key:secret
    MAAS_INSECURE         true|false  (skip TLS verify; same as plugin default)

  OpenStack (required for live OpenStack section — same as list_openstack_hosts_and_nodes.py):
    OS_AUTH_URL or OPENSTACK_AUTH_URL
    OS_USERNAME / OS_PASSWORD  OR  application credential ID/secret
    OS_PROJECT_NAME or OS_PROJECT_ID  (password auth needs a scoped project)
    OS_USER_DOMAIN_NAME, OS_PROJECT_DOMAIN_NAME (often Default)
    OS_REGION_NAME or OPENSTACK_REGION_NAME
    OPENSTACK_INSECURE=true  (optional, skip TLS verify)

  Optional:
    OPENSTACK_AUDIT_ALL_PROJECTS, OPENSTACK_PROJECT_ALLOWLIST  (multi-project scan; plugin parity)

Usage (from repo root netbox-automation-plugin/):

  export MAAS_URL='...' MAAS_API_KEY='...' MAAS_INSECURE=true
  export OS_AUTH_URL='...' OS_USERNAME='...' OS_PASSWORD='...' OS_PROJECT_NAME=admin ...

  python scripts/inspect_maas_os_nic_metadata.py
  python scripts/inspect_maas_os_nic_metadata.py --hostname b1-r3-gpu-1
  python scripts/inspect_maas_os_nic_metadata.py --no-openstack
  python scripts/inspect_maas_os_nic_metadata.py --no-maas --openstack-json drift_os.json
  python scripts/inspect_maas_os_nic_metadata.py --raw-maas-interfaces   # full MAAS iface JSON

MAAS interfaces: the script merges (1) GET .../machines/{id}/interfaces/ (and /nodes/.../interfaces/)
with (2) interface_set on the machine detail JSON. Embedded detail alone often omits NICs (e.g. some
GPU hosts); the list endpoint is usually complete.

Dependencies: pip install requests requests-oauthlib openstacksdk
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import types
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]

# --- env helpers (match scripts/list_openstack_hosts_and_nodes.py) ---


def _strtobool(v: str | None, default: bool = False) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _env(*keys: str, default: str = "") -> str:
    for k in keys:
        v = os.environ.get(k)
        if v:
            return v.strip()
    return default


def _normalize_auth_url(auth_url: str) -> str:
    auth_url = (auth_url or "").rstrip("/")
    if auth_url and not auth_url.endswith("/v3"):
        auth_url = auth_url + "/v3"
    return auth_url


def _openstack_config_from_env() -> dict[str, Any]:
    region = _env("OS_REGION_NAME", "OPENSTACK_REGION_NAME") or "birch"
    audit = _strtobool(_env("OPENSTACK_AUDIT_ALL_PROJECTS"), default=False)
    allow_raw = _env("OPENSTACK_PROJECT_ALLOWLIST")
    allowlist = [p.strip() for p in allow_raw.split(",") if p.strip()] if allow_raw else []
    return {
        "openstack_auth_url": _env("OPENSTACK_AUTH_URL", "OS_AUTH_URL"),
        "openstack_username": _env("OPENSTACK_USERNAME", "OS_USERNAME"),
        "openstack_password": _env("OPENSTACK_PASSWORD", "OS_PASSWORD"),
        "openstack_project_name": _env("OPENSTACK_PROJECT_NAME", "OS_PROJECT_NAME"),
        "openstack_project_id": _env("OPENSTACK_PROJECT_ID", "OS_PROJECT_ID"),
        "openstack_region_name": region,
        "openstack_interface": _env("OPENSTACK_INTERFACE", "OS_INTERFACE", default="public"),
        "openstack_user_domain_name": _env(
            "OPENSTACK_USER_DOMAIN_NAME", "OS_USER_DOMAIN_NAME", default="Default"
        ),
        "openstack_project_domain_name": _env(
            "OPENSTACK_PROJECT_DOMAIN_NAME", "OS_PROJECT_DOMAIN_NAME", default="Default"
        ),
        "openstack_application_credential_id": _env(
            "OPENSTACK_APPLICATION_CREDENTIAL_ID", "OS_APPLICATION_CREDENTIAL_ID"
        ),
        "openstack_application_credential_secret": _env(
            "OPENSTACK_APPLICATION_CREDENTIAL_SECRET", "OS_APPLICATION_CREDENTIAL_SECRET"
        ),
        "openstack_insecure": _strtobool(_env("OPENSTACK_INSECURE", default="false"), default=False),
        "openstack_audit_all_projects": audit,
        "openstack_project_allowlist": allowlist,
    }


def _import_fetch_openstack_data_for_config():
    """
    Load plugin openstack_client without importing netbox_automation_plugin/__init__.py
    (that pulls Django / netbox.plugins).
    """
    import importlib.util

    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))

    def _ensure_pkg(name: str, path: Path) -> None:
        if name in sys.modules:
            return
        m = types.ModuleType(name)
        m.__path__ = [str(path)]
        sys.modules[name] = m

    _ensure_pkg("netbox_automation_plugin", _REPO_ROOT / "netbox_automation_plugin")
    _ensure_pkg("netbox_automation_plugin.sync", _REPO_ROOT / "netbox_automation_plugin" / "sync")
    _ensure_pkg(
        "netbox_automation_plugin.sync.config",
        _REPO_ROOT / "netbox_automation_plugin" / "sync" / "config",
    )
    _ensure_pkg(
        "netbox_automation_plugin.sync.clients",
        _REPO_ROOT / "netbox_automation_plugin" / "sync" / "clients",
    )

    st_name = "netbox_automation_plugin.sync.config.settings"
    if st_name not in sys.modules:
        st = types.ModuleType(st_name)
        st.OPENSTACK_DEFAULT_REGION_NAME = _env("OS_REGION_NAME", "OPENSTACK_REGION_NAME") or "birch"
        sys.modules[st_name] = st

    mod_path = _REPO_ROOT / "netbox_automation_plugin/sync/clients/openstack_client.py"
    spec = importlib.util.spec_from_file_location(
        "netbox_automation_plugin.sync.clients.openstack_client",
        mod_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load openstack_client from {mod_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["netbox_automation_plugin.sync.clients.openstack_client"] = mod
    spec.loader.exec_module(mod)
    return mod.fetch_openstack_data_for_config


# --- MAAS REST ---


def _normalize_maas_base(maas_url: str) -> str:
    base = (maas_url or "").rstrip("/")
    if not base.lower().endswith("maas"):
        base = base + "/MAAS" if "/MAAS" not in base.upper() else base
    return base


def _maas_session(maas_api_key: str):
    try:
        import requests
        from requests_oauthlib import OAuth1
    except ImportError as e:
        raise SystemExit("Install: pip install requests requests-oauthlib") from e
    parts = maas_api_key.split(":", 2)
    if len(parts) != 3:
        raise SystemExit("MAAS_API_KEY must be consumer:key:token (3 colon-separated parts).")
    ck, tk, ts = parts[0], parts[1], parts[2]
    auth = OAuth1(ck, "", tk, ts, signature_method="PLAINTEXT")
    session = requests.Session()
    session.auth = auth
    return session


def _short_hostname(h: str) -> str:
    return (h or "").strip().split(".", 1)[0].lower()


def _normalize_mac(m: str) -> str:
    return str(m or "").strip().lower().replace("-", ":")


def _maas_embedded_interfaces(machine: dict) -> list[dict]:
    if not isinstance(machine, dict):
        return []
    for key in ("interface_set", "interfaces", "network_interfaces"):
        arr = machine.get(key)
        if isinstance(arr, list) and arr:
            return [x for x in arr if isinstance(x, dict)]
    return []


def _fetch_maas_interfaces_rest_list(sess, base: str, system_id: str, verify_tls: bool) -> list[dict]:
    """
    Full interface list from MAAS REST (often more complete than machine.interface_set alone).
    """
    out: list[dict] = []
    for url in (
        f"{base}/api/2.0/machines/{system_id}/interfaces/",
        f"{base}/api/2.0/nodes/{system_id}/interfaces/",
    ):
        try:
            r = sess.get(url, verify=verify_tls, timeout=90)
            if r.status_code in (404,):
                continue
            if r.status_code != 200:
                continue
            data = r.json()
            if isinstance(data, list) and data:
                out = [x for x in data if isinstance(x, dict)]
                if out:
                    return out
            if isinstance(data, dict):
                for k in ("interfaces", "interface_set", "results"):
                    arr = data.get(k)
                    if isinstance(arr, list) and arr:
                        cand = [x for x in arr if isinstance(x, dict)]
                        if cand:
                            return cand
        except Exception:
            continue
    return out


def _iface_merge_key(iface: dict) -> tuple:
    mac = _normalize_mac(str(iface.get("mac_address") or iface.get("mac") or iface.get("hwaddr") or ""))
    if mac:
        return ("mac", mac)
    iid = iface.get("id")
    if iid is not None and str(iid).strip() != "":
        return ("id", str(iid))
    name = str(iface.get("name") or "").strip().lower()
    return ("name", name or "_noname_")


def _merge_two_iface(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        cur = out.get(k)
        if cur in (None, "", []):
            out[k] = v
    return out


def _merge_maas_interface_sources(rest_list: list, embedded: list) -> tuple[list[dict], str]:
    """
    Union REST list + embedded machine NICs. REST first preserves API order; embedded fills gaps.
    """
    by_key: dict[tuple, dict] = {}
    order: list[tuple] = []

    def ingest(lst: list) -> None:
        for iface in lst:
            if not isinstance(iface, dict):
                continue
            k = _iface_merge_key(iface)
            if k not in by_key:
                by_key[k] = dict(iface)
                order.append(k)
            else:
                by_key[k] = _merge_two_iface(by_key[k], iface)

    ingest(rest_list)
    ingest(embedded)
    merged = [by_key[k] for k in order]
    note = (
        f"REST list={len(rest_list)}, embedded={len(embedded)}, unique_after_merge={len(merged)}"
    )
    return merged, note


# MAAS link_speed is typically Mb/s (e.g. 400000 -> 400 Gbps link training)
_SPEED_MBPS_TO_LABEL: tuple[tuple[int, str], ...] = (
    (4_000_000, "4T"),
    (400_000, "400GE"),
    (200_000, "200GE"),
    (100_000, "100GE"),
    (56_000, "56G"),
    (50_000, "50GE"),
    (40_000, "40GE"),
    (25_000, "25GE"),
    (10_000, "10GE"),
    (2_500, "2.5GE"),
    (1_000, "1GE"),
    (100, "100M"),
)


def link_speed_mbps_to_phy_label(mbps_val: Any) -> str:
    try:
        n = int(mbps_val)
    except (TypeError, ValueError):
        return ""
    if n <= 0:
        return ""
    for threshold, label in _SPEED_MBPS_TO_LABEL:
        if n == threshold:
            return label
    if n >= 1_000 and n % 1_000 == 0:
        return f"{n // 1_000}G"
    return f"{n}Mbps"


def _heuristic_data_from_link_speed(mbps_val: Any) -> bool:
    """Treat 100GE+ as typical data-plane speeds; heuristic only."""
    try:
        n = int(mbps_val)
    except (TypeError, ValueError):
        return False
    return n >= 100_000


def _heuristic_management_from_link_speed(mbps_val: Any) -> bool:
    """10 Gb/s link (MAAS link_speed 10000) often maps to management in this environment."""
    try:
        n = int(mbps_val)
    except (TypeError, ValueError):
        return False
    return n == 10_000


def _maas_vlan_name(iface: dict) -> str:
    vlan = iface.get("vlan")
    if isinstance(vlan, dict):
        return str(vlan.get("name") or "").strip()
    return ""


def _vlan_name_suggests_management(vlan_name: str) -> bool:
    n = (vlan_name or "").lower()
    return "management" in n


def _suggested_netbox_interface_type_slug(iface: dict) -> str:
    """
    NetBox Interface.type value (slug) when inferable from MAAS product text.
    See dcim.choices.InterfaceTypeChoices (e.g. TYPE_10GBASE_T -> '10gbase-t').
    Empty string when unknown — do not guess 10G optical vs copper from link_speed alone.
    """
    p = str(iface.get("product") or "").lower().replace(" ", "")
    if "10gbase-t" in p:
        return "10gbase-t"
    if "1000base-t" in p or "1gbase-t" in p:
        return "1000base-t"
    if "25gbase" in p or ("sfp28" in p and "25" in p):
        return "25gbase-x-sfp28"
    if "40gbase" in p or "qsfp+" in p:
        return "40gbase-x-qsfpp"
    if "100gbase" in p or ("qsfp28" in p and "100" in p):
        return "100gbase-x-qsfp28"
    return ""


def _product_string_management_tags(product: str) -> list[str]:
    """
    PCI/product description substrings that often indicate out-of-band or LOM-style
    management-class NICs in brownfield naming (heuristic only).
    """
    p = (product or "").lower()
    tags: list[str] = []
    if "10gbase-t" in p.replace(" ", ""):
        tags.append("10GBASE-T")
    if "1000base-t" in p.replace(" ", "") or "1gbase-t" in p.replace(" ", ""):
        tags.append("1000BASE-T")
    return tags


def _flatten_keys(obj: Any, prefix: str = "", depth: int = 0, max_depth: int = 4) -> list[str]:
    """Dot-path keys for debugging what MAAS exposes."""
    out: list[str] = []
    if depth > max_depth:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            out.append(p)
            out.extend(_flatten_keys(v, p, depth + 1, max_depth))
    elif isinstance(obj, list) and obj and depth < max_depth:
        for i, item in enumerate(obj[:5]):
            out.extend(_flatten_keys(item, f"{prefix}[{i}]", depth + 1, max_depth))
    return out


_INTERESTING_SUBSTR = (
    "mtu",
    "speed",
    "link",
    "type",
    "vendor",
    "product",
    "firmware",
    "model",
    "iface",
    "fabric",
    "vlan",
    "lldp",
    "neighbor",
    "bmc",
    "ipmi",
    "idrac",
)


def _interesting_paths(flat: list[str]) -> list[str]:
    hit = []
    for p in flat:
        pl = p.lower()
        if any(s in pl for s in _INTERESTING_SUBSTR):
            hit.append(p)
    return sorted(set(hit))


def _iface_quick_fields(iface: dict) -> dict[str, Any]:
    """Pull common MAAS interface fields if present (names vary by MAAS version)."""
    out: dict[str, Any] = {}
    keys = (
        "id",
        "name",
        "mac_address",
        "type",
        "enabled",
        "link_connected",
        "link_speed",
        "interface_speed",
        "numa_node",
        "vendor",
        "product",
        "firmware_version",
        "mtu",
        "effective_mtu",
    )
    for k in keys:
        if k in iface:
            out[k] = iface[k]
    vlan = iface.get("vlan")
    if isinstance(vlan, dict):
        out["vlan_vid"] = vlan.get("vid")
        out["vlan_name"] = vlan.get("name")
    phy = link_speed_mbps_to_phy_label(out.get("link_speed"))
    if phy:
        out["derived_phy_speed"] = phy
    pst = _product_string_management_tags(str(out.get("product") or ""))
    if pst:
        out["derived_product_mgmt_class"] = ", ".join(pst)
    nb_type = _suggested_netbox_interface_type_slug(iface)
    if nb_type:
        out["suggested_netbox_interface_type"] = nb_type
    return out


def _derive_nic_labels(
    short_host: str,
    machine: dict,
    iface: dict,
    os_row: dict | None,
) -> list[str]:
    labels: list[str] = []
    h = short_host.lower()
    if "gpu" in h:
        labels.append("host:GPU-in-name")
    if "cpu" in h:
        labels.append("host:CPU-in-name")

    mac = _normalize_mac(
        str(iface.get("mac_address") or iface.get("mac") or iface.get("hwaddr") or "")
    )
    bmc_mac = _normalize_mac(str(machine.get("bmc_mac") or ""))
    if mac and bmc_mac and mac == bmc_mac:
        labels.append("BMC-mac-match")

    iname = str(iface.get("name") or "").lower()
    if any(x in iname for x in ("ipmi", "bmc", "idrac", "ilo")):
        labels.append("iface-name-BMC-ish")

    ptype = str(machine.get("power_type") or "").lower()
    if "ipmi" in ptype:
        labels.append("machine:power_type-IPMI")
    if "redfish" in ptype or "idrac" in ptype:
        labels.append("machine:power_type-Redfish/iDRAC-ish")

    if os_row:
        phys = str(os_row.get("provider_physical_network") or "").lower()
        if "mgmt" in phys or "management" in phys:
            labels.append("OS:physical_network-mgmt-ish")
        if "data" in phys or "leaf" in phys:
            labels.append("OS:physical_network-data-ish")
        nt = str(os_row.get("network_type") or "").lower()
        if nt == "vlan" and (os_row.get("os_runtime_vlan") or "").strip():
            labels.append("OS:provider-VLAN")

    ls = iface.get("link_speed")
    phy = link_speed_mbps_to_phy_label(ls)
    if phy:
        labels.append(f"MAAS:PHY-{phy}")
    if _heuristic_management_from_link_speed(ls):
        labels.append("heuristic:Management-ish-from-link_speed(10GE)")
    elif _heuristic_data_from_link_speed(ls):
        labels.append("heuristic:Data-ish-from-link_speed(>=100GE)")

    product = str(iface.get("product") or "")
    for tag in _product_string_management_tags(product):
        labels.append(f"heuristic:Management-ish-from-product({tag})")

    vname = _maas_vlan_name(iface)
    if vname and _vlan_name_suggests_management(vname):
        labels.append("heuristic:Management-ish-from-MAAS-vlan_name")

    nb_slug = _suggested_netbox_interface_type_slug(iface)
    if nb_slug:
        labels.append(f"NetBox:interface_type_suggestion({nb_slug})")

    return sorted(set(labels))


def main() -> None:
    ap = argparse.ArgumentParser(description="Inspect MAAS + OpenStack NIC metadata for one host.")
    ap.add_argument("--hostname", default="b1-r3-gpu-1", help="Short hostname (matches MAAS before first dot)")
    ap.add_argument("--no-maas", action="store_true", help="Skip MAAS API calls")
    ap.add_argument("--no-openstack", action="store_true", help="Skip live OpenStack fetch")
    ap.add_argument(
        "--openstack-json",
        metavar="FILE",
        help="Load OpenStack payload from JSON file (keys: runtime_nics, runtime_bmc, error, …)",
    )
    ap.add_argument("--raw-maas-interfaces", action="store_true", help="Print full MAAS interface_set JSON")
    ap.add_argument("--verify-tls", action="store_true", help="Verify TLS even if MAAS_INSECURE=true")
    args = ap.parse_args()
    target = _short_hostname(args.hostname)
    maas_ifaces_merged: list[dict] | None = None

    print("=== Environment (secrets masked) ===")
    print(f"  MAAS_URL: {_env('MAAS_URL') or '(unset)'}")
    print(f"  MAAS_API_KEY: {'***' if _env('MAAS_API_KEY') else '(unset)'}")
    print(f"  MAAS_INSECURE: {_strtobool(_env('MAAS_INSECURE', default='false'), True)}")
    print(f"  OS_AUTH_URL: {_env('OS_AUTH_URL', 'OPENSTACK_AUTH_URL') or '(unset)'}")
    print(f"  OS_PROJECT_NAME: {_env('OS_PROJECT_NAME', 'OPENSTACK_PROJECT_NAME') or '(unset)'}")
    print(f"  OS_REGION_NAME: {_env('OS_REGION_NAME', 'OPENSTACK_REGION_NAME') or '(unset)'}")

    maas_machine: dict | None = None
    if not args.no_maas:
        maas_url = _env("MAAS_URL")
        maas_key = _env("MAAS_API_KEY")
        if not maas_url or not maas_key:
            print("\n[MAAS] Skipped: set MAAS_URL and MAAS_API_KEY")
        else:
            verify_tls = args.verify_tls or not _strtobool(_env("MAAS_INSECURE", default="true"), True)
            base = _normalize_maas_base(maas_url)
            sess = _maas_session(maas_key)
            print(f"\n=== MAAS: listing machines (filter client-side for hostname ~ {target!r}) ===")
            try:
                r = sess.get(f"{base}/api/2.0/machines/", verify=verify_tls, timeout=120)
                r.raise_for_status()
                machines = r.json()
            except Exception as e:
                print(f"[MAAS] list failed: {e}")
                machines = []

            if not isinstance(machines, list):
                machines = []

            def _host_matches(m: dict) -> bool:
                hn = _short_hostname(str(m.get("hostname") or ""))
                fq = _short_hostname(str(m.get("fqdn") or ""))
                return target in (hn, fq) or hn == target or fq == target

            hits = [m for m in machines if isinstance(m, dict) and _host_matches(m)]
            if not hits:
                print(f"[MAAS] No list match for {target!r}; trying hostname= query…")
                try:
                    r2 = sess.get(
                        f"{base}/api/2.0/machines/",
                        params={"hostname": args.hostname},
                        verify=verify_tls,
                        timeout=120,
                    )
                    if r2.ok:
                        data = r2.json()
                        if isinstance(data, list):
                            hits = [m for m in data if isinstance(m, dict) and _host_matches(m)]
                except Exception:
                    pass

            if not hits:
                print(f"[MAAS] No machine found for hostname {target!r} (check MAAS hostname/FQDN).")
            else:
                sid = str(hits[0].get("system_id") or "").strip()
                print(f"[MAAS] Matched system_id={sid!r} (showing detail fetch)")
                for path in (f"{base}/api/2.0/machines/{sid}/", f"{base}/api/2.0/nodes/{sid}/"):
                    try:
                        rd = sess.get(path, verify=verify_tls, timeout=90)
                        if rd.status_code == 200:
                            maas_machine = rd.json()
                            break
                    except Exception:
                        continue

            if isinstance(maas_machine, dict):
                sid_detail = str(
                    maas_machine.get("system_id") or (hits[0].get("system_id") if hits else "") or ""
                ).strip()
                print("\n=== MAAS: machine summary ===")
                for k in (
                    "hostname",
                    "fqdn",
                    "system_id",
                    "power_type",
                    "architecture",
                    "hardware_vendor",
                    "hardware_product",
                    "bmc_mac",
                    "bmc_ip",
                ):
                    if k in maas_machine and maas_machine[k] not in (None, ""):
                        print(f"  {k}: {maas_machine[k]}")

                embedded = _maas_embedded_interfaces(maas_machine)
                rest_list = (
                    _fetch_maas_interfaces_rest_list(sess, base, sid_detail, verify_tls)
                    if sid_detail
                    else []
                )
                ifaces, merge_note = _merge_maas_interface_sources(rest_list, embedded)
                maas_ifaces_merged = ifaces
                print(f"\n=== MAAS: interfaces ({len(ifaces)} rows) — {merge_note} ===")
                if len(rest_list) != len(embedded) and (rest_list or embedded):
                    print(
                        "  (Merged list = GET .../interfaces/ plus machine.interface_set; "
                        "use this list for full NIC coverage.)"
                    )
                for i, iface in enumerate(ifaces):
                    print(f"\n--- NIC {i + 1}: {iface.get('name')!r} ---")
                    qf = _iface_quick_fields(iface)
                    print("  quick_fields:", json.dumps(qf, indent=2, default=str))
                    flat = _interesting_paths(_flatten_keys(iface))
                    print("  interesting nested keys (sample):", ", ".join(flat[:40]) or "(none)")
                    if args.raw_maas_interfaces:
                        print("  raw:", json.dumps(iface, indent=2, default=str))

                print("\n=== MAAS: derivation hints (heuristic labels per NIC) ===")
                for i, iface in enumerate(ifaces):
                    name = iface.get("name")
                    labs = _derive_nic_labels(target, maas_machine, iface, None)
                    print(f"  {name!r}: {labs or ['(no heuristic hits)']}")

    # OpenStack
    os_payload: dict[str, Any] | None = None
    if args.openstack_json:
        p = Path(args.openstack_json)
        if not p.is_file():
            raise SystemExit(f"--openstack-json not found: {p}")
        os_payload = json.loads(p.read_text(encoding="utf-8"))
        print(f"\n=== OpenStack: loaded JSON {p} ===")
    elif not args.no_openstack:
        cfg = _openstack_config_from_env()
        if not (cfg.get("openstack_auth_url") or "").strip():
            print("\n[OpenStack] Skipped: set OS_AUTH_URL or OPENSTACK_AUTH_URL")
        else:
            print("\n=== OpenStack: fetch (plugin fetch_openstack_data_for_config) ===")
            try:
                fetch_fn = _import_fetch_openstack_data_for_config()
                os_payload = fetch_fn(cfg)
            except Exception as e:
                print(f"[OpenStack] import/fetch failed: {e}")
                os_payload = {"error": str(e), "runtime_nics": [], "runtime_bmc": []}

    if os_payload is not None:
        err = os_payload.get("error")
        if err:
            print(f"  error: {err}")
        nics = [r for r in (os_payload.get("runtime_nics") or []) if isinstance(r, dict)]
        bmc = [r for r in (os_payload.get("runtime_bmc") or []) if isinstance(r, dict)]
        host_nics = [r for r in nics if _short_hostname(str(r.get("hostname") or "")) == target]
        host_bmc = [r for r in bmc if _short_hostname(str(r.get("hostname") or "")) == target]

        print(f"\n=== OpenStack: runtime_nics for host {target!r} ({len(host_nics)} of {len(nics)} total) ===")
        for j, row in enumerate(host_nics):
            print(f"\n--- OS NIC {j + 1} ---")
            print(json.dumps(row, indent=2, default=str))

        print(f"\n=== OpenStack: runtime_bmc for host {target!r} ({len(host_bmc)} of {len(bmc)} total) ===")
        for j, row in enumerate(host_bmc):
            print(f"\n--- OS BMC {j + 1} ---")
            print(json.dumps(row, indent=2, default=str))

        # MTU: often on Neutron network / port — runtime_nics may not include it; say so
        print("\n=== Notes ===")
        print(
            "  Label / Data vs Mgmt: often policy; hints use MAAS link_speed, product (10GBASE-T), "
            "and vlan.name containing 'management' (e.g. Birch Management Default)."
        )
        print(
            "  suggested_netbox_interface_type in quick_fields is the NetBox Interface.type slug "
            "(API value); in Django use InterfaceTypeChoices with the same string, e.g. 10gbase-t."
        )
        print(
            "  MTU: check Neutron network + port APIs or host OS; plugin runtime_nics rows may omit mtu."
        )
        print(
            "  PHY Type (e.g. 400G): rarely on Neutron 'port type'; may need MAAS inventory, Redfish, or manual."
        )

        if isinstance(maas_machine, dict):
            ifaces = (
                maas_ifaces_merged
                if maas_ifaces_merged is not None
                else _maas_embedded_interfaces(maas_machine)
            )
            mac_os = {_normalize_mac(str(r.get("mac") or "")): r for r in host_nics}
            print("\n=== Combined: MAAS iface ↔ OS runtime row by MAC ===")
            for iface in ifaces:
                mac = _normalize_mac(
                    str(iface.get("mac_address") or iface.get("mac") or iface.get("hwaddr") or "")
                )
                os_row = mac_os.get(mac)
                labs = _derive_nic_labels(target, maas_machine, iface, os_row)
                print(f"  MAAS {iface.get('name')!r} mac={mac}: labels={labs}")
                if os_row:
                    print(f"    OS: physical_network={os_row.get('provider_physical_network')!r} "
                          f"vlan={os_row.get('os_runtime_vlan')!r} ips={os_row.get('os_ips')!r}")


if __name__ == "__main__":
    main()
