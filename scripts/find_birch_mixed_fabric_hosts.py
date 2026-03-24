#!/usr/bin/env python3
"""
Find MAAS hosts in Birch domain that have NICs on both Birch and Spruce fabrics.

Output: table with hostname, serial, NIC name, NIC MAC, and resolved NIC fabric.

Usage:
  export MAAS_URL='https://maas.example.com/MAAS'
  export MAAS_API_KEY='consumer:key:token'
  export MAAS_INSECURE=true

  python scripts/find_birch_mixed_fabric_hosts.py
  python scripts/find_birch_mixed_fabric_hosts.py --domain-keyword birch --fabric-a birch --fabric-b spruce
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from urllib.parse import urlparse


def _strtobool(v: str | None, default: bool = False) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _norm_url(base: str) -> str:
    b = (base or "").strip()
    if not b:
        return b
    if not re.match(r"^https?://", b):
        b = "http://" + b
    return b.rstrip("/")


def _json_request(session, url: str, *, verify_tls: bool):
    r = session.get(url, verify=verify_tls, timeout=120)
    ctype = (r.headers.get("content-type") or "").lower()
    if "json" in ctype:
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"_raw": r.text[:1000]}
    return r.status_code, {"_raw": r.text[:1000]}


def _pick_array(data) -> list[dict]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("results", "machines", "nodes"):
            arr = data.get(key)
            if isinstance(arr, list):
                return [x for x in arr if isinstance(x, dict)]
    return []


def _maas_auth_session(maas_api_key: str):
    try:
        import requests  # type: ignore
        from requests_oauthlib import OAuth1  # type: ignore
    except Exception as e:
        raise SystemExit(
            "Install dependencies first: pip install requests requests-oauthlib"
        ) from e

    parts = maas_api_key.split(":", 2)
    if len(parts) != 3:
        raise SystemExit(
            "MAAS_API_KEY must be consumer_secret:key:token (3 parts separated by ':')."
        )
    ck, tk, ts = parts[0], parts[1], parts[2]
    auth = OAuth1(ck, "", tk, ts, signature_method="PLAINTEXT")
    session = requests.Session()
    session.auth = auth
    session.headers.update({"Accept": "application/json"})
    return session


def _fabric_catalog(session, maas_url: str, verify_tls: bool) -> dict[str, str]:
    out: dict[str, str] = {}
    code, data = _json_request(session, f"{maas_url}/api/2.0/fabrics/", verify_tls=verify_tls)
    if code != 200:
        return out
    for item in _pick_array(data):
        fid = str(item.get("id") or "").strip()
        name = str(item.get("name") or "").strip()
        if fid and name:
            out[fid] = name
        if name:
            out[name.lower()] = name
    return out


def _fabric_id_from_url(maybe_url: str) -> str:
    text = (maybe_url or "").strip()
    if not text:
        return ""
    try:
        path = urlparse(text).path
    except Exception:
        path = text
    m = re.search(r"/fabrics/([^/]+)/?", path)
    return (m.group(1) if m else "").strip()


def _resolve_fabric_name(interface_row: dict, catalog: dict[str, str]) -> str:
    # MAAS may expose fabric on interface.fabric or vlan.fabric; values can be URL/name/dict.
    candidates = []
    raw_fab = interface_row.get("fabric")
    if raw_fab is not None:
        candidates.append(raw_fab)
    vlan = interface_row.get("vlan")
    if isinstance(vlan, dict) and vlan.get("fabric") is not None:
        candidates.append(vlan.get("fabric"))

    for raw in candidates:
        if isinstance(raw, dict):
            nm = str(raw.get("name") or "").strip()
            if nm:
                return nm
            raw = raw.get("id") or ""
        txt = str(raw or "").strip()
        if not txt:
            continue
        # Direct named fabric.
        if txt.lower() in catalog:
            return catalog[txt.lower()]
        # Numeric id.
        if txt in catalog:
            return catalog[txt]
        # URL containing fabric id.
        fid = _fabric_id_from_url(txt)
        if fid and fid in catalog:
            return catalog[fid]
        # Fall back to raw text for visibility.
        return txt
    return "-"


def _machine_detail(session, maas_url: str, verify_tls: bool, system_id: str) -> dict:
    for url in (
        f"{maas_url}/api/2.0/machines/{system_id}/",
        f"{maas_url}/api/2.0/nodes/{system_id}/",
    ):
        code, data = _json_request(session, url, verify_tls=verify_tls)
        if code == 200 and isinstance(data, dict):
            return data
    return {}


def _machine_interfaces(session, maas_url: str, verify_tls: bool, system_id: str) -> list[dict]:
    for url in (
        f"{maas_url}/api/2.0/machines/{system_id}/interfaces/",
        f"{maas_url}/api/2.0/nodes/{system_id}/interfaces/",
    ):
        code, data = _json_request(session, url, verify_tls=verify_tls)
        if code == 200 and isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if code == 200 and isinstance(data, dict) and isinstance(data.get("interfaces"), list):
            return [x for x in data["interfaces"] if isinstance(x, dict)]
    return []


def _domain_name(machine_detail: dict) -> str:
    dom = machine_detail.get("domain")
    if isinstance(dom, dict):
        return str(dom.get("name") or "").strip()
    return str(dom or "").strip()


def _serial(machine_detail: dict) -> str:
    direct = str(machine_detail.get("serial") or machine_detail.get("serial_number") or "").strip()
    if direct:
        return direct
    hw = machine_detail.get("hardware_info")
    if isinstance(hw, dict):
        s = str(hw.get("system_serial") or hw.get("serial") or "").strip()
        if s:
            return s
    return "-"


def _print_table(rows: list[dict]) -> None:
    headers = ["HOSTNAME", "SYSTEM_ID", "DOMAIN", "SERIAL", "NIC", "NIC_MAC", "FABRIC"]
    if not rows:
        print("No matching hosts found.")
        return
    widths = {h: len(h) for h in headers}
    for r in rows:
        for h in headers:
            widths[h] = max(widths[h], len(str(r.get(h, ""))))

    def fmt(row: dict) -> str:
        return "  ".join(str(row.get(h, "")).ljust(widths[h]) for h in headers)

    print(fmt({h: h for h in headers}))
    print("  ".join("-" * widths[h] for h in headers))
    for r in rows:
        print(fmt(r))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Show Birch-domain MAAS hosts that have at least one Birch NIC fabric and "
            "at least one Spruce NIC fabric."
        )
    )
    ap.add_argument("--url", default=os.getenv("MAAS_URL", ""), help="MAAS base URL")
    ap.add_argument("--api-key", default=os.getenv("MAAS_API_KEY", ""), help="MAAS API key")
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    ap.add_argument("--verify-tls", action="store_true", help="Force TLS verification")
    ap.add_argument("--domain-keyword", default="birch", help="Domain keyword filter (default: birch)")
    ap.add_argument("--fabric-a", default="birch", help="Required fabric A keyword (default: birch)")
    ap.add_argument("--fabric-b", default="spruce", help="Required fabric B keyword (default: spruce)")
    ap.add_argument("--limit", type=int, default=0, help="Optional max hosts to inspect (0 = all)")
    args = ap.parse_args()

    maas_url = _norm_url(args.url)
    api_key = (args.api_key or "").strip()
    if not maas_url or not api_key:
        print("ERROR: MAAS_URL and MAAS_API_KEY are required (env or args).")
        return 2

    verify_tls = True
    if args.insecure:
        verify_tls = False
    elif _strtobool(os.getenv("MAAS_INSECURE"), default=False):
        verify_tls = False
    if args.verify_tls:
        verify_tls = True

    session = _maas_auth_session(api_key)
    code, body = _json_request(session, f"{maas_url}/api/2.0/machines/", verify_tls=verify_tls)
    if code >= 400:
        print(f"ERROR: GET machines failed HTTP {code}")
        return 1
    machines = _pick_array(body)
    if args.limit > 0:
        machines = machines[: args.limit]

    fabric_cat = _fabric_catalog(session, maas_url, verify_tls)
    domain_kw = args.domain_keyword.strip().lower()
    fab_a = args.fabric_a.strip().lower()
    fab_b = args.fabric_b.strip().lower()

    out_rows: list[dict] = []
    matching_hosts = 0

    for m in machines:
        sid = str(m.get("system_id") or "").strip()
        host = str(m.get("hostname") or m.get("fqdn") or "").strip()
        if not sid or not host:
            continue

        md = _machine_detail(session, maas_url, verify_tls, sid)
        if not md:
            continue
        domain = _domain_name(md)
        if domain_kw and domain_kw not in domain.lower():
            continue

        ifaces = _machine_interfaces(session, maas_url, verify_tls, sid)
        nic_rows = []
        host_fabrics = set()
        for i in ifaces:
            mac = str(i.get("mac_address") or i.get("mac") or "").strip().lower()
            if not mac:
                continue
            fab = _resolve_fabric_name(i, fabric_cat)
            host_fabrics.add(fab.lower())
            nic_rows.append(
                {
                    "HOSTNAME": host,
                    "SYSTEM_ID": sid,
                    "DOMAIN": domain or "-",
                    "SERIAL": _serial(md),
                    "NIC": str(i.get("name") or "-"),
                    "NIC_MAC": mac,
                    "FABRIC": fab or "-",
                }
            )

        if not nic_rows:
            continue
        has_a = any(fab_a in f for f in host_fabrics)
        has_b = any(fab_b in f for f in host_fabrics)
        if not (has_a and has_b):
            continue

        matching_hosts += 1
        out_rows.extend(nic_rows)

    print(f"Scanned machines: {len(machines)}")
    print(f"TLS verify: {verify_tls}")
    print(f"Matched hosts (domain~{domain_kw}, fabrics include {fab_a} + {fab_b}): {matching_hosts}")
    print()
    _print_table(out_rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())

