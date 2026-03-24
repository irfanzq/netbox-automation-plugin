#!/usr/bin/env python3
"""
Debug MAAS host scope logic used by MAAS/OpenStack Sync UI.

Purpose:
- Reproduce location/domain tie-break decisions from the UI workflow.
- Grep specific hosts (e.g. GPU hosts) and explain include/exclude reasons.

This script focuses on MAAS-side scope logic (where most confusion is happening).
It does not require NetBox DB access.

Usage:
  export MAAS_URL='https://maas.example.com/MAAS'
  export MAAS_API_KEY='consumer:key:token'
  export MAAS_INSECURE=true

  python scripts/debug_ui_scope_domain_logic.py \
    --locations "Spruce,Spruce v2,Staging" \
    --all-locations "Birch,Spruce,Spruce v2,Staging" \
    --grep "b1-r1-gpu"

  python scripts/debug_ui_scope_domain_logic.py \
    --locations "Birch" \
    --all-locations "Birch,Spruce,Spruce v2,Staging" \
    --grep "b1-r[13]-gpu"
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from urllib.parse import urlparse


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
        raise SystemExit("Install dependencies: pip install requests requests-oauthlib") from e

    parts = maas_api_key.split(":", 2)
    if len(parts) != 3:
        raise SystemExit("MAAS_API_KEY must be consumer_secret:key:token (3 parts).")
    ck, tk, ts = parts[0], parts[1], parts[2]
    auth = OAuth1(ck, "", tk, ts, signature_method="PLAINTEXT")
    session = requests.Session()
    session.auth = auth
    session.headers.update({"Accept": "application/json"})
    return session


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


def _resolve_fabric_name(interface_row: dict, catalog: dict[str, str]) -> str:
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
        if txt.lower() in catalog:
            return catalog[txt.lower()]
        if txt in catalog:
            return catalog[txt]
        fid = _fabric_id_from_url(txt)
        if fid and fid in catalog:
            return catalog[fid]
        return txt
    return "-"


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


def _short_hostname(name: str) -> str:
    return str(name or "").split(".", 1)[0].strip()


def _norm_tokens(s: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t}


def _fabric_matches_locations(fabric_name: str, selected_location_names: set[str]) -> bool:
    if not selected_location_names:
        return False
    fab = (fabric_name or "").strip().lower()
    if not fab:
        return False
    fab_compact = re.sub(r"[^a-z0-9]+", "", fab)
    fab_tokens = _norm_tokens(fab)
    for loc in selected_location_names:
        loc_l = (loc or "").strip().lower()
        if not loc_l:
            continue
        loc_compact = re.sub(r"[^a-z0-9]+", "", loc_l)
        loc_tokens = _norm_tokens(loc_l)
        if loc_compact and (loc_compact in fab_compact or fab_compact in loc_compact):
            return True
        if any(len(t) >= 4 and t in fab_tokens for t in loc_tokens):
            return True
    return False


def _text_matches_locations(text: str, selected_location_names: set[str]) -> bool:
    if not selected_location_names:
        return False
    src = (text or "").strip().lower()
    if not src:
        return False
    src_compact = re.sub(r"[^a-z0-9]+", "", src)
    src_tokens = _norm_tokens(src)
    for loc in selected_location_names:
        loc_l = (loc or "").strip().lower()
        if not loc_l:
            continue
        loc_compact = re.sub(r"[^a-z0-9]+", "", loc_l)
        loc_tokens = _norm_tokens(loc_l)
        if loc_compact and (loc_compact in src_compact or src_compact in loc_compact):
            return True
        if any(len(t) >= 4 and t in src_tokens for t in loc_tokens):
            return True
    return False


def _maas_effective_dns_name(m: dict) -> str:
    dns = (m.get("dns_name") or "").strip()
    if dns:
        return dns
    fqdn = (m.get("fqdn") or "").strip()
    if fqdn:
        return fqdn
    host = (m.get("hostname") or "").strip()
    dom = (m.get("domain_name") or m.get("domain") or "").strip()
    if host and dom and "." not in host:
        return f"{host}.{dom}"
    return ""


def _machine_fabrics(machine: dict) -> set[str]:
    out = set()
    base = (machine.get("fabric_name") or "").strip()
    if base and base != "-":
        out.add(base)
    for mi in machine.get("interfaces") or []:
        f = (mi.get("iface_fabric") or "").strip()
        if f and f != "-":
            out.add(f)
    return out


def _location_matches_machine_fabrics(location_name: str, machine: dict) -> bool:
    return any(_fabric_matches_locations(fab, {location_name}) for fab in _machine_fabrics(machine))


def _fqdn_location_hint(machine: dict, candidate_locations: set[str]) -> str:
    dns_text = _maas_effective_dns_name(machine)
    for loc in sorted(candidate_locations or set(), key=lambda x: (-len(x), x.lower())):
        if _text_matches_locations(dns_text, {loc}):
            return loc
    return ""


def _scoped_location_decision(
    machine: dict,
    selected_location_names: set[str],
    all_location_names: set[str],
) -> tuple[bool, str, dict]:
    debug = {}
    if not selected_location_names:
        return False, "", debug

    selected_hits = {
        loc for loc in selected_location_names
        if _location_matches_machine_fabrics(loc, machine)
    }
    debug["selected_hits"] = sorted(selected_hits)
    if not selected_hits:
        dns_match = _text_matches_locations(_maas_effective_dns_name(machine), selected_location_names)
        debug["dns_match_selected"] = dns_match
        return dns_match, "", debug

    other_hits = {
        loc for loc in (all_location_names - selected_location_names)
        if _location_matches_machine_fabrics(loc, machine)
    }
    debug["other_hits"] = sorted(other_hits)
    if not other_hits:
        chosen = sorted(selected_hits, key=lambda x: x.lower())[0]
        debug["hinted"] = chosen
        return True, chosen, debug

    hinted = _fqdn_location_hint(machine, selected_hits | other_hits)
    debug["hinted"] = hinted
    if hinted:
        return (hinted in selected_location_names), hinted, debug
    return False, "", debug


def _csv_set(value: str) -> set[str]:
    return {x.strip() for x in (value or "").split(",") if x.strip()}


def main() -> int:
    ap = argparse.ArgumentParser(description="Debug UI location/domain scope decisions for MAAS hosts.")
    ap.add_argument("--maas-url", default="", help="MAAS URL (else use MAAS_URL env)")
    ap.add_argument("--maas-api-key", default="", help="MAAS API key (else MAAS_API_KEY env)")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    ap.add_argument("--locations", default="", help="Selected locations CSV, e.g. 'Spruce,Spruce v2,Staging'")
    ap.add_argument("--all-locations", default="", help="All location names CSV used for conflict detection")
    ap.add_argument("--grep", default="gpu", help="Regex filter for hostnames to print")
    args = ap.parse_args()

    maas_url = _norm_url(args.maas_url or os.environ.get("MAAS_URL", ""))
    maas_api_key = args.maas_api_key or os.environ.get("MAAS_API_KEY", "")
    maas_insecure = bool(args.insecure or (os.environ.get("MAAS_INSECURE", "").lower() in {"1", "true", "yes"}))
    if not maas_url or not maas_api_key:
        print("ERROR: provide MAAS URL/API key via args or env.", file=sys.stderr)
        return 2
    verify_tls = not maas_insecure

    selected_location_names = _csv_set(args.locations)
    all_location_names = _csv_set(args.all_locations) or set(selected_location_names)
    grep_re = re.compile(args.grep, re.I)

    session = _maas_auth_session(maas_api_key)
    code, body = _json_request(session, f"{maas_url}/api/2.0/machines/", verify_tls=verify_tls)
    if code >= 400:
        print(f"MAAS error: GET machines failed HTTP {code}", file=sys.stderr)
        return 1
    machines_raw = _pick_array(body)
    fabric_cat = _fabric_catalog(session, maas_url, verify_tls)

    rows = []
    for mr in machines_raw:
        sid = str(mr.get("system_id") or "").strip()
        raw_name = str(mr.get("hostname") or mr.get("fqdn") or "").strip()
        host = _short_hostname(raw_name)
        if not sid or not host:
            continue
        ifaces_raw = _machine_interfaces(session, maas_url, verify_tls, sid)
        interfaces = []
        fabrics = []
        for ir in ifaces_raw:
            fabric = _resolve_fabric_name(ir, fabric_cat)
            mac = str(ir.get("mac_address") or ir.get("mac") or "").strip().lower()
            interfaces.append(
                {
                    "name": str(ir.get("name") or "").strip() or "-",
                    "iface_fabric": fabric,
                    "mac": mac,
                }
            )
            if fabric and fabric != "-":
                fabrics.append(fabric)
        domain = ""
        dom = mr.get("domain")
        if isinstance(dom, dict):
            domain = str(dom.get("name") or "").strip()
        elif dom:
            domain = str(dom).strip()
        dns_name = str(mr.get("fqdn") or "").strip()
        if not dns_name and domain:
            dns_name = f"{host}.{domain}"
        m = {
            "hostname": host,
            "fqdn": str(mr.get("fqdn") or "").strip(),
            "dns_name": dns_name,
            "domain_name": domain,
            "fabric_name": fabrics[0] if fabrics else "-",
            "interfaces": interfaces,
        }
        host = (m.get("hostname") or "").strip()
        if not host or not grep_re.search(host):
            continue
        in_scope, chosen_loc, dbg = _scoped_location_decision(m, selected_location_names, all_location_names)
        domain = (m.get("domain_name") or "").strip()
        dns = _maas_effective_dns_name(m)
        fabrics = sorted(_machine_fabrics(m), key=str.lower)
        rows.append({
            "host": host,
            "domain": domain or "-",
            "dns": dns or "-",
            "fabrics": ", ".join(fabrics) if fabrics else "-",
            "selected_hits": ", ".join(dbg.get("selected_hits", [])) or "-",
            "other_hits": ", ".join(dbg.get("other_hits", [])) or "-",
            "hinted": dbg.get("hinted", "") or "-",
            "include": "YES" if in_scope else "NO",
            "chosen_loc": chosen_loc or "-",
        })

    rows.sort(key=lambda r: r["host"])
    print(f"Selected locations: {', '.join(sorted(selected_location_names)) or '(none)'}")
    print(f"All locations: {', '.join(sorted(all_location_names)) or '(none)'}")
    print(f"Host grep: {args.grep}")
    print(f"Matched hosts: {len(rows)}")
    print()

    if not rows:
        print("No hosts matched grep.")
        return 0

    headers = [
        "host", "include", "chosen_loc", "domain", "dns",
        "fabrics", "selected_hits", "other_hits", "hinted",
    ]
    widths = {h: len(h) for h in headers}
    for r in rows:
        for h in headers:
            widths[h] = max(widths[h], len(str(r[h])))

    def line(d: dict) -> str:
        return "  ".join(str(d[h]).ljust(widths[h]) for h in headers)

    print(line({h: h for h in headers}))
    print("  ".join("-" * widths[h] for h in headers))
    for r in rows:
        print(line(r))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

