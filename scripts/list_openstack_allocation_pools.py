#!/usr/bin/env python3
"""
Standalone OpenStack allocation-pool inspector.

Lists subnet allocation pools (start/end) with network/subnet/project context.

Usage:
  python scripts/list_openstack_allocation_pools.py
  python scripts/list_openstack_allocation_pools.py --json
  python scripts/list_openstack_allocation_pools.py --only-missing-pools
  python scripts/list_openstack_allocation_pools.py --region birch

Auth env vars:
  OPENSTACK_* or OS_* (same pattern used by project helper scripts)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any


def _env(*keys: str, default: str = "") -> str:
    for k in keys:
        v = os.environ.get(k)
        if v:
            return v.strip()
    return default


def _strtobool(v: str | None, default: bool = False) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _normalize_auth_url(auth_url: str) -> str:
    auth_url = (auth_url or "").rstrip("/")
    if auth_url and not auth_url.endswith("/v3"):
        auth_url = auth_url + "/v3"
    return auth_url


def _build_connect_kwargs(region_override: str | None = None) -> dict[str, Any]:
    region = region_override or _env("OS_REGION_NAME", "OPENSTACK_REGION_NAME", default="birch")
    app_id = _env("OPENSTACK_APPLICATION_CREDENTIAL_ID", "OS_APPLICATION_CREDENTIAL_ID")
    app_secret = _env("OPENSTACK_APPLICATION_CREDENTIAL_SECRET", "OS_APPLICATION_CREDENTIAL_SECRET")
    verify_tls = not _strtobool(_env("OPENSTACK_INSECURE", default="false"), default=False)
    auth_url = _normalize_auth_url(_env("OPENSTACK_AUTH_URL", "OS_AUTH_URL"))
    interface = _env("OPENSTACK_INTERFACE", "OS_INTERFACE", default="public")

    if app_id and app_secret:
        return {
            "auth_url": auth_url,
            "application_credential_id": app_id,
            "application_credential_secret": app_secret,
            "region_name": region,
            "interface": interface,
            "verify": verify_tls,
        }

    kwargs: dict[str, Any] = {
        "auth_url": auth_url,
        "username": _env("OPENSTACK_USERNAME", "OS_USERNAME"),
        "password": _env("OPENSTACK_PASSWORD", "OS_PASSWORD"),
        "user_domain_name": _env("OPENSTACK_USER_DOMAIN_NAME", "OS_USER_DOMAIN_NAME", default="Default"),
        "project_domain_name": _env(
            "OPENSTACK_PROJECT_DOMAIN_NAME", "OS_PROJECT_DOMAIN_NAME", default="Default"
        ),
        "region_name": region,
        "interface": interface,
        "verify": verify_tls,
    }
    project_id = _env("OPENSTACK_PROJECT_ID", "OS_PROJECT_ID")
    project_name = _env("OPENSTACK_PROJECT_NAME", "OS_PROJECT_NAME")
    if project_id:
        kwargs["project_id"] = project_id
    else:
        kwargs["project_name"] = project_name
    return kwargs


def _collect_pool_rows(conn) -> list[dict[str, str]]:
    networks = {}
    for n in conn.network.networks():
        nid = str(getattr(n, "id", "") or "").strip()
        if nid:
            networks[nid] = str(getattr(n, "name", "") or nid).strip()

    rows: list[dict[str, str]] = []
    for sn in conn.network.subnets():
        subnet_id = str(getattr(sn, "id", "") or "").strip()
        subnet_name = str(getattr(sn, "name", "") or "-").strip()
        cidr = str(getattr(sn, "cidr", "") or "").strip()
        network_id = str(getattr(sn, "network_id", "") or "").strip()
        network_name = networks.get(network_id, network_id or "-")
        project_id = str(getattr(sn, "project_id", None) or getattr(sn, "tenant_id", None) or "").strip()
        pools = getattr(sn, "allocation_pools", None) or []
        for idx, p in enumerate(pools):
            if isinstance(p, dict):
                start = str(p.get("start") or "").strip()
                end = str(p.get("end") or "").strip()
            else:
                start = str(getattr(p, "start", "") or "").strip()
                end = str(getattr(p, "end", "") or "").strip()
            if not start or not end:
                continue
            rows.append(
                {
                    "region": str(conn.config.get_region_name() or "").strip() or "-",
                    "network_name": network_name,
                    "network_id": network_id or "-",
                    "subnet_name": subnet_name,
                    "subnet_id": subnet_id or "-",
                    "cidr": cidr or "-",
                    "pool_index": str(idx + 1),
                    "start_address": start,
                    "end_address": end,
                    "project_id": project_id or "-",
                }
            )
    return rows


def _print_table(rows: list[dict[str, str]]) -> None:
    headers = [
        "Region",
        "Network",
        "Subnet",
        "CIDR",
        "Pool#",
        "Start",
        "End",
        "Project ID",
    ]
    cols = [
        ("region", 10),
        ("network_name", 24),
        ("subnet_name", 24),
        ("cidr", 20),
        ("pool_index", 6),
        ("start_address", 18),
        ("end_address", 18),
        ("project_id", 36),
    ]
    print(" | ".join(h.ljust(w) for h, (_, w) in zip(headers, cols)))
    print("-+-".join("-" * w for _, w in cols))
    for r in rows:
        line = []
        for key, width in cols:
            v = str(r.get(key, "") or "")
            if len(v) > width:
                v = v[: max(1, width - 1)] + "…"
            line.append(v.ljust(width))
        print(" | ".join(line))


def main() -> int:
    ap = argparse.ArgumentParser(description="List OpenStack subnet allocation pools.")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of table.")
    ap.add_argument("--region", default="", help="Override region name (default from env).")
    args = ap.parse_args()

    try:
        import openstack
    except Exception:
        print("Missing dependency: openstacksdk (pip install openstacksdk)", file=sys.stderr)
        return 2

    kwargs = _build_connect_kwargs(region_override=(args.region.strip() or None))
    try:
        conn = openstack.connect(**kwargs)
    except Exception as e:
        print(f"OpenStack connect failed: {e}", file=sys.stderr)
        return 2

    try:
        rows = _collect_pool_rows(conn)
    except Exception as e:
        print(f"Failed to collect allocation pools: {e}", file=sys.stderr)
        return 2

    rows = sorted(
        rows,
        key=lambda r: (
            r.get("region", "").lower(),
            r.get("network_name", "").lower(),
            r.get("subnet_name", "").lower(),
            r.get("pool_index", ""),
        ),
    )

    if args.json:
        print(json.dumps({"count": len(rows), "allocation_pools": rows}, indent=2))
    else:
        if not rows:
            print("No allocation pools found.")
            return 0
        _print_table(rows)
        print("")
        print(f"Total allocation pools: {len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

