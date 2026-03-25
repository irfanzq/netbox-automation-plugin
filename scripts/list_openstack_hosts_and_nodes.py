#!/usr/bin/env python3
"""
Probe OpenStack for hypervisor (compute node) hostnames and VM instances.

Uses the same credentials as the NetBox plugin: OPENSTACK_* or standard OS_* env vars.

  Hypervisors — physical compute nodes (Nova); often requires admin or operator role.
  Servers — VM instances. By default Nova is called with all_projects=True (all tenants), so
  you see VMs across the cloud — OS_PROJECT_NAME only scopes your *login token*, not the
  list (unless you pass --current-project-only). Project names are resolved via Keystone
  when your user can list projects.

Password / user auth must include a project scope or Keystone returns an empty service catalog:

  export OS_PROJECT_NAME=admin          # or OS_PROJECT_ID=...
  export OS_USER_DOMAIN_NAME=Default
  export OS_PROJECT_DOMAIN_NAME=Default

Usage:
  source openrc.sh   # or export OS_* / OPENSTACK_* manually

  # From repo root: python scripts/list_openstack_hosts_and_nodes.py
  # From scripts/:   python list_openstack_hosts_and_nodes.py
  python list_openstack_hosts_and_nodes.py
  python list_openstack_hosts_and_nodes.py --servers-only
  python list_openstack_hosts_and_nodes.py --hypervisors-only
  python list_openstack_hosts_and_nodes.py --json
  python list_openstack_hosts_and_nodes.py --current-project-only

Dependencies:
  pip install openstacksdk
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any


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


def _config_from_env() -> dict[str, Any]:
    """Mirror plugin keys (netbox_automation_plugin/sync/config/settings.py)."""
    region = _env("OS_REGION_NAME", "OPENSTACK_REGION_NAME") or "birch"
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
        "openstack_insecure": _strtobool(
            _env("OPENSTACK_INSECURE", default="false"), default=False
        ),
    }


def _password_auth_missing_project(cfg: dict[str, Any]) -> bool:
    """True when username/password auth is used but neither project id nor name is set."""
    app_id = (cfg.get("openstack_application_credential_id") or "").strip()
    app_secret = (cfg.get("openstack_application_credential_secret") or "").strip()
    if app_id and app_secret:
        return False
    if not (cfg.get("openstack_username") or "").strip():
        return False
    if not (cfg.get("openstack_password") or "").strip():
        return False
    pid = (cfg.get("openstack_project_id") or "").strip()
    pname = (cfg.get("openstack_project_name") or "").strip()
    return not pid and not pname


def _is_empty_catalog_error(exc: BaseException) -> bool:
    if type(exc).__name__ == "EmptyCatalog":
        return True
    return "service catalog is empty" in str(exc).lower()


def _empty_catalog_message() -> str:
    return (
        "Keystone service catalog is empty (unscoped or invalid project). "
        "Set OS_PROJECT_NAME or OS_PROJECT_ID plus domains, e.g.:\n"
        "  export OS_PROJECT_NAME=admin\n"
        "  export OS_USER_DOMAIN_NAME=Default\n"
        "  export OS_PROJECT_DOMAIN_NAME=Default"
    )


def _build_connect_kwargs(cfg: dict[str, Any]) -> dict[str, Any]:
    verify_tls = not cfg.get("openstack_insecure", False)
    auth_url = _normalize_auth_url(cfg.get("openstack_auth_url") or "")
    region = (cfg.get("openstack_region_name") or "").strip() or "birch"
    app_id = (cfg.get("openstack_application_credential_id") or "").strip()
    app_secret = (cfg.get("openstack_application_credential_secret") or "").strip()
    interface = cfg.get("openstack_interface") or "public"

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
        "username": cfg.get("openstack_username") or "",
        "password": cfg.get("openstack_password") or "",
        "user_domain_name": cfg.get("openstack_user_domain_name") or "Default",
        "project_domain_name": cfg.get("openstack_project_domain_name") or "Default",
        "region_name": region,
        "interface": interface,
        "verify": verify_tls,
    }
    pid = (cfg.get("openstack_project_id") or "").strip()
    pname = (cfg.get("openstack_project_name") or "").strip()
    if pid:
        kwargs["project_id"] = pid
    else:
        kwargs["project_name"] = pname or ""
    return kwargs


def _get_attr(obj: Any, *names: str, default: str = "") -> str:
    for n in names:
        v = getattr(obj, n, None)
        if v is not None and v != "":
            return str(v)
    return default


def _collect_hypervisors(conn) -> tuple[list[dict[str, Any]], str | None]:
    rows: list[dict[str, Any]] = []
    err: str | None = None
    try:
        for hv in conn.compute.hypervisors():
            rows.append({
                "id": _get_attr(hv, "id"),
                "name": _get_attr(hv, "name"),
                "hostname": _get_attr(hv, "hypervisor_hostname", "name"),
                "host_ip": _get_attr(hv, "host_ip"),
                "state": _get_attr(hv, "state"),
                "status": _get_attr(hv, "status"),
                "type": _get_attr(hv, "hypervisor_type"),
                "vcpus_used": _get_attr(hv, "vcpus_used", default="0"),
                "vcpus": _get_attr(hv, "vcpus", default=""),
                "memory_mb_used": _get_attr(hv, "memory_mb_used", default="0"),
                "memory_mb": _get_attr(hv, "memory_mb", default=""),
                "running_vms": _get_attr(hv, "running_vms", default="0"),
            })
    except Exception as e:
        if _is_empty_catalog_error(e):
            err = _empty_catalog_message()
        else:
            err = str(e).strip() or repr(e)
    return rows, err


def _server_dict(s: Any) -> dict[str, Any]:
    flavor_id = _get_attr(s, "flavor_id")
    if not flavor_id:
        fl = getattr(s, "flavor", None)
        if isinstance(fl, dict):
            flavor_id = str(fl.get("id") or "")
        elif fl is not None:
            flavor_id = _get_attr(fl, "id")
    return {
        "id": _get_attr(s, "id"),
        "name": _get_attr(s, "name"),
        "status": _get_attr(s, "status"),
        "project_id": _get_attr(s, "project_id", "tenant_id"),
        "project_name": "",
        "hypervisor_hostname": _get_attr(s, "hypervisor_hostname"),
        "host": _get_attr(s, "host"),
        "flavor_id": flavor_id,
        "addresses": getattr(s, "addresses", None) or {},
    }


def _fetch_project_names_by_id(conn) -> tuple[dict[str, str], str | None]:
    """Keystone project id -> name. May fail if policy blocks identity:list_projects."""
    m: dict[str, str] = {}
    err: str | None = None
    try:
        for p in conn.identity.projects():
            pid = (getattr(p, "id", None) or "").strip()
            pname = (getattr(p, "name", None) or "").strip()
            if pid:
                m[pid] = pname or pid[:8]
    except Exception as e:
        err = str(e).strip() or repr(e)
    return m, err


def _attach_project_names(servers: list[dict[str, Any]], project_map: dict[str, str]) -> None:
    for r in servers:
        pid = (r.get("project_id") or "").strip()
        if not pid:
            r["project_name"] = ""
            continue
        r["project_name"] = project_map.get(pid, "")


def _collect_servers(
    conn, *, want_all_projects: bool
) -> tuple[list[dict[str, Any]], str | None, str]:
    """
    Returns (rows, error, scope_note): scope_note is 'all_projects', 'current_project',
    or 'current_project_fallback' when all-projects was requested but the SDK fell back.
    """
    rows: list[dict[str, Any]] = []
    err: str | None = None
    scope_note = "current_project"

    try:
        if want_all_projects:
            scope_note = "all_projects"
            try:
                gen = conn.compute.servers(details=True, all_projects=True)
            except TypeError:
                try:
                    gen = conn.compute.servers(details=True, all_tenants=True)
                except TypeError:
                    print(
                        "Warning: openstacksdk does not accept all_projects/all_tenants; "
                        "listing instances for the current project scope only.",
                        file=sys.stderr,
                    )
                    gen = conn.compute.servers(details=True)
                    scope_note = "current_project_fallback"
        else:
            gen = conn.compute.servers(details=True)

        for s in gen:
            rows.append(_server_dict(s))
    except Exception as e:
        if _is_empty_catalog_error(e):
            err = _empty_catalog_message()
            scope_note = "current_project"
        else:
            err = str(e).strip() or repr(e)
    return rows, err, scope_note


def _print_table(headers: list[str], table: list[list[str]]) -> None:
    if not table:
        print("  (none)")
        return
    widths = [len(h) for h in headers]
    for row in table:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    fmt = "  ".join(f"{{:{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for row in table:
        print(fmt.format(*row))


def main() -> int:
    parser = argparse.ArgumentParser(description="List OpenStack hypervisors and servers.")
    parser.add_argument(
        "--cloud",
        default="",
        help="Optional cloud name (openstacksdk / clouds.yaml); if set, other auth env is ignored.",
    )
    parser.add_argument(
        "--hypervisors-only",
        action="store_true",
        help="Only list hypervisors (compute nodes).",
    )
    parser.add_argument(
        "--servers-only",
        action="store_true",
        help="Only list servers (instances).",
    )
    parser.add_argument(
        "--current-project-only",
        action="store_true",
        help="List servers only in OS_PROJECT_NAME/OS_PROJECT_ID (default: all projects).",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON instead of tables.")
    args = parser.parse_args()

    try:
        import openstack
    except ImportError:
        print("Install openstacksdk: pip install openstacksdk", file=sys.stderr)
        return 1

    if args.cloud:
        try:
            conn = openstack.connect(cloud=args.cloud)
        except Exception as e:
            print(f"Connect failed (cloud={args.cloud!r}): {e}", file=sys.stderr)
            return 1
        auth_summary = f"cloud={args.cloud!r}"
    else:
        cfg = _config_from_env()
        if not cfg["openstack_auth_url"]:
            print(
                "Set OS_AUTH_URL or OPENSTACK_AUTH_URL (or use --cloud NAME).",
                file=sys.stderr,
            )
            return 1
        if _password_auth_missing_project(cfg):
            print(
                "Password auth requires OS_PROJECT_NAME or OS_PROJECT_ID (scoped token). "
                "Without a project, Keystone returns an empty service catalog.\n"
                "Example:\n"
                "  export OS_PROJECT_NAME=admin\n"
                "  export OS_USER_DOMAIN_NAME=Default\n"
                "  export OS_PROJECT_DOMAIN_NAME=Default",
                file=sys.stderr,
            )
            return 2
        kwargs = _build_connect_kwargs(cfg)
        try:
            conn = openstack.connect(**kwargs)
        except Exception as e:
            print(f"Connect failed: {e}", file=sys.stderr)
            return 1
        auth_summary = (
            f"region={kwargs.get('region_name')!r} "
            f"auth_url={kwargs.get('auth_url', '')[:48]}..."
        )

    do_hv = not args.servers_only
    do_srv = not args.hypervisors_only

    hypervisors: list[dict[str, Any]] = []
    hv_error: str | None = None
    servers: list[dict[str, Any]] = []
    srv_error: str | None = None

    if do_hv:
        hypervisors, hv_error = _collect_hypervisors(conn)
    want_all_projects = not args.current_project_only
    servers_scope: str | None = None
    if do_srv:
        servers, srv_error, servers_scope = _collect_servers(
            conn, want_all_projects=want_all_projects
        )

    keystone_projects_error: str | None = None
    project_name_map: dict[str, str] = {}
    if do_srv and not srv_error:
        project_name_map, keystone_projects_error = _fetch_project_names_by_id(conn)
        _attach_project_names(servers, project_name_map)

    auth_scope_project = _env("OS_PROJECT_NAME", "OPENSTACK_PROJECT_NAME", "OS_PROJECT_ID", "OPENSTACK_PROJECT_ID")

    out: dict[str, Any] = {
        "auth": auth_summary,
        "auth_scope_project": auth_scope_project or None,
        "nova_list_all_projects_requested": want_all_projects if do_srv else None,
        "servers_scope": servers_scope if do_srv else None,
        "keystone_projects_list_error": keystone_projects_error if do_srv else None,
        "keystone_project_count": len(project_name_map) if do_srv else None,
        "hypervisors": hypervisors,
        "hypervisors_error": hv_error,
        "servers": servers,
        "servers_error": srv_error,
    }

    if args.json:
        print(json.dumps(out, indent=2, default=str))
        return 0

    print(f"Connected ({auth_summary})")
    if do_srv:
        if not want_all_projects:
            mode = "Nova list: current project only (--current-project-only)"
        elif servers_scope == "all_projects":
            mode = "Nova list: all projects (all_projects=True)"
        elif servers_scope == "current_project_fallback":
            mode = (
                "Nova list: SDK fell back to single-project list (no all_projects support)"
            )
        else:
            mode = f"Nova list: scope={servers_scope!r}"
        scope_line = (
            f"Auth token scope (env): {auth_scope_project or '(unset)'}  |  {mode}"
        )
        print(scope_line)
        if want_all_projects:
            print(
                "  (OS_PROJECT_* is only for Keystone login; it does not limit the "
                "Nova server list unless you use --current-project-only.)"
            )
        if keystone_projects_error:
            print(
                f"  Warning: could not list Keystone projects for names: {keystone_projects_error}",
                file=sys.stderr,
            )
    print()

    if do_hv:
        print("=== Hypervisors (compute nodes) ===")
        if hv_error:
            print(f"  Error: {hv_error}")
        else:
            _print_table(
                [
                    "name",
                    "hostname",
                    "host_ip",
                    "state",
                    "status",
                    "vcpus_used",
                    "mem_used_mb",
                    "running_vms",
                ],
                [
                    [
                        r["name"],
                        r["hostname"],
                        r["host_ip"],
                        r["state"],
                        r["status"],
                        r["vcpus_used"],
                        r["memory_mb_used"],
                        r["running_vms"],
                    ]
                    for r in hypervisors
                ],
            )
        print()

    if do_srv:
        scope_hint = {
            "all_projects": " (all projects)",
            "current_project": " (current project only)",
            "current_project_fallback": " (wanted all projects; SDK fell back to current project)",
        }.get(servers_scope, "")
        print(f"=== Servers (instances){scope_hint} ===")
        if srv_error:
            print(f"  Error: {srv_error}")
        else:
            _print_table(
                [
                    "name",
                    "id",
                    "project_name",
                    "project_id",
                    "status",
                    "hypervisor_hostname",
                ],
                [
                    [
                        (r["name"] or "")[:32],
                        (r["id"] or "")[:13],
                        (r["project_name"] or "-")[:24],
                        (r["project_id"] or "")[:36],
                        r["status"],
                        (r["hypervisor_hostname"] or "-")[:22],
                    ]
                    for r in servers
                ],
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
