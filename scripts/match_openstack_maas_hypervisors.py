#!/usr/bin/env python3
"""
Connect to OpenStack and MAAS, list compute hosts, and find MAAS system_id correlations.

Queries:
  • Nova hypervisors (all compute nodes)
  • Ironic bare metal nodes (details=True) — UUID + UUIDs inside properties/driver_info vs MAAS
  • Nova servers (all projects), default on — UUID in hypervisor_hostname/host vs MAAS

Matching:
  1) 32-hex UUID ↔ MAAS system_id (when UUID-shaped), MAAS hardware_uuid / hardware_info UUIDs ↔
     Nova hypervisor id/name/hostname, instance hypervisor_hostname/host, Ironic node uuid, or any
     UUID string nested in Ironic properties/driver_info. Short MAAS system_ids (e.g. qqfq84)
     never match Nova/Ironic RFC UUIDs by string equality.
  2) Normalized hardware serial ↔ MAAS machine serial fields and Ironic properties/driver_info
     (Ironic inspection stores SMBIOS serials under keys like serial_number / system_serial — see
     OpenStack Ironic inspection data docs). Use --maas-fetch-serial if MAAS list omits serials.
  3) Hostname ↔ MAAS hostname / fqdn (Nova hypervisor and Ironic node name).
  4) Nova hypervisor id/name/hostname ↔ same UUID as an Ironic node → Ironic `name` (rack hostname);
     see table "Hypervisor UUID → Ironic name". Needs permission to list all baremetal nodes.
  5) **Ironic `instance_uuid` ↔ Nova instance id** — on an active node, the baremetal row’s Instance UUID
     is the Nova server id; match that to `servers()` (all-projects) for display name, project, etc.
  6) hypervisor host_ip ↔ MAAS ip_addresses (when populated).

Usage (OS_* / OPENSTACK_* plus MAAS — same as list_openstack_hosts_and_nodes.py):

  export MAAS_URL='https://maas.example.com/MAAS'
  export MAAS_API_KEY='consumer:key:token'
  export MAAS_INSECURE=true
  export OS_AUTH_URL=... OS_USERNAME=... OS_PASSWORD=... OS_PROJECT_NAME=...

  # From repo root (netbox-automation-plugin/):
  python scripts/match_openstack_maas_hypervisors.py
  # From scripts/ directory:
  python match_openstack_maas_hypervisors.py

  python match_openstack_maas_hypervisors.py --json
  python match_openstack_maas_hypervisors.py --json --quiet | jq '.ironic_nodes_catalog'  # no stderr noise
  python match_openstack_maas_hypervisors.py --no-servers
  python match_openstack_maas_hypervisors.py --no-ironic
  python match_openstack_maas_hypervisors.py --maas-fetch-serial   # GET each machine if list has no serial
  python match_openstack_maas_hypervisors.py --show-unmatched-maas

JSON output includes `ironic_nodes_catalog` (uuid, name, state) and `ironic_nova_instance_links`
(Ironic `instance_uuid` joined to Nova server id / name / project — per ops: match Instance ID to the node).

Dependencies: pip install openstacksdk requests requests-oauthlib
"""

from __future__ import annotations

import argparse
import json
import os
import re
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


def _norm_url(base: str) -> str:
    b = (base or "").strip()
    if not b:
        return b
    if not re.match(r"^https?://", b):
        b = "http://" + b
    return b.rstrip("/")


def _json_request(session, url: str, *, verify_tls: bool) -> tuple[int, Any]:
    r = session.get(url, verify=verify_tls, timeout=120)
    ctype = (r.headers.get("content-type") or "").lower()
    if "json" in ctype:
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"_raw": r.text[:1000]}
    return r.status_code, {"_raw": r.text[:1000]}


def _pick_array(data: Any) -> list[dict]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in ("results", "machines", "nodes"):
            arr = data.get(k)
            if isinstance(arr, list):
                return [x for x in arr if isinstance(x, dict)]
    return []


def _maas_auth_session(maas_api_key: str):
    try:
        import requests  # type: ignore
        from requests_oauthlib import OAuth1  # type: ignore
    except Exception as e:
        raise SystemExit(
            "Install: pip install requests requests-oauthlib"
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


def _normalize_auth_url(auth_url: str) -> str:
    auth_url = (auth_url or "").rstrip("/")
    if auth_url and not auth_url.endswith("/v3"):
        auth_url = auth_url + "/v3"
    return auth_url


def _config_from_env() -> dict[str, Any]:
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
        "openstack_insecure": _strtobool(_env("OPENSTACK_INSECURE", default="false"), False),
    }


def _password_auth_missing_project(cfg: dict[str, Any]) -> bool:
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


_UUID_HEX = re.compile(r"^[0-9a-fA-F]{32}$")


def _uuid_compact(s: str) -> str:
    """32 hex chars lowercase, no hyphens, or ''."""
    t = re.sub(r"[^0-9a-fA-F]", "", (s or "").strip())
    if len(t) == 32 and _UUID_HEX.match(t):
        return t.lower()
    return ""


def _short_hostname(name: str) -> str:
    n = (name or "").strip().lower()
    if not n:
        return ""
    if "." in n:
        return n.split(".", 1)[0]
    return n


def _maas_list_machines(session, maas_url: str, verify_tls: bool) -> list[dict]:
    code, body = _json_request(session, f"{maas_url}/api/2.0/machines/", verify_tls=verify_tls)
    if code >= 400:
        raise SystemExit(f"MAAS GET machines failed HTTP {code}: {body!r}")
    return _pick_array(body)


def _maas_ip_set(machine: dict) -> set[str]:
    out: set[str] = set()
    raw = machine.get("ip_addresses")
    if isinstance(raw, list):
        for x in raw:
            if isinstance(x, str) and x.strip():
                out.add(x.strip().lower())
            elif isinstance(x, dict):
                a = str(x.get("ip") or x.get("address") or "").strip().lower()
                if a:
                    out.add(a)
    return out


def _norm_serial(s: str) -> str:
    """Normalize for comparison: strip non-alphanumerics, upper (matches NetBox/MAAS style)."""
    t = re.sub(r"[^A-Z0-9]", "", (s or "").strip().upper())
    if len(t) < 4 or len(t) > 64:
        return ""
    return t


# Keys that may hold a *system* serial — not product names (SKU/model strings collide across hosts).
_SERIAL_FIELD_KEYS = frozenset({
    "serial",
    "serial_number",
    "system_serial",
    "baseboard_serial",
    "chassis_serial",
    "mfg_serial",
    "service_tag",
    "asset_tag",
    "enclosure_serial",
    "system_product_serial",
})


def _key_looks_like_serial_field(key: str) -> bool:
    lk = str(key).lower().replace("-", "_")
    if lk in _SERIAL_FIELD_KEYS:
        return True
    if lk.endswith("_serial") or lk.endswith("_serial_number"):
        return True
    return False


_SERIAL_VALUE_REJECT_SUBSTR = re.compile(
    r"ETHERNET|NETWORK|CONTROLLER|CONNECTX|GIGABIT|FAMILY|FIRMWARE|VERSION|"
    r"RACK\s*MOUNT|CHASSIS\s*TYPE|POWEREDGE\s*[A-Z]?\d{3,}",
    re.I,
)

_BAD_SERIAL_TOKENS = frozenset({
    "UNKNOWN",
    "DEFAULT",
    "NA",
    "NONE",
    "SYSTEMSERIALNUMBER",
    "TOSERIALNUMBERBESET",
    "NOTPROVIDED",
    "NOTAVAILABLE",
    "INVALID",
    "EMPTY",
    # Common junk SMBIOS / placeholder duplicated across many boards
    "01234567890123456789AB",
})


def _accept_serial_candidate(ns: str, raw: str) -> bool:
    """
    Drop generic SMBIOS placeholders and PCI / NIC model strings that were polluting the index
    (e.g. RACKMOUNTCHASSIS, MT2892FAMILYCONNECTX6DX) when keys were matched too loosely.
    """
    if not ns or len(ns) < 6 or len(ns) > 32:
        return False
    if ns in _BAD_SERIAL_TOKENS:
        return False
    if not any(ch.isdigit() for ch in ns):
        return False
    if _SERIAL_VALUE_REJECT_SUBSTR.search(raw or ""):
        return False
    return True


def _walk_dict_serial_fields(d: dict, sink: set[str], depth: int = 0) -> None:
    """Recurse dict/list; only take string values under keys that look like serial fields."""
    if depth > 10 or not isinstance(d, dict):
        return
    for k, v in d.items():
        if isinstance(v, str) and v.strip() and _key_looks_like_serial_field(k):
            ns = _norm_serial(v)
            if ns and _accept_serial_candidate(ns, v):
                sink.add(ns)
        elif isinstance(v, dict):
            _walk_dict_serial_fields(v, sink, depth + 1)
        elif isinstance(v, list):
            for x in v:
                if isinstance(x, dict):
                    _walk_dict_serial_fields(x, sink, depth + 1)


def _maas_serial_candidates(machine: dict) -> set[str]:
    """Serials from MAAS machine JSON — strict keys only (avoids model/SKU false positives)."""
    found: set[str] = set()
    for key in ("serial", "serial_number", "mfg_serial"):
        v = machine.get(key)
        if isinstance(v, str) and v.strip():
            ns = _norm_serial(v)
            if ns and _accept_serial_candidate(ns, v):
                found.add(ns)
    hw = machine.get("hardware_info")
    if isinstance(hw, dict):
        for k in (
            "serial",
            "serial_number",
            "system_serial",
            "baseboard_serial",
            "chassis_serial",
        ):
            v = hw.get(k)
            if isinstance(v, str) and v.strip():
                ns = _norm_serial(v)
                if ns and _accept_serial_candidate(ns, v):
                    found.add(ns)
        _walk_dict_serial_fields(hw, found)
    return found


def _ironic_serial_candidates(properties: dict, driver_info: dict) -> set[str]:
    """Ironic properties/driver_info: same strict serial-field rules as MAAS."""
    found: set[str] = set()
    for d in (properties, driver_info):
        if isinstance(d, dict):
            _walk_dict_serial_fields(d, found)
    return found


def _maas_machine_detail(session, maas_url: str, verify_tls: bool, system_id: str) -> dict:
    for url in (
        f"{maas_url}/api/2.0/machines/{system_id}/",
        f"{maas_url}/api/2.0/nodes/{system_id}/",
    ):
        code, data = _json_request(session, url, verify_tls=verify_tls)
        if code == 200 and isinstance(data, dict):
            return data
    return {}


def _build_maas_serial_index(
    session: Any,
    maas_url: str,
    verify_tls: bool,
    maas_machines: list[dict],
    *,
    fetch_detail_if_empty: bool,
) -> tuple[dict[str, dict], list[str]]:
    """
    Map normalized serial -> MAAS machine dict (first wins).
    Returns (by_serial, collision_notes).
    """
    by_serial: dict[str, dict] = {}
    collisions: list[str] = []
    for m in maas_machines:
        sid = str(m.get("system_id") or "").strip()
        found = _maas_serial_candidates(m)
        if fetch_detail_if_empty and sid and not found:
            detail = _maas_machine_detail(session, maas_url, verify_tls, sid)
            found |= _maas_serial_candidates(detail)
        for ns in found:
            if ns in by_serial:
                prev = str(by_serial[ns].get("system_id") or "")
                cur = sid
                if prev != cur:
                    collisions.append(f"serial {ns}: {prev!r} vs {cur!r}")
            else:
                by_serial[ns] = m
    return by_serial, collisions


def _openstack_hypervisors(conn) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for hv in conn.compute.hypervisors():
        rows.append({
            "id": _get_attr(hv, "id"),
            "name": _get_attr(hv, "name"),
            "hostname": _get_attr(hv, "hypervisor_hostname", "name"),
            "host_ip": _get_attr(hv, "host_ip"),
        })
    return rows


def _extract_uuids_nested(obj: Any, sink: set[str], depth: int = 0) -> None:
    """Collect 32-hex UUIDs from nested dict/list/str (properties, driver_info)."""
    if depth > 8:
        return
    if isinstance(obj, str):
        u = _uuid_compact(obj)
        if u:
            sink.add(u)
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _extract_uuids_nested(v, sink, depth + 1)
        return
    if isinstance(obj, list):
        for x in obj:
            _extract_uuids_nested(x, sink, depth + 1)


def _openstack_ironic_nodes(conn) -> tuple[list[dict[str, Any]], str | None]:
    """
    List Ironic nodes. Returns rows with uuid, name, instance_uuid, provision_state, driver,
    plus properties/driver_info for UUID mining (not printed in full to avoid secrets in logs).
    """
    rows: list[dict[str, Any]] = []
    err: str | None = None
    try:
        bm = conn.baremetal
    except Exception as e:
        return [], f"baremetal service unavailable: {e}"
    try:
        for n in bm.nodes(details=True):
            props = getattr(n, "properties", None)
            if not isinstance(props, dict):
                props = {}
            dinfo = getattr(n, "driver_info", None)
            if not isinstance(dinfo, dict):
                dinfo = {}
            meta_uuids: set[str] = set()
            _extract_uuids_nested(props, meta_uuids)
            _extract_uuids_nested(dinfo, meta_uuids)
            serials = _ironic_serial_candidates(props, dinfo)
            rows.append({
                "uuid": _get_attr(n, "id"),
                "name": _get_attr(n, "name"),
                # openstacksdk uses instance_id on some releases; API/CLI say instance_uuid
                "instance_uuid": _get_attr(n, "instance_uuid", "instance_id"),
                "provision_state": _get_attr(n, "provision_state"),
                "power_state": _get_attr(n, "power_state"),
                "driver": _get_attr(n, "driver"),
                "properties": props,
                "driver_info": dinfo,
                "metadata_uuids": sorted(meta_uuids),
                "detected_serials": sorted(serials),
            })
    except Exception as e:
        err = str(e).strip() or repr(e)
    return rows, err


def _ironic_nodes_catalog(ironic_nodes: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Slim rows for stdout/JSON: uuid → name (no properties/driver_info)."""
    out: list[dict[str, str]] = []
    for n in ironic_nodes:
        out.append({
            "uuid": str(n.get("uuid") or ""),
            "name": str(n.get("name") or ""),
            "provision_state": str(n.get("provision_state") or ""),
            "power_state": str(n.get("power_state") or ""),
            "instance_uuid": str(n.get("instance_uuid") or ""),
            "driver": str(n.get("driver") or ""),
        })
    return out


def _match_ironic_maas(
    ironic_nodes: list[dict[str, Any]],
    by_uuid: dict[str, dict],
    by_host: dict[str, list[dict]],
    by_serial: dict[str, dict],
) -> tuple[list[dict[str, Any]], set[str]]:
    """Match each Ironic node to MAAS by UUID, metadata UUIDs, hardware serial, or hostname."""
    out: list[dict[str, Any]] = []
    maas_sids: set[str] = set()
    for node in ironic_nodes:
        nu = _uuid_compact(str(node.get("uuid") or ""))
        name = (node.get("name") or "").strip()
        maas_row: dict | None = None
        method = ""
        matched_uuid_key = ""
        matched_serial = ""

        if nu and nu in by_uuid:
            maas_row = by_uuid[nu]
            method = "ironic.node_uuid"
            matched_uuid_key = nu
        if maas_row is None:
            for u in node.get("metadata_uuids") or []:
                if u in by_uuid:
                    maas_row = by_uuid[u]
                    method = "ironic.metadata_uuid"
                    matched_uuid_key = u
                    break
        if maas_row is None and by_serial:
            for ns in node.get("detected_serials") or []:
                if ns in by_serial:
                    maas_row = by_serial[ns]
                    method = "ironic.serial"
                    matched_serial = ns
                    break
        if maas_row is None:
            for key in (_short_hostname(name), name.lower()):
                if key and key in by_host:
                    maas_row = by_host[key][0]
                    method = "ironic.name_hostname"
                    break

        if maas_row:
            msid = str(maas_row.get("system_id") or "")
            if msid:
                maas_sids.add(msid)
            out.append({
                "match_method": method,
                "matched_uuid_key": matched_uuid_key,
                "matched_serial": matched_serial,
                "ironic_uuid": node.get("uuid") or "",
                "ironic_name": name,
                "ironic_instance_uuid": node.get("instance_uuid") or "",
                "ironic_provision_state": node.get("provision_state") or "",
                "ironic_driver": node.get("driver") or "",
                "maas_system_id": msid,
                "maas_hostname": str(maas_row.get("hostname") or ""),
                "maas_fqdn": str(maas_row.get("fqdn") or ""),
                "maas_status": str(maas_row.get("status_name") or maas_row.get("status") or ""),
                "metadata_uuid_count": len(node.get("metadata_uuids") or []),
                "ironic_serial_count": len(node.get("detected_serials") or []),
            })
    return out, maas_sids


def _match_hypervisor_maas_via_ironic_serial(
    hypervisors: list[dict[str, str]],
    ironic_nodes: list[dict[str, Any]],
    by_serial: dict[str, dict],
) -> tuple[list[dict[str, Any]], set[str]]:
    """
    UUID-named Nova hypervisors: resolve to Ironic node by UUID, then match MAAS by shared serial.
    """
    ironic_by_u: dict[str, dict[str, Any]] = {}
    for n in ironic_nodes:
        u = _uuid_compact(str(n.get("uuid") or ""))
        if u:
            ironic_by_u[u] = n

    out: list[dict[str, Any]] = []
    maas_sids: set[str] = set()
    if not by_serial:
        return out, maas_sids

    for hv in hypervisors:
        linked = False
        for field in ("id", "name", "hostname"):
            if linked:
                break
            u = _uuid_compact(str(hv.get(field) or ""))
            if not u or u not in ironic_by_u:
                continue
            node = ironic_by_u[u]
            for ns in node.get("detected_serials") or []:
                if ns not in by_serial:
                    continue
                m = by_serial[ns]
                msid = str(m.get("system_id") or "")
                if msid:
                    maas_sids.add(msid)
                out.append({
                    "match_method": "hypervisor.ironic_uuid.serial",
                    "hypervisor_field": field,
                    "os_hypervisor_id": hv.get("id") or "",
                    "os_hypervisor_name": hv.get("name") or "",
                    "os_hypervisor_hostname": hv.get("hostname") or "",
                    "ironic_uuid": str(node.get("uuid") or ""),
                    "ironic_name": str(node.get("name") or ""),
                    "matched_serial": ns,
                    "maas_system_id": msid,
                    "maas_hostname": str(m.get("hostname") or ""),
                })
                linked = True
                break
    return out, maas_sids


def _link_ironic_hypervisors(
    ironic_nodes: list[dict[str, Any]],
    hypervisors: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Rows where a Nova hypervisor id/name/hostname equals an Ironic node UUID (same string)."""
    ironic_uuids = {_uuid_compact(str(n.get("uuid") or "")) for n in ironic_nodes}
    ironic_uuids.discard("")
    ironic_by_u: dict[str, str] = {}
    for n in ironic_nodes:
        u = _uuid_compact(str(n.get("uuid") or ""))
        if u:
            ironic_by_u[u] = str(n.get("name") or "")

    links: list[dict[str, str]] = []
    for hv in hypervisors:
        done = False
        for field, label in (
            ("id", "hypervisor.id"),
            ("name", "hypervisor.name"),
            ("hostname", "hypervisor.hostname"),
        ):
            if done:
                break
            u = _uuid_compact(str(hv.get(field) or ""))
            if not u or u not in ironic_uuids:
                continue
            links.append({
                "match_field": label,
                "openstack_uuid": u,
                "hypervisor_name": hv.get("name") or "",
                "hypervisor_hostname": hv.get("hostname") or "",
                "ironic_name": ironic_by_u.get(u, ""),
            })
            done = True
    return links


def _link_ironic_nodes_to_nova_instances(
    ironic_nodes: list[dict[str, Any]],
    servers: list[dict[str, str]],
) -> list[dict[str, str]]:
    """
    For each Ironic node, `instance_uuid` (when set) is the Nova server id for the workload on that node.
    Join to all-projects server list so NetBox / ops can tie baremetal name ↔ instance metadata.
    """
    by_server_id: dict[str, dict[str, str]] = {}
    for s in servers:
        u = _uuid_compact(str(s.get("id") or ""))
        if u:
            by_server_id[u] = s

    out: list[dict[str, str]] = []
    for n in ironic_nodes:
        iu = _uuid_compact(str(n.get("instance_uuid") or ""))
        srv = by_server_id.get(iu) if iu else None
        out.append({
            "ironic_node_uuid": str(n.get("uuid") or ""),
            "ironic_name": str(n.get("name") or ""),
            "instance_uuid": str(n.get("instance_uuid") or ""),
            "nova_server_name": (srv.get("name") or "") if srv else "",
            "nova_server_id": (srv.get("id") or "") if srv else "",
            "nova_status": (srv.get("status") or "") if srv else "",
            "nova_project_id": (srv.get("project_id") or "") if srv else "",
            "nova_hypervisor_hostname": (srv.get("hypervisor_hostname") or "") if srv else "",
        })
    return out


def _openstack_servers_all_projects(conn) -> tuple[list[dict[str, str]], str | None]:
    """List instances with details; prefer all_projects=True (same as list_openstack_hosts_and_nodes)."""
    rows: list[dict[str, str]] = []
    err: str | None = None
    try:
        try:
            gen = conn.compute.servers(details=True, all_projects=True)
        except TypeError:
            try:
                gen = conn.compute.servers(details=True, all_tenants=True)
            except TypeError:
                gen = conn.compute.servers(details=True)
        for s in gen:
            rows.append({
                "id": _get_attr(s, "id"),
                "name": _get_attr(s, "name"),
                "status": _get_attr(s, "status"),
                "project_id": _get_attr(s, "project_id", "tenant_id"),
                "hypervisor_hostname": _get_attr(s, "hypervisor_hostname"),
                "host": _get_attr(s, "host"),
            })
    except Exception as e:
        err = str(e).strip() or repr(e)
    return rows, err


def _build_maas_indexes(
    maas_machines: list[dict],
) -> tuple[dict[str, dict], dict[str, list[dict]]]:
    """
    by_uuid: 32-hex keys for MAAS system_id (when it is a UUID), hardware_uuid
    (SMBIOS; often aligns with Ironic node UUID), and hardware_info UUID-style fields.
    """
    by_uuid: dict[str, dict] = {}
    by_host: dict[str, list[dict]] = {}
    for m in maas_machines:
        sid = str(m.get("system_id") or "").strip()
        if not sid:
            continue
        u = _uuid_compact(sid)
        if u:
            by_uuid[u] = m
        hwu = _uuid_compact(str(m.get("hardware_uuid") or ""))
        if hwu:
            by_uuid[hwu] = m
        # Some fabrics expose commissioning SMBIOS UUID under hardware_info
        hw = m.get("hardware_info")
        if isinstance(hw, dict):
            for k in ("system_uuid", "uuid", "hardware_uuid"):
                u2 = _uuid_compact(str(hw.get(k) or ""))
                if u2:
                    by_uuid[u2] = m
        host = str(m.get("hostname") or "").strip()
        fqdn = str(m.get("fqdn") or "").strip()
        for key in {_short_hostname(host), _short_hostname(fqdn), host.lower(), fqdn.lower()}:
            if not key:
                continue
            by_host.setdefault(key, []).append(m)
    return by_uuid, by_host


def _match_servers_maas_system_id(
    servers: list[dict[str, str]],
    by_uuid: dict[str, dict],
) -> list[dict[str, Any]]:
    """Instances whose hypervisor_hostname/host is a UUID that matches MAAS (system_id or hardware_uuid)."""
    out: list[dict[str, Any]] = []
    for s in servers:
        for field, label in (
            ("hypervisor_hostname", "server.hypervisor_hostname_uuid"),
            ("host", "server.host_uuid"),
        ):
            u = _uuid_compact(s.get(field) or "")
            if not u or u not in by_uuid:
                continue
            m = by_uuid[u]
            out.append({
                "match_method": label,
                "server_id": s.get("id") or "",
                "server_name": s.get("name") or "",
                "server_status": s.get("status") or "",
                "server_project_id": s.get("project_id") or "",
                "openstack_field": field,
                "openstack_value": s.get(field) or "",
                "maas_system_id": str(m.get("system_id") or ""),
                "maas_hostname": str(m.get("hostname") or ""),
                "maas_fqdn": str(m.get("fqdn") or ""),
                "maas_status": str(m.get("status_name") or m.get("status") or ""),
            })
            break
    return out


def _match_hypervisors(
    hypervisors: list[dict[str, str]],
    maas_machines: list[dict],
    by_uuid: dict[str, dict],
    by_host: dict[str, list[dict]],
) -> tuple[list[dict[str, Any]], list[dict[str, str]], set[str]]:
    """
    Returns (matched_rows, unmatched_hypervisors, matched_maas_system_ids).
    """
    matched_maas_sid: set[str] = set()
    matches: list[dict[str, Any]] = []

    for hv in hypervisors:
        hid = _uuid_compact(hv.get("id") or "")
        hname = (hv.get("name") or "").strip()
        hhost = (hv.get("hostname") or "").strip()
        hip = (hv.get("host_ip") or "").strip().lower()
        hn_u = _uuid_compact(hname)
        hh_u = _uuid_compact(hhost)

        maas_row: dict | None = None
        method = ""

        for candidate_uuid, label in ((hid, "hypervisor.id"), (hn_u, "hypervisor.name_uuid"), (hh_u, "hypervisor.hostname_uuid")):
            if candidate_uuid and candidate_uuid in by_uuid:
                maas_row = by_uuid[candidate_uuid]
                method = label
                break

        if maas_row is None:
            for label, key in (
                ("hostname", _short_hostname(hname)),
                ("hostname", _short_hostname(hhost)),
                ("hostname_full", hname.lower()),
                ("hostname_full", hhost.lower()),
            ):
                if not key:
                    continue
                candidates = by_host.get(key)
                if candidates:
                    maas_row = candidates[0]
                    method = label
                    break

        if maas_row is None and hip:
            for m in maas_machines:
                sid = str(m.get("system_id") or "").strip()
                if not sid:
                    continue
                ips = _maas_ip_set(m)
                if hip in ips:
                    maas_row = m
                    method = "ip_address"
                    break

        if maas_row:
            msid = str(maas_row.get("system_id") or "")
            matched_maas_sid.add(msid)
            matches.append({
                "match_method": method,
                "os_hypervisor_id": hv.get("id") or "",
                "os_hypervisor_name": hname,
                "os_hypervisor_hostname": hhost,
                "os_host_ip": hv.get("host_ip") or "",
                "maas_system_id": msid,
                "maas_hostname": str(maas_row.get("hostname") or ""),
                "maas_fqdn": str(maas_row.get("fqdn") or ""),
                "maas_status": str(maas_row.get("status_name") or maas_row.get("status") or ""),
            })
        else:
            matches.append({
                "match_method": "none",
                "os_hypervisor_id": hv.get("id") or "",
                "os_hypervisor_name": hname,
                "os_hypervisor_hostname": hhost,
                "os_host_ip": hv.get("host_ip") or "",
                "maas_system_id": "",
                "maas_hostname": "",
                "maas_fqdn": "",
                "maas_status": "",
            })

    matched_rows = [m for m in matches if m["match_method"] != "none"]
    unmatched_hv = [
        {
            "id": m["os_hypervisor_id"],
            "name": m["os_hypervisor_name"],
            "hostname": m["os_hypervisor_hostname"],
            "host_ip": m["os_host_ip"],
        }
        for m in matches
        if m["match_method"] == "none"
    ]
    return matched_rows, unmatched_hv, matched_maas_sid


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
    ap = argparse.ArgumentParser(
        description=(
            "Query OpenStack (Nova hypervisors, Ironic nodes, all-projects servers) and MAAS; "
            "correlate UUIDs and hostnames."
        )
    )
    ap.add_argument("--maas-url", default=os.getenv("MAAS_URL", ""))
    ap.add_argument("--maas-api-key", default=os.getenv("MAAS_API_KEY", ""))
    ap.add_argument("--maas-insecure", action="store_true")
    ap.add_argument(
        "--no-ironic",
        action="store_true",
        help="Skip Ironic bare metal node list (baremetal API).",
    )
    ap.add_argument(
        "--no-servers",
        action="store_true",
        help="Skip Nova server list (only match hypervisors to MAAS).",
    )
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="With --json: suppress MAAS collision and OpenStack soft warnings on stderr.",
    )
    ap.add_argument(
        "--show-unmatched-maas",
        action="store_true",
        help="Print MAAS machines with no hypervisor, server, or Ironic UUID match.",
    )
    ap.add_argument(
        "--maas-fetch-serial",
        action="store_true",
        help=(
            "GET /machines/{system_id}/ when list response has no serial candidates "
            "(slower; improves serial index for MAAS↔Ironic matching)."
        ),
    )
    args = ap.parse_args()

    maas_url = _norm_url(args.maas_url)
    api_key = (args.maas_api_key or "").strip()
    if not maas_url or not api_key:
        print("Set MAAS_URL and MAAS_API_KEY.", file=sys.stderr)
        return 2

    verify_maas = True
    if args.maas_insecure or _strtobool(os.getenv("MAAS_INSECURE"), False):
        verify_maas = False
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    cfg = _config_from_env()
    if not cfg["openstack_auth_url"]:
        print("Set OS_AUTH_URL or OPENSTACK_AUTH_URL.", file=sys.stderr)
        return 2
    if _password_auth_missing_project(cfg):
        print(
            "Password auth needs OS_PROJECT_NAME or OS_PROJECT_ID (see list_openstack_hosts_and_nodes.py).",
            file=sys.stderr,
        )
        return 2

    try:
        import openstack
    except ImportError:
        print("pip install openstacksdk", file=sys.stderr)
        return 1

    session = _maas_auth_session(api_key)
    maas_machines = _maas_list_machines(session, maas_url, verify_maas)
    by_serial, maas_serial_collisions = _build_maas_serial_index(
        session,
        maas_url,
        verify_maas,
        maas_machines,
        fetch_detail_if_empty=args.maas_fetch_serial,
    )
    quiet_err = bool(args.json and args.quiet)
    if maas_serial_collisions and not quiet_err:
        print(
            f"Warning: {len(maas_serial_collisions)} MAAS serial key collision(s) "
            f"(same normalized serial on multiple machines). First machine wins.",
            file=sys.stderr,
        )
        for line in maas_serial_collisions[:15]:
            print(f"  {line}", file=sys.stderr)
        if len(maas_serial_collisions) > 15:
            print(f"  … and {len(maas_serial_collisions) - 15} more", file=sys.stderr)

    try:
        conn = openstack.connect(**_build_connect_kwargs(cfg))
        hypervisors = _openstack_hypervisors(conn)
    except Exception as e:
        print(f"OpenStack failed: {e}", file=sys.stderr)
        return 1

    ironic_nodes: list[dict[str, Any]] = []
    ironic_error: str | None = None
    if not args.no_ironic:
        ironic_nodes, ironic_error = _openstack_ironic_nodes(conn)
        if ironic_error and not quiet_err:
            print(f"Warning: Ironic bare metal list failed: {ironic_error}", file=sys.stderr)

    servers: list[dict[str, str]] = []
    servers_error: str | None = None
    if not args.no_servers:
        servers, servers_error = _openstack_servers_all_projects(conn)
        if servers_error and not quiet_err:
            print(f"Warning: Nova server list failed: {servers_error}", file=sys.stderr)

    by_uuid, by_host = _build_maas_indexes(maas_machines)
    matched, unmatched_os, maas_sids_from_hv = _match_hypervisors(
        hypervisors, maas_machines, by_uuid, by_host
    )
    server_maas_matches = (
        [] if args.no_servers else _match_servers_maas_system_id(servers, by_uuid)
    )
    maas_sids_from_servers = {m["maas_system_id"] for m in server_maas_matches if m.get("maas_system_id")}
    ironic_maas_matches: list[dict[str, Any]] = []
    maas_sids_from_ironic: set[str] = set()
    if ironic_nodes:
        ironic_maas_matches, maas_sids_from_ironic = _match_ironic_maas(
            ironic_nodes, by_uuid, by_host, by_serial
        )
    else:
        ironic_maas_matches = []
        maas_sids_from_ironic = set()
    ironic_hv_links = (
        _link_ironic_hypervisors(ironic_nodes, hypervisors) if ironic_nodes else []
    )
    ironic_nova_instance_links = (
        _link_ironic_nodes_to_nova_instances(ironic_nodes, servers)
        if ironic_nodes
        else []
    )
    ironic_nodes_with_instance_uuid = sum(
        1 for r in ironic_nova_instance_links if (r.get("instance_uuid") or "").strip()
    )
    ironic_instance_uuid_matched_nova_server = sum(
        1 for r in ironic_nova_instance_links if (r.get("nova_server_id") or "").strip()
    )
    hv_maas_via_serial: list[dict[str, Any]] = []
    maas_sids_from_hv_serial: set[str] = set()
    if ironic_nodes and by_serial:
        hv_maas_via_serial, maas_sids_from_hv_serial = (
            _match_hypervisor_maas_via_ironic_serial(
                hypervisors, ironic_nodes, by_serial
            )
        )
    all_matched_maas_sids = (
        maas_sids_from_hv
        | maas_sids_from_servers
        | maas_sids_from_ironic
        | maas_sids_from_hv_serial
    )

    unmatched_maas = [
        m
        for m in maas_machines
        if str(m.get("system_id") or "").strip() not in all_matched_maas_sids
    ]
    unmatched_maas_rows = [
        {
            "system_id": str(m.get("system_id") or ""),
            "hostname": str(m.get("hostname") or ""),
            "fqdn": str(m.get("fqdn") or ""),
            "status": str(m.get("status_name") or m.get("status") or ""),
        }
        for m in unmatched_maas
    ]

    ironic_catalog = _ironic_nodes_catalog(ironic_nodes)

    _ospid = (cfg.get("openstack_project_id") or "").strip()
    _ospname = (cfg.get("openstack_project_name") or "").strip()
    _os_scope = _ospid or _ospname or ""

    out = {
        "summary": {
            "openstack_project_id": _ospid,
            "openstack_project_name": _ospname,
            "openstack_project_scope": _os_scope,
            "openstack_region_name": (cfg.get("openstack_region_name") or "").strip(),
            "openstack_interface": (cfg.get("openstack_interface") or "").strip(),
            "openstack_hypervisor_count": len(hypervisors),
            "openstack_ironic_node_count": len(ironic_nodes),
            "openstack_ironic_error": ironic_error,
            "openstack_server_count": len(servers),
            "openstack_servers_error": servers_error,
            "maas_machine_count": len(maas_machines),
            "maas_serial_distinct_keys": len(by_serial),
            "maas_serial_collision_count": len(maas_serial_collisions),
            "hypervisor_match_count": len(matched),
            "hypervisor_maas_via_ironic_serial_count": len(hv_maas_via_serial),
            "ironic_maas_match_count": len(ironic_maas_matches),
            "ironic_hypervisor_uuid_link_count": len(ironic_hv_links),
            "ironic_nodes_with_instance_uuid_count": ironic_nodes_with_instance_uuid,
            "ironic_instance_uuid_matched_nova_server_count": ironic_instance_uuid_matched_nova_server,
            "server_maas_system_id_match_count": len(server_maas_matches),
            "maas_matched_total_distinct": len(all_matched_maas_sids),
            "unmatched_openstack_hypervisor_count": len(unmatched_os),
            "unmatched_maas_count": len(unmatched_maas),
        },
        "matches": matched,
        "hypervisor_matches": matched,
        "ironic_maas_matches": ironic_maas_matches,
        "ironic_nodes_catalog": ironic_catalog,
        "ironic_nova_instance_links": ironic_nova_instance_links,
        "ironic_hypervisor_uuid_links": ironic_hv_links,
        "hypervisor_maas_via_ironic_serial": hv_maas_via_serial,
        "maas_serial_index_collisions": maas_serial_collisions,
        "server_maas_system_id_matches": server_maas_matches,
        "unmatched_openstack_hypervisors": unmatched_os,
        "unmatched_maas_machines": unmatched_maas_rows,
    }

    if args.json:
        print(json.dumps(out, indent=2))
        return 0

    s = out["summary"]
    _psc = s.get("openstack_project_scope") or "(not set)"
    print(
        f"OpenStack scope: project={_psc!r}  region={s.get('openstack_region_name')!r}  "
        f"interface={s.get('openstack_interface')!r}"
    )
    print(
        f"Hypervisors: {s['openstack_hypervisor_count']}  "
        f"Ironic nodes: {s['openstack_ironic_node_count']}  "
        f"Servers: {s['openstack_server_count']}  "
        f"MAAS machines: {s['maas_machine_count']}"
    )
    print(
        f"MAAS serial index keys: {s['maas_serial_distinct_keys']}  "
        f"(collisions: {s['maas_serial_collision_count']})"
    )
    print(
        f"Hypervisor↔MAAS: {s['hypervisor_match_count']}  "
        f"Hypervisor→Ironic→serial→MAAS: {s['hypervisor_maas_via_ironic_serial_count']}  "
        f"Ironic↔MAAS: {s['ironic_maas_match_count']}  "
        f"Ironic UUID = hypervisor: {s['ironic_hypervisor_uuid_link_count']}  "
        f"Ironic instance→Nova: {s['ironic_instance_uuid_matched_nova_server_count']}/"
        f"{s['ironic_nodes_with_instance_uuid_count']}  "
        f"Server↔MAAS UUID: {s['server_maas_system_id_match_count']}  "
        f"Distinct MAAS system_ids hit: {s['maas_matched_total_distinct']}"
    )
    print(
        f"Unmatched hypervisors: {s['unmatched_openstack_hypervisor_count']}  "
        f"Unmatched MAAS: {s['unmatched_maas_count']}"
    )
    if not args.no_ironic:
        print()
        print(
            "=== Ironic API — all nodes you can list (uuid → name; same data as baremetal CLI/UI) ==="
        )
        if ironic_error:
            print(f"  (list error: {ironic_error})")
        _print_table(
            ["name", "uuid", "provision", "power", "instance_uuid"],
            [
                [
                    (r["name"] or "-")[:28],
                    (r["uuid"] or "")[:36],
                    (r["provision_state"] or "")[:14],
                    (r["power_state"] or "")[:10],
                    (r["instance_uuid"] or "-")[:14],
                ]
                for r in ironic_catalog
            ],
        )
        if not ironic_error and 0 < len(ironic_nodes) < len(hypervisors):
            print(
                "Note: Fewer Ironic nodes than Nova hypervisors. Ironic node:list is scoped by "
                "project (owner/lessee policy), unlike Nova server list all_projects. "
                f"Your OS_PROJECT_NAME/OS_PROJECT_ID is {_psc!r}; full fleet on kolla often uses "
                "'admin'.",
                file=sys.stderr,
            )
        print()
        print(
            "=== Ironic instance_uuid → Nova server (match Instance ID to baremetal node) ==="
        )
        if args.no_servers:
            print("  (Skipped: no server list — drop --no-servers to join instance UUIDs.)")
        _print_table(
            [
                "ironic_name",
                "node_uuid",
                "instance_uuid",
                "nova_server_name",
                "nova_status",
            ],
            [
                [
                    (r["ironic_name"] or "-")[:20],
                    (r["ironic_node_uuid"] or "")[:13] + "…",
                    (r["instance_uuid"] or "-")[:13] + ("…" if len(r["instance_uuid"] or "") > 13 else ""),
                    (r["nova_server_name"] or "-")[:22],
                    (r["nova_status"] or "-")[:10],
                ]
                for r in ironic_nova_instance_links
            ],
        )
        print()
        print(
            "=== Ironic ↔ MAAS (UUID, metadata UUID, serial, hostname) ==="
        )
        _print_table(
            ["method", "ironic_name", "serial", "maas_host", "maas_id"],
            [
                [
                    (r["match_method"] or "")[:18],
                    (r["ironic_name"] or "")[:20],
                    (r.get("matched_serial") or "-")[:16],
                    (r["maas_hostname"] or "")[:16],
                    (r["maas_system_id"] or "")[:12],
                ]
                for r in ironic_maas_matches
            ],
        )
        print()
        print(
            "=== Nova hypervisor (UUID) → Ironic → shared serial → MAAS hostname ==="
        )
        _print_table(
            ["hypervisor_display", "ironic_name", "serial", "maas_host", "maas_id"],
            [
                [
                    (r["os_hypervisor_name"] or r["os_hypervisor_hostname"])[:24],
                    (r["ironic_name"] or "")[:18],
                    (r["matched_serial"] or "")[:16],
                    (r["maas_hostname"] or "")[:16],
                    (r["maas_system_id"] or "")[:12],
                ]
                for r in hv_maas_via_serial
            ],
        )
        print()
        print(
            "=== Hypervisor UUID → Ironic name (Nova id/name/hostname == Ironic node uuid) ==="
        )
        _print_table(
            ["hv_field", "hypervisor", "ironic_name", "uuid"],
            [
                [
                    (r["match_field"] or "")[:14],
                    (r["hypervisor_name"] or r["hypervisor_hostname"])[:26],
                    (r["ironic_name"] or "")[:22],
                    (r["openstack_uuid"] or "")[:14],
                ]
                for r in ironic_hv_links
            ],
        )
    else:
        print()
        print("(Ironic bare metal API skipped: --no-ironic)")
    print()
    print("=== Hypervisor ↔ MAAS (UUID / hostname / IP) ===")
    _print_table(
        ["method", "os_name", "maas_hostname", "maas_system_id", "maas_status"],
        [
            [
                (r["match_method"] or "")[:22],
                (r["os_hypervisor_name"] or r["os_hypervisor_hostname"])[:26],
                (r["maas_hostname"] or "")[:22],
                (r["maas_system_id"] or "")[:14],
                (r["maas_status"] or "")[:12],
            ]
            for r in matched
        ],
    )
    if not args.no_servers:
        print()
        print("=== Instances whose hypervisor host field equals a MAAS system_id (UUID) ===")
        _print_table(
            ["method", "server", "maas_hostname", "maas_system_id", "field"],
            [
                [
                    (r["match_method"] or "")[:26],
                    (r["server_name"] or r["server_id"])[:26],
                    (r["maas_hostname"] or "")[:22],
                    (r["maas_system_id"] or "")[:14],
                    (r["openstack_field"] or "")[:18],
                ]
                for r in server_maas_matches
            ],
        )
    print()
    print("=== OpenStack hypervisors with no MAAS match ===")
    _print_table(
        ["name", "hostname", "id", "host_ip"],
        [
            [
                (r["name"] or "")[:28],
                (r["hostname"] or "")[:28],
                (r["id"] or "")[:14],
                r["host_ip"] or "-",
            ]
            for r in unmatched_os
        ],
    )
    if args.show_unmatched_maas:
        print()
        print("=== MAAS machines with no hypervisor match ===")
        _print_table(
            ["hostname", "fqdn", "system_id", "status"],
            [
                [
                    str(m.get("hostname") or "")[:24],
                    str(m.get("fqdn") or "")[:32],
                    str(m.get("system_id") or "")[:14],
                    str(m.get("status_name") or m.get("status") or "")[:12],
                ]
                for m in unmatched_maas
            ],
        )
    else:
        print()
        print("(Use --show-unmatched-maas to list MAAS machines with no hypervisor match.)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
