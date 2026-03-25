"""
OpenStack client wrapper using openstacksdk.

Fetches networks, subnets, floating IPs, plus optional Ironic/Neutron runtime NIC view
for bare-metal nodes (hostname + MAC + runtime IP + provider VLAN where available).
Supports optional multi-project scan (all Keystone projects or a comma-separated allow list).
"""

import logging
import re
from collections import defaultdict

from netbox_automation_plugin.sync.config.settings import OPENSTACK_DEFAULT_REGION_NAME

logger = logging.getLogger("netbox_automation_plugin.sync")

# Keystone project id (UUID)
_PROJECT_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


def fetch_openstack_data(config: dict):
    """
    Fetch networks, subnets, floating IPs from OpenStack. config is the result of get_sync_config().
    Returns a dict with:
      - networks: list of {id, name}
      - subnets: list of {id, cidr, network_id}
      - floating_ips: list of {floating_ip_address, fixed_ip_address, id, project_id, project_name}
      - error: str if connection failed
      - openstack_projects_scanned: int (optional) when multi-project mode ran
    """
    return fetch_openstack_data_for_config(config)


def _normalize_auth_url(auth_url: str) -> str:
    auth_url = (auth_url or "").rstrip("/")
    if auth_url and not auth_url.endswith("/v3"):
        auth_url = auth_url + "/v3"
    return auth_url


def _build_connect_kwargs(
    config: dict,
    *,
    project_id: str | None = None,
    project_name: str | None = None,
    use_config_project_if_unset: bool = True,
) -> dict:
    """Build kwargs for openstack.connect (no connect call)."""
    verify_tls = not config.get("openstack_insecure", False)
    auth_url = _normalize_auth_url(config.get("openstack_auth_url") or "")
    region = (
        (config.get("openstack_region_name") or "").strip()
        or OPENSTACK_DEFAULT_REGION_NAME
    )
    app_id = (config.get("openstack_application_credential_id") or "").strip()
    app_secret = (config.get("openstack_application_credential_secret") or "").strip()
    interface = config.get("openstack_interface") or "public"

    if app_id and app_secret:
        kwargs = {
            "auth_url": auth_url,
            "application_credential_id": app_id,
            "application_credential_secret": app_secret,
            "region_name": region,
            "interface": interface,
            "verify": verify_tls,
        }
    else:
        kwargs = {
            "auth_url": auth_url,
            "username": config.get("openstack_username") or "",
            "password": config.get("openstack_password") or "",
            "user_domain_name": config.get("openstack_user_domain_name") or "Default",
            "project_domain_name": config.get("openstack_project_domain_name") or "Default",
            "region_name": region,
            "interface": interface,
            "verify": verify_tls,
        }
        pid = (project_id or "").strip() if project_id is not None else ""
        pname = (project_name or "").strip() if project_name is not None else ""
        if not pid and not pname and use_config_project_if_unset:
            pid = (config.get("openstack_project_id") or "").strip()
            pname = (config.get("openstack_project_name") or "").strip()
        if pid:
            kwargs["project_id"] = pid
        else:
            kwargs["project_name"] = pname or ""

    return kwargs


def _collect_neutron(conn, project_label: str) -> tuple[list, list, list]:
    networks = []
    subnets = []
    floating_ips = []

    for net in conn.network.networks():
        networks.append({
            "id": net.id,
            "name": net.name or net.id,
            "is_router_external": bool(getattr(net, "is_router_external", False)),
            "provider_network_type": getattr(net, "provider_network_type", "") or "",
            "provider_segmentation_id": str(getattr(net, "provider_segmentation_id", "") or ""),
            "provider_physical_network": getattr(net, "provider_physical_network", "") or "",
        })

    for sn in conn.network.subnets():
        tid = getattr(sn, "tenant_id", None) or getattr(sn, "project_id", None) or ""
        subnets.append({
            "id": sn.id,
            "cidr": getattr(sn, "cidr", ""),
            "network_id": getattr(sn, "network_id", ""),
            "name": getattr(sn, "name", "") or "",
            "description": getattr(sn, "description", "") or "",
            "gateway_ip": getattr(sn, "gateway_ip", "") or "",
            "ip_version": str(getattr(sn, "ip_version", "") or ""),
            "enable_dhcp": bool(getattr(sn, "is_dhcp_enabled", False)),
            "project_id": str(tid)[:36] if tid else "",
            "project_name": project_label or "",
        })

    for fip in conn.network.ips(floating=True):
        tid = getattr(fip, "tenant_id", None) or getattr(fip, "project_id", None) or ""
        floating_ips.append({
            "floating_ip_address": getattr(fip, "floating_ip_address", ""),
            "fixed_ip_address": getattr(fip, "fixed_ip_address", "") or "-",
            "id": getattr(fip, "id", ""),
            "project_id": str(tid)[:36] if tid else "",
            "project_name": project_label,
            "floating_network_id": getattr(fip, "floating_network_id", "") or "",
        })

    return networks, subnets, floating_ips


def _collect_subnet_consumers(conn, subnets: list[dict], networks: list[dict]) -> list[dict]:
    """
    Summarize subnet consumers from Neutron ports (+ Nova server names for compute ports).
    This powers role inference using runtime consumers rather than naming heuristics.
    """
    try:
        nw = conn.network
    except Exception:
        return []

    subnet_ids = {str(s.get("id") or "").strip() for s in (subnets or []) if s.get("id")}
    if not subnet_ids:
        return []

    net_by_id = {(n.get("id") or ""): n for n in (networks or []) if n.get("id")}

    server_name_by_id: dict[str, str] = {}
    try:
        for srv in conn.compute.servers(details=False):
            sid = str(getattr(srv, "id", "") or "").strip()
            if sid:
                server_name_by_id[sid] = str(getattr(srv, "name", "") or "").strip()
    except Exception:
        server_name_by_id = {}

    by_sid: dict[str, dict] = {}
    for sid in subnet_ids:
        by_sid[sid] = {
            "subnet_id": sid,
            "ports_total": 0,
            "owners": {},
            "router_gateway_ports": 0,
            "router_interface_ports": 0,
            "floatingip_ports": 0,
            "compute_ports": 0,
            "service_ports": 0,
            "dhcp_ports": 0,
            "server_storage_hits": 0,
            "server_vm_hits": 0,
        }

    for p in nw.ports():
        owner = str(getattr(p, "device_owner", "") or "").strip().lower()
        device_id = str(getattr(p, "device_id", "") or "").strip()
        fixed_ips = getattr(p, "fixed_ips", None) or []
        for f in fixed_ips:
            if not isinstance(f, dict):
                continue
            sid = str(f.get("subnet_id") or "").strip()
            if sid not in by_sid:
                continue
            row = by_sid[sid]
            row["ports_total"] += 1
            row["owners"][owner] = int(row["owners"].get(owner, 0)) + 1
            if owner.startswith("network:router_gateway"):
                row["router_gateway_ports"] += 1
            elif owner.startswith("network:router_interface"):
                row["router_interface_ports"] += 1
            elif owner.startswith("network:floatingip"):
                row["floatingip_ports"] += 1
            elif owner.startswith("network:dhcp"):
                row["dhcp_ports"] += 1
            elif owner.startswith("compute:") or owner == "baremetal:none":
                row["compute_ports"] += 1
                nm = server_name_by_id.get(device_id, "").lower()
                if any(k in nm for k in ("ceph", "storage", "swift", "cinder", "nfs", "gluster")):
                    row["server_storage_hits"] += 1
                else:
                    row["server_vm_hits"] += 1
            else:
                row["service_ports"] += 1

    out: list[dict] = []
    for s in (subnets or []):
        sid = str(s.get("id") or "").strip()
        if sid not in by_sid:
            continue
        row = by_sid[sid]
        net = net_by_id.get(str(s.get("network_id") or "").strip(), {})
        owners_sorted = sorted(
            ((k, v) for k, v in (row.get("owners") or {}).items() if k),
            key=lambda kv: kv[1],
            reverse=True,
        )
        top_owners = ", ".join(f"{k}:{v}" for k, v in owners_sorted[:3]) or "-"
        # Consumer-first bucket inference (no network/project name matching).
        bucket = "vm"
        reason = "compute consumers dominate"
        confidence = "medium"
        if bool(net.get("is_router_external")) or row["router_gateway_ports"] > 0 or row["floatingip_ports"] > 0:
            bucket = "public"
            reason = "external/router-gateway/floating-IP consumers present"
            confidence = "high"
        elif row["server_storage_hits"] > 0 and row["server_storage_hits"] >= row["server_vm_hits"]:
            bucket = "storage"
            reason = "compute consumers are mostly storage-class nodes"
            confidence = "medium"
        elif row["service_ports"] > 0 and row["compute_ports"] == 0:
            bucket = "admin"
            reason = "non-compute service consumers only"
            confidence = "low"

        out.append({
            "subnet_id": sid,
            "role_bucket": bucket,
            "role_reason": reason,
            "confidence": confidence,
            "ports_total": row["ports_total"],
            "top_owners": top_owners,
        })
    return out


def _collect_runtime_nics(conn, networks: list[dict]) -> list[dict]:
    """
    Best-effort runtime NIC map from Ironic + Neutron:
      hostname/node_uuid + MAC + runtime fixed IP(s) + runtime provider VLAN (if VLAN provider network).
    """
    out: list[dict] = []
    try:
        bm = conn.baremetal
        nw = conn.network
    except Exception:
        return out

    net_by_id = {(n.get("id") or ""): n for n in (networks or []) if n.get("id")}

    # Cache Neutron ports by instance_uuid to avoid repeated queries.
    ports_by_instance: dict[str, list[dict]] = {}

    def _instance_ports(instance_uuid: str) -> list[dict]:
        if instance_uuid in ports_by_instance:
            return ports_by_instance[instance_uuid]
        rows: list[dict] = []
        try:
            for p in nw.ports(device_id=instance_uuid):
                fixed_ips = getattr(p, "fixed_ips", None) or []
                ip_list = []
                for f in fixed_ips:
                    if isinstance(f, dict):
                        ip = str(f.get("ip_address") or "").strip()
                        if ip:
                            ip_list.append(ip)
                rows.append({
                    "id": getattr(p, "id", "") or "",
                    "mac": str(getattr(p, "mac_address", "") or "").strip().lower(),
                    "ips": ip_list,
                    "network_id": str(getattr(p, "network_id", "") or "").strip(),
                })
        except Exception:
            rows = []
        ports_by_instance[instance_uuid] = rows
        return rows

    try:
        ports_by_node: dict[str, list[dict]] = defaultdict(list)
        for p in bm.ports(details=True):
            node_uuid = str(getattr(p, "node_uuid", None) or getattr(p, "node_id", None) or "").strip()
            if not node_uuid:
                continue
            internal = getattr(p, "internal_info", None)
            if not isinstance(internal, dict):
                internal = {}
            ports_by_node[node_uuid].append({
                "mac": str(getattr(p, "address", "") or "").strip().lower(),
                "physical_network": str(getattr(p, "physical_network", "") or "").strip(),
                "tenant_vif_port_id": str(internal.get("tenant_vif_port_id") or "").strip(),
            })

        for n in bm.nodes(details=True):
            node_uuid = str(getattr(n, "id", "") or "").strip()
            if not node_uuid:
                continue
            hostname = str(getattr(n, "name", "") or "").strip()
            instance_uuid = str(
                getattr(n, "instance_uuid", None) or getattr(n, "instance_id", None) or ""
            ).strip()

            nports = ports_by_node.get(node_uuid) or []
            ip_ports = _instance_ports(instance_uuid) if instance_uuid else []
            ip_by_port_id = {r.get("id", ""): r for r in ip_ports if r.get("id")}
            ip_by_mac = {r.get("mac", ""): r for r in ip_ports if r.get("mac")}

            for bp in nports:
                mac = bp.get("mac", "")
                if not mac:
                    continue
                chosen = None
                vif_id = bp.get("tenant_vif_port_id", "")
                if vif_id and vif_id in ip_by_port_id:
                    chosen = ip_by_port_id[vif_id]
                elif mac in ip_by_mac:
                    chosen = ip_by_mac[mac]

                network_id = (chosen or {}).get("network_id", "")
                net = net_by_id.get(network_id, {})
                net_type = str(net.get("provider_network_type") or "").strip().lower()
                seg = str(net.get("provider_segmentation_id") or "").strip()
                runtime_vlan = seg if net_type == "vlan" and seg else ""

                out.append({
                    "hostname": hostname,
                    "node_uuid": node_uuid,
                    "instance_uuid": instance_uuid,
                    "mac": mac,
                    "os_mac": mac,
                    "os_ips": list((chosen or {}).get("ips") or []),
                    "os_ip": ", ".join((chosen or {}).get("ips") or []) if chosen else "",
                    "network_id": network_id,
                    "network_type": net_type,
                    "provider_physical_network": str(
                        net.get("provider_physical_network") or bp.get("physical_network") or ""
                    ),
                    "os_runtime_vlan": runtime_vlan,
                    "tenant_vif_port_id": vif_id,
                })
    except Exception as e:
        logger.info("OpenStack: runtime NIC enrichment skipped: %s", e)

    return out


def _collect_runtime_bmc(conn) -> list[dict]:
    """
    Best-effort BMC view from Ironic node details:
      hostname, node_uuid, driver/power interfaces, vendor, redfish/ipmi endpoint and parsed host.
    """
    out: list[dict] = []
    try:
        bm = conn.baremetal
    except Exception:
        return out

    for n in bm.nodes(details=True):
        try:
            node_uuid = str(getattr(n, "id", "") or "").strip()
            hostname = str(getattr(n, "name", "") or "").strip()
            driver = str(getattr(n, "driver", "") or "").strip().lower()
            power_if = str(getattr(n, "power_interface", "") or "").strip().lower()
            mgmt_if = str(getattr(n, "management_interface", "") or "").strip().lower()
            props = getattr(n, "properties", None)
            if not isinstance(props, dict):
                props = {}
            vendor = str(props.get("vendor") or "").strip()

            driver_info = getattr(n, "driver_info", None)
            if not isinstance(driver_info, dict):
                driver_info = {}

            endpoint = ""
            bmc_host = ""
            for k in ("redfish_address", "ipmi_address", "ilo_address", "address"):
                v = str(driver_info.get(k) or "").strip()
                if not v:
                    continue
                endpoint = v
                m = re.match(r"^https?://([^/]+)", v, re.I)
                bmc_host = (m.group(1).strip() if m else v).strip()
                bmc_host = bmc_host.split(":", 1)[0]
                break

            out.append({
                "hostname": hostname,
                "node_uuid": node_uuid,
                "driver": driver,
                "power_interface": power_if,
                "management_interface": mgmt_if,
                "vendor": vendor,
                "provision_state": str(getattr(n, "provision_state", "") or "").strip().lower(),
                "power_state": str(getattr(n, "power_state", "") or "").strip().lower(),
                "maintenance": bool(getattr(n, "maintenance", False)),
                "instance_uuid": str(
                    getattr(n, "instance_uuid", None) or getattr(n, "instance_id", None) or ""
                ).strip(),
                "os_bmc_endpoint": endpoint,
                "os_bmc_ip": bmc_host,
            })
        except Exception:
            continue
    return out


def _merge_openstack_into_maps(
    nets_by_id: dict,
    subs_by_id: dict,
    fips_by_key: dict,
    runtime_by_key: dict,
    bmc_by_key: dict,
    subnet_consumers_by_sid: dict,
    networks: list,
    subnets: list,
    floating_ips: list,
    runtime_nics: list,
    runtime_bmc: list,
    subnet_consumers: list,
) -> None:
    for n in networks:
        nid = n.get("id")
        if nid:
            nets_by_id[nid] = n
    for s in subnets:
        sid = s.get("id")
        if sid:
            subs_by_id[sid] = s
    for f in floating_ips:
        key = (f.get("id") or "").strip() or (f.get("floating_ip_address") or "").strip()
        if key:
            fips_by_key[key] = f
    for r in runtime_nics:
        key = (
            (r.get("hostname") or "").strip().lower(),
            (r.get("mac") or "").strip().lower(),
            (r.get("node_uuid") or "").strip().lower(),
        )
        if key[0] and key[1] and key[2]:
            runtime_by_key[key] = r
    for b in runtime_bmc:
        key = (b.get("hostname") or "").strip().lower()
        if key:
            bmc_by_key[key] = b
    for sc in subnet_consumers:
        sid = (sc.get("subnet_id") or "").strip()
        if sid:
            subnet_consumers_by_sid[sid] = sc


def _allowlist_matches_project(allow_norm: set, proj_id: str, proj_name: str) -> bool:
    if proj_id and proj_id.lower() in allow_norm:
        return True
    if proj_name and proj_name.lower() in allow_norm:
        return True
    return False


def _specs_from_allowlist_tokens(tokens: list) -> list[dict]:
    """Each token: UUID -> project_id, else project_name."""
    out = []
    for t in tokens:
        t = (t or "").strip()
        if not t:
            continue
        if _PROJECT_ID_RE.match(t):
            out.append({"id": t, "name": "", "label": t[:12]})
        else:
            out.append({"id": "", "name": t, "label": t})
    return out


def _list_keystone_projects(conn) -> list[dict] | None:
    """Return [{'id','name','label'}, ...] or None if listing failed."""
    try:
        rows = []
        for p in conn.identity.projects():
            pid = getattr(p, "id", "") or ""
            pname = getattr(p, "name", "") or ""
            rows.append({
                "id": pid,
                "name": pname,
                "label": pname or pid[:12] or pid,
            })
        return rows
    except Exception as e:
        logger.warning("OpenStack: could not list Keystone projects: %s", e)
        return None


def _fetch_single_project(openstack, config: dict) -> dict:
    """Original single-scope behavior."""
    result = {
        "networks": [],
        "subnets": [],
        "floating_ips": [],
        "runtime_nics": [],
        "runtime_bmc": [],
        "subnet_consumers": [],
        "error": None,
        "openstack_projects_scanned": 1,
    }
    kwargs = _build_connect_kwargs(config, use_config_project_if_unset=True)
    conn = openstack.connect(**kwargs)
    project_label = (
        (config.get("openstack_project_name") or "").strip()
        or (config.get("openstack_project_id") or "").strip()[:12]
        or "-"
    )
    n, s, f = _collect_neutron(conn, project_label)
    rn = _collect_runtime_nics(conn, n)
    rb = _collect_runtime_bmc(conn)
    sc = _collect_subnet_consumers(conn, s, n)
    result["networks"] = n
    result["subnets"] = s
    result["floating_ips"] = f
    result["runtime_nics"] = rn
    result["runtime_bmc"] = rb
    result["subnet_consumers"] = sc
    return result


def _fetch_multi_project(openstack, config: dict, audit_all: bool, allowlist: list) -> dict:
    """
    Scan multiple projects; merge networks/subnets/FIPs with dedupe by id (FIP by id or address).
    """
    result = {
        "networks": [],
        "subnets": [],
        "floating_ips": [],
        "runtime_nics": [],
        "runtime_bmc": [],
        "subnet_consumers": [],
        "error": None,
        "openstack_projects_scanned": 0,
    }
    nets_by_id: dict = {}
    subs_by_id: dict = {}
    fips_by_key: dict = {}
    runtime_by_key: dict = {}
    bmc_by_key: dict = {}
    subnet_consumers_by_sid: dict = {}
    scan_errors: list[str] = []

    allow_tokens = [str(x).strip() for x in (allowlist or []) if str(x).strip()]
    allow_norm = {t.lower() for t in allow_tokens}

    # Bootstrap connection (config project) for Keystone list when audit_all
    try:
        base_kwargs = _build_connect_kwargs(config, use_config_project_if_unset=True)
        base_conn = openstack.connect(**base_kwargs)
    except Exception as e:
        logger.exception("OpenStack multi-project: initial connect failed")
        result["error"] = str(e)
        return result

    specs: list[dict] = []

    if audit_all:
        listed = _list_keystone_projects(base_conn)
        if listed is None:
            # e.g. app cred cannot list — fall back to single project
            logger.info(
                "OpenStack: AUDIT_ALL_PROJECTS set but project list unavailable; "
                "using single project from config."
            )
            return _fetch_single_project(openstack, config)

        if allow_norm:
            specs = [
                sp for sp in listed
                if _allowlist_matches_project(allow_norm, sp.get("id", ""), sp.get("name", ""))
            ]
        else:
            specs = list(listed)

        if not specs:
            msg = "OpenStack: no projects to scan (empty Keystone list or allowlist filter)."
            logger.warning(msg)
            result["error"] = msg
            return result
    else:
        # Allowlist-only mode (no Keystone list)
        specs = _specs_from_allowlist_tokens(allow_tokens)
        if not specs:
            result["error"] = "OpenStack: OPENSTACK_PROJECT_ALLOWLIST is empty."
            return result

    for sp in specs:
        pid = (sp.get("id") or "").strip()
        pname = (sp.get("name") or "").strip()
        label = (sp.get("label") or pname or pid[:12] or pid or "-")

        try:
            kwargs = _build_connect_kwargs(
                config,
                project_id=pid if pid else None,
                project_name=pname if pname else None,
                use_config_project_if_unset=False,
            )
            # If both empty (shouldn't happen), skip
            if not kwargs.get("project_id") and not kwargs.get("project_name"):
                scan_errors.append(f"project {label!r}: missing project id/name")
                continue
            conn = openstack.connect(**kwargs)
            n, s, f = _collect_neutron(conn, label)
            rn = _collect_runtime_nics(conn, n)
            rb = _collect_runtime_bmc(conn)
            sc = _collect_subnet_consumers(conn, s, n)
            _merge_openstack_into_maps(
                nets_by_id,
                subs_by_id,
                fips_by_key,
                runtime_by_key,
                bmc_by_key,
                subnet_consumers_by_sid,
                n,
                s,
                f,
                rn,
                rb,
                sc,
            )
            result["openstack_projects_scanned"] += 1
        except Exception as e:
            err = f"{label}: {e}"
            logger.warning("OpenStack: Neutron fetch skipped for project %s", err)
            scan_errors.append(err)

    result["networks"] = list(nets_by_id.values())
    result["subnets"] = list(subs_by_id.values())
    result["floating_ips"] = list(fips_by_key.values())
    result["runtime_nics"] = list(runtime_by_key.values())
    result["runtime_bmc"] = list(bmc_by_key.values())
    result["subnet_consumers"] = list(subnet_consumers_by_sid.values())

    if result["openstack_projects_scanned"] == 0 and scan_errors:
        result["error"] = "; ".join(scan_errors[:5])
        if len(scan_errors) > 5:
            result["error"] += f" … (+{len(scan_errors) - 5} more)"
    elif scan_errors:
        logger.info(
            "OpenStack: multi-project scan completed with %s project(s) ok, %s warning(s)",
            result["openstack_projects_scanned"],
            len(scan_errors),
        )

    return result


def fetch_openstack_data_for_config(config: dict):
    """
    Fetch OpenStack data using a config dict that has openstack_* keys
    (e.g. one entry from get_openstack_configs()). Same return shape as fetch_openstack_data().
    """
    result = {
        "networks": [],
        "subnets": [],
        "floating_ips": [],
        "runtime_nics": [],
        "runtime_bmc": [],
        "subnet_consumers": [],
        "error": None,
    }

    auth_url = config.get("openstack_auth_url") or ""
    if not auth_url:
        result["error"] = "OpenStack auth URL not set (OS_AUTH_URL or OPENSTACK_AUTH_URL)"
        return result

    try:
        import openstack
    except ImportError:
        result["error"] = (
            "openstacksdk is not installed. Add it to plugin_requirements.txt and reinstall the plugin."
        )
        return result

    audit_all = bool(config.get("openstack_audit_all_projects"))
    allowlist = config.get("openstack_project_allowlist") or []
    if isinstance(allowlist, str):
        allowlist = [p.strip() for p in allowlist.split(",") if p.strip()]

    use_multi = audit_all or bool(allowlist)

    try:
        if use_multi:
            inner = _fetch_multi_project(openstack, config, audit_all, list(allowlist))
        else:
            inner = _fetch_single_project(openstack, config)
        result.update(inner)
    except Exception as e:
        os_config_exc = None
        try:
            from openstack.exceptions import ConfigException as os_config_exc
        except ImportError:
            pass

        msg = str(e).strip() or repr(e)
        is_config_exc = os_config_exc is not None and isinstance(e, os_config_exc)
        if is_config_exc:
            # Misconfigured clouds.yml / env — full traceback is noise in NetBox logs.
            logger.warning("OpenStack fetch failed (config): %s", msg)
        else:
            logger.exception("OpenStack fetch failed")

        low = msg.lower()
        region_hint = ("region" in low and "not found" in low) or "region name" in low
        if region_hint:
            kwargs = _build_connect_kwargs(config, use_config_project_if_unset=True)
            rn = kwargs.get("region_name", "?")
            msg += (
                f" — Using region_name={rn!r}. Set OS_REGION_NAME (or OPENSTACK_REGION_NAME) "
                "on the NetBox container to match `openstack region list`, then restart."
            )
        elif is_config_exc:
            msg += (
                " — Check OPENSTACK_* / OS_* env on the NetBox container (auth_url, region, "
                "project, application credential or user/password) match an `openstack cloud` that works."
            )
        result["error"] = msg
        if "openstack_projects_scanned" not in result:
            result["openstack_projects_scanned"] = 0

    return result


def fetch_all_openstack_data(configs: list):
    """
    Fetch from multiple OpenStack configs (e.g. from get_openstack_configs()).
    Returns list of {"label": str, "data": dict}; each data has networks, subnets, floating_ips, error.
    """
    out = []
    for c in configs:
        label = c.get("label") or "OpenStack"
        out.append({"label": label, "data": fetch_openstack_data_for_config(c)})
    return out
