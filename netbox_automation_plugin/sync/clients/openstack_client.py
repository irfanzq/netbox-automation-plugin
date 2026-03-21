"""
OpenStack client wrapper using openstacksdk.

Fetches networks, subnets, floating IPs. Used for drift audit and OpenStack visibility sync.
Supports optional multi-project scan (all Keystone projects or a comma-separated allow list).
"""

import logging
import re

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
        networks.append({"id": net.id, "name": net.name or net.id})

    for sn in conn.network.subnets():
        subnets.append({
            "id": sn.id,
            "cidr": getattr(sn, "cidr", ""),
            "network_id": getattr(sn, "network_id", ""),
            "name": getattr(sn, "name", "") or "",
            "description": getattr(sn, "description", "") or "",
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


def _merge_openstack_into_maps(
    nets_by_id: dict,
    subs_by_id: dict,
    fips_by_key: dict,
    networks: list,
    subnets: list,
    floating_ips: list,
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
    result["networks"] = n
    result["subnets"] = s
    result["floating_ips"] = f
    return result


def _fetch_multi_project(openstack, config: dict, audit_all: bool, allowlist: list) -> dict:
    """
    Scan multiple projects; merge networks/subnets/FIPs with dedupe by id (FIP by id or address).
    """
    result = {
        "networks": [],
        "subnets": [],
        "floating_ips": [],
        "error": None,
        "openstack_projects_scanned": 0,
    }
    nets_by_id: dict = {}
    subs_by_id: dict = {}
    fips_by_key: dict = {}
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
            _merge_openstack_into_maps(nets_by_id, subs_by_id, fips_by_key, n, s, f)
            result["openstack_projects_scanned"] += 1
        except Exception as e:
            err = f"{label}: {e}"
            logger.warning("OpenStack: Neutron fetch skipped for project %s", err)
            scan_errors.append(err)

    result["networks"] = list(nets_by_id.values())
    result["subnets"] = list(subs_by_id.values())
    result["floating_ips"] = list(fips_by_key.values())

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
    result = {"networks": [], "subnets": [], "floating_ips": [], "error": None}

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
