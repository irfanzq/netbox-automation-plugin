"""
MAAS client wrapper using python-libmaas.

Fetches machines, interfaces (NICs), zones, resource pools.
Used for drift audit and (later) MAAS -> NetBox reconciliation.

MAAS uses FQDN (hostname + domain, e.g. se-h1-23-gpu.pxe.spruce.whitefiber.com).
NetBox devices use short hostname only (e.g. se-h1-23-gpu).
We normalize MAAS hostname to the short name (part before first dot) for matching.
"""

import asyncio
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

logger = logging.getLogger("netbox_automation_plugin.sync")

_maas_insecure_warn_done = False


def _silence_urllib3_insecure_when_maas_tls_skipped():
    """
    MAAS_INSECURE=true uses verify=False on many requests per machine; urllib3
    logs InsecureRequestWarning each time. Silence once per process when intentional.
    """
    global _maas_insecure_warn_done
    if _maas_insecure_warn_done:
        return
    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass
    _maas_insecure_warn_done = True


def _bmc_ip_from_power(power_parameters, power_type=None) -> str:
    """
    Best-effort BMC / power endpoint from MAAS power_parameters or op=power_parameters JSON.
    Same fields as test_maas_libmaas.py bmc_from_power (IPMI, Redfish, etc.).
    """
    if not isinstance(power_parameters, dict):
        return ""
    addr = ""
    for key in (
        "power_address",
        "power_host",
        "redfish_address",
        "redfish_host",
        "bmc_address",
        "power_ip",
        "ip_address",
    ):
        raw = power_parameters.get(key)
        if raw is None:
            continue
        addr = str(raw).strip()
        if addr and addr.lower() not in ("none", "null", "-"):
            break
    else:
        addr = ""
    if not addr:
        return ""
    try:
        if "://" in addr:
            host = (urlparse(addr).hostname or "").strip()
            if host:
                return host[:64]
    except Exception:
        pass
    first = addr.split()[0]
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$", first)
    if m:
        return m.group(1)
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", addr)
    if m:
        return m.group(1)
    return first[:64] if len(first) <= 64 else first[:62] + ".."


def _bmc_from_machine_or_power_op(j: dict) -> str:
    """power_parameters may be nested or op=power_parameters may return flat keys."""
    if not isinstance(j, dict):
        return ""
    pp = j.get("power_parameters")
    for candidate in (pp, j):
        if isinstance(candidate, dict) and candidate:
            bmc = _bmc_ip_from_power(candidate, j.get("power_type"))
            if bmc:
                return bmc
    return ""


def _maas_rest_fetch_bmc(maas_url: str, api_key: str, system_id: str, verify_tls: bool) -> str:
    """
    BMC from MAAS: normal machine read often omits power_parameters (null) for non-admin keys.
    MAAS also exposes machine power-parameters via op=power_parameters (admin only); see
    https://maas.io/docs/machine — same for python-libmaas vs raw REST.
    """
    parts = api_key.split(":", 2)
    if len(parts) != 3 or not system_id:
        return ""
    ck, tk, ts = parts[0], parts[1], parts[2]
    base = _maas_rest_base(maas_url)
    try:
        import requests
        from requests_oauthlib import OAuth1
    except ImportError:
        return ""
    auth = OAuth1(ck, "", tk, ts, signature_method="PLAINTEXT")

    for path in (f"{base}/api/2.0/machines/{system_id}/", f"{base}/api/2.0/nodes/{system_id}/"):
        try:
            r = requests.get(path, auth=auth, verify=verify_tls, timeout=45)
            if r.status_code == 200:
                j = r.json()
                if isinstance(j, dict):
                    bmc = _bmc_from_machine_or_power_op(j)
                    if bmc:
                        return bmc
        except Exception:
            logger.debug("MAAS BMC fetch %s", path, exc_info=True)

    # Admin-only: full power config including IPMI power_address (403 otherwise)
    for path in (f"{base}/api/2.0/machines/{system_id}/", f"{base}/api/2.0/nodes/{system_id}/"):
        try:
            r = requests.get(
                path,
                params={"op": "power_parameters"},
                auth=auth,
                verify=verify_tls,
                timeout=45,
            )
            if r.status_code == 403:
                logger.debug(
                    "MAAS op=power_parameters returned 403 for %s — use admin MAAS API key for BMC IP",
                    system_id,
                )
                continue
            if r.status_code != 200:
                continue
            j = r.json()
            if isinstance(j, dict):
                bmc = _bmc_from_machine_or_power_op(j)
                if bmc:
                    return bmc
        except Exception:
            logger.debug("MAAS power_parameters op %s", path, exc_info=True)

    try:
        r = requests.get(
            f"{base}/api/2.0/machines/",
            params={"op": "power_parameters", "id": system_id},
            auth=auth,
            verify=verify_tls,
            timeout=45,
        )
        if r.status_code == 200:
            j = r.json()
            if isinstance(j, dict):
                bmc = _bmc_from_machine_or_power_op(j)
                if bmc:
                    return bmc
            if isinstance(j, list) and j and isinstance(j[0], dict):
                bmc = _bmc_from_machine_or_power_op(j[0])
                if bmc:
                    return bmc
    except Exception:
        logger.debug("MAAS machines op=power_parameters", exc_info=True)

    return ""


def _maas_rest_base(maas_url: str) -> str:
    base = maas_url.rstrip("/")
    if not base.lower().endswith("maas"):
        base = base + "/MAAS" if "/MAAS" not in base.upper() else base
    return base


def _fetch_maas_fabric_catalog(maas_url: str, api_key: str, verify_tls: bool) -> dict:
    """
    GET /api/2.0/fabrics/ — map fabric id and name -> display name.
    MAAS interface JSON often has fabric as URL or slug; vlan.fabric is rarely a {name:} dict.
    """
    parts = api_key.split(":", 2)
    if len(parts) != 3:
        return {}
    ck, tk, ts = parts[0], parts[1], parts[2]
    base = _maas_rest_base(maas_url)
    try:
        import requests
        from requests_oauthlib import OAuth1
    except ImportError:
        logger.warning("MAAS fabric catalog skipped (install requests requests_oauthlib)")
        return {}
    auth = OAuth1(ck, "", tk, ts, signature_method="PLAINTEXT")
    try:
        r = requests.get(f"{base}/api/2.0/fabrics/", auth=auth, verify=verify_tls, timeout=120)
        if r.status_code != 200:
            logger.warning("MAAS fabrics list HTTP %s", r.status_code)
            return {}
    except Exception:
        logger.debug("MAAS fabrics fetch failed", exc_info=True)
        return {}
    out = {}
    for fab in r.json() or []:
        if not isinstance(fab, dict):
            continue
        fid = str(fab.get("id", ""))
        name = (fab.get("name") or fid or "").strip()
        if fid:
            out[fid] = name or fid
        if name:
            out[name.lower()] = name
    return out


def _fabric_from_rest_ifaces(items: list, fabric_catalog: dict | None = None) -> str:
    """Resolve fabric from MAAS interface JSON (interface.fabric string/URL + vlan.fabric)."""
    catalog = fabric_catalog or {}

    def add(seen: list, n: str) -> None:
        n = (n or "").strip()
        if n and n not in seen:
            seen.append(n)

    seen = []
    for item in items:
        if not isinstance(item, dict):
            continue
        fab = item.get("fabric")
        if isinstance(fab, str) and fab.strip():
            s = fab.strip()
            if "/" in s:
                key = s.rstrip("/").split("/")[-1]
                add(seen, catalog.get(key, key))
            else:
                add(seen, catalog.get(s, catalog.get(s.lower(), s)))
        elif isinstance(fab, dict):
            add(seen, str(fab.get("name") or fab.get("id") or ""))
        vlan = item.get("vlan")
        if isinstance(vlan, dict):
            vf = vlan.get("fabric")
            if isinstance(vf, dict) and vf.get("name"):
                add(seen, str(vf["name"]))
            elif isinstance(vf, str) and vf.strip():
                key = vf.rstrip("/").split("/")[-1]
                add(seen, catalog.get(key, key))
    if not seen:
        return "-"
    return seen[0] if len(seen) == 1 else ", ".join(seen[:3])


def _enrich_machines_fabric_rest(
    machines: list,
    maas_url: str,
    maas_api_key: str,
    verify_tls: bool,
    fabric_catalog: dict,
) -> None:
    """Fill fabric_name from machine detail REST when still '-' (libmaas often omits fabric on VLAN)."""
    need = [
        i
        for i, mm in enumerate(machines)
        if mm.get("system_id") and (mm.get("fabric_name") or "-").strip() in ("-", "")
    ]
    if not need:
        return

    def fetch_idx(i: int) -> tuple:
        mm = machines[i]
        sid = mm["system_id"]
        base = _maas_rest_base(maas_url)
        parts = maas_api_key.split(":", 2)
        if len(parts) != 3:
            return i, "-"
        ck, tk, ts = parts[0], parts[1], parts[2]
        try:
            import requests
            from requests_oauthlib import OAuth1
        except ImportError:
            return i, "-"
        auth = OAuth1(ck, "", tk, ts, signature_method="PLAINTEXT")
        for path in (f"{base}/api/2.0/machines/{sid}/", f"{base}/api/2.0/nodes/{sid}/"):
            try:
                r = requests.get(path, auth=auth, verify=verify_tls, timeout=90)
                if r.status_code != 200:
                    continue
                machine = r.json()
                arr = _embedded_interface_arrays(machine)
                if arr:
                    return i, _fabric_from_rest_ifaces(arr, fabric_catalog)
            except Exception:
                logger.debug("MAAS fabric enrich %s", path, exc_info=True)
        return i, "-"

    max_workers = min(16, max(4, len(need)))
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            for fut in as_completed([ex.submit(fetch_idx, i) for i in need]):
                try:
                    i, fab = fut.result()
                    if fab and fab != "-":
                        machines[i]["fabric_name"] = fab
                except Exception:
                    pass
    except Exception:
        logger.debug("Fabric enrichment pool failed", exc_info=True)


def _enrich_machines_bmc_rest(
    machines: list, maas_url: str, maas_api_key: str, verify_tls: bool
) -> None:
    """Fill bmc_ip via REST for machines missing it (parallel)."""
    need = [
        i
        for i, mm in enumerate(machines)
        if mm.get("system_id") and not (str(mm.get("bmc_ip") or "").strip())
    ]
    if not need:
        return

    def fetch_idx(i: int) -> tuple:
        mm = machines[i]
        return (
            i,
            _maas_rest_fetch_bmc(maas_url, maas_api_key, mm["system_id"], verify_tls),
        )

    # One GET chain per machine (read + op=power_parameters); parallelize for UI drift latency
    max_workers = min(32, max(8, len(need)))
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(fetch_idx, i) for i in need]
            for fut in as_completed(futures):
                try:
                    i, bmc = fut.result()
                    if bmc:
                        machines[i]["bmc_ip"] = bmc
                except Exception:
                    pass
    except Exception:
        logger.debug("BMC enrichment pool failed", exc_info=True)


def _ip_host_only(addr: str) -> str:
    if not addr:
        return ""
    return str(addr).split("/", 1)[0].strip().lower()


def _ifaces_from_viscera_list(iface_list):
    """
    Build interface dicts from python-libmaas Interface objects.
    Each NIC is isolated in try/except so one broken object does not zero out the whole machine.
    """
    rows = []
    for iface in iface_list:
        try:
            mac = (getattr(iface, "mac_address", None) or "").strip().lower().replace("-", ":")
            name = (getattr(iface, "name", None) or "").strip()
            itype = str(getattr(iface, "type", "") or "")
            ips = []
            try:
                links = getattr(iface, "links", None) or []
                for link in list(links):
                    try:
                        ip = getattr(link, "ip_address", None)
                        if ip:
                            h = _ip_host_only(str(ip))
                            if h:
                                ips.append(h)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                for disc in list(getattr(iface, "discovered", None) or []):
                    try:
                        ip = getattr(disc, "ip_address", None)
                        if ip:
                            h = _ip_host_only(str(ip))
                            if h and h not in ips:
                                ips.append(h)
                    except Exception:
                        pass
            except Exception:
                pass
            vid = ""
            iface_fabric = ""
            try:
                v = getattr(iface, "vlan", None)
                if v is not None:
                    vid = str(getattr(v, "vid", None) or getattr(v, "id", None) or "")
                    fab = getattr(v, "fabric", None)
                    if fab is not None:
                        iface_fabric = str(getattr(fab, "name", None) or fab or "").strip()
                    if not iface_fabric:
                        vd = getattr(v, "_data", None) or {}
                        if isinstance(vd, dict):
                            fd = vd.get("fabric")
                            if isinstance(fd, dict) and fd.get("name"):
                                iface_fabric = str(fd["name"]).strip()
            except Exception:
                pass
            rows.append({
                "name": name,
                "mac": mac,
                "ips": ips,
                "type": itype,
                "vlan_vid": vid,
                "iface_fabric": iface_fabric,
            })
        except Exception as e:
            logger.debug("MAAS viscera iface skip: %s", e)
            continue
    return rows


async def _machine_interfaces_list(machine):
    """Return list of {name, mac, ips[], type} for one MAAS machine via Interfaces.read."""
    try:
        from maas.client.viscera.interfaces import Interfaces
    except ImportError:
        return []
    sid = getattr(machine, "system_id", None) or ""
    try:
        iface_set = await Interfaces.read(sid or machine)
    except Exception as e:
        logger.debug("Interfaces.read failed for %s: %s", sid, e)
        return []
    try:
        ilist = list(iface_set)
    except Exception as e:
        logger.warning("MAAS interfaces list() failed for %s: %s", sid, e)
        return []
    return _ifaces_from_viscera_list(ilist)


def _fabric_from_iface_set(iface_set):
    """Best-effort MAAS fabric name from interfaces' VLAN (same API round-trip as NIC list)."""
    seen = []
    for iface in iface_set:
        v = getattr(iface, "vlan", None)
        if v is None:
            continue
        fab = getattr(v, "fabric", None)
        if fab is not None:
            n = getattr(fab, "name", None) or str(fab)
            if n and n not in seen:
                seen.append(str(n))
        else:
            d = getattr(v, "_data", None) or {}
            fd = d.get("fabric")
            if isinstance(fd, dict) and fd.get("name"):
                n = str(fd["name"])
                if n not in seen:
                    seen.append(n)
    if not seen:
        return "-"
    return seen[0] if len(seen) == 1 else ", ".join(seen[:3])


def _fabric_name_from_interface_item(item: dict, fabric_catalog: dict | None) -> str:
    """Single interface row: resolved fabric display name (for per-NIC scope in drift)."""
    catalog = fabric_catalog or {}
    if not isinstance(item, dict):
        return ""
    out = []

    def add(n: str) -> None:
        n = (n or "").strip()
        if n and n not in out:
            out.append(n)

    fab = item.get("fabric")
    if isinstance(fab, str) and fab.strip():
        s = fab.strip()
        if "/" in s:
            key = s.rstrip("/").split("/")[-1]
            add(catalog.get(key, key))
        else:
            add(catalog.get(s, catalog.get(s.lower(), s)))
    elif isinstance(fab, dict):
        add(str(fab.get("name") or fab.get("id") or ""))
    vlan = item.get("vlan")
    if isinstance(vlan, dict):
        vf = vlan.get("fabric")
        if isinstance(vf, dict) and vf.get("name"):
            add(str(vf["name"]))
        elif isinstance(vf, str) and vf.strip():
            key = vf.rstrip("/").split("/")[-1]
            add(catalog.get(key, key))
    return out[0] if out else ""


def _rest_rows_from_iface_dicts(items: list, fabric_catalog: dict | None = None) -> list:
    """Parse MAAS interface objects (list endpoint or interface_set on machine)."""
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        mac = (
            item.get("mac_address")
            or item.get("mac")
            or item.get("hwaddr")
            or ""
        )
        mac = str(mac).strip().lower().replace("-", ":")
        name = (item.get("name") or "").strip()
        itype = str(item.get("type") or "")
        ips = []
        for link in item.get("links") or []:
            if not isinstance(link, dict):
                continue
            ip = link.get("ip_address")
            if ip:
                h = _ip_host_only(str(ip))
                if h and h not in ips:
                    ips.append(h)
        for disc in item.get("discovered") or []:
            if isinstance(disc, dict) and disc.get("ip_address"):
                h = _ip_host_only(str(disc["ip_address"]))
                if h and h not in ips:
                    ips.append(h)
        vid = ""
        vlan = item.get("vlan") if isinstance(item, dict) else None
        if isinstance(vlan, dict):
            vid = str(vlan.get("vid") or vlan.get("id") or "")
        iface_fabric = _fabric_name_from_interface_item(item, fabric_catalog)
        rows.append({
            "name": name,
            "mac": mac,
            "ips": ips,
            "type": itype,
            "vlan_vid": vid,
            "iface_fabric": iface_fabric,
        })
    return rows


def _embedded_interface_arrays(machine: dict):
    """MAAS 3.x machine JSON may use interface_set, interfaces, or boot_interface only."""
    if not isinstance(machine, dict):
        return []
    for key in ("interface_set", "interfaces", "network_interfaces"):
        arr = machine.get(key)
        if isinstance(arr, list) and arr:
            return arr
    return []


def _maas_interfaces_rest(
    maas_url: str,
    api_key: str,
    system_id: str,
    verify_tls: bool,
    fabric_catalog: dict | None = None,
):
    """
    When python-libmaas returns no NICs: same data as MAAS UI via REST.

    1) GET .../interfaces/ (list)
    2) GET .../machines/{id}/ or .../nodes/{id}/ and read interface_set (MAAS 3.6 often
       populates here even when the list endpoint is empty).
    """
    parts = api_key.split(":", 2)
    if len(parts) != 3:
        return [], "-"
    ck, tk, ts = parts[0], parts[1], parts[2]
    base = maas_url.rstrip("/")
    if not base.lower().endswith("maas"):
        base = base + "/MAAS" if "/MAAS" not in base.upper() else base
    try:
        import requests
        from requests_oauthlib import OAuth1
    except ImportError:
        logger.warning("requests_oauthlib not available for MAAS REST interface fallback")
        return [], "-"
    auth = OAuth1(ck, "", tk, ts, signature_method="PLAINTEXT")
    last_err = None

    list_urls = [
        f"{base}/api/2.0/machines/{system_id}/interfaces/",
        f"{base}/api/2.0/nodes/{system_id}/interfaces/",
    ]
    for url in list_urls:
        try:
            r = requests.get(url, auth=auth, verify=verify_tls, timeout=90)
            if r.status_code == 404:
                continue
            if r.status_code != 200:
                last_err = f"{url} -> {r.status_code} {r.text[:100]}"
                continue
            data = r.json()
            if isinstance(data, list) and data:
                rows = _rest_rows_from_iface_dicts(data, fabric_catalog)
                if rows:
                    return rows, _fabric_from_rest_ifaces(data, fabric_catalog)
            elif isinstance(data, dict) and data.get("interfaces"):
                arr = data["interfaces"]
                if isinstance(arr, list):
                    rows = _rest_rows_from_iface_dicts(arr, fabric_catalog)
                    if rows:
                        return rows, _fabric_from_rest_ifaces(arr, fabric_catalog)
        except Exception as e:
            last_err = str(e)
            logger.debug("MAAS REST %s: %s", url, e)

    detail_urls = [
        f"{base}/api/2.0/machines/{system_id}/",
        f"{base}/api/2.0/nodes/{system_id}/",
    ]
    for url in detail_urls:
        try:
            r = requests.get(url, auth=auth, verify=verify_tls, timeout=90)
            if r.status_code != 200:
                last_err = f"{url} -> {r.status_code} {r.text[:100]}"
                continue
            machine = r.json()
            arr = _embedded_interface_arrays(machine)
            if not arr:
                last_err = f"{url} -> 200 but no interface_set/interfaces on machine JSON"
                continue
            rows = _rest_rows_from_iface_dicts(arr, fabric_catalog)
            if rows:
                logger.info(
                    "MAAS interfaces from machine detail %s (%d NICs)",
                    system_id,
                    len(rows),
                )
                return rows, _fabric_from_rest_ifaces(arr, fabric_catalog)
        except Exception as e:
            last_err = str(e)
            logger.debug("MAAS machine detail %s: %s", url, e)

    if last_err:
        logger.warning(
            "MAAS REST could not load interfaces for system_id=%s host check MAAS_URL matches UI MAAS. Last: %s",
            system_id,
            last_err,
        )
    return [], "-"


def hostname_short(name):
    """
    Return the short hostname (before first dot) for matching with NetBox.
    MAAS can return FQDN; NetBox has hostname only. e.g.:
      se-h1-23-gpu.pxe.spruce.whitefiber.com -> se-h1-23-gpu
      se-h1-23-gpu -> se-h1-23-gpu
    """
    if not name:
        return ""
    return str(name).split(".", 1)[0].strip()


async def fetch_maas_data(maas_url: str, maas_api_key: str, maas_insecure: bool):
    """
    Fetch machines, zones, and pools from MAAS. Returns a dict with:
      - machines: list of {hostname, system_id, zone_name, pool_name, status_name}
      - zones: list of {name, id}
      - pools: list of {name, id}
      - error: str if connection failed
    """
    result = {"machines": [], "zones": [], "pools": [], "error": None}
    if not maas_url or not maas_api_key:
        result["error"] = "MAAS_URL and MAAS_API_KEY are required"
        return result

    # Silence InsecureRequestWarning for this run (MAAS_INSECURE=true is common in labs)
    _silence_urllib3_insecure_when_maas_tls_skipped()

    try:
        from maas.client import connect
    except ImportError:
        result["error"] = "python-libmaas is not installed. Add it to plugin_requirements.txt and reinstall the plugin."
        return result

    try:
        client = await connect(maas_url, apikey=maas_api_key, insecure=maas_insecure)
    except Exception as e:
        logger.exception("MAAS connection failed")
        result["error"] = str(e)
        return result

    try:
        # Zones
        zones = await client.zones.list()
        for z in zones:
            result["zones"].append({"name": z.name, "id": getattr(z, "id", None)})

        # Pools
        pools = await client.resource_pools.list()
        for p in pools:
            result["pools"].append({"name": p.name, "id": getattr(p, "id", None)})

        # Machines (with zone and pool)
        machines = await client.machines.list()
        fabric_catalog = await asyncio.to_thread(
            _fetch_maas_fabric_catalog, maas_url, maas_api_key, not maas_insecure
        )
        for m in machines:
            zone_name = "-"
            pool_name = "-"
            try:
                z = getattr(m, "zone", None)
                if z is not None:
                    zone_name = getattr(z, "name", str(z))
            except Exception:
                pass
            try:
                p = getattr(m, "pool", None)
                if p is not None:
                    pool_name = getattr(p, "name", str(p))
            except Exception:
                pass
            # MAAS may give hostname or fqdn; normalize to short name for NetBox matching
            raw_name = getattr(m, "hostname", "") or getattr(m, "fqdn", "")
            short_name = hostname_short(raw_name)
            domain_part = ""
            try:
                dom = getattr(m, "domain", None)
                if dom is not None:
                    domain_part = (getattr(dom, "name", None) or "").strip()
            except Exception:
                pass
            md_pre = getattr(m, "_data", None)
            if not domain_part and isinstance(md_pre, dict):
                dmd = md_pre.get("domain")
                if isinstance(dmd, dict):
                    domain_part = (dmd.get("name") or "").strip()
            raw_fqdn = (getattr(m, "fqdn", None) or "").strip()
            if raw_fqdn and "." in raw_fqdn:
                dns_name = raw_fqdn
            elif domain_part and short_name:
                dns_name = f"{short_name}.{domain_part}"
            elif raw_name and "." in str(raw_name):
                dns_name = str(raw_name).strip()
            else:
                dns_name = short_name
            status_name = "-"
            try:
                st = getattr(m, "status", None)
                if st is not None:
                    status_name = getattr(st, "name", None) or str(st)
            except Exception:
                pass
            sid = (getattr(m, "system_id", None) or "").strip()
            ifaces = []
            fabric_name = "-"
            if sid:
                # Use REST for interfaces; viscera Interfaces.read() is class-bound and
                # raises "type object 'Interfaces' has no attribute '_handler'" when
                # called without a client origin.
                rest_if, rest_fab = await asyncio.to_thread(
                    _maas_interfaces_rest,
                    maas_url,
                    maas_api_key,
                    sid,
                    not maas_insecure,
                    fabric_catalog,
                )
                if rest_if:
                    ifaces = rest_if
                    fabric_name = rest_fab if rest_fab != "-" else fabric_name
            bmc_ip = ""
            serial = ""
            try:
                md = getattr(m, "_data", None)
                if isinstance(md, dict):
                    bmc_ip = _bmc_ip_from_power(
                        md.get("power_parameters"), md.get("power_type")
                    )
                    serial = (
                        (md.get("serial") or "")
                        or (md.get("serial_number") or "")
                        or (md.get("product_serial") or "")
                    )
            except Exception:
                pass
            if not serial:
                serial = (
                    (getattr(m, "serial", None) or "")
                    or (getattr(m, "serial_number", None) or "")
                )
            result["machines"].append({
                "hostname": short_name,
                "fqdn": raw_name if raw_name != short_name else "",
                "dns_name": dns_name,
                "system_id": getattr(m, "system_id", ""),
                "serial": str(serial).strip(),
                "zone_name": zone_name,
                "pool_name": pool_name,
                "fabric_name": fabric_name,
                "status_name": status_name,
                "interfaces": ifaces,
                "bmc_ip": bmc_ip,
            })
        _enrich_machines_fabric_rest(
            result["machines"], maas_url, maas_api_key, not maas_insecure, fabric_catalog
        )
        _enrich_machines_bmc_rest(result["machines"], maas_url, maas_api_key, not maas_insecure)
    except Exception as e:
        logger.exception("MAAS fetch failed")
        result["error"] = str(e)

    return result


def fetch_maas_data_sync(maas_url: str, maas_api_key: str, maas_insecure: bool):
    """Synchronous wrapper for fetch_maas_data (for use from Django view)."""
    return asyncio.run(fetch_maas_data(maas_url, maas_api_key, maas_insecure))
