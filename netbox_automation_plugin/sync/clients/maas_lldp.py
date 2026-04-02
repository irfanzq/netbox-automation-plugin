"""
MAAS commissioning LLDP from ``GET .../machines/{system_id}/op-details`` (BSON payload).

Maps host interface name -> neighbor switch name + remote port (``lldpctl -f xml`` shape).
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any

logger = logging.getLogger("netbox_automation_plugin.sync")


def _strip_xml_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def parse_lldpctl_xml_to_iface_index(xml_text: str) -> dict[str, dict[str, str]]:
    """
    Parse lldpctl XML: ``interface@name`` -> ``{switch, port}``.

    Prefer chassis ``type=local`` for system name; port ``type=ifname`` for neighbor port.
    """
    raw = (xml_text or "").strip()
    if not raw or not raw.startswith("<"):
        return {}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        try:
            root = ET.fromstring(f"<root>{raw}</root>")
        except ET.ParseError as e:
            logger.debug("LLDP XML parse error: %s", e)
            return {}

    out: dict[str, dict[str, str]] = {}
    for iface in root.iter():
        if _strip_xml_ns(iface.tag) != "interface":
            continue
        iname = (iface.get("name") or "").strip().lower()
        if not iname:
            continue
        switch = ""
        port = ""
        chassis_local = ""
        chassis_other: list[str] = []
        port_ifname = ""
        for child in iface:
            ct = _strip_xml_ns(child.tag)
            if ct == "chassis":
                typ = (child.get("type") or "").strip().lower()
                body = (child.text or "").strip()
                cid = (child.get("id") or "").strip().lower()
                if typ == "local" and body:
                    chassis_local = body
                elif body and typ not in ("mac",):
                    chassis_other.append(body)
                elif typ == "mac" and cid == "local" and body:
                    chassis_local = body
            elif ct == "port":
                typ = (child.get("type") or "").strip().lower()
                body = (child.text or "").strip()
                if typ == "ifname" and body:
                    port_ifname = body
                elif typ in ("local", "label") and body and not port_ifname:
                    port_ifname = body
        switch = chassis_local or ("; ".join(chassis_other) if chassis_other else "")
        port = port_ifname
        if switch or port:
            out[iname] = {
                "switch": switch[:200],
                "port": port[:200],
            }
    return out


def _decode_maas_op_details_payload(content: bytes) -> dict[str, Any] | None:
    if not content:
        return None
    # Some proxies return JSON.
    if content[:1] in (b"{", b"["):
        try:
            import json

            return json.loads(content.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    try:
        from bson import BSON
    except ImportError:
        logger.debug("pymongo/bson not installed; cannot decode MAAS op-details BSON")
        return None
    try:
        return BSON(content).decode()
    except Exception as e:
        logger.debug("MAAS op-details BSON decode failed: %s", e)
        return None


def extract_lldp_xml_from_op_details(doc: dict[str, Any] | None) -> str:
    """Return raw LLDP XML string from decoded op-details map."""
    if not doc or not isinstance(doc, dict):
        return ""
    raw = doc.get("lldp")
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return ""
    if isinstance(raw, str):
        return raw
    return str(raw)


def fetch_maas_op_details_lldp_xml(
    maas_base_url: str,
    api_key: str,
    system_id: str,
    *,
    verify_tls: bool = True,
    timeout: int = 60,
) -> str:
    """
    GET ``/api/2.0/machines/{system_id}/op-details/`` and return LLDP XML blob if present.
    """
    if not maas_base_url or not api_key or not system_id:
        return ""
    base = str(maas_base_url).rstrip("/")
    if not base.endswith("/MAAS"):
        if "/MAAS" not in base:
            base = base + "/MAAS"
    try:
        import requests
        from requests_oauthlib import OAuth1
    except ImportError:
        return ""
    url = f"{base}/api/2.0/machines/{system_id}/op-details/"
    parts = str(api_key).split(":", 2)
    if len(parts) != 3:
        return ""
    ck, tk, ts = parts[0], parts[1], parts[2]
    auth = OAuth1(ck, "", tk, ts, signature_method="PLAINTEXT")
    try:
        r = requests.get(url, auth=auth, verify=verify_tls, timeout=timeout)
        if r.status_code != 200:
            logger.debug("MAAS op-details %s HTTP %s", system_id, r.status_code)
            return ""
        doc = _decode_maas_op_details_payload(r.content)
        return extract_lldp_xml_from_op_details(doc)
    except Exception as e:
        logger.debug("MAAS op-details fetch %s: %s", system_id, e)
        return ""


def lldp_by_iface_name_for_machine(
    maas_base_url: str,
    api_key: str,
    system_id: str,
    *,
    verify_tls: bool = True,
) -> dict[str, dict[str, str]]:
    """Convenience: op-details -> iface name (lower) -> {switch, port}."""
    xml = fetch_maas_op_details_lldp_xml(
        maas_base_url, api_key, system_id, verify_tls=verify_tls
    )
    return parse_lldpctl_xml_to_iface_index(xml)


def enrich_interface_dicts_with_maas_lldp(
    interfaces: list[dict],
    lldp_by_iface: dict[str, dict[str, str]],
) -> None:
    """Mutate each interface dict with ``maas_lldp_switch`` / ``maas_lldp_port`` when known."""
    if not interfaces or not lldp_by_iface:
        return
    for row in interfaces:
        if not isinstance(row, dict):
            continue
        name = (row.get("name") or "").strip().lower()
        if not name:
            continue
        hit = lldp_by_iface.get(name)
        if not hit:
            continue
        sw = (hit.get("switch") or "").strip()
        pt = (hit.get("port") or "").strip()
        if sw:
            row["maas_lldp_switch"] = sw
        if pt:
            row["maas_lldp_port"] = pt
