"""
MAAS commissioning LLDP from machine details (``?op=details`` BSON/JSON, or legacy ``op-details/``).

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


def _lldp_element_body(el: ET.Element) -> str:
    """Text value for lldpctl chassis/port elements (usually in ``.text``)."""
    t = (el.text or "").strip()
    if t:
        return t
    for sub in el:
        st = (sub.text or "").strip()
        if st:
            return st
    return ""


def _chassis_port_from_lldp_block_flat(block: ET.Element) -> tuple[str, str]:
    """Flat TLVs: ``<chassis type="sysname">…</chassis>`` (older lldpctl)."""
    chassis_pri = {"sysname": 0, "name": 1, "descr": 3, "local": 6, "mac": 9}
    port_pri = {"ifname": 0, "descr": 1, "local": 2, "label": 3, "mac": 9}
    chassis_opts: list[tuple[int, str]] = []
    port_opts: list[tuple[int, str]] = []
    for el in block.iter():
        tag = _strip_xml_ns(el.tag)
        if tag == "chassis":
            typ = (el.get("type") or "").strip().lower()
            body = _lldp_element_body(el)
            if not body:
                continue
            chassis_opts.append((chassis_pri.get(typ, 4), body))
        elif tag == "port":
            typ = (el.get("type") or "").strip().lower()
            body = _lldp_element_body(el)
            if not body:
                continue
            port_opts.append((port_pri.get(typ, 5), body))
    switch = ""
    port = ""
    if chassis_opts:
        chassis_opts.sort(key=lambda x: x[0])
        switch = chassis_opts[0][1][:200]
    if port_opts:
        port_opts.sort(key=lambda x: x[0])
        port = port_opts[0][1][:200]
    return switch, port


def _chassis_port_from_lldp_block(block: ET.Element) -> tuple[str, str]:
    """
    Neighbor switch + port from one ``rid`` subtree (or whole interface).

    Handles **nested** lldpctl (Arista/Cumulus, etc.): ``<chassis><name>SysName</name>``
    and ``<port><id type="ifname">…</id></port>``. Falls back to flat TLVs if needed.
    """
    switch = ""
    port = ""
    for el in block.iter():
        if _strip_xml_ns(el.tag) != "chassis":
            continue
        if not list(el):
            continue
        child_tags = {_strip_xml_ns(c.tag) for c in el}
        if "name" not in child_tags and "id" not in child_tags:
            continue
        sysname = ""
        mac = ""
        for c in el:
            ct = _strip_xml_ns(c.tag)
            t = _lldp_element_body(c)
            if not t:
                continue
            if ct == "name":
                sysname = t
            elif ct == "id" and (c.get("type") or "").strip().lower() == "mac":
                mac = t
        cand = sysname or mac
        if cand:
            switch = cand[:200]
            break

    for el in block.iter():
        if _strip_xml_ns(el.tag) != "port":
            continue
        if not list(el):
            continue
        for c in el:
            if _strip_xml_ns(c.tag) != "id":
                continue
            if (c.get("type") or "").strip().lower() != "ifname":
                continue
            t = _lldp_element_body(c)
            if t:
                port = t[:200]
                break
        if port:
            break

    flat_sw, flat_pt = _chassis_port_from_lldp_block_flat(block)
    if not switch:
        switch = flat_sw
    if not port:
        port = flat_pt
    return switch, port


def parse_lldpctl_xml_to_iface_index(xml_text: str) -> dict[str, dict[str, str]]:
    """
    Parse lldpctl XML: ``interface@name`` -> ``{switch, port}``.

    Walks each interface subtree (including ``rid`` children) so nested chassis/port match
    MAAS / modern lldpctl output.
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
        iname = (iface.get("name") or iface.get("label") or "").strip().lower()
        if not iname:
            continue
        rids = [c for c in iface if _strip_xml_ns(c.tag) == "rid"]
        blocks: list[ET.Element] = rids if rids else [iface]
        for block in blocks:
            switch, port = _chassis_port_from_lldp_block(block)
            if switch or port:
                out[iname] = {"switch": switch[:200], "port": port[:200]}
                break
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


def _maas_op_details_urls(base: str, system_id: str) -> list[str]:
    """
    MAAS versions differ: some expose ``?op=details`` only; older docs mention ``op-details/``.
    """
    bid = system_id.strip()
    return [
        f"{base}/api/2.0/machines/{bid}/?op=details",
        f"{base}/api/2.0/nodes/{bid}/?op=details",
        f"{base}/api/2.0/machines/{bid}/op-details/",
    ]


def fetch_maas_op_details_lldp_xml(
    maas_base_url: str,
    api_key: str,
    system_id: str,
    *,
    verify_tls: bool = True,
    timeout: int = 60,
) -> str:
    """
    GET commissioning details (BSON or JSON) and return the ``lldp`` XML blob if present.

    Tries, in order: ``machines/{id}/?op=details``, ``nodes/{id}/?op=details``,
    ``machines/{id}/op-details/`` (legacy path on some installs).
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
    parts = str(api_key).split(":", 2)
    if len(parts) != 3:
        return ""
    ck, tk, ts = parts[0], parts[1], parts[2]
    auth = OAuth1(ck, "", tk, ts, signature_method="PLAINTEXT")
    headers = {
        "Accept": (
            "application/bson, application/octet-stream, "
            "application/json;q=0.3, */*;q=0.1"
        ),
    }
    try:
        for url in _maas_op_details_urls(base, system_id):
            r = requests.get(
                url, auth=auth, verify=verify_tls, timeout=timeout, headers=headers
            )
            if r.status_code != 200:
                logger.debug(
                    "MAAS op-details %s %s HTTP %s", system_id, url, r.status_code
                )
                continue
            doc = _decode_maas_op_details_payload(r.content)
            if doc is None:
                logger.debug("MAAS op-details %s %s decode failed", system_id, url)
                continue
            return extract_lldp_xml_from_op_details(doc)
        return ""
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
