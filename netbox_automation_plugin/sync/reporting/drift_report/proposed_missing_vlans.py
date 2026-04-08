"""Proposed IPAM VLAN rows when NIC or prefix proposals reference a VID that IPAM cannot resolve.

NIC VIDs use the same rules as ``apply_create_interface`` /
``apply_update_interface`` (``_interface_mac_vlan_ip_from_cells``), not only when
``SET_NETBOX_UNTAGGED_VLAN`` appears in Proposed Action.

Prefix rows (new/update OpenStack prefix gaps) use ``NB Proposed VLAN`` + ``NB Proposed Scope``
with the same resolution as ``apply_create_prefix`` (``_resolve_vlan_for_prefix_scope``).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

_NB_VLAN_NAME_MAX_LEN = 64

from netbox_automation_plugin.sync.reporting.drift_report.drift_nb_picker_catalog import (
    DRIFT_NB_PROPOSED_TENANT_DEFAULT,
)
from netbox_automation_plugin.sync.reporting.drift_report.drift_overrides_apply import (
    HEADERS_DETAIL_EXISTING_PREFIXES,
    HEADERS_DETAIL_NIC_DRIFT,
    HEADERS_DETAIL_NEW_NICS,
    HEADERS_DETAIL_NEW_PREFIXES,
)
from netbox_automation_plugin.sync.reporting.drift_report.proposed_action_format import (
    SET_NETBOX_ACTION_CREATE_VLAN,
)
from netbox_automation_plugin.sync.reconciliation.apply_cells import (
    _interface_mac_vlan_ip_from_cells,
    _resolve_vlan_by_group_name_and_vid,
    _resolve_vlan_for_device,
    _resolve_vlan_for_prefix_scope,
)

_RE_UNTAGGED = re.compile(r"\bSET_NETBOX_UNTAGGED_VLAN\s*=\s*([^;]+)", re.I)

_IDX_DRIFT = {h: i for i, h in enumerate(HEADERS_DETAIL_NIC_DRIFT)}
_IDX_NEW = {h: i for i, h in enumerate(HEADERS_DETAIL_NEW_NICS)}

# Same label as drift_overrides_apply.HEADERS_DETAIL_*_PREFIXES — VLAN name hint for prefix rows.
_NB_PREFIX_PROPOSED_DESC_HEADER = "NB Proposed Prefix description (editable)"


def _audit_row_to_cells(headers: list[str], row: list[Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for i, h in enumerate(headers):
        v = row[i] if i < len(row) else ""
        out[str(h)] = "" if v is None else str(v).strip()
    return out


def _unicast_ieee_vids_from_nic_cells(
    cells: dict[str, str], *, include_nb_vlan_fallback: bool
) -> list[int]:
    """
    Same VLAN resolution path as interface apply so missing-VLAN rows are emitted whenever
    create/update interface would set an untagged VID (not only when Proposed Action
    contains ``SET_NETBOX_UNTAGGED_VLAN``).
    """
    _mac, vid, _ips = _interface_mac_vlan_ip_from_cells(
        cells, include_nb_fallback=include_nb_vlan_fallback
    )
    if vid is None:
        return []
    try:
        vi = int(vid)
    except (TypeError, ValueError):
        return []
    if not (1 <= vi <= 4094):
        return []
    return [vi]


def _collect_vids_for_nic_drift(pa: str, cells: dict[str, str]) -> list[int]:
    vids = _parse_tagged_vids_from_proposed_action(pa)
    if not vids:
        vids = _unicast_ieee_vids_from_nic_cells(
            cells, include_nb_vlan_fallback=True
        )
    return list(dict.fromkeys(vids))


def _collect_vids_for_new_nic(pa: str, cells: dict[str, str]) -> list[int]:
    vids = _parse_tagged_vids_from_proposed_action(pa)
    if not vids:
        vids = _unicast_ieee_vids_from_nic_cells(
            cells, include_nb_vlan_fallback=False
        )
    return list(dict.fromkeys(vids))


def _parse_tagged_vids_from_proposed_action(pa: str) -> list[int]:
    out: list[int] = []
    for m in _RE_UNTAGGED.finditer(pa or ""):
        chunk = (m.group(1) or "").strip()
        if not chunk or chunk in {"—", "-"}:
            continue
        try:
            vi = int(str(chunk.split()[0]), 10)
        except ValueError:
            continue
        if 1 <= vi <= 4094:
            out.append(vi)
    return list(dict.fromkeys(out))


def _cell_shows_ieee_vlan_tag(cell: str) -> bool:
    """True if drift/audit cell carries a real 802.1Q tag (MAAS/OS columns), not native/empty."""
    s = str(cell or "").strip()
    if not s or s in {"—", "-"}:
        return False
    try:
        v = int(str(s).split()[0], 10)
    except ValueError:
        return False
    return 1 <= v <= 4094


def _skip_proposed_missing_vlan_maas_untagged(auth: str, maas_vlan: str, os_vlan: str) -> bool:
    """
    MAAS authority with no tagged VID in MAAS or OS columns matches fabric-native (vid 0) NICs.
    Do not emit IPAM create-VLAN rows for that case.
    """
    if "[MAAS]" not in str(auth or ""):
        return False
    return not _cell_shows_ieee_vlan_tag(maas_vlan) and not _cell_shows_ieee_vlan_tag(os_vlan)


def _device_for_host(host: str):
    try:
        from dcim.models import Device

        h = (host or "").strip()
        if not h:
            return None
        return Device.objects.filter(name=h).first()
    except Exception:
        return None


def _netbox_location_object_name(loc) -> str:
    """NetBox Location model name only (no site prefix — NB site is a separate column)."""
    if loc is None:
        return ""
    try:
        return (getattr(loc, "name", None) or "").strip()
    except Exception:
        return ""


def _nb_location_cell_for_missing_vlan_row(*, nb_location: str, site_disp: str) -> str:
    """
    NB location column: show Birch / Staging, not ``B52 / Birch`` when NB site already holds B52.
    Strips a leading ``{site} /`` segment when it matches ``site_disp``; otherwise returns the cell
    trimmed (operators may enter plain location names).
    """
    raw = (nb_location or "").strip()
    if not raw or raw in {"—", "-"}:
        return ""
    site_s = (site_disp or "").strip()
    if site_s:
        parts = re.split(r"\s*/\s*", raw, maxsplit=1)
        if (
            len(parts) == 2
            and (parts[0] or "").strip()
            and (parts[0].strip().casefold() == site_s.casefold())
        ):
            rest = (parts[1] or "").strip()
            if rest:
                return rest
    return raw


def _location_match_hints(*, device, nb_site: str, nb_location: str) -> list[str]:
    """Ordered location/site name fragments (e.g. Birch, Spruce) for fuzzy VLAN group name match."""
    hints: list[str] = []

    def add(s: str) -> None:
        t = (s or "").strip()
        if t and t not in {"—", "-", "None", "none"}:
            hints.append(t)

    if device is not None:
        loc = getattr(device, "location", None)
        if loc is not None:
            add(getattr(loc, "name", None) or "")
        site = getattr(device, "site", None)
        if site is not None:
            add(getattr(site, "name", None) or "")
    add(nb_site)
    raw_loc = (nb_location or "").strip()
    if raw_loc and raw_loc not in {"—", "-"}:
        for part in re.split(r"\s*/\s*", raw_loc):
            add(part)
    seen: set[str] = set()
    uniq: list[str] = []
    for h in hints:
        k = h.casefold()
        if k not in seen:
            seen.add(k)
            uniq.append(h)
    return sorted(uniq, key=len, reverse=True)


def _match_vlan_group_name_from_hints(hints: list[str]) -> str:
    """
    Pick the best-matching VLAN group **name** from all NetBox VLAN groups using location-style
    hints (e.g. location ``Birch`` → group ``Birch VLANs``).
    """
    from ipam.models import VLANGroup

    names = [(g.name or "").strip() for g in VLANGroup.objects.all().order_by("name")]
    names = [n for n in names if n]
    if not hints or not names:
        return ""

    best_gn = ""
    best_score = -1
    for gn in names:
        gn_cf = gn.casefold()
        for hint in hints:
            h = (hint or "").strip()
            if not h:
                continue
            hcf = h.casefold()
            score = 0
            if hcf in gn_cf:
                score = 1000 + len(hcf)
            else:
                g_words = re.findall(r"[a-z0-9]+", gn_cf)
                h_words = re.findall(r"[a-z0-9]+", hcf)
                if g_words and h_words and h_words[0] == g_words[0]:
                    score = 500 + len(h_words[0])
            if score > best_score:
                best_score = score
                best_gn = gn
            elif score == best_score and score > 0 and gn < best_gn:
                best_gn = gn

    return best_gn if best_score > 0 else ""


def _suggest_vlan_group_name(*, device, nb_site: str, nb_location: str) -> str:
    """Prefer name-based match (Birch → Birch VLANs) over strict scope FK; then scope fallback."""
    from django.contrib.contenttypes.models import ContentType
    from dcim.models import Location, Site
    from ipam.models import VLANGroup

    from netbox_automation_plugin.sync.reconciliation.apply_cells import _resolve_by_name

    hints = _location_match_hints(device=device, nb_site=nb_site, nb_location=nb_location)
    by_name = _match_vlan_group_name_from_hints(hints)
    if by_name:
        return by_name

    if device is not None:
        loc = getattr(device, "location", None)
        if loc is not None:
            try:
                ct = ContentType.objects.get_for_model(loc)
                g = VLANGroup.objects.filter(scope_type=ct, scope_id=loc.pk).order_by("name").first()
                if g and (g.name or "").strip():
                    return (g.name or "").strip()
            except Exception:
                pass
        site = getattr(device, "site", None)
        if site is not None:
            try:
                ct = ContentType.objects.get_for_model(site)
                g = VLANGroup.objects.filter(scope_type=ct, scope_id=site.pk).order_by("name").first()
                if g and (g.name or "").strip():
                    return (g.name or "").strip()
            except Exception:
                pass

    loc_name = (nb_location or "").strip()
    if loc_name and loc_name not in {"—", "-"}:
        loc_obj = _resolve_by_name(Location, loc_name)
        if loc_obj is not None:
            try:
                ct = ContentType.objects.get_for_model(loc_obj)
                g = VLANGroup.objects.filter(scope_type=ct, scope_id=loc_obj.pk).order_by("name").first()
                if g and (g.name or "").strip():
                    return (g.name or "").strip()
            except Exception:
                pass
    site_name = (nb_site or "").strip()
    if site_name and site_name not in {"—", "-"}:
        site_obj = _resolve_by_name(Site, site_name)
        if site_obj is not None:
            try:
                ct = ContentType.objects.get_for_model(site_obj)
                g = VLANGroup.objects.filter(scope_type=ct, scope_id=site_obj.pk).order_by("name").first()
                if g and (g.name or "").strip():
                    return (g.name or "").strip()
            except Exception:
                pass
    return ""


def _defaults_for_vlan_group(group_name: str) -> dict[str, str]:
    """
    Status / VLAN name: first VLAN in the group by VID (stable template).
    Tenant: left empty — operators set NB Proposed Tenant via the drift picker (real NetBox tenants only).
    """
    from ipam.models import VLAN, VLANGroup

    gn = (group_name or "").strip()
    if not gn:
        return {
            "tenant": DRIFT_NB_PROPOSED_TENANT_DEFAULT,
            "status": "active",
            "vlan_name": "TBD",
        }
    grp = VLANGroup.objects.filter(name__iexact=gn).first()
    if grp is None:
        return {
            "tenant": DRIFT_NB_PROPOSED_TENANT_DEFAULT,
            "status": "active",
            "vlan_name": "TBD",
        }
    gfk = "group" if any(f.name == "group" for f in VLAN._meta.fields) else "vlan_group"
    v0 = VLAN.objects.filter(**{gfk: grp}).order_by("vid").first()
    if v0 is None:
        return {
            "tenant": DRIFT_NB_PROPOSED_TENANT_DEFAULT,
            "status": "active",
            "vlan_name": "TBD",
        }
    st = getattr(v0, "status", None)
    status_s = str(st).strip() if st is not None else "active"
    vn = (v0.name or "").strip() or "TBD"
    return {
        "tenant": DRIFT_NB_PROPOSED_TENANT_DEFAULT,
        "status": status_s,
        "vlan_name": vn,
    }


def _clamp_nb_vlan_name(raw: str) -> str:
    s = (raw or "").strip()
    if not s or s in {"—", "-"}:
        return ""
    if len(s) > _NB_VLAN_NAME_MAX_LEN:
        return s[:_NB_VLAN_NAME_MAX_LEN].rstrip()
    return s


def _disambiguate_vlan_display_name(base: str, vid: int, attempt: int) -> str:
    """Append VID (and optional suffix) so names stay unique within a VLAN group; respect max length."""
    b = (base or "").strip() or f"VLAN-{vid}"
    tag = f" ({vid})" if attempt == 0 else f" ({vid})#{attempt}"
    room = _NB_VLAN_NAME_MAX_LEN - len(tag)
    if room < 8:
        return _clamp_nb_vlan_name(f"V{vid}-{attempt}" if attempt else f"V{vid}")
    trimmed = b[:room].rstrip() if len(b) > room else b
    return _clamp_nb_vlan_name(trimmed + tag)


def _ensure_unique_proposed_missing_vlan_names(rows: list[list[Any]]) -> None:
    """
    NetBox enforces unique (vlan_group, name) regardless of VID. Rows often inherit the same
    display name from :func:`_defaults_for_vlan_group` or OpenStack labels, which duplicates
    across VIDs. De-duplicate proposed names against existing IPAM VLANs per **NB proposed VLAN group**
    and within this batch.
    """
    if not rows:
        return
    try:
        from ipam.models import VLAN, VLANGroup
    except Exception:
        return

    gfk = "group" if any(f.name == "group" for f in VLAN._meta.fields) else "vlan_group"
    row_groups = {(r[6] or "").strip() for r in rows if isinstance(r, (list, tuple)) and len(r) > 6}
    row_groups = {g for g in row_groups if g and g not in {"—", "-"}}

    net_names: dict[str, dict[str, int]] = {}
    for g in row_groups:
        grp = VLANGroup.objects.filter(name__iexact=g).first()
        if grp is None:
            continue
        gkey = g.casefold()
        d: dict[str, int] = {}
        try:
            for v in VLAN.objects.filter(**{gfk: grp}).only("vid", "name"):
                nm = (getattr(v, "name", None) or "").strip()
                if nm:
                    d[nm.casefold()] = int(v.vid)
        except Exception:
            continue
        net_names[gkey] = d

    batch_claims: dict[str, dict[str, int]] = {}

    for row in rows:
        if not isinstance(row, (list, tuple)) or len(row) <= 7:
            continue
        group = (row[6] or "").strip()
        if not group or group in {"—", "-"}:
            continue
        gkey = group.casefold()
        try:
            vid = int(str(row[5] or "").strip())
        except ValueError:
            continue
        raw = (row[7] or "").strip()
        if not raw or raw in {"—", "-"}:
            name = f"VLAN-{vid}"
        else:
            name = _clamp_nb_vlan_name(raw) or f"VLAN-{vid}"

        nx = net_names.get(gkey) or {}
        bn = batch_claims.setdefault(gkey, {})

        def foreign_claim(nl: str) -> bool:
            owner = nx.get(nl)
            return owner is not None and int(owner) != int(vid)

        def batch_conflict(nl: str) -> bool:
            owner = bn.get(nl)
            return owner is not None and int(owner) != int(vid)

        def is_taken(n: str) -> bool:
            nl = n.casefold()
            return foreign_claim(nl) or batch_conflict(nl)

        candidate = name
        attempt = 0
        while is_taken(candidate):
            candidate = _disambiguate_vlan_display_name(name, vid, attempt)
            attempt += 1
            if attempt > 50:
                candidate = _clamp_nb_vlan_name(f"VLAN-{vid}-{attempt}")
                break
        row[7] = candidate
        bn[candidate.casefold()] = vid


def _norm_mac_for_match(mac: str) -> str:
    s = (mac or "").strip().lower().replace("-", ":")
    parts = [p for p in s.split(":") if p]
    if len(parts) != 6:
        return s
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return s


def _first_ip_hint_from_cidr(cidr: str) -> str:
    """First usable IPv4/IPv6 host in prefix for VLAN name / prefix-correlation hints."""
    t = (cidr or "").strip()
    if not t:
        return ""
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        return ""
    try:
        addr = net.network_address
        if net.version == 4 and net.num_addresses > 1:
            return str(addr + 1)
        return str(addr)
    except ValueError:
        return str(net.network_address)


def _location_obj_for_prefix_scope(scope_name: str):
    sn = (scope_name or "").strip()
    if not sn or sn in {"—", "-"}:
        return None
    try:
        from dcim.models import Location

        from netbox_automation_plugin.sync.reconciliation.apply_cells import _resolve_by_name

        return _resolve_by_name(Location, sn)
    except Exception:
        return None


def _parse_nic_ip_strings(maas_ips_cell: str, os_ip_cell: str) -> list[str]:
    """Host IP strings (no mask) from MAAS / OS NIC columns for prefix correlation."""
    out: list[str] = []
    seen: set[str] = set()
    for blob in (maas_ips_cell, os_ip_cell):
        for piece in re.split(r"[,;\s]+", str(blob or "")):
            t = piece.strip()
            if not t or t in {"—", "-", "none", "None"}:
                continue
            host_part = t.split("/", 1)[0].strip()
            try:
                ip_o = ipaddress.ip_address(host_part)
            except ValueError:
                continue
            key = str(ip_o)
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


def _build_prefix_vlan_lookup() -> tuple[list[tuple], list[tuple]]:
    """
    (network, vid, vlan_name) rows longest-prefix-first per IP version.
    Used to suggest a VLAN display name when a NIC IP falls in a Prefix tied to a VLAN.
    """
    try:
        from ipam.models import Prefix
    except Exception:
        return [], []

    v4: list[tuple] = []
    v6: list[tuple] = []
    try:
        for p in (
            Prefix.objects.select_related("vlan")
            .filter(vlan__isnull=False)
            .only("prefix", "vlan_id", "vlan__vid", "vlan__name")
            .iterator(chunk_size=4000)
        ):
            vl = getattr(p, "vlan", None)
            if vl is None:
                continue
            vid = getattr(vl, "vid", None)
            if vid is None:
                continue
            nm = (getattr(vl, "name", None) or "").strip()
            if not nm:
                continue
            pfx = str(getattr(p, "prefix", "") or "").strip()
            if not pfx:
                continue
            try:
                net = ipaddress.ip_network(pfx, strict=False)
            except ValueError:
                continue
            rec = (net, int(vid), nm)
            if net.version == 4:
                v4.append(rec)
            else:
                v6.append(rec)
    except Exception:
        return [], []
    v4.sort(key=lambda r: r[0].prefixlen, reverse=True)
    v6.sort(key=lambda r: r[0].prefixlen, reverse=True)
    return v4, v6


def _vlan_name_from_prefixes(
    rows_v4: list[tuple],
    rows_v6: list[tuple],
    ip_str: str,
    vid: int,
) -> str:
    try:
        ip_o = ipaddress.ip_address((ip_str or "").strip())
    except ValueError:
        return ""
    rows = rows_v4 if ip_o.version == 4 else rows_v6
    for net, pvid, name in rows:
        if int(pvid) != int(vid):
            continue
        if ip_o in net:
            return _clamp_nb_vlan_name(name)
    return ""


def _vlan_name_in_netbox_group(group_name: str, vid: int) -> str:
    """If IPAM already has this VID in the VLAN group, reuse that VLAN's name."""
    from ipam.models import VLAN, VLANGroup

    gn = (group_name or "").strip()
    if not gn:
        return ""
    grp = VLANGroup.objects.filter(name__iexact=gn).first()
    if grp is None:
        return ""
    gfk = "group" if any(f.name == "group" for f in VLAN._meta.fields) else "vlan_group"
    try:
        v = VLAN.objects.filter(**{gfk: grp}, vid=int(vid)).first()
    except Exception:
        return ""
    if v is None:
        return ""
    return _clamp_nb_vlan_name(str(getattr(v, "name", None) or ""))


def _maas_interface_vlan_name(machine: dict | None, maas_intf: str, maas_mac: str) -> str:
    """MAAS REST/viscera-derived ``vlan_name`` / ``vlan.name`` for the matching interface."""
    if not machine or not isinstance(machine, dict):
        return ""
    want_if = (maas_intf or "").strip()
    want_mac = _norm_mac_for_match(maas_mac)
    for iface in machine.get("interfaces") or []:
        if not isinstance(iface, dict):
            continue
        iname = str(iface.get("name") or "").strip()
        imac = _norm_mac_for_match(str(iface.get("mac") or ""))
        if want_mac and imac and imac == want_mac:
            matched = True
        elif want_if and iname == want_if:
            matched = True
        else:
            matched = False
        if not matched:
            continue
        vn = str(iface.get("vlan_name") or "").strip()
        vv = iface.get("vlan")
        if not vn and isinstance(vv, dict):
            vn = str(vv.get("name") or "").strip()
        mvid = str(iface.get("vlan_vid") or "").strip()
        if not mvid and isinstance(vv, dict) and vv.get("vid") is not None:
            try:
                mvid = str(int(vv["vid"]))
            except (TypeError, ValueError):
                mvid = ""
        if vn.strip().lower() == "untagged" and mvid in ("0", ""):
            return ""
        return _clamp_nb_vlan_name(vn)
    return ""


def _is_vid_like_label(s: str) -> bool:
    t = (s or "").strip()
    if not t:
        return True
    if t.isdigit() and 1 <= int(t) <= 4094:
        return True
    return False


def _suggest_vlan_display_name(
    *,
    dfl_vlan_name: str,
    group_name: str,
    vid: int,
    prefix_rows_v4: list[tuple],
    prefix_rows_v6: list[tuple],
    ip_strings: list[str],
    maas_vlan_label: str,
    os_network_name: str,
    location_hints: list[str],
    openstack_subnet_description: str = "",
) -> str:
    """
    NetBox prefix/VLAN correlation from NIC (or prefix CIDR) IPs first, then the combined prefix-row
    hint (``NB Proposed Prefix description (editable)`` or ``OS Description`` passed together as
    ``openstack_subnet_description``), then existing VLAN in group, MAAS/OpenStack labels, fuzzy
    match in group, then template default from :func:`_defaults_for_vlan_group`.
    """
    for ip_s in ip_strings:
        hit = _vlan_name_from_prefixes(prefix_rows_v4, prefix_rows_v6, ip_s, vid)
        if hit:
            return hit

    desc_hint = _clamp_nb_vlan_name(openstack_subnet_description)
    if desc_hint and not _is_vid_like_label(desc_hint):
        return desc_hint

    hit_g = _vlan_name_in_netbox_group(group_name, vid)
    if hit_g:
        return hit_g

    for cand in (
        _clamp_nb_vlan_name(maas_vlan_label),
        _clamp_nb_vlan_name(os_network_name),
    ):
        if cand and not _is_vid_like_label(cand):
            return cand

    maas_clean = _clamp_nb_vlan_name(maas_vlan_label)
    os_clean = _clamp_nb_vlan_name(os_network_name)
    blob_cf = f"{maas_clean} {os_clean}".casefold()
    if blob_cf.strip():
        try:
            from ipam.models import VLAN, VLANGroup

            grp = VLANGroup.objects.filter(name__iexact=(group_name or "").strip()).first()
            if grp is not None:
                gfk = "group" if any(f.name == "group" for f in VLAN._meta.fields) else "vlan_group"
                best_nm = ""
                best_sc = -1
                hint_cf = [h.casefold() for h in location_hints if len((h or "").strip()) >= 3]
                toks = [t for t in re.findall(r"[a-z0-9]+", blob_cf) if len(t) >= 3]
                svid = str(int(vid))
                for v in VLAN.objects.filter(**{gfk: grp}).only("vid", "name").iterator():
                    if int(getattr(v, "vid", -1)) == int(vid):
                        continue
                    nm = (getattr(v, "name", None) or "").strip()
                    if not nm:
                        continue
                    ncf = nm.casefold()
                    score = 0
                    for t in toks:
                        if t in ncf:
                            score += 3
                    for h in hint_cf:
                        if h in ncf:
                            score += 5
                    if len(svid) >= 2 and svid in ncf:
                        score += 4
                    if score > best_sc:
                        best_sc = score
                        best_nm = nm
                if best_sc >= 6 and best_nm:
                    return _clamp_nb_vlan_name(best_nm)
        except Exception:
            pass

    return _clamp_nb_vlan_name(dfl_vlan_name) or "TBD"


def build_proposed_missing_vlan_rows(
    update_nic: list,
    add_nb_interfaces: list,
    *,
    maas_by_hostname: dict[str, dict] | None = None,
    runtime_nic_by_host_mac: dict[tuple[str, str], dict] | None = None,
    add_prefixes: list | None = None,
    update_prefixes: list | None = None,
) -> list[list[Any]]:
    """
    One row per (suggested **NB proposed VLAN group**, VID) where NIC drift / new-NIC proposals
    reference a tagged VID that does not resolve for the device (or device absent — placement
    from NB site/location), or where prefix rows reference ``NB Proposed VLAN`` that
    :func:`_resolve_vlan_for_prefix_scope` cannot satisfy (same as ``apply_create_prefix``).
    """
    prefix_v4, prefix_v6 = _build_prefix_vlan_lookup()
    seen: set[tuple[str, int]] = set()
    out: list[list[Any]] = []

    def maybe_append(
        *,
        host: str,
        dev,
        nb_site: str,
        nb_location: str,
        maas_vlan: str,
        os_vlan: str,
        maas_ips: str,
        os_ip: str,
        maas_intf: str,
        maas_mac: str,
        vid_src: str,
        vid: int,
        openstack_subnet_description: str = "",
    ) -> None:
        try:
            if int(vid) <= 0 or int(vid) > 4094:
                return
        except (TypeError, ValueError):
            return
        if dev is not None and _resolve_vlan_for_device(dev, vid) is not None:
            return
        group = _suggest_vlan_group_name(device=dev, nb_site=nb_site, nb_location=nb_location)
        if group and group not in {"—", "-"}:
            if _resolve_vlan_by_group_name_and_vid(group, vid) is not None:
                return
        dfl = _defaults_for_vlan_group(group)
        site_disp = nb_site.strip() if (nb_site or "").strip() not in {"", "—", "-"} else ""
        if not site_disp and dev is not None and getattr(dev, "site", None):
            site_disp = (getattr(dev.site, "name", None) or "").strip()
        loc_disp = _nb_location_cell_for_missing_vlan_row(
            nb_location=nb_location, site_disp=site_disp
        )
        if not loc_disp and dev is not None:
            loc_disp = _netbox_location_object_name(getattr(dev, "location", None))
        hints = _location_match_hints(device=dev, nb_site=nb_site, nb_location=nb_location)
        maas_machine = None
        if maas_by_hostname:
            hs = (host or "").strip()
            maas_machine = maas_by_hostname.get(hs) or maas_by_hostname.get(hs.lower())
        maas_iface_vlan = _maas_interface_vlan_name(maas_machine, maas_intf, maas_mac)
        os_net_name = ""
        if runtime_nic_by_host_mac:
            k = ((host or "").strip().lower(), _norm_mac_for_match(maas_mac))
            osr = runtime_nic_by_host_mac.get(k)
            if isinstance(osr, dict):
                os_net_name = str(osr.get("network_name") or "").strip()
        vlan_disp = _suggest_vlan_display_name(
            dfl_vlan_name=dfl["vlan_name"],
            group_name=group,
            vid=vid,
            prefix_rows_v4=prefix_v4,
            prefix_rows_v6=prefix_v6,
            ip_strings=_parse_nic_ip_strings(maas_ips, os_ip),
            maas_vlan_label=maas_iface_vlan,
            os_network_name=os_net_name,
            location_hints=hints,
            openstack_subnet_description=openstack_subnet_description,
        )
        # Never pre-fill create-VLAN rows with MAAS's fabric-native label; operators set a NetBox name.
        if (vlan_disp or "").strip().lower() == "untagged":
            vlan_disp = "—"
        scope_key = (
            group.strip().casefold()
            if group
            else f"{site_disp.strip().casefold()}|{loc_disp.strip().casefold()}|{host.strip().casefold()}"
        )
        gkey = (scope_key, vid)
        if gkey in seen:
            return
        seen.add(gkey)
        risk = "Medium" if dev is not None else "High"
        out.append(
            [
                site_disp or "—",
                loc_disp or "—",
                maas_vlan if (maas_vlan or "").strip() else "—",
                os_vlan if (os_vlan or "").strip() else "—",
                vid_src,
                str(vid),
                group,
                vlan_disp,
                dfl["tenant"],
                dfl["status"],
                SET_NETBOX_ACTION_CREATE_VLAN,
                risk,
            ]
        )

    for row in update_nic or []:
        if not isinstance(row, (list, tuple)):
            continue
        r = list(row)
        while len(r) < len(HEADERS_DETAIL_NIC_DRIFT):
            r.append("")
        pa = str(r[_IDX_DRIFT["Proposed Action"]] or "")
        cells = _audit_row_to_cells(HEADERS_DETAIL_NIC_DRIFT, r)
        vids = _collect_vids_for_nic_drift(pa, cells)
        if not vids:
            continue
        host = str(r[_IDX_DRIFT["Host"]] or "").strip()
        dev = _device_for_host(host)
        nb_site = ""
        nb_loc = ""
        if dev is not None:
            if getattr(dev, "site", None):
                nb_site = (dev.site.name or "").strip()
            nb_loc = _netbox_location_object_name(getattr(dev, "location", None))
        maas_vlan = str(r[_IDX_DRIFT["MAAS VLAN"]] or "—")
        os_vlan = str(r[_IDX_DRIFT["OS runtime VLAN"]] or "—")
        maas_ips = str(r[_IDX_DRIFT["MAAS IPs"]] or "")
        os_ip = str(r[_IDX_DRIFT["OS runtime IP"]] or "")
        maas_intf = str(r[_IDX_DRIFT["MAAS intf"]] or "")
        maas_mac = str(r[_IDX_DRIFT["MAAS MAC"]] or "")
        auth = str(r[_IDX_DRIFT["Authority"]] or "")
        if _skip_proposed_missing_vlan_maas_untagged(auth, maas_vlan, os_vlan):
            continue
        vid_src = "OS runtime" if "[OS]" in auth else "MAAS"
        for vid in vids:
            maybe_append(
                host=host,
                dev=dev,
                nb_site=nb_site,
                nb_location=nb_loc,
                maas_vlan=maas_vlan,
                os_vlan=os_vlan,
                maas_ips=maas_ips,
                os_ip=os_ip,
                maas_intf=maas_intf,
                maas_mac=maas_mac,
                vid_src=vid_src,
                vid=vid,
                openstack_subnet_description="",
            )

    for row in add_nb_interfaces or []:
        if not isinstance(row, (list, tuple)):
            continue
        r = list(row)
        while len(r) < len(HEADERS_DETAIL_NEW_NICS):
            r.append("")
        pa = str(r[_IDX_NEW["Proposed Action"]] or "")
        cells = _audit_row_to_cells(HEADERS_DETAIL_NEW_NICS, r)
        vids = _collect_vids_for_new_nic(pa, cells)
        if not vids:
            continue
        host = str(r[_IDX_NEW["Host"]] or "").strip()
        dev = _device_for_host(host)
        nb_site = str(r[_IDX_NEW["NB site"]] or "").strip()
        nb_loc = str(r[_IDX_NEW["NB location"]] or "").strip()
        maas_vlan = str(r[_IDX_NEW["MAAS VLAN"]] or "—")
        os_vlan = str(r[_IDX_NEW["OS runtime VLAN"]] or "—")
        maas_ips = str(r[_IDX_NEW["MAAS IPs"]] or "")
        os_ip = str(r[_IDX_NEW["OS runtime IP"]] or "")
        maas_intf = str(r[_IDX_NEW["MAAS intf"]] or "")
        maas_mac = str(r[_IDX_NEW["MAAS MAC"]] or "")
        auth = str(r[_IDX_NEW["Authority"]] or "")
        if _skip_proposed_missing_vlan_maas_untagged(auth, maas_vlan, os_vlan):
            continue
        vid_src = "OS runtime" if "[OS]" in auth else "MAAS"
        for vid in vids:
            maybe_append(
                host=host,
                dev=dev,
                nb_site=nb_site,
                nb_location=nb_loc,
                maas_vlan=maas_vlan,
                os_vlan=os_vlan,
                maas_ips=maas_ips,
                os_ip=os_ip,
                maas_intf=maas_intf,
                maas_mac=maas_mac,
                vid_src=vid_src,
                vid=vid,
                openstack_subnet_description="",
            )

    def maybe_append_from_prefix_row(
        *,
        nb_scope: str,
        vlan_cell: str,
        nb_proposed_prefix_description: str,
        os_description: str,
        cidr: str,
    ) -> None:
        raw_v = str(vlan_cell or "").strip()
        if not raw_v or raw_v in {"—", "-"}:
            return
        scope_obj = _location_obj_for_prefix_scope(nb_scope)
        try:
            if _resolve_vlan_for_prefix_scope(raw_v, scope_obj) is not None:
                return
        except Exception:
            return
        try:
            vi = int(str(raw_v).split()[0], 10)
        except ValueError:
            return
        if not (1 <= vi <= 4094):
            return
        nb_site = ""
        if scope_obj is not None and getattr(scope_obj, "site", None):
            nb_site = (getattr(scope_obj.site, "name", None) or "").strip()
        nb_location = (nb_scope or "").strip()
        ip_hint = _first_ip_hint_from_cidr(cidr)
        prop = (nb_proposed_prefix_description or "").strip()
        if not prop or prop in {"—", "-"}:
            prop = (os_description or "").strip()
        maybe_append(
            host="",
            dev=None,
            nb_site=nb_site,
            nb_location=nb_location,
            maas_vlan="—",
            os_vlan=str(vi),
            maas_ips="",
            os_ip=ip_hint,
            maas_intf="",
            maas_mac="",
            vid_src="OpenStack prefix",
            vid=vi,
            openstack_subnet_description=prop,
        )

    for row in add_prefixes or []:
        if not isinstance(row, (list, tuple)):
            continue
        r = list(row)
        while len(r) < len(HEADERS_DETAIL_NEW_PREFIXES):
            r.append("")
        cells = _audit_row_to_cells(HEADERS_DETAIL_NEW_PREFIXES, r)
        maybe_append_from_prefix_row(
            nb_scope=cells.get("NB Proposed Scope") or "",
            vlan_cell=cells.get("NB Proposed VLAN") or "",
            nb_proposed_prefix_description=cells.get(_NB_PREFIX_PROPOSED_DESC_HEADER) or "",
            os_description=cells.get("OS Description") or "",
            cidr=cells.get("CIDR") or "",
        )

    for row in update_prefixes or []:
        if not isinstance(row, (list, tuple)):
            continue
        r = list(row)
        while len(r) < len(HEADERS_DETAIL_EXISTING_PREFIXES):
            r.append("")
        cells = _audit_row_to_cells(HEADERS_DETAIL_EXISTING_PREFIXES, r)
        maybe_append_from_prefix_row(
            nb_scope=cells.get("NB Proposed Scope") or "",
            vlan_cell=cells.get("NB Proposed VLAN") or "",
            nb_proposed_prefix_description=cells.get(_NB_PREFIX_PROPOSED_DESC_HEADER) or "",
            os_description=cells.get("OS Description") or "",
            cidr=cells.get("CIDR") or "",
        )

    _ensure_unique_proposed_missing_vlan_names(out)
    return sorted(
        out,
        key=lambda x: (
            (x[0] or "").lower(),
            (x[1] or "").lower(),
            int(x[5] or 0) if str(x[5] or "").strip().isdigit() else 0,
        ),
    )
