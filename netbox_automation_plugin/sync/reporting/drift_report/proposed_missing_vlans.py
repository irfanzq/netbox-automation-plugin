"""Proposed IPAM VLAN rows when interface drift names a tagged VID missing from NetBox scope."""

from __future__ import annotations

import ipaddress
import random
import re
from collections import Counter
from typing import Any

_NB_VLAN_NAME_MAX_LEN = 64

from netbox_automation_plugin.sync.reporting.drift_report.drift_overrides_apply import (
    HEADERS_DETAIL_NIC_DRIFT,
    HEADERS_DETAIL_NEW_NICS,
)
from netbox_automation_plugin.sync.reporting.drift_report.proposed_action_format import (
    SET_NETBOX_ACTION_CREATE_VLAN,
)

_RE_UNTAGGED = re.compile(r"\bSET_NETBOX_UNTAGGED_VLAN\s*=\s*([^;]+)", re.I)

_IDX_DRIFT = {h: i for i, h in enumerate(HEADERS_DETAIL_NIC_DRIFT)}
_IDX_NEW = {h: i for i, h in enumerate(HEADERS_DETAIL_NEW_NICS)}


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


def _location_picker_label(loc) -> str:
    if loc is None:
        return ""
    try:
        site = getattr(loc, "site", None)
        site_name = (getattr(site, "name", None) or getattr(site, "slug", "") or "").strip()
        loc_name = (getattr(loc, "name", None) or "").strip()
        if site_name and loc_name:
            return f"{site_name} / {loc_name}"
        return loc_name or site_name
    except Exception:
        return (getattr(loc, "name", None) or "").strip()


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


def _tenant_display_from_vlan(v) -> str:
    if v is None or not getattr(v, "tenant_id", None):
        return ""
    t = getattr(v, "tenant", None)
    if t is None:
        return ""
    child = (t.name or "").strip()
    p = getattr(t, "parent", None)
    if p is not None and (p.name or "").strip():
        return f"{(p.name or '').strip()} / {child}"
    return child


def _defaults_for_vlan_group(group_name: str) -> dict[str, str]:
    """
    Tenant: plurality among 2–3 random VLANs in the group that already have a tenant.
    Status / VLAN name: first VLAN in the group by VID (stable template).
    """
    from ipam.models import VLAN, VLANGroup

    gn = (group_name or "").strip()
    if not gn:
        return {"tenant": "", "status": "active", "vlan_name": "TBD"}
    grp = VLANGroup.objects.filter(name__iexact=gn).first()
    if grp is None:
        return {"tenant": "", "status": "active", "vlan_name": "TBD"}
    gfk = "group" if any(f.name == "group" for f in VLAN._meta.fields) else "vlan_group"
    all_v = list(VLAN.objects.filter(**{gfk: grp}).select_related("tenant", "tenant__parent").order_by("vid"))
    if not all_v:
        return {"tenant": "", "status": "active", "vlan_name": "TBD"}

    with_tenant = [v for v in all_v if getattr(v, "tenant_id", None)]
    tenant_s = ""
    if with_tenant:
        nwt = len(with_tenant)
        if nwt == 1:
            sample = with_tenant
        else:
            k = 3 if nwt >= 3 else 2
            sample = random.sample(with_tenant, k)
        disps = [_tenant_display_from_vlan(v) for v in sample]
        disps = [d for d in disps if d]
        if disps:
            tenant_s = Counter(disps).most_common(1)[0][0]

    v0 = all_v[0]
    st = getattr(v0, "status", None)
    status_s = str(st).strip() if st is not None else "active"
    vn = (v0.name or "").strip() or "TBD"
    return {"tenant": tenant_s, "status": status_s, "vlan_name": vn}


def _clamp_nb_vlan_name(raw: str) -> str:
    s = (raw or "").strip()
    if not s or s in {"—", "-"}:
        return ""
    if len(s) > _NB_VLAN_NAME_MAX_LEN:
        return s[:_NB_VLAN_NAME_MAX_LEN].rstrip()
    return s


def _norm_mac_for_match(mac: str) -> str:
    s = (mac or "").strip().lower().replace("-", ":")
    parts = [p for p in s.split(":") if p]
    if len(parts) != 6:
        return s
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return s


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
) -> str:
    """
    Prefer NetBox-backed labels (prefix VLAN, existing group+VID), then MAAS/OpenStack names,
    then template default from :func:`_defaults_for_vlan_group`.
    """
    for ip_s in ip_strings:
        hit = _vlan_name_from_prefixes(prefix_rows_v4, prefix_rows_v6, ip_s, vid)
        if hit:
            return hit

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
) -> list[list[Any]]:
    """
    One row per (suggested VLAN group, VID) where NIC drift / new-NIC proposals reference a tagged
    VID that does not resolve for the device (or device absent — placement from NB site/location).
    """
    from netbox_automation_plugin.sync.reconciliation.apply_cells import _resolve_vlan_for_device

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
    ) -> None:
        try:
            if int(vid) <= 0 or int(vid) > 4094:
                return
        except (TypeError, ValueError):
            return
        if dev is not None and _resolve_vlan_for_device(dev, vid) is not None:
            return
        group = _suggest_vlan_group_name(device=dev, nb_site=nb_site, nb_location=nb_location)
        dfl = _defaults_for_vlan_group(group)
        site_disp = nb_site.strip() if (nb_site or "").strip() not in {"", "—", "-"} else ""
        if not site_disp and dev is not None and getattr(dev, "site", None):
            site_disp = (getattr(dev.site, "name", None) or "").strip()
        loc_disp = nb_location.strip() if (nb_location or "").strip() not in {"", "—", "-"} else ""
        if not loc_disp and dev is not None:
            loc_disp = _location_picker_label(getattr(dev, "location", None))
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
                str(vid),
                vid_src,
                maas_vlan if (maas_vlan or "").strip() else "—",
                os_vlan if (os_vlan or "").strip() else "—",
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
        if "SET_NETBOX_UNTAGGED_VLAN" not in pa.upper():
            continue
        vids = _parse_tagged_vids_from_proposed_action(pa)
        if not vids:
            continue
        host = str(r[_IDX_DRIFT["Host"]] or "").strip()
        dev = _device_for_host(host)
        nb_site = ""
        nb_loc = ""
        if dev is not None:
            if getattr(dev, "site", None):
                nb_site = (dev.site.name or "").strip()
            nb_loc = _location_picker_label(getattr(dev, "location", None))
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
            )

    for row in add_nb_interfaces or []:
        if not isinstance(row, (list, tuple)):
            continue
        r = list(row)
        while len(r) < len(HEADERS_DETAIL_NEW_NICS):
            r.append("")
        pa = str(r[_IDX_NEW["Proposed Action"]] or "")
        if "SET_NETBOX_UNTAGGED_VLAN" not in pa.upper():
            continue
        vids = _parse_tagged_vids_from_proposed_action(pa)
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
            )

    return sorted(
        out,
        key=lambda x: (
            (x[0] or "").lower(),
            (x[1] or "").lower(),
            int(x[2] or 0) if str(x[2] or "").strip().isdigit() else 0,
        ),
    )
