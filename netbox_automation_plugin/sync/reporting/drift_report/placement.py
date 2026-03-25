"""Drift inventory helpers and MAAS→NetBox site/location inference."""

import re

def _drift_for_user_reports(drift):
    """
    Shallow copy of drift for HTML/XLSX output and session cache.
    Clears in_netbox_not_maas (NetBox-only hostnames are not shown in user reports).
    """
    d = dict(drift or {})
    d["in_netbox_not_maas"] = []
    return d


def _dedupe_keep_order(items):
    seen = set()
    out = []
    for raw in (items or []):
        s = (str(raw or "")).strip()
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


def _format_inventory_list(
    items,
    *,
    noisy_regex=None,
    noisy_label="auto-generated",
    sample=20,
    max_named_display=35,
):
    vals = _dedupe_keep_order(items)
    if not vals:
        return "(none)"
    if not noisy_regex:
        if len(vals) <= max_named_display:
            return ", ".join(vals)
        show = vals[:max_named_display]
        more = len(vals) - len(show)
        return f"{', '.join(show)}, ... +{more} more unique"
    pat = re.compile(noisy_regex)
    noisy = [v for v in vals if pat.match(v)]
    named = [v for v in vals if not pat.match(v)]
    parts = []
    if named:
        show_n = named[:max_named_display]
        more_n = len(named) - len(show_n)
        txt_n = ", ".join(show_n)
        if more_n > 0:
            txt_n = f"{txt_n}, ... +{more_n} more named"
        parts.append(f"named ({len(named)} unique): {txt_n}")
    if noisy:
        show = noisy[:sample]
        more = len(noisy) - len(show)
        txt = ", ".join(show)
        if more > 0:
            txt = f"{txt}, ... +{more} more"
        parts.append(f"{noisy_label} ({len(noisy)} unique): {txt}")
    return " | ".join(parts) if parts else "(none)"


def _maas_machine_by_hostname(maas_data):
    out = {}
    for m in maas_data.get("machines") or []:
        h = (m.get("hostname") or "").strip()
        if h:
            out[h] = m
    return out


def _nb_tokens(s: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t}


def _fabric_matches_location_name(fabric_name: str, loc_name: str) -> bool:
    fab = (fabric_name or "").strip().lower()
    loc_l = (loc_name or "").strip().lower()
    if not fab or not loc_l:
        return False
    fab_compact = re.sub(r"[^a-z0-9]+", "", fab)
    loc_compact = re.sub(r"[^a-z0-9]+", "", loc_l)
    fab_tokens = _nb_tokens(fabric_name)
    loc_tokens = _nb_tokens(loc_name)
    if loc_compact and (loc_compact in fab_compact or fab_compact in loc_compact):
        return True
    return any(len(t) >= 4 and t in fab_tokens for t in loc_tokens)


def _location_suggestion_sort_key(fabric_name: str, loc_name: str):
    """
    Best key wins (max sort). Used to pick one NetBox location name for a MAAS fabric.

    Multi-word locations like "Birch Staging" must not beat "Staging" when the fabric is
    "spruce-staging": only the token "staging" overlapped, so coverage ratio is lower.
    """
    fab = (fabric_name or "").strip()
    nm = (loc_name or "").strip()
    if not fab or fab == "-" or not nm:
        return None
    if not _fabric_matches_location_name(fab, nm):
        return None
    fab_l = fab.lower()
    loc_l = nm.lower()
    fab_compact = re.sub(r"[^a-z0-9]+", "", fab_l)
    loc_compact = re.sub(r"[^a-z0-9]+", "", loc_l)
    fab_tokens = _nb_tokens(fab)
    loc_tokens = _nb_tokens(nm)
    if loc_compact and loc_compact in fab_compact:
        return (4, len(loc_compact), nm.lower())
    if fab_compact and fab_compact in loc_compact:
        return (3, len(fab_compact), nm.lower())
    sig = [t for t in loc_tokens if len(t) >= 4]
    if not sig:
        sig = [t for t in loc_tokens if t]
    if not sig:
        return None
    hits = sum(1 for t in sig if t in fab_tokens)
    if hits == 0:
        return None
    ratio = hits / len(sig)
    extra = len(sig) - hits
    matched_len = sum(len(t) for t in sig if t in fab_tokens)
    return (2, ratio, -extra, matched_len, nm.lower())


def _site_meta_for_slug(netbox_data, site_slug: str) -> dict:
    slug = (site_slug or "").strip()
    if not slug:
        return {}
    for s in netbox_data.get("sites") or []:
        if (s.get("slug") or "").strip() == slug:
            return s
    return {}


def _site_slug_for_location_name(netbox_data, location_name: str) -> str:
    loc_l = (location_name or "").strip().lower()
    if not loc_l:
        return ""
    for loc in netbox_data.get("locations") or []:
        nm = (loc.get("name") or "").strip().lower()
        if nm and nm == loc_l:
            return (loc.get("site_slug") or "").strip()
    return ""


def _derive_site_slug_from_maas(machine: dict, fabric_map: dict, pool_map: dict) -> str:
    fab = (machine.get("fabric_name") or "").strip()
    pool = (machine.get("pool_name") or "").strip()
    if fab and fab != "-":
        for k, v in (fabric_map or {}).items():
            if str(k).strip().lower() == fab.lower():
                return str(v).strip()
    if pool and pool != "-":
        for k, v in (pool_map or {}).items():
            if str(k).strip().lower() == pool.lower():
                return str(v).strip()
    return ""


def _suggest_nb_location_for_fabric(
    fabric_name: str, site_slug: str, netbox_data: dict
) -> str:
    fab = (fabric_name or "").strip()
    if not fab or fab == "-":
        return ""
    site_slug = (site_slug or "").strip()
    best_nm = ""
    best_key = None
    for loc in netbox_data.get("locations") or []:
        ss = (loc.get("site_slug") or "").strip()
        if site_slug and ss and ss != site_slug:
            continue
        nm = (loc.get("name") or "").strip()
        if not nm:
            continue
        key = _location_suggestion_sort_key(fab, nm)
        if key is None:
            continue
        if best_key is None or key > best_key:
            best_key = key
            best_nm = nm
    return best_nm


def _netbox_placement_from_maas_machine(
    machine: dict,
    netbox_data: dict,
    fabric_map: dict,
    pool_map: dict,
) -> tuple[str, str, str]:
    """NB region, site display name, and location for a MAAS-only host (Detail — new devices logic)."""
    site_slug = _derive_site_slug_from_maas(machine, fabric_map, pool_map)
    site_meta = _site_meta_for_slug(netbox_data, site_slug) if site_slug else {}
    nb_site = (
        (site_meta.get("name") or site_slug or "—").strip() if site_slug else "—"
    )
    nb_region = (site_meta.get("region_name") or "—") if site_slug else "—"
    nb_loc = (
        _suggest_nb_location_for_fabric(
            str(machine.get("fabric_name") or ""), site_slug, netbox_data
        )
        or "—"
    )
    if (not site_slug) and nb_loc not in {"", "—"}:
        site_slug = _site_slug_for_location_name(netbox_data, nb_loc)
        if site_slug:
            site_meta = _site_meta_for_slug(netbox_data, site_slug)
            nb_site = (site_meta.get("name") or site_slug or "—").strip()
            nb_region = site_meta.get("region_name") or "—"
    return nb_region, nb_site, nb_loc

