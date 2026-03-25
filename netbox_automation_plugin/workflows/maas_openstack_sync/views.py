from django.shortcuts import render
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.translation import gettext_lazy as _
from django.core.cache import cache
import re

from .forms import MAASOpenStackSyncForm

# Cache key for last drift audit result (so Download Excel uses it without re-running)
DRIFT_AUDIT_CACHE_TIMEOUT = 600  # seconds

# Sync package lives under netbox_automation_plugin.sync (not workflows.sync)
from netbox_automation_plugin.sync.config import get_sync_config, get_openstack_configs
from netbox_automation_plugin.sync.clients.maas_client import fetch_maas_data_sync
from netbox_automation_plugin.sync.clients.netbox_client import (
    fetch_netbox_data_local,
    fetch_netbox_audit_detail_for_names,
    fetch_netbox_interfaces_for_names,
    fetch_netbox_prefix_cidrs,
)
from netbox_automation_plugin.sync.reconciliation.audit_detail import (
    build_maas_netbox_interface_audit,
    build_maas_netbox_matched_rows,
    openstack_floating_ips_missing_from_netbox,
    openstack_subnet_prefix_hints,
    openstack_subnets_missing_prefixes,
)
from netbox_automation_plugin.sync.clients.openstack_client import fetch_openstack_data, fetch_all_openstack_data
from netbox_automation_plugin.sync.reconciliation.maas_netbox import compute_maas_netbox_drift
from netbox_automation_plugin.sync.reporting.drift_report import (
    _drift_for_user_reports,
    build_drift_report_xlsx,
    format_drift_report,
)
from django.http import HttpResponse
from django.urls import reverse

import logging

logger = logging.getLogger("netbox_automation_plugin")


def _list_site_location_choices():
    """Return (site_choices, location_choices, location_meta_by_key)."""
    site_choices = []
    location_choices = []
    location_meta = {}
    try:
        from dcim.models import Site, Location
        for s in Site.objects.only("slug", "name").order_by("name"):
            slug = (s.slug or "").strip()
            if slug:
                site_choices.append((slug, s.name or slug))
        for loc in (
            Location.objects.select_related("site")
            .only("name", "slug", "site__slug", "site__name")
            .order_by("site__name", "name")
        ):
            site_slug = (getattr(loc.site, "slug", "") or "").strip()
            loc_name = (loc.name or "").strip()
            if not site_slug or not loc_name:
                continue
            key = f"{site_slug}::{loc_name}"
            label = f"{getattr(loc.site, 'name', site_slug) or site_slug} / {loc_name}"
            location_choices.append((key, label))
            location_meta[key] = {"site_slug": site_slug, "location_name": loc_name}
    except Exception as e:
        logger.warning("Could not build site/location filter choices: %s", e)
    return site_choices, location_choices, location_meta


def _norm_tokens(s: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t}


def _unique_fabric_names(machines):
    """Distinct MAAS fabric_name values, normalized; dedupe case-insensitively."""
    seen: dict[str, str] = {}
    for m in machines or []:
        raw = (m.get("fabric_name") or "").strip()
        if not raw or raw == "-":
            continue
        raw = re.sub(r"\s+", " ", raw)
        key = raw.casefold()
        if key not in seen:
            seen[key] = raw
    return sorted(seen.values(), key=lambda x: x.casefold())


def _fabric_matches_locations(fabric_name: str, selected_location_names: set[str]) -> bool:
    """Fuzzy match MAAS fabric text to selected NetBox location names."""
    if not selected_location_names:
        return False
    fab = (fabric_name or "").strip().lower()
    if not fab:
        return False
    fab_compact = re.sub(r"[^a-z0-9]+", "", fab)
    fab_tokens = _norm_tokens(fab)
    for loc in selected_location_names:
        loc_l = (loc or "").strip().lower()
        if not loc_l:
            continue
        loc_compact = re.sub(r"[^a-z0-9]+", "", loc_l)
        loc_tokens = _norm_tokens(loc_l)
        if loc_compact and (loc_compact in fab_compact or fab_compact in loc_compact):
            return True
        if any(len(t) >= 4 and t in fab_tokens for t in loc_tokens):
            return True
    return False


def _maas_effective_dns_name(m: dict) -> str:
    """FQDN / DNS name for scope matching (hostname + domain from MAAS)."""
    dns = (m.get("dns_name") or "").strip()
    if dns:
        return dns
    fqdn = (m.get("fqdn") or "").strip()
    if fqdn:
        return fqdn
    host = (m.get("hostname") or "").strip()
    dom = (m.get("domain_name") or m.get("domain") or "").strip()
    if host and dom and "." not in host:
        return f"{host}.{dom}"
    return ""


def _maas_iface_row_fabric(m: dict, mi: dict) -> str:
    f = (mi.get("iface_fabric") or "").strip()
    if f and f != "-":
        return f
    return (m.get("fabric_name") or "").strip()


def _make_maas_iface_filter(selected_location_names: set, selected_sites: set):
    """
    Include MAAS interfaces that have a MAC — required for L2 identity vs NetBox (match by MAC).

    Interfaces without MAC in MAAS (some VLAN/bond children, placeholders) are skipped here;
    they are not comparable to NetBox NICs the same way.
    """
    _ = (selected_location_names, selected_sites)  # call-site compatibility; scope is upstream

    def filt(m: dict, mi: dict) -> bool:
        return bool((mi.get("mac") or "").strip())

    return filt


def _unique_fabrics_from_filtered_maas_interfaces(machines, iface_filt):
    """Distinct fabric names from MAAS NICs that pass iface_filt."""
    seen: dict[str, str] = {}
    for m in machines or []:
        for mi in m.get("interfaces") or []:
            if not iface_filt(m, mi):
                continue
            raw = _maas_iface_row_fabric(m, mi)
            if not raw or raw == "-":
                continue
            raw = re.sub(r"\s+", " ", raw)
            k = raw.casefold()
            if k not in seen:
                seen[k] = raw
    return sorted(seen.values(), key=lambda x: x.casefold())


def _text_matches_locations(text: str, selected_location_names: set[str]) -> bool:
    if not selected_location_names:
        return False
    src = (text or "").strip().lower()
    if not src:
        return False
    src_compact = re.sub(r"[^a-z0-9]+", "", src)
    src_tokens = _norm_tokens(src)
    for loc in selected_location_names:
        loc_l = (loc or "").strip().lower()
        if not loc_l:
            continue
        loc_compact = re.sub(r"[^a-z0-9]+", "", loc_l)
        loc_tokens = _norm_tokens(loc_l)
        if loc_compact and (loc_compact in src_compact or src_compact in loc_compact):
            return True
        if any(len(t) >= 4 and t in src_tokens for t in loc_tokens):
            return True
    return False


def _machine_fabrics(machine: dict) -> set[str]:
    """All fabric names seen on machine + interfaces (normalized)."""
    out = set()
    base = (machine.get("fabric_name") or "").strip()
    if base and base != "-":
        out.add(base)
    for mi in machine.get("interfaces") or []:
        f = (mi.get("iface_fabric") or "").strip()
        if f and f != "-":
            out.add(f)
    return out


def _location_matches_machine_fabrics(location_name: str, machine: dict) -> bool:
    for fab in _machine_fabrics(machine):
        if _fabric_matches_locations(fab, {location_name}):
            return True
    return False


def _fqdn_location_hint(machine: dict, candidate_locations: set[str]) -> str:
    """
    Resolve ambiguous host location using MAAS DNS/FQDN text.
    Prefer longer location names first (more specific token matches).
    """
    dns_text = _maas_effective_dns_name(machine)
    for loc in sorted(candidate_locations or set(), key=lambda x: (-len(x), x.lower())):
        if _text_matches_locations(dns_text, {loc}):
            return loc
    return ""


def _scoped_location_decision(
    machine: dict,
    selected_location_names: set[str],
    all_location_names: set[str],
) -> tuple[bool, str]:
    """
    Decide if host belongs in selected location scope.

    If host spans selected and non-selected fabrics, use FQDN/DNS as tie-break.
    """
    if not selected_location_names:
        return False, ""

    selected_hits = {
        loc for loc in selected_location_names
        if _location_matches_machine_fabrics(loc, machine)
    }
    if not selected_hits:
        return (_text_matches_locations(_maas_effective_dns_name(machine), selected_location_names), "")

    other_hits = {
        loc for loc in (all_location_names - selected_location_names)
        if _location_matches_machine_fabrics(loc, machine)
    }
    if not other_hits:
        chosen = sorted(selected_hits, key=lambda x: x.lower())[0]
        return True, chosen

    # Host appears on multiple location-like fabrics; force location via DNS/FQDN hint.
    hinted = _fqdn_location_hint(machine, selected_hits | other_hits)
    if hinted:
        return (hinted in selected_location_names), hinted
    return False, ""


def _filter_openstack_by_locations(openstack_data: dict, selected_location_names: set[str]) -> tuple[dict, dict]:
    """
    Scope OpenStack data by selected NB locations using fuzzy text matching:
    - networks.name
    - subnets.name / subnets.description
    - floating_ips.project_name
    - floating_ips.floating_network_id (if network matched)
    """
    if not openstack_data or openstack_data.get("error") or not selected_location_names:
        return openstack_data, {
            "openstack_networks_before": len((openstack_data or {}).get("networks") or []),
            "openstack_subnets_before": len((openstack_data or {}).get("subnets") or []),
            "openstack_fips_before": len((openstack_data or {}).get("floating_ips") or []),
            "openstack_networks_after": len((openstack_data or {}).get("networks") or []),
            "openstack_subnets_after": len((openstack_data or {}).get("subnets") or []),
            "openstack_fips_after": len((openstack_data or {}).get("floating_ips") or []),
            "openstack_unmatched_network_names": [],
        }

    nets = list(openstack_data.get("networks") or [])
    subs = list(openstack_data.get("subnets") or [])
    fips = list(openstack_data.get("floating_ips") or [])

    matched_net_ids = {
        n.get("id")
        for n in nets
        if _text_matches_locations(n.get("name") or "", selected_location_names)
    }
    matched_net_ids = {x for x in matched_net_ids if x}

    filtered_subs = []
    for s in subs:
        if (
            (s.get("network_id") in matched_net_ids)
            or _text_matches_locations(s.get("name") or "", selected_location_names)
            or _text_matches_locations(s.get("description") or "", selected_location_names)
        ):
            filtered_subs.append(s)
            if s.get("network_id"):
                matched_net_ids.add(s.get("network_id"))

    filtered_nets = [n for n in nets if (n.get("id") in matched_net_ids)]

    filtered_fips = []
    for f in fips:
        if (
            _text_matches_locations(str(f.get("project_name") or ""), selected_location_names)
            or ((f.get("floating_network_id") or "") in matched_net_ids)
        ):
            filtered_fips.append(f)

    scoped = dict(openstack_data)
    scoped["networks"] = filtered_nets
    scoped["subnets"] = filtered_subs
    scoped["floating_ips"] = filtered_fips
    unmatched_network_names = sorted({
        (n.get("name") or "").strip()
        for n in nets
        if (n.get("name") or "").strip() and (n.get("id") not in matched_net_ids)
    })
    meta = {
        "openstack_networks_before": len(nets),
        "openstack_subnets_before": len(subs),
        "openstack_fips_before": len(fips),
        "openstack_networks_after": len(filtered_nets),
        "openstack_subnets_after": len(filtered_subs),
        "openstack_fips_after": len(filtered_fips),
        "openstack_unmatched_network_names": unmatched_network_names[:20],
        "openstack_unmatched_network_names_more": max(0, len(unmatched_network_names) - 20),
    }
    return scoped, meta


def _drift_audit_cache_key(request):
    """Per-session key for cached drift audit (so Download Excel does not re-run)."""
    return f"drift_audit:{request.session.session_key or request.user.pk}"


def _cache_drift_audit(request, payload):
    """Store audit payload for later XLSX download. drift sets -> lists for serialization."""
    key = _drift_audit_cache_key(request)
    drift_raw = payload.get("drift") or {}
    payload = dict(payload)
    # Do not persist NetBox-only hostnames; same sanitization as HTML/XLSX reports.
    payload["drift"] = {
        **_drift_for_user_reports(drift_raw),
        "in_maas_not_netbox": list(drift_raw.get("in_maas_not_netbox") or []),
    }
    cache.set(key, payload, timeout=DRIFT_AUDIT_CACHE_TIMEOUT)


def _audit_summary_from_payload(payload):
    """Build audit_summary dict from cached or fresh audit payload."""
    maas_data = payload.get("maas_data") or {}
    netbox_data = payload.get("netbox_data") or {}
    openstack_data = payload.get("openstack_data")
    drift = payload.get("drift") or {}
    matched_rows = payload.get("matched_rows")
    interface_audit = payload.get("interface_audit")
    return {
        "maas_ok": not maas_data.get("error"),
        "maas_machines": len(maas_data.get("machines") or []),
        "maas_error": (maas_data.get("error") or "")[:280],
        "netbox_ok": not netbox_data.get("error"),
        "netbox_devices": len(netbox_data.get("devices") or []),
        "netbox_error": (netbox_data.get("error") or "")[:280],
        "openstack_ok": openstack_data and not openstack_data.get("error"),
        "openstack_skipped": openstack_data is None,
        "openstack_networks": len((openstack_data or {}).get("networks") or []),
        "openstack_subnets": len((openstack_data or {}).get("subnets") or []),
        "openstack_fips": len((openstack_data or {}).get("floating_ips") or []),
        "openstack_error": ((openstack_data or {}).get("error") or "")[:320],
        "openstack_cred_missing": bool((openstack_data or {}).get("openstack_cred_missing")),
        "matched_hostnames": len(matched_rows or []),
        "interface_audit_hosts": len((interface_audit or {}).get("hosts") or []),
        "drift_matched": drift.get("matched_count", 0),
    }


class MAASOpenStackSyncView(LoginRequiredMixin, View):
    """
    MAAS / OpenStack Sync workflow.

    Automation -> MAAS / OpenStack Sync.
    Phase 1: Drift Audit (read-only). Full Sync and branch apply in later phases.
    """

    template_name = "netbox_automation_plugin/maas_openstack_sync_form.html"

    def get(self, request):
        site_choices, location_choices, _ = _list_site_location_choices()
        form = MAASOpenStackSyncForm(site_choices=site_choices, location_choices=location_choices)
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        site_choices, location_choices, location_meta = _list_site_location_choices()
        # Empty <select multiple> is often omitted from POST entirely; normalize so the audit always runs.
        post_data = request.POST.copy()
        if "sites" not in post_data:
            post_data.setlist("sites", [])
        if "locations" not in post_data:
            post_data.setlist("locations", [])
        form = MAASOpenStackSyncForm(
            post_data,
            site_choices=site_choices,
            location_choices=location_choices,
        )
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})

        mode = (form.cleaned_data.get("mode") or "audit").strip()
        if mode != "audit":
            return render(request, self.template_name, {"form": form})

        selected_sites = set(form.cleaned_data.get("sites") or [])
        selected_location_keys = set(form.cleaned_data.get("locations") or [])
        all_sites_selected = "__all__" in selected_sites
        all_locations_selected = "__all__" in selected_location_keys
        selected_sites.discard("__all__")
        selected_location_keys.discard("__all__")
        selected_location_names = {
            location_meta[k]["location_name"]
            for k in selected_location_keys
            if k in location_meta
        }
        selected_location_sites = {
            location_meta[k]["site_slug"]
            for k in selected_location_keys
            if k in location_meta
        }
        # Keep parent-site context for display/debug only. Do NOT widen host scope by site
        # when specific locations are selected; location-scoped runs must stay strict.
        selected_sites |= selected_location_sites
        if all_sites_selected:
            selected_sites = set()
        if all_locations_selected:
            selected_location_names = set()
        scope_meta = {
            "selected_sites": sorted(selected_sites),
            "selected_locations": sorted(selected_location_names),
        }

        # If Download Excel: show report and trigger download (via GET endpoint). Cache hit = use cache; miss = run audit below.
        export_xlsx = request.POST.get("format") == "xlsx"
        if export_xlsx:
            cached = cache.get(_drift_audit_cache_key(request))
            if cached:
                try:
                    report_out = format_drift_report(
                        cached["maas_data"],
                        cached["netbox_data"],
                        cached["openstack_data"],
                        cached["drift"],
                        matched_rows=cached.get("matched_rows"),
                        os_subnet_hints=cached.get("os_subnet_hints"),
                        os_subnet_gaps=cached.get("os_subnet_gaps"),
                        os_floating_gaps=cached.get("os_floating_gaps"),
                        netbox_prefix_count=cached.get("netbox_prefix_count", 0),
                        interface_audit=cached.get("interface_audit"),
                        netbox_ifaces=cached.get("netbox_ifaces"),
                    )
                    report_drift = report_out.get("drift", "") if isinstance(report_out, dict) else report_out
                    report_drift_markup = (
                        report_out.get("drift_markup", "text")
                        if isinstance(report_out, dict)
                        else "text"
                    )
                    report_reference = report_out.get("reference", "") if isinstance(report_out, dict) else ""
                    audit_summary = _audit_summary_from_payload(cached)
                    return render(
                        request,
                        self.template_name,
                        {
                            "form": form,
                            "report_drift": report_drift,
                            "report_drift_markup": report_drift_markup,
                            "report_reference": report_reference,
                            "audit_done": True,
                            "audit_summary": audit_summary,
                            "auto_download_xlsx": True,
                            "download_xlsx_url": request.build_absolute_uri(
                                reverse("plugins:netbox_automation_plugin:maas_openstack_sync_download_xlsx")
                            ),
                        },
                    )
                except Exception as e:
                    logger.warning("Report from cache failed, will re-run audit: %s", e)

        # Phase 1: Drift Audit — MAAS + OpenStack via HTTP; NetBox via local DB (same as vlan_deployment)
        config = get_sync_config()

        # 1) MAAS
        maas_data = fetch_maas_data_sync(
            config.get("maas_url") or "",
            config.get("maas_api_key") or "",
            config.get("maas_insecure", True),
        )
        maas_machines_before = list(maas_data.get("machines") or [])
        scope_meta["maas_machines_before"] = len(maas_machines_before)
        fabrics_before = _unique_fabric_names(maas_machines_before)
        scope_meta["maas_all_fabrics"] = fabrics_before

        # 2) NetBox — local ORM only (same process as NetBox app)
        netbox_data = fetch_netbox_data_local()
        scope_meta["netbox_devices_before"] = len(netbox_data.get("devices") or [])

        # Optional site/location filter scope based on NetBox canonical data.
        if selected_sites or selected_location_names:
            try:
                from dcim.models import Device
                dev_qs = Device.objects.select_related("site", "location").only(
                    "name", "site__slug", "location__name"
                )
                if selected_sites:
                    dev_qs = dev_qs.filter(site__slug__in=selected_sites)
                if selected_location_names:
                    dev_qs = dev_qs.filter(location__name__in=selected_location_names)
                allowed_nb_names = {
                    (d.name or "").strip()
                    for d in dev_qs
                    if (d.name or "").strip()
                }
                netbox_data["devices"] = [
                    d for d in (netbox_data.get("devices") or [])
                    if (d.get("name") or "").strip() in allowed_nb_names
                ]
            except Exception as e:
                logger.warning("Failed applying NetBox site/location filter: %s", e)
        scope_meta["netbox_devices_after"] = len(netbox_data.get("devices") or [])

        # 3) OpenStack — one or more clouds (OPENSTACK_* and optional OPENSTACK_2_*); merge into one dataset
        openstack_configs = get_openstack_configs()
        openstack_data = None
        all_results = []
        if openstack_configs:
            c1 = openstack_configs[0]
            has_creds_1 = bool(
                (c1.get("openstack_password") or "").strip()
                or (
                    (c1.get("openstack_application_credential_id") or "").strip()
                    and (c1.get("openstack_application_credential_secret") or "").strip()
                )
            )
            if not has_creds_1 and len(openstack_configs) == 1:
                openstack_data = {
                    "networks": [],
                    "subnets": [],
                    "floating_ips": [],
                    "runtime_nics": [],
                    "runtime_bmc": [],
                    "error": "OpenStack auth URL set but no OS_PASSWORD (or application credential ID/secret). Drift report will omit OpenStack data.",
                    "openstack_cred_missing": True,
                }
            else:
                all_results = fetch_all_openstack_data(openstack_configs)
                # Merge all clouds into one dataset; user sees one OpenStack vs NetBox report
                merged = {
                    "networks": [],
                    "subnets": [],
                    "floating_ips": [],
                    "runtime_nics": [],
                    "runtime_bmc": [],
                    "error": None,
                }
                errors = []
                for r in all_results:
                    data = r.get("data") or {}
                    if data.get("error"):
                        errors.append((r.get("label") or "OpenStack") + ": " + (data["error"][:80] or "error"))
                    else:
                        merged["networks"].extend(data.get("networks") or [])
                        merged["subnets"].extend(data.get("subnets") or [])
                        merged["floating_ips"].extend(data.get("floating_ips") or [])
                        merged["runtime_nics"].extend(data.get("runtime_nics") or [])
                        merged["runtime_bmc"].extend(data.get("runtime_bmc") or [])
                if errors and not merged["networks"] and not merged["subnets"] and not merged["floating_ips"]:
                    merged["error"] = "; ".join(errors)
                elif errors:
                    merged["error"] = None  # partial success; report combined data
                # Per-cloud counts and errors so report can show "data from N clouds" and why one failed
                merged["_cloud_summary"] = []
                for r in all_results:
                    data = r.get("data") or {}
                    err = data.get("error")
                    merged["_cloud_summary"].append({
                        "label": r.get("label") or "OpenStack",
                        "networks": len(data.get("networks") or []),
                        "subnets": len(data.get("subnets") or []),
                        "floating_ips": len(data.get("floating_ips") or []),
                        "runtime_nics": len(data.get("runtime_nics") or []),
                        "runtime_bmc": len(data.get("runtime_bmc") or []),
                        "error": (err[:200] if err else None),
                    })
                openstack_data = merged
                logger.info(
                    "OpenStack merge: %d clouds -> %d networks, %d subnets, %d FIPs, %d runtime NIC rows, %d runtime BMC rows (clouds: %s)",
                    len(all_results),
                    len(merged["networks"]),
                    len(merged["subnets"]),
                    len(merged["floating_ips"]),
                    len(merged["runtime_nics"]),
                    len(merged["runtime_bmc"]),
                    [
                        (
                            c["label"],
                            c["networks"],
                            c["subnets"],
                            c["floating_ips"],
                            c["runtime_nics"],
                            c["runtime_bmc"],
                        )
                        for c in merged["_cloud_summary"]
                    ],
                )
        # Full inventory lists for manual verification (before location filter on OpenStack).
        if openstack_data and not openstack_data.get("error"):
            scope_meta["openstack_all_network_names"] = sorted({
                (n.get("name") or "").strip()
                for n in (openstack_data.get("networks") or [])
                if (n.get("name") or "").strip()
            })
        else:
            scope_meta["openstack_all_network_names"] = []
        scope_meta["openstack_networks_before"] = len((openstack_data or {}).get("networks") or [])
        scope_meta["openstack_subnets_before"] = len((openstack_data or {}).get("subnets") or [])
        scope_meta["openstack_fips_before"] = len((openstack_data or {}).get("floating_ips") or [])

        # 4) Drift (MAAS vs NetBox)
        drift = compute_maas_netbox_drift(maas_data, netbox_data)

        matched_rows = None
        interface_audit = None
        netbox_ifaces_for_report = None
        audit_map = None
        os_subnet_hints = None
        os_subnet_gaps = None
        os_floating_gaps = []
        netbox_prefix_count = 0
        if not netbox_data.get("error"):
            maas_h = {
                (m.get("hostname") or "").strip()
                for m in (maas_data.get("machines") or [])
                if (m.get("hostname") or "").strip()
            }
            nb_h = {
                (d.get("name") or "").strip()
                for d in (netbox_data.get("devices") or [])
                if (d.get("name") or "").strip()
            }
            matched_names = maas_h & nb_h
            audit_map = fetch_netbox_audit_detail_for_names(matched_names)
            matched_rows = build_maas_netbox_matched_rows(
                maas_data, audit_map, openstack_data
            )
            prefix_set = fetch_netbox_prefix_cidrs()
            netbox_prefix_count = len(prefix_set)
            if openstack_data and not openstack_data.get("error"):
                os_subnet_hints = openstack_subnet_prefix_hints(openstack_data, prefix_set)
                os_subnet_gaps = openstack_subnets_missing_prefixes(os_subnet_hints)

        if openstack_data and not openstack_data.get("error"):
            os_floating_gaps = openstack_floating_ips_missing_from_netbox(openstack_data)

        # Optional OpenStack scope by selected NetBox locations using naming heuristics.
        if selected_location_names and openstack_data and not openstack_data.get("error"):
            openstack_data, os_scope = _filter_openstack_by_locations(openstack_data, selected_location_names)
            scope_meta.update(os_scope)
            # Recompute OpenStack gap outputs after OpenStack scoping
            if not netbox_data.get("error"):
                prefix_set = fetch_netbox_prefix_cidrs()
                netbox_prefix_count = len(prefix_set)
                os_subnet_hints = openstack_subnet_prefix_hints(openstack_data, prefix_set)
                os_subnet_gaps = openstack_subnets_missing_prefixes(os_subnet_hints)
            os_floating_gaps = openstack_floating_ips_missing_from_netbox(openstack_data)
        else:
            scope_meta["openstack_networks_after"] = len((openstack_data or {}).get("networks") or [])
            scope_meta["openstack_subnets_after"] = len((openstack_data or {}).get("subnets") or [])
            scope_meta["openstack_fips_after"] = len((openstack_data or {}).get("floating_ips") or [])
            scope_meta["openstack_unmatched_network_names"] = []
            scope_meta["openstack_unmatched_network_names_more"] = 0
        scope_meta["openstack_network_names_after"] = sorted({
            (n.get("name") or "").strip()
            for n in ((openstack_data or {}).get("networks") or [])
            if (n.get("name") or "").strip()
        })

        # Apply MAAS-side scope after audit maps are built:
        # include hosts in selected NB scope OR hosts with MAAS fabric fuzzy-matching selected locations.
        host_location_override: dict[str, str] = {}
        if selected_sites or selected_location_names:
            allowed_names = set()
            all_location_names = {
                (meta.get("location_name") or "").strip()
                for meta in (location_meta or {}).values()
                if (meta.get("location_name") or "").strip()
            }
            if matched_rows:
                for r in matched_rows:
                    host = (r.get("hostname") or "").strip()
                    if not host:
                        continue
                    nb_site = (r.get("netbox_site") or "").strip()
                    nb_loc = (r.get("netbox_location") or "").strip()
                    # Location selection is strict: do not include by site-only match.
                    if (not selected_location_names) and selected_sites and nb_site in selected_sites:
                        allowed_names.add(host)
                    if selected_location_names and nb_loc in selected_location_names:
                        allowed_names.add(host)
            for m in (maas_data.get("machines") or []):
                host = (m.get("hostname") or "").strip()
                if not host:
                    continue
                if selected_location_names:
                    in_scope, chosen_loc = _scoped_location_decision(
                        m, selected_location_names, all_location_names
                    )
                    if in_scope:
                        allowed_names.add(host)
                        if chosen_loc:
                            host_location_override[host] = chosen_loc
                if selected_location_names and _text_matches_locations(
                    _maas_effective_dns_name(m), selected_location_names
                ):
                    allowed_names.add(host)
                if selected_sites and _text_matches_locations(
                    _maas_effective_dns_name(m), selected_sites
                ):
                    # Same rule: if locations are selected, ignore site-only DNS matches.
                    if not selected_location_names:
                        allowed_names.add(host)

            maas_data["machines"] = [
                m for m in (maas_data.get("machines") or [])
                if (m.get("hostname") or "").strip() in allowed_names
            ]
            if selected_location_names:
                unmatched_keys: dict[str, str] = {}
                for m in maas_machines_before:
                    raw = (m.get("fabric_name") or "").strip()
                    if not raw or raw == "-":
                        continue
                    raw = re.sub(r"\s+", " ", raw)
                    if not _fabric_matches_locations(raw, selected_location_names):
                        k = raw.casefold()
                        if k not in unmatched_keys:
                            unmatched_keys[k] = raw
                unmatched_fabrics = sorted(unmatched_keys.values(), key=lambda x: x.casefold())
            else:
                unmatched_fabrics = []
            scope_meta["maas_unmatched_fabrics"] = unmatched_fabrics[:20]
            scope_meta["maas_unmatched_fabrics_more"] = max(0, len(unmatched_fabrics) - 20)
            if matched_rows is not None:
                matched_rows = [r for r in matched_rows if (r.get("hostname") or "").strip() in allowed_names]
                for r in matched_rows:
                    h = (r.get("hostname") or "").strip()
                    if h in host_location_override:
                        r["maas_fabric"] = host_location_override[h]

            # Recompute drift counts from scoped host/device sets.
            drift = compute_maas_netbox_drift(maas_data, netbox_data)

        # NIC filter: MAC only — host scope is from NetBox + MAAS DNS/fabric above.
        _iface_filt = _make_maas_iface_filter(
            selected_location_names or set(),
            selected_sites or set(),
        )
        scope_meta["maas_fabrics_after"] = _unique_fabrics_from_filtered_maas_interfaces(
            maas_data.get("machines"), _iface_filt
        )

        if not netbox_data.get("error"):
            nb_h_final = {
                (d.get("name") or "").strip()
                for d in (netbox_data.get("devices") or [])
                if (d.get("name") or "").strip()
            }
            maas_h_final = {
                (m.get("hostname") or "").strip()
                for m in (maas_data.get("machines") or [])
                if (m.get("hostname") or "").strip()
            }
            mn_final = maas_h_final & nb_h_final
            audit_map_final = fetch_netbox_audit_detail_for_names(mn_final)
            nb_if_final = fetch_netbox_interfaces_for_names(mn_final)
            netbox_ifaces_for_report = nb_if_final
            interface_audit = build_maas_netbox_interface_audit(
                mn_final,
                maas_data,
                nb_if_final,
                netbox_audit=audit_map_final,
                maas_iface_filter=_iface_filt,
                openstack_data=openstack_data,
            )
            if interface_audit and host_location_override:
                for host_row in interface_audit.get("hosts") or []:
                    h = (host_row.get("hostname") or "").strip()
                    forced_loc = host_location_override.get(h)
                    if not forced_loc:
                        continue
                    host_row["maas_fabric"] = forced_loc
                    for nic_row in host_row.get("rows") or []:
                        nic_row["maas_fabric"] = forced_loc

        scope_meta["maas_machines_after"] = len(maas_data.get("machines") or [])
        scope_meta["coverage_status"] = (
            "PASS"
            if not maas_data.get("error") and not netbox_data.get("error") and not ((openstack_data or {}).get("error"))
            else "PARTIAL"
        )
        drift["scope_meta"] = scope_meta

        # 5) Report (drift-only main + reference for collapsible section); single combined OpenStack view
        report_out = format_drift_report(
            maas_data,
            netbox_data,
            openstack_data,
            drift,
            matched_rows=matched_rows,
            os_subnet_hints=os_subnet_hints,
            os_subnet_gaps=os_subnet_gaps,
            os_floating_gaps=os_floating_gaps,
            netbox_prefix_count=netbox_prefix_count,
            interface_audit=interface_audit,
            netbox_ifaces=netbox_ifaces_for_report,
        )
        report_drift = report_out.get("drift", "") if isinstance(report_out, dict) else report_out
        report_drift_markup = (
            report_out.get("drift_markup", "text") if isinstance(report_out, dict) else "text"
        )
        report_reference = report_out.get("reference", "") if isinstance(report_out, dict) else ""

        maas_m = len(maas_data.get("machines") or [])
        nb_d = len(netbox_data.get("devices") or [])
        audit_summary = {
            "maas_ok": not maas_data.get("error"),
            "maas_machines": maas_m,
            "maas_error": (maas_data.get("error") or "")[:280],
            "netbox_ok": not netbox_data.get("error"),
            "netbox_devices": nb_d,
            "netbox_error": (netbox_data.get("error") or "")[:280],
            "openstack_ok": openstack_data and not openstack_data.get("error"),
            "openstack_skipped": openstack_data is None,
            "openstack_networks": len((openstack_data or {}).get("networks") or []),
            "openstack_subnets": len((openstack_data or {}).get("subnets") or []),
            "openstack_fips": len((openstack_data or {}).get("floating_ips") or []),
            "openstack_error": ((openstack_data or {}).get("error") or "")[:320],
            "openstack_cred_missing": bool(
                (openstack_data or {}).get("openstack_cred_missing")
            ),
            "matched_hostnames": len(matched_rows or []),
            "interface_audit_hosts": len((interface_audit or {}).get("hosts") or []),
            "drift_matched": drift.get("matched_count", 0),
        }

        # Store result so "Download as Excel" can use it without re-running the audit
        try:
            _cache_drift_audit(request, {
                "maas_data": maas_data,
                "netbox_data": netbox_data,
                "openstack_data": openstack_data,
                "drift": drift,
                "matched_rows": matched_rows,
                "os_subnet_hints": os_subnet_hints,
                "os_subnet_gaps": os_subnet_gaps,
                "os_floating_gaps": os_floating_gaps,
                "netbox_prefix_count": netbox_prefix_count,
                "interface_audit": interface_audit,
                "netbox_ifaces": netbox_ifaces_for_report,
            })
        except Exception as e:
            logger.debug("Could not cache drift audit for XLSX reuse: %s", e)

        if export_xlsx:
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                    "report_drift": report_drift,
                    "report_drift_markup": report_drift_markup,
                    "report_reference": report_reference,
                    "audit_done": True,
                    "audit_summary": audit_summary,
                    "auto_download_xlsx": True,
                    "download_xlsx_url": request.build_absolute_uri(
                        reverse("plugins:netbox_automation_plugin:maas_openstack_sync_download_xlsx")
                    ),
                },
            )

        return render(
            request,
            self.template_name,
            {
                "form": form,
                "report_drift": report_drift,
                "report_drift_markup": report_drift_markup,
                "report_reference": report_reference,
                "audit_done": True,
                "audit_summary": audit_summary,
            },
        )


class DriftAuditDownloadXlsxView(LoginRequiredMixin, View):
    """GET: return drift-report.xlsx from session cache (no re-run). Used after POST format=xlsx to trigger download."""

    def get(self, request):
        cached = cache.get(_drift_audit_cache_key(request))
        if not cached:
            return HttpResponse(
                _("Run drift audit first, then use Download as Excel."),
                status=404,
                content_type="text/plain; charset=utf-8",
            )
        try:
            xlsx_bytes = build_drift_report_xlsx(
                cached["maas_data"],
                cached["netbox_data"],
                cached["openstack_data"],
                cached["drift"],
                matched_rows=cached.get("matched_rows"),
                os_subnet_hints=cached.get("os_subnet_hints"),
                os_subnet_gaps=cached.get("os_subnet_gaps"),
                os_floating_gaps=cached.get("os_floating_gaps"),
                netbox_prefix_count=cached.get("netbox_prefix_count", 0),
                interface_audit=cached.get("interface_audit"),
                netbox_ifaces=cached.get("netbox_ifaces"),
            )
        except Exception as e:
            logger.exception("XLSX export failed: %s", e)
            return HttpResponse(
                _("Excel export failed: ") + str(e),
                status=500,
                content_type="text/plain; charset=utf-8",
            )
        resp = HttpResponse(
            xlsx_bytes,
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        resp["Content-Disposition"] = 'attachment; filename="drift-report.xlsx"'
        return resp
