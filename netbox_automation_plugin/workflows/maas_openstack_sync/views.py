from django.shortcuts import render
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.translation import gettext_lazy as _
from django.core.cache import cache

from .forms import MAASOpenStackSyncForm

# Cache key for last drift audit result (so Download Excel uses it without re-running)
DRIFT_AUDIT_CACHE_TIMEOUT = 600  # seconds

# Sync package lives under netbox_automation_plugin.sync (not workflows.sync)
from netbox_automation_plugin.sync.config import get_sync_config, get_openstack_configs
from netbox_automation_plugin.sync.clients.maas_client import fetch_maas_data_sync
from netbox_automation_plugin.sync.clients.netbox_client import (
    fetch_netbox_data,
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
    format_drift_report,
    build_drift_report_xlsx,
)
from django.http import HttpResponse
from django.urls import reverse

import logging
import os

logger = logging.getLogger("netbox_automation_plugin")


def _drift_audit_cache_key(request):
    """Per-session key for cached drift audit (so Download Excel does not re-run)."""
    return f"drift_audit:{request.session.session_key or request.user.pk}"


def _cache_drift_audit(request, payload):
    """Store audit payload for later XLSX download. drift sets -> lists for serialization."""
    key = _drift_audit_cache_key(request)
    drift = payload.get("drift") or {}
    payload = dict(payload)
    payload["drift"] = {
        **drift,
        "in_maas_not_netbox": list(drift.get("in_maas_not_netbox") or []),
        "in_netbox_not_maas": list(drift.get("in_netbox_not_maas") or []),
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
    use_remote_netbox = payload.get("use_remote_netbox", False)
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
        "use_remote_netbox": use_remote_netbox,
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
        form = MAASOpenStackSyncForm()
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = MAASOpenStackSyncForm(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})

        mode = (form.cleaned_data.get("mode") or "audit").strip()
        if mode != "audit":
            return render(request, self.template_name, {"form": form})

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
                        use_remote_netbox=cached.get("use_remote_netbox", False),
                        interface_audit=cached.get("interface_audit"),
                    )
                    report_drift = report_out.get("drift", "") if isinstance(report_out, dict) else report_out
                    report_reference = report_out.get("reference", "") if isinstance(report_out, dict) else ""
                    audit_summary = _audit_summary_from_payload(cached)
                    return render(
                        request,
                        self.template_name,
                        {
                            "form": form,
                            "report_drift": report_drift,
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

        # 2) NetBox — ORM inside this app (no NETBOX_URL / token / DNS)
        use_remote_netbox = str(
            config.get("netbox_sync_use_remote_api") or os.environ.get("NETBOX_SYNC_USE_REMOTE_API", "")
        ).lower() in ("1", "true", "yes")
        if use_remote_netbox:
            base_url = request.build_absolute_uri("/").rstrip("/") if request else ""
            netbox_data = fetch_netbox_data(
                config.get("netbox_url") or "",
                config.get("netbox_token") or "",
                base_url_fallback=base_url,
                ssl_verify=config.get("netbox_ssl_verify", True),
                ca_bundle=config.get("netbox_ca_bundle") or None,
            )
        else:
            netbox_data = fetch_netbox_data_local()

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
                    "error": "OpenStack auth URL set but no OS_PASSWORD (or application credential ID/secret). Drift report will omit OpenStack data.",
                    "openstack_cred_missing": True,
                }
            else:
                all_results = fetch_all_openstack_data(openstack_configs)
                # Merge all clouds into one dataset; user sees one OpenStack vs NetBox report
                merged = {"networks": [], "subnets": [], "floating_ips": [], "error": None}
                errors = []
                for r in all_results:
                    data = r.get("data") or {}
                    if data.get("error"):
                        errors.append((r.get("label") or "OpenStack") + ": " + (data["error"][:80] or "error"))
                    else:
                        merged["networks"].extend(data.get("networks") or [])
                        merged["subnets"].extend(data.get("subnets") or [])
                        merged["floating_ips"].extend(data.get("floating_ips") or [])
                if errors and not merged["networks"] and not merged["subnets"] and not merged["floating_ips"]:
                    merged["error"] = "; ".join(errors)
                elif errors:
                    merged["error"] = None  # partial success; report combined data
                # Per-cloud counts so report can show "data from N clouds" for validation
                merged["_cloud_summary"] = [
                    {
                        "label": r.get("label") or "OpenStack",
                        "networks": len((r.get("data") or {}).get("networks") or []),
                        "subnets": len((r.get("data") or {}).get("subnets") or []),
                        "floating_ips": len((r.get("data") or {}).get("floating_ips") or []),
                    }
                    for r in all_results
                ]
                openstack_data = merged
                logger.info(
                    "OpenStack merge: %d clouds -> %d networks, %d subnets, %d FIPs (clouds: %s)",
                    len(all_results),
                    len(merged["networks"]),
                    len(merged["subnets"]),
                    len(merged["floating_ips"]),
                    [(c["label"], c["networks"], c["subnets"], c["floating_ips"]) for c in merged["_cloud_summary"]],
                )

        # 4) Drift (MAAS vs NetBox)
        drift = compute_maas_netbox_drift(maas_data, netbox_data)

        matched_rows = None
        interface_audit = None
        os_subnet_hints = None
        os_subnet_gaps = None
        os_floating_gaps = []
        netbox_prefix_count = 0
        if not use_remote_netbox and not netbox_data.get("error"):
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
            nb_ifaces = fetch_netbox_interfaces_for_names(matched_names)
            interface_audit = build_maas_netbox_interface_audit(
                matched_names, maas_data, nb_ifaces, netbox_audit=audit_map
            )
            prefix_set = fetch_netbox_prefix_cidrs()
            netbox_prefix_count = len(prefix_set)
            if openstack_data and not openstack_data.get("error"):
                os_subnet_hints = openstack_subnet_prefix_hints(openstack_data, prefix_set)
                os_subnet_gaps = openstack_subnets_missing_prefixes(os_subnet_hints)

        if openstack_data and not openstack_data.get("error"):
            os_floating_gaps = openstack_floating_ips_missing_from_netbox(openstack_data)

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
            use_remote_netbox=use_remote_netbox,
            interface_audit=interface_audit,
        )
        report_drift = report_out.get("drift", "") if isinstance(report_out, dict) else report_out
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
            "use_remote_netbox": use_remote_netbox,
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
                "use_remote_netbox": use_remote_netbox,
                "interface_audit": interface_audit,
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
                use_remote_netbox=cached.get("use_remote_netbox", False),
                interface_audit=cached.get("interface_audit"),
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
