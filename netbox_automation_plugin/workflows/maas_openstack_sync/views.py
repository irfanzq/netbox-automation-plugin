from django.shortcuts import render
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.translation import gettext_lazy as _

from .forms import MAASOpenStackSyncForm

# Sync package lives under netbox_automation_plugin.sync (not workflows.sync)
from netbox_automation_plugin.sync.config import get_sync_config
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
from netbox_automation_plugin.sync.clients.openstack_client import fetch_openstack_data
from netbox_automation_plugin.sync.reconciliation.maas_netbox import compute_maas_netbox_drift
from netbox_automation_plugin.sync.reporting.drift_report import format_drift_report

import logging
import os

logger = logging.getLogger("netbox_automation_plugin")


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

        # 3) OpenStack (optional; if auth not set, skip)
        openstack_data = None
        if config.get("openstack_auth_url"):
            openstack_data = fetch_openstack_data(config)

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

        # 5) Report
        report = format_drift_report(
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

        return render(
            request,
            self.template_name,
            {
                "form": form,
                "report": report,
                "audit_done": True,
            },
        )
