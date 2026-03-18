from django.shortcuts import render
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.translation import gettext_lazy as _

from .forms import MAASOpenStackSyncForm

# Sync module: config, clients, reconciliation, reporting
from ..sync.config import get_sync_config
from ..sync.clients.maas_client import fetch_maas_data_sync
from ..sync.clients.netbox_client import fetch_netbox_data
from ..sync.clients.openstack_client import fetch_openstack_data
from ..sync.reconciliation.maas_netbox import compute_maas_netbox_drift
from ..sync.reporting.drift_report import format_drift_report

import logging

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

        mode = form.cleaned_data["mode"]
        if mode != "audit":
            return render(request, self.template_name, {"form": form})

        # Phase 1: Drift Audit — collect from MAAS, NetBox, optional OpenStack; compare; report
        config = get_sync_config()
        base_url = request.build_absolute_uri("/").rstrip("/") if request else ""

        # 1) MAAS
        maas_data = fetch_maas_data_sync(
            config.get("maas_url") or "",
            config.get("maas_api_key") or "",
            config.get("maas_insecure", True),
        )

        # 2) NetBox (use NETBOX_URL or current request host)
        netbox_data = fetch_netbox_data(
            config.get("netbox_url") or "",
            config.get("netbox_token") or "",
            base_url_fallback=base_url,
        )

        # 3) OpenStack (optional; if auth not set, skip)
        openstack_data = None
        if config.get("openstack_auth_url"):
            openstack_data = fetch_openstack_data(config)

        # 4) Drift (MAAS vs NetBox)
        drift = compute_maas_netbox_drift(maas_data, netbox_data)

        # 5) Report
        report = format_drift_report(maas_data, netbox_data, openstack_data, drift)

        return render(
            request,
            self.template_name,
            {
                "form": form,
                "report": report,
                "audit_done": True,
            },
        )
