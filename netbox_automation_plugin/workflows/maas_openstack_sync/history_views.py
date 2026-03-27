from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.views import View

from netbox_automation_plugin.sync.reporting.drift_report import build_drift_report_xlsx

from .history_models import MAASOpenStackDriftRun
from .tables import MAASOpenStackDriftRunTable


class MAASOpenStackSyncRunsView(LoginRequiredMixin, View):
    template_name = "netbox_automation_plugin/maas_openstack_sync_runs.html"

    def get(self, request):
        runs = MAASOpenStackDriftRun.objects.select_related("created_by").all()
        table = MAASOpenStackDriftRunTable(runs, orderable=True)
        context = {
            "table": table,
            "run_count": runs.count(),
        }
        return render(request, self.template_name, context)


class MAASOpenStackSyncRunDetailView(LoginRequiredMixin, View):
    template_name = "netbox_automation_plugin/maas_openstack_sync_run_detail.html"

    def get(self, request, run_id: int):
        run = get_object_or_404(MAASOpenStackDriftRun, pk=run_id)
        return render(
            request,
            self.template_name,
            {
                "run": run,
                "report_drift": run.report_drift,
                "report_drift_markup": run.report_drift_markup or "html",
                "report_reference": run.report_reference or "",
            },
        )


class MAASOpenStackSyncRunDownloadXlsxView(LoginRequiredMixin, View):
    def get(self, request, run_id: int):
        run = get_object_or_404(MAASOpenStackDriftRun, pk=run_id)
        payload = run.snapshot_payload or {}
        try:
            xlsx_bytes = build_drift_report_xlsx(
                payload.get("maas_data") or {},
                payload.get("netbox_data") or {},
                payload.get("openstack_data"),
                payload.get("drift") or {},
                matched_rows=payload.get("matched_rows"),
                os_subnet_hints=payload.get("os_subnet_hints"),
                os_subnet_gaps=payload.get("os_subnet_gaps"),
                os_floating_gaps=payload.get("os_floating_gaps"),
                netbox_prefix_count=payload.get("netbox_prefix_count", 0),
                interface_audit=payload.get("interface_audit"),
                netbox_ifaces=payload.get("netbox_ifaces"),
            )
        except Exception as e:
            return HttpResponse(
                f"Excel export failed for run {run_id}: {e}",
                status=500,
                content_type="text/plain; charset=utf-8",
            )
        resp = HttpResponse(
            xlsx_bytes,
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        resp["Content-Disposition"] = f'attachment; filename="drift-report-run-{run_id}.xlsx"'
        return resp
