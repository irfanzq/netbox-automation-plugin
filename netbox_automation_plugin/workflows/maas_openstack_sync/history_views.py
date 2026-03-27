from datetime import date, timedelta

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.views import View
from django_tables2 import RequestConfig

from netbox_automation_plugin.sync.reporting.drift_report import build_drift_report_xlsx

from .history_models import MAASOpenStackDriftRun
from .netbox_scope_choices import list_site_location_choices
from .tables import MAASOpenStackDriftRunTable


def _filter_runs_by_saved_location_scope(qs, location_keys: list[str], location_meta: dict):
    """
    Narrow drift runs whose persisted scope_filters include a selected NetBox location name.
    Keys are ``site_slug::location_name`` (same encoding as the drift audit location picker).
    """
    location_names: set[str] = set()
    for key in location_keys:
        k = (key or "").strip()
        if not k:
            continue
        meta = location_meta.get(k) or {}
        name = (meta.get("location_name") or "").strip()
        if name:
            location_names.add(name)
    if not location_names:
        return qs
    loc_q = Q()
    for loc_name in sorted(location_names):
        loc_q |= Q(scope_filters__contains={"locations": [loc_name]})
    return qs.filter(loc_q)


class MAASOpenStackSyncRunsView(LoginRequiredMixin, View):
    template_name = "netbox_automation_plugin/maas_openstack_sync_runs.html"

    def get(self, request):
        runs = MAASOpenStackDriftRun.objects.select_related("created_by").all()
        preset = (request.GET.get("preset") or "").strip().lower()
        from_date_raw = (request.GET.get("from_date") or "").strip()
        to_date_raw = (request.GET.get("to_date") or "").strip()
        filter_locations = request.GET.getlist("filter_location")

        _, location_choices, location_meta, _ = list_site_location_choices()
        selected_location_key_set = {k for k in filter_locations if k}

        if preset == "last_week":
            runs = runs.filter(created__date__gte=(date.today() - timedelta(days=7)))
        elif preset == "last_30_days":
            runs = runs.filter(created__date__gte=(date.today() - timedelta(days=30)))
        elif preset == "last_3_months":
            runs = runs.filter(created__date__gte=(date.today() - timedelta(days=90)))

        if from_date_raw:
            try:
                runs = runs.filter(created__date__gte=date.fromisoformat(from_date_raw))
            except ValueError:
                from_date_raw = ""
        if to_date_raw:
            try:
                runs = runs.filter(created__date__lte=date.fromisoformat(to_date_raw))
            except ValueError:
                to_date_raw = ""

        runs = _filter_runs_by_saved_location_scope(
            runs,
            list(selected_location_key_set),
            location_meta,
        )

        table = MAASOpenStackDriftRunTable(runs, orderable=True)
        RequestConfig(request, paginate={"per_page": 25}).configure(table)
        run_count = runs.count()
        any_runs_in_db = MAASOpenStackDriftRun.objects.exists()
        context = {
            "table": table,
            "run_count": run_count,
            "preset": preset,
            "from_date": from_date_raw,
            "to_date": to_date_raw,
            "location_choices_for_filter": location_choices,
            "selected_filter_location_keys": selected_location_key_set,
            "history_filtered_empty": run_count == 0 and any_runs_in_db,
            "history_never_ran": not any_runs_in_db,
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
