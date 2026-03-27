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

# GET ``filter_location`` sentinel: runs whose NetBox sites / locations column shows
# "All (no site/location filter)" (unscoped); filter UI: "All (No site/location filter in run)".
HIST_FILTER_UNSCOPED_SITE_LOCATION = "__unscoped_site_location__"


def _unscoped_site_location_q() -> Q:
    """
    Runs whose saved scope has no NetBox sites and no locations (same rule as
    ``MAASOpenStackDriftRunTable.render_netbox_sites_locations``).
    """
    sites_empty = (
        Q(scope_filters__sites=[])
        | ~Q(scope_filters__has_key="sites")
        | Q(scope_filters__sites__isnull=True)
    )
    locs_empty = (
        Q(scope_filters__locations=[])
        | ~Q(scope_filters__has_key="locations")
        | Q(scope_filters__locations__isnull=True)
    )
    return sites_empty & locs_empty


def _location_names_from_keys(location_keys: list[str], location_meta: dict) -> set[str]:
    names: set[str] = set()
    for key in location_keys:
        k = (key or "").strip()
        if not k or k == HIST_FILTER_UNSCOPED_SITE_LOCATION:
            continue
        meta = location_meta.get(k) or {}
        name = (meta.get("location_name") or "").strip()
        if name:
            names.add(name)
    return names


def _apply_history_location_filters(qs, selected_keys: set[str], location_meta: dict):
    """
    Combine optional "unscoped" filter with optional site/location key filters (OR if both).
    """
    keys = {k for k in selected_keys if k}
    want_unscoped = HIST_FILTER_UNSCOPED_SITE_LOCATION in keys
    loc_keys = [k for k in keys if k != HIST_FILTER_UNSCOPED_SITE_LOCATION]
    location_names = _location_names_from_keys(loc_keys, location_meta)

    parts: list[Q] = []
    if want_unscoped:
        parts.append(_unscoped_site_location_q())
    if location_names:
        loc_q = Q()
        for loc_name in sorted(location_names):
            loc_q |= Q(scope_filters__contains={"locations": [loc_name]})
        parts.append(loc_q)

    if not parts:
        return qs
    combined = parts[0]
    for p in parts[1:]:
        combined |= p
    return qs.filter(combined)


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

        runs = _apply_history_location_filters(
            runs,
            selected_location_key_set,
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
            "hist_filter_unscoped_value": HIST_FILTER_UNSCOPED_SITE_LOCATION,
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
