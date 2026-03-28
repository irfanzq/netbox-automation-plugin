import json
from datetime import date, timedelta

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django_tables2 import RequestConfig

from netbox_automation_plugin.sync.reporting.drift_report.drift_overrides_apply import (
    normalize_drift_review_overrides,
)

from .drift_snapshot_export import (
    build_drift_report_xlsx_from_snapshot_payload,
    format_drift_report_from_snapshot_payload,
)
from .history_models import MAASOpenStackDriftRun
from netbox_automation_plugin.sync.reporting.drift_report.drift_nb_picker_catalog import (
    build_drift_nb_picker_catalog,
)
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


@method_decorator(ensure_csrf_cookie, name="dispatch")
class MAASOpenStackSyncRunDetailView(LoginRequiredMixin, View):
    template_name = "netbox_automation_plugin/maas_openstack_sync_run_detail.html"

    def get(self, request, run_id: int):
        run = get_object_or_404(MAASOpenStackDriftRun, pk=run_id)
        markup = run.report_drift_markup or "html"
        picker_catalog = None
        if str(markup).lower() == "html":
            try:
                picker_catalog = build_drift_nb_picker_catalog()
            except Exception:
                picker_catalog = {}
        want_modified = (request.GET.get("view") or "").strip().lower() in (
            "modified",
            "1",
            "true",
        )
        has_modified_html = bool((run.report_drift_modified_html or "").strip())
        has_overrides = bool(normalize_drift_review_overrides(run.drift_review_overrides))
        drift_has_saved_review = has_modified_html or has_overrides
        report_body = run.report_drift
        if want_modified and has_modified_html:
            report_body = run.report_drift_modified_html
        elif want_modified and not has_modified_html:
            want_modified = False

        return render(
            request,
            self.template_name,
            {
                "run": run,
                "report_drift": report_body,
                "report_drift_markup": markup,
                "report_reference": run.report_reference or "",
                "drift_nb_picker_catalog": picker_catalog,
                "drift_view_modified": want_modified and has_modified_html,
                "drift_has_saved_review": drift_has_saved_review,
                "drift_review_saved_at": run.drift_review_saved_at,
                "drift_save_review_url": reverse(
                    "plugins:netbox_automation_plugin:maas_openstack_sync_run_save_review",
                    args=[run.id],
                ),
                "drift_download_xlsx_modified_url": reverse(
                    "plugins:netbox_automation_plugin:maas_openstack_sync_run_download_xlsx",
                    args=[run.id],
                )
                + "?modified=1",
                "drift_download_xlsx_modified_post_url": "",
            },
        )


class MAASOpenStackSyncRunSaveReviewView(LoginRequiredMixin, View):
    """POST JSON { "overrides": { selection_key: { row_idx: { header: value } } } }."""

    http_method_names = ["post"]

    def post(self, request, run_id: int):
        run = get_object_or_404(MAASOpenStackDriftRun, pk=run_id)
        try:
            body = json.loads(request.body.decode() or "{}")
        except json.JSONDecodeError:
            return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)
        raw_ov = body.get("overrides")
        overrides = normalize_drift_review_overrides(raw_ov)
        mod_xlsx = None
        try:
            if not overrides:
                mod_html = ""
            else:
                report_out = format_drift_report_from_snapshot_payload(
                    run.snapshot_payload,
                    drift_overrides=overrides,
                )
                mod_html = report_out.get("drift") or ""
                mod_xlsx = build_drift_report_xlsx_from_snapshot_payload(
                    run.snapshot_payload,
                    drift_overrides=overrides,
                )
        except Exception as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=500)
        run.drift_review_overrides = overrides
        run.report_drift_modified_html = mod_html
        run.drift_review_modified_xlsx = mod_xlsx if overrides else None
        run.drift_review_saved_at = timezone.now()
        run.drift_review_saved_by = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
        run.save()
        return JsonResponse({"ok": True, "run_id": run.id, "reload": True})


class MAASOpenStackSyncRunDownloadXlsxView(LoginRequiredMixin, View):
    def get(self, request, run_id: int):
        run = get_object_or_404(MAASOpenStackDriftRun, pk=run_id)
        payload = run.snapshot_payload or {}
        want_modified = (request.GET.get("modified") or "").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        drift_overrides = None
        if want_modified:
            norm = normalize_drift_review_overrides(run.drift_review_overrides)
            if not norm:
                return HttpResponse(
                    "No saved review edits for this run. Save review edits first.",
                    status=404,
                    content_type="text/plain; charset=utf-8",
                )
            drift_overrides = run.drift_review_overrides
            stored = run.drift_review_modified_xlsx
            if stored:
                xlsx_bytes = bytes(stored)
                resp = HttpResponse(
                    xlsx_bytes,
                    content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
                resp["Content-Disposition"] = (
                    f'attachment; filename="drift-report-run-{run_id}-modified.xlsx"'
                )
                return resp
        try:
            xlsx_bytes = build_drift_report_xlsx_from_snapshot_payload(
                payload,
                drift_overrides=drift_overrides,
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
        suffix = "-modified" if want_modified else ""
        resp["Content-Disposition"] = (
            f'attachment; filename="drift-report-run-{run_id}{suffix}.xlsx"'
        )
        return resp
