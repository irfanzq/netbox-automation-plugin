import json
import logging
from datetime import date, timedelta

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.decorators.cache import never_cache
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
from netbox_automation_plugin.models import MAASOpenStackReconciliationRun

from .history_models import MAASOpenStackDriftRun
from .netbox_scope_choices import list_site_location_choices
from .tables import MAASOpenStackDriftRunTable

logger = logging.getLogger(__name__)

# GET ``filter_location`` sentinel: runs whose NetBox sites / locations column shows
# "All (no site/location filter)" (unscoped); filter UI: "All (No site/location filter in run)".
HIST_FILTER_UNSCOPED_SITE_LOCATION = "__unscoped_site_location__"


def _drift_review_saved_query_string(run: MAASOpenStackDriftRun) -> str:
    """
    Query string for ?view=modified (and matching Excel links) so the URL changes
    whenever review edits are re-saved — avoids stale cached HTML/XLSX when another
    tab saved newer data for the same run.
    """
    ts = getattr(run, "drift_review_saved_at", None)
    base = "view=modified"
    if ts is None:
        return base
    try:
        v = int(ts.timestamp())
    except (OSError, OverflowError, TypeError, ValueError):
        return base
    return f"{base}&review_saved={v}"


def _drift_modified_xlsx_query_string(run: MAASOpenStackDriftRun) -> str:
    ts = getattr(run, "drift_review_saved_at", None)
    base = "modified=1"
    if ts is None:
        return base
    try:
        v = int(ts.timestamp())
    except (OSError, OverflowError, TypeError, ValueError):
        return base
    return f"{base}&review_saved={v}"


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


@method_decorator(never_cache, name="dispatch")
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


@method_decorator(never_cache, name="dispatch")
@method_decorator(ensure_csrf_cookie, name="dispatch")
class MAASOpenStackSyncRunDetailView(LoginRequiredMixin, View):
    template_name = "netbox_automation_plugin/maas_openstack_sync_run_detail.html"

    def get(self, request, run_id: int):
        run = get_object_or_404(MAASOpenStackDriftRun, pk=run_id)
        run.refresh_from_db(
            fields=[
                "report_drift",
                "report_drift_modified_html",
                "drift_review_overrides",
                "drift_review_modified_xlsx",
                "drift_review_saved_at",
                "drift_review_saved_by",
                "snapshot_payload",
            ]
        )
        markup = run.report_drift_markup or "html"
        # Persisted run pages are read-only: no NetBox picker catalog or save-review UI.
        picker_catalog = None
        want_modified = (request.GET.get("view") or "").strip().lower() in (
            "modified",
            "1",
            "true",
        )
        has_modified_html = bool((run.report_drift_modified_html or "").strip())
        has_overrides = bool(normalize_drift_review_overrides(run.drift_review_overrides))
        drift_has_saved_review = has_modified_html or has_overrides
        report_body = run.report_drift
        drift_view_modified = False
        if want_modified:
            payload = run.snapshot_payload if isinstance(run.snapshot_payload, dict) else {}
            # When overrides exist, regenerate from snapshot + normalized overrides first so
            # merge fixes (e.g. legacy truncated \"NB\" column keys) always apply in history
            # even if report_drift_modified_html was saved before those fixes or matched the
            # original HTML by mistake. Fall back to stored modified HTML if regen fails or
            # is empty.
            if has_overrides and payload:
                try:
                    report_out = format_drift_report_from_snapshot_payload(
                        payload,
                        drift_overrides=run.drift_review_overrides,
                    )
                    regen = (report_out.get("drift") or "").strip()
                    if regen:
                        report_body = regen
                        drift_view_modified = True
                except Exception:
                    logger.exception(
                        "Drift run %s: could not regenerate modified HTML from snapshot",
                        run.id,
                    )
            if not drift_view_modified and has_modified_html:
                report_body = run.report_drift_modified_html
                drift_view_modified = True
            if not drift_view_modified:
                want_modified = False

        reconciliation_runs = list(
            MAASOpenStackReconciliationRun.objects.filter(drift_run_id=run.id)
            .order_by("-created")
            .only("pk", "status", "branch_name", "created")[:25]
        )

        audit_only = (request.GET.get("audit") or "").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        if reconciliation_runs and not want_modified and not audit_only:
            return redirect(
                "plugins:netbox_automation_plugin:maas_openstack_reconciliation_detail",
                pk=reconciliation_runs[0].pk,
            )

        return render(
            request,
            self.template_name,
            {
                "run": run,
                "report_drift": report_body,
                "report_drift_markup": markup,
                "report_reference": run.report_reference or "",
                "drift_nb_picker_catalog": picker_catalog,
                "drift_run_detail_readonly": True,
                "drift_view_modified": drift_view_modified,
                "drift_has_saved_review": drift_has_saved_review,
                "drift_review_saved_at": run.drift_review_saved_at,
                "drift_save_review_url": None,
                "drift_download_xlsx_modified_url": reverse(
                    "plugins:netbox_automation_plugin:maas_openstack_sync_run_download_xlsx",
                    args=[run.id],
                )
                + f"?{_drift_modified_xlsx_query_string(run)}",
                "drift_view_modified_query_string": _drift_review_saved_query_string(run),
                "drift_download_xlsx_modified_post_url": "",
                "reconciliation_runs": reconciliation_runs,
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
                # Latest snapshot from DB (avoids stale in-memory row after parallel edits).
                run.refresh_from_db(fields=["snapshot_payload"])
                report_out = format_drift_report_from_snapshot_payload(
                    run.snapshot_payload,
                    drift_overrides=overrides,
                )
                mod_html = (report_out.get("drift") or "").strip()
                if not mod_html:
                    logger.error(
                        "Save review: overrides present but empty drift HTML for run %s",
                        run_id,
                    )
                    return JsonResponse(
                        {
                            "ok": False,
                            "error": (
                                "Could not build modified report HTML from this run's snapshot. "
                                "Re-run the drift audit, then save edits again."
                            ),
                        },
                        status=500,
                    )
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


@method_decorator(never_cache, name="dispatch")
class MAASOpenStackSyncRunDownloadXlsxView(LoginRequiredMixin, View):
    def get(self, request, run_id: int):
        run = get_object_or_404(MAASOpenStackDriftRun, pk=run_id)
        run.refresh_from_db(
            fields=[
                "snapshot_payload",
                "drift_review_overrides",
                "drift_review_modified_xlsx",
                "drift_review_saved_at",
            ]
        )
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
                    "No saved edits for this run. Save edits first.",
                    status=404,
                    content_type="text/plain; charset=utf-8",
                )
            drift_overrides = norm
            stored = run.drift_review_modified_xlsx
            if stored:
                try:
                    blob = bytes(stored)
                except TypeError:
                    blob = b""
                if len(blob) > 0:
                    resp = HttpResponse(
                        blob,
                        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    )
                    resp["Content-Disposition"] = (
                        f'attachment; filename="drift-report-run-{run_id}-modified.xlsx"'
                    )
                    resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                    resp["Pragma"] = "no-cache"
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
        resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp["Pragma"] = "no-cache"
        return resp
