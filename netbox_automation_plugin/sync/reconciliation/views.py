"""API + pages for MAAS/OpenStack branch reconciliation runs."""

from __future__ import annotations

import json
import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import NoReverseMatch, reverse
from django.utils.decorators import method_decorator
from django.utils.html import escape
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.decorators.cache import never_cache

from netbox_automation_plugin.models import MAASOpenStackReconciliationRun

from netbox_automation_plugin.workflows.maas_openstack_sync.history_models import (
    MAASOpenStackDriftRun,
)
from .service import (
    apply_result_row_needs_attention,
    check_and_reapply_if_branch_ready,
    frozen_operations_apply_snapshots,
    frozen_operations_for_display,
    group_apply_snapshot_tables,
    group_reconciliation_operation_tables,
    RECONCILIATION_DISCARD_BLOCKED_STATUSES,
    apply_reconciliation_run,
    create_reconciliation_run,
    discard_reconciliation_run,
    preview_reconciliation,
)

logger = logging.getLogger(__name__)

MAAS_RECON_STAGING_SESSION_KEY = "maas_recon_staging_v1"


def _reconciliation_run_page_context(
    run: MAASOpenStackReconciliationRun,
    *,
    nav_active: str,
) -> dict[str, object]:
    """Shared URLs, flags, and apply_results for reconciliation detail + apply-results pages."""
    blocked_discard = RECONCILIATION_DISCARD_BLOCKED_STATUSES
    apply_ok = {
        MAASOpenStackReconciliationRun.STATUS_BRANCH_CREATED,
        MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED_PARTIAL,
        MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED,
    }
    apply_results: dict = run.apply_results if isinstance(run.apply_results, dict) else {}
    result_rows = apply_results.get("rows") if isinstance(apply_results.get("rows"), list) else []
    branch_schema_blocked = bool(
        apply_results.get("branch_not_ready")
        or run.status == MAASOpenStackReconciliationRun.STATUS_BRANCH_NOT_READY
    )
    failed_row_n = sum(
        1 for r in result_rows if isinstance(r, dict) and str(r.get("status") or "") == "failed"
    )
    skipped_row_n = sum(
        1
        for r in result_rows
        if isinstance(r, dict)
        and str(r.get("status") or "") == "skipped"
        and apply_result_row_needs_attention(r)
    )
    retry_eligible_status = run.status in {
        MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED_PARTIAL,
        MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED,
        MAASOpenStackReconciliationRun.STATUS_APPLIED,
    }
    can_retry_partial_base = (
        retry_eligible_status and bool(result_rows) and not branch_schema_blocked
    )
    detail_url = reverse(
        "plugins:netbox_automation_plugin:maas_openstack_reconciliation_detail",
        args=[run.pk],
    )
    apply_results_url = reverse(
        "plugins:netbox_automation_plugin:maas_openstack_reconciliation_apply_results",
        args=[run.pk],
    )
    show_recheck_branch_btn = branch_schema_blocked
    return {
        "run": run,
        "apply_results": apply_results,
        "apply_url": reverse(
            "plugins:netbox_automation_plugin:maas_openstack_reconciliation_apply",
            args=[run.pk],
        ),
        "recheck_branch_url": reverse(
            "plugins:netbox_automation_plugin:maas_openstack_reconciliation_recheck_branch",
            args=[run.pk],
        ),
        "retry_failed_url": reverse(
            "plugins:netbox_automation_plugin:maas_openstack_reconciliation_retry_failed",
            args=[run.pk],
        ),
        "discard_url": reverse(
            "plugins:netbox_automation_plugin:maas_openstack_reconciliation_discard",
            args=[run.pk],
        ),
        "recon_detail_url": detail_url,
        "apply_results_url": apply_results_url,
        "branching_branch_url": _netbox_branching_branch_url(branch_pk=run.branch_id),
        "can_discard": run.status not in blocked_discard,
        "can_apply": run.status in apply_ok and not branch_schema_blocked,
        "can_retry_failed": can_retry_partial_base and failed_row_n > 0,
        "can_retry_skipped": can_retry_partial_base and skipped_row_n > 0,
        "can_retry_failed_or_skipped": can_retry_partial_base
        and (failed_row_n > 0 or skipped_row_n > 0),
        "recon_apply_failed_row_count": failed_row_n,
        "recon_apply_skipped_row_count": skipped_row_n,
        "show_recheck_branch_btn": show_recheck_branch_btn,
        "branch_schema_blocked": branch_schema_blocked,
        "nav_active": nav_active,
    }


def _reconciliation_toast_error(title: str, detail: str):
    """
    NetBox renders django messages in toasts via ``{{ message }}`` without ``linebreaksbr``,
    so plain newlines collapse. Build safe HTML with explicit ``<br>`` and escaped text.

    Wrap in ``alert-danger`` so the blocker / failure reads as a red banner inside the toast.
    """
    t = escape(str(title))
    br_detail = "<br>".join(escape(line) for line in str(detail).split("\n"))
    # Marker for maas_openstack_sync_form sticky-toast JS (NetBox renders messages after
    # page content; outer toast still uses data-bs-delay unless we patch the instance).
    return mark_safe(
        '<span class="d-none nb-recon-sticky-marker" aria-hidden="true"></span>'
        '<div class="alert alert-danger border-danger mb-0 py-2 px-3 text-start reconciliation-sticky-toast" role="alert">'
        f'<div class="fw-semibold mb-1">{t}</div>'
        f'<div class="small text-break reconciliation-msg-detail">{br_detail}</div>'
        "</div>"
    )


def _netbox_branching_branch_url(*, branch_pk: int | None) -> str | None:
    """Relative URL to the NetBox Branching branch detail page, if installed."""
    if branch_pk is None:
        return None
    for name in (
        "plugins:netbox_branching:branch",
        "plugins:netbox_branching:branch_detail",
    ):
        try:
            return reverse(name, kwargs={"pk": branch_pk})
        except NoReverseMatch:
            continue
    return None


@method_decorator(never_cache, name="dispatch")
class ReconciliationPreviewView(LoginRequiredMixin, View):
    """POST JSON { drift_run_id, selected: { section: [row_key, ...] } }."""

    http_method_names = ["post"]

    def post(self, request):
        try:
            body = json.loads(request.body.decode() or "{}")
        except json.JSONDecodeError:
            return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)
        raw_id = body.get("drift_run_id")
        try:
            drift_run_id = int(raw_id)
        except (TypeError, ValueError):
            return JsonResponse({"ok": False, "error": "drift_run_id required"}, status=400)
        drift_run = get_object_or_404(MAASOpenStackDriftRun, pk=drift_run_id)
        selected = body.get("selected")
        posted = body.get("drift_review_overrides")
        if posted is None:
            posted = body.get("posted_review_overrides")
        if posted is not None and not isinstance(posted, dict):
            return JsonResponse(
                {"ok": False, "error": "drift_review_overrides must be a JSON object"},
                status=400,
            )
        try:
            payload = preview_reconciliation(
                drift_run=drift_run,
                selected_raw=selected,
                posted_review_overrides_raw=posted,
            )
        except ValueError as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=400)
        except Exception as e:
            logger.exception("Reconciliation preview failed for drift run %s", drift_run_id)
            return JsonResponse({"ok": False, "error": str(e)}, status=500)
        return JsonResponse({"ok": True, **payload})


@method_decorator(never_cache, name="dispatch")
class ReconciliationCreateView(LoginRequiredMixin, View):
    """POST JSON { drift_run_id, selected, preview_ack_token }."""

    http_method_names = ["post"]

    def post(self, request):
        try:
            body = json.loads(request.body.decode() or "{}")
        except json.JSONDecodeError:
            return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)
        raw_id = body.get("drift_run_id")
        try:
            drift_run_id = int(raw_id)
        except (TypeError, ValueError):
            return JsonResponse({"ok": False, "error": "drift_run_id required"}, status=400)
        token = body.get("preview_ack_token") or body.get("preview_token") or ""
        if not isinstance(token, str) or not token.strip():
            return JsonResponse(
                {"ok": False, "error": "Valid preview acknowledgement token is required."},
                status=400,
            )
        drift_run = get_object_or_404(MAASOpenStackDriftRun, pk=drift_run_id)
        posted = body.get("drift_review_overrides")
        if posted is None:
            posted = body.get("posted_review_overrides")
        if posted is not None and not isinstance(posted, dict):
            return JsonResponse(
                {"ok": False, "error": "drift_review_overrides must be a JSON object"},
                status=400,
            )
        try:
            run = create_reconciliation_run(
                drift_run=drift_run,
                selected_raw=body.get("selected"),
                preview_ack_token=token.strip(),
                user=request.user,
                posted_review_overrides_raw=posted,
            )
        except ValueError as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=400)
        except Exception as e:
            logger.exception("Reconciliation create failed for drift run %s", drift_run_id)
            return JsonResponse({"ok": False, "error": str(e)}, status=500)

        detail_url = reverse(
            "plugins:netbox_automation_plugin:maas_openstack_reconciliation_detail",
            args=[run.pk],
        )
        if run.status == MAASOpenStackReconciliationRun.STATUS_BRANCH_CREATE_FAILED:
            return JsonResponse(
                {
                    "ok": False,
                    "error": run.error_message or "Branch creation failed.",
                    "reconciliation_run_id": run.pk,
                    "redirect_url": detail_url,
                },
                status=422,
            )
        return JsonResponse(
            {
                "ok": True,
                "reconciliation_run_id": run.pk,
                "branch_name": run.branch_name,
                "branch_id": run.branch_id,
                "redirect_url": detail_url,
            }
        )


@method_decorator(never_cache, name="dispatch")
class ReconciliationRunsListView(LoginRequiredMixin, View):
    template_name = "netbox_automation_plugin/maas_openstack_reconciliation_runs.html"

    def get(self, request):
        runs = (
            MAASOpenStackReconciliationRun.objects.select_related("drift_run", "created_by")
            .order_by("-created")[:500]
        )
        return render(
            request,
            self.template_name,
            {"runs": runs},
        )


@method_decorator(never_cache, name="dispatch")
class ReconciliationRunDetailView(LoginRequiredMixin, View):
    template_name = "netbox_automation_plugin/maas_openstack_reconciliation_detail.html"

    def get(self, request, run_id: int):
        run = get_object_or_404(
            MAASOpenStackReconciliationRun.objects.select_related("drift_run", "created_by"),
            pk=run_id,
        )
        raw_frozen_list = run.frozen_operations if isinstance(run.frozen_operations, list) else []
        frozen_ops = frozen_operations_for_display(raw_frozen_list)
        ops_for_tables = [
            {
                "summary": o.get("summary"),
                "action": o.get("action"),
                "section": o.get("selection_key"),
                "selection_key": o.get("selection_key"),
                "cells": dict(o.get("cells") or {}),
            }
            for o in raw_frozen_list
            if isinstance(o, dict)
        ]
        operation_tables = group_reconciliation_operation_tables(ops_for_tables)
        apply_snapshot_ops = frozen_operations_apply_snapshots(raw_frozen_list)
        apply_snapshot_tables = group_apply_snapshot_tables(apply_snapshot_ops)
        ctx = _reconciliation_run_page_context(run, nav_active="detail")
        ctx.update(
            {
                "frozen_ops": frozen_ops,
                "operation_tables": operation_tables,
                "apply_snapshot_ops": apply_snapshot_ops,
                "apply_snapshot_tables": apply_snapshot_tables,
            }
        )
        return render(request, self.template_name, ctx)


@method_decorator(never_cache, name="dispatch")
class ReconciliationApplyResultsView(LoginRequiredMixin, View):
    template_name = "netbox_automation_plugin/maas_openstack_reconciliation_apply_results.html"

    def get(self, request, run_id: int):
        run = get_object_or_404(
            MAASOpenStackReconciliationRun.objects.select_related("drift_run", "created_by"),
            pk=run_id,
        )
        ctx = _reconciliation_run_page_context(run, nav_active="apply_results")
        return render(request, self.template_name, ctx)


@method_decorator(never_cache, name="dispatch")
class ReconciliationApplyView(LoginRequiredMixin, View):
    http_method_names = ["post"]

    def post(self, request, run_id: int):
        run = get_object_or_404(MAASOpenStackReconciliationRun, pk=run_id)
        try:
            run = apply_reconciliation_run(run=run, actor=request.user, retry_failed_only=False)
        except ValueError as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=400)
        except Exception as e:
            logger.exception("Reconciliation apply failed for run %s", run_id)
            return JsonResponse({"ok": False, "error": str(e)}, status=500)
        apply_results_url = reverse(
            "plugins:netbox_automation_plugin:maas_openstack_reconciliation_apply_results",
            args=[run.pk],
        )
        payload = {
            "ok": True,
            "run_id": run.pk,
            "status": run.status,
            "apply_results": run.apply_results if isinstance(run.apply_results, dict) else {},
            "redirect_url": apply_results_url,
        }
        bu = _netbox_branching_branch_url(branch_pk=run.branch_id)
        if bu:
            payload["branching_branch_url"] = bu
        return JsonResponse(payload)


@method_decorator(never_cache, name="dispatch")
class ReconciliationRetryFailedView(LoginRequiredMixin, View):
    http_method_names = ["post"]

    def post(self, request, run_id: int):
        mode = "failed"
        if request.body:
            try:
                raw = json.loads(request.body.decode() or "{}")
            except json.JSONDecodeError:
                raw = {}
            if isinstance(raw, dict):
                m = str(raw.get("retry") or raw.get("mode") or "").strip().lower()
                if m in ("skipped", "failed", "both", "failed_and_skipped"):
                    mode = "failed_and_skipped" if m == "both" else m
        run = get_object_or_404(MAASOpenStackReconciliationRun, pk=run_id)
        try:
            if mode == "skipped":
                run = apply_reconciliation_run(
                    run=run, actor=request.user, retry_failed_only=False, retry_skipped_only=True
                )
            elif mode == "failed_and_skipped":
                run = apply_reconciliation_run(
                    run=run, actor=request.user, retry_failed_only=True, retry_skipped_only=True
                )
            else:
                run = apply_reconciliation_run(
                    run=run, actor=request.user, retry_failed_only=True, retry_skipped_only=False
                )
        except ValueError as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=400)
        except Exception as e:
            logger.exception("Reconciliation retry-failed failed for run %s", run_id)
            return JsonResponse({"ok": False, "error": str(e)}, status=500)
        apply_results_url = reverse(
            "plugins:netbox_automation_plugin:maas_openstack_reconciliation_apply_results",
            args=[run.pk],
        )
        payload = {
            "ok": True,
            "run_id": run.pk,
            "status": run.status,
            "apply_results": run.apply_results if isinstance(run.apply_results, dict) else {},
            "redirect_url": apply_results_url,
        }
        bu = _netbox_branching_branch_url(branch_pk=run.branch_id)
        if bu:
            payload["branching_branch_url"] = bu
        return JsonResponse(payload)


@method_decorator(never_cache, name="dispatch")
class ReconciliationRecheckBranchView(LoginRequiredMixin, View):
    """POST JSON {} — verify branch DB alias, then retry failed rows only."""

    http_method_names = ["post"]

    def post(self, request, run_id: int):
        run = get_object_or_404(MAASOpenStackReconciliationRun, pk=run_id)
        try:
            ok, reason, run = check_and_reapply_if_branch_ready(run=run, actor=request.user)
        except ValueError as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=400)
        except Exception as e:
            logger.exception("Reconciliation recheck-branch failed for run %s", run_id)
            return JsonResponse({"ok": False, "error": str(e)}, status=500)
        if not ok:
            detail = _("Try again in a few seconds.")
            err_text = _("Branch schema still not ready: %(reason)s %(detail)s") % {
                "reason": reason,
                "detail": detail,
            }
            return JsonResponse(
                {
                    "ok": False,
                    "error": err_text,
                    "branch_not_ready": True,
                    "reason": reason,
                },
                status=422,
            )
        apply_results_url = reverse(
            "plugins:netbox_automation_plugin:maas_openstack_reconciliation_apply_results",
            args=[run.pk],
        )
        payload = {
            "ok": True,
            "run_id": run.pk,
            "status": run.status,
            "apply_results": run.apply_results if isinstance(run.apply_results, dict) else {},
            "redirect_url": apply_results_url,
        }
        bu = _netbox_branching_branch_url(branch_pk=run.branch_id)
        if bu:
            payload["branching_branch_url"] = bu
        return JsonResponse(payload)


@method_decorator(never_cache, name="dispatch")
class ReconciliationDiscardView(LoginRequiredMixin, View):
    http_method_names = ["post"]

    def post(self, request, run_id: int):
        run = get_object_or_404(MAASOpenStackReconciliationRun, pk=run_id)
        try:
            run = discard_reconciliation_run(run=run, actor=request.user)
        except ValueError as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=400)
        except Exception as e:
            logger.exception("Reconciliation discard failed for run %s", run_id)
            return JsonResponse({"ok": False, "error": str(e)}, status=500)
        detail_url = reverse(
            "plugins:netbox_automation_plugin:maas_openstack_reconciliation_detail",
            args=[run.pk],
        )
        return JsonResponse(
            {
                "ok": True,
                "run_id": run.pk,
                "status": run.status,
                "apply_results": run.apply_results if isinstance(run.apply_results, dict) else {},
                "redirect_url": detail_url,
            }
        )


@method_decorator(never_cache, name="dispatch")
class ReconciliationStagingView(LoginRequiredMixin, View):
    """
    Full-page reconciliation preview: POST from drift audit stores preview in session;
    GET shows operations, next steps, and create-branch action.
    """

    http_method_names = ["get", "post"]
    template_name = "netbox_automation_plugin/maas_openstack_reconciliation_staging.html"

    def get(self, request):
        # Lets operators open "reconciliation preview" in a new tab from the drift audit: audit page
        # writes selection + overrides to localStorage; this GET renders a page that POSTs to ``post``.
        if request.GET.get("from_local_draft") == "1":
            raw_id = request.GET.get("drift_run_id")
            try:
                drift_run_id = int(raw_id)
            except (TypeError, ValueError):
                messages.error(request, _("Invalid drift run."))
                return redirect("plugins:netbox_automation_plugin:maas_openstack_sync")
            get_object_or_404(MAASOpenStackDriftRun, pk=drift_run_id)
            audit_back = (
                reverse("plugins:netbox_automation_plugin:maas_openstack_sync")
                + f"?drift_run_id={drift_run_id}"
            )
            return render(
                request,
                "netbox_automation_plugin/maas_openstack_reconciliation_stage_local_draft.html",
                {
                    "drift_run_id": drift_run_id,
                    "stage_post_url": reverse(
                        "plugins:netbox_automation_plugin:maas_openstack_reconciliation_stage",
                    ),
                    "audit_back_url": audit_back,
                },
            )

        data = request.session.get(MAAS_RECON_STAGING_SESSION_KEY)
        if not isinstance(data, dict) or "drift_run_id" not in data:
            messages.warning(
                request,
                _(
                    "No reconciliation preview in progress. On the drift audit, select rows and "
                    "click Continue to reconciliation preview."
                ),
            )
            return redirect("plugins:netbox_automation_plugin:maas_openstack_sync")
        drift_run = get_object_or_404(MAASOpenStackDriftRun, pk=int(data["drift_run_id"]))
        audit_back_url = (
            reverse("plugins:netbox_automation_plugin:maas_openstack_sync")
            + f"?drift_run_id={drift_run.pk}"
        )
        apply_snapshot_ops = (
            data.get("apply_snapshot_ops") if isinstance(data.get("apply_snapshot_ops"), list) else []
        )
        apply_snapshot_tables = data.get("apply_snapshot_tables")
        if not isinstance(apply_snapshot_tables, list) or not apply_snapshot_tables:
            apply_snapshot_tables = group_apply_snapshot_tables(apply_snapshot_ops)
        return render(
            request,
            self.template_name,
            {
                "drift_run": drift_run,
                "audit_back_url": audit_back_url,
                "hide_reconciliation_runs_nav": bool(data.get("from_live_audit")),
                "reconciliation_runs_url": reverse(
                    "plugins:netbox_automation_plugin:maas_openstack_reconciliation_runs",
                ),
                "create_url": reverse(
                    "plugins:netbox_automation_plugin:maas_openstack_reconciliation_create",
                ),
                "preview_ack_token": data.get("preview_ack_token") or "",
                "operations_digest": data.get("operations_digest") or "",
                "operation_count": data.get("operation_count") or 0,
                "operations": data.get("operations") if isinstance(data.get("operations"), list) else [],
                "operation_tables": data.get("operation_tables")
                if isinstance(data.get("operation_tables"), list)
                else [],
                "apply_snapshot_ops": apply_snapshot_ops,
                "apply_snapshot_tables": apply_snapshot_tables,
                "counts_by_action": data.get("counts_by_action")
                if isinstance(data.get("counts_by_action"), dict)
                else {},
                "counts_by_section": data.get("counts_by_section")
                if isinstance(data.get("counts_by_section"), dict)
                else {},
                "warnings": data.get("warnings") if isinstance(data.get("warnings"), list) else [],
                "selected": data.get("selected") if isinstance(data.get("selected"), dict) else {},
                "row_diffs": data.get("row_diffs")
                if isinstance(data.get("row_diffs"), list)
                else [],
                "posted_review_overrides": data.get("posted_review_overrides")
                if isinstance(data.get("posted_review_overrides"), dict)
                else {},
            },
        )

    def post(self, request):
        raw_id = request.POST.get("drift_run_id")
        try:
            drift_run_id = int(raw_id)
        except (TypeError, ValueError):
            messages.error(request, _("Invalid drift run."))
            return redirect("plugins:netbox_automation_plugin:maas_openstack_sync")
        back = (
            reverse("plugins:netbox_automation_plugin:maas_openstack_sync")
            + f"?drift_run_id={drift_run_id}"
        )
        selected_raw = request.POST.get("selected_json") or "{}"
        try:
            selected = json.loads(selected_raw)
        except json.JSONDecodeError:
            messages.error(request, _("Invalid selection data."))
            return redirect(back)
        posted_raw = request.POST.get("drift_review_overrides_json") or ""
        posted_overrides = None
        if posted_raw.strip():
            try:
                posted_overrides = json.loads(posted_raw)
            except json.JSONDecodeError:
                messages.error(request, _("Invalid drift review overrides JSON."))
                return redirect(back)
            if not isinstance(posted_overrides, dict):
                messages.error(request, _("Drift review overrides must be a JSON object."))
                return redirect(back)
        drift_run = get_object_or_404(MAASOpenStackDriftRun, pk=drift_run_id)
        try:
            payload = preview_reconciliation(
                drift_run=drift_run,
                selected_raw=selected,
                posted_review_overrides_raw=posted_overrides,
            )
        except ValueError as e:
            messages.error(
                request,
                _reconciliation_toast_error(_("Reconciliation preview blocked"), str(e)),
                extra_tags="nb-recon-sticky",
            )
            return redirect(back)
        except Exception as e:
            logger.exception("Reconciliation staging preview failed for drift run %s", drift_run_id)
            messages.error(
                request,
                _reconciliation_toast_error(_("Reconciliation preview failed"), str(e)),
                extra_tags="nb-recon-sticky",
            )
            return redirect(back)

        posted_store = posted_overrides if isinstance(posted_overrides, dict) else {}
        request.session[MAAS_RECON_STAGING_SESSION_KEY] = {
            "drift_run_id": drift_run.pk,
            "from_live_audit": True,
            "selected": selected,
            "posted_review_overrides": posted_store,
            "preview_ack_token": payload.get("preview_ack_token") or "",
            "operations_digest": payload.get("operations_digest") or "",
            "operation_count": payload.get("operation_count") or 0,
            "operations": payload.get("operations") or [],
            "operation_tables": payload.get("operation_tables") or [],
            "apply_snapshot_ops": payload.get("apply_snapshot_ops") or [],
            "apply_snapshot_tables": payload.get("apply_snapshot_tables") or [],
            "counts_by_action": payload.get("counts_by_action") or {},
            "counts_by_section": payload.get("counts_by_section") or {},
            "warnings": payload.get("warnings") or [],
            "row_diffs": payload.get("row_diffs") or [],
        }
        request.session.modified = True
        return redirect("plugins:netbox_automation_plugin:maas_openstack_reconciliation_stage")


@method_decorator(never_cache, name="dispatch")
class ReconciliationNotImplementedPostView(LoginRequiredMixin, View):
    """Placeholder for validate / merge / discard lifecycle endpoints."""

    http_method_names = ["post"]

    def post(self, request, run_id: int):
        get_object_or_404(MAASOpenStackReconciliationRun, pk=run_id)
        return JsonResponse(
            {"ok": False, "error": "This lifecycle action is not implemented yet."},
            status=501,
        )
