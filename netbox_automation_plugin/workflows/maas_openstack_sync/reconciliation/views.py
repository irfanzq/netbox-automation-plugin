"""API + pages for MAAS/OpenStack branch reconciliation runs."""

from __future__ import annotations

import json
import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import never_cache

from netbox_automation_plugin.models import MAASOpenStackReconciliationRun

from ..history_models import MAASOpenStackDriftRun
from .service import (
    frozen_operations_for_display,
    RECONCILIATION_DISCARD_BLOCKED_STATUSES,
    apply_reconciliation_run,
    create_reconciliation_run,
    discard_reconciliation_run,
    preview_reconciliation,
)

logger = logging.getLogger(__name__)

MAAS_RECON_STAGING_SESSION_KEY = "maas_recon_staging_v1"


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
        blocked_discard = RECONCILIATION_DISCARD_BLOCKED_STATUSES
        apply_ok = {
            MAASOpenStackReconciliationRun.STATUS_BRANCH_CREATED,
            MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED_PARTIAL,
            MAASOpenStackReconciliationRun.STATUS_APPLY_FAILED,
        }
        return render(
            request,
            self.template_name,
            {
                "run": run,
                "frozen_ops": frozen_operations_for_display(
                    run.frozen_operations if isinstance(run.frozen_operations, list) else []
                ),
                "apply_results": run.apply_results if isinstance(run.apply_results, dict) else {},
                "apply_url": reverse(
                    "plugins:netbox_automation_plugin:maas_openstack_reconciliation_apply",
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
                "can_discard": run.status not in blocked_discard,
                "can_apply": run.status in apply_ok,
                "can_retry_failed": run.status in apply_ok
                and run.status
                != MAASOpenStackReconciliationRun.STATUS_BRANCH_CREATED,
            },
        )


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
        return JsonResponse(
            {
                "ok": True,
                "run_id": run.pk,
                "status": run.status,
                "apply_results": run.apply_results if isinstance(run.apply_results, dict) else {},
            }
        )


@method_decorator(never_cache, name="dispatch")
class ReconciliationRetryFailedView(LoginRequiredMixin, View):
    http_method_names = ["post"]

    def post(self, request, run_id: int):
        run = get_object_or_404(MAASOpenStackReconciliationRun, pk=run_id)
        try:
            run = apply_reconciliation_run(run=run, actor=request.user, retry_failed_only=True)
        except ValueError as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=400)
        except Exception as e:
            logger.exception("Reconciliation retry-failed failed for run %s", run_id)
            return JsonResponse({"ok": False, "error": str(e)}, status=500)
        return JsonResponse(
            {
                "ok": True,
                "run_id": run.pk,
                "status": run.status,
                "apply_results": run.apply_results if isinstance(run.apply_results, dict) else {},
            }
        )


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
        return JsonResponse(
            {
                "ok": True,
                "run_id": run.pk,
                "status": run.status,
                "apply_results": run.apply_results if isinstance(run.apply_results, dict) else {},
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
        return render(
            request,
            self.template_name,
            {
                "drift_run": drift_run,
                "audit_back_url": audit_back_url,
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
            messages.error(request, str(e))
            return redirect(back)
        except Exception as e:
            logger.exception("Reconciliation staging preview failed for drift run %s", drift_run_id)
            messages.error(request, str(e))
            return redirect(back)

        posted_store = posted_overrides if isinstance(posted_overrides, dict) else {}
        request.session[MAAS_RECON_STAGING_SESSION_KEY] = {
            "drift_run_id": drift_run.pk,
            "selected": selected,
            "posted_review_overrides": posted_store,
            "preview_ack_token": payload.get("preview_ack_token") or "",
            "operations_digest": payload.get("operations_digest") or "",
            "operation_count": payload.get("operation_count") or 0,
            "operations": payload.get("operations") or [],
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
