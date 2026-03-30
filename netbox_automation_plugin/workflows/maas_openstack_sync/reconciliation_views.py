"""API + pages for MAAS/OpenStack branch reconciliation runs."""

from __future__ import annotations

import json
import logging

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import never_cache

from netbox_automation_plugin.models import MAASOpenStackReconciliationRun

from .history_models import MAASOpenStackDriftRun
from .reconciliation_service import (
    RECONCILIATION_DISCARD_BLOCKED_STATUSES,
    apply_reconciliation_run,
    create_reconciliation_run,
    discard_reconciliation_run,
    preview_reconciliation,
)

logger = logging.getLogger(__name__)


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
        try:
            payload = preview_reconciliation(drift_run=drift_run, selected_raw=selected)
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
        try:
            run = create_reconciliation_run(
                drift_run=drift_run,
                selected_raw=body.get("selected"),
                preview_ack_token=token.strip(),
                user=request.user,
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
                "frozen_ops": run.frozen_operations if isinstance(run.frozen_operations, list) else [],
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
class ReconciliationNotImplementedPostView(LoginRequiredMixin, View):
    """Placeholder for validate / merge / discard lifecycle endpoints."""

    http_method_names = ["post"]

    def post(self, request, run_id: int):
        get_object_or_404(MAASOpenStackReconciliationRun, pk=run_id)
        return JsonResponse(
            {"ok": False, "error": "This lifecycle action is not implemented yet."},
            status=501,
        )
