from django.conf import settings
from django.db import models

from netbox.models import NetBoxModel


class MAASOpenStackDriftRun(NetBoxModel):
    """
    Persist one full drift-report snapshot per run for audit/history replay.
    """

    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = (
        (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED, "Failed"),
    )

    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_COMPLETED,
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="maas_openstack_drift_runs",
    )
    scope_filters = models.JSONField(default=dict, blank=True)
    audit_summary = models.JSONField(default=dict, blank=True)
    report_drift = models.TextField(blank=True)
    report_drift_markup = models.CharField(max_length=16, default="html")
    report_reference = models.TextField(blank=True)
    snapshot_payload = models.JSONField(default=dict, blank=True)
    source_cache_key = models.CharField(max_length=200, blank=True, default="")
    error_message = models.TextField(blank=True, default="")

    class Meta:
        app_label = "netbox_automation_plugin"
        ordering = ["-created"]
        verbose_name = "MAAS/OpenStack Drift Run"
        verbose_name_plural = "MAAS/OpenStack Drift Runs"
        indexes = [
            models.Index(fields=["-created"]),
            models.Index(fields=["status", "-created"]),
            models.Index(fields=["created_by", "-created"]),
        ]

    def __str__(self):
        return f"Drift run {self.pk} ({self.status})"
