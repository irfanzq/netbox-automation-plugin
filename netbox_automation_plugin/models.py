"""
NetBox Automation Plugin Models
"""

from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from netbox.models import NetBoxModel
from dcim.models import Device
from extras.models import CustomField


class AutomationJob(NetBoxModel):
    """
    Track automation jobs and their status
    """
    JOB_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    JOB_TYPE_CHOICES = [
        ('config_deploy', 'Configuration Deployment'),
        ('data_collection', 'Data Collection'),
        ('compliance_check', 'Compliance Check'),
        ('backup', 'Backup'),
        ('custom', 'Custom Task'),
    ]
    
    name = models.CharField(max_length=100)
    job_type = models.CharField(max_length=20, choices=JOB_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=JOB_STATUS_CHOICES, default='pending')
    devices = models.ManyToManyField(Device, related_name='automation_jobs')
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    result_data = models.JSONField(default=dict, blank=True)
    
    class Meta:
        app_label = 'netbox_automation_plugin'
        ordering = ['-created']
        verbose_name = 'Automation Job'
        verbose_name_plural = 'Automation Jobs'


class DeviceCompliance(NetBoxModel):
    """
    Track device compliance status
    """
    COMPLIANCE_STATUS_CHOICES = [
        ('compliant', 'Compliant'),
        ('non_compliant', 'Non-Compliant'),
        ('unknown', 'Unknown'),
        ('error', 'Error'),
    ]
    
    device = models.OneToOneField(Device, on_delete=models.CASCADE, related_name='compliance')
    status = models.CharField(max_length=20, choices=COMPLIANCE_STATUS_CHOICES, default='unknown')
    last_checked = models.DateTimeField(auto_now=True)
    compliance_score = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        default=0
    )
    issues = models.JSONField(default=list, blank=True)
    recommendations = models.JSONField(default=list, blank=True)
    
    class Meta:
        app_label = 'netbox_automation_plugin'
        ordering = ['-last_checked']
        verbose_name = 'Device Compliance'
        verbose_name_plural = 'Device Compliance Records'


class AutomationTemplate(NetBoxModel):
    """
    Store automation templates for different device types
    """
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    device_type = models.ForeignKey(
        'dcim.DeviceType',
        on_delete=models.CASCADE,
        related_name='automation_templates'
    )
    template_type = models.CharField(
        max_length=20,
        choices=[
            ('config', 'Configuration Template'),
            ('compliance', 'Compliance Check'),
            ('backup', 'Backup Script'),
            ('custom', 'Custom Script'),
        ]
    )
    template_content = models.TextField()
    is_active = models.BooleanField(default=True)
    
    class Meta:
        app_label = 'netbox_automation_plugin'
        ordering = ['name']
        verbose_name = 'Automation Template'
        verbose_name_plural = 'Automation Templates'


class VLANDeploymentJob(NetBoxModel):
    """
    Track VLAN deployment workflow executions (dry runs and deployments)
    """
    JOB_TYPE_CHOICES = [
        ('dryrun', 'Dry Run'),
        ('deployment', 'Deployment'),
    ]
    
    JOB_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    job_type = models.CharField(
        max_length=20,
        choices=JOB_TYPE_CHOICES,
        verbose_name='Type'
    )
    status = models.CharField(
        max_length=20,
        choices=JOB_STATUS_CHOICES,
        default='pending',
        verbose_name='Status'
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='vlan_deployment_jobs',
        verbose_name='User'
    )
    started_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Started'
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Completed'
    )
    
    # Deployment parameters
    deployment_scope = models.CharField(
        max_length=20,
        choices=[
            ('single', 'Single Device'),
            ('group', 'Device Group'),
        ],
        default='single'
    )
    sync_netbox_to_device = models.BooleanField(
        default=False,
        verbose_name='Sync Mode'
    )
    untagged_vlan_id = models.IntegerField(
        null=True,
        blank=True,
        verbose_name='Untagged VLAN'
    )
    tagged_vlan_ids = models.JSONField(
        default=list,
        blank=True,
        verbose_name='Tagged VLANs'
    )
    
    # Devices involved in this deployment
    devices = models.ManyToManyField(
        Device,
        related_name='vlan_deployment_jobs',
        blank=True
    )
    
    # Results and metadata
    result_summary = models.JSONField(
        default=dict,
        blank=True,
        help_text='Summary of deployment results'
    )
    error_message = models.TextField(
        blank=True,
        help_text='Error message if job failed'
    )
    execution_log = models.TextField(
        blank=True,
        help_text='Detailed execution log'
    )
    
    class Meta:
        app_label = 'netbox_automation_plugin'
        ordering = ['-created']
        verbose_name = 'VLAN Deployment Job'
        verbose_name_plural = 'VLAN Deployment Jobs'
        indexes = [
            models.Index(fields=['-created']),
            models.Index(fields=['job_type', 'status']),
            models.Index(fields=['created_by']),
        ]
    
    def __str__(self):
        return f"VLAN Deployment {self.job_type} - {self.get_status_display()} ({self.id})"


class MAASOpenStackDriftRun(NetBoxModel):
    """
    Persist one full MAAS/OpenStack drift-report snapshot per run.
    """
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED, "Failed"),
    ]

    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_COMPLETED)
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
    drift_review_overrides = models.JSONField(
        default=dict,
        blank=True,
        help_text="User edits to NB proposed columns (by selection_key / row / header).",
    )
    report_drift_modified_html = models.TextField(
        blank=True,
        help_text="HTML drift report regenerated with drift_review_overrides applied.",
    )
    drift_review_modified_xlsx = models.BinaryField(
        null=True,
        blank=True,
        help_text="Excel export built when review edits were saved (same overrides as modified HTML).",
    )
    drift_review_saved_at = models.DateTimeField(null=True, blank=True)
    drift_review_saved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="maas_openstack_drift_runs_review_saved",
    )

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


class MAASOpenStackReconciliationRun(NetBoxModel):
    """
    Branch reconciliation run: frozen drift rows → NetBox Branch → (future) apply/merge.
    """

    STATUS_DRAFT = "draft"
    STATUS_BRANCH_CREATING = "branch_creating"
    STATUS_BRANCH_CREATED = "branch_created"
    STATUS_BRANCH_CREATE_FAILED = "branch_create_failed"
    STATUS_APPLY_IN_PROGRESS = "apply_in_progress"
    STATUS_APPLIED = "applied"
    STATUS_APPLY_FAILED_PARTIAL = "apply_failed_partial"
    STATUS_APPLY_FAILED = "apply_failed"
    STATUS_VALIDATION_IN_PROGRESS = "validation_in_progress"
    STATUS_VALIDATED = "validated"
    STATUS_VALIDATION_FAILED = "validation_failed"
    STATUS_MERGE_IN_PROGRESS = "merge_in_progress"
    STATUS_MERGED = "merged"
    STATUS_MERGE_FAILED = "merge_failed"
    STATUS_DISCARDED = "discarded"

    STATUS_CHOICES = [
        (STATUS_DRAFT, "Draft"),
        (STATUS_BRANCH_CREATING, "Branch creating"),
        (STATUS_BRANCH_CREATED, "Branch created"),
        (STATUS_BRANCH_CREATE_FAILED, "Branch create failed"),
        (STATUS_APPLY_IN_PROGRESS, "Apply in progress"),
        (STATUS_APPLIED, "Applied"),
        (STATUS_APPLY_FAILED_PARTIAL, "Apply failed (partial)"),
        (STATUS_APPLY_FAILED, "Apply failed"),
        (STATUS_VALIDATION_IN_PROGRESS, "Validation in progress"),
        (STATUS_VALIDATED, "Validated"),
        (STATUS_VALIDATION_FAILED, "Validation failed"),
        (STATUS_MERGE_IN_PROGRESS, "Merge in progress"),
        (STATUS_MERGED, "Merged"),
        (STATUS_MERGE_FAILED, "Merge failed"),
        (STATUS_DISCARDED, "Discarded"),
    ]

    drift_run = models.ForeignKey(
        MAASOpenStackDriftRun,
        on_delete=models.CASCADE,
        related_name="reconciliation_runs",
    )
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default=STATUS_DRAFT)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="maas_openstack_reconciliation_runs",
    )
    branch_id = models.PositiveBigIntegerField(
        null=True,
        blank=True,
        help_text="NetBox Branch primary key when branching is available.",
    )
    branch_name = models.CharField(max_length=240, blank=True, default="")
    frozen_operations = models.JSONField(
        default=list,
        blank=True,
        help_text="Immutable operation set resolved at create time.",
    )
    operations_digest = models.CharField(max_length=64, blank=True, default="")
    selection = models.JSONField(
        default=dict,
        blank=True,
        help_text="Selected row keys by drift section (selection_key → row_key list).",
    )
    error_message = models.TextField(blank=True, default="")
    apply_results = models.JSONField(default=dict, blank=True)

    class Meta:
        app_label = "netbox_automation_plugin"
        ordering = ["-created"]
        verbose_name = "MAAS/OpenStack branch reconciliation run"
        verbose_name_plural = "MAAS/OpenStack branch reconciliation runs"
        indexes = [
            models.Index(fields=["-created"]),
            models.Index(fields=["status", "-created"]),
            models.Index(fields=["drift_run", "-created"]),
        ]

    def __str__(self):
        return f"Reconciliation {self.pk} ({self.status})"


