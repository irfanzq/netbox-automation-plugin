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


