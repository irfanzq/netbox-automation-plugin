# Generated migration for MAASOpenStackDriftRun model

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_automation_plugin", "0002_vlandeploymentjob"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="MAASOpenStackDriftRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict)),
                (
                    "status",
                    models.CharField(
                        choices=[("completed", "Completed"), ("failed", "Failed")],
                        default="completed",
                        max_length=16,
                    ),
                ),
                ("scope_filters", models.JSONField(blank=True, default=dict)),
                ("audit_summary", models.JSONField(blank=True, default=dict)),
                ("report_drift", models.TextField(blank=True)),
                ("report_drift_markup", models.CharField(default="html", max_length=16)),
                ("report_reference", models.TextField(blank=True)),
                ("snapshot_payload", models.JSONField(blank=True, default=dict)),
                ("source_cache_key", models.CharField(blank=True, default="", max_length=200)),
                ("error_message", models.TextField(blank=True, default="")),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="maas_openstack_drift_runs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "MAAS/OpenStack Drift Run",
                "verbose_name_plural": "MAAS/OpenStack Drift Runs",
                "ordering": ["-created"],
            },
        ),
        migrations.AddIndex(
            model_name="maasopenstackdriftrun",
            index=models.Index(fields=["-created"], name="netbox_auto_drift_created_idx"),
        ),
        migrations.AddIndex(
            model_name="maasopenstackdriftrun",
            index=models.Index(fields=["status", "-created"], name="netbox_auto_drift_status_created_idx"),
        ),
        migrations.AddIndex(
            model_name="maasopenstackdriftrun",
            index=models.Index(fields=["created_by", "-created"], name="netbox_auto_drift_user_created_idx"),
        ),
    ]
