# Generated manually for MAASOpenStackReconciliationRun

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_automation_plugin", "0005_maasopenstackdriftrun_modified_xlsx"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="MAASOpenStackReconciliationRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("draft", "Draft"),
                            ("branch_creating", "Branch creating"),
                            ("branch_created", "Branch created"),
                            ("branch_create_failed", "Branch create failed"),
                            ("apply_in_progress", "Apply in progress"),
                            ("applied", "Applied"),
                            ("apply_failed_partial", "Apply failed (partial)"),
                            ("apply_failed", "Apply failed"),
                            ("validation_in_progress", "Validation in progress"),
                            ("validated", "Validated"),
                            ("validation_failed", "Validation failed"),
                            ("merge_in_progress", "Merge in progress"),
                            ("merged", "Merged"),
                            ("merge_failed", "Merge failed"),
                            ("discarded", "Discarded"),
                        ],
                        default="draft",
                        max_length=32,
                    ),
                ),
                (
                    "branch_id",
                    models.PositiveBigIntegerField(
                        blank=True,
                        help_text="NetBox Branch primary key when branching is available.",
                        null=True,
                    ),
                ),
                ("branch_name", models.CharField(blank=True, default="", max_length=240)),
                (
                    "frozen_operations",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text="Immutable operation set resolved at create time.",
                    ),
                ),
                ("operations_digest", models.CharField(blank=True, default="", max_length=64)),
                (
                    "selection",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Selected row keys by drift section (selection_key → row_key list).",
                    ),
                ),
                ("error_message", models.TextField(blank=True, default="")),
                ("apply_results", models.JSONField(blank=True, default=dict)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="maas_openstack_reconciliation_runs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "drift_run",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="reconciliation_runs",
                        to="netbox_automation_plugin.maasopenstackdriftrun",
                    ),
                ),
            ],
            options={
                "verbose_name": "MAAS/OpenStack branch reconciliation run",
                "verbose_name_plural": "MAAS/OpenStack branch reconciliation runs",
                "ordering": ["-created"],
            },
        ),
        migrations.AddIndex(
            model_name="maasopenstackreconciliationrun",
            index=models.Index(fields=["-created"], name="netbox_auto_recon_created_idx"),
        ),
        migrations.AddIndex(
            model_name="maasopenstackreconciliationrun",
            index=models.Index(
                fields=["status", "-created"],
                name="netbox_auto_recon_stat_crt_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="maasopenstackreconciliationrun",
            index=models.Index(
                fields=["drift_run", "-created"],
                name="netbox_auto_rcn_drift_c_idx",
            ),
        ),
    ]
