# Add MAASOpenStackReconciliationRun.STATUS_BRANCH_NOT_READY choice

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_automation_plugin", "0010_add_netboxmodel_tags"),
    ]

    operations = [
        migrations.AlterField(
            model_name="maasopenstackreconciliationrun",
            name="status",
            field=models.CharField(
                max_length=32,
                choices=[
                    ("draft", "Draft"),
                    ("branch_creating", "Branch creating"),
                    ("branch_created", "Branch created"),
                    ("branch_create_failed", "Branch create failed"),
                    ("apply_in_progress", "Apply in progress"),
                    ("applied", "Applied"),
                    ("apply_failed_partial", "Apply failed (partial)"),
                    ("apply_failed", "Apply failed"),
                    ("branch_not_ready", "Branch schema not ready"),
                    ("validation_in_progress", "Validation in progress"),
                    ("validated", "Validated"),
                    ("validation_failed", "Validation failed"),
                    ("merge_in_progress", "Merge in progress"),
                    ("merged", "Merged"),
                    ("merge_failed", "Merge failed"),
                    ("discarded", "Discarded"),
                ],
                default="draft",
            ),
        ),
    ]
