# Align ChangeLoggingMixin / CustomFieldsMixin fields with NetBox NetBoxModel (fixes makemigrations drift).

from django.db import migrations, models
from django.utils.translation import gettext_lazy as _

from utilities.json import CustomFieldJSONEncoder


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_automation_plugin", "0008_rename_indexes_max_30"),
    ]

    operations = [
        migrations.AlterField(
            model_name="automationjob",
            name="created",
            field=models.DateTimeField(
                auto_now_add=True,
                blank=True,
                null=True,
                verbose_name=_("created"),
            ),
        ),
        migrations.AlterField(
            model_name="automationjob",
            name="last_updated",
            field=models.DateTimeField(
                auto_now=True,
                blank=True,
                null=True,
                verbose_name=_("last updated"),
            ),
        ),
        migrations.AlterField(
            model_name="automationjob",
            name="custom_field_data",
            field=models.JSONField(
                blank=True,
                default=dict,
                encoder=CustomFieldJSONEncoder,
            ),
        ),
        migrations.AlterField(
            model_name="devicecompliance",
            name="created",
            field=models.DateTimeField(
                auto_now_add=True,
                blank=True,
                null=True,
                verbose_name=_("created"),
            ),
        ),
        migrations.AlterField(
            model_name="devicecompliance",
            name="last_updated",
            field=models.DateTimeField(
                auto_now=True,
                blank=True,
                null=True,
                verbose_name=_("last updated"),
            ),
        ),
        migrations.AlterField(
            model_name="devicecompliance",
            name="custom_field_data",
            field=models.JSONField(
                blank=True,
                default=dict,
                encoder=CustomFieldJSONEncoder,
            ),
        ),
        migrations.AlterField(
            model_name="automationtemplate",
            name="created",
            field=models.DateTimeField(
                auto_now_add=True,
                blank=True,
                null=True,
                verbose_name=_("created"),
            ),
        ),
        migrations.AlterField(
            model_name="automationtemplate",
            name="last_updated",
            field=models.DateTimeField(
                auto_now=True,
                blank=True,
                null=True,
                verbose_name=_("last updated"),
            ),
        ),
        migrations.AlterField(
            model_name="automationtemplate",
            name="custom_field_data",
            field=models.JSONField(
                blank=True,
                default=dict,
                encoder=CustomFieldJSONEncoder,
            ),
        ),
        migrations.AlterField(
            model_name="vlandeploymentjob",
            name="created",
            field=models.DateTimeField(
                auto_now_add=True,
                blank=True,
                null=True,
                verbose_name=_("created"),
            ),
        ),
        migrations.AlterField(
            model_name="vlandeploymentjob",
            name="last_updated",
            field=models.DateTimeField(
                auto_now=True,
                blank=True,
                null=True,
                verbose_name=_("last updated"),
            ),
        ),
        migrations.AlterField(
            model_name="vlandeploymentjob",
            name="custom_field_data",
            field=models.JSONField(
                blank=True,
                default=dict,
                encoder=CustomFieldJSONEncoder,
            ),
        ),
        migrations.AlterField(
            model_name="maasopenstackdriftrun",
            name="created",
            field=models.DateTimeField(
                auto_now_add=True,
                blank=True,
                null=True,
                verbose_name=_("created"),
            ),
        ),
        migrations.AlterField(
            model_name="maasopenstackdriftrun",
            name="last_updated",
            field=models.DateTimeField(
                auto_now=True,
                blank=True,
                null=True,
                verbose_name=_("last updated"),
            ),
        ),
        migrations.AlterField(
            model_name="maasopenstackdriftrun",
            name="custom_field_data",
            field=models.JSONField(
                blank=True,
                default=dict,
                encoder=CustomFieldJSONEncoder,
            ),
        ),
        migrations.AlterField(
            model_name="maasopenstackreconciliationrun",
            name="created",
            field=models.DateTimeField(
                auto_now_add=True,
                blank=True,
                null=True,
                verbose_name=_("created"),
            ),
        ),
        migrations.AlterField(
            model_name="maasopenstackreconciliationrun",
            name="last_updated",
            field=models.DateTimeField(
                auto_now=True,
                blank=True,
                null=True,
                verbose_name=_("last updated"),
            ),
        ),
        migrations.AlterField(
            model_name="maasopenstackreconciliationrun",
            name="custom_field_data",
            field=models.JSONField(
                blank=True,
                default=dict,
                encoder=CustomFieldJSONEncoder,
            ),
        ),
    ]
