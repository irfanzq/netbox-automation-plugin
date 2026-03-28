from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("netbox_automation_plugin", "0003_maasopenstackdriftrun"),
    ]

    operations = [
        migrations.AddField(
            model_name="maasopenstackdriftrun",
            name="drift_review_overrides",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text="User edits to NB proposed columns (by selection_key / row / header).",
            ),
        ),
        migrations.AddField(
            model_name="maasopenstackdriftrun",
            name="report_drift_modified_html",
            field=models.TextField(
                blank=True,
                help_text="HTML drift report regenerated with drift_review_overrides applied.",
            ),
        ),
        migrations.AddField(
            model_name="maasopenstackdriftrun",
            name="drift_review_saved_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="maasopenstackdriftrun",
            name="drift_review_saved_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="maas_openstack_drift_runs_review_saved",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
