from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_automation_plugin", "0004_maasopenstackdriftrun_review_overrides"),
    ]

    operations = [
        migrations.AddField(
            model_name="maasopenstackdriftrun",
            name="drift_review_modified_xlsx",
            field=models.BinaryField(
                blank=True,
                help_text="Excel export built when review edits were saved (same overrides as modified HTML).",
                null=True,
            ),
        ),
    ]
