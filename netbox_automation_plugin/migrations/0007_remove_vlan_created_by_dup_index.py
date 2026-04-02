from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_automation_plugin", "0006_maasopenstackreconciliationrun"),
    ]

    operations = [
        migrations.RemoveIndex(
            model_name="vlandeploymentjob",
            name="netbox_auto_created_by_idx",
        ),
    ]
