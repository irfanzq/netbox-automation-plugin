from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_automation_plugin", "0007_remove_vlan_created_by_dup_index"),
    ]

    operations = [
        migrations.RenameIndex(
            model_name="vlandeploymentjob",
            new_name="na_vlan_job_type_stat_idx",
            old_name="netbox_auto_job_type_status_idx",
        ),
        migrations.RenameIndex(
            model_name="maasopenstackdriftrun",
            new_name="na_drift_stat_created_idx",
            old_name="netbox_auto_drift_status_created_idx",
        ),
        migrations.RenameIndex(
            model_name="maasopenstackdriftrun",
            new_name="na_drift_user_created_idx",
            old_name="netbox_auto_drift_user_created_idx",
        ),
    ]
