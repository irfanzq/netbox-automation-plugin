# Generated migration for VLANDeploymentJob model

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dcim', '0001_initial'),
        ('netbox_automation_plugin', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='VLANDeploymentJob',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict)),
                ('job_type', models.CharField(
                    choices=[('dryrun', 'Dry Run'), ('deployment', 'Deployment')],
                    max_length=20,
                    verbose_name='Type'
                )),
                ('status', models.CharField(
                    choices=[
                        ('pending', 'Pending'),
                        ('running', 'Running'),
                        ('completed', 'Completed'),
                        ('failed', 'Failed'),
                        ('cancelled', 'Cancelled')
                    ],
                    default='pending',
                    max_length=20,
                    verbose_name='Status'
                )),
                ('started_at', models.DateTimeField(blank=True, null=True, verbose_name='Started')),
                ('completed_at', models.DateTimeField(blank=True, null=True, verbose_name='Completed')),
                ('deployment_scope', models.CharField(
                    choices=[('single', 'Single Device'), ('group', 'Device Group')],
                    default='single',
                    max_length=20
                )),
                ('sync_netbox_to_device', models.BooleanField(default=False, verbose_name='Sync Mode')),
                ('untagged_vlan_id', models.IntegerField(blank=True, null=True, verbose_name='Untagged VLAN')),
                ('tagged_vlan_ids', models.JSONField(blank=True, default=list, verbose_name='Tagged VLANs')),
                ('result_summary', models.JSONField(blank=True, default=dict, help_text='Summary of deployment results')),
                ('error_message', models.TextField(blank=True, help_text='Error message if job failed')),
                ('execution_log', models.TextField(blank=True, help_text='Detailed execution log')),
                ('created_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='vlan_deployment_jobs',
                    to=settings.AUTH_USER_MODEL,
                    verbose_name='User'
                )),
                ('devices', models.ManyToManyField(
                    blank=True,
                    related_name='vlan_deployment_jobs',
                    to='dcim.device'
                )),
            ],
            options={
                'verbose_name': 'VLAN Deployment Job',
                'verbose_name_plural': 'VLAN Deployment Jobs',
                'ordering': ['-created'],
            },
        ),
        migrations.AddIndex(
            model_name='vlandeploymentjob',
            index=models.Index(fields=['-created'], name='netbox_auto_created_idx'),
        ),
        migrations.AddIndex(
            model_name='vlandeploymentjob',
            index=models.Index(fields=['job_type', 'status'], name='netbox_auto_job_type_status_idx'),
        ),
        migrations.AddIndex(
            model_name='vlandeploymentjob',
            index=models.Index(fields=['created_by'], name='netbox_auto_created_by_idx'),
        ),
    ]
