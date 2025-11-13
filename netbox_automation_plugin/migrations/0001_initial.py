from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('dcim', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AutomationJob',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('last_updated', models.DateTimeField(auto_now=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict)),
                ('name', models.CharField(max_length=100)),
                ('job_type', models.CharField(
                    choices=[
                        ('config_deploy', 'Configuration Deployment'),
                        ('data_collection', 'Data Collection'),
                        ('compliance_check', 'Compliance Check'),
                        ('backup', 'Backup'),
                        ('custom', 'Custom Task')
                    ],
                    max_length=20
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
                    max_length=20
                )),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('error_message', models.TextField(blank=True)),
                ('result_data', models.JSONField(blank=True, default=dict)),
                ('created_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    to=settings.AUTH_USER_MODEL
                )),
                ('devices', models.ManyToManyField(
                    related_name='automation_jobs',
                    to='dcim.device'
                )),
            ],
            options={
                'ordering': ['-created'],
                'verbose_name': 'Automation Job',
                'verbose_name_plural': 'Automation Jobs',
            },
        ),
        migrations.CreateModel(
            name='DeviceCompliance',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('last_updated', models.DateTimeField(auto_now=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict)),
                ('status', models.CharField(
                    choices=[
                        ('compliant', 'Compliant'),
                        ('non_compliant', 'Non-Compliant'),
                        ('unknown', 'Unknown'),
                        ('error', 'Error')
                    ],
                    default='unknown',
                    max_length=20
                )),
                ('last_checked', models.DateTimeField(auto_now=True)),
                ('compliance_score', models.IntegerField(
                    default=0,
                    validators=[MinValueValidator(0), MaxValueValidator(100)]
                )),
                ('issues', models.JSONField(blank=True, default=list)),
                ('recommendations', models.JSONField(blank=True, default=list)),
                ('device', models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='compliance',
                    to='dcim.device'
                )),
            ],
            options={
                'ordering': ['-last_checked'],
                'verbose_name': 'Device Compliance',
                'verbose_name_plural': 'Device Compliance Records',
            },
        ),
        migrations.CreateModel(
            name='AutomationTemplate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('last_updated', models.DateTimeField(auto_now=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict)),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True)),
                ('template_type', models.CharField(
                    choices=[
                        ('config', 'Configuration Template'),
                        ('compliance', 'Compliance Check'),
                        ('backup', 'Backup Script'),
                        ('custom', 'Custom Script')
                    ],
                    max_length=20
                )),
                ('template_content', models.TextField()),
                ('is_active', models.BooleanField(default=True)),
                ('device_type', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='automation_templates',
                    to='dcim.devicetype'
                )),
            ],
            options={
                'ordering': ['name'],
                'verbose_name': 'Automation Template',
                'verbose_name_plural': 'Automation Templates',
            },
        ),
    ]

