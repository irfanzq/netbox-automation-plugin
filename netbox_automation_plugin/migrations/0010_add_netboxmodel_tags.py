# NetBoxModel includes TagsMixin (tags); historical CreateModels omitted this field.

import taggit.managers
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_automation_plugin", "0009_align_netboxmodel_base_fields"),
        # TaggedItem / Tag live in extras; __first__ avoids pinning a specific squashed name per NetBox release.
        ("extras", "__first__"),
    ]

    operations = [
        migrations.AddField(
            model_name="automationjob",
            name="tags",
            field=taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
        ),
        migrations.AddField(
            model_name="automationtemplate",
            name="tags",
            field=taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
        ),
        migrations.AddField(
            model_name="devicecompliance",
            name="tags",
            field=taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
        ),
        migrations.AddField(
            model_name="maasopenstackdriftrun",
            name="tags",
            field=taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
        ),
        migrations.AddField(
            model_name="maasopenstackreconciliationrun",
            name="tags",
            field=taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
        ),
        migrations.AddField(
            model_name="vlandeploymentjob",
            name="tags",
            field=taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
        ),
    ]
