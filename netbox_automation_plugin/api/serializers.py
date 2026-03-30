"""
Serializers referenced by utilities.api.get_serializer_for_model().

NetBox enqueues model updates for event rules using extras.events.serialize_for_event(),
which requires a serializer class at netbox_automation_plugin.api.serializers.<Model>Serializer.
Without this, saving these models raises SerializerNotFound.
"""

from rest_framework import serializers

from netbox_automation_plugin.models import MAASOpenStackDriftRun, MAASOpenStackReconciliationRun


class MAASOpenStackDriftRunSerializer(serializers.ModelSerializer):
    """Minimal, safe fields for change events (exclude large text/binary blobs)."""

    display = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = MAASOpenStackDriftRun
        fields = [
            "id",
            "display",
            "created",
            "last_updated",
            "status",
            "created_by",
            "drift_review_saved_at",
            "drift_review_saved_by",
            "source_cache_key",
        ]
        read_only_fields = fields

    def get_display(self, obj):
        return str(obj)


class MAASOpenStackReconciliationRunSerializer(serializers.ModelSerializer):
    """Minimal fields for change events (omit large JSON / text blobs)."""

    display = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = MAASOpenStackReconciliationRun
        fields = [
            "id",
            "display",
            "created",
            "last_updated",
            "status",
            "drift_run",
            "created_by",
            "branch_id",
            "branch_name",
            "operations_digest",
        ]
        read_only_fields = fields

    def get_display(self, obj):
        return str(obj)
