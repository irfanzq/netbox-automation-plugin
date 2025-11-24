import django_tables2 as tables
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html

from dcim.models import Device, Interface
from netbox.tables import NetBoxTable, columns


class VLANDeploymentResultTable(NetBoxTable):
    """
    Results table for VLAN deployment showing per-device/interface status.
    """

    device = tables.Column(
        accessor="device",
        verbose_name=_("Device"),
        linkify=True,
    )
    interface = tables.Column(
        accessor="interface",
        verbose_name=_("Interface"),
    )
    vlan_id = tables.Column(
        accessor="vlan_id",
        verbose_name=_("VLAN ID"),
    )
    vlan_name = tables.Column(
        accessor="vlan_name",
        verbose_name=_("VLAN Name"),
    )
    status = tables.Column(
        accessor="status",
        verbose_name=_("Status"),
    )
    config_applied = tables.Column(
        accessor="config_applied",
        verbose_name=_("Config Applied"),
    )
    netbox_updated = tables.Column(
        accessor="netbox_updated",
        verbose_name=_("NetBox Updated"),
    )
    deployment_logs = tables.Column(
        accessor="deployment_logs",
        verbose_name=_("Deployment Logs"),
        orderable=False,
    )

    def render_deployment_logs(self, value):
        """Render deployment logs as expandable HTML with proper formatting."""
        if not value:
            return format_html('<span class="text-muted">No logs available</span>')

        # Create expandable log section with unique ID
        import hashlib
        log_id = hashlib.md5(str(value).encode()).hexdigest()[:8]

        # Format logs with line breaks and proper styling
        formatted_logs = value.replace('\n', '<br>')

        html = f'''
        <details class="deployment-logs">
            <summary style="cursor: pointer; color: #0066cc; font-weight: bold;">
                📋 View Detailed Logs ({len(value.split(chr(10)))} lines)
            </summary>
            <div style="margin-top: 10px; padding: 10px; background-color: #f5f5f5; border-left: 3px solid #0066cc; font-family: monospace; font-size: 12px; max-height: 400px; overflow-y: auto;">
                {formatted_logs}
            </div>
        </details>
        '''
        return format_html(html)

    class Meta(NetBoxTable.Meta):
        model = Interface
        fields = (
            "device",
            "interface",
            "vlan_id",
            "vlan_name",
            "status",
            "config_applied",
            "netbox_updated",
            "deployment_logs",
        )
        default_columns = (
            "device",
            "interface",
            "vlan_id",
            "vlan_name",
            "status",
            "config_applied",
            "netbox_updated",
            "deployment_logs",
        )

