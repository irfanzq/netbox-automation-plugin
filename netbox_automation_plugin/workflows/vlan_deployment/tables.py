import django_tables2 as tables
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.utils.safestring import mark_safe

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
        orderable=True,
    )
    interface = tables.Column(
        accessor="interface",
        verbose_name=_("Interface"),
        orderable=True,
    )
    vlan = tables.Column(
        accessor="vlan_id",
        verbose_name=_("VLAN"),
        orderable=True,
    )
    device_status = tables.Column(
        accessor="device_status",
        verbose_name=_("Device Status"),
        orderable=True,
    )
    interface_status = tables.Column(
        accessor="interface_status",
        verbose_name=_("Interface Status"),
        orderable=True,
    )
    overall_status = tables.Column(
        accessor="overall_status",
        verbose_name=_("Overall Status"),
        orderable=True,
    )
    risk_level = tables.Column(
        accessor="risk_level",
        verbose_name=_("Risk Level"),
        orderable=True,
    )
    actions = tables.Column(
        accessor="deployment_logs",
        verbose_name=_("Actions"),
        orderable=False,
    )
    
    # Legacy columns (hidden by default but kept for compatibility)
    vlan_id = tables.Column(
        accessor="vlan_id",
        verbose_name=_("VLAN ID"),
        visible=False,
    )
    vlan_name = tables.Column(
        accessor="vlan_name",
        verbose_name=_("VLAN Name"),
        visible=False,
    )
    status = tables.Column(
        accessor="status",
        verbose_name=_("Status"),
        visible=False,
    )
    config_applied = tables.Column(
        accessor="config_applied",
        verbose_name=_("Config Applied"),
        visible=False,
    )
    netbox_updated = tables.Column(
        accessor="netbox_updated",
        verbose_name=_("NetBox Updated"),
        visible=False,
    )
    deployment_logs = tables.Column(
        accessor="deployment_logs",
        verbose_name=_("Deployment Logs"),
        orderable=False,
        visible=False,
    )

    def render_vlan(self, record):
        """Render VLAN ID and name."""
        vlan_id = record.get('vlan_id', 'N/A')
        vlan_name = record.get('vlan_name', '')
        if vlan_name:
            return format_html('{} ({})', vlan_id, vlan_name)
        return format_html('{}', vlan_id)
    
    def render_device_status(self, value):
        """Render device status with color-coded badge."""
        if not value:
            return format_html('<span class="badge bg-secondary">N/A</span>')
        value_upper = str(value).upper()
        if value_upper == 'PASS' or 'PASS' in value_upper:
            return format_html('<span class="badge bg-success">{}</span>', value)
        elif value_upper == 'BLOCK' or 'BLOCK' in value_upper:
            return format_html('<span class="badge bg-danger">{}</span>', value)
        return format_html('<span class="badge bg-secondary">{}</span>', value)
    
    def render_interface_status(self, value):
        """Render interface status with color-coded badge."""
        if not value:
            return format_html('<span class="badge bg-secondary">N/A</span>')
        value_upper = str(value).upper()
        if value_upper == 'PASS' or 'PASS' in value_upper:
            return format_html('<span class="badge bg-success">{}</span>', value)
        elif value_upper == 'WARN' or 'WARN' in value_upper:
            return format_html('<span class="badge bg-warning text-dark">{}</span>', value)
        elif value_upper == 'BLOCK' or 'BLOCK' in value_upper:
            return format_html('<span class="badge bg-danger">{}</span>', value)
        return format_html('<span class="badge bg-secondary">{}</span>', value)
    
    def render_overall_status(self, value):
        """Render overall status with color-coded badge."""
        if not value:
            return format_html('<span class="badge bg-secondary">N/A</span>')
        value_upper = str(value).upper()
        if value_upper == 'PASS' or 'PASS' in value_upper:
            return format_html('<span class="badge bg-success">{}</span>', value)
        elif value_upper == 'WARN' or 'WARN' in value_upper:
            return format_html('<span class="badge bg-warning text-dark">{}</span>', value)
        elif value_upper == 'BLOCKED' or 'BLOCK' in value_upper:
            return format_html('<span class="badge bg-danger">{}</span>', value)
        return format_html('<span class="badge bg-secondary">{}</span>', value)
    
    def render_risk_level(self, value):
        """Render risk level with color-coded badge."""
        if value == 'HIGH':
            return format_html('<span class="badge bg-danger">{}</span>', value)
        elif value == 'MEDIUM':
            return format_html('<span class="badge bg-warning text-dark">{}</span>', value)
        elif value == 'LOW':
            return format_html('<span class="badge bg-success">{}</span>', value)
        return format_html('<span class="badge bg-secondary">{}</span>', value or 'N/A')
    
    def render_actions(self, record):
        """Render expandable detailed logs button."""
        value = record.get('deployment_logs', '')
        if not value:
            return format_html('<span class="text-muted">No logs available</span>')

        # Create expandable log section with unique ID
        import hashlib
        log_id = hashlib.md5(str(value).encode()).hexdigest()[:8]
        
        # Get status for filtering
        overall_status = record.get('overall_status', '').lower()
        if overall_status == 'blocked':
            status_filter = 'blocked'
        elif overall_status == 'warn':
            status_filter = 'warn'
        else:
            status_filter = 'pass'

        # Format logs with line breaks and proper styling
        # Escape HTML in logs to prevent XSS, but preserve our <br> tags
        import html as html_module
        escaped_logs = html_module.escape(value).replace('\n', '<br>')
        line_count = len(value.split('\n'))

        # Use mark_safe instead of format_html to avoid issues with curly braces in logs
        html = (
            '<details class="deployment-logs" data-status-filter="' + html_module.escape(status_filter) + '">'
            '<summary style="cursor: pointer; color: var(--nbx-color-fg-link, #0066cc); font-weight: bold;">'
            'View Details (' + str(line_count) + ' lines)'
            '</summary>'
            '<div style="margin-top: 10px; padding: 10px; background-color: var(--nbx-color-bg-secondary, #f5f5f5); color: #212529; border-left: 3px solid var(--nbx-color-border-primary, #0066cc); font-family: monospace; font-size: 12px; max-height: 400px; overflow-y: auto;">'
            + escaped_logs +
            '</div>'
            '<style>'
            '@media (prefers-color-scheme: dark) {'
            '.deployment-logs[data-status-filter="' + html_module.escape(status_filter) + '"] div {'
            'background-color: #2a2a2a !important; /* Dark background in dark mode */'
            'color: #ffffff !important; /* White in dark mode */'
            '}'
            '}'
            '</style>'
            '</details>'
        )
        return mark_safe(html)
    
    def render_deployment_logs(self, value):
        """Render deployment logs as expandable HTML with proper formatting."""
        if not value:
            return format_html('<span class="text-muted">No logs available</span>')

        # Create expandable log section with unique ID
        import hashlib
        import html as html_module
        log_id = hashlib.md5(str(value).encode()).hexdigest()[:8]

        # Format logs with line breaks and proper styling
        # Escape HTML in logs to prevent XSS, but preserve our <br> tags
        escaped_logs = html_module.escape(value).replace('\n', '<br>')
        line_count = len(value.split('\n'))

        # Use mark_safe instead of format_html to avoid issues with curly braces in logs
        html = (
            '<details class="deployment-logs">'
            '<summary style="cursor: pointer; color: var(--nbx-color-fg-link, #0066cc); font-weight: bold;">'
            'View Detailed Logs (' + str(line_count) + ' lines)'
            '</summary>'
            '<div style="margin-top: 10px; padding: 10px; background-color: var(--nbx-color-bg-secondary, #f5f5f5); color: #212529; border-left: 3px solid var(--nbx-color-border-primary, #0066cc); font-family: monospace; font-size: 12px; max-height: 400px; overflow-y: auto;">'
            + escaped_logs +
            '</div>'
            '<style>'
            '@media (prefers-color-scheme: dark) {'
            '.deployment-logs div {'
            'color: #ffffff !important; /* White in dark mode */'
            '}'
            '}'
            '</style>'
            '</details>'
        )
        return mark_safe(html)

    class Meta(NetBoxTable.Meta):
        model = Interface
        fields = (
            "device",
            "interface",
            "vlan",
            "device_status",
            "interface_status",
            "overall_status",
            "risk_level",
            "actions",
            # Legacy fields (hidden)
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
            "vlan",
            "device_status",
            "interface_status",
            "overall_status",
            "risk_level",
            "actions",
        )

