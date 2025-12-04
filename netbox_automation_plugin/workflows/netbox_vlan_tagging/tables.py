import django_tables2 as tables
from django.utils.html import format_html
from django.urls import reverse

from dcim.models import Device, Interface


class VLANTaggingDeviceTable(tables.Table):
    """Table for displaying device analysis results"""
    
    name = tables.Column(linkify=True)
    role = tables.Column(accessor='role.name')
    site = tables.Column(accessor='site.name')
    status = tables.Column()
    recommendation = tables.Column(empty_values=())
    tags = tables.ManyToManyColumn(linkify_item=True)
    
    class Meta:
        model = Device
        fields = ('name', 'role', 'site', 'status', 'recommendation', 'tags')
        attrs = {
            'class': 'table table-hover',
        }
    
    def render_recommendation(self, value, record):
        """Render recommendation based on analysis"""
        # TODO: Implement based on analysis results
        return format_html('<span class="badge bg-success">Ready</span>')


class VLANTaggingInterfaceTable(tables.Table):
    """Table for displaying interface analysis results"""
    
    device = tables.Column(linkify=True, accessor='device.name')
    name = tables.Column(linkify=True)
    type = tables.Column(accessor='type')
    mode = tables.Column(accessor='mode', empty_values=())
    untagged_vlan = tables.Column(accessor='untagged_vlan.vid', empty_values=())
    tagged_vlans = tables.ManyToManyColumn(accessor='tagged_vlans', empty_values=())
    recommendation = tables.Column(empty_values=())
    reason = tables.Column(empty_values=())
    tags = tables.ManyToManyColumn(linkify_item=True)
    
    class Meta:
        model = Interface
        fields = ('device', 'name', 'type', 'mode', 'untagged_vlan', 'tagged_vlans', 'recommendation', 'reason', 'tags')
        attrs = {
            'class': 'table table-hover',
        }
    
    def render_recommendation(self, value, record):
        """Render recommendation badge"""
        # TODO: Implement based on analysis results
        return format_html('<span class="badge bg-info">Access-Ready</span>')
    
    def render_reason(self, value, record):
        """Render reason for classification"""
        # TODO: Implement based on analysis results
        return "Cabled to Host Device, active status"


class VLANTaggingResultTable(tables.Table):
    """Table for displaying overall workflow results"""
    
    category = tables.Column()
    count = tables.Column()
    percentage = tables.Column(empty_values=())
    
    class Meta:
        attrs = {
            'class': 'table table-hover',
        }
    
    def render_percentage(self, value, record):
        """Calculate and render percentage"""
        if record.get('total', 0) > 0:
            pct = (record.get('count', 0) / record.get('total', 1)) * 100
            return format_html('{:.1f}%', pct)
        return '0%'

