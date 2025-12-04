from django import forms
from django.utils.translation import gettext_lazy as _

from dcim.models import Device, Site, Location, DeviceRole, Manufacturer


class VLANTaggingForm(forms.Form):
    """
    Form for NetBox VLAN Tagging workflow.
    
    This workflow analyzes devices and interfaces and applies NetBox tags based on criteria.
    It has two modes:
    1. Analysis Mode: Analyze and show classification results
    2. Tagging Mode: Apply tags to devices and interfaces
    """

    # Workflow mode: Analysis or Tagging
    workflow_mode = forms.ChoiceField(
        choices=[
            ('analysis', 'Analysis Mode'),
            ('tagging', 'Tagging Mode'),
        ],
        initial='analysis',
        label=_("Workflow Mode"),
        help_text=_("Analysis Mode: Analyze devices/interfaces and show results. Tagging Mode: Apply tags based on analysis."),
        widget=forms.RadioSelect(attrs={'class': 'form-check-input'}),
    )

    # Device selection: single device or group
    device_selection = forms.ChoiceField(
        choices=[
            ('single', 'Single Device'),
            ('group', 'Device Group (by Site, Location, Role, Manufacturer)'),
        ],
        initial='single',
        label=_("Device Selection"),
        help_text=_("Select a single device or a group of devices by filters."),
        widget=forms.RadioSelect(attrs={'class': 'form-check-input'}),
    )

    # Single device mode: Multi-select devices
    devices = forms.ModelMultipleChoiceField(
        queryset=Device.objects.select_related(
            'primary_ip4', 'primary_ip6', 'site', 'role', 
            'device_type', 'device_type__manufacturer'
        ).filter(
            primary_ip4__isnull=False
        ) | Device.objects.select_related(
            'primary_ip4', 'primary_ip6', 'site', 'role',
            'device_type', 'device_type__manufacturer'
        ).filter(
            primary_ip6__isnull=False
        ),
        required=False,
        label=_("Devices"),
        help_text=_("Select one or more devices for analysis/tagging."),
    )

    # Group selection (for Device Group mode)
    site = forms.ModelChoiceField(
        queryset=Site.objects.all(),
        required=False,
        label=_("Site"),
        help_text=_("Select site for group analysis/tagging."),
    )

    location = forms.ModelChoiceField(
        queryset=Location.objects.all(),
        required=False,
        label=_("Location"),
        help_text=_("Select location within the site."),
    )

    manufacturer = forms.ModelChoiceField(
        queryset=Manufacturer.objects.all(),
        required=False,
        label=_("Manufacturer"),
        help_text=_("Select manufacturer to filter devices (e.g., Arista, Mellanox)."),
    )

    role = forms.ModelChoiceField(
        queryset=DeviceRole.objects.all(),
        required=False,
        label=_("Device Role"),
        help_text=_("Select device role (e.g., Network Leaf)."),
    )

    # Tagging mode options
    tag_devices = forms.BooleanField(
        required=False,
        initial=False,
        label=_("Tag Devices"),
        help_text=_("Apply 'automation-ready:vlan' tag to eligible devices."),
    )

    tag_interfaces = forms.BooleanField(
        required=False,
        initial=False,
        label=_("Tag Interfaces"),
        help_text=_("Apply interface tags (vlan-mode:access, vlan-mode:tagged, etc.) to eligible interfaces."),
    )

    # Delete tags options
    delete_device_tags = forms.BooleanField(
        required=False,
        initial=False,
        label=_("Delete Device Tags"),
        help_text=_("Delete 'automation-ready:vlan' tag from selected devices."),
    )

    delete_interface_tags = forms.BooleanField(
        required=False,
        initial=False,
        label=_("Delete Interface Tags"),
        help_text=_("Delete all 'vlan-mode:*' tags from interfaces on selected devices."),
    )

    # Optional: Use device config check for safety warnings
    use_device_config_check = forms.BooleanField(
        required=False,
        initial=False,
        label=_("Use Device Config Check (Optional)"),
        help_text=_("Query device configuration to warn about NetBox/device mismatches (slower but safer)."),
    )

