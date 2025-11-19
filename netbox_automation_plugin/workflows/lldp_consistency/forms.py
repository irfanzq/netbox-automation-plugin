from django import forms
from django.utils.translation import gettext_lazy as _
from django.db.models import Q

from dcim.models import Device, Manufacturer, Site, DeviceRole
from dcim.choices import DeviceStatusChoices


class DeviceChoiceField(forms.ModelMultipleChoiceField):
    """Custom field to display devices with their IP addresses"""
    
    def label_from_instance(self, obj):
        """Show device name and IP address"""
        if obj.primary_ip4:
            return f"{obj.name} ({obj.primary_ip4.address.ip})"
        elif obj.primary_ip6:
            return f"{obj.name} ({obj.primary_ip6.address.ip})"
        else:
            return f"{obj.name} (No IP)"


class LLDPConsistencyCheckForm(forms.Form):
    """
    Form for selecting devices and options for the LLDP Consistency Check workflow.
    """

    manufacturer = forms.ModelChoiceField(
        queryset=Manufacturer.objects.all(),
        required=False,
        label=_("Manufacturer"),
        help_text=_("Filter devices by manufacturer (e.g. Mellanox, Nvidia, Cumulus)."),
    )

    site = forms.ModelChoiceField(
        queryset=Site.objects.all(),
        required=False,
        label=_("Site"),
        help_text=_("Filter devices by site."),
    )

    role = forms.ModelChoiceField(
        queryset=DeviceRole.objects.all(),
        required=False,
        label=_("Role"),
        help_text=_("Filter devices by device role."),
    )

    status = forms.MultipleChoiceField(
        choices=DeviceStatusChoices,
        required=False,
        label=_("Status"),
        help_text=_("Filter devices by status (e.g. Active, Staged, Offline)."),
        widget=forms.SelectMultiple(attrs={'class': 'form-control', 'size': '7'}),
    )

    devices = DeviceChoiceField(
        queryset=Device.objects.select_related('primary_ip4', 'primary_ip6').all(),
        required=False,
        label=_("Devices"),
        help_text=_(
            "Select specific devices by name or IP address. If empty, the filters above will be used instead. "
            "Only devices with a primary IP will be included."
        ),
    )

    generate_csv = forms.BooleanField(
        required=False,
        initial=True,
        label=_("Generate CSV"),
        help_text=_("Include a CSV download of the LLDP consistency results."),
    )


