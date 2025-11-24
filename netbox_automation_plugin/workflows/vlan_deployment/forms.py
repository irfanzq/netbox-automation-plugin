from django import forms
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator

from dcim.models import Device, Site, Location, DeviceRole, Interface
from ipam.models import VLAN


class VLANDeploymentForm(forms.Form):
    """
    Form for VLAN deployment workflow.
    Phase 1: Single VLAN assignment to interfaces in access mode.

    Single Device Mode: Select one or more devices + common interfaces (dropdown)
    Device Group Mode: Select Site + Location + Role + manual interface list (text input)
    """

    # Deployment scope: single device or group
    deployment_scope = forms.ChoiceField(
        choices=[
            ('single', 'Single Device'),
            ('group', 'Device Group (by Site, Location, and Role)'),
        ],
        initial='single',
        label=_("Deployment Scope"),
        help_text=_("Deploy to a single device or a group of devices."),
        widget=forms.RadioSelect(attrs={'class': 'form-check-input'}),
    )

    # Single device mode: Multi-select devices (same as LLDP form)
    devices = forms.ModelMultipleChoiceField(
        queryset=Device.objects.select_related('primary_ip4', 'primary_ip6', 'site', 'role', 'device_type', 'device_type__manufacturer').filter(
            primary_ip4__isnull=False
        ) | Device.objects.select_related('primary_ip4', 'primary_ip6', 'site', 'role', 'device_type', 'device_type__manufacturer').filter(
            primary_ip6__isnull=False
        ),
        required=False,
        label=_("Devices"),
        help_text=_("Select one or more devices. Interfaces will be filtered to show only those common to all selected devices."),
    )

    # Group selection (for Device Group mode)
    site = forms.ModelChoiceField(
        queryset=Site.objects.all(),
        required=False,
        label=_("Site"),
        help_text=_("Select site for group deployment (e.g., B52)."),
    )

    location = forms.ModelChoiceField(
        queryset=Location.objects.all(),
        required=False,
        label=_("Location"),
        help_text=_("Select location within the site (e.g., Spruce)."),
    )

    role = forms.ModelChoiceField(
        queryset=DeviceRole.objects.all(),
        required=False,
        label=_("Device Role"),
        help_text=_("Select device role for group deployment (e.g., Network Leaf)."),
    )

    # Simple VLAN ID input - just a number field
    vlan_id = forms.IntegerField(
        required=True,
        min_value=1,
        max_value=4094,
        label=_("VLAN ID"),
        help_text=_("Enter VLAN ID (1-4094)"),
        widget=forms.NumberInput(attrs={
            'placeholder': 'e.g., 100',
            'class': 'form-control'
        }),
    )

    # Interface selection - Checkbox list (populated via JavaScript)
    # Using CharField instead of MultipleChoiceField to avoid validation issues
    interfaces_select = forms.CharField(
        required=False,
        widget=forms.HiddenInput(),  # Hidden field, actual checkboxes rendered in template
        label=_("Available Interfaces"),
    )

    # Interface selection - Manual text input
    interfaces_manual = forms.CharField(
        required=False,
        label=_("Additional Interfaces"),
        help_text=_(
            "Enter additional interface names separated by commas (e.g., swp1, swp2, bond1) or use ranges (e.g., swp1-48, Ethernet1-24)."
        ),
        widget=forms.Textarea(attrs={
            'rows': 2,
            'placeholder': 'Optional: Add custom interfaces (e.g., swp100, swp200 or swp1-48)',
            'class': 'form-control'
        }),
    )

    # Deployment options (mutually exclusive)
    dry_run = forms.BooleanField(
        required=False,
        initial=True,
        label=_("Dry Run (Preview Only)"),
        help_text=_("Preview changes without applying them to devices or NetBox."),
    )

    deploy_changes = forms.BooleanField(
        required=False,
        initial=False,
        label=_("Deploy Changes to Devices and NetBox"),
        help_text=_("Apply VLAN configuration to devices and update NetBox interface assignments."),
    )

    def clean_interfaces_select(self):
        """
        Get the list of selected interfaces from checkboxes.
        Since the field is a CharField (hidden), we need to get the actual checkbox values from request data.
        """
        # Get the raw submitted values (list of interface names from checkboxes)
        interfaces = self.data.getlist('interfaces_select')
        # Return as list (not string)
        return interfaces if interfaces else []

    def _parse_interface_list(self, interfaces_str):
        """
        Parse comma-separated interface list with support for ranges.
        Examples:
          - "swp1, swp2, swp3" -> ["swp1", "swp2", "swp3"]
          - "swp1-3" -> ["swp1", "swp2", "swp3"]
          - "Ethernet1-24" -> ["Ethernet1", "Ethernet2", ..., "Ethernet24"]
        """
        import re

        interfaces = []
        parts = [p.strip() for p in interfaces_str.split(',')]

        for part in parts:
            if '-' in part and not part.startswith('-'):
                # Range format: swp1-48 or Ethernet1-24
                match = re.match(r'^([a-zA-Z]+)(\d+)-(\d+)$', part)
                if match:
                    prefix = match.group(1)
                    start = int(match.group(2))
                    end = int(match.group(3))

                    if start <= end:
                        for i in range(start, end + 1):
                            interfaces.append(f"{prefix}{i}")
                    else:
                        # Invalid range
                        continue
                else:
                    # Not a valid range, treat as single interface
                    interfaces.append(part)
            else:
                # Single interface
                if part:
                    interfaces.append(part)

        return interfaces

    def clean(self):
        cleaned_data = super().clean()
        scope = cleaned_data.get('deployment_scope')
        devices = cleaned_data.get('devices')
        site = cleaned_data.get('site')
        location = cleaned_data.get('location')
        role = cleaned_data.get('role')
        interfaces_select = cleaned_data.get('interfaces_select', [])
        interfaces_manual = cleaned_data.get('interfaces_manual', '')
        dry_run = cleaned_data.get('dry_run')
        deploy_changes = cleaned_data.get('deploy_changes')

        # Validate deployment mode - must select one and only one
        if dry_run and deploy_changes:
            raise forms.ValidationError(_("Please select either 'Dry Run' OR 'Deploy Changes', not both."))

        if not dry_run and not deploy_changes:
            raise forms.ValidationError(_("Please select either 'Dry Run' (preview) or 'Deploy Changes' (apply)."))

        # Validate based on scope
        if scope == 'single':
            if not devices:
                raise forms.ValidationError(_("Please select at least one device for single device deployment."))
        elif scope == 'group':
            if not site or not location or not role:
                raise forms.ValidationError(_("Please select Site, Location, and Role for group deployment."))

        # Combine checkbox selections and manual entries
        combined_interfaces = list(interfaces_select) if interfaces_select else []

        # Parse manual interfaces (handles ranges like swp1-48) - only if provided
        if interfaces_manual and interfaces_manual.strip():
            manual_list = self._parse_interface_list(interfaces_manual.strip())
            if manual_list:  # Only extend if parsing returned valid interfaces
                combined_interfaces.extend(manual_list)

        # Remove duplicates while preserving order
        combined_interfaces = list(dict.fromkeys(combined_interfaces))

        # Validate that at least one interface is specified (from either field)
        if not combined_interfaces:
            raise forms.ValidationError(_("Please select at least one interface from the checkbox list or enter manually in the text field."))

        # Validate that all interfaces exist on selected devices (only if devices are selected)
        if devices and combined_interfaces:
            self._validate_interfaces_on_devices(devices, combined_interfaces, cleaned_data)

        # Store combined interface list for use in view
        cleaned_data['combined_interfaces'] = combined_interfaces

        return cleaned_data

    def _validate_interfaces_on_devices(self, devices, interface_list, cleaned_data):
        """
        Validate that all specified interfaces exist on all selected devices.
        """
        from dcim.models import Interface

        errors = []

        for device in devices:
            device_interfaces = set(
                Interface.objects.filter(device=device).values_list('name', flat=True)
            )

            for iface_name in interface_list:
                if iface_name not in device_interfaces:
                    errors.append(
                        f"Interface '{iface_name}' does not exist on device '{device.name}'"
                    )

        if errors:
            raise forms.ValidationError(errors)

