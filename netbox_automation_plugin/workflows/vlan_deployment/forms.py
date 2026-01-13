from django import forms
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator
import logging

from dcim.models import Device, Site, Location, DeviceRole, Interface, Manufacturer
from ipam.models import VLAN
from extras.models import Tag

logger = logging.getLogger(__name__)


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

    # Sync NetBox to Device checkbox
    sync_netbox_to_device = forms.BooleanField(
        required=False,
        initial=False,
        label=_("Sync NetBox to Device"),
        help_text=_(
            "When enabled, automatically sync all interface VLAN configurations from NetBox to devices. "
            "All interfaces with VLAN configurations in NetBox will be deployed and auto-tagged."
        ),
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input', 'id': 'id_sync_netbox_to_device'}),
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
        help_text=_("Select one or more devices. Interfaces will be shown grouped by device."),
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

    manufacturer = forms.ModelChoiceField(
        queryset=Manufacturer.objects.all(),
        required=False,
        label=_("Manufacturer"),
        help_text=_("Select manufacturer to filter devices (e.g., Arista for EOS, Mellanox for Cumulus). Prevents mixing incompatible platforms."),
    )

    role = forms.ModelChoiceField(
        queryset=DeviceRole.objects.all(),
        required=False,
        label=_("Device Role"),
        help_text=_("Select device role for group deployment (e.g., Network Leaf)."),
    )

    # Untagged VLAN - IntegerField (simple VLAN ID input)
    untagged_vlan = forms.IntegerField(
        required=False,
        min_value=1,
        max_value=4094,
        label=_("Untagged VLAN ID"),
        help_text=_("Enter untagged VLAN ID (1-4094). Optional if only deploying tagged VLANs."),
        widget=forms.NumberInput(attrs={
            'placeholder': 'e.g., 100',
            'class': 'form-control',
            'id': 'id_untagged_vlan'
        }),
    )

    # Tagged VLANs - CharField for comma-separated VLAN IDs
    tagged_vlans = forms.CharField(
        required=False,
        label=_("Tagged VLAN IDs"),
        help_text=_("Enter tagged VLAN IDs separated by commas (e.g., 100,200,300). Optional if only deploying untagged VLAN."),
        widget=forms.TextInput(attrs={
            'placeholder': 'e.g., 100,200,300',
            'class': 'form-control',
            'id': 'id_tagged_vlans',
            'list': 'tagged_vlans_datalist'
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

    # Excluded devices - Devices to skip during deployment (Group mode only)
    excluded_devices = forms.ModelMultipleChoiceField(
        queryset=Device.objects.all(),
        required=False,
        label=_("Excluded Devices"),
        help_text=_(
            "Optional (Group mode only): Select devices to exclude from the automatically selected group. "
            "Useful when some devices don't have certain interfaces. "
            "For example, if swp64 only exists on device5, exclude devices 1-4 for swp64 deployment."
        ),
        widget=forms.SelectMultiple(attrs={
            'class': 'form-control',
            'data-placeholder': 'Select devices to exclude...'
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
        logger.info(f"[FORM DEBUG] clean_interfaces_select: Got {len(interfaces)} interfaces from form data")
        logger.info(f"[FORM DEBUG] Interfaces: {interfaces}")
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
        sync_netbox_to_device = cleaned_data.get('sync_netbox_to_device', False)

        # Validate deployment mode - must select one and only one
        if dry_run and deploy_changes:
            # Wrap in list to prevent Django from trying to format the string
            raise forms.ValidationError([_("Please select either 'Dry Run' OR 'Deploy Changes', not both.")])

        if not dry_run and not deploy_changes:
            # Wrap in list to prevent Django from trying to format the string
            raise forms.ValidationError([_("Please select either 'Dry Run' (preview) or 'Deploy Changes' (apply).")])

        # Sync mode validation
        if sync_netbox_to_device:
            # In sync mode, VLAN fields are not required (read from NetBox)
            if 'untagged_vlan' in self.errors:
                del self.errors['untagged_vlan']
            if 'tagged_vlans' in self.errors:
                del self.errors['tagged_vlans']
            # Additional interfaces field is not used in sync mode
            if interfaces_manual and interfaces_manual.strip():
                # Wrap in list to prevent Django from trying to format the string
                raise forms.ValidationError([_("Additional interfaces field is not available in sync mode. Interfaces are auto-discovered from NetBox.")])
        
        # Normal mode validation: At least one VLAN (untagged or tagged) must be provided
        if not sync_netbox_to_device:
            untagged_vlan = cleaned_data.get('untagged_vlan')
            tagged_vlans_str = cleaned_data.get('tagged_vlans', '').strip()
            
            if not untagged_vlan and not tagged_vlans_str:
                # Wrap in list to prevent Django from trying to format the string
                raise forms.ValidationError([_("Please provide at least one VLAN (untagged or tagged) for deployment.")])
            
            # Validate tagged_vlans format (comma-separated integers)
            if tagged_vlans_str:
                try:
                    tagged_list = [int(x.strip()) for x in tagged_vlans_str.split(',') if x.strip()]
                    for vlan_id in tagged_list:
                        if vlan_id < 1 or vlan_id > 4094:
                            raise forms.ValidationError([_("Tagged VLAN IDs must be between 1 and 4094.")])
                    cleaned_data['tagged_vlans_parsed'] = tagged_list
                except ValueError:
                    raise forms.ValidationError([_("Tagged VLANs must be comma-separated integers (e.g., 100,200,300).")])

        # Validate based on scope
        if scope == 'single':
            if not devices:
                # Wrap in list to prevent Django from trying to format the string
                raise forms.ValidationError([_("Please select at least one device for single device deployment.")])
        elif scope == 'group':
            if not site or not location or not role:
                # Wrap in list to prevent Django from trying to format the string
                raise forms.ValidationError([_("Please select Site, Location, and Role for group deployment.")])
            if not cleaned_data.get('manufacturer'):
                # Wrap in list to prevent Django from trying to format the string
                raise forms.ValidationError([_("Please select Manufacturer for group deployment to prevent mixing incompatible platforms (e.g., EOS and Cumulus).")])

        # Combine checkbox selections and manual entries
        combined_interfaces = list(interfaces_select) if interfaces_select else []
        logger.info(f"[FORM DEBUG] After combining checkbox selections: {len(combined_interfaces)} interfaces")
        logger.info(f"[FORM DEBUG] Combined interfaces: {combined_interfaces}")

        # Parse manual interfaces (handles ranges like swp1-48) - only if provided and not in sync mode
        if not sync_netbox_to_device and interfaces_manual and interfaces_manual.strip():
            manual_list = self._parse_interface_list(interfaces_manual.strip())
            if manual_list:  # Only extend if parsing returned valid interfaces
                combined_interfaces.extend(manual_list)

        # Remove duplicates while preserving order
        combined_interfaces = list(dict.fromkeys(combined_interfaces))
        logger.info(f"[FORM DEBUG] Final combined_interfaces: {len(combined_interfaces)} interfaces")
        logger.info(f"[FORM DEBUG] Final list: {combined_interfaces}")

        # Validate that at least one interface is specified
        if not combined_interfaces:
            logger.warning(f"[FORM DEBUG] No interfaces found! sync_mode={sync_netbox_to_device}, interfaces_select={interfaces_select}, interfaces_manual={interfaces_manual}")
            if sync_netbox_to_device:
                # Wrap in list to prevent Django from trying to format the string
                raise forms.ValidationError([_("In sync mode, at least one interface must be selected for sync.")])
            else:
                # Wrap in list to prevent Django from trying to format the string
                raise forms.ValidationError([_("Please select at least one interface from the checkbox list or enter manually in the text field.")])

        # Validate that all interfaces exist on selected devices (only if devices are selected)
        # In sync mode, interfaces are in "device:interface" format, so skip this validation
        if devices and combined_interfaces and not sync_netbox_to_device:
            self._validate_interfaces_on_devices(devices, combined_interfaces, cleaned_data)
            
            # Validate tags and interface eligibility
            # For actual deployment: block on errors
            # For dry run: show warnings but don't block (validation shown in dry run results)
            if deploy_changes:
                self._validate_tags_and_interfaces(devices, combined_interfaces, cleaned_data, blocking=True)
            elif dry_run:
                # Dry run: validate but only show warnings, don't block
                self._validate_tags_and_interfaces(devices, combined_interfaces, cleaned_data, blocking=False)

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
                        "Interface '" + iface_name + "' does not exist on device '" + device.name + "'"
                    )

        if errors:
            # Pass as a list to ValidationError to prevent string formatting issues
            # Django will handle the list properly without trying to format it
            raise forms.ValidationError(errors)
    
    def _validate_tags_and_interfaces(self, devices, interface_list, cleaned_data, blocking=True):
        """
        Validate device and interface tags before deployment.
        Implements pre-validation checks from TAGGING_WORKFLOW_CRITERIA.md.
        
        Args:
            blocking: If True, raise ValidationError on blocking issues. If False, only collect warnings.
        
        Blocking errors (must fix):
        - Device not tagged as automation-ready:vlan
        - Interface tagged as vlan-mode:uplink
        - Interface tagged as vlan-mode:routed
        - Interface is port-channel member
        - Interface not cabled
        - Connected device status is offline/decommissioning
        
        Warnings (can proceed with confirmation):
        - Interface tagged as vlan-mode:needs-review
        - Interface not tagged but passes other checks
        """
        from extras.models import Tag
        
        blocking_errors = []
        warnings = []
        
        # Get tags
        try:
            device_tag = Tag.objects.get(name='automation-ready:vlan')
        except Tag.DoesNotExist:
            device_tag = None
        
        interface_tag_names = {
            'uplink': 'vlan-mode:uplink',
            'routed': 'vlan-mode:routed',
            'needs-review': 'vlan-mode:needs-review',
            'access': 'vlan-mode:access',
        }
        interface_tags = {}
        for key, tag_name in interface_tag_names.items():
            try:
                interface_tags[key] = Tag.objects.get(name=tag_name)
            except Tag.DoesNotExist:
                interface_tags[key] = None
        
        # Validate each device
        for device in devices:
            device.refresh_from_db()
            device_tags = list(device.tags.all())
            
            # Check device tag (BLOCKING)
            if device_tag and device_tag not in device_tags:
                blocking_errors.append(
                    "Device '" + device.name + "' is not tagged as 'automation-ready:vlan'. "
                    "Please run the Tagging Workflow first to tag this device."
                )
            
            # Validate each interface on this device
            for iface_name in interface_list:
                try:
                    interface = Interface.objects.get(device=device, name=iface_name)
                    interface.refresh_from_db()
                    interface_tag_list = list(interface.tags.all())
                    interface_tag_names_list = [t.name for t in interface_tag_list]
                    
                    # CRITICAL CHECK: Interface with IP address is a routed port (BLOCKING)
                    # This must be checked BEFORE tag checks, as IP address is a stronger signal
                    if interface.ip_addresses.exists():
                        blocking_errors.append(
                            "Interface '" + iface_name + "' on device '" + device.name + "' has IP address configured (routed port) - cannot apply VLAN configuration to routed interfaces."
                        )
                        continue  # Skip further checks for this interface

                    # Check for blocking tags (BLOCKING)
                    if interface_tags.get('uplink') and interface_tags['uplink'].name in interface_tag_names_list:
                        blocking_errors.append(
                            "Interface '" + iface_name + "' on device '" + device.name + "' is marked as 'vlan-mode:uplink' - cannot modify uplink interfaces."
                        )
                        continue  # Skip further checks for this interface

                    if interface_tags.get('routed') and interface_tags['routed'].name in interface_tag_names_list:
                        blocking_errors.append(
                            "Interface '" + iface_name + "' on device '" + device.name + "' is marked as 'vlan-mode:routed' - cannot modify routed interfaces."
                        )
                        continue  # Skip further checks for this interface
                    
                    # Check for port-channel membership (BLOCKING)
                    if hasattr(interface, 'lag') and interface.lag:
                        blocking_errors.append(
                            "Interface '" + iface_name + "' on device '" + device.name + "' is a port-channel member - configure on port-channel '" + interface.lag.name + "' instead."
                        )
                        continue  # Skip further checks for this interface

                    # Check if cabled (BLOCKING)
                    # EXCEPTION: Bond interfaces (LAG/port-channel) don't need to be cabled in normal mode
                    # Bonds are logical interfaces - cables are on member interfaces, not bonds
                    from dcim.choices import InterfaceTypeChoices
                    is_bond_interface = interface.type == InterfaceTypeChoices.TYPE_LAG
                    
                    if not interface.cable and not is_bond_interface:
                        blocking_errors.append(
                            "Interface '" + iface_name + "' on device '" + device.name + "' is not cabled in NetBox - please add cable information first."
                        )
                        continue  # Skip further checks for this interface
                    
                    # Check connected device status (BLOCKING)
                    try:
                        endpoints = interface.connected_endpoints
                        if endpoints:
                            endpoint = endpoints[0]
                            connected_device = endpoint.device
                            if connected_device.status in ['offline', 'decommissioning']:
                                blocking_errors.append(
                                    "Interface '" + iface_name + "' on device '" + device.name + "' is connected to device '" + connected_device.name + "' "
                                    "with status '" + str(connected_device.status) + "' - cannot configure VLAN."
                                )
                                continue  # Skip further checks for this interface
                    except Exception as e:
                        # If we can't get endpoints, log but don't block (cable exists)
                        import logging
                        logger = logging.getLogger('netbox_automation_plugin')
                        logger.warning("Could not get connected endpoints for " + device.name + ":" + iface_name + ": " + str(e))
                    
                    # Check for warning conditions
                    if interface_tags.get('needs-review') and interface_tags['needs-review'].name in interface_tag_names_list:
                        warnings.append(
                            "Interface '" + iface_name + "' on device '" + device.name + "' is marked as 'vlan-mode:needs-review' - "
                            "please review in Tagging Workflow first. Proceeding anyway."
                        )
                    elif interface_tags.get('access') and interface_tags['access'].name not in interface_tag_names_list:
                        # Interface is not tagged as access-ready but passes other checks
                        warnings.append(
                            "Interface '" + iface_name + "' on device '" + device.name + "' is not tagged as 'vlan-mode:access' - "
                            "may have conflicts. Consider running Tagging Workflow to tag this interface."
                        )

                except Interface.DoesNotExist:
                    # Interface doesn't exist - this should have been caught earlier, but handle gracefully
                    blocking_errors.append(
                        "Interface '" + iface_name + "' does not exist on device '" + device.name + "'"
                    )
        
        # Raise blocking errors if any (only if blocking=True)
        if blocking_errors and blocking:
            # Build error messages as a list to prevent Django from trying to format them
            # This avoids "unexpected '{' in field name" errors
            error_messages = ["The following issues must be resolved before deployment:"]
            error_messages.extend("• " + str(err) for err in blocking_errors)
            if warnings:
                error_messages.append("")
                error_messages.append("Warnings:")
                error_messages.extend("⚠ " + str(warn) for warn in warnings)
            # Pass as a list to ValidationError to prevent string formatting
            raise forms.ValidationError(error_messages)
        
        # Store warnings and blocking errors for display (for dry run mode)
        if warnings or (blocking_errors and not blocking):
            cleaned_data['_tagging_warnings'] = warnings
            if blocking_errors and not blocking:
                # In dry run, store blocking errors as warnings
                cleaned_data['_tagging_blocking_errors'] = blocking_errors

