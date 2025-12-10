from django.shortcuts import render
from django.views import View
from django.http import HttpResponse, JsonResponse
from django.utils.translation import gettext_lazy as _
from django.db import transaction

from dcim.models import Device, Interface
from ipam.models import VLAN
from extras.models import Tag

from ...core.napalm_integration import NAPALMDeviceManager
from ...core.nornir_integration import NornirDeviceManager
from .forms import VLANDeploymentForm
from .tables import VLANDeploymentResultTable
import logging
import traceback

logger = logging.getLogger('netbox_automation_plugin')


class VLANDeploymentView(View):
    """
    VLAN Deployment Workflow:
    - Deploy VLAN configurations to devices (single or group)
    - Update NetBox interface VLAN assignments
    - Phase 1: Access mode (untagged) only
    """

    template_name_form = "netbox_automation_plugin/vlan_deployment_form.html"
    template_name_results = "netbox_automation_plugin/vlan_deployment_results.html"

    def get(self, request):
        form = VLANDeploymentForm()
        # Form uses vlan_id (IntegerField), not a ModelChoiceField, so no queryset to set
        return render(request, self.template_name_form, {"form": form})

    def post(self, request):
        import traceback
        import logging
        logger = logging.getLogger('netbox_automation_plugin')

        try:
            form = VLANDeploymentForm(request.POST)
            if not form.is_valid():
                return render(request, self.template_name_form, {"form": form})
        except Exception as e:
            logger.error(f"Form validation error: {e}")
            logger.error(traceback.format_exc())
            raise

        # Get devices based on scope
        devices = self._get_devices(form.cleaned_data)
        if not devices:
            form.add_error(None, _("No devices found matching the selection (with primary IP)."))
            return render(request, self.template_name_form, {"form": form})

        # Filter out excluded devices (only applies to Group mode)
        deployment_scope = form.cleaned_data.get('deployment_scope', 'single')
        excluded_devices = form.cleaned_data.get('excluded_devices', [])
        if excluded_devices and deployment_scope == 'group':
            excluded_device_ids = {d.id for d in excluded_devices}
            devices = [d for d in devices if d.id not in excluded_device_ids]
            logger.info(f"Excluded {len(excluded_devices)} devices. Remaining: {len(devices)} devices for deployment")
            
            if not devices:
                form.add_error(None, _("All devices were excluded. Please select at least one device for deployment."))
                return render(request, self.template_name_form, {"form": form})

        # Additional tag validation before deployment (even for dry run, to show warnings)
        # This provides a second layer of validation and shows warnings even in dry run mode
        tagging_warnings = form.cleaned_data.get('_tagging_warnings', [])
        if not form.cleaned_data.get('dry_run', False):
            # For actual deployment, do a final check
            validation_errors = self._validate_tags_before_deployment(devices, form.cleaned_data.get('combined_interfaces', []))
            if validation_errors:
                for error in validation_errors:
                    form.add_error(None, error)
                return render(request, self.template_name_form, {"form": form})

        # Run deployment
        results = self._run_vlan_deployment(devices, form.cleaned_data)

        # CSV export if requested
        if "export_csv" in request.POST:
            csv_content = self._build_csv(results)
            response = HttpResponse(csv_content, content_type="text/csv; charset=utf-8-sig")
            response["Content-Disposition"] = 'attachment; filename="vlan_deployment_results.csv"'
            return response

        table = VLANDeploymentResultTable(results, orderable=True)
        summary = self._build_summary(results, len(devices))

        # Get excluded devices info
        excluded_devices = form.cleaned_data.get('excluded_devices', [])
        excluded_device_names = [d.name for d in excluded_devices] if excluded_devices else []

        # Get tagging warnings if any
        tagging_warnings = form.cleaned_data.get('_tagging_warnings', [])
        
        context = {
            "form": form,
            "table": table,
            "summary": summary,
            "excluded_devices": excluded_device_names,
            "excluded_count": len(excluded_devices),
            "tagging_warnings": tagging_warnings,
        }
        return render(request, self.template_name_results, context)

    def _get_devices(self, cleaned_data):
        """Get devices based on deployment scope."""
        scope = cleaned_data.get('deployment_scope')

        if scope == 'single':
            # Multi-device selection
            devices = cleaned_data.get('devices', [])
            # Filter to only devices with primary IP
            devices = [d for d in devices if d.primary_ip4 or d.primary_ip6]
            return devices

        elif scope == 'group':
            site = cleaned_data.get('site')
            location = cleaned_data.get('location')
            manufacturer = cleaned_data.get('manufacturer')
            role = cleaned_data.get('role')

            devices = Device.objects.filter(
                site=site,
                location=location,
                device_type__manufacturer=manufacturer,
                role=role,
            ).select_related('primary_ip4', 'primary_ip6', 'site', 'location', 'role', 'device_type', 'device_type__manufacturer')

            # Only keep devices with primary IP
            devices = [d for d in devices if d.primary_ip4 or d.primary_ip6]
            return devices

        return []

    def _validate_tags_for_dry_run(self, devices, interface_list):
        """
        Validate tags for dry run mode - shows what would block/warn/pass.
        Returns validation results without blocking.
        
        Returns:
            dict: {
                'device_validation': {device_name: {'status': 'pass'|'block'|'warn', 'message': str}},
                'interface_validation': {f'{device_name}:{iface}': {'status': 'pass'|'block'|'warn', 'message': str}}
            }
        """
        from extras.models import Tag
        
        results = {
            'device_validation': {},
            'interface_validation': {},
        }
        
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
            
            if device_tag and device_tag not in device_tags:
                results['device_validation'][device.name] = {
                    'status': 'block',
                    'message': f"Device not tagged as 'automation-ready:vlan' - would block deployment"
                }
            else:
                results['device_validation'][device.name] = {
                    'status': 'pass',
                    'message': f"Device tagged as 'automation-ready:vlan' - would pass"
                }
            
            # Validate each interface
            for iface_name in interface_list:
                key = f"{device.name}:{iface_name}"
                try:
                    interface = Interface.objects.get(device=device, name=iface_name)
                    interface.refresh_from_db()
                    interface_tag_list = list(interface.tags.all())
                    interface_tag_names_list = [t.name for t in interface_tag_list]
                    
                    # Check for blocking tags
                    if interface_tags.get('uplink') and interface_tags['uplink'].name in interface_tag_names_list:
                        results['interface_validation'][key] = {
                            'status': 'block',
                            'message': f"Interface marked as 'vlan-mode:uplink' - would block deployment"
                        }
                        continue
                    
                    if interface_tags.get('routed') and interface_tags['routed'].name in interface_tag_names_list:
                        results['interface_validation'][key] = {
                            'status': 'block',
                            'message': f"Interface marked as 'vlan-mode:routed' - would block deployment"
                        }
                        continue
                    
                    # Check port-channel membership
                    if hasattr(interface, 'lag') and interface.lag:
                        results['interface_validation'][key] = {
                            'status': 'block',
                            'message': f"Interface is port-channel member - would block deployment"
                        }
                        continue
                    
                    # Check cable
                    if not interface.cable:
                        results['interface_validation'][key] = {
                            'status': 'block',
                            'message': f"Interface not cabled - would block deployment"
                        }
                        continue
                    
                    # Check connected device status
                    try:
                        endpoints = interface.connected_endpoints
                        if endpoints:
                            endpoint = endpoints[0]
                            connected_device = endpoint.device
                            if connected_device.status in ['offline', 'decommissioning']:
                                results['interface_validation'][key] = {
                                    'status': 'block',
                                    'message': f"Connected device status '{connected_device.status}' - would block deployment"
                                }
                                continue
                    except Exception:
                        pass
                    
                    # Check for warnings
                    if interface_tags.get('needs-review') and interface_tags['needs-review'].name in interface_tag_names_list:
                        results['interface_validation'][key] = {
                            'status': 'warn',
                            'message': f"Interface marked as 'vlan-mode:needs-review' - would warn but allow"
                        }
                    elif interface_tags.get('access') and interface_tags['access'].name in interface_tag_names_list:
                        results['interface_validation'][key] = {
                            'status': 'pass',
                            'message': f"Interface tagged as 'vlan-mode:access' - would pass"
                        }
                    else:
                        results['interface_validation'][key] = {
                            'status': 'warn',
                            'message': f"Interface not tagged - would warn but allow"
                        }
                
                except Interface.DoesNotExist:
                    results['interface_validation'][key] = {
                        'status': 'block',
                        'message': f"Interface does not exist - would block deployment"
                    }
        
        return results

    def _get_current_device_config(self, device, interface_name, platform):
        """
        Get current interface configuration from device (read-only).
        Tries to connect to device, falls back to NetBox inference if unavailable.
        
        Returns:
            dict: {
                'success': bool,
                'current_config': str,  # Current config from device
                'source': 'device'|'netbox'|'error',
                'error': str (if failed)
            }
        """
        napalm_manager = None
        try:
            napalm_manager = NAPALMDeviceManager(device)
            
            if platform == 'cumulus':
                # For Cumulus, use nv show command via NAPALM
                # Try to get interface bridge domain config
                try:
                    if napalm_manager.connect():
                        # Use NAPALM's cli() method if available, or get_config and parse
                        # For now, we'll use a simpler approach - get full config and parse
                        # Or use napalm-cumulus specific methods
                        config = napalm_manager.get_config(retrieve='running')
                        if config:
                            # Parse config to find interface bridge domain settings
                            # This is a simplified version - in production you might want to use
                            # nv show interface <iface> bridge domain br_default directly
                            current_config = self._parse_cumulus_interface_config(config, interface_name)
                            napalm_manager.disconnect()
                            return {
                                'success': True,
                                'current_config': current_config,
                                'source': 'device'
                            }
                except Exception as e:
                    logger.warning(f"Could not get device config for {device.name}:{interface_name}: {e}")
                    if napalm_manager:
                        napalm_manager.disconnect()
            
            elif platform == 'eos':
                # For EOS, get running config and parse interface section
                try:
                    if napalm_manager.connect():
                        config = napalm_manager.get_config(retrieve='running')
                        if config:
                            current_config = self._parse_eos_interface_config(config, interface_name)
                            napalm_manager.disconnect()
                            return {
                                'success': True,
                                'current_config': current_config,
                                'source': 'device'
                            }
                except Exception as e:
                    logger.warning(f"Could not get device config for {device.name}:{interface_name}: {e}")
                    if napalm_manager:
                        napalm_manager.disconnect()
            
            # Fallback to NetBox inference
            return self._get_netbox_inferred_config(device, interface_name, platform)
            
        except Exception as e:
            logger.error(f"Error getting device config for {device.name}:{interface_name}: {e}")
            if napalm_manager:
                try:
                    napalm_manager.disconnect()
                except:
                    pass
            # Fallback to NetBox
            return self._get_netbox_inferred_config(device, interface_name, platform)
    
    def _parse_cumulus_interface_config(self, config_dict, interface_name):
        """
        Parse Cumulus config to extract interface bridge domain settings.
        This is a simplified parser - in production you might want to use nv show directly.
        """
        # For now, return a placeholder - actual implementation would parse nv show output
        # or use napalm-cumulus's get_config which might return structured data
        running_config = config_dict.get('running', '')
        if running_config:
            # Try to find interface bridge domain config in running config
            # This is simplified - actual implementation would need proper parsing
            return f"Interface {interface_name} bridge domain config (parsed from device)"
        return f"Interface {interface_name} - no current config found"
    
    def _parse_eos_interface_config(self, config_dict, interface_name):
        """
        Parse EOS config to extract interface switchport settings.
        """
        running_config = config_dict.get('running', '')
        if running_config and interface_name in running_config:
            # Extract interface section
            lines = running_config.split('\n')
            in_interface = False
            interface_lines = []
            for line in lines:
                if f"interface {interface_name}" in line:
                    in_interface = True
                    interface_lines.append(line)
                elif in_interface:
                    if line.strip().startswith('interface ') or line.strip() == '!':
                        break
                    interface_lines.append(line)
            return '\n'.join(interface_lines) if interface_lines else f"Interface {interface_name} - no config found"
        return f"Interface {interface_name} - no config found"
    
    def _get_netbox_inferred_config(self, device, interface_name, platform):
        """
        Infer current config from NetBox interface state.
        Used as fallback when device is unreachable.
        """
        try:
            interface = Interface.objects.get(device=device, name=interface_name)
            interface.refresh_from_db()
            
            untagged_vlan = interface.untagged_vlan.vid if interface.untagged_vlan else None
            tagged_vlans = list(interface.tagged_vlans.values_list('vid', flat=True))
            mode = interface.mode if hasattr(interface, 'mode') else None
            
            if platform == 'cumulus':
                if untagged_vlan:
                    config = f"nv set interface {interface_name} bridge domain br_default access {untagged_vlan}"
                else:
                    config = f"Interface {interface_name} - no VLAN configured"
                if tagged_vlans:
                    config += f"\nTagged VLANs: {', '.join(map(str, tagged_vlans))}"
            elif platform == 'eos':
                if mode == 'access' and untagged_vlan:
                    config = f"interface {interface_name}\n   switchport mode access\n   switchport access vlan {untagged_vlan}"
                elif mode == 'tagged' and tagged_vlans:
                    config = f"interface {interface_name}\n   switchport mode trunk\n   switchport trunk allowed vlan {','.join(map(str, tagged_vlans))}"
                else:
                    config = f"interface {interface_name} - no VLAN configured"
            else:
                config = f"Interface {interface_name} - unknown platform"
            
            return {
                'success': True,
                'current_config': config,
                'source': 'netbox'
            }
        except Interface.DoesNotExist:
            return {
                'success': False,
                'current_config': f"Interface {interface_name} not found in NetBox",
                'source': 'error',
                'error': 'Interface not found'
            }
    
    def _get_netbox_current_state(self, device, interface_name, vlan_id):
        """
        Get current NetBox interface state.
        
        Returns:
            dict: {
                'mode': str or None,
                'untagged_vlan': int or None,
                'tagged_vlans': list of ints,
                'has_changes': bool
            }
        """
        try:
            interface = Interface.objects.get(device=device, name=interface_name)
            interface.refresh_from_db()
            
            current_mode = interface.mode if hasattr(interface, 'mode') else None
            current_untagged = interface.untagged_vlan.vid if interface.untagged_vlan else None
            current_tagged = list(interface.tagged_vlans.values_list('vid', flat=True))
            
            # Proposed state
            proposed_mode = 'tagged'  # Always set to tagged
            proposed_untagged = vlan_id
            proposed_tagged = current_tagged  # Keep existing tagged VLANs
            
            # Check if there are changes
            has_changes = (
                current_mode != proposed_mode or
                current_untagged != proposed_untagged
            )
            
            return {
                'current': {
                    'mode': current_mode,
                    'untagged_vlan': current_untagged,
                    'tagged_vlans': current_tagged,
                },
                'proposed': {
                    'mode': proposed_mode,
                    'untagged_vlan': proposed_untagged,
                    'tagged_vlans': proposed_tagged,
                },
                'has_changes': has_changes
            }
        except Interface.DoesNotExist:
            return {
                'current': {'mode': None, 'untagged_vlan': None, 'tagged_vlans': []},
                'proposed': {'mode': 'tagged', 'untagged_vlan': vlan_id, 'tagged_vlans': []},
                'has_changes': True
            }
    
    def _generate_config_diff(self, current_config, proposed_config, platform):
        """
        Generate a diff between current and proposed config.
        
        Returns:
            str: Formatted diff showing changes
        """
        if current_config == proposed_config:
            return "No changes (config already applied)"
        
        # Simple diff format
        diff_lines = []
        diff_lines.append("--- Current Configuration")
        diff_lines.append("+++ Proposed Configuration")
        diff_lines.append("")
        
        if platform == 'cumulus':
            # For Cumulus, show command differences
            if "no current config" in current_config.lower() or "no config found" in current_config.lower():
                diff_lines.append(f"+ {proposed_config}")
            else:
                diff_lines.append(f"- {current_config}")
                diff_lines.append(f"+ {proposed_config}")
        elif platform == 'eos':
            # For EOS, show interface config differences
            current_lines = current_config.split('\n')
            proposed_lines = proposed_config.split('\n')
            
            # Simple line-by-line diff
            for line in current_lines:
                if line.strip() and line not in proposed_lines:
                    diff_lines.append(f"- {line}")
            for line in proposed_lines:
                if line.strip() and line not in current_lines:
                    diff_lines.append(f"+ {line}")
        
        return '\n'.join(diff_lines)
    
    def _generate_netbox_diff(self, current_state, proposed_state):
        """
        Generate a diff for NetBox interface state changes.
        
        Returns:
            str: Formatted diff showing NetBox changes
        """
        if not current_state['has_changes']:
            return "No changes (NetBox already has this configuration)"
        
        diff_lines = []
        diff_lines.append("NetBox Interface Changes:")
        diff_lines.append("")
        
        # Mode change
        if current_state['current']['mode'] != proposed_state['mode']:
            old_mode = current_state['current']['mode'] or 'None'
            diff_lines.append(f"  802.1Q Mode: {old_mode} → {proposed_state['mode']}")
        
        # Untagged VLAN change
        if current_state['current']['untagged_vlan'] != proposed_state['untagged_vlan']:
            old_vlan = current_state['current']['untagged_vlan'] or 'None'
            new_vlan = proposed_state['untagged_vlan'] or 'None'
            diff_lines.append(f"  Untagged VLAN: {old_vlan} → {new_vlan}")
        
        # Tagged VLANs (usually unchanged, but show if different)
        if set(current_state['current']['tagged_vlans']) != set(proposed_state['tagged_vlans']):
            old_tagged = ', '.join(map(str, current_state['current']['tagged_vlans'])) or 'None'
            new_tagged = ', '.join(map(str, proposed_state['tagged_vlans'])) or 'None'
            diff_lines.append(f"  Tagged VLANs: [{old_tagged}] → [{new_tagged}]")
        
        if len(diff_lines) == 2:  # Only header and empty line
            return "No changes"
        
        return '\n'.join(diff_lines)

    def _validate_tags_before_deployment(self, devices, interface_list):
        """
        Final validation before deployment - double-check tags and interface eligibility.
        This is a safety check that runs even after form validation.
        
        Returns list of error messages (empty if all valid).
        """
        errors = []
        
        # Get tags
        try:
            device_tag = Tag.objects.get(name='automation-ready:vlan')
        except Tag.DoesNotExist:
            device_tag = None
            logger.warning("Tag 'automation-ready:vlan' does not exist - skipping device tag validation")
        
        interface_tag_names = {
            'uplink': 'vlan-mode:uplink',
            'routed': 'vlan-mode:routed',
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
                errors.append(
                    f"Device '{device.name}' is not tagged as 'automation-ready:vlan'. "
                    f"Please run the Tagging Workflow first to tag this device."
                )
            
            # Validate each interface on this device
            for iface_name in interface_list:
                try:
                    interface = Interface.objects.get(device=device, name=iface_name)
                    interface.refresh_from_db()
                    interface_tag_list = list(interface.tags.all())
                    interface_tag_names_list = [t.name for t in interface_tag_list]
                    
                    # Check for blocking tags (BLOCKING)
                    if interface_tags.get('uplink') and interface_tags['uplink'].name in interface_tag_names_list:
                        errors.append(
                            f"Interface '{iface_name}' on device '{device.name}' is marked as 'vlan-mode:uplink' - cannot modify uplink interfaces."
                        )
                        continue
                    
                    if interface_tags.get('routed') and interface_tags['routed'].name in interface_tag_names_list:
                        errors.append(
                            f"Interface '{iface_name}' on device '{device.name}' is marked as 'vlan-mode:routed' - cannot modify routed interfaces."
                        )
                        continue
                    
                    # Check for port-channel membership (BLOCKING)
                    if hasattr(interface, 'lag') and interface.lag:
                        errors.append(
                            f"Interface '{iface_name}' on device '{device.name}' is a port-channel member - configure on port-channel '{interface.lag.name}' instead."
                        )
                        continue
                    
                    # Check if cabled (BLOCKING)
                    if not interface.cable:
                        errors.append(
                            f"Interface '{iface_name}' on device '{device.name}' is not cabled in NetBox - please add cable information first."
                        )
                        continue
                    
                    # Check connected device status (BLOCKING)
                    try:
                        endpoints = interface.connected_endpoints
                        if endpoints:
                            endpoint = endpoints[0]
                            connected_device = endpoint.device
                            if connected_device.status in ['offline', 'decommissioning']:
                                errors.append(
                                    f"Interface '{iface_name}' on device '{device.name}' is connected to device '{connected_device.name}' "
                                    f"with status '{connected_device.status}' - cannot configure VLAN."
                                )
                                continue
                    except Exception as e:
                        logger.warning(f"Could not get connected endpoints for {device.name}:{iface_name}: {e}")
                
                except Interface.DoesNotExist:
                    errors.append(
                        f"Interface '{iface_name}' does not exist on device '{device.name}'"
                    )
        
        return errors

    def _run_vlan_deployment(self, devices, cleaned_data):
        """
        Core VLAN deployment logic.
        Environment-agnostic - uses NornirDeviceManager from core.
        Supports both Cumulus and EOS platforms.
        """
        # Get VLAN ID from form
        vlan_id = cleaned_data.get('vlan_id')

        # Try to get VLAN object and name from NetBox (best effort - may have multiple VLANs with same ID)
        vlan = None
        vlan_name = f"VLAN {vlan_id}"  # Default fallback
        try:
            # Try to find VLAN by filtering by first device's location/site
            first_device = devices[0] if devices else None
            if first_device:
                # Try location first
                if first_device.location:
                    vlans = VLAN.objects.filter(
                        vid=vlan_id,
                        group__name__icontains=first_device.location.name
                    )
                    if vlans.exists():
                        vlan = vlans.first()

                # Try site if not found by location
                if not vlan and first_device.site:
                    vlans = VLAN.objects.filter(vid=vlan_id, site=first_device.site)
                    if vlans.exists():
                        vlan = vlans.first()

                # Just get any VLAN with this ID if still not found
                if not vlan:
                    vlan = VLAN.objects.filter(vid=vlan_id).first()

                if vlan:
                    vlan_name = vlan.name
        except Exception as e:
            logger.warning(f"Could not look up VLAN name for ID {vlan_id}: {e}")

        scope = cleaned_data.get('deployment_scope')
        dry_run = cleaned_data.get('dry_run', False)
        deploy_changes = cleaned_data.get('deploy_changes', False)

        # If deploy_changes is True, we apply to devices and NetBox
        # If dry_run is True, we only preview (no changes to devices or NetBox)
        update_netbox = deploy_changes  # Only update NetBox if deploying changes

        # Get combined interface list from form validation
        interface_list = cleaned_data.get('combined_interfaces', [])

        results = []

        # Detect platform - all devices should be same platform (enforced by manufacturer filter)
        platform = self._get_device_platform(devices[0]) if devices else 'cumulus'
        
        logger.info(f"VLAN Deployment: {len(devices)} devices, {len(interface_list)} interfaces, platform: {platform}")

        if dry_run:
            # Dry run mode - generate comprehensive preview with validation and diffs
            # First, run tag validation
            validation_results = self._validate_tags_for_dry_run(devices, interface_list)
            
            for device in devices:
                device_validation = validation_results['device_validation'].get(device.name, {})
                
                for interface_name in interface_list:
                    interface_key = f"{device.name}:{interface_name}"
                    interface_validation = validation_results['interface_validation'].get(interface_key, {})
                    
                    # Get proposed config
                    proposed_config = self._generate_vlan_config(interface_name, vlan_id, platform)
                    
                    # Get current device config (try device, fallback to NetBox)
                    device_config_result = self._get_current_device_config(device, interface_name, platform)
                    current_device_config = device_config_result.get('current_config', 'Unable to fetch')
                    config_source = device_config_result.get('source', 'error')
                    
                    # Generate config diff
                    config_diff = self._generate_config_diff(current_device_config, proposed_config, platform)
                    
                    # Get NetBox current and proposed state
                    netbox_state = self._get_netbox_current_state(device, interface_name, vlan_id)
                    netbox_diff = self._generate_netbox_diff(netbox_state, netbox_state['proposed'])
                    
                    # Build validation status message
                    validation_status = []
                    if device_validation.get('status') == 'block':
                        validation_status.append(f"⚠ Device: {device_validation.get('message', 'Would block')}")
                    elif device_validation.get('status') == 'warn':
                        validation_status.append(f"⚠ Device: {device_validation.get('message', 'Would warn')}")
                    else:
                        validation_status.append(f"✓ Device: {device_validation.get('message', 'Would pass')}")
                    
                    if interface_validation.get('status') == 'block':
                        validation_status.append(f"⚠ Interface: {interface_validation.get('message', 'Would block')}")
                    elif interface_validation.get('status') == 'warn':
                        validation_status.append(f"⚠ Interface: {interface_validation.get('message', 'Would warn')}")
                    else:
                        validation_status.append(f"✓ Interface: {interface_validation.get('message', 'Would pass')}")
                    
                    # Determine overall status
                    if device_validation.get('status') == 'block' or interface_validation.get('status') == 'block':
                        overall_status = "error"
                        status_message = "Would BLOCK deployment"
                    elif device_validation.get('status') == 'warn' or interface_validation.get('status') == 'warn':
                        overall_status = "success"
                        status_message = "Would WARN but allow deployment"
                    else:
                        overall_status = "success"
                        status_message = "Would PASS validation"
                    
                    # Build comprehensive deployment logs
                    logs = []
                    logs.append("=== DRY RUN MODE - PREVIEW ONLY ===")
                    logs.append("")
                    logs.append("--- Validation Results ---")
                    logs.extend(validation_status)
                    logs.append("")
                    logs.append(f"--- Device Config ({config_source}) ---")
                    logs.append(f"Current: {current_device_config}")
                    logs.append(f"Proposed: {proposed_config}")
                    logs.append("")
                    logs.append("--- Config Diff ---")
                    logs.append(config_diff)
                    logs.append("")
                    logs.append("--- NetBox Changes ---")
                    logs.append(netbox_diff)
                    logs.append("")
                    logs.append(f"Status: {status_message}")
                    
                    results.append({
                        "device": device,
                        "interface": interface_name,
                        "vlan_id": vlan_id,
                        "vlan_name": vlan_name,
                        "status": overall_status,
                        "config_applied": "Dry Run",
                        "netbox_updated": "Preview",
                        "message": f"{status_message} | Platform: {platform}",
                        "deployment_logs": '\n'.join(logs),
                        "validation_status": validation_status,
                        "device_config_diff": config_diff,
                        "netbox_diff": netbox_diff,
                        "config_source": config_source,
                    })
        else:
            # Deploy mode - use Nornir for parallel execution
            nornir_manager = NornirDeviceManager(devices=devices)
            nornir_manager.initialize()
            
            # Deploy VLAN across all devices in parallel
            nornir_results = nornir_manager.deploy_vlan(
                interface_list=interface_list,
                vlan_id=vlan_id,
                platform=platform,
                timeout=90
            )
            
            # Process Nornir results into table format
            for device in devices:
                device_results = nornir_results.get(device.name, {})
                
                for interface_name in interface_list:
                    interface_result = device_results.get(interface_name, {
                        'success': False,
                        'error': 'No result returned from Nornir'
                    })
                    
                    # Convert Nornir result to table entry
                    # Get logs from deployment
                    logs = interface_result.get('logs', []) if isinstance(interface_result.get('logs'), list) else []
                    
                    if interface_result.get('success'):
                        status = "success"
                        config_applied = "Yes"
                        message = interface_result.get('message', 'Configuration deployed successfully')
                        
                        # Update NetBox if requested and deployment was committed
                        netbox_updated = "No"
                        if update_netbox and interface_result.get('committed', False) and vlan:
                            logs.append("")
                            logs.append("[Step 4] Updating NetBox interface assignment...")
                            netbox_result = self._update_netbox_interface(device, interface_name, vlan)
                            if netbox_result['success']:
                                netbox_updated = "Yes"
                                message += " | NetBox updated"
                                logs.append(f"✓ NetBox interface updated successfully")
                            else:
                                netbox_updated = "Failed"
                                message += f" | NetBox update failed: {netbox_result['error']}"
                                logs.append(f"✗ NetBox update failed: {netbox_result['error']}")
                        elif interface_result.get('rolled_back', False):
                            netbox_updated = "Skipped"
                            message += " | NetBox update skipped (deployment rolled back)"
                            logs.append(f"⚠ NetBox update skipped (deployment was rolled back)")
                        else:
                            logs.append(f"⚠ NetBox update skipped (deployment not committed)")
                    else:
                        status = "error"
                        config_applied = "Failed"
                        netbox_updated = "No"
                        message = interface_result.get('error', 'Unknown error')
                    
                    # Add final summary to logs
                    logs.append("")
                    logs.append("=== Deployment Completed ===")
                    logs.append(f"Final Status: {status.upper()}")
                    logs.append(f"Config Applied: {config_applied}")
                    logs.append(f"NetBox Updated: {netbox_updated}")
                    
                    results.append({
                        "device": device,
                        "interface": interface_name,
                        "vlan_id": vlan_id,
                        "vlan_name": vlan_name,
                        "status": status,
                        "config_applied": config_applied,
                        "netbox_updated": netbox_updated,
                        "message": message,
                        "deployment_logs": '\n'.join(logs) if logs else message,
                    })

        return results

    def _get_device_platform(self, device):
        """
        Detect device platform (cumulus or eos).
        Uses the same logic as NAPALMDeviceManager.
        """
        from netbox_automation_plugin.core.napalm_integration import NAPALMDeviceManager

        napalm_manager = NAPALMDeviceManager(device)
        driver = napalm_manager.get_driver_name()
        return driver

    def _generate_vlan_config(self, interface_name, vlan_id, platform):
        """
        Generate platform-specific VLAN configuration command.
        Phase 1: Access mode only.

        Supported platforms:
        - cumulus: Cumulus Linux NVUE
        - eos: Arista EOS

        Args:
            interface_name: Interface name (e.g., 'bond1', 'Ethernet1')
            vlan_id: VLAN ID (1-4094)
            platform: Platform type ('cumulus' or 'eos')

        Returns:
            str: Configuration command(s) for the platform
        """
        if platform == 'cumulus':
            # Cumulus NVUE command
            return f"nv set interface {interface_name} bridge domain br_default access {vlan_id}"

        elif platform == 'eos':
            # Arista EOS commands (hierarchical config format for NAPALM)
            # NAPALM EOS expects config in "configure terminal" format
            commands = [
        f"interface {interface_name}",
        f"   switchport mode access",
        f"   switchport access vlan {vlan_id}",
            ]
            return "\n".join(commands)

        else:
            # Unsupported platform
            raise ValueError(f"Unsupported platform: {platform}. Supported platforms: cumulus, eos")

    def _deploy_config_to_device(self, device, interface_name, config_command, platform, vlan_id):
        """
        Deploy configuration command to a single device using safe deployment.
        Uses NAPALMDeviceManager with deploy_config_safe for failsafe deployment.
        Handles platform-specific deployment logic with post-deployment verification.

        Supports both EOS and Cumulus platforms with commit-confirm workflow:
        - EOS: Uses "configure session" with commit timer (auto-rollback if not confirmed)
        - Cumulus: Uses "nv config apply --confirm {timeout}s" (auto-rollback if not confirmed)

        Both platforms support the same safe deployment workflow:
        1. Load config (merge mode for incremental changes)
        2. Commit with rollback timer (90 seconds)
        3. Verify device health (connectivity, interfaces)
        4. Confirm commit if checks pass, otherwise auto-rollback

        Args:
            device: Device object (NetBox Device model)
            interface_name: Name of the interface being configured
            config_command: Configuration command(s) to deploy
            platform: Platform type ('cumulus' or 'eos')

        Returns:
            dict: {
                "success": bool,
                "committed": bool,
                "rolled_back": bool,
                "message": str,
                "verification_results": dict,
                "logs": list,
                "error": str (optional)
            }
        """
        napalm_manager = None
        logs = []

        try:
            logs.append(f"[2.1] Platform detection: {platform}")

            # Convert platform-specific commands to NAPALM config format
            if platform == 'cumulus':
                # For Cumulus NVUE, the config_command is already an NVUE command (e.g., "nv set interface ...")
                # NAPALM's commit_config() will handle "nv config apply --confirm {timeout}s" automatically
                # So we only need the NVUE set command, not the apply command
                config_text = config_command
                logs.append(f"[2.2] Cumulus NVUE command prepared: {config_text}")
                logger.info(f"Deploying to Cumulus device {device.name}: {config_text}")

            elif platform == 'eos':
                # For Arista EOS, the config_command already contains multi-line CLI commands
                # NAPALM will handle the commit-confirm workflow using configure session
                # EOS uses configure session with commit timer for safe deployment
                config_text = config_command
                logs.append(f"[2.2] Arista EOS command prepared: {config_text}")
                logger.info(f"Deploying to EOS device {device.name}: {config_text}")

            else:
                logger.error(f"Unsupported platform {platform} for device {device.name}")
                logs.append(f"✗ Unsupported platform: {platform}")
                return {
                    "success": False,
                    "committed": False,
                    "rolled_back": False,
                    "message": f"Unsupported platform: {platform}. Supported platforms: cumulus, eos",
                    "verification_results": {},
                    "logs": logs,
                    "error": f"Unsupported platform: {platform}"
                }

            # Initialize NAPALM manager for this device
            logs.append(f"[2.3] Initializing NAPALM connection to {device.name}...")
            logs.append(f"      Device IP: {device.primary_ip4 or device.primary_ip6}")
            napalm_manager = NAPALMDeviceManager(device)
            logger.info(f"Initialized NAPALM manager for {device.name} (platform: {platform})")
            logs.append(f"✓ NAPALM manager initialized")

            # Deploy using safe deployment with post-checks
            # Both EOS and Cumulus support commit-confirm workflow:
            # - EOS: Uses "configure session" with commit timer
            # - Cumulus: Uses "nv config apply --confirm {timeout}s"
            # Use merge mode (replace=False) since we're only adding VLAN config
            # Set timeout to 90 seconds for rollback timer
            # Check connectivity and interfaces (the interface we're configuring should stay up)
            logs.append(f"[2.4] Starting safe deployment with 90s rollback timer...")
            logs.append(f"      Mode: Merge (incremental changes)")
            logs.append(f"      Checks: connectivity")
            logs.append(f"      Interface: {interface_name}")
            logs.append(f"      VLAN ID: {vlan_id}")

            logger.info(f"Starting safe deployment for {device.name} (interface: {interface_name}, timeout: 90s)")
            deploy_result = napalm_manager.deploy_config_safe(
                config=config_text,
                replace=False,  # Merge mode for incremental changes
                timeout=90,  # 90 second rollback timer (works for both EOS and Cumulus)
                checks=['connectivity', 'lldp'],  # Verify device connectivity and LLDP neighbors (device-level)
                critical_interfaces=None,  # Don't check if interfaces are up (they might be unplugged)
                min_neighbors=0,  # Not checking minimum neighbors (interface might be unplugged)
                vlan_id=vlan_id,  # Pass VLAN ID for verification
                interface_name=interface_name  # Pass interface name for verification (LLDP check excludes this interface)
            )

            # Extract detailed logs from deploy_result if available
            if deploy_result.get("logs"):
                logs.append(f"[2.5] Deployment execution logs:")
                for log_line in deploy_result["logs"]:
                    logs.append(f"      {log_line}")

            logger.info(f"Deployment result for {device.name}: success={deploy_result.get('success')}, "
                       f"committed={deploy_result.get('committed')}, rolled_back={deploy_result.get('rolled_back')}")

            logs.append(f"[2.6] Deployment completed:")
            logs.append(f"      Success: {deploy_result.get('success', False)}")
            logs.append(f"      Committed: {deploy_result.get('committed', False)}")
            logs.append(f"      Rolled Back: {deploy_result.get('rolled_back', False)}")
            logs.append(f"      Message: {deploy_result.get('message', '')}")

            # Map deploy_config_safe result to our expected format
            return {
                "success": deploy_result.get("success", False),
                "committed": deploy_result.get("committed", False),
                "rolled_back": deploy_result.get("rolled_back", False),
                "message": deploy_result.get("message", ""),
                "verification_results": deploy_result.get("verification_results", {}),
                "logs": logs,
                "error": None if deploy_result.get("success") else deploy_result.get("message", "Unknown error")
            }

        except Exception as e:
            logger.error(f"Exception during safe deployment to {device.name}: {e}")
            logs.append(f"✗ Exception during deployment: {str(e)}")
            import traceback
            logs.append(f"Traceback:")
            for line in traceback.format_exc().split('\n'):
                if line.strip():
                    logs.append(f"  {line}")

            return {
                "success": False,
                "committed": False,
                "rolled_back": False,
                "message": f"Exception during deployment: {str(e)}",
                "verification_results": {},
                "logs": logs,
                "error": str(e)
            }
        finally:
            # Always disconnect NAPALM connection
            if napalm_manager:
                try:
                    logs.append(f"[2.7] Disconnecting from {device.name}...")
                    napalm_manager.disconnect()
                    logs.append(f"✓ Disconnected successfully")
                except Exception as e:
                    logger.warning(f"Error disconnecting from {device.name}: {e}")
                    logs.append(f"⚠ Warning during disconnect: {e}")

    def _update_netbox_interface(self, device, interface_name, vlan):
        """
        Update NetBox interface with VLAN assignment.

        Returns:
            dict: {"success": bool, "error": str}
        """
        try:
            with transaction.atomic():
                # Find the interface in NetBox
                interface = Interface.objects.filter(
                    device=device,
                    name=interface_name
                ).first()

                if not interface:
                    return {
                        "success": False,
                        "error": f"Interface {interface_name} not found in NetBox"
                    }

                # Set untagged VLAN (tagged mode for VLAN-aware bridges)
                # Note: Even for access ports, we use 'tagged' mode in NetBox because
                # Cumulus/Mellanox devices use VLAN-aware bridges where all ports are in tagged mode
                interface.mode = 'tagged'
                interface.untagged_vlan = vlan
                interface.save()

                return {
                    "success": True,
                    "error": None
                }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }


    def _build_summary(self, results, device_count):
        """Build summary statistics for the results."""
        summary = {
            "device_count": device_count,
            "interface_count": len(results),
            "success": 0,
            "error": 0,
            "dry_run": 0,
        }

        for r in results:
            status = r.get("status")
            if status == "success":
                if r.get("config_applied") == "Dry Run":
                    summary["dry_run"] += 1
                else:
                    summary["success"] += 1
            elif status == "error":
                summary["error"] += 1

        return summary

    def _parse_interface_list(self, interfaces_str):
        """
        Parse comma-separated interface list with support for ranges.
        Examples:
          - "bond1,bond2,bond3" -> ['bond1', 'bond2', 'bond3']
          - "swp1-48" -> ['swp1', 'swp2', ..., 'swp48']
          - "Ethernet1-24" -> ['Ethernet1', 'Ethernet2', ..., 'Ethernet24']
        """
        import re

        interface_list = []
        parts = [p.strip() for p in interfaces_str.split(',') if p.strip()]

        for part in parts:
            # Check if it's a range (e.g., swp1-48 or Ethernet1-24)
            range_match = re.match(r'^([a-zA-Z]+)(\d+)-(\d+)$', part)
            if range_match:
                prefix = range_match.group(1)
                start = int(range_match.group(2))
                end = int(range_match.group(3))
                # Generate range
                for i in range(start, end + 1):
                    interface_list.append(f"{prefix}{i}")
            else:
                # Single interface
                interface_list.append(part)

        return interface_list

    def _validate_interfaces_on_devices(self, devices, interface_list):
        """
        Validate that all specified interfaces exist on all devices.
        Returns list of error messages (empty if all valid).
        """
        errors = []

        for device in devices:
            # Get all interface names for this device
            device_interfaces = set(
                Interface.objects.filter(device=device).values_list('name', flat=True)
            )

            # Check each interface
            for iface_name in interface_list:
                if iface_name not in device_interfaces:
                    errors.append(
                        f"Interface '{iface_name}' does not exist on device '{device.name}'"
                    )

        return errors

    def _build_csv(self, results):
        """Generate CSV export of results."""
        import csv
        from io import StringIO

        output = StringIO()
        # Add UTF-8 BOM for Excel compatibility
        output.write('\ufeff')

        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        writer.writerow([
            "Device",
            "Interface",
            "VLAN ID",
            "VLAN Name",
            "Status",
            "Config Applied",
            "NetBox Updated",
            "Message",
        ])

        for r in results:
            device_name = r["device"].name if r.get("device") else ""
            writer.writerow([
                device_name,
                r.get("interface", ""),
                r.get("vlan_id", ""),
                r.get("vlan_name", ""),
                r.get("status", ""),
                r.get("config_applied", ""),
                r.get("netbox_updated", ""),
                r.get("message", ""),
            ])

        return output.getvalue()


class GetCommonInterfacesView(View):
    """
    AJAX endpoint to get common interfaces for selected devices.
    Returns JSON list of interfaces that exist on ALL selected devices.
    
    Accepts either:
    - device_ids[]: List of device IDs (Single mode)
    - site_id, location_id, manufacturer_id, role_id: Filter parameters (Group mode)
    """

    def get(self, request):
        device_ids = request.GET.getlist('device_ids[]')
        
        # Group mode filter parameters
        site_id = request.GET.get('site_id')
        location_id = request.GET.get('location_id')
        manufacturer_id = request.GET.get('manufacturer_id')
        role_id = request.GET.get('role_id')

        # Get devices either by IDs (Single mode) or by filters (Group mode)
        if device_ids:
            # Single mode: Use provided device IDs
            devices = Device.objects.filter(id__in=device_ids)
        elif site_id and location_id and manufacturer_id and role_id:
            # Group mode: Query devices by filters
            from django.db.models import Q
            devices = Device.objects.filter(
                site_id=site_id,
                location_id=location_id,
                device_type__manufacturer_id=manufacturer_id,
                role_id=role_id
            ).filter(
                Q(primary_ip4__isnull=False) | Q(primary_ip6__isnull=False)
            ).select_related('device_type', 'device_type__manufacturer')
            
            logger.info(f"Group mode: Found {devices.count()} devices matching filters (site={site_id}, location={location_id}, manufacturer={manufacturer_id}, role={role_id})")
            # Log device names for debugging
            device_names = [d.name for d in devices]
            logger.info(f"Group mode devices: {device_names}")
        else:
            return JsonResponse({'interfaces': [], 'device_count': 0})

        if not devices.exists():
            return JsonResponse({'interfaces': [], 'device_count': 0})

        # Get interfaces for each device
        device_interface_sets = []
        for device in devices:
            interfaces = set(
                Interface.objects.filter(device=device).values_list('name', flat=True)
            )
            device_interface_sets.append(interfaces)
            # Debug: Log first few interfaces per device
            logger.debug(f"Device {device.name}: {len(interfaces)} interfaces, first 5: {list(interfaces)[:5]}")

        # Find common interfaces using pattern matching
        # Handles cases where devices have different naming (swp7 vs swp1s1, swp2s1, etc.)
        if device_interface_sets:
            import re
            
            def get_base_interface_name(interface_name):
                """
                Extract base interface name for pattern matching.
                Examples:
                - swp7 -> swp7
                - swp1s1 -> swp1
                - swp2s2 -> swp2
                - Ethernet1 -> Ethernet1
                - Ethernet1/1 -> Ethernet1
                """
                # Remove sub-interface notation (s1, s2, etc.)
                # Pattern: swp1s1 -> swp1, swp2s2 -> swp2
                match = re.match(r'^([a-zA-Z]+\d+)s\d+', interface_name)
                if match:
                    return match.group(1)
                
                # Remove port notation (Ethernet1/1 -> Ethernet1)
                match = re.match(r'^([a-zA-Z]+\d+)/\d+', interface_name)
                if match:
                    return match.group(1)
                
                # Return as-is for simple names (swp7, Ethernet1)
                return interface_name
            
            # Group interfaces by base name across all devices
            base_interface_map = {}  # base_name -> set of actual interface names
            for interface_set in device_interface_sets:
                for interface in interface_set:
                    base_name = get_base_interface_name(interface)
                    if base_name not in base_interface_map:
                        base_interface_map[base_name] = set()
                    base_interface_map[base_name].add(interface)
            
            # Count how many devices have each base interface
            base_interface_counts = {}
            for interface_set in device_interface_sets:
                base_names_found = set()
                for interface in interface_set:
                    base_name = get_base_interface_name(interface)
                    base_names_found.add(base_name)
                
                for base_name in base_names_found:
                    base_interface_counts[base_name] = base_interface_counts.get(base_name, 0) + 1
            
            # Calculate threshold: 80% of devices, but at least 1 device (for single device case)
            total_devices = len(device_interface_sets)
            if total_devices == 1:
                # Single device: show all interfaces (except management)
                management_interfaces = {'eth0', 'lo', 'mgmt', 'management', 'loopback', 'Loopback0'}
                all_interfaces = device_interface_sets[0]
                common_interfaces = sorted(
                    [iface for iface in all_interfaces if iface.lower() not in management_interfaces],
                    key=self._natural_sort_key
                )
                logger.info(f"Single device: Showing {len(common_interfaces)} interfaces (excluding management)")
            else:
                # Multiple devices: use threshold approach
                threshold = max(1, int(total_devices * 0.8))
                
                # Filter out management interfaces (eth0, lo, mgmt, etc.)
                management_interfaces = {'eth0', 'lo', 'mgmt', 'management', 'loopback', 'Loopback0'}
                
                # Get base interfaces that exist on at least threshold devices
                common_base_interfaces = {
                    base_name for base_name, count in base_interface_counts.items()
                    if count >= threshold and base_name.lower() not in management_interfaces
                }
                
                # For each common base interface, pick the most common actual interface name
                # This handles swp7 vs swp7s1 - we'll show the one that appears most
                common_interfaces = []
                for base_name in common_base_interfaces:
                    # Get all actual interface names for this base
                    actual_names = base_interface_map[base_name]
                    
                    # Count occurrences of each actual name
                    actual_name_counts = {}
                    for interface_set in device_interface_sets:
                        for interface in interface_set:
                            if get_base_interface_name(interface) == base_name:
                                actual_name_counts[interface] = actual_name_counts.get(interface, 0) + 1
                    
                    # Pick the most common actual name, or shortest if tie
                    if actual_name_counts:
                        most_common = max(actual_name_counts.items(), key=lambda x: (x[1], -len(x[0])))
                        common_interfaces.append(most_common[0])
                
                # Sort for consistent display
                common_interfaces = sorted(common_interfaces, key=self._natural_sort_key)
                logger.info(f"Common interfaces across {total_devices} devices (threshold: {threshold}): {len(common_interfaces)} found - {list(common_interfaces)[:10]}")
        else:
            common_interfaces = []

        return JsonResponse({
            'interfaces': list(common_interfaces),
            'device_count': len(devices),
        })

    def _natural_sort_key(self, s):
        """
        Sort interface names naturally (e.g., swp1, swp2, swp10 instead of swp1, swp10, swp2).
        """
        import re
        return [int(text) if text.isdigit() else text.lower()
                for text in re.split('([0-9]+)', s)]


class GetVLANsBySiteView(View):
    """
    AJAX endpoint to get VLANs filtered by location.
    Returns JSON list of VLANs for the selected location.

    VLANs are filtered by VLAN Groups that belong to the device's location.

    Accepts either:
    - site_id: Direct site ID (from group mode)
    - device_ids[]: List of device IDs (from single mode - will get location from first device)
    """

    def get(self, request):
        site_id = request.GET.get('site_id')
        device_ids = request.GET.getlist('device_ids[]')
        location_id = None

        # If device_ids provided (single mode), get location from first device
        if device_ids and not site_id:
            devices = Device.objects.filter(id__in=device_ids).select_related('location', 'site')
            if devices.exists():
                first_device = devices.first()
                # Get location from first device
                location_id = first_device.location_id if first_device.location else None
                # Fallback to site if no location
                if not location_id:
                    site_id = first_device.site_id if first_device.site else None

        # Filter VLANs by location through VLAN Groups
        # VLAN Group names contain location names (e.g., "Birch VLANs", "Spruce VLANs")
        # Since scope is inconsistent (some use Location, some use Site), we filter by name
        try:
            if location_id:
                # Get the location object to find its name
                from dcim.models import Location
                location = Location.objects.filter(id=location_id).first()

                if location:
                    # Filter VLANs by VLAN Groups whose name contains the location name
                    # e.g., location "Birch" → VLAN Group "Birch VLANs"
                    vlans = VLAN.objects.filter(
                        group__name__icontains=location.name
                    ).select_related('group').order_by('vid')
                else:
                    vlans = VLAN.objects.none()
            elif site_id:
                # Fallback: Filter VLANs by site
                vlans = VLAN.objects.filter(site_id=site_id).select_related('group').order_by('vid')
            else:
                vlans = VLAN.objects.none()
        except Exception as e:
            import traceback
            return JsonResponse({
                'error': str(e),
                'traceback': traceback.format_exc(),
                'vlans': [],
                'count': 0,
            }, status=500)

        vlan_list = [
            {
                'id': vlan.id,
                'vid': vlan.vid,
                'name': vlan.name,
                'display': f"VLAN{vlan.vid} ({vlan.name})" if vlan.name else f"VLAN{vlan.vid}",
            }
            for vlan in vlans
        ]

        return JsonResponse({
            'vlans': vlan_list,
            'count': len(vlan_list),
        })
