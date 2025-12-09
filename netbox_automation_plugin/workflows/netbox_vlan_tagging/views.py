from django.shortcuts import render
from django.views import View
from django.http import HttpResponse, JsonResponse
from django.utils.translation import gettext_lazy as _
from django.db import transaction
from django.db.models import Q

from dcim.models import Device, Interface
from extras.models import Tag

from .forms import VLANTaggingForm
from .tables import VLANTaggingResultTable
from netbox_automation_plugin.core.napalm_integration import NAPALMDeviceManager
import logging
import traceback
import re

logger = logging.getLogger('netbox_automation_plugin')


class VLANTaggingView(View):
    """
    NetBox VLAN Tagging Workflow
    
    This workflow analyzes devices and interfaces based on defined criteria and applies NetBox tags.
    It is a standalone analysis and tagging tool, completely independent of deployment workflows.
    
    Features:
    - Device-level analysis and tagging (automation-ready:vlan)
    - Interface-level analysis and tagging (vlan-mode:access, vlan-mode:tagged, vlan-mode:uplink, vlan-mode:routed, vlan-mode:needs-review)
    - Bulk analysis and tagging
    - Auto-tagging based on NetBox data
    """

    template_name_form = "netbox_automation_plugin/vlan_tagging_form.html"
    template_name_results = "netbox_automation_plugin/vlan_tagging_results.html"

    def get(self, request):
        """Display the form for device selection and workflow mode"""
        form = VLANTaggingForm()
        return render(request, self.template_name_form, {"form": form})

    def post(self, request):
        """Process the form and run analysis or tagging"""
        try:
            form = VLANTaggingForm(request.POST)
            if not form.is_valid():
                return render(request, self.template_name_form, {"form": form})
            
            workflow_mode = form.cleaned_data['workflow_mode']
            device_selection = form.cleaned_data['device_selection']
            
            # Get devices based on selection mode
            if device_selection == 'single':
                devices = form.cleaned_data['devices']
            else:
                # Group mode: filter by site, location, role, manufacturer
                devices = self._get_devices_from_filters(
                    form.cleaned_data.get('site'),
                    form.cleaned_data.get('location'),
                    form.cleaned_data.get('role'),
                    form.cleaned_data.get('manufacturer'),
                )
            
            if not devices:
                form.add_error(None, _("No devices found matching the selected criteria."))
                return render(request, self.template_name_form, {"form": form})
            
            if workflow_mode == 'analysis':
                # Run analysis and show results
                results = self._analyze_devices(devices, form.cleaned_data.get('use_device_config_check', False))
                # Get currently tagged devices/interfaces for display
                current_tags_info = self._get_current_tags_info(devices)
                return render(request, self.template_name_results, {
                    "form": form,
                    "results": results,
                    "current_tags_info": current_tags_info,
                    "workflow_mode": "analysis",
                })
            else:
                # Tagging mode: apply or delete tags
                action = request.POST.get('action', 'deploy')  # Default to 'deploy' for backward compatibility
                
                # Based on action, determine which operations to perform
                if action == 'delete':
                    # Delete mode: only process deletion
                    tag_devices = False
                    tag_interfaces = False
                    delete_device_tags = form.cleaned_data.get('delete_device_tags', False)
                    delete_interface_tags = form.cleaned_data.get('delete_interface_tags', False)
                    
                    if not (delete_device_tags or delete_interface_tags):
                        form.add_error(None, _("Please select at least one deletion option (Delete Device Tags or Delete Interface Tags)."))
                        return render(request, self.template_name_form, {"form": form})
                else:
                    # Deploy mode: only process tagging
                    tag_devices = form.cleaned_data.get('tag_devices', False)
                    tag_interfaces = form.cleaned_data.get('tag_interfaces', False)
                    delete_device_tags = False
                    delete_interface_tags = False
                    
                    if not (tag_devices or tag_interfaces):
                        form.add_error(None, _("Please select at least one tagging option (Tag Devices or Tag Interfaces)."))
                        return render(request, self.template_name_form, {"form": form})
                
                # Run analysis first (needed for tagging, and useful for deletion preview)
                analysis_results = self._analyze_devices(devices, form.cleaned_data.get('use_device_config_check', False))
                
                # Apply or delete tags with transaction for atomicity
                try:
                    with transaction.atomic():
                        tagging_results = {
                            'devices_tagged': {'count': 0, 'devices': []},
                            'interfaces_tagged': {},
                            'devices_deleted': {'count': 0, 'devices': []},
                            'interfaces_deleted': {'count': 0, 'interfaces': []},
                            'interfaces_updated': {},
                            'interfaces_no_change': {},
                            'errors': [],
                        }
                        
                        # Apply tags if requested
                        if tag_devices or tag_interfaces:
                            apply_results = self._apply_tags(devices, analysis_results, tag_devices, tag_interfaces)
                            tagging_results['devices_tagged'] = apply_results['devices_tagged']
                            tagging_results['interfaces_tagged'] = apply_results['interfaces_tagged']
                            tagging_results['interfaces_updated'] = apply_results.get('interfaces_updated', {})
                            tagging_results['interfaces_no_change'] = apply_results.get('interfaces_no_change', {})
                        
                        # Delete tags if requested
                        if delete_device_tags or delete_interface_tags:
                            delete_results = self._delete_tags(devices, delete_device_tags, delete_interface_tags)
                            tagging_results['devices_deleted'] = delete_results['devices_deleted']
                            tagging_results['interfaces_deleted'] = delete_results['interfaces_deleted']
                            if delete_results.get('errors'):
                                tagging_results['errors'].extend(delete_results['errors'])
                    
                    # Determine operation type for display
                    has_tagging = tag_devices or tag_interfaces
                    has_deletion = delete_device_tags or delete_interface_tags
                    if has_tagging and has_deletion:
                        operation_type = "both"
                    elif has_deletion:
                        operation_type = "delete"
                    else:
                        operation_type = "apply"
                    
                    return render(request, self.template_name_results, {
                        "form": form,
                        "results": analysis_results,
                        "tagging_results": tagging_results,
                        "workflow_mode": "tagging",
                        "operation_type": operation_type,
                    })
                except Exception as e:
                    logger.error(f"Error applying/deleting tags: {e}")
                    logger.error(traceback.format_exc())
                    form.add_error(None, _(f"Error applying/deleting tags: {str(e)}"))
                    return render(request, self.template_name_form, {"form": form})
                
        except Exception as e:
            logger.error(f"VLAN Tagging workflow error: {e}")
            logger.error(traceback.format_exc())
            form.add_error(None, _(f"Error: {str(e)}"))
            return render(request, self.template_name_form, {"form": form})

    def _get_devices_from_filters(self, site, location, role, manufacturer):
        """Get devices based on filters"""
        devices = Device.objects.select_related(
            'primary_ip4', 'primary_ip6', 'site', 'role',
            'device_type', 'device_type__manufacturer'
        ).filter(
            Q(primary_ip4__isnull=False) | Q(primary_ip6__isnull=False)
        )
        
        if site:
            devices = devices.filter(site=site)
        if location:
            devices = devices.filter(location=location)
        if role:
            devices = devices.filter(role=role)
        if manufacturer:
            devices = devices.filter(device_type__manufacturer=manufacturer)
        
        return devices

    def _analyze_devices(self, devices, use_device_config_check=False):
        """
        Analyze devices and interfaces based on criteria from TAGGING_WORKFLOW_SUMMARY.md
        
        Returns a dictionary with:
        - device_summary: counts of ready/not ready devices
        - interface_summary: counts by tag type
        - device_details: per-device analysis
        - interface_details: per-interface classification
        """
        results = {
            'device_summary': {
                'total': 0,
                'ready': 0,
                'not_ready': 0,
                'needs_review': 0,
            },
            'interface_summary': {
                'total': 0,
                'access': 0,
                'tagged': 0,
                'uplink': 0,
                'routed': 0,
                'needs_review': 0,
                'no_tag': 0,
            },
            'device_details': [],
            'interface_details': [],
        }
        
        results['device_summary']['total'] = devices.count()
        logger.info(f"Analyzing {results['device_summary']['total']} devices...")
        
        # Analyze each device
        for device in devices:
            device_analysis = self._analyze_device(device)
            results['device_details'].append(device_analysis)
            
            # Log device analysis result
            logger.debug(f"Device {device.name}: recommendation = {device_analysis['recommendation']}, "
                        f"status = {device_analysis['status']}, "
                        f"manufacturer = {device_analysis['manufacturer']}, "
                        f"role = {device_analysis['role']}")
            
            # Update device summary
            if device_analysis['recommendation'] == 'ready':
                results['device_summary']['ready'] += 1
                logger.info(f"Device {device.name} is READY for automation")
            elif device_analysis['recommendation'] == 'not_ready':
                results['device_summary']['not_ready'] += 1
                logger.debug(f"Device {device.name} is NOT READY: {device_analysis['reasons']}")
            else:
                results['device_summary']['needs_review'] += 1
                logger.debug(f"Device {device.name} NEEDS REVIEW: {device_analysis['reasons']}")
            
            # Analyze interfaces for this device (only host-facing interfaces per scope)
            interfaces = Interface.objects.filter(device=device).select_related(
                'cable', 'untagged_vlan', 'device', 'device__role'
            ).prefetch_related('tagged_vlans', 'ip_addresses', 'tags')
            
            for interface in interfaces:
                interface_analysis = self._analyze_interface(interface, device, use_device_config_check)
                # Only include host-facing interfaces (or interfaces that need review)
                # Uplink and routed interfaces are included for completeness but marked appropriately
                if interface_analysis and (
                    interface_analysis.get('connected_role_parent') == 'Host Device' or
                    interface_analysis.get('recommended_tag') in ['needs-review', 'uplink', 'routed'] or
                    interface_analysis.get('recommended_tag') is None  # Not cabled or offline
                ):
                    results['interface_details'].append(interface_analysis)
                    results['interface_summary']['total'] += 1
                    
                    # Update interface summary
                    tag_type = interface_analysis.get('recommended_tag')
                    if tag_type:
                        if tag_type in results['interface_summary']:
                            results['interface_summary'][tag_type] += 1
                    else:
                        results['interface_summary']['no_tag'] += 1
        
        return results

    def _analyze_device(self, device):
        """
        Analyze a single device for automation-ready:vlan tag eligibility
        
        Returns a dictionary with device analysis results
        """
        analysis = {
            'device': device,
            'device_name': device.name,
            'role': device.role.name if device.role else 'N/A',
            'site': device.site.name if device.site else 'N/A',
            'manufacturer': device.device_type.manufacturer.name if device.device_type and device.device_type.manufacturer else 'N/A',
            'status': device.status,
            'primary_ip': str(device.primary_ip4) if device.primary_ip4 else (str(device.primary_ip6) if device.primary_ip6 else None),
            'recommendation': 'not_ready',
            'reasons': [],
            'criteria_met': [],
            'criteria_missed': [],
        }
        
        # Check device status (required for automation)
        if device.status not in ['active', 'staged']:
            analysis['criteria_missed'].append(f"Device status is '{device.status}' (must be 'active' or 'staged')")
            analysis['reasons'].append(f"Device status '{device.status}' is not eligible")
            # Status check fails - device cannot be ready
            analysis['recommendation'] = 'not_ready'
            return analysis
        else:
            analysis['criteria_met'].append(f"Device status is '{device.status}'")
        
        # Check primary IP (required for automation)
        if not device.primary_ip4 and not device.primary_ip6:
            analysis['criteria_missed'].append("Device has no primary IP configured")
            analysis['reasons'].append("Device is not reachable (no primary IP)")
            # Primary IP check fails - device cannot be ready
            analysis['recommendation'] = 'not_ready'
            return analysis
        else:
            analysis['criteria_met'].append("Device has primary IP configured")
        
        # Check manufacturer/platform (required for automation)
        manufacturer_name = analysis['manufacturer'].lower()
        is_supported = 'cumulus' in manufacturer_name or 'mellanox' in manufacturer_name or 'arista' in manufacturer_name
        if not is_supported:
            analysis['criteria_missed'].append(f"Manufacturer '{analysis['manufacturer']}' is not supported (must be Cumulus/Mellanox or Arista)")
            analysis['reasons'].append(f"Unsupported platform: {analysis['manufacturer']}")
            # Manufacturer check fails - device cannot be ready
            analysis['recommendation'] = 'not_ready'
            return analysis
        else:
            analysis['criteria_met'].append(f"Platform is supported: {analysis['manufacturer']}")
        
        # Check device role (Primary Method: Check interface connections)
        has_host_facing = False
        has_uplink = False
        
        interfaces = Interface.objects.filter(device=device).select_related('cable')
        for interface in interfaces:
            if interface.cable:
                try:
                    endpoints = interface.connected_endpoints
                    if endpoints:
                        endpoint = endpoints[0]
                        connected_device = endpoint.device
                        connected_role = connected_device.role
                        
                        # Check if host-facing
                        if connected_role and connected_role.parent:
                            if connected_role.parent.name == "Host Device":
                                has_host_facing = True
                        
                        # Check if uplink (spine or same role)
                        if connected_role:
                            uplink_role_names = ['Network Spine', 'IB Spine', 'Management Spine']
                            if (connected_role.name in uplink_role_names or 
                                connected_role == device.role):
                                has_uplink = True
                except Exception as e:
                    logger.debug(f"Error checking interface {interface.name} endpoints: {e}")
        
        # Fallback Method: Check device role name
        # Based on actual NetBox device roles in the system
        role_name = device.role.name if device.role else ''
        appropriate_roles = [
            'Network Leaf', 'IB Leaf', 'Management Leaf', 'Storage IB Leaf',
            'Network Switch', 'Management Switch', 'Console Switch'
        ]
        inappropriate_roles = [
            'Network Spine', 'IB Spine', 'Management Spine',
            'Edge Router', 'Cluster Edge Router', 'Router Gateway', 'Vyos'
        ]
        generic_roles = ['Network Switch', 'Management Switch']
        
        # Decision logic: Has host-facing OR appropriate role name = ready
        # Only has uplinks (no host-facing) AND inappropriate role = not_ready
        if has_host_facing:
            analysis['criteria_met'].append("Has host-facing connections (leaf switch)")
            analysis['recommendation'] = 'ready'
        elif role_name in appropriate_roles:
            # Appropriate role name is sufficient (even without host-facing connections yet)
            analysis['criteria_met'].append(f"Device role '{role_name}' is appropriate for automation")
            analysis['recommendation'] = 'ready'
        elif has_uplink and not has_host_facing and role_name in inappropriate_roles:
            # Only has uplinks, no host-facing, AND inappropriate role = spine switch
            analysis['criteria_missed'].append("Only has uplink connections (spine switch)")
            analysis['reasons'].append("Device is a spine switch (no host-facing connections)")
            analysis['recommendation'] = 'not_ready'
        elif role_name in inappropriate_roles:
            analysis['criteria_missed'].append(f"Device role '{role_name}' is not appropriate for automation")
            analysis['reasons'].append(f"Inappropriate role: {role_name}")
            analysis['recommendation'] = 'not_ready'
        elif role_name in generic_roles:
            if not has_host_facing and not has_uplink:
                analysis['criteria_missed'].append("Generic role with no connections - needs review")
                analysis['reasons'].append("Cannot determine device type from role or connections")
                analysis['recommendation'] = 'needs_review'
            else:
                analysis['recommendation'] = 'ready' if has_host_facing else 'not_ready'
        
        return analysis
    
    def _analyze_interface(self, interface, device, use_device_config_check=False):
        """
        Analyze a single interface for tagging eligibility
        
        Returns a dictionary with interface analysis results, or None if not host-facing
        """
        # Skip management interfaces
        if interface.name in ['eth0', 'mgmt0', 'Management1', 'lo']:
            return None
        
        analysis = {
            'interface': interface,
            'device': device,
            'device_name': device.name,
            'interface_name': interface.name,
            'recommended_tag': None,
            'reasons': [],
            'criteria_met': [],
            'criteria_missed': [],
        }
        
        # PRIMARY CHECK: Cable must exist
        if not interface.cable:
            # Not cabled - cannot determine purpose
            analysis['recommended_tag'] = None
            analysis['reasons'].append("Interface is not cabled - cannot determine purpose")
            analysis['criteria_missed'].append("No cable in NetBox")
            return analysis  # Still return for reporting, but no tag
        
        # Get connected endpoint information
        try:
            endpoints = interface.connected_endpoints
            if not endpoints:
                analysis['recommended_tag'] = None
                analysis['reasons'].append("Cable exists but no connected endpoints found")
                return analysis
            
            endpoint = endpoints[0]
            connected_device = endpoint.device
            connected_role = connected_device.role
            connected_role_parent = connected_role.parent.name if connected_role and connected_role.parent else None
            connected_status = connected_device.status
            
            analysis['connected_device'] = connected_device.name
            analysis['connected_role'] = connected_role.name if connected_role else 'N/A'
            analysis['connected_role_parent'] = connected_role_parent
            analysis['connected_status'] = connected_status
        except Exception as e:
            logger.error(f"Error getting connected endpoints for {interface.name}: {e}")
            analysis['recommended_tag'] = None
            analysis['reasons'].append(f"Error getting connection info: {str(e)}")
            return analysis
        
        # Check if host-facing (PRIMARY use case)
        # Host device roles from actual NetBox instance: CPU Host, GPU Host, Host Device, bare metal infra host
        # All have parent "Host Device" or are "Host Device" themselves
        is_host_device = (
            connected_role_parent == "Host Device" or
            (connected_role and connected_role.name in ['CPU Host', 'GPU Host', 'Host Device', 'bare metal infra host', 'Storage', 'Storage Host'])
        )
        
        if is_host_device and connected_status in ["active", "staged", "failed", "planned"]:
            analysis['criteria_met'].append("Cabled to Host Device with active status")
            
            # Check for vlan-mode:access (single untagged VLAN)
            untagged_vlan = interface.untagged_vlan.vid if interface.untagged_vlan else None
            tagged_vlans = list(interface.tagged_vlans.values_list('vid', flat=True))
            has_tagged = len(tagged_vlans) > 0
            interface_mode = interface.mode if hasattr(interface, 'mode') else None
            
            # Check for vlan-mode:tagged (both tagged and untagged - Cumulus/Mellanox only)
            manufacturer_name = device.device_type.manufacturer.name.lower() if device.device_type and device.device_type.manufacturer else ''
            is_cumulus_mellanox = 'cumulus' in manufacturer_name or 'mellanox' in manufacturer_name
            
            if untagged_vlan and has_tagged and interface_mode == 'tagged' and is_cumulus_mellanox:
                # vlan-mode:tagged (Cumulus/Mellanox with both tagged and untagged)
                analysis['recommended_tag'] = 'tagged'
                analysis['reasons'].append("Cumulus/Mellanox interface with both tagged and untagged VLANs (VLAN-aware bridge)")
                analysis['criteria_met'].append("Has both untagged and tagged VLANs (normal for Cumulus/Mellanox)")
            elif untagged_vlan and not has_tagged:
                # vlan-mode:access (single untagged VLAN)
                analysis['recommended_tag'] = 'access'
                analysis['reasons'].append("Host-facing interface with single untagged VLAN")
                analysis['criteria_met'].append("Has only untagged VLAN (access port)")
            elif not untagged_vlan and not has_tagged:
                # Empty port but cabled to host - auto-tag as access-ready
                analysis['recommended_tag'] = 'access'
                analysis['reasons'].append("Empty port cabled to Host Device - ready for VLAN assignment")
                analysis['criteria_met'].append("Empty port ready for VLAN configuration")
            else:
                # Has tagged VLANs but not in tagged mode or not Cumulus/Mellanox
                analysis['recommended_tag'] = 'needs-review'
                analysis['reasons'].append("Interface has tagged VLANs but configuration is unclear")
                analysis['criteria_missed'].append("Tagged VLANs present but mode/platform mismatch")
        
        # Check if routed (interface has IP or connected to router/L3 device)
        # Check this BEFORE uplink, as routers are L3 devices
        elif interface.ip_addresses.exists():
            analysis['recommended_tag'] = 'routed'
            analysis['reasons'].append("Interface has IP address configured (routed port)")
            analysis['criteria_met'].append("Routed port detected")
        elif connected_role:
            # Router/firewall role names from actual NetBox instance
            router_role_names = [
                'Cluster Edge Router', 'Edge Router', 'Router Gateway', 'Vyos'
            ]
            
            # Check if connected device is a router/firewall/L3 device
            role_name = connected_role.name if connected_role.name else ''
            role_name_lower = role_name.lower()
            
            # Check exact match first, then partial match for flexibility
            is_router = (
                role_name in router_role_names or
                'router' in role_name_lower or
                'gateway' in role_name_lower or
                'vyos' in role_name_lower or
                'firewall' in role_name_lower or
                (connected_role.parent and connected_role.parent.name and 
                 'router' in connected_role.parent.name.lower())
            )
            
            if is_router:
                analysis['recommended_tag'] = 'routed'
                analysis['reasons'].append(f"Interface is connected to {role_name} (routed connection)")
                analysis['criteria_met'].append("Routed connection detected")
            else:
                # Check if uplink (connected to spine or same role switch)
                # This comes AFTER router check, as uplinks are L2 trunk connections between switches
                uplink_role_names = ['Network Spine', 'IB Spine', 'Management Spine']
                is_uplink = (
                    connected_role.name in uplink_role_names or
                    connected_role == device.role  # Same role = peer switch
                )
                
                if is_uplink:
                    analysis['recommended_tag'] = 'uplink'
                    analysis['reasons'].append(f"Interface is connected to {connected_role.name} (uplink)")
                    analysis['criteria_met'].append("Uplink connection detected")
        
        # Check for offline/decommissioning
        elif connected_status in ["decommissioning", "offline"]:
            analysis['recommended_tag'] = None
            analysis['reasons'].append(f"Connected device status is '{connected_status}' - cannot tag")
            analysis['criteria_missed'].append("Connected device is not active")
        
        # Unknown connection type
        else:
            analysis['recommended_tag'] = 'needs-review'
            analysis['reasons'].append(f"Cannot determine interface type from NetBox data (connected to {connected_role.name if connected_role else 'unknown device'})")
            analysis['criteria_missed'].append("Unknown connection type")
        
        # Device config check (optional - for safety warnings)
        if use_device_config_check:
            config_warnings = self._check_device_config(interface, device)
            if config_warnings:
                analysis['config_warnings'] = config_warnings
                # Add warnings to reasons for visibility
                for warning in config_warnings:
                    analysis['reasons'].append(f"⚠️ Config Warning: {warning}")
        
        return analysis
    
    def _check_device_config(self, interface, device):
        """
        Check device configuration for interface conflicts
        
        Returns a list of warning messages if conflicts are detected.
        NetBox is the source of truth, but we warn if device config doesn't match.
        
        Checks:
        - Arista EOS: port-channel member, trunk port, routed port
        - Cumulus/Mellanox: bond member (bond interfaces themselves are OK), routed port
        
        Returns:
            List of warning strings (empty if no conflicts)
        """
        warnings = []
        
        try:
            # Get device manufacturer/platform
            manufacturer_name = device.device_type.manufacturer.name.lower() if device.device_type and device.device_type.manufacturer else ''
            is_cumulus_mellanox = 'cumulus' in manufacturer_name or 'mellanox' in manufacturer_name
            is_arista = 'arista' in manufacturer_name
            
            # Only check if device is supported
            if not (is_cumulus_mellanox or is_arista):
                return warnings  # No warnings for unsupported platforms
            
            # Connect to device using NAPALM
            napalm_manager = NAPALMDeviceManager(device)
            if not napalm_manager.connect():
                warnings.append(f"Could not connect to device to verify configuration")
                return warnings
            
            try:
                # Get running configuration
                config_result = napalm_manager.get_config(retrieve='running')
                if not config_result or 'running' not in config_result:
                    warnings.append(f"Could not retrieve device configuration")
                    return warnings
                
                running_config = config_result.get('running', '')
                interface_name = interface.name
                
                # Parse interface configuration based on platform
                if is_arista:
                    # Arista EOS interface config parsing
                    warnings.extend(self._check_arista_interface_config(running_config, interface_name))
                elif is_cumulus_mellanox:
                    # Cumulus/Mellanox interface config parsing
                    warnings.extend(self._check_cumulus_interface_config(running_config, interface_name))
                
            finally:
                napalm_manager.disconnect()
                
        except Exception as e:
            logger.warning(f"Error checking device config for {device.name}:{interface.name}: {e}")
            logger.debug(traceback.format_exc())
            warnings.append(f"Error checking device configuration: {str(e)}")
        
        return warnings
    
    def _check_arista_interface_config(self, config, interface_name):
        """
        Check Arista EOS interface configuration for conflicts
        
        Returns list of warning messages
        """
        warnings = []
        
        # Find interface section in config
        interface_pattern = rf'^interface\s+{re.escape(interface_name)}\s*$'
        interface_section = None
        
        lines = config.split('\n')
        in_interface = False
        interface_lines = []
        
        for i, line in enumerate(lines):
            if re.match(interface_pattern, line.strip(), re.IGNORECASE):
                in_interface = True
                interface_lines = []
                continue
            elif in_interface:
                if line.strip().startswith('interface ') or line.strip() == '!':
                    # End of interface section
                    break
                interface_lines.append(line.strip())
        
        if not interface_lines:
            # Interface not found in config - might be a new interface
            return warnings
        
        interface_config = '\n'.join(interface_lines)
        
        # Check for port-channel member
        if 'channel-group' in interface_config.lower():
            warnings.append(f"Interface is a port-channel member (channel-group configured) - VLAN config must be on port-channel interface, not member")
        
        # Check for trunk port
        if 'switchport mode trunk' in interface_config.lower():
            warnings.append(f"Interface is configured as trunk port (switchport mode trunk) - NetBox indicates access-ready, verify NetBox data")
        
        # Check for routed port
        if 'no switchport' in interface_config.lower():
            warnings.append(f"Interface is configured as routed port (no switchport) - NetBox indicates access-ready, verify NetBox data")
        
        # Check for IP address (routed port)
        if re.search(r'ip\s+address\s+', interface_config, re.IGNORECASE):
            warnings.append(f"Interface has IP address configured (routed port) - NetBox indicates access-ready, verify NetBox data")
        
        return warnings
    
    def _check_cumulus_interface_config(self, config, interface_name):
        """
        Check Cumulus/Mellanox interface configuration for conflicts
        
        Returns list of warning messages
        Note: Bond member interfaces CAN have VLAN config in Cumulus - this is normal
        """
        warnings = []
        
        # Check if interface is a bond member
        # Pattern: bond swp1 slaves swp1 (or similar)
        bond_member_pattern = rf'bond\s+\w+\s+slaves\s+{re.escape(interface_name)}\b'
        if re.search(bond_member_pattern, config, re.IGNORECASE):
            # This is a bond member - check if it's the bond interface itself
            # Bond interfaces (like bond_swp1) can have VLAN config - this is OK
            # Physical interfaces that are bond members should not have VLAN config
            if not interface_name.startswith('bond'):
                warnings.append(f"Interface is a bond member (physical interface) - VLAN config should be on bond interface, not member")
        
        # Check for IP address (routed port)
        # Pattern: interface swp1, ip address 10.0.0.1/24
        interface_ip_pattern = rf'interface\s+{re.escape(interface_name)}[,\s].*?ip\s+address\s+'
        if re.search(interface_ip_pattern, config, re.IGNORECASE | re.DOTALL):
            warnings.append(f"Interface has IP address configured (routed port) - NetBox indicates access-ready, verify NetBox data")
        
        # Check for VRF (routed port)
        vrf_pattern = rf'interface\s+{re.escape(interface_name)}[,\s].*?vrf\s+'
        if re.search(vrf_pattern, config, re.IGNORECASE | re.DOTALL):
            warnings.append(f"Interface is in VRF (routed port) - NetBox indicates access-ready, verify NetBox data")
        
        return warnings
    
    def _apply_tags(self, devices, analysis_results, tag_devices, tag_interfaces):
        """
        Apply tags to devices and interfaces based on analysis results
        
        Returns a dictionary with:
        - devices_tagged: count and list
        - interfaces_tagged: count and list by tag type
        - errors: any errors encountered
        """
        results = {
            'devices_tagged': {'count': 0, 'devices': []},
            'interfaces_tagged': {
                'access': {'count': 0, 'interfaces': []},
                'tagged': {'count': 0, 'interfaces': []},
                'uplink': {'count': 0, 'interfaces': []},
                'routed': {'count': 0, 'interfaces': []},
                'needs-review': {'count': 0, 'interfaces': []},  # Match the recommended_tag key
            },
            'interfaces_updated': {
                'access': {'count': 0, 'interfaces': []},
                'tagged': {'count': 0, 'interfaces': []},
                'uplink': {'count': 0, 'interfaces': []},
                'routed': {'count': 0, 'interfaces': []},
                'needs-review': {'count': 0, 'interfaces': []},
            },
            'interfaces_no_change': {
                'access': {'count': 0, 'interfaces': []},
                'tagged': {'count': 0, 'interfaces': []},
                'uplink': {'count': 0, 'interfaces': []},
                'routed': {'count': 0, 'interfaces': []},
                'needs-review': {'count': 0, 'interfaces': []},
            },
            'errors': [],
        }
        
        # Get or create tags
        logger.info("Creating/retrieving tags...")
        device_tag, device_tag_created = Tag.objects.get_or_create(name='automation-ready:vlan', defaults={'slug': 'automation-ready-vlan'})
        if device_tag_created:
            logger.info(f"Created device tag 'automation-ready:vlan' (ID: {device_tag.id})")
        else:
            logger.info(f"Retrieved existing device tag 'automation-ready:vlan' (ID: {device_tag.id})")
        
        interface_tags = {
            'access': Tag.objects.get_or_create(name='vlan-mode:access', defaults={'slug': 'vlan-mode-access'})[0],
            'tagged': Tag.objects.get_or_create(name='vlan-mode:tagged', defaults={'slug': 'vlan-mode-tagged'})[0],
            'uplink': Tag.objects.get_or_create(name='vlan-mode:uplink', defaults={'slug': 'vlan-mode-uplink'})[0],
            'routed': Tag.objects.get_or_create(name='vlan-mode:routed', defaults={'slug': 'vlan-mode-routed'})[0],
            'needs-review': Tag.objects.get_or_create(name='vlan-mode:needs-review', defaults={'slug': 'vlan-mode-needs-review'})[0],
        }
        logger.info(f"Interface tags ready: {list(interface_tags.keys())}")
        
        # Get all vlan-mode tags for removal (to ensure only one tag per interface)
        # Also get by name to catch any vlan-mode tags that might exist
        all_vlan_mode_tags = list(interface_tags.values())
        all_vlan_mode_tag_names = [t.name for t in all_vlan_mode_tags]
        
        # Tag devices
        if tag_devices:
            logger.info(f"Tagging devices: Found {len(analysis_results['device_details'])} devices in analysis results")
            ready_count = sum(1 for d in analysis_results['device_details'] if d['recommendation'] == 'ready')
            logger.info(f"Devices with 'ready' recommendation: {ready_count}")
            
            if ready_count == 0:
                logger.warning("No devices have 'ready' recommendation - check device criteria (status, primary IP, manufacturer, role)")
            
            for device_detail in analysis_results['device_details']:
                recommendation = device_detail.get('recommendation')
                logger.debug(f"Device {device_detail['device_name']}: recommendation = {recommendation}")
                
                if recommendation == 'ready':
                    device = device_detail['device']
                    try:
                        # Refresh device from DB to ensure we have latest state
                        device.refresh_from_db()
                        current_tags = list(device.tags.all())
                        if device_tag not in current_tags:
                            device.tags.add(device_tag)
                            # tags.add() automatically persists ManyToMany changes, no need for save()
                            results['devices_tagged']['count'] += 1
                            results['devices_tagged']['devices'].append(device.name)
                            logger.info(f"Tagged device {device.name} with automation-ready:vlan")
                        else:
                            # Device already has tag - still count it as "tagged" for this workflow run
                            results['devices_tagged']['count'] += 1
                            results['devices_tagged']['devices'].append(device.name)
                            logger.info(f"Device {device.name} already has tag automation-ready:vlan (counted in summary)")
                    except Exception as e:
                        error_msg = f"Error tagging device {device.name}: {str(e)}"
                        logger.error(error_msg)
                        logger.error(traceback.format_exc())
                        results['errors'].append(error_msg)
                else:
                    logger.debug(f"Skipping device {device_detail['device_name']}: recommendation = {recommendation} (not 'ready')")
        
        # Tag interfaces
        if tag_interfaces:
            logger.info(f"Tagging interfaces: Found {len(analysis_results['interface_details'])} interfaces in analysis results")
            
            interface_count_by_tag = {}
            for interface_detail in analysis_results['interface_details']:
                recommended_tag = interface_detail.get('recommended_tag')
                if recommended_tag:
                    interface_count_by_tag[recommended_tag] = interface_count_by_tag.get(recommended_tag, 0) + 1
            logger.info(f"Interfaces by recommended tag: {interface_count_by_tag}")
            
            for interface_detail in analysis_results['interface_details']:
                recommended_tag = interface_detail.get('recommended_tag')
                logger.debug(f"Interface {interface_detail['device_name']}:{interface_detail['interface_name']}: recommended_tag = {recommended_tag}")
                
                if recommended_tag and recommended_tag in interface_tags:
                    interface = interface_detail['interface']
                    tag = interface_tags[recommended_tag]
                    try:
                        # Refresh interface from DB to ensure we have latest state
                        interface.refresh_from_db()
                        current_tags = list(interface.tags.all())
                        current_tag_names = [t.name for t in current_tags]
                        
                        # Find all existing vlan-mode tags (by checking tag names to be safe)
                        existing_vlan_mode_tags = [t for t in current_tags if t.name in all_vlan_mode_tag_names]
                        had_existing_tag = len(existing_vlan_mode_tags) > 0
                        tag_already_correct = False
                        tag_changed = False
                        interface_name = f"{interface_detail['device_name']}:{interface_detail['interface_name']}"
                        
                        # Check if the correct tag already exists
                        if tag in existing_vlan_mode_tags:
                            # Tag already exists and is correct - don't touch it
                            tag_already_correct = True
                            logger.info(f"Interface {interface_detail['device_name']}:{interface_detail['interface_name']} already has correct tag {tag.name} (no change needed)")
                            
                            # Track as "already applied"
                            if recommended_tag not in results['interfaces_no_change']:
                                results['interfaces_no_change'][recommended_tag] = {'count': 0, 'interfaces': []}
                            results['interfaces_no_change'][recommended_tag]['count'] += 1
                            results['interfaces_no_change'][recommended_tag]['interfaces'].append(interface_name)
                        else:
                            # Tag needs to be changed or added
                            if existing_vlan_mode_tags:
                                # Different tag exists - remove old ones first
                                removed_tag_names = [t.name for t in existing_vlan_mode_tags]
                                for old_tag in existing_vlan_mode_tags:
                                    interface.tags.remove(old_tag)
                                interface.refresh_from_db()
                                logger.info(f"Removed old vlan-mode tags from {interface_detail['device_name']}:{interface_detail['interface_name']}: {removed_tag_names}")
                                tag_changed = True
                            
                            # Apply the new tag
                            interface.tags.add(tag)
                            interface.refresh_from_db()
                            
                            # Verify the tag is now present
                            final_tags = list(interface.tags.all())
                            final_tag_names = [t.name for t in final_tags]
                            if tag.name not in final_tag_names:
                                raise Exception(f"Failed to apply tag {tag.name} to interface")
                            
                            # Track in appropriate category
                            if tag_changed:
                                # Tag was changed from a different vlan-mode tag
                                logger.info(f"Updated tag on {interface_detail['device_name']}:{interface_detail['interface_name']} from {removed_tag_names} to {tag.name}")
                                if recommended_tag not in results['interfaces_updated']:
                                    results['interfaces_updated'][recommended_tag] = {'count': 0, 'interfaces': []}
                                results['interfaces_updated'][recommended_tag]['count'] += 1
                                results['interfaces_updated'][recommended_tag]['interfaces'].append(interface_name)
                                # Also count in main tagged list
                                if recommended_tag not in results['interfaces_tagged']:
                                    results['interfaces_tagged'][recommended_tag] = {'count': 0, 'interfaces': []}
                                results['interfaces_tagged'][recommended_tag]['count'] += 1
                                results['interfaces_tagged'][recommended_tag]['interfaces'].append(interface_name)
                            else:
                                # New tag - no existing vlan-mode tags
                                logger.info(f"Tagged interface {interface_detail['device_name']}:{interface_detail['interface_name']} with {tag.name}")
                                if recommended_tag not in results['interfaces_tagged']:
                                    results['interfaces_tagged'][recommended_tag] = {'count': 0, 'interfaces': []}
                                results['interfaces_tagged'][recommended_tag]['count'] += 1
                                results['interfaces_tagged'][recommended_tag]['interfaces'].append(interface_name)
                    except Exception as e:
                        error_msg = f"Error tagging interface {interface_detail['device_name']}:{interface_detail['interface_name']}: {str(e)}"
                        logger.error(error_msg)
                        logger.error(traceback.format_exc())
                        results['errors'].append(error_msg)
                else:
                    logger.debug(f"Skipping interface {interface_detail['device_name']}:{interface_detail['interface_name']}: no recommended_tag or tag not in interface_tags")
        
        # Log final summary
        logger.info(f"Tagging complete: {results['devices_tagged']['count']} devices, "
                   f"{sum(data['count'] for data in results['interfaces_tagged'].values())} interfaces tagged")
        
        return results
    
    def _get_current_tags_info(self, devices):
        """
        Get information about currently tagged devices and interfaces
        
        Returns a dictionary with current tag information for display in analysis mode
        """
        info = {
            'devices_tagged': {'count': 0, 'devices': []},
            'interfaces_tagged': {
                'access': {'count': 0, 'interfaces': []},
                'tagged': {'count': 0, 'interfaces': []},
                'uplink': {'count': 0, 'interfaces': []},
                'routed': {'count': 0, 'interfaces': []},
                'needs-review': {'count': 0, 'interfaces': []},
            },
        }
        
        try:
            device_tag = Tag.objects.get(name='automation-ready:vlan')
        except Tag.DoesNotExist:
            logger.debug("Device tag 'automation-ready:vlan' does not exist")
            return info
        
        # Check device tags
        for device in devices:
            device.refresh_from_db()
            if device_tag in device.tags.all():
                info['devices_tagged']['count'] += 1
                info['devices_tagged']['devices'].append(device.name)
        
        # Check interface tags
        interface_tag_map = {
            'vlan-mode:access': 'access',
            'vlan-mode:tagged': 'tagged',
            'vlan-mode:uplink': 'uplink',
            'vlan-mode:routed': 'routed',
            'vlan-mode:needs-review': 'needs-review',
        }
        
        for device in devices:
            interfaces = Interface.objects.filter(device=device).prefetch_related('tags')
            for interface in interfaces:
                interface.refresh_from_db()
                current_tags = list(interface.tags.all())
                for tag in current_tags:
                    if tag.name in interface_tag_map:
                        tag_type = interface_tag_map[tag.name]
                        info['interfaces_tagged'][tag_type]['count'] += 1
                        interface_name = f"{device.name}:{interface.name}"
                        info['interfaces_tagged'][tag_type]['interfaces'].append(interface_name)
        
        return info
    
    def _delete_tags(self, devices, delete_device_tags, delete_interface_tags):
        """
        Delete automation tags from devices and interfaces
        
        Returns a dictionary with deletion results
        """
        results = {
            'devices_deleted': {'count': 0, 'devices': []},
            'interfaces_deleted': {'count': 0, 'interfaces': []},
            'errors': [],
        }
        
        # Get tags to delete
        device_tag = None
        interface_tags = {}
        
        if delete_device_tags:
            try:
                device_tag = Tag.objects.get(name='automation-ready:vlan')
            except Tag.DoesNotExist:
                logger.warning("Device tag 'automation-ready:vlan' does not exist - nothing to delete")
        
        if delete_interface_tags:
            interface_tag_names = [
                'vlan-mode:access',
                'vlan-mode:tagged',
                'vlan-mode:uplink',
                'vlan-mode:routed',
                'vlan-mode:needs-review',
            ]
            for tag_name in interface_tag_names:
                try:
                    tag = Tag.objects.get(name=tag_name)
                    interface_tags[tag_name] = tag
                except Tag.DoesNotExist:
                    logger.debug(f"Interface tag '{tag_name}' does not exist - skipping")
        
        # Delete device tags
        if delete_device_tags and device_tag:
            logger.info(f"Deleting device tags from {devices.count()} devices...")
            for device in devices:
                try:
                    device.refresh_from_db()
                    if device_tag in device.tags.all():
                        device.tags.remove(device_tag)
                        device.refresh_from_db()
                        results['devices_deleted']['count'] += 1
                        results['devices_deleted']['devices'].append(device.name)
                        logger.info(f"Deleted tag from device {device.name}")
                except Exception as e:
                    error_msg = f"Error deleting tag from device {device.name}: {str(e)}"
                    logger.error(error_msg)
                    results['errors'].append(error_msg)
        
        # Delete interface tags
        if delete_interface_tags and interface_tags:
            logger.info(f"Deleting interface tags from devices...")
            for device in devices:
                interfaces = Interface.objects.filter(device=device).prefetch_related('tags')
                for interface in interfaces:
                    try:
                        interface.refresh_from_db()
                        current_tags = list(interface.tags.all())
                        deleted_any = False
                        
                        # Remove all vlan-mode tags
                        for tag in current_tags:
                            if tag.name in interface_tags:
                                interface.tags.remove(tag)
                                deleted_any = True
                        
                        if deleted_any:
                            interface.refresh_from_db()
                            results['interfaces_deleted']['count'] += 1
                            interface_name = f"{device.name}:{interface.name}"
                            results['interfaces_deleted']['interfaces'].append(interface_name)
                            logger.info(f"Deleted tags from interface {interface_name}")
                    except Exception as e:
                        error_msg = f"Error deleting tags from interface {device.name}:{interface.name}: {str(e)}"
                        logger.error(error_msg)
                        results['errors'].append(error_msg)
        
        # Log final summary
        logger.info(f"Deletion complete: {results['devices_deleted']['count']} devices, "
                   f"{results['interfaces_deleted']['count']} interfaces")
        
        return results

