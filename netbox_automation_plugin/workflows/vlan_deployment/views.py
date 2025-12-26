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

        # Check if sync mode is enabled
        sync_netbox_to_device = form.cleaned_data.get('sync_netbox_to_device', False)
        
        # Additional tag validation before deployment (even for dry run, to show warnings)
        # This provides a second layer of validation and shows warnings even in dry run mode
        # NOTE: Skip this validation in sync mode - sync mode uses different validation logic
        # and interfaces are in "device:interface" format which breaks this validation
        tagging_warnings = form.cleaned_data.get('_tagging_warnings', [])
        if not form.cleaned_data.get('dry_run', False) and not sync_netbox_to_device:
            # For actual deployment, do a final check (only in normal mode, not sync mode)
            validation_errors = self._validate_tags_before_deployment(devices, form.cleaned_data.get('combined_interfaces', []))
            if validation_errors:
                for error in validation_errors:
                    form.add_error(None, error)
                return render(request, self.template_name_form, {"form": form})

        # Run deployment - route to sync or normal mode
        if sync_netbox_to_device:
            results = self._run_vlan_sync(devices, form.cleaned_data)
        else:
            results = self._run_vlan_deployment(devices, form.cleaned_data)

        # CSV export if requested
        if "export_csv" in request.POST:
            csv_content = self._build_csv(results)
            response = HttpResponse(csv_content, content_type="text/csv; charset=utf-8-sig")
            response["Content-Disposition"] = 'attachment; filename="vlan_deployment_results.csv"'
            return response

        table = VLANDeploymentResultTable(results, orderable=True)
        summary = self._build_summary(results, len(devices))
        
        # Calculate device summaries and status counts
        device_summaries = self._build_device_summaries(results)
        status_counts = self._calculate_status_counts(results)

        # Get excluded devices info
        excluded_devices = form.cleaned_data.get('excluded_devices', [])
        excluded_device_names = [d.name for d in excluded_devices] if excluded_devices else []

        # Get tagging warnings if any
        tagging_warnings = form.cleaned_data.get('_tagging_warnings', [])

        context = {
            "form": form,
            "table": table,
            "summary": summary,
            "device_summaries": device_summaries,
            "status_counts": status_counts,
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
        
        Tagging Priority Hierarchy (highest to lowest):
        1. Device: automation-ready:vlan (required for deployment)
        2. Interface tags (checked in priority order):
           - vlan-mode:routed (if IP address or VRF - BLOCKS, highest priority)
           - vlan-mode:uplink (if connected to Spine or same role - BLOCKS)
           - vlan-mode:tagged (if connected to Host AND has tagged/untagged VLANs - ALLOWS)
           - vlan-mode:access (if connected to Host AND has only untagged VLAN - ALLOWS)
           - vlan-mode:needs-review (if unclear or conflicts - WARNS but allows, lowest priority)
        
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
            'tagged': 'vlan-mode:tagged',
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
                    
                    # CRITICAL CHECK: Interface with IP address or VRF is a routed port (BLOCKING)
                    # Priority 1: vlan-mode:routed (if interface has IP address or in VRF, it's routed - highest priority)
                    # This must be checked BEFORE tag checks, as IP address/VRF is a stronger signal
                    has_ip = interface.ip_addresses.exists()
                    has_vrf = hasattr(interface, 'vrf') and interface.vrf is not None
                    # Also check VRF on IP addresses
                    if not has_vrf:
                        for ip_addr in interface.ip_addresses.all():
                            if hasattr(ip_addr, 'vrf') and ip_addr.vrf:
                                has_vrf = True
                                break
                    
                    if has_ip or has_vrf:
                        reason = []
                        if has_ip:
                            reason.append("IP address configured")
                        if has_vrf:
                            reason.append("VRF configured")
                        results['interface_validation'][key] = {
                            'status': 'block',
                            'message': f"Interface has {' and '.join(reason)} (routed port) - would block deployment"
                        }
                        continue  # Skip further checks for this interface
                    
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
                    
                    # Note: Port-channel/bond membership is handled automatically - 
                    # config is applied to bond interface instead of member (no blocking needed)
                    
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
                    # REQUIRED: Interface must be tagged as 'access' or 'tagged' to allow deployment
                    elif interface_tags.get('access') and interface_tags['access'].name in interface_tag_names_list:
                        results['interface_validation'][key] = {
                            'status': 'pass',
                            'message': f"Interface tagged as 'vlan-mode:access' - would pass"
                        }
                    elif interface_tags.get('tagged') and interface_tags['tagged'].name in interface_tag_names_list:
                        results['interface_validation'][key] = {
                            'status': 'pass',
                            'message': f"Interface tagged as 'vlan-mode:tagged' - would pass"
                        }
                    else:
                        # BLOCK: Interface must be tagged as 'access' or 'tagged' for VLAN deployment
                        results['interface_validation'][key] = {
                            'status': 'block',
                            'message': f"Interface not tagged as 'vlan-mode:access' or 'vlan-mode:tagged' - would block deployment"
                        }
                
                except Interface.DoesNotExist:
                    results['interface_validation'][key] = {
                        'status': 'block',
                        'message': f"Interface does not exist - would block deployment"
                    }
        
        return results

    def _looks_like_value(self, key):
        """Check if a key looks like a value (IP address, number, etc.) rather than a config key."""
        import re
        # IP address pattern (IPv4 or IPv6 with CIDR)
        if re.match(r'^[0-9a-fA-F:.]+/\d+$', key):
            return True
        # Pure number
        if re.match(r'^\d+$', key):
            return True
        # IPv6 address without CIDR (less common but possible)
        if '::' in key and re.match(r'^[0-9a-fA-F:.]+$', key):
            return True
        return False

    def _interface_matches_range(self, interface_name, range_key):
        """
        Check if an interface name matches a range pattern.
        Examples:
        - swp6 matches swp1-32 -> True
        - swp6 matches swp6 -> True
        - swp6 matches bond6 -> False
        - swp6 matches swp1-5 -> False
        - swp1s0 matches swp1s0-1 -> True
        - swp2s1 matches swp1s0-3,swp2s0-3 -> True
        """
        import re
        # Exact match
        if interface_name == range_key:
            return True
        
        # Range pattern: swp1-32, bond3-6, swp1s0-1, etc.
        # Pattern 1: Simple range like swp1-32
        range_match = re.match(r'^([a-zA-Z]+)(\d+)-(\d+)$', range_key)
        if range_match:
            prefix = range_match.group(1)
            start = int(range_match.group(2))
            end = int(range_match.group(3))
            
            # Check if interface matches the prefix and is in range
            # Try simple pattern first: swp5
            interface_match = re.match(r'^([a-zA-Z]+)(\d+)$', interface_name)
            if interface_match:
                iface_prefix = interface_match.group(1)
                iface_num = int(interface_match.group(2))
                
                if iface_prefix == prefix and start <= iface_num <= end:
                    return True
            
            # Also check complex interfaces like swp1s0 against parent range swp1-64
            # Extract base number from complex interface (e.g., swp1s0 -> 1)
            interface_match_complex = re.match(r'^([a-zA-Z]+)(\d+)([a-zA-Z]+)(\d+)$', interface_name)
            if interface_match_complex:
                iface_prefix = interface_match_complex.group(1)
                iface_base_num = int(interface_match_complex.group(2))
                
                # If prefix matches and base number is in range, it's a match
                # Example: swp1s0 matches swp1-64 (base number 1 is in range 1-64)
                if iface_prefix == prefix and start <= iface_base_num <= end:
                    return True
        
        # Pattern 2: Complex range like swp1s0-1, swp2s0-3
        # Match pattern: prefix + digits + suffix + digits - digits
        range_match_complex = re.match(r'^([a-zA-Z]+)(\d+)([a-zA-Z]+)(\d+)-(\d+)$', range_key)
        if range_match_complex:
            prefix = range_match_complex.group(1)
            prefix_num = int(range_match_complex.group(2))
            suffix = range_match_complex.group(3)
            start = int(range_match_complex.group(4))
            end = int(range_match_complex.group(5))
            
            # Check if interface matches: swp1s0, swp2s1, etc.
            interface_match_complex = re.match(r'^([a-zA-Z]+)(\d+)([a-zA-Z]+)(\d+)$', interface_name)
            if interface_match_complex:
                iface_prefix = interface_match_complex.group(1)
                iface_prefix_num = int(interface_match_complex.group(2))
                iface_suffix = interface_match_complex.group(3)
                iface_suffix_num = int(interface_match_complex.group(4))
                
                # Match prefix, prefix number, suffix, and suffix number in range
                if (iface_prefix == prefix and 
                    iface_prefix_num == prefix_num and 
                    iface_suffix == suffix and 
                    start <= iface_suffix_num <= end):
                    return True
        
        # Comma-separated list: bond3,5-6 or swp1s0-1,swp2s0-3
        if ',' in range_key:
            parts = range_key.split(',')
            for part in parts:
                if self._interface_matches_range(interface_name, part.strip()):
                    return True
        
        return False

    def _get_bridge_vlans_from_json(self, config_data):
        """
        Extract bridge domain br_default VLAN list from JSON config.
        Handles VLAN ranges and comma-separated values in all formats.
        
        Supports three formats:
        1. Single key with comma-separated and range: {"10,3000-3199": {}}
        2. Single key with range and nested vni: {"3019-3099": {"vni": {"auto": {}}}}
        3. Multiple keys (comma-separated and range) with nested vni:
           {"2000,3000": {}, "3019-3099": {"vni": {"auto": {}}}}
        
        The function extracts VLAN strings from dict keys regardless of nested structures.
        Example: "10,3000-3199" -> [10, 3000, 3001, ..., 3199]
        
        Returns:
            list: Sorted list of individual VLAN IDs that are already on the bridge.
        """
        bridge_vlans = []
        try:
            # Navigate to bridge section
            # config_data is a list of dicts, each with 'set' key
            for item in config_data:
                if isinstance(item, dict) and 'set' in item:
                    set_data = item['set']
                    if isinstance(set_data, dict) and 'bridge' in set_data:
                        bridge_data = set_data['bridge']
                        if isinstance(bridge_data, dict) and 'domain' in bridge_data:
                            domain_data = bridge_data['domain']
                            if isinstance(domain_data, dict) and 'br_default' in domain_data:
                                br_default_data = domain_data['br_default']
                                if isinstance(br_default_data, dict) and 'vlan' in br_default_data:
                                    vlan_data = br_default_data['vlan']
                                    
                                    # VLAN data structure examples:
                                    # Format 1: {"10,3000-3199": {}}
                                    # Format 2: {"3019-3099": {"vni": {"auto": {}}}}
                                    # Format 3: {"2000,3000": {}, "3019-3099": {"vni": {"auto": {}}}}
                                    # The keys are the VLAN strings we need to parse
                                    # The values can be empty dicts or nested structures - we ignore them
                                    if isinstance(vlan_data, dict):
                                        # Parse each key (VLAN string) - values don't matter
                                        for vlan_key in vlan_data.keys():
                                            if isinstance(vlan_key, str):
                                                # Parse VLAN string (handles "10,3000-3199", "3019-3099", "2000,3000", etc.)
                                                parsed_vlans = self._parse_vlan_string(vlan_key)
                                                bridge_vlans.extend(parsed_vlans)
                                                logger.debug(f"Parsed bridge VLAN key '{vlan_key}' -> {len(parsed_vlans)} VLAN IDs")
                                            elif isinstance(vlan_key, (int, float)):
                                                # Direct VLAN ID (unlikely but handle it)
                                                bridge_vlans.append(int(vlan_key))
                                    elif isinstance(vlan_data, list):
                                        # If it's a list, parse each item
                                        for vlan_item in vlan_data:
                                            if isinstance(vlan_item, str):
                                                bridge_vlans.extend(self._parse_vlan_string(vlan_item))
                                            elif isinstance(vlan_item, (int, float)):
                                                bridge_vlans.append(int(vlan_item))
                                    elif isinstance(vlan_data, str):
                                        # Single string value
                                        bridge_vlans.extend(self._parse_vlan_string(vlan_data))
                                    elif isinstance(vlan_data, (int, float)):
                                        # Single numeric value
                                        bridge_vlans.append(int(vlan_data))
        except Exception as e:
            logger.debug(f"Could not extract bridge VLANs from JSON: {e}")
            import traceback
            logger.debug(f"Traceback: {traceback.format_exc()}")
        
        # Remove duplicates and sort
        bridge_vlans = sorted(list(set(bridge_vlans)))
        if bridge_vlans:
            logger.debug(f"Extracted {len(bridge_vlans)} unique bridge VLAN IDs: {bridge_vlans[:10]}{'...' if len(bridge_vlans) > 10 else ''}")
        return bridge_vlans
    
    def _parse_vlan_string(self, vlan_string):
        """
        Parse VLAN string that can contain:
        - Single VLANs: "10"
        - Comma-separated: "10,20,30"
        - Ranges: "3000-3199"
        - Mixed: "10,3000-3199,4000"
        
        Returns list of VLAN IDs.
        """
        vlan_ids = []
        if not vlan_string:
            return vlan_ids
        
        try:
            # Split by comma to handle multiple VLANs/ranges
            parts = str(vlan_string).split(',')
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                
                # Check if it's a range (e.g., "3000-3199")
                if '-' in part:
                    try:
                        start_str, end_str = part.split('-', 1)
                        start = int(start_str.strip())
                        end = int(end_str.strip())
                        # Add all VLANs in the range
                        vlan_ids.extend(range(start, end + 1))
                    except (ValueError, IndexError):
                        # If parsing fails, try to parse as single VLAN
                        try:
                            vlan_ids.append(int(part))
                        except ValueError:
                            pass
                else:
                    # Single VLAN
                    try:
                        vlan_ids.append(int(part))
                    except ValueError:
                        pass
        except Exception as e:
            logger.debug(f"Error parsing VLAN string '{vlan_string}': {e}")
        
        return vlan_ids
    
    def _format_vlan_list(self, vlan_list):
        """
        Format a list of VLAN IDs into a readable string with ranges.
        Example: [10, 3000, 3001, 3002, ..., 3199] -> "10,3000-3199"
        """
        if not vlan_list:
            return "None"
        
        # Sort the list
        sorted_vlans = sorted(set(vlan_list))
        
        if len(sorted_vlans) == 0:
            return "None"
        if len(sorted_vlans) == 1:
            return str(sorted_vlans[0])
        
        # Group consecutive VLANs into ranges
        result = []
        start = sorted_vlans[0]
        end = sorted_vlans[0]
        
        for i in range(1, len(sorted_vlans)):
            if sorted_vlans[i] == end + 1:
                # Consecutive, extend range
                end = sorted_vlans[i]
            else:
                # Gap found, add current range/individual
                if start == end:
                    result.append(str(start))
                else:
                    result.append(f"{start}-{end}")
                start = sorted_vlans[i]
                end = sorted_vlans[i]
        
        # Add the last range/individual
        if start == end:
            result.append(str(start))
        else:
            result.append(f"{start}-{end}")
        
        return ",".join(result)
    
    def _is_vlan_in_bridge_vlans(self, vlan_id, bridge_vlans):
        """
        Check if a VLAN ID already exists in bridge VLANs (handles both individual VLANs and ranges).
        
        Args:
            vlan_id: VLAN ID to check (int)
            bridge_vlans: List of existing bridge VLANs, which can be:
                - List of integers: [3019, 3020, 3021, ...]
                - List of strings with ranges: ["3019-3099", "4000"]
                - Mixed: [3019, "3020-3030", 4000]
        
        Returns:
            bool: True if VLAN already exists in bridge VLANs, False otherwise
        """
        if not bridge_vlans:
            return False
        
        # Parse all bridge VLANs into a set of individual VLAN IDs
        existing_vlan_ids = set()
        
        for vlan_item in bridge_vlans:
            if isinstance(vlan_item, int):
                existing_vlan_ids.add(vlan_item)
            elif isinstance(vlan_item, str):
                # Could be a range like "3019-3099" or individual like "3019"
                parsed = self._parse_vlan_string(vlan_item)
                existing_vlan_ids.update(parsed)
            else:
                # Try to convert to int
                try:
                    existing_vlan_ids.add(int(vlan_item))
                except (ValueError, TypeError):
                    pass
        
        return vlan_id in existing_vlan_ids
    
    def _deep_merge_dicts(self, base_dict, override_dict):
        """
        Deep merge two dictionaries. Values from override_dict take precedence.
        Used to merge configs from multiple sources (exact match, ranges, etc.).
        """
        if not isinstance(base_dict, dict) or not isinstance(override_dict, dict):
            # If either is not a dict, return override (or base if override is None)
            return override_dict if override_dict is not None else base_dict
        
        result = base_dict.copy()
        for key, value in override_dict.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                # Recursively merge nested dicts
                result[key] = self._deep_merge_dicts(result[key], value)
            else:
                # Override with new value
                result[key] = value
        return result
    
    def _find_interface_config_in_json(self, config_data, interface_name):
        """
        Find ALL interface configurations in JSON that apply to the interface.
        Collects configs from:
        1. Direct/exact match (e.g., swp1s0: {...})
        2. Range matches (e.g., swp1-64: {...}, swp1s0-1: {...})
        3. Bond member configs (if interface is a bond member)
        
        Handles complex ranges like:
        - swp1-64 (simple range)
        - swp1s0-1 (split range)
        - swp1-31,33-64,swp1s0-1,swp2s0-1 (comma-separated ranges)
        
        Returns merged config dict with all applicable configs, or None if not found.
        """
        # Navigate to interface section - extract from "interface" key
        interfaces = None
        for item in config_data:
            if isinstance(item, dict) and 'set' in item:
                set_data = item['set']
                if isinstance(set_data, dict) and 'interface' in set_data:
                    interfaces = set_data['interface']  # Extract from "interface" key
                    break
        
        if not interfaces or not isinstance(interfaces, dict):
            return None
        
        merged_config = {}
        inherited_from = []
        bond_member_of = None
        
        # ALWAYS check for bond membership FIRST (independent of interface config)
        # Interface can exist in config AND be a bond member - both should be detected
        for bond_name, bond_config in interfaces.items():
            if isinstance(bond_config, dict) and 'bond' in bond_config:
                bond_members = bond_config.get('bond', {}).get('member', {})
                if isinstance(bond_members, dict) and interface_name in bond_members:
                    # Interface is a bond member - record bond name and merge bond config
                    bond_member_of = bond_name
                    if isinstance(bond_config, dict):
                        merged_config = self._deep_merge_dicts(merged_config, bond_config)
                    break  # Only one bond per interface
        
        # 1. Check for exact match (highest priority - most specific)
        # This runs independently of bond detection - interface can have its own config too
        if interface_name in interfaces:
            exact_config = interfaces[interface_name]
            if isinstance(exact_config, dict):
                # Merge interface config with bond config (if bond was found above)
                merged_config = self._deep_merge_dicts(merged_config, exact_config)
        
        # 2. Check ALL range matches (collect all, don't stop at first)
        # This handles cases where interface matches multiple ranges
        for range_key, range_config in interfaces.items():
            # Skip exact match (already handled above)
            if range_key == interface_name:
                continue
            
            # Check if interface matches this range
            if self._interface_matches_range(interface_name, range_key):
                if isinstance(range_config, dict):
                    # Merge range config into merged_config
                    merged_config = self._deep_merge_dicts(merged_config, range_config)
                    inherited_from.append(range_key)
        
        # Return config with metadata if we found ANY config (interface config, bond config, or range config)
        # OR if bond membership was detected (even if no config found)
        if merged_config or bond_member_of:
            # Add metadata about inheritance
            if inherited_from:
                merged_config['_inherited_from'] = inherited_from
            if bond_member_of:
                merged_config['_bond_member_of'] = bond_member_of
            
            # Return config dict (even if empty, it will have bond_member_of metadata)
            # This ensures bond membership is always detected and returned
            if not merged_config:
                merged_config = {}  # Return empty dict with just metadata
            
            return merged_config
        
        return None

    def _parse_json_to_nv_commands(self, config_dict, base_path, interface_name):
        """
        Recursively parse JSON structure from nv config show -o json and generate nv set commands.
        This is a fully generic parser with NO hardcoding - it parses and displays whatever is 
        present in the interface configuration (ranges, individual interfaces, bond members, etc.).
        
        Args:
            config_dict: Dictionary from JSON (interface configuration from "interface" key)
            base_path: Current path prefix (e.g., "ip", "bridge domain", "link state")
            interface_name: Interface name for the nv set command
            
        Returns:
            List of nv set command strings - shows all configs as-is, no filtering/hardcoding
        """
        commands = []
        
        if not isinstance(config_dict, dict):
            return commands
        
        for key, value in config_dict.items():
            # Build the path
            path = f"{base_path} {key}" if base_path else key
            
            # Check if value is a dict (nested structure)
            if isinstance(value, dict):
                # Check if dict is empty {} - this means the key itself might be a value or a boolean flag
                if not value:
                    # Empty dict - could be:
                    # 1. Key is a value (e.g., IP address as key: "172.19.1.29/23": {})
                    # 2. Key is a boolean flag (e.g., "up": {}, "on": {}, "enable": {})
                    if self._looks_like_value(key):
                        # Key is the value - use it directly
                        if base_path:
                            # Filter out link-local IPv6
                            if 'address' in base_path.lower() and key.startswith('fe80::'):
                                pass  # Skip link-local
                            else:
                                commands.append(f"nv set interface {interface_name} {base_path} {key}")
                    else:
                        # Empty dict with a key - this is a boolean flag or config option
                        # Show it regardless - no hardcoding, just show what's there
                        commands.append(f"nv set interface {interface_name} {path}")
                else:
                    # Non-empty dict - recurse into nested structure
                    nested_commands = self._parse_json_to_nv_commands(value, path, interface_name)
                    commands.extend(nested_commands)
            else:
                # Leaf value - generate command
                # Filter out link-local IPv6
                if 'address' in key.lower() and isinstance(value, str) and value.startswith('fe80::'):
                    pass  # Skip link-local
                else:
                    # Convert value to string
                    value_str = str(value)
                    commands.append(f"nv set interface {interface_name} {path} {value_str}")
        
        return commands

    def _parse_yaml_to_nv_commands(self, block_lines, base_path, interface_name):
        """
        Recursively parse YAML-like structure from nv config show and generate nv set commands.
        This is a generic parser that doesn't hardcode specific fields - it parses whatever is present.
        
        Args:
            block_lines: List of lines from the YAML-like config
            base_path: Current path prefix (e.g., "ip", "bridge domain")
            interface_name: Interface name for the nv set command
            
        Returns:
            List of nv set command strings
        """
        commands = []
        i = 0
        while i < len(block_lines):
            line = block_lines[i]
            if not line.strip():
                i += 1
                continue
            
            # Get indentation level
            indent = len(line) - len(line.lstrip())
            stripped = line.strip()
            
            # Skip if no colon (not a key:value pair)
            if ':' not in stripped:
                i += 1
                continue
            
            # Parse key: value or key: (with nested structure)
            key_part, value_part = stripped.split(':', 1)
            key = key_part.strip()
            value = value_part.strip()
            
            # Check if next line is more indented (nested structure)
            if i + 1 < len(block_lines):
                next_line = block_lines[i + 1]
                next_indent = len(next_line) - len(next_line.lstrip())
                next_stripped = next_line.strip()
                
                if next_indent > indent and ':' in next_stripped:
                    # Check if next line's key looks like a value (e.g., IP address as key)
                    next_key_part = next_stripped.split(':', 1)[0].strip()
                    if self._looks_like_value(next_key_part) and value == '':
                        # Special case: key is actually a value
                        # e.g., "address:\n  172.19.1.29/23: {}"
                        # The IP address is the value for "address"
                        path = f"{base_path} {key}" if base_path else key
                        if 'address' in key.lower() and next_key_part.startswith('fe80::'):
                            pass  # Skip link-local IPv6
                        else:
                            commands.append(f"nv set interface {interface_name} {path} {next_key_part}")
                        i += 1  # Skip next line
                        continue
                    
                    # Regular nested structure - recurse
                    nested_lines = []
                    for j in range(i + 1, len(block_lines)):
                        nested_line = block_lines[j]
                        nested_indent = len(nested_line) - len(nested_line.lstrip())
                        if nested_indent <= indent:
                            break
                        nested_lines.append(nested_line)
                    
                    # Recursively parse nested structure
                    nested_commands = self._parse_yaml_to_nv_commands(
                        nested_lines, 
                        f"{base_path} {key}" if base_path else key,
                        interface_name
                    )
                    commands.extend(nested_commands)
                    i = j
                    continue
            
            # Leaf value - generate command
            # Check if key itself looks like a value (e.g., IP address as key: "172.19.1.29/23: {}")
            if self._looks_like_value(key) and (value == '' or value == '{}'):
                # Key is the value - use it directly
                path = base_path if base_path else ""
                if path:
                    # Filter out link-local IPv6
                    if 'address' in path.lower() and key.startswith('fe80::'):
                        pass  # Skip link-local
                    else:
                        commands.append(f"nv set interface {interface_name} {path} {key}")
            elif value and value != '{}':
                # Value is on same line: "key: value"
                value_clean = value.strip('{}').strip()
                if value_clean:
                    path = f"{base_path} {key}" if base_path else key
                    # Filter out link-local IPv6
                    if 'address' in key.lower() and value_clean.startswith('fe80::'):
                        pass  # Skip link-local
                    else:
                        commands.append(f"nv set interface {interface_name} {path} {value_clean}")
            # If value is empty and we didn't recurse, it's a parent key with no direct value
            
            i += 1
        
        return commands

    def _get_current_device_config(self, device, interface_name, platform):
        """
        Get current interface configuration from device (read-only).
        Always tries to get REAL config from device using CLI commands.
        Falls back to NetBox inference only if device is completely unreachable.
        
        Returns:
            dict: {
                'success': bool,
                'current_config': str,  # Current config from device
                'source': 'device'|'netbox'|'error',
                'timestamp': str,  # Timestamp of config fetch
                'error': str (if failed)
            }
        """
        napalm_manager = None
        try:
            from django.utils import timezone
            napalm_manager = NAPALMDeviceManager(device)
            timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            
            if platform == 'cumulus':
                # For Cumulus, use nv config show (most complete, shows bridge/VLAN configs)
                # Note: We don't use nv show interface -o json as fallback because it's incomplete
                # (missing gateway, missing bridge access VLANs) - better to show "no config" than false info
                try:
                    if napalm_manager.connect():
                        connection = napalm_manager.connection
                        
                        # Primary method: Use nv config show (more complete, shows bridge/VLAN configs)
                        # Add retry logic in case command fails if sent too early
                        current_config = None
                        device_connected = True  # Track if device is actually connected
                        device_uptime = None  # Track device uptime for connection verification
                        bridge_vlans = []  # Track bridge VLANs extracted from config
                        bond_member_of = None  # Track bond interface name if this interface is a bond member
                        bond_interface_config_commands = []  # Track bond interface config commands
                        try:
                            if hasattr(connection, 'cli'):
                                # Check device uptime to verify connection
                                try:
                                    uptime_output = connection.cli(['uptime'])
                                    if uptime_output:
                                        if isinstance(uptime_output, dict):
                                            device_uptime = list(uptime_output.values())[0] if uptime_output else None
                                        else:
                                            device_uptime = str(uptime_output).strip() if uptime_output else None
                                        if device_uptime:
                                            logger.debug(f"Device {device.name} uptime: {device_uptime}")
                                except Exception as e_uptime:
                                    logger.debug(f"Could not get uptime for {device.name}: {e_uptime}")
                                
                                # Primary: Use nv config show -o json (more reliable than YAML parsing)
                                # Retry up to 3 times with 1 second delay between retries
                                # Initialize config_json_str before loop to ensure it's always in scope
                                config_show_output = None
                                config_json_str = None  # Initialize to None - will be set in loop if successful
                                max_retries = 3
                                for attempt in range(max_retries):
                                    try:
                                        config_show_output = connection.cli(['nv config show -o json'])
                                        
                                        # If cli() returns None, try Netmiko fallback (Cumulus driver may not implement cli() properly)
                                        if config_show_output is None and hasattr(connection, 'device') and hasattr(connection.device, 'send_command'):
                                            logger.debug(f"cli() returned None, falling back to Netmiko send_command() for {device.name}")
                                            try:
                                                config_show_output = connection.device.send_command('nv config show -o json', read_timeout=60)
                                            except Exception as netmiko_error:
                                                logger.debug(f"Netmiko fallback also failed: {netmiko_error}")
                                                config_show_output = None
                                        
                                        if config_show_output:
                                            # Extract output (might be keyed by command)
                                            if isinstance(config_show_output, dict):
                                                if 'nv config show -o json' in config_show_output:
                                                    config_json_str = config_show_output['nv config show -o json']
                                                elif 'nv config show' in config_show_output:
                                                    config_json_str = config_show_output['nv config show']
                                                else:
                                                    config_json_str = list(config_show_output.values())[0] if config_show_output else None
                                            else:
                                                # Netmiko returns string directly
                                                config_json_str = str(config_show_output).strip()
                                            
                                            if config_json_str and config_json_str.strip():
                                                break  # Success, exit retry loop
                                        if attempt < max_retries - 1:
                                            import time
                                            time.sleep(1)  # Wait 1 second before retry
                                            logger.debug(f"nv config show attempt {attempt + 1} failed, retrying...")
                                    except Exception as e_retry:
                                        if attempt < max_retries - 1:
                                            import time
                                            time.sleep(1)
                                            logger.debug(f"nv config show attempt {attempt + 1} failed with error: {e_retry}, retrying...")
                                        else:
                                            logger.warning(f"nv config show failed after {max_retries} attempts: {e_retry}")
                                
                                # Parse JSON config if we got it
                                # config_json_str is initialized to None before the loop, so it's always defined
                                json_parsed_successfully = False
                                if config_json_str and config_json_str.strip():
                                    import json
                                    command_lines = []
                                    
                                    try:
                                        # Parse JSON
                                        config_data = json.loads(config_json_str)
                                        json_parsed_successfully = True  # Mark that we successfully parsed JSON
                                        
                                        # Extract bridge VLANs for later use (to check if VLAN already exists)
                                        bridge_vlans = self._get_bridge_vlans_from_json(config_data)
                                        
                                        # Find interface config (handles ranges and bond members)
                                        interface_config = self._find_interface_config_in_json(config_data, interface_name)
                                        
                                        # Check if config is inherited from range or bond
                                        inherited_from = None
                                        bond_member_of = None
                                        bond_interface_config = None
                                        bond_interface_config_commands = []
                                        if isinstance(interface_config, dict):
                                            inherited_from = interface_config.pop('_inherited_from', None)
                                            bond_member_of = interface_config.pop('_bond_member_of', None)
                                        
                                        # If interface is a bond member, get the bond interface config
                                        if bond_member_of:
                                            bond_interface_config = self._find_interface_config_in_json(config_data, bond_member_of)
                                            if bond_interface_config:
                                                # Remove metadata from bond config
                                                if isinstance(bond_interface_config, dict):
                                                    bond_interface_config.pop('_inherited_from', None)
                                                    bond_interface_config.pop('_bond_member_of', None)
                                                # Convert bond interface config to commands
                                                bond_parsed_commands = self._parse_json_to_nv_commands(bond_interface_config, "", bond_member_of)
                                                bond_interface_config_commands.extend(bond_parsed_commands)
                                        
                                        if interface_config:
                                            # Convert JSON structure to nv set commands
                                            parsed_commands = self._parse_json_to_nv_commands(interface_config, "", interface_name)
                                            command_lines.extend(parsed_commands)
                                            
                                            # Don't add inheritance notes - just show actual configs
                                            # (inheritance info is metadata, not actual config)
                                        
                                        if command_lines:
                                            current_config = '\n'.join(command_lines)
                                            # bridge_vlans is already extracted and stored in the variable above
                                        else:
                                            # Interface not found in config or has no configuration commands
                                            # But still show minimal config if it exists (like link state up)
                                            if interface_config:
                                                # Interface exists but has minimal/no config - show that
                                                # Don't add inheritance notes - just show actual configs
                                                current_config = f"(interface {interface_name} exists but has minimal configuration)"
                                            else:
                                                # Interface not found in JSON - check if it's a bond member
                                                # Even if interface config wasn't found, it might be a bond member
                                                if not bond_member_of and config_data:
                                                    try:
                                                        for item in config_data:
                                                            if isinstance(item, dict) and 'set' in item:
                                                                set_data = item.get('set', {})
                                                                if isinstance(set_data, dict) and 'interface' in set_data:
                                                                    interfaces = set_data.get('interface', {})
                                                                    if isinstance(interfaces, dict):
                                                                        for potential_bond_name, potential_bond_config in interfaces.items():
                                                                            if isinstance(potential_bond_config, dict) and 'bond' in potential_bond_config:
                                                                                bond_data = potential_bond_config.get('bond', {})
                                                                                if isinstance(bond_data, dict):
                                                                                    members = bond_data.get('member', {})
                                                                                    if isinstance(members, dict) and interface_name in members:
                                                                                        bond_member_of = potential_bond_name
                                                                                        # Get bond config
                                                                                        bond_interface_config = self._find_interface_config_in_json(config_data, bond_member_of)
                                                                                        if bond_interface_config:
                                                                                            if isinstance(bond_interface_config, dict):
                                                                                                bond_interface_config.pop('_inherited_from', None)
                                                                                                bond_interface_config.pop('_bond_member_of', None)
                                                                                            bond_parsed_commands = self._parse_json_to_nv_commands(bond_interface_config, "", bond_member_of)
                                                                                            bond_interface_config_commands.extend(bond_parsed_commands)
                                                                                        break
                                                                        if bond_member_of:
                                                                            break
                                                    except Exception as bond_check_error:
                                                        logger.debug(f"Could not check bond membership when interface not found: {bond_check_error}")
                                                
                                                # Set current_config message based on whether bond was found
                                                if bond_member_of:
                                                    current_config = f"(interface {interface_name} not found in config, but detected as bond member of {bond_member_of})"
                                                else:
                                                    # Interface not found in JSON - try grep fallback
                                                    current_config = None
                                    except json.JSONDecodeError as e:
                                        logger.warning(f"Failed to parse JSON config for {device.name}:{interface_name}: {e}")
                                        current_config = None  # JSON parse failed - will try grep fallback
                                        
                                        # Still try to detect bond membership even if JSON parse failed
                                        if not bond_member_of and config_data:
                                            try:
                                                # Check if interface is a bond member by looking through all bonds in config
                                                for item in config_data:
                                                    if isinstance(item, dict) and 'set' in item:
                                                        set_data = item.get('set', {})
                                                        if isinstance(set_data, dict) and 'interface' in set_data:
                                                            interfaces = set_data.get('interface', {})
                                                            if isinstance(interfaces, dict):
                                                                for potential_bond_name, potential_bond_config in interfaces.items():
                                                                    if isinstance(potential_bond_config, dict) and 'bond' in potential_bond_config:
                                                                        bond_data = potential_bond_config.get('bond', {})
                                                                        if isinstance(bond_data, dict):
                                                                            members = bond_data.get('member', {})
                                                                            if isinstance(members, dict) and interface_name in members:
                                                                                bond_member_of = potential_bond_name
                                                                                # Try to get bond config even though interface config failed
                                                                                bond_interface_config = self._find_interface_config_in_json(config_data, bond_member_of)
                                                                                if bond_interface_config:
                                                                                    if isinstance(bond_interface_config, dict):
                                                                                        bond_interface_config.pop('_inherited_from', None)
                                                                                        bond_interface_config.pop('_bond_member_of', None)
                                                                                    bond_parsed_commands = self._parse_json_to_nv_commands(bond_interface_config, "", bond_member_of)
                                                                                    bond_interface_config_commands.extend(bond_parsed_commands)
                                                                                break
                                                            if bond_member_of:
                                                                break
                                            except Exception as bond_check_error:
                                                logger.debug(f"Could not check bond membership after JSON parse error: {bond_check_error}")
                                    except Exception as e:
                                        error_msg = str(e)
                                        logger.warning(f"Error processing JSON config for {device.name}:{interface_name}: {error_msg}")
                                        
                                        # Try to detect bond membership even if config processing failed
                                        if not bond_member_of and config_data:
                                            try:
                                                # Check if interface is a bond member by looking through all bonds in config
                                                for item in config_data:
                                                    if isinstance(item, dict) and 'set' in item:
                                                        set_data = item.get('set', {})
                                                        if isinstance(set_data, dict) and 'interface' in set_data:
                                                            interfaces = set_data.get('interface', {})
                                                            if isinstance(interfaces, dict):
                                                                for potential_bond_name, potential_bond_config in interfaces.items():
                                                                    if isinstance(potential_bond_config, dict) and 'bond' in potential_bond_config:
                                                                        bond_data = potential_bond_config.get('bond', {})
                                                                        if isinstance(bond_data, dict):
                                                                            members = bond_data.get('member', {})
                                                                            if isinstance(members, dict) and interface_name in members:
                                                                                bond_member_of = potential_bond_name
                                                                                # Try to get bond config even though interface config failed
                                                                                bond_interface_config = self._find_interface_config_in_json(config_data, bond_member_of)
                                                                                if bond_interface_config:
                                                                                    if isinstance(bond_interface_config, dict):
                                                                                        bond_interface_config.pop('_inherited_from', None)
                                                                                        bond_interface_config.pop('_bond_member_of', None)
                                                                                    bond_parsed_commands = self._parse_json_to_nv_commands(bond_interface_config, "", bond_member_of)
                                                                                    bond_interface_config_commands.extend(bond_parsed_commands)
                                                                                break
                                                            if bond_member_of:
                                                                break
                                            except Exception as bond_check_error:
                                                logger.debug(f"Could not check bond membership after config processing error: {bond_check_error}")
                                        
                                        # If it's a variable error, provide more context
                                        if 'cannot access local variable' in error_msg or 'not associated with a value' in error_msg:
                                            logger.error(f"Variable scope error in config parsing - config_json_str may not be initialized. Error: {error_msg}")
                                        current_config = None  # Processing error - will try grep fallback
                                
                                # Fallback: If interface not found (even if JSON parsed successfully) or JSON parsing failed
                                # Try grep fallback to catch interfaces that might be in ranges we didn't match properly
                                if not current_config:
                                    logger.debug(f"nv config show -o json didn't find {interface_name} or returned empty. Trying YAML grep fallback...")
                                    try:
                                        # Use grep with context: nv config show | grep -A15 -B15 {interface_name}
                                        # Note: grep works better with YAML format (line-based)
                                        grep_command = f'nv config show | grep -A15 -B15 {interface_name}'
                                        grep_output = connection.cli([grep_command])
                                        
                                        if grep_output:
                                            # Extract output
                                            grep_result = None
                                            if isinstance(grep_output, dict):
                                                if grep_command in grep_output:
                                                    grep_result = grep_output[grep_command]
                                                else:
                                                    grep_result = list(grep_output.values())[0] if grep_output else None
                                            else:
                                                grep_result = str(grep_output)
                                            
                                            if grep_result and grep_result.strip():
                                                # Parse grep output (has context lines before/after)
                                                import re
                                                command_lines = []
                                                
                                                # Find the interface line in grep output
                                                grep_lines = grep_result.split('\n')
                                                interface_found = False
                                                interface_block_lines = []
                                                interface_indent = None
                                                range_key_found = None
                                                
                                                # First, try exact match
                                                for i, line in enumerate(grep_lines):
                                                    stripped = line.strip()
                                                    if stripped.startswith(f'{interface_name}:'):
                                                        interface_found = True
                                                        interface_indent = len(line) - len(line.lstrip())
                                                        # Start collecting from this line
                                                        interface_block_lines.append(line)
                                                        # Collect following lines until we hit another interface or section
                                                        for j in range(i + 1, len(grep_lines)):
                                                            next_line = grep_lines[j]
                                                            if not next_line.strip():
                                                                continue
                                                            next_indent = len(next_line) - len(next_line.lstrip())
                                                            # Stop if we hit a line at same or less indent with colon (new interface/section)
                                                            if next_indent <= interface_indent and ':' in next_line.strip():
                                                                break
                                                            interface_block_lines.append(next_line)
                                                        break
                                                
                                                # If exact match not found, try to find range that contains this interface
                                                if not interface_found:
                                                    # Try simple pattern first: swp5
                                                    interface_match = re.match(r'^([a-zA-Z]+)(\d+)$', interface_name)
                                                    if interface_match:
                                                        iface_prefix = interface_match.group(1)
                                                        iface_num = int(interface_match.group(2))
                                                        
                                                        # Look for range patterns like swp1-32, swp1-2, etc.
                                                        for i, line in enumerate(grep_lines):
                                                            stripped = line.strip()
                                                            # Check if this line is a range that might contain our interface
                                                            # Pattern: swp1-32:, bond3-6:, etc.
                                                            range_match = re.match(r'^([a-zA-Z]+)(\d+)-(\d+):\s*$', stripped)
                                                            if range_match:
                                                                range_prefix = range_match.group(1)
                                                                range_start = int(range_match.group(2))
                                                                range_end = int(range_match.group(3))
                                                                
                                                                # Check if our interface is in this range
                                                                if iface_prefix == range_prefix and range_start <= iface_num <= range_end:
                                                                    range_key_found = f"{range_prefix}{range_start}-{range_end}"
                                                                    interface_found = True
                                                                    interface_indent = len(line) - len(line.lstrip())
                                                                    # Start collecting from this line
                                                                    interface_block_lines.append(line)
                                                                    # Collect following lines until we hit another interface or section
                                                                    for j in range(i + 1, len(grep_lines)):
                                                                        next_line = grep_lines[j]
                                                                        if not next_line.strip():
                                                                            continue
                                                                        next_indent = len(next_line) - len(next_line.lstrip())
                                                                        # Stop if we hit a line at same or less indent with colon (new interface/section)
                                                                        if next_indent <= interface_indent and ':' in next_line.strip():
                                                                            break
                                                                        interface_block_lines.append(next_line)
                                                                    break
                                                    
                                                    # Try complex pattern: swp1s0
                                                    if not interface_found:
                                                        interface_match_complex = re.match(r'^([a-zA-Z]+)(\d+)([a-zA-Z]+)(\d+)$', interface_name)
                                                        if interface_match_complex:
                                                            iface_prefix = interface_match_complex.group(1)
                                                            iface_prefix_num = int(interface_match_complex.group(2))
                                                            iface_suffix = interface_match_complex.group(3)
                                                            iface_suffix_num = int(interface_match_complex.group(4))
                                                            
                                                            # Look for range patterns like swp1s0-1:, swp2s0-3:, etc.
                                                            for i, line in enumerate(grep_lines):
                                                                stripped = line.strip()
                                                                # Pattern: swp1s0-1:, swp2s0-3:, etc.
                                                                range_match_complex = re.match(r'^([a-zA-Z]+)(\d+)([a-zA-Z]+)(\d+)-(\d+):\s*$', stripped)
                                                                if range_match_complex:
                                                                    range_prefix = range_match_complex.group(1)
                                                                    range_prefix_num = int(range_match_complex.group(2))
                                                                    range_suffix = range_match_complex.group(3)
                                                                    range_start = int(range_match_complex.group(4))
                                                                    range_end = int(range_match_complex.group(5))
                                                                    
                                                                    # Check if our interface is in this range
                                                                    if (iface_prefix == range_prefix and 
                                                                        iface_prefix_num == range_prefix_num and 
                                                                        iface_suffix == range_suffix and 
                                                                        range_start <= iface_suffix_num <= range_end):
                                                                        range_key_found = f"{range_prefix}{range_prefix_num}{range_suffix}{range_start}-{range_end}"
                                                                        interface_found = True
                                                                        interface_indent = len(line) - len(line.lstrip())
                                                                        # Start collecting from this line
                                                                        interface_block_lines.append(line)
                                                                        # Collect following lines until we hit another interface or section
                                                                        for j in range(i + 1, len(grep_lines)):
                                                                            next_line = grep_lines[j]
                                                                            if not next_line.strip():
                                                                                continue
                                                                            next_indent = len(next_line) - len(next_line.lstrip())
                                                                            # Stop if we hit a line at same or less indent with colon (new interface/section)
                                                                            if next_indent <= interface_indent and ':' in next_line.strip():
                                                                                break
                                                                            interface_block_lines.append(next_line)
                                                                        break
                                                
                                                if interface_found and interface_block_lines:
                                                    # Use the same generic parser for grep output
                                                    parsed_commands = self._parse_yaml_to_nv_commands(interface_block_lines, "", interface_name)
                                                    
                                                    # Don't add inheritance notes - just show actual configs
                                                    # Add all parsed commands (link-local IPv6 already filtered in parser)
                                                    command_lines.extend(parsed_commands)
                                                
                                                if command_lines:
                                                    current_config = '\n'.join(command_lines)
                                    except Exception as e_grep:
                                        logger.debug(f"Grep fallback failed for {device.name}:{interface_name}: {e_grep}")
                                
                                # Final check: If both methods failed, show appropriate message
                                if not current_config:
                                    if device_connected:
                                        # Device is connected but no config found
                                        current_config = f"(no configuration found for interface {interface_name})"
                                    else:
                                        # Device connection issue
                                        current_config = f"(unable to retrieve config from device for interface {interface_name})"
                            else:
                                # No CLI method, try get_config
                                config = napalm_manager.get_config(retrieve='running')
                                if config:
                                    # Try to extract interface section from config
                                    if isinstance(config, dict) and 'running' in config:
                                        running_config = config['running']
                                        if isinstance(running_config, str) and interface_name in running_config:
                                            # Extract interface section
                                            lines = running_config.split('\n')
                                            interface_lines = []
                                            in_interface = False
                                            for line in lines:
                                                if f"interface {interface_name}" in line or f"{interface_name}" in line:
                                                    in_interface = True
                                                if in_interface:
                                                    interface_lines.append(line)
                                                    # Stop at next interface or end
                                                    if line.strip().startswith('interface ') and interface_name not in line and in_interface:
                                                        break
                                            current_config = '\n'.join(interface_lines) if interface_lines else f"(no config found)"
                                        else:
                                            current_config = f"(interface not found in running config)"
                                    else:
                                        current_config = f"(CLI method not available)"
                                else:
                                    current_config = f"(could not retrieve config)"
                            
                            
                            napalm_manager.disconnect()
                            return {
                                'success': True,
                                'current_config': current_config if current_config is not None else f"(no output from device for interface {interface_name})",
                                'source': 'device',
                                'timestamp': timestamp,
                                'device_uptime': device_uptime,
                                '_bridge_vlans': bridge_vlans,  # Include bridge VLANs for checking if VLAN already exists
                                'bond_member_of': bond_member_of,  # Bond interface name if this interface is a bond member
                                'bond_interface_config': '\n'.join(bond_interface_config_commands) if bond_interface_config_commands else None  # Bond interface config commands
                            }
                        except Exception as e2:
                            logger.warning(f"Could not get interface config for {device.name}:{interface_name}: {e2}")
                            napalm_manager.disconnect()
                            # Device was connected but config retrieval failed - not "unreachable"
                            return {
                                'success': False,
                                'current_config': f"ERROR: Could not retrieve config from device: {str(e2)}",
                                'source': 'error',
                                'timestamp': timestamp,
                                'error': str(e2),
                                'device_connected': True,  # Device was connected, but config retrieval failed
                                'bond_member_of': None,
                                'bond_interface_config': None
                            }
                except Exception as e:
                    logger.error(f"Could not connect to device {device.name}:{interface_name}: {e}")
                    if napalm_manager:
                        napalm_manager.disconnect()
                    # Device unreachable - fallback to NetBox with clear marking
                    return self._get_netbox_inferred_config(device, interface_name, platform, device_unreachable=True)
            
            elif platform == 'eos':
                # For EOS, get full interface config using CLI - no hardcoding
                try:
                    if napalm_manager.connect():
                        connection = napalm_manager.connection
                        
                        # Get full interface config using show running-config
                        try:
                            if hasattr(connection, 'cli'):
                                # Get complete interface configuration
                                cli_output = connection.cli([f'show running-config interface {interface_name}'])
                                if cli_output:
                                    # Extract interface section from output - show full config
                                    output = list(cli_output.values())[0] if isinstance(cli_output, dict) else str(cli_output)
                                    # Show the full config as-is from device
                                    current_config = output.strip() if output.strip() else f"interface {interface_name}\n(no config found)"
                                else:
                                    current_config = f"interface {interface_name}\n(show running-config returned empty output)"
                            else:
                                # No CLI method, use get_config
                                config = napalm_manager.get_config(retrieve='running')
                                if config:
                                    # Extract interface section from running config
                                    if isinstance(config, dict) and 'running' in config:
                                        running_config = config['running']
                                        if isinstance(running_config, str) and interface_name in running_config:
                                            # Extract interface section
                                            lines = running_config.split('\n')
                                            interface_lines = []
                                            in_interface = False
                                            for line in lines:
                                                if f"interface {interface_name}" in line:
                                                    in_interface = True
                                                if in_interface:
                                                    interface_lines.append(line)
                                                    # Stop at next interface or end
                                                    if line.strip().startswith('interface ') and interface_name not in line and in_interface:
                                                        break
                                            current_config = '\n'.join(interface_lines) if interface_lines else f"interface {interface_name}\n(no config found in running config)"
                                        else:
                                            current_config = f"interface {interface_name}\n(could not find interface in running config)"
                                    else:
                                        current_config = f"interface {interface_name}\n(could not parse config - CLI method not available)"
                                else:
                                    current_config = f"interface {interface_name}\n(could not retrieve config)"
                            
                            napalm_manager.disconnect()
                            return {
                                'success': True,
                                'current_config': current_config,
                                'source': 'device',
                                'timestamp': timestamp,
                                'bond_member_of': None,  # EOS bond detection not implemented yet
                                'bond_interface_config': None
                            }
                        except Exception as e2:
                            logger.warning(f"Could not get interface config for {device.name}:{interface_name}: {e2}")
                            napalm_manager.disconnect()
                            # Device was connected but config retrieval failed - not "unreachable"
                            return {
                                'success': False,
                                'current_config': f"interface {interface_name} - ERROR: Could not retrieve config from device: {str(e2)}",
                                'source': 'error',
                                'timestamp': timestamp,
                                'error': str(e2),
                                'device_connected': True  # Device was connected, but config retrieval failed
                            }
                except Exception as e:
                    logger.error(f"Could not connect to device {device.name}:{interface_name}: {e}")
                    if napalm_manager:
                        napalm_manager.disconnect()
                    # Device unreachable - fallback to NetBox with clear marking
                    return self._get_netbox_inferred_config(device, interface_name, platform, device_unreachable=True)
            
            # Unknown platform - fallback to NetBox
            return self._get_netbox_inferred_config(device, interface_name, platform, device_unreachable=True)
            
        except Exception as e:
            logger.error(f"Error getting device config for {device.name}:{interface_name}: {e}")
            if napalm_manager:
                try:
                    napalm_manager.disconnect()
                except:
                    pass
            # Device unreachable - fallback to NetBox with clear marking
            return self._get_netbox_inferred_config(device, interface_name, platform, device_unreachable=True)
    
    def _parse_cumulus_cli_output(self, cli_output, interface_name):
        """
        Parse Cumulus CLI output from 'nv show interface' command.
        Extracts bridge domain config or shows full output.
        """
        try:
            if not cli_output:
                return f"interface {interface_name} - no config found"
            
            # Parse text output from nv show
            lines = cli_output.split('\n') if isinstance(cli_output, str) else str(cli_output).split('\n')
            
            # Look for bridge domain access VLAN
            for line in lines:
                line_lower = line.lower().strip()
                # Look for patterns like "access 3020" or "access: 3020"
                if 'bridge' in line_lower and 'domain' in line_lower and 'br_default' in line_lower:
                    # Extract VLAN if present
                    if 'access' in line_lower:
                        # Try to find VLAN number
                        parts = line.split()
                        if 'access' in parts:
                            access_idx = parts.index('access')
                            if access_idx + 1 < len(parts):
                                vlan = parts[access_idx + 1].strip(':')
                                return f"nv set interface {interface_name} bridge domain br_default access {vlan}"
                        # Or check for "access: 3020" format
                        if ':' in line:
                            after_colon = line.split(':', 1)[1].strip()
                            if after_colon.isdigit():
                                return f"nv set interface {interface_name} bridge domain br_default access {after_colon}"
            
            # If we found bridge domain but no access VLAN, return what we have
            if any('bridge' in line.lower() and 'domain' in line.lower() for line in lines):
                return f"interface {interface_name} bridge domain config:\n{cli_output.strip()}"
            
            # No bridge domain found
            return f"interface {interface_name} - no bridge domain config found"
        except Exception as e:
            logger.warning(f"Error parsing Cumulus CLI output for {interface_name}: {e}")
            return f"interface {interface_name}\n{cli_output.strip()}" if cli_output else f"interface {interface_name} - error parsing output"
    
    def _parse_eos_cli_output(self, cli_output, interface_name):
        """
        Parse EOS CLI output from 'show running-config interface' command.
        Extracts interface section.
        """
        try:
            if not cli_output:
                return f"interface {interface_name} - no config found"
            
            # Extract interface section from output
            lines = cli_output.split('\n') if isinstance(cli_output, str) else str(cli_output).split('\n')
            interface_lines = []
            in_interface = False
            
            for line in lines:
                if f"interface {interface_name}" in line:
                    in_interface = True
                    interface_lines.append(line)
                elif in_interface:
                    if line.strip().startswith('interface ') or line.strip() == '!':
                        break
                    interface_lines.append(line)
            
            if interface_lines:
                return '\n'.join(interface_lines)
            else:
                return f"interface {interface_name} - no config found"
        except Exception as e:
            logger.warning(f"Error parsing EOS CLI output for {interface_name}: {e}")
            return f"interface {interface_name}\n{cli_output.strip()}" if cli_output else f"interface {interface_name} - error parsing output"
    
    def _parse_cumulus_interface_config(self, config_output, interface_name):
        """
        Parse Cumulus config to extract interface bridge domain settings.
        Handles JSON config from get_config() with format='json'.
        """
        try:
            import json
            
            # Handle different input formats
            config_dict = None
            if isinstance(config_output, dict):
                # If it's already a dict, check for 'running' key
                if 'running' in config_output:
                    running_config = config_output['running']
                    # If running is a string, try to parse as JSON
                    if isinstance(running_config, str):
                        try:
                            config_dict = json.loads(running_config)
                        except json.JSONDecodeError:
                            # Not JSON, return placeholder
                            return f"interface {interface_name} - bridge domain config (text format, cannot parse)"
                    else:
                        config_dict = running_config
                else:
                    config_dict = config_output
            elif isinstance(config_output, str):
                try:
                    config_dict = json.loads(config_output)
                except json.JSONDecodeError:
                    # Not JSON, return placeholder
                    return f"interface {interface_name} - bridge domain config (text format, cannot parse)"
            
            # Navigate NVUE JSON structure: interface -> bridge -> domain -> br_default -> access
            if config_dict and isinstance(config_dict, dict):
                # NVUE JSON structure: {"interface": {"eth1": {"bridge": {"domain": {"br_default": {"access": 3020}}}}}}
                if 'interface' in config_dict:
                    interfaces = config_dict['interface']
                    if interface_name in interfaces:
                        iface_config = interfaces[interface_name]
                        bridge_config = iface_config.get('bridge', {})
                        domain_config = bridge_config.get('domain', {})
                        br_default = domain_config.get('br_default', {})
                        access_vlan = br_default.get('access')
                        
                        if access_vlan:
                            return f"nv set interface {interface_name} bridge domain br_default access {access_vlan}"
                
                # Alternative structure: direct interface name at root
                if interface_name in config_dict:
                    iface_config = config_dict[interface_name]
                    bridge_config = iface_config.get('bridge', {})
                    domain_config = bridge_config.get('domain', {})
                    br_default = domain_config.get('br_default', {})
                    access_vlan = br_default.get('access')
                    
                    if access_vlan:
                        return f"nv set interface {interface_name} bridge domain br_default access {access_vlan}"
            
            # If we couldn't parse it, return a generic message
            return f"interface {interface_name} - no bridge domain config found (interface may not be configured for bridging)"
        except Exception as e:
            logger.warning(f"Error parsing Cumulus config for {interface_name}: {e}")
            return f"interface {interface_name} - error parsing config: {str(e)}"
    
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
    
    def _get_netbox_inferred_config(self, device, interface_name, platform, device_unreachable=False):
        """
        Infer current config from NetBox interface state.
        Used as fallback when device is unreachable.
        Clearly marks config as ESTIMATED/INFERRED, not real device config.
        """
        from django.utils import timezone
        
        try:
            interface = Interface.objects.get(device=device, name=interface_name)
            interface.refresh_from_db()
            
            untagged_vlan = interface.untagged_vlan.vid if interface.untagged_vlan else None
            tagged_vlans = list(interface.tagged_vlans.values_list('vid', flat=True))
            mode = interface.mode if hasattr(interface, 'mode') else None
            
            # Check if interface has IP address (routed)
            has_ip = interface.ip_addresses.exists()
            
            if has_ip:
                # Routed interface - show IP info
                ip_lines = []
                for ip_addr in interface.ip_addresses.all():
                    ip_lines.append(f"  ip address {ip_addr.address}")
                if hasattr(interface, 'vrf') and interface.vrf:
                    ip_lines.append(f"  vrf: {interface.vrf.name}")
                config = f"interface {interface_name}\n" + "\n".join(ip_lines) if ip_lines else f"interface {interface_name} (routed interface with IP)"
            elif platform == 'cumulus':
                if untagged_vlan:
                    config = f"nv set interface {interface_name} bridge domain br_default access {untagged_vlan}"
                else:
                    config = f"interface {interface_name} - no VLAN configured"
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
                config = f"interface {interface_name} - unknown platform"
            
            # Clearly mark as ESTIMATED if device was unreachable
            if device_unreachable:
                config = f"[ESTIMATED FROM NETBOX - DEVICE UNREACHABLE]\n{config}\n\nWARNING: This is inferred from NetBox data, not actual device configuration!"
            
            timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            return {
                'success': True,
                'current_config': config,
                'source': 'netbox',
                'timestamp': timestamp
            }
        except Interface.DoesNotExist:
            timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            return {
                'success': False,
                'current_config': f"Interface {interface_name} not found in NetBox",
                'source': 'error',
                'timestamp': timestamp,
                'error': 'Interface not found'
            }
    
    def _get_netbox_current_state(self, device, interface_name, vlan_id):
        """
        Get current NetBox interface state (comprehensive - VLAN-relevant only).
        
        Returns:
            dict: {
                'current': {
                    'mode': str or None,
                    'untagged_vlan': int or None,
                    'tagged_vlans': list of ints,
                    'ip_addresses': list of str,
                    'vrf': str or None,
                    'cable_status': str,
                    'connected_to': str or None,
                    'enabled': bool,
                    'port_channel_member': bool,
                },
                'proposed': {
                    'mode': str,
                    'untagged_vlan': int,
                    'tagged_vlans': list of ints,
                    'ip_addresses': list (empty - will be removed),
                    'vrf': None (will be removed),
                    'cable_status': str (unchanged),
                    'connected_to': str or None (unchanged),
                    'enabled': bool (unchanged),
                    'port_channel_member': bool (unchanged),
                },
                'has_changes': bool
            }
        """
        try:
            interface = Interface.objects.get(device=device, name=interface_name)
            interface.refresh_from_db()
            
            # Current state
            current_mode = interface.mode if hasattr(interface, 'mode') else None
            current_untagged = interface.untagged_vlan.vid if interface.untagged_vlan else None
            current_tagged = list(interface.tagged_vlans.values_list('vid', flat=True))
            current_ip_addresses = [str(ip.address) for ip in interface.ip_addresses.all()]
            
            # Get VRF - try multiple ways to access it
            current_vrf = None
            if hasattr(interface, 'vrf'):
                if interface.vrf:
                    current_vrf = interface.vrf.name if hasattr(interface.vrf, 'name') else str(interface.vrf)
            # Also check if VRF is on IP addresses
            if not current_vrf:
                for ip_addr in interface.ip_addresses.all():
                    if hasattr(ip_addr, 'vrf') and ip_addr.vrf:
                        current_vrf = ip_addr.vrf.name if hasattr(ip_addr.vrf, 'name') else str(ip_addr.vrf)
                        break
            current_cable_status = 'Connected' if interface.cable else 'Not Connected'
            current_connected_to = None
            if interface.cable:
                # Get connected device and interface
                if hasattr(interface.cable, 'termination_a') and hasattr(interface.cable, 'termination_b'):
                    term_a = interface.cable.termination_a
                    term_b = interface.cable.termination_b
                    # Find which termination is not our interface
                    if hasattr(term_a, 'device') and term_a.device == device and hasattr(term_a, 'name') and term_a.name == interface_name:
                        # We are term_a, connected to term_b
                        if hasattr(term_b, 'device') and hasattr(term_b, 'name'):
                            current_connected_to = f"{term_b.device.name} ({term_b.name})"
                    elif hasattr(term_b, 'device') and term_b.device == device and hasattr(term_b, 'name') and term_b.name == interface_name:
                        # We are term_b, connected to term_a
                        if hasattr(term_a, 'device') and hasattr(term_a, 'name'):
                            current_connected_to = f"{term_a.device.name} ({term_a.name})"
            current_enabled = interface.enabled if hasattr(interface, 'enabled') else True
            current_port_channel_member = bool(interface.lag) if hasattr(interface, 'lag') else False
            
            # Proposed state - VLAN deployment will replace existing config
            proposed_mode = 'tagged'  # Always set to tagged
            proposed_untagged = vlan_id
            proposed_tagged = []  # Clear tagged VLANs for access mode deployment
            proposed_ip_addresses = []  # Remove IP addresses (routed → bridged)
            proposed_vrf = None  # Remove VRF (routed → bridged)
            proposed_cable_status = current_cable_status  # Keep cable status
            proposed_connected_to = current_connected_to  # Keep connected device
            proposed_enabled = current_enabled  # Keep enabled status
            proposed_port_channel_member = current_port_channel_member  # Keep port-channel status
            
            # Check if there are changes
            has_changes = (
                current_mode != proposed_mode or
                current_untagged != proposed_untagged or
                set(current_tagged) != set(proposed_tagged) or
                set(current_ip_addresses) != set(proposed_ip_addresses) or
                current_vrf != proposed_vrf
            )
            
            return {
                'current': {
                    'mode': current_mode,
                    'untagged_vlan': current_untagged,
                    'tagged_vlans': current_tagged,
                    'ip_addresses': current_ip_addresses,
                    'vrf': current_vrf,
                    'cable_status': current_cable_status,
                    'connected_to': current_connected_to,
                    'enabled': current_enabled,
                    'port_channel_member': current_port_channel_member,
                },
                'proposed': {
                    'mode': proposed_mode,
                    'untagged_vlan': proposed_untagged,
                    'tagged_vlans': proposed_tagged,
                    'ip_addresses': proposed_ip_addresses,
                    'vrf': proposed_vrf,
                    'cable_status': proposed_cable_status,
                    'connected_to': proposed_connected_to,
                    'enabled': proposed_enabled,
                    'port_channel_member': proposed_port_channel_member,
                },
                'has_changes': has_changes
            }
        except Interface.DoesNotExist:
            return {
                'current': {
                    'mode': None,
                    'untagged_vlan': None,
                    'tagged_vlans': [],
                    'ip_addresses': [],
                    'vrf': None,
                    'cable_status': 'Not Connected',
                    'connected_to': None,
                    'enabled': True,
                    'port_channel_member': False,
                },
                'proposed': {
                    'mode': 'tagged',
                    'untagged_vlan': vlan_id,
                    'tagged_vlans': [],
                    'ip_addresses': [],
                    'vrf': None,
                    'cable_status': 'Not Connected',
                    'connected_to': None,
                    'enabled': True,
                    'port_channel_member': False,
                },
                'has_changes': True
            }
    
    def _generate_config_diff(self, current_config, proposed_config, platform, device=None, interface_name=None, bridge_vlans=None):
        """
        Generate a diff between current and proposed config.
        
        Args:
            current_config: Current device configuration
            proposed_config: Proposed configuration command
            platform: Platform type ('cumulus' or 'eos')
            device: Device object (optional, for bridge-level VLAN checks)
            interface_name: Interface name (optional, for bridge-level VLAN checks)
        
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
            # For Cumulus, show what's currently configured vs what commands will be executed
            if "no current config" in current_config.lower() or "no config found" in current_config.lower() or "(no configuration" in current_config.lower() or "ERROR:" in current_config:
                # No current config - show only proposed with + signs
                proposed_lines = [line.strip() for line in proposed_config.split('\n') if line.strip()]
                for line in proposed_lines:
                    diff_lines.append(f"  + {line}")
                diff_lines.append("")
                diff_lines.append("Note: This interface has no current VLAN configuration.")
            else:
                # Parse current config commands
                current_lines = [line.strip() for line in current_config.split('\n') if line.strip()]
                current_bridge_configs = []
                current_vlan_configs = []  # All VLAN-related configs (bridge domain access)
                has_ip_or_vrf = False
                
                # Find current bridge domain configs (these will be replaced)
                # IMPORTANT: We only show bridge domain configs as "removed/replaced"
                # We do NOT show link state, type, or other non-VLAN configs (these are preserved)
                # Safety check: IP/VRF configs should be blocked by validation and should not appear here
                for line in current_lines:
                    if line.startswith('nv set'):
                        # Skip comments
                        if line.startswith('# Note:'):
                            continue
                        # Skip link state and type - these are NOT VLAN-related and will be preserved
                        if 'link state' in line or 'type ' in line or 'bond member' in line or 'evpn' in line:
                            continue  # These are preserved, not removed
                        # Track bridge domain access VLAN configs (these will be replaced by new VLAN config)
                        # IMPORTANT: In Cumulus, an interface can be part of br_default AND have an access VLAN
                        # So we only remove/replace lines with "access" - NOT the base "bridge domain br_default" line
                        # - bridge domain br_default access <vlan> (old untagged/access VLAN) -> REMOVE/REPLACE
                        # - bridge domain br_default (base membership) -> KEEP (not removed)
                        # Note: Tagged VLANs are configured at the bridge level, not per interface
                        if 'bridge domain' in line and 'access' in line:
                            # Only track lines with "access" - these are the ones being replaced
                            current_bridge_configs.append(line)
                            current_vlan_configs.append(line)
                        # Safety check: IP/VRF configs should be blocked by validation
                        elif 'ip address' in line or 'ip gateway' in line or 'ip vrf' in line:
                            has_ip_or_vrf = True
                
                # Warn if IP/VRF detected (indicates validation bug - these ports should be blocked)
                if has_ip_or_vrf:
                    diff_lines.append("[WARN] Interface has IP address or VRF configuration.")
                    diff_lines.append("      This interface should have been blocked by validation.")
                    diff_lines.append("      Deployment will NOT proceed for interfaces with IP/VRF.")
                    diff_lines.append("")
                
                # Show current VLAN configs with "-" signs (what will be removed/replaced)
                if current_vlan_configs:
                    for item in current_vlan_configs:
                        diff_lines.append(f"  - {item}")
                else:
                    # No current VLAN configs to remove
                    diff_lines.append("  (no current VLAN configuration to remove)")
                diff_lines.append("")
                
                # Show proposed configs with "+" signs (what will be added)
                proposed_lines = [line.strip() for line in proposed_config.split('\n') if line.strip()]
                for line in proposed_lines:
                    diff_lines.append(f"  + {line}")
                # Note: Bridge VLAN commands are already included in proposed_config if needed
                # (they're generated in _generate_config_from_netbox or _generate_vlan_config)
                diff_lines.append("")
                diff_lines.append("Note: The interface can be part of 'br_default' bridge domain AND have an access VLAN.")
                diff_lines.append("      Only the access VLAN is replaced - bridge domain membership is preserved.")
                diff_lines.append("      The bridge 'nv set' command is additive - it adds the VLAN to the")
                diff_lines.append("      existing bridge VLAN list without replacing it.")
                
        elif platform == 'eos':
            # For EOS, show what's currently configured vs what commands will be executed
            current_lines = [line.strip() for line in current_config.split('\n') if line.strip()]
            proposed_lines = [line.strip() for line in proposed_config.split('\n') if line.strip()]
            
            # Show what's currently configured (for reference)
            if current_lines:
                diff_lines.append("Currently Configured (will be replaced):")
                for line in current_lines:
                    if line.strip():
                        diff_lines.append(f"  {line}")
                diff_lines.append("")
            
            # Show actual deployment commands that will be executed
            diff_lines.append("Commands to Execute:")
            for line in proposed_lines:
                if line.strip():
                    diff_lines.append(f"  {line}")
        
        return '\n'.join(diff_lines)
    
    def _generate_netbox_diff(self, current_state, proposed_state, bond_info=None, interface_name=None, bond_name=None):
        """
        Generate a diff for NetBox interface state changes (comprehensive).
        Shows all VLAN-relevant changes including IP/VRF removals.
        
        ISSUE 5 FIX: For sync mode with bond detection, shows VLAN migration from interface to bond.
        
        Args:
            current_state: Current NetBox state dict
            proposed_state: Proposed NetBox state dict
            bond_info: Optional bond information dict (for sync mode)
            interface_name: Original interface name (e.g., 'swp3')
            bond_name: Bond interface name (e.g., 'bond3')
        
        Returns:
            str: Formatted diff showing NetBox changes
        """
        if not current_state['has_changes']:
            return "No changes (NetBox already has this configuration)"
        
        diff_lines = []
        diff_lines.append("--- Current NetBox State")
        diff_lines.append("+++ Proposed NetBox State")
        diff_lines.append("")
        
        # ISSUE 5 FIX: If bond detected in sync mode, show VLAN migration
        # Check for bond_name and interface_name (bond_info can be None if NetBox doesn't have bond yet)
        if bond_name and interface_name:
            # Show migration message
            diff_lines.append(f"[INFO] BOND DETECTED: VLANs will be moved from interface '{interface_name}' to bond '{bond_name}'")
            diff_lines.append(f"  Bond '{bond_name}' will be created in NetBox (if missing)")
            diff_lines.append("")
            diff_lines.append(f"Interface '{interface_name}' (VLANs will be cleared):")
            old_untagged = current_state['current']['untagged_vlan'] or 'None'
            old_tagged = ', '.join(map(str, sorted(current_state['current']['tagged_vlans']))) or 'None'
            diff_lines.append(f"  Untagged VLAN: {old_untagged} → None (cleared - migrating to bond)")
            diff_lines.append(f"  Tagged VLANs: [{old_tagged}] → [] (cleared - migrating to bond)")
            diff_lines.append("")
            diff_lines.append(f"Bond '{bond_name}' (VLANs migrated from '{interface_name}'):")
            new_untagged = proposed_state['untagged_vlan'] or 'None'
            new_tagged = ', '.join(map(str, sorted(proposed_state['tagged_vlans']))) or 'None'
            if old_untagged != 'None':
                diff_lines.append(f"  Untagged VLAN: None → {old_untagged} (migrated from member interface)")
            if old_tagged != 'None':
                diff_lines.append(f"  Tagged VLANs: [] → [{old_tagged}] (migrated from member interface)")
            diff_lines.append("")
            return '\n'.join(diff_lines)
        
        # Normal mode (no bond migration)
        # Mode change
        old_mode = current_state['current']['mode'] or 'None'
        new_mode = proposed_state['mode']
        if old_mode != new_mode:
            diff_lines.append(f"  802.1Q Mode: {old_mode} → {new_mode}")
        
        # Untagged VLAN change
        old_untagged = current_state['current']['untagged_vlan'] or 'None'
        new_untagged = proposed_state['untagged_vlan'] or 'None'
        if old_untagged != new_untagged:
            diff_lines.append(f"  Untagged VLAN: {old_untagged} → {new_untagged}")
        
        # Tagged VLANs change
        old_tagged_set = set(current_state['current']['tagged_vlans'])
        new_tagged_set = set(proposed_state['tagged_vlans'])
        if old_tagged_set != new_tagged_set:
            old_tagged = ', '.join(map(str, sorted(current_state['current']['tagged_vlans']))) or 'None'
            new_tagged = ', '.join(map(str, sorted(proposed_state['tagged_vlans']))) or 'None'
            diff_lines.append(f"  Tagged VLANs: [{old_tagged}] → [{new_tagged}]")
        
        # IP Addresses change (removal for routed → bridged)
        old_ip_set = set(current_state['current']['ip_addresses'])
        new_ip_set = set(proposed_state['ip_addresses'])
        if old_ip_set != new_ip_set:
            old_ips = ', '.join(current_state['current']['ip_addresses']) or 'None'
            new_ips = ', '.join(proposed_state['ip_addresses']) or 'None'
            diff_lines.append(f"  IP Addresses: {old_ips} → {new_ips} (removed - interface changing from routed to bridged)")
        
        # VRF change (removal for routed → bridged)
        old_vrf = current_state['current']['vrf'] or 'None'
        new_vrf = proposed_state['vrf'] or 'None'
        if old_vrf != new_vrf:
            diff_lines.append(f"  VRF: {old_vrf} → {new_vrf} (removed - interface changing from routed to bridged)")
        
        # Show unchanged fields (for completeness)
        if current_state['current']['cable_status'] == proposed_state['cable_status']:
            diff_lines.append(f"  Cable Status: {proposed_state['cable_status']} → {proposed_state['cable_status']} (no change)")
        if current_state['current']['connected_to'] == proposed_state['connected_to']:
            if proposed_state['connected_to']:
                diff_lines.append(f"  Connected To: {proposed_state['connected_to']} → {proposed_state['connected_to']} (no change)")
        if current_state['current']['enabled'] == proposed_state['enabled']:
            diff_lines.append(f"  Enabled: {proposed_state['enabled']} → {proposed_state['enabled']} (no change)")
        if current_state['current']['port_channel_member'] == proposed_state['port_channel_member']:
            diff_lines.append(f"  Port-Channel Member: {proposed_state['port_channel_member']} → {proposed_state['port_channel_member']} (no change)")
        
        # Add warning if IP/VRF are being removed
        if old_ip_set and not new_ip_set:
            diff_lines.append("")
            diff_lines.append("[WARN] IP addresses will be removed from NetBox interface (routed → bridged)")
        if old_vrf != 'None' and new_vrf == 'None':
            diff_lines.append("[WARN] VRF will be removed from NetBox interface (routed → bridged)")
        
        if len(diff_lines) == 3:  # Only header lines
            return "No changes"
        
        return '\n'.join(diff_lines)
    
    def _get_interface_details(self, device, interface_name):
        """
        Get detailed interface information for dry run display.
        
        Returns:
            dict: Interface details including type, cable, connected device, etc.
        """
        try:
            interface = Interface.objects.get(device=device, name=interface_name)
            interface.refresh_from_db()
            
            details = {
                'name': interface_name,
                'type': interface.type if hasattr(interface, 'type') else 'Unknown',
                'description': interface.description or 'No description',
                'cabled': interface.cable is not None,
                'connected_device': None,
                'connected_role': None,
                'port_channel_member': False,
                'port_channel_name': None,
            }
            
            # Check port-channel membership
            if hasattr(interface, 'lag') and interface.lag:
                details['port_channel_member'] = True
                details['port_channel_name'] = interface.lag.name
            
            # Get connected device info
            if interface.cable:
                try:
                    endpoints = interface.connected_endpoints
                    if endpoints:
                        endpoint = endpoints[0]
                        connected_device = endpoint.device
                        details['connected_device'] = connected_device.name
                        details['connected_role'] = connected_device.role.name if connected_device.role else 'Unknown'
                        details['connected_status'] = connected_device.status
                except Exception as e:
                    logger.debug(f"Could not get connected device info: {e}")
            
            return details
        except Interface.DoesNotExist:
            return {
                'name': interface_name,
                'type': 'Unknown',
                'description': 'Interface not found in NetBox',
                'cabled': False,
                'connected_device': None,
                'connected_role': None,
                'port_channel_member': False,
            }
    
    def _generate_rollback_info(self, device, interface_name, vlan_id, platform, timeout=90, current_config=None):
        """
        Generate comprehensive rollback information for both Cumulus and EOS.
        Includes previous running config for manual rollback if auto-rollback fails.
        
        Args:
            device: Device object
            interface_name: Interface name
            vlan_id: VLAN ID being deployed
            platform: Platform type ('cumulus' or 'eos')
            timeout: Rollback timer in seconds
            current_config: Current device configuration (for manual rollback)
        
        Returns:
            str: Formatted rollback information
        """
        rollback_lines = []
        rollback_lines.append("Rollback Plan:")
        rollback_lines.append("")
        
        # Show captured interface-specific running config for reference (in case auto-rollback fails)
        if current_config and not ('ERROR' in current_config or 'Unable to fetch' in current_config or 'no configuration' in current_config.lower()):
            rollback_lines.append("Captured Interface Config (before deployment):")
            rollback_lines.append("  This is the interface configuration that was active before deployment.")
            rollback_lines.append("  Use these commands to manually restore if auto-rollback fails.")
            rollback_lines.append("")
            
            # Extract interface-specific configs (same logic as dry run mode)
            config_lines = current_config.split('\n')
            interface_config_found = False
            
            if platform == 'cumulus':
                # For Cumulus, show all nv set/unset commands for this interface
                for line in config_lines:
                    if line.strip():
                        # Show interface-specific commands (nv set/unset interface <name> ...)
                        if interface_name in line and ('nv set interface' in line or 'nv unset interface' in line):
                            rollback_lines.append(f"  {line.strip()}")
                            interface_config_found = True
                        # Also show notes/comments about this interface
                        elif line.strip().startswith('#') and interface_name in line:
                            rollback_lines.append(f"  {line.strip()}")
            elif platform == 'eos':
                # For EOS, show all interface config lines
                in_interface_section = False
                for line in config_lines:
                    stripped = line.strip()
                    if f"interface {interface_name}" in stripped:
                        in_interface_section = True
                        rollback_lines.append(f"  {line.strip()}")
                        interface_config_found = True
                    elif in_interface_section:
                        # Stop at next interface or end of config
                        if stripped.startswith('interface ') and interface_name not in stripped:
                            break
                        if stripped:  # Skip empty lines
                            rollback_lines.append(f"  {line.strip()}")
                            interface_config_found = True
            
            if not interface_config_found:
                rollback_lines.append("  # No previous VLAN configuration found for this interface")
            rollback_lines.append("")
        
        if platform == 'cumulus':
            rollback_lines.append("Platform: Cumulus Linux (NVUE)")
            rollback_lines.append("")
            rollback_lines.append("Option 1: Auto-Rollback (PRIMARY - happens automatically):")
            rollback_lines.append(f"  [OK] Supported: Yes (native commit-confirm)")
            rollback_lines.append(f"  • Method: nv config apply --confirm {timeout}s")
            rollback_lines.append(f"  • Timer: {timeout} seconds")
            rollback_lines.append(f"  • Behavior: Automatically rolls back if not confirmed within {timeout}s")
            rollback_lines.append(f"  • Status: ACTIVE - rollback will happen automatically if deployment fails")
            rollback_lines.append("")
            rollback_lines.append("Manual Rollback Options (only if auto-rollback fails or timer expires):")
            rollback_lines.append("")
            rollback_lines.append("  Option 2: Abort pending config (before timer expires):")
            rollback_lines.append("    nv config abort")
            rollback_lines.append("")
            rollback_lines.append("  Option 3: Remove VLAN config and restore previous state:")
            # Extract previous config commands from current_config
            if current_config and 'nv set' in current_config:
                rollback_lines.append("    # Previous configuration commands (restore these):")
                config_lines = current_config.split('\n')
                for line in config_lines:
                    if line.strip() and ('nv set' in line or 'nv unset' in line):
                        # Only show interface-specific configs
                        if interface_name in line:
                            rollback_lines.append(f"    {line.strip()}")
                # If no previous config found, show generic unset
                if not any(interface_name in line for line in config_lines if 'nv set' in line or 'nv unset' in line):
                    rollback_lines.append(f"    nv unset interface {interface_name} bridge domain br_default access")
                    rollback_lines.append("    # Note: Interface had no previous VLAN config")
            else:
                rollback_lines.append(f"    nv unset interface {interface_name} bridge domain br_default access")
            rollback_lines.append("    nv config apply")
            rollback_lines.append("")
            rollback_lines.append("  Option 4: Rollback using NVUE config history (recommended if auto-rollback failed):")
            rollback_lines.append("    # Step 1: View config history to find previous revision")
            rollback_lines.append("    nv config history")
            rollback_lines.append("")
            rollback_lines.append("    # Step 2: View diff to see what changed (replace <rev_id> with previous revision)")
            rollback_lines.append("    nv config diff <rev_id>")
            rollback_lines.append("")
            rollback_lines.append("    # Step 3: Apply previous revision (replace <rev_id> with previous revision)")
            rollback_lines.append("    nv config apply <rev_id>")
            rollback_lines.append("    # Note: This will prompt for confirmation. Type 'y' to confirm.")
            rollback_lines.append("")
            rollback_lines.append("To Confirm (prevent rollback):")
            rollback_lines.append("  nv config confirm")
            
        elif platform == 'eos':
            rollback_lines.append("Platform: Arista EOS")
            rollback_lines.append("")
            rollback_lines.append("Option 1: Auto-Rollback (PRIMARY - happens automatically):")
            timer_minutes = max(2, min(120, timeout // 60))
            rollback_lines.append(f"  [OK] Supported: Yes (configure session with commit timer)")
            rollback_lines.append(f"  • Method: configure session <name> + commit timer {timer_minutes}:00:00")
            rollback_lines.append(f"  • Timer: {timer_minutes} minutes")
            rollback_lines.append(f"  • Behavior: Automatically rolls back when timer expires if not confirmed")
            rollback_lines.append(f"  • Status: ACTIVE - rollback will happen automatically if deployment fails")
            rollback_lines.append("")
            rollback_lines.append("Manual Rollback Options (only if auto-rollback fails or timer expires):")
            rollback_lines.append("")
            rollback_lines.append("  Option 2: Abort session (before timer expires):")
            rollback_lines.append("    configure session <session_name>")
            rollback_lines.append("    abort")
            rollback_lines.append("    # Or wait for timer to expire (automatic rollback)")
            rollback_lines.append("")
            rollback_lines.append("  Option 3: Remove VLAN config and restore previous state:")
            # Extract previous config commands from current_config
            if current_config and ('interface' in current_config.lower() or 'switchport' in current_config.lower()):
                rollback_lines.append("    # Previous configuration commands (restore these):")
                config_lines = current_config.split('\n')
                in_interface = False
                for line in config_lines:
                    stripped = line.strip()
                    if f"interface {interface_name}" in stripped:
                        in_interface = True
                        rollback_lines.append(f"    {line.strip()}")
                    elif in_interface:
                        # Stop at next interface
                        if stripped.startswith('interface ') and interface_name not in stripped:
                            break
                        if stripped:
                            rollback_lines.append(f"    {line.strip()}")
                # If no previous config found, show generic removal
                if not in_interface:
                    rollback_lines.append(f"    interface {interface_name}")
                    rollback_lines.append("    no switchport access vlan")
                    rollback_lines.append("    # Note: Interface had no previous VLAN config")
            else:
                rollback_lines.append(f"    interface {interface_name}")
                rollback_lines.append("    no switchport access vlan")
            rollback_lines.append("")
            rollback_lines.append("  Option 4: Rollback using EOS configuration archive (if enabled and auto-rollback failed):")
            rollback_lines.append("    # EOS can maintain configuration archives if configured")
            rollback_lines.append("    # Step 1: View configuration archive (if available)")
            rollback_lines.append("    show archive")
            rollback_lines.append("")
            rollback_lines.append("    # Step 2: Compare with previous config (if archive exists)")
            rollback_lines.append("    show archive config differences <archive_number>")
            rollback_lines.append("")
            rollback_lines.append("    # Step 3: Load previous config from archive (if archive exists)")
            rollback_lines.append("    configure replace <archive_file>")
            rollback_lines.append("    # Note: Configuration archive must be enabled on device")
            rollback_lines.append("")
            rollback_lines.append("To Confirm (prevent rollback):")
            rollback_lines.append("  commit")
            rollback_lines.append("")
            rollback_lines.append("Note: Session name is auto-generated (format: netbox_vlan_XXXX)")
        else:
            rollback_lines.append(f"Platform: {platform}")
            rollback_lines.append("")
            rollback_lines.append("Auto-Rollback:")
            rollback_lines.append("  [WARN] Not supported on this platform")
            rollback_lines.append("  • Manual intervention may be required")
        
        return '\n'.join(rollback_lines)
    
    def _generate_validation_table(self, device_validation, interface_validation):
        """
        Generate a formatted validation breakdown table.
        
        Returns:
            str: Formatted validation table
        """
        table_lines = []
        table_lines.append("Validation Breakdown:")
        table_lines.append("")
        table_lines.append("Check                          | Status | Details")
        table_lines.append("-" * 80)
        
        # Device validation
        device_status = device_validation.get('status', 'unknown')
        device_msg = device_validation.get('message', '')
        status_symbol = '[BLOCK]' if device_status == 'block' else '[WARN]' if device_status == 'warn' else '[PASS]'
        table_lines.append(f"Device: automation-ready:vlan    | {status_symbol} {device_status.upper():5} | {device_msg}")
        
        # Interface validation
        iface_status = interface_validation.get('status', 'unknown')
        iface_msg = interface_validation.get('message', '')
        status_symbol = '[BLOCK]' if iface_status == 'block' else '[WARN]' if iface_status == 'warn' else '[PASS]'
        table_lines.append(f"Interface: tag check            | {status_symbol} {iface_status.upper():5} | {iface_msg}")
        
        return '\n'.join(table_lines)
    
    def _generate_risk_assessment(self, device_validation, interface_validation, current_vlan, new_vlan):
        """
        Generate risk assessment based on validation and changes.
        
        Returns:
            str: Risk assessment text
        """
        risk_lines = []
        risk_lines.append("Risk Assessment:")
        risk_lines.append("")
        
        # Determine risk level
        if device_validation.get('status') == 'block' or interface_validation.get('status') == 'block':
            risk_level = "HIGH"
            risk_icon = "[HIGH]"
        elif device_validation.get('status') == 'warn' or interface_validation.get('status') == 'warn':
            risk_level = "MEDIUM"
            risk_icon = "[MEDIUM]"
        else:
            risk_level = "LOW"
            risk_icon = "[LOW]"
        
        risk_lines.append(f"Risk Level: {risk_icon} {risk_level}")
        risk_lines.append("")
        
        # List risk factors
        risk_factors = []
        if device_validation.get('status') == 'block':
            risk_factors.append("Device not tagged as automation-ready (would block deployment)")
        if interface_validation.get('status') == 'block':
            risk_factors.append("Interface validation failed (would block deployment)")
        if interface_validation.get('status') == 'warn':
            risk_factors.append("Interface not properly tagged (would warn but allow)")
        if current_vlan and current_vlan != new_vlan:
            risk_factors.append(f"VLAN change: {current_vlan} → {new_vlan} (existing configuration will be modified)")
        
        if risk_factors:
            risk_lines.append("Risk Factors:")
            for factor in risk_factors:
                risk_lines.append(f"  • {factor}")
        else:
            risk_lines.append("Risk Factors: None identified")
        
        return '\n'.join(risk_lines)

    def _validate_tags_before_deployment(self, devices, interface_list):
        """
        Final validation before deployment - double-check tags and interface eligibility.
        This is a safety check that runs even after form validation.
        
        Tagging Priority Hierarchy (highest to lowest):
        1. Device: automation-ready:vlan (required for deployment)
        2. Interface tags (checked in priority order):
           - vlan-mode:routed (if IP address or VRF - BLOCKS, highest priority)
           - vlan-mode:uplink (if connected to Spine or same role - BLOCKS)
           - vlan-mode:tagged (if connected to Host AND has tagged/untagged VLANs - ALLOWS)
           - vlan-mode:access (if connected to Host AND has only untagged VLAN - ALLOWS)
           - vlan-mode:needs-review (if unclear or conflicts - WARNS but allows, lowest priority)
        
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
            'access': 'vlan-mode:access',
            'tagged': 'vlan-mode:tagged',
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
                    
                    # CRITICAL CHECK: Interface with IP address or VRF is a routed port (BLOCKING)
                    # Priority 1: vlan-mode:routed (if interface has IP address or in VRF, it's routed - highest priority)
                    # This must be checked BEFORE tag checks, as IP address/VRF is a stronger signal
                    has_ip = interface.ip_addresses.exists()
                    has_vrf = hasattr(interface, 'vrf') and interface.vrf is not None
                    # Also check VRF on IP addresses
                    if not has_vrf:
                        for ip_addr in interface.ip_addresses.all():
                            if hasattr(ip_addr, 'vrf') and ip_addr.vrf:
                                has_vrf = True
                                break
                    
                    if has_ip or has_vrf:
                        reason = []
                        if has_ip:
                            reason.append("IP address configured")
                        if has_vrf:
                            reason.append("VRF configured")
                        errors.append(
                            "Interface '" + iface_name + "' on device '" + device.name + "' has " + ' and '.join(reason) + " (routed port) - cannot modify routed interfaces."
                        )
                        continue  # Skip further checks for this interface
                    
                    # Check for blocking tags (BLOCKING)
                    if interface_tags.get('uplink') and interface_tags['uplink'].name in interface_tag_names_list:
                        errors.append(
                            "Interface '" + iface_name + "' on device '" + device.name + "' is marked as 'vlan-mode:uplink' - cannot modify uplink interfaces."
                        )
                        continue

                    if interface_tags.get('routed') and interface_tags['routed'].name in interface_tag_names_list:
                        errors.append(
                            "Interface '" + iface_name + "' on device '" + device.name + "' is marked as 'vlan-mode:routed' - cannot modify routed interfaces."
                        )
                        continue
                    
                    # Note: Port-channel/bond membership is handled automatically - 
                    # config is applied to bond interface instead of member (no blocking needed)

                    # Check if cabled (BLOCKING)
                    if not interface.cable:
                        errors.append(
                            "Interface '" + iface_name + "' on device '" + device.name + "' is not cabled in NetBox - please add cable information first."
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
                                    "Interface '" + iface_name + "' on device '" + device.name + "' is connected to device '" + connected_device.name + "' "
                                    "with status '" + str(connected_device.status) + "' - cannot configure VLAN."
                                )
                                continue
                    except Exception as e:
                        logger.warning("Could not get connected endpoints for " + device.name + ":" + iface_name + ": " + str(e))
                    
                    # REQUIRED: Interface must be tagged as 'access' or 'tagged' to allow deployment (BLOCKING)
                    has_access_tag = interface_tags.get('access') and interface_tags['access'].name in interface_tag_names_list
                    has_tagged_tag = interface_tags.get('tagged') and interface_tags['tagged'].name in interface_tag_names_list
                    if not has_access_tag and not has_tagged_tag:
                        errors.append(
                            "Interface '" + iface_name + "' on device '" + device.name + "' is not tagged as 'vlan-mode:access' or 'vlan-mode:tagged' - "
                            "cannot deploy VLAN. Please run the Tagging Workflow to properly tag this interface."
                        )
                        continue

                except Interface.DoesNotExist:
                    errors.append(
                        "Interface '" + iface_name + "' does not exist on device '" + device.name + "'"
                    )
        
        return errors

    def _get_interfaces_for_sync(self, devices, selected_interface_names=None, include_missing_tags=False):
        """
        Get interfaces from NetBox for selected devices that have VLAN configuration.
        Separates into tagged and missing_netbox_tags sections.
        
        Args:
            devices: QuerySet or list of Device objects
            selected_interface_names: Optional list of interface names selected by user.
                                     Format: ["device1:swp1", "device1:swp2", "device2:Ethernet1"]
                                     If None, returns all interfaces with VLAN config.
            include_missing_tags: If True, include interfaces missing proper vlan-mode tags (Section 2). Default: False
        
        Returns:
            dict: {
                'tagged': {device_name: [Interface objects]},
                'missing_netbox_tags': {device_name: [Interface objects]}
            }
        """
        tagged_interfaces_by_device = {}
        missing_tags_interfaces_by_device = {}
        
        # Management interfaces to exclude
        management_interfaces = {'eth0', 'lo', 'mgmt', 'management', 'loopback', 'Loopback0'}
        
        for device in devices:
            device_interfaces = Interface.objects.filter(
                device=device
            ).select_related('untagged_vlan').prefetch_related('tagged_vlans', 'tags')
            
            tagged_interfaces = []
            missing_tags_interfaces = []
            
            for iface in device_interfaces:
                # Skip management interfaces
                if iface.name.lower() in [m.lower() for m in management_interfaces]:
                    continue
                
                # Only process interfaces with VLAN config
                if not (iface.untagged_vlan or iface.tagged_vlans.exists()):
                    continue
                
                # If user selected specific interfaces, filter to those
                if selected_interface_names:
                    interface_key = f"{device.name}:{iface.name}"
                    if interface_key not in selected_interface_names:
                        continue
                
                # Check tags
                interface_tags = set(iface.tags.values_list('name', flat=True))
                has_vlan_mode_access_tagged = any(
                    tag.startswith('vlan-mode:access') or tag.startswith('vlan-mode:tagged')
                    for tag in interface_tags
                )
                has_any_tags = iface.tags.exists()
                
                # Explicit duplicate prevention: if interface has vlan-mode:access or vlan-mode:tagged,
                # it MUST go to Section 1 only, never Section 2
                if has_vlan_mode_access_tagged:
                    # Section 1: Has vlan-mode:access or vlan-mode:tagged tag
                    tagged_interfaces.append(iface)
                elif include_missing_tags:
                    # Section 2: All interfaces with VLAN config that DON'T have vlan-mode:access/tagged
                    # No strict filtering - include all interfaces with VLAN config
                    # This includes: interfaces with uplink/routed, needs-review, or any other vlan-mode tags (but not access/tagged)
                    missing_tags_interfaces.append(iface)
                # Note: Interfaces without VLAN config are already filtered out above
            
            # Safety check: Verify no duplicates between Section 1 and Section 2
            tagged_interface_ids = {iface.id for iface in tagged_interfaces}
            missing_tags_interface_ids = {iface.id for iface in missing_tags_interfaces}
            duplicates = tagged_interface_ids & missing_tags_interface_ids
            if duplicates:
                logger.warning(f"Found duplicate interfaces between Section 1 and Section 2 for device {device.name}: {duplicates}")
                # Remove duplicates from Section 2 (Section 1 takes priority)
                missing_tags_interfaces = [iface for iface in missing_tags_interfaces if iface.id not in duplicates]
            
            if tagged_interfaces:
                tagged_interfaces_by_device[device.name] = tagged_interfaces
            if missing_tags_interfaces:
                missing_tags_interfaces_by_device[device.name] = missing_tags_interfaces
        
        return {
            'tagged': tagged_interfaces_by_device,
            'missing_netbox_tags': missing_tags_interfaces_by_device,
        }

    def _generate_bond_deletion_commands(self, bond_name, platform):
        """Generate commands to delete a bond interface from the device."""
        commands = []
        if platform == 'cumulus':
            commands.append(f"nv unset interface {bond_name}")
        elif platform == 'eos':
            commands.append(f"no interface {bond_name}")
        return commands

    def _generate_bond_creation_commands(self, bond_name, member_interfaces, platform):
        """Generate commands to create a bond interface (minimum config - no EVPN)."""
        commands = []
        if platform == 'cumulus':
            commands.append(f"nv set interface {bond_name} type bond")
            for member in member_interfaces:
                commands.append(f"nv set interface {bond_name} bond member {member}")
            commands.append(f"nv set interface {bond_name} bond lacp-rate fast")
            commands.append(f"nv set interface {bond_name} bond lacp-bypass on")
            commands.append(f"nv set interface {bond_name} bridge domain br_default")
        elif platform == 'eos':
            commands.append(f"interface {bond_name}")
            for member in member_interfaces:
                commands.append(f"interface {member}")
                commands.append(f"   channel-group {bond_name.replace('Port-Channel', '')} mode active")
        return commands

    def _generate_config_from_netbox(self, device, interface, platform, existing_bridge_vlans=None, force_bond_interface=None):
        """
        Generate platform-specific config based on NetBox interface state.
        
        If interface is a bond member, applies config to bond interface instead.
        
        Args:
            device: Device object
            interface: Interface object from NetBox
            platform: Platform type ('cumulus' or 'eos')
            existing_bridge_vlans: Optional list of VLANs already in bridge (to avoid redundant commands)
            force_bond_interface: Optional bond interface name to use (overrides auto-detection)
        
        Returns:
            dict: {
                'commands': list of command strings,
                'mode': str ('access' or 'tagged'),
                'untagged_vlan': int or None,
                'tagged_vlans': list of ints,
                'bridge_vlans': list of ints (for Cumulus, VLANs to add to bridge),
                'target_interface': str (actual interface name used - bond if member, original otherwise),
                'is_bond_member': bool (True if interface is bond member)
            }
        """
        mode = getattr(interface, 'mode', None)
        untagged_vlan = interface.untagged_vlan.vid if interface.untagged_vlan else None
        tagged_vlans = list(interface.tagged_vlans.values_list('vid', flat=True))
        
        # Check if interface is a bond member - if so, use bond interface
        # Priority: force_bond_interface > NetBox LAG > device config
        target_interface = interface.name
        is_bond_member = False
        
        if force_bond_interface:
            # Force bond interface (from pre-check or bond migration)
            target_interface = force_bond_interface
            is_bond_member = True
        elif hasattr(interface, 'lag') and interface.lag:
            # Check NetBox LAG
            target_interface = interface.lag.name
            is_bond_member = True
        else:
            # Fall back to device config if NetBox doesn't have bond info
            bond_info = self._get_bond_interface_for_member(device, interface.name, platform=platform)
            if bond_info:
                target_interface = bond_info['bond_name']
                is_bond_member = True
        
        commands = []
        bridge_vlans = []
        
        if platform == 'cumulus':
            # Cumulus: VLANs are bridge-level, access is interface-level
            # IMPORTANT: Use "vlan {id}" - this is additive and won't overwrite existing VLANs
            # 1. Add all VLANs to bridge (untagged + tagged) using "vlan {id}" for each VLAN
            all_vlans = set()
            if untagged_vlan:
                all_vlans.add(untagged_vlan)
            all_vlans.update(tagged_vlans)
            
            # Generate bridge VLAN commands - ONLY for VLANs that don't already exist
            for vlan_vid in sorted(all_vlans):
                # Skip if VLAN already exists in bridge (check ranges and individual VLANs)
                if existing_bridge_vlans is None or not self._is_vlan_in_bridge_vlans(vlan_vid, existing_bridge_vlans):
                    bridge_cmd = f"nv set bridge domain br_default vlan {vlan_vid}"
                    commands.append(bridge_cmd)
            bridge_vlans = sorted(all_vlans)
            
            # 2. Set interface access VLAN (untagged) - use target_interface (bond if member)
            if untagged_vlan:
                access_cmd = f"nv set interface {target_interface} bridge domain br_default access {untagged_vlan}"
                commands.append(access_cmd)
            
            # Note: "nv config apply" is handled by the deployment method, don't include here
        
        elif platform == 'eos':
            # EOS: Config is interface-level - use target_interface (bond if member)
            if mode == 'access' and untagged_vlan:
                commands.append(f"interface {target_interface}")
                commands.append(f"   switchport mode access")
                commands.append(f"   switchport access vlan {untagged_vlan}")
            elif mode in ['tagged', 'tagged-all'] and tagged_vlans:
                commands.append(f"interface {target_interface}")
                commands.append(f"   switchport mode trunk")
                # Format: "switchport trunk allowed vlan 100,200,300"
                vlan_list = ','.join(map(str, sorted(tagged_vlans)))
                commands.append(f"   switchport trunk allowed vlan {vlan_list}")
                # If untagged VLAN exists, set native VLAN
                if untagged_vlan:
                    commands.append(f"   switchport trunk native vlan {untagged_vlan}")
        
        return {
            'commands': commands,
            'mode': mode or 'access',
            'untagged_vlan': untagged_vlan,
            'tagged_vlans': sorted(tagged_vlans),
            'bridge_vlans': bridge_vlans,
            'target_interface': target_interface,
            'is_bond_member': is_bond_member,
        }

    def _auto_tag_interface_after_deployment(self, interface, replace_conflicting_tags=False):
        """
        Auto-tag interface based on NetBox VLAN config after successful deployment.
        Bypasses analysis criteria (cable checks, etc.) since we've already deployed.
        
        Args:
            interface: Interface object from NetBox
            replace_conflicting_tags: If True, remove vlan-mode:uplink/routed tags before adding new tag
        
        Returns:
            str: Tag name that was applied, or None if tagging failed/skipped
        """
        from extras.models import Tag
        
        # Refresh interface from DB to get latest tags
        interface.refresh_from_db()
        
        # Read NetBox VLAN config
        has_untagged = interface.untagged_vlan is not None
        has_tagged = interface.tagged_vlans.exists()
        
        # Determine tag based on VLAN config only (no mode check)
        if has_tagged:
            tag_name = "vlan-mode:tagged"
        elif has_untagged:
            tag_name = "vlan-mode:access"
        else:
            # No VLAN config - shouldn't happen, but skip
            logger.warning(f"Interface {interface.name} has no VLAN config, skipping auto-tag")
            return None
        
        # Get Tag objects
        try:
            new_tag = Tag.objects.get(name=tag_name)
        except Tag.DoesNotExist:
            logger.error(f"Tag '{tag_name}' not found in NetBox - cannot auto-tag interface {interface.name}")
            return None
        
        # If replacing conflicting tags, remove vlan-mode:uplink and vlan-mode:routed tags first
        if replace_conflicting_tags:
            conflicting_tags_to_remove = []
            interface_tags = list(interface.tags.all())
            for tag in interface_tags:
                if tag.name.startswith('vlan-mode:uplink') or tag.name.startswith('vlan-mode:routed'):
                    conflicting_tags_to_remove.append(tag)
            
            if conflicting_tags_to_remove:
                for old_tag in conflicting_tags_to_remove:
                    interface.tags.remove(old_tag)
                    logger.info(f"Removed conflicting tag '{old_tag.name}' from interface {interface.device.name}:{interface.name}")
                interface.save()
        
        # Remove any existing vlan-mode:access or vlan-mode:tagged tags (if any) before adding new one
        existing_vlan_mode_tags = [
            tag for tag in interface.tags.all()
            if tag.name.startswith('vlan-mode:access') or tag.name.startswith('vlan-mode:tagged')
        ]
        if existing_vlan_mode_tags:
            for old_tag in existing_vlan_mode_tags:
                interface.tags.remove(old_tag)
            interface.save()
        
        # Add new tag
        try:
            interface.tags.add(new_tag)
            interface.save()
            
            # Verify tag was added
            interface.refresh_from_db()
            if new_tag in interface.tags.all():
                action = "replaced" if replace_conflicting_tags or existing_vlan_mode_tags else "applied"
                logger.info(f"Auto-tagged interface {interface.device.name}:{interface.name} as {tag_name} ({action})")
                return tag_name
            else:
                logger.error(f"Failed to verify tag {tag_name} on interface {interface.name}")
                return None
        except Exception as e:
            logger.error(f"Error auto-tagging interface {interface.name}: {e}")
            return None

    def _batch_deploy_interfaces_per_device(self, device, interfaces_with_configs, platform, dry_run=False):
        """
        Batch deploy multiple interfaces on the same device in a single commit-confirm session.
        Combines all interface configs into one deployment to avoid conflicting commits.
        
        Args:
            device: Device object
            interfaces_with_configs: List of dicts, each containing:
                - 'interface': Interface object
                - 'config_command': Config command string for this interface
                - 'target_interface': Target interface name (bond if member)
                - 'vlan_id': VLAN ID for deployment (for display)
                - 'preview_logs': List of preview log lines (for display)
            platform: Platform type ('cumulus' or 'eos')
            dry_run: If True, only show preview, don't deploy
        
        Returns:
            List of result dicts (one per interface), same format as _deploy_config_to_device
        """
        if dry_run or not interfaces_with_configs:
            # For dry run, return a SINGLE consolidated result showing all interfaces
            # This matches the actual deployment behavior where all interfaces are deployed together
            if not interfaces_with_configs:
                return []
            
            # Consolidate all interface preview logs into one with proposed configs consolidated
            consolidated_logs = []
            consolidated_logs.append("=" * 80)
            consolidated_logs.append(f"DEVICE-LEVEL DEPLOYMENT: {device.name}")
            consolidated_logs.append(f"Deploying {len(interfaces_with_configs)} interface(s) - DRY RUN")
            consolidated_logs.append("=" * 80)
            consolidated_logs.append("")
            
            # Collect proposed sections from all interfaces for consolidation
            all_proposed_configs = []
            all_config_commands = []
            
            # Add each interface's CURRENT state (not proposed)
            for idx, item in enumerate(interfaces_with_configs, 1):
                consolidated_logs.append(f"[{idx}/{len(interfaces_with_configs)}] Interface: {item['interface'].name}")
                consolidated_logs.append("=" * 80)
                
                # Parse preview logs to separate current vs proposed sections
                preview_logs = item.get('preview_logs', [])
                if isinstance(preview_logs, list):
                    in_proposed_section = False
                    for line in preview_logs:
                        # Detect start of proposed/diff/changes sections to skip
                        # KEEP: NetBox Configuration Changes (shows bond migration - important!)
                        if any(marker in line for marker in [
                            '--- Proposed Device Configuration',
                            '--- Config Diff ---',
                            '--- Configuration Changes (What Will Be Applied)',
                            '--- Pre-Deployment Traffic Check'
                        ]):
                            in_proposed_section = True
                            # Collect proposed config for consolidation
                            if '--- Proposed Device Configuration' in line:
                                all_proposed_configs.append({
                                    'interface': item['interface'].name,
                                    'config': item.get('config_command', ''),
                                    'target_interface': item.get('target_interface', item['interface'].name)
                                })
                            continue
                        
                        # Detect end of sections we want to skip
                        if in_proposed_section and line.strip().startswith('---'):
                            in_proposed_section = False
                            # Don't skip this line - it might be NetBox Configuration Changes
                            # Fall through to add it
                        
                        # Only add lines that are NOT in proposed sections
                        if not in_proposed_section:
                            consolidated_logs.append(line)
                else:
                    consolidated_logs.append(str(preview_logs))
                
                consolidated_logs.append("")
                
                # Collect config commands
                config_cmd = item.get('config_command', '')
                if config_cmd:
                    all_config_commands.append({
                        'interface': item['interface'].name,
                        'target': item.get('target_interface', item['interface'].name),
                        'commands': config_cmd
                    })
            
            # Add consolidated proposed configuration section
            consolidated_logs.append("=" * 80)
            consolidated_logs.append("CONSOLIDATED PROPOSED CONFIGURATION (ALL INTERFACES)")
            consolidated_logs.append("=" * 80)
            consolidated_logs.append("")
            consolidated_logs.append("--- Proposed Device Configuration ---")
            consolidated_logs.append("Commands that will be applied in single batch:")
            consolidated_logs.append("")
            consolidated_logs.append("[NOTE] When bond is detected:")
            consolidated_logs.append("       - Commands use BOND interface (e.g., bond3), not member interface (e.g., swp3)")
            consolidated_logs.append("       - NetBox changes affect BOND, VLANs migrated from member to bond")
            consolidated_logs.append("       - Traffic checks run on BOND interface, not member")
            consolidated_logs.append("")
            for config_item in all_config_commands:
                if config_item['commands']:
                    if config_item['interface'] != config_item['target']:
                        # Bond detected
                        consolidated_logs.append(f"  Member Interface: {config_item['interface']} → Target: {config_item['target']} (BOND)")
                    else:
                        # Direct interface
                        consolidated_logs.append(f"  Interface: {config_item['interface']}")
                    for line in config_item['commands'].split('\n'):
                        if line.strip():
                            consolidated_logs.append(f"    {line.strip()}")
                    consolidated_logs.append("")
            
            # Add batching summary at the end
            consolidated_logs.append("=" * 80)
            consolidated_logs.append("BATCHED DEPLOYMENT SUMMARY")
            consolidated_logs.append("=" * 80)
            consolidated_logs.append("")
            consolidated_logs.append(f"[BATCH] All {len(interfaces_with_configs)} interface(s) would be deployed together")
            consolidated_logs.append(f"        in a single atomic commit-confirm session.")
            consolidated_logs.append("")
            consolidated_logs.append("Interfaces in this batch:")
            for item in interfaces_with_configs:
                consolidated_logs.append(f"  - {item['interface'].name}")
            consolidated_logs.append("")
            consolidated_logs.append("Benefits of batched deployment:")
            consolidated_logs.append("  [OK] Single commit-confirm session (no conflicts)")
            consolidated_logs.append("  [OK] Atomic rollback (all-or-nothing)")
            consolidated_logs.append("  [OK] Faster execution (one SSH session)")
            consolidated_logs.append("  [OK] Consistent state (all interfaces updated simultaneously)")
            consolidated_logs.append("")
            
            # Collect all VLANs for display
            all_vlan_ids = set()
            for item in interfaces_with_configs:
                # Collect untagged VLAN
                if item.get('untagged_vid'):
                    all_vlan_ids.add(int(item['untagged_vid']))
                # Collect tagged VLANs
                if item.get('tagged_vids'):
                    for vid in item['tagged_vids']:
                        all_vlan_ids.add(int(vid))
                # Fallback: use vlan_id if other fields not available
                if item.get('vlan_id') and not item.get('untagged_vid') and not item.get('tagged_vids'):
                    all_vlan_ids.add(int(item['vlan_id']))
            
            # Return a SINGLE result for all interfaces
            result = {
                'success': True,
                'committed': False,
                'rolled_back': False,
                'message': f'Dry run - would deploy {len(interfaces_with_configs)} interface(s)',
                'logs': consolidated_logs,
                'device': device,
                'interface': f"Batched ({len(interfaces_with_configs)} interfaces)",
                'dry_run': True,
                'vlan_id': sorted(all_vlan_ids) if all_vlan_ids else [],  # Store as list for smart rendering
                'vlan_count': len(all_vlan_ids),
                'interfaces_count': len(interfaces_with_configs),
                'is_batched': True,  # Flag for table renderer
                '_interface_count': len(interfaces_with_configs),
                '_interface_names': [item['interface'].name for item in interfaces_with_configs]
            }
            return [result]  # Return as single-item list for consistency
        
        # Build combined config for all interfaces
        all_config_lines = []
        interface_mapping = {}  # {original_interface: target_interface}
        command_to_interface_map = {}  # Map each command to its source interface
        
        # Collect all unique bridge VLANs (for Cumulus)
        bridge_vlans_to_add = set()
        
        for item in interfaces_with_configs:
            interface = item['interface']
            config_command = item.get('config_command', '')
            target_interface = item.get('target_interface', interface.name)
            interface_mapping[interface.name] = target_interface
            
            # Parse config_command to extract commands
            for line in config_command.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # For Cumulus, collect bridge VLAN commands separately to avoid duplicates
                if platform == 'cumulus' and 'nv set bridge domain br_default vlan' in line:
                    # Extract VLAN ID from command
                    import re
                    match = re.search(r'vlan (\d+)', line)
                    if match:
                        bridge_vlans_to_add.add(int(match.group(1)))
                        # Map bridge VLAN command to interface that requested it
                        command_to_interface_map[line] = interface.name
                else:
                    # Add interface-specific commands
                    all_config_lines.append(line)
                    # Map this command to the interface it belongs to
                    command_to_interface_map[line] = interface.name
        
        # Add bridge VLAN commands at the beginning (for Cumulus)
        if platform == 'cumulus' and bridge_vlans_to_add:
            # Check existing bridge VLANs to avoid duplicates
            bridge_vlans = []
            bridge_vlans_fetched = False
            config_data = None
            try:
                napalm_mgr = NAPALMDeviceManager(device)
                if napalm_mgr.connect():
                    connection = napalm_mgr.connection
                    try:
                        if hasattr(connection, 'cli'):
                            config_show_output = connection.cli(['nv config show -o json'])
                        elif hasattr(connection, 'device') and hasattr(connection.device, 'send_command'):
                            config_show_output = connection.device.send_command('nv config show -o json', read_timeout=60)
                        else:
                            config_show_output = None
                        
                        if config_show_output:
                            if isinstance(config_show_output, dict):
                                config_json_str = config_show_output.get('nv config show -o json') or list(config_show_output.values())[0] if config_show_output else None
                            else:
                                config_json_str = str(config_show_output).strip()
                            
                            if config_json_str:
                                import json
                                config_data = json.loads(config_json_str)
                                bridge_vlans = self._get_bridge_vlans_from_json(config_data)
                                bridge_vlans_fetched = True
                                logger.info(f"[BATCHED] Fetched {len(bridge_vlans)} existing bridge VLANs: {sorted(bridge_vlans)[:20]}")
                    except Exception as fetch_error:
                        logger.warning(f"[BATCHED] Could not fetch existing bridge VLANs: {fetch_error}")
                    finally:
                        napalm_mgr.disconnect()
            except Exception as connect_error:
                logger.warning(f"[BATCHED] Could not connect to fetch bridge VLANs: {connect_error}")
            
            # Add only VLANs that don't already exist
            vlans_to_add = []
            vlans_already_exist = []
            for vlan_id in sorted(bridge_vlans_to_add):
                if not bridge_vlans_fetched:
                    # If we couldn't fetch bridge VLANs, add all VLANs (safe but may cause format changes)
                    # This is the old behavior - better than failing
                    vlans_to_add.append(vlan_id)
                elif not self._is_vlan_in_bridge_vlans(vlan_id, bridge_vlans):
                    vlans_to_add.append(vlan_id)
                else:
                    vlans_already_exist.append(vlan_id)
            
            if vlans_already_exist:
                logger.info(f"[BATCHED] Skipping {len(vlans_already_exist)} VLANs that already exist on bridge: {vlans_already_exist}")
            if vlans_to_add:
                logger.info(f"[BATCHED] Adding {len(vlans_to_add)} new VLANs to bridge: {vlans_to_add}")
                
                # FIX: Generate a single consolidated command with all VLANs (existing + new) to avoid format changes
                # This prevents NVUE from showing deletion/re-addition when device has comma-separated format
                if bridge_vlans_fetched and bridge_vlans:
                    # Combine existing VLANs with new VLANs
                    all_vlan_ids = sorted(set(bridge_vlans + vlans_to_add))
                    # Format as comma-separated list (NVUE's preferred format)
                    vlan_list_str = ','.join(map(str, all_vlan_ids))
                    all_config_lines.insert(0, f"nv set bridge domain br_default vlan {vlan_list_str}")
                    logger.info(f"[BATCHED] Generated consolidated VLAN command: vlan {vlan_list_str} (preserves existing format)")
                else:
                    # Fallback: Add individual commands (when we couldn't fetch existing VLANs)
                    for vlan_id in vlans_to_add:
                        all_config_lines.insert(0, f"nv set bridge domain br_default vlan {vlan_id}")
                    logger.info(f"[BATCHED] Added {len(vlans_to_add)} individual VLAN commands (could not fetch existing format)")
            else:
                logger.info(f"[BATCHED] No new bridge VLANs to add (all already exist)")
        
        # Combine all configs
        combined_config = '\n'.join(all_config_lines)
        
        logger.info(f"[BATCHED] Device {device.name}: Deploying {len(interfaces_with_configs)} interfaces in single commit-confirm session")
        logger.debug(f"[BATCHED] Combined config ({len(all_config_lines)} commands):\n{combined_config}")
        
        # Deploy combined config in single session
        napalm_mgr = NAPALMDeviceManager(device)
        all_results = []
        
        try:
            if not napalm_mgr.connect():
                error_msg = f"Failed to connect to {device.name}"
                logger.error(error_msg)
                # Mark all interfaces as failed
                for item in interfaces_with_configs:
                    result = {
                        'success': False,
                        'committed': False,
                        'rolled_back': False,
                        'error': error_msg,
                        'message': error_msg,
                        'logs': item.get('preview_logs', []) + [f"[FAIL] Connection failed: {error_msg}"],
                        'device': device,
                        'interface': item['interface'].name,
                        'dry_run': False
                    }
                    all_results.append(result)
                return all_results
            
            # Add batched deployment header
            combined_logs = []
            combined_logs.append("=" * 80)
            combined_logs.append(f"[BATCHED DEPLOYMENT] Device: {device.name}")
            combined_logs.append(f"[BATCHED DEPLOYMENT] Deploying {len(interfaces_with_configs)} interface(s) in SINGLE commit-confirm session")
            combined_logs.append("=" * 80)
            combined_logs.append("")
            combined_logs.append("Interfaces being configured:")
            for item in interfaces_with_configs:
                interface = item['interface']
                target_interface = item.get('target_interface', interface.name)
                if target_interface != interface.name:
                    combined_logs.append(f"  - {interface.name} → {target_interface} (bond detected)")
                else:
                    combined_logs.append(f"  - {interface.name}")
            combined_logs.append("")
            combined_logs.append(f"Combined configuration ({len(all_config_lines)} commands):")
            for line in all_config_lines:
                combined_logs.append(f"  {line}")
            combined_logs.append("")
            
            # Deploy using deploy_config_safe (single commit-confirm session)
            deploy_result = napalm_mgr.deploy_config_safe(
                config=combined_config,
                timeout=90,
                replace=False,
                interface_name=None,  # Multiple interfaces
                vlan_id=None  # Multiple VLANs possible
            )
            
            # Enhanced error handling: If deployment failed, try to identify which interface/command caused it
            if not deploy_result.get('success', False):
                error_message = deploy_result.get('message', 'Unknown error')
                error_logs = deploy_result.get('logs', [])
                
                # Parse error logs to identify problematic interface/command
                failed_interface = None
                failed_command = None
                error_detail = None
                failed_commands_list = []
                
                # Strategy 1: Look for commands in error context using our mapping
                for log_line in error_logs:
                    # Check if line contains an nv command
                    if 'nv set' in log_line or 'nv unset' in log_line:
                        # Extract the command from the line
                        import re
                        cmd_match = re.search(r'(nv (?:set|unset) [^\n]+)', log_line)
                        if cmd_match:
                            potential_cmd = cmd_match.group(1).strip()
                            # Check if this command is in our mapping
                            if potential_cmd in command_to_interface_map:
                                # Check if this is an error context
                                if any(indicator in log_line.lower() for indicator in ['error', 'failed', 'invalid', 'rejected', 'cannot', '✗']):
                                    failed_interface = command_to_interface_map[potential_cmd]
                                    failed_command = potential_cmd
                                    error_detail = log_line.strip()
                                    failed_commands_list.append((potential_cmd, command_to_interface_map[potential_cmd]))
                                    break
                
                # Strategy 2: Look for interface names mentioned in error context
                if not failed_interface:
                    for log_line in error_logs:
                        for item in interfaces_with_configs:
                            interface_name = item['interface'].name
                            target_interface = item.get('target_interface', interface_name)
                            
                            # Check if this interface is mentioned near an error
                            if interface_name in log_line or target_interface in log_line:
                                if any(indicator in log_line.lower() for indicator in ['error', 'failed', 'invalid', 'rejected', 'cannot', '✗']):
                                    failed_interface = interface_name
                                    error_detail = log_line.strip()
                                    break
                        if failed_interface:
                            break
                
                # Strategy 3: Extract generic command from error message
                if not failed_command:
                    for log_line in error_logs:
                        if 'nv set' in log_line or 'nv unset' in log_line:
                            if any(indicator in log_line.lower() for indicator in ['error', 'failed', 'invalid', '✗']):
                                import re
                                cmd_match = re.search(r'(nv (?:set|unset) [^\n]+)', log_line)
                                if cmd_match:
                                    failed_command = cmd_match.group(1).strip()
                
                # Add enhanced error information to logs
                enhanced_error_logs = []
                enhanced_error_logs.append("")
                enhanced_error_logs.append("=" * 80)
                enhanced_error_logs.append("DEPLOYMENT FAILURE ANALYSIS")
                enhanced_error_logs.append("=" * 80)
                enhanced_error_logs.append("")
                enhanced_error_logs.append("[WARN] ATOMIC DEPLOYMENT FAILED - ALL INTERFACES ROLLED BACK")
                enhanced_error_logs.append("")
                
                if failed_interface:
                    enhanced_error_logs.append(f"Suspected Problem Interface: {failed_interface}")
                if failed_command:
                    enhanced_error_logs.append(f"Failed Command: {failed_command}")
                if error_detail:
                    enhanced_error_logs.append(f"Error Detail: {error_detail}")
                
                enhanced_error_logs.append("")
                enhanced_error_logs.append("Impact: All interfaces on this device were rolled back to original state")
                enhanced_error_logs.append("")
                enhanced_error_logs.append("Interfaces Affected (all rolled back):")
                for idx, item in enumerate(interfaces_with_configs, 1):
                    interface = item['interface']
                    target_interface = item.get('target_interface', interface.name)
                    status = "← PROBLEM HERE" if interface.name == failed_interface else ""
                    enhanced_error_logs.append(f"  [{idx}] {interface.name}" + 
                                             (f" → {target_interface} (bond)" if target_interface != interface.name else "") +
                                             f" {status}")
                
                enhanced_error_logs.append("")
                enhanced_error_logs.append("Troubleshooting Steps:")
                enhanced_error_logs.append("  1. Review the error detail above")
                enhanced_error_logs.append("  2. Check NetBox configuration for the problem interface")
                enhanced_error_logs.append("  3. Verify VLAN exists in bridge domain on device")
                enhanced_error_logs.append("  4. Check for syntax errors in generated commands")
                enhanced_error_logs.append("  5. Fix the issue and re-run deployment")
                enhanced_error_logs.append("")
                enhanced_error_logs.append("Commands That Were Attempted (before rollback):")
                
                # Show commands grouped by interface for better clarity
                commands_by_interface = {}
                for cmd, iface in command_to_interface_map.items():
                    if iface not in commands_by_interface:
                        commands_by_interface[iface] = []
                    commands_by_interface[iface].append(cmd)
                
                # Show failed interface first if identified
                shown_count = 0
                max_commands_to_show = 30
                
                if failed_interface and failed_interface in commands_by_interface:
                    enhanced_error_logs.append(f"  Interface {failed_interface} (PROBLEM INTERFACE):")
                    for cmd in commands_by_interface[failed_interface][:10]:
                        marker = " ← FAILED HERE" if cmd == failed_command else ""
                        enhanced_error_logs.append(f"    {cmd}{marker}")
                        shown_count += 1
                    del commands_by_interface[failed_interface]
                
                # Show other interfaces
                for iface, cmds in list(commands_by_interface.items())[:5]:  # Show up to 5 other interfaces
                    if shown_count >= max_commands_to_show:
                        break
                    enhanced_error_logs.append(f"  Interface {iface}:")
                    for cmd in cmds[:5]:  # Show first 5 commands per interface
                        enhanced_error_logs.append(f"    {cmd}")
                        shown_count += 1
                        if shown_count >= max_commands_to_show:
                            break
                
                total_commands = len(all_config_lines)
                if shown_count < total_commands:
                    enhanced_error_logs.append(f"  ... and {total_commands - shown_count} more commands")
                enhanced_error_logs.append("")
                
                # Insert enhanced error analysis before existing error logs
                deploy_result['logs'] = combined_logs + enhanced_error_logs + deploy_result.get('logs', [])
            else:
                # Success - just prepend batched header
                if deploy_result.get('logs'):
                    deploy_result['logs'] = combined_logs + deploy_result['logs']
            
            # Create result for each interface (all share same deployment result)
            # Create SINGLE consolidated result for the device with ALL interfaces
            # Build consolidated logs showing all interfaces and their configs
            consolidated_logs = []
            
            # Header
            consolidated_logs.append("=" * 80)
            consolidated_logs.append(f"DEVICE-LEVEL DEPLOYMENT: {device.name}")
            consolidated_logs.append(f"Deploying {len(interfaces_with_configs)} interface(s) in SINGLE commit-confirm session")
            consolidated_logs.append("=" * 80)
            consolidated_logs.append("")
            
            # Show each interface's running/proposed config
            for idx, item in enumerate(interfaces_with_configs, 1):
                interface = item['interface']
                target_interface = item.get('target_interface', interface.name)
                
                consolidated_logs.append("")
                consolidated_logs.append("=" * 80)
                consolidated_logs.append(f"[{idx}/{len(interfaces_with_configs)}] INTERFACE: {interface.name}" + 
                                        (f" → {target_interface} (bond)" if target_interface != interface.name else ""))
                consolidated_logs.append("=" * 80)
                
                # Add interface-specific preview logs (running config, proposed config, etc.)
                preview_logs = item.get('preview_logs', [])
                if preview_logs:
                    consolidated_logs.extend(preview_logs)
                
                consolidated_logs.append("")
            
            # Add separator before deployment execution
            consolidated_logs.append("")
            consolidated_logs.append("=" * 80)
            consolidated_logs.append("DEPLOYMENT EXECUTION (ALL INTERFACES TOGETHER)")
            consolidated_logs.append("=" * 80)
            consolidated_logs.append("")
            
            # Add the shared batched deployment execution logs
            deployment_logs = deploy_result.get('logs', [])
            consolidated_logs.extend(deployment_logs)
            
            # Collect interface names and VLANs for display
            all_interface_names = [item['interface'].name for item in interfaces_with_configs]
            all_vlan_ids = set()
            for item in interfaces_with_configs:
                # Collect untagged VLAN
                if item.get('untagged_vid'):
                    all_vlan_ids.add(int(item['untagged_vid']))
                # Collect tagged VLANs
                if item.get('tagged_vids'):
                    for vid in item['tagged_vids']:
                        all_vlan_ids.add(int(vid))
                # Fallback: use vlan_id if other fields not available
                if item.get('vlan_id') and not item.get('untagged_vid') and not item.get('tagged_vids'):
                    all_vlan_ids.add(int(item['vlan_id']))
            
            # Create single result entry for the device
            device_result = deploy_result.copy()
            device_result['logs'] = consolidated_logs
            device_result['device'] = device
            device_result['interface'] = ', '.join(all_interface_names)  # Show all interfaces
            device_result['target_interface'] = ', '.join(all_interface_names)
            device_result['vlan_id'] = sorted(all_vlan_ids) if all_vlan_ids else []  # Store as list for smart rendering
            device_result['vlan_count'] = len(all_vlan_ids)
            device_result['dry_run'] = False
            device_result['interfaces_count'] = len(interfaces_with_configs)
            device_result['all_interfaces'] = all_interface_names
            device_result['is_batched'] = True  # Flag for table renderer
            
            # Add status fields
            device_result['device_status'] = "PASS"
            device_result['interface_status'] = "PASS" if device_result.get('success') else "BLOCK"
            device_result['overall_status'] = "PASS" if device_result.get('success') else "BLOCKED"
            device_result['risk_level'] = "LOW" if device_result.get('success') else "HIGH"
            
            all_results.append(device_result)
        
        except Exception as e:
            logger.error(f"Error during batched deployment for {device.name}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            
            # Create single consolidated error result for the device
            consolidated_error_logs = []
            consolidated_error_logs.append("=" * 80)
            consolidated_error_logs.append(f"DEVICE-LEVEL DEPLOYMENT: {device.name}")
            consolidated_error_logs.append(f"Deploying {len(interfaces_with_configs)} interface(s) - ERROR OCCURRED")
            consolidated_error_logs.append("=" * 80)
            consolidated_error_logs.append("")
            
            # Show each interface that was attempted
            for idx, item in enumerate(interfaces_with_configs, 1):
                interface = item['interface']
                consolidated_error_logs.append(f"[{idx}/{len(interfaces_with_configs)}] Interface: {interface.name}")
                if item.get('preview_logs'):
                    consolidated_error_logs.extend(item['preview_logs'][:20])  # Show first 20 lines
                consolidated_error_logs.append("")
            
            consolidated_error_logs.append("=" * 80)
            consolidated_error_logs.append("DEPLOYMENT ERROR")
            consolidated_error_logs.append("=" * 80)
            consolidated_error_logs.append(f"[FAIL] Deployment failed: {str(e)}")
            consolidated_error_logs.append(f"Error type: {type(e).__name__}")
            consolidated_error_logs.append("")
            
            all_interface_names = [item['interface'].name for item in interfaces_with_configs]
            
            # Collect VLANs for error display
            error_vlan_ids = set()
            for item in interfaces_with_configs:
                if item.get('untagged_vid'):
                    error_vlan_ids.add(int(item['untagged_vid']))
                if item.get('tagged_vids'):
                    for vid in item['tagged_vids']:
                        error_vlan_ids.add(int(vid))
                if item.get('vlan_id') and not item.get('untagged_vid') and not item.get('tagged_vids'):
                    error_vlan_ids.add(int(item['vlan_id']))
            
            error_result = {
                'success': False,
                'committed': False,
                'rolled_back': False,
                'message': f'Batched deployment failed: {str(e)}',
                'error': str(e),
                'logs': consolidated_error_logs,
                'device': device,
                'interface': ', '.join(all_interface_names),
                'dry_run': False,
                'vlan_id': sorted(error_vlan_ids) if error_vlan_ids else [],
                'vlan_count': len(error_vlan_ids),
                'interfaces_count': len(interfaces_with_configs),
                'all_interfaces': all_interface_names,
                'is_batched': True
            }
            all_results.append(error_result)
        finally:
            napalm_mgr.disconnect()
        
        return all_results

    def _run_vlan_sync(self, devices, cleaned_data):
        """
        Sync NetBox interface VLAN configurations to devices.
        Uses existing deployment infrastructure (Nornir/NAPALM).
        
        Args:
            devices: QuerySet or list of Device objects
            cleaned_data: Form cleaned data containing:
                - sync_netbox_to_device: bool
                - interfaces_select: list (interface names in "device:interface" format)
                - dry_run: bool
                - deploy_changes: bool
        
        Returns:
            list: Results in same format as _run_vlan_deployment
        """
        dry_run = cleaned_data.get('dry_run', False)
        deploy_changes = cleaned_data.get('deploy_changes', False)
        
        # Get selected interfaces from form (user may have unchecked some)
        selected_interfaces_str = cleaned_data.get('interfaces_select', [])
        selected_interface_names = None
        if selected_interfaces_str:
            # Parse list of "device:interface" pairs
            if isinstance(selected_interfaces_str, list):
                selected_interface_names = selected_interfaces_str
            else:
                selected_interface_names = [s.strip() for s in str(selected_interfaces_str).split(',') if s.strip()]
        
        # Get deploy_missing_tags_interfaces checkbox value
        deploy_missing_tags = cleaned_data.get('deploy_untagged_interfaces', False)  # Keep form field name for backward compatibility
        
        # Get interfaces for each device from NetBox (filtered by user selection)
        # Returns dict with 'tagged' and 'missing_netbox_tags' sections
        interfaces_dict = self._get_interfaces_for_sync(
            devices, 
            selected_interface_names, 
            include_missing_tags=deploy_missing_tags
        )
        
        tagged_interfaces_by_device = interfaces_dict['tagged']
        missing_tags_interfaces_by_device = interfaces_dict['missing_netbox_tags'] if deploy_missing_tags else {}
        
        results = []
        
        # Detect platform - all devices should be same platform
        platform = self._get_device_platform(devices[0]) if devices else 'cumulus'
        
        logger.info(f"VLAN Sync: {len(devices)} devices, platform: {platform}, dry_run: {dry_run}, deploy_missing_tags: {deploy_missing_tags}")
        
        # Track which interfaces need auto-tagging (Section 2 only)
        interfaces_to_auto_tag = []
        
        # Process Section 1: Tagged interfaces (always deploy)
        # BATCH DEPLOYMENT: Collect all interfaces per device, then deploy in single commit-confirm session
        for device in devices:
            device_interfaces = tagged_interfaces_by_device.get(device.name, [])
            
            if not device_interfaces:
                continue
            
            # Collect all interfaces with their configs for batched deployment
            interfaces_with_configs = []
            dry_run_device_interfaces = []  # Track interfaces for dry run summary
            sync_dry_run_interface_data = []  # Collect all interface data for consolidated dry run result
            
            # Get device bridge VLANs ONCE per device (not per interface)
            device_bridge_vlans = []
            if device_interfaces:
                try:
                    first_interface = device_interfaces[0]
                    device_config_result = self._get_current_device_config(device, first_interface.name, platform)
                    device_bridge_vlans = device_config_result.get('_bridge_vlans', [])
                except Exception as e:
                    logger.warning(f"Could not fetch bridge VLANs for device {device.name}: {e}")
            
            for interface in device_interfaces:
                # PRE-CHECK: Detect bond membership BEFORE generating config
                bond_detected_early = None
                netbox_bond = None
                bond_creation_commands = []
                bond_deletion_commands = []
                bond_traffic_warning = None
                old_bond_name = None
                
                logger.info(f"[PRE-CHECK] Starting bond detection for {device.name}:{interface.name}")
                
                # Check device bond
                try:
                    device_config_check = self._get_current_device_config(device, interface.name, platform)
                    bond_detected_early = device_config_check.get('bond_member_of')
                except Exception as e:
                    logger.error(f"[PRE-CHECK] FAILED to check device bond: {e}")
                
                # Check NetBox bond
                if hasattr(interface, 'lag') and interface.lag:
                    netbox_bond = interface.lag.name
                
                # Handle bond scenarios
                if netbox_bond and not bond_detected_early:
                    # Scenario 3: CREATE - NetBox has bond, device doesn't
                    logger.info(f"[BOND AUTO-CREATE] NetBox has bond {netbox_bond}, device doesn't - will create bond on device")
                    # Get all members of this bond from NetBox
                    member_interfaces = []
                    try:
                        lag_interfaces = Interface.objects.filter(device=device, lag=interface.lag)
                        member_interfaces = [iface.name for iface in lag_interfaces]
                    except Exception as e:
                        logger.warning(f"Could not get LAG members: {e}")
                        member_interfaces = [interface.name]
                    bond_creation_commands = self._generate_bond_creation_commands(netbox_bond, member_interfaces, platform)
                    bond_detected_early = netbox_bond
                elif bond_detected_early and netbox_bond and bond_detected_early != netbox_bond:
                    # Scenario 4: MIGRATE (NetBox is source of truth!)
                    logger.warning(f"[BOND MIGRATION] Device={bond_detected_early}, NetBox={netbox_bond} -> using NetBox")
                    old_bond_name = bond_detected_early
                    try:
                        traffic_check = self._check_interface_traffic_stats(device, old_bond_name, platform)
                        if traffic_check.get('has_traffic'):
                            bond_traffic_warning = f"[TRAFFIC] Bond '{old_bond_name}' is carrying traffic!"
                    except Exception:
                        pass
                    bond_deletion_commands = self._generate_bond_deletion_commands(old_bond_name, platform)
                    # Get all members of NetBox bond
                    member_interfaces = []
                    try:
                        lag_interfaces = Interface.objects.filter(device=device, lag=interface.lag)
                        member_interfaces = [iface.name for iface in lag_interfaces]
                    except Exception as e:
                        logger.warning(f"Could not get LAG members: {e}")
                        member_interfaces = [interface.name]
                    bond_creation_commands = self._generate_bond_creation_commands(netbox_bond, member_interfaces, platform)
                    bond_detected_early = netbox_bond
                
                # Generate config from NetBox state
                # IMPORTANT: Pass force_bond_interface if bond was detected/created to ensure VLAN configs use bond interface
                logger.info(f"[CONFIG GEN] Calling _generate_config_from_netbox() for {device.name}:{interface.name}, force_bond_interface={bond_detected_early}")
                config_info = self._generate_config_from_netbox(
                    device, 
                    interface, 
                    platform, 
                    existing_bridge_vlans=device_bridge_vlans,
                    force_bond_interface=bond_detected_early if bond_detected_early else None
                )
                config_commands = config_info['commands']
                
                # PREPEND bond deletion + creation commands if needed
                if bond_deletion_commands or bond_creation_commands:
                    all_bond_commands = bond_deletion_commands + bond_creation_commands
                    config_commands = all_bond_commands + config_commands
                    config_info['commands'] = config_commands
                    config_info['bond_migrated'] = bool(bond_deletion_commands)
                    config_info['old_bond_name'] = old_bond_name
                    config_info['bond_traffic_warning'] = bond_traffic_warning
                
                logger.info(f"[CONFIG GEN] Generated {len(config_commands)} commands, target_interface={config_info.get('target_interface')}, is_bond_member={config_info.get('is_bond_member')}")
                
                # CRITICAL FIX: If bond was detected in pre-check but config_info doesn't have it, FORCE regeneration
                actual_target_interface = config_info.get('target_interface', interface.name)
                if bond_detected_early and actual_target_interface == interface.name:
                    logger.warning(f"[CRITICAL FIX] Bond {bond_detected_early} was detected but config_info still has member interface {interface.name}")
                    logger.warning(f"[CRITICAL FIX] Forcing regeneration of commands with bond interface {bond_detected_early}")
                    
                    # Regenerate commands with correct bond interface
                    untagged_vid = config_info.get('untagged_vlan')
                    tagged_vids = config_info.get('tagged_vlans', [])
                    
                    if platform == 'cumulus':
                        regenerated_commands = []
                        
                        # IMPORTANT: Prepend bond creation commands if bond is being created
                        if bond_creation_commands:
                            regenerated_commands.extend(bond_creation_commands)
                            logger.info(f"[CRITICAL FIX] Including {len(bond_creation_commands)} bond creation commands in regenerated commands")
                        
                        all_vlans = set()
                        if untagged_vid:
                            all_vlans.add(untagged_vid)
                        all_vlans.update(tagged_vids)
                        
                        for vlan_vid in sorted(all_vlans):
                            if not self._is_vlan_in_bridge_vlans(vlan_vid, device_bridge_vlans):
                                regenerated_commands.append(f"nv set bridge domain br_default vlan {vlan_vid}")
                        
                        if untagged_vid:
                            regenerated_commands.append(f"nv set interface {bond_detected_early} bridge domain br_default access {untagged_vid}")
                        
                        config_commands = regenerated_commands
                        # Update config_info with correct target
                        config_info['target_interface'] = bond_detected_early
                        config_info['is_bond_member'] = True
                        logger.info(f"[CRITICAL FIX] ✓ Regenerated {len(regenerated_commands)} commands using bond {bond_detected_early}")
                        logger.info(f"[CRITICAL FIX] Commands: {', '.join(regenerated_commands)}")
                elif bond_detected_early and actual_target_interface == bond_detected_early:
                    logger.info(f"[CRITICAL FIX] ✓ Bond detection worked! target_interface={actual_target_interface}")
                elif not bond_detected_early:
                    logger.info(f"[CRITICAL FIX] No bond detected in pre-check for {interface.name}")
                
                # Combine commands into single config string (for deployment)
                config_command = '\n'.join(config_commands) if isinstance(config_commands, list) else config_commands
                logger.info(f"[CONFIG FINAL] Final config_command for {interface.name}: {config_command[:100]}...")
                
                # VALIDATION: Double-check commands don't contain member interface in bridge/access commands
                if f"interface {interface.name} bridge" in config_command:
                    logger.error(f"[VALIDATION FAIL] ✗ Commands STILL contain member interface {interface.name} in bridge config!")
                    logger.error(f"[VALIDATION FAIL] Commands: {config_command}")
                    logger.error(f"[VALIDATION FAIL] config_info: {config_info}")
                    logger.error(f"[VALIDATION FAIL] bond_detected_early: {bond_detected_early}")
                    logger.error(f"[VALIDATION FAIL] This WILL cause 'bridge cannot be configured on bond member' error!")
                else:
                    logger.info(f"[VALIDATION PASS] ✓ Commands do NOT contain member interface in bridge config")
                
                if dry_run:
                    # Dry run mode - show what would be deployed
                    # Get current device config
                    device_config_result = self._get_current_device_config(device, interface.name, platform)
                    current_device_config = device_config_result.get('current_config', 'Unable to fetch')
                    config_source = device_config_result.get('source', 'error')
                    
                    # Get bond info early for diff generation
                    bond_member_of = device_config_result.get('bond_member_of')
                    
                    # Get NetBox state
                    untagged_vid = config_info['untagged_vlan']
                    tagged_vids = config_info['tagged_vlans']
                    
                    # Get VLAN ID and name for display
                    # Use untagged VLAN if available, otherwise first tagged VLAN
                    vlan_id = untagged_vid if untagged_vid else (tagged_vids[0] if tagged_vids else None)
                    vlan_name = 'N/A'
                    if vlan_id:
                        try:
                            vlan_obj = VLAN.objects.filter(vid=vlan_id).first()
                            if vlan_obj:
                                vlan_name = vlan_obj.name or f"VLAN {vlan_id}"
                            else:
                                vlan_name = f"VLAN {vlan_id}"
                        except Exception:
                            vlan_name = f"VLAN {vlan_id}"
                    
                    # Format VLAN display (show untagged and tagged if both exist)
                    if untagged_vid and tagged_vids:
                        vlan_display = f"{untagged_vid} (untagged) + {', '.join(map(str, tagged_vids))} (tagged)"
                    elif untagged_vid:
                        vlan_display = str(untagged_vid)
                    elif tagged_vids:
                        vlan_display = ', '.join(map(str, tagged_vids))
                    else:
                        vlan_display = 'N/A'
                    
                    netbox_state = {
                        'current': {
                            'untagged_vlan': interface.untagged_vlan.vid if interface.untagged_vlan else None,
                            'tagged_vlans': list(interface.tagged_vlans.values_list('vid', flat=True)),
                            'mode': getattr(interface, 'mode', None),
                        },
                        'proposed': {
                            'untagged_vlan': untagged_vid,
                            'tagged_vlans': tagged_vids,
                            'mode': config_info['mode'],
                        }
                    }
                    
                    # Generate deployment logs - match normal mode structure
                    logs = []
                    logs.append("=" * 80)
                    logs.append("SYNC MODE DRY RUN - PREVIEW ONLY")
                    logs.append("=" * 80)
                    logs.append("")
                    logs.append("[NOTE] This interface will be deployed in a BATCHED commit with all other")
                    logs.append(f"       interfaces on device '{device.name}' in a single atomic session.")
                    logs.append("       All interface configs will be applied together with one commit-confirm.")
                    logs.append("")
                    
                    # Get bond info FIRST before showing proposed config (so proposed config shows bond3)
                    bond_member_of = device_config_result.get('bond_member_of')
                    bond_interface_config = device_config_result.get('bond_interface_config')
                    bridge_vlans = device_config_result.get('_bridge_vlans', [])
                    
                    # If bond detected, regenerate config_command with bond interface name
                    # IMPORTANT: Include ALL VLANs (untagged + tagged) from this interface
                    # ISSUE 1 FIX: Check if VLANs already exist in bridge before adding
                    # Also check if NetBox has bond but device doesn't (bond creation needed)
                    if bond_member_of or (hasattr(interface, 'lag') and interface.lag and not bond_member_of):
                        # Regenerate config with bond interface instead of member interface
                        # Check if NetBox has bond but device doesn't
                        netbox_bond_for_dryrun = None
                        if hasattr(interface, 'lag') and interface.lag:
                            netbox_bond_for_dryrun = interface.lag.name
                        
                        # Use NetBox bond if device doesn't have bond
                        target_interface = bond_member_of if bond_member_of else netbox_bond_for_dryrun
                        
                        if target_interface:
                            # Regenerate config_command using target_interface (bond) - include ALL VLANs
                            if platform == 'cumulus':
                                regenerated_commands = []
                                
                                # IMPORTANT: Prepend bond creation commands if NetBox has bond but device doesn't
                                if netbox_bond_for_dryrun and not bond_member_of:
                                    # NetBox has bond, device doesn't - need to create bond
                                    # Get all members of this bond from NetBox
                                    member_interfaces = []
                                    try:
                                        lag_interfaces = Interface.objects.filter(device=device, lag=interface.lag)
                                        member_interfaces = [iface.name for iface in lag_interfaces]
                                    except Exception as e:
                                        logger.warning(f"Could not get LAG members: {e}")
                                        member_interfaces = [interface.name]
                                    
                                    bond_creation_commands_dryrun = self._generate_bond_creation_commands(
                                        netbox_bond_for_dryrun, 
                                        member_interfaces, 
                                        platform
                                    )
                                    regenerated_commands.extend(bond_creation_commands_dryrun)
                                    logger.info(f"[DRY RUN] Including {len(bond_creation_commands_dryrun)} bond creation commands for {netbox_bond_for_dryrun} (NetBox has bond, device doesn't)")
                                
                                # Collect ALL VLANs from this interface (untagged + tagged)
                                all_vlans = set()
                                if untagged_vid:
                                    all_vlans.add(untagged_vid)
                                all_vlans.update(tagged_vids)
                                
                                # Generate bridge VLAN commands for ALL VLANs
                                # ISSUE 1: Only add VLANs that don't already exist in bridge
                                for vlan_vid in sorted(all_vlans):
                                    # Check if VLAN already exists in bridge (handles ranges like "3019-3099")
                                    if not self._is_vlan_in_bridge_vlans(vlan_vid, bridge_vlans):
                                        regenerated_commands.append(f"nv set bridge domain br_default vlan {vlan_vid}")
                                        logger.debug(f"VLAN {vlan_vid} not in bridge - will add")
                                    else:
                                        logger.debug(f"VLAN {vlan_vid} already exists in bridge (range or individual) - skipping")
                                
                                # Set interface access VLAN using bond interface (if untagged VLAN exists)
                                if untagged_vid:
                                    regenerated_commands.append(f"nv set interface {target_interface} bridge domain br_default access {untagged_vid}")
                                
                                config_command = '\n'.join(regenerated_commands)
                            # For EOS, would need similar regeneration
                    
                    # Generate diff AFTER bond detection and config_command regeneration
                    # Use bond interface name if bond detected
                    target_interface_for_diff = bond_member_of if bond_member_of else interface.name
                    config_diff = self._generate_config_diff(
                        current_device_config, 
                        config_command, 
                        platform, 
                        device=device, 
                        interface_name=target_interface_for_diff
                    )
                    
                    logs.append("--- Current Device Configuration (Real from Device) ---")
                    logs.append("")
                    
                    # Check if interface is a bond member
                    if bond_member_of:
                        logs.append(f"Bond Membership: Interface '{interface.name}' is a member of bond '{bond_member_of}'")
                        logs.append(f"Note: VLAN configuration will be applied to bond '{bond_member_of}', not to '{interface.name}' directly.")
                        logs.append("")
                        logs.append(f"Interface-Level Configuration (for '{interface.name}'):")
                        if current_device_config and current_device_config.strip() and not "ERROR:" in current_device_config:
                            for line in current_device_config.split('\n'):
                                if line.strip():
                                    logs.append(f"  {line}")
                        else:
                            logs.append("  (no configuration found for this interface)")
                        logs.append("")
                        logs.append(f"Bond Interface '{bond_member_of}' Configuration:")
                        if bond_interface_config and bond_interface_config.strip():
                            for line in bond_interface_config.split('\n'):
                                if line.strip():
                                    logs.append(f"  {line}")
                        else:
                            logs.append("  (unable to retrieve bond interface configuration)")
                    else:
                        # Not a bond member - show interface config normally
                        logs.append(f"Interface-Level Configuration:")
                        if current_device_config and current_device_config.strip() and not "ERROR:" in current_device_config:
                            for line in current_device_config.split('\n'):
                                if line.strip():
                                    logs.append(f"  {line}")
                        else:
                            logs.append("  (unable to retrieve or no configuration)")
                    logs.append("")
                    
                    # Bridge-Level Configuration (for Cumulus - always show)
                    if platform == 'cumulus':
                        logs.append("Bridge-Level Configuration (br_default):")
                        if bridge_vlans and len(bridge_vlans) > 0:
                            vlan_list_str = self._format_vlan_list(bridge_vlans)
                            logs.append(f"  nv set bridge domain br_default vlan {vlan_list_str}")
                        else:
                            logs.append("  (bridge VLAN information not available)")
                        logs.append("")
                    
                    # ISSUE 2 FIX: Show Current NetBox Configuration FIRST (source of truth)
                    # Then show conflict detection, then diff
                    logs.append("--- Current NetBox Configuration (Source of Truth) ---")
                    netbox_current = netbox_state['current']
                    logs.append(f"802.1Q Mode: {netbox_current['mode'] or 'None'}")
                    logs.append(f"Untagged VLAN: {netbox_current['untagged_vlan'] or 'None'}")
                    tagged_vlans_str = ', '.join(map(str, netbox_current['tagged_vlans'])) if netbox_current['tagged_vlans'] else 'None'
                    logs.append(f"Tagged VLANs: [{tagged_vlans_str}]")
                    logs.append("")
                    
                    # Configuration Conflict Detection
                    logs.append("--- Configuration Conflict Detection ---")
                    # Check if device config matches NetBox
                    device_config_has_vlan = False
                    device_vlan_id = None
                    if current_device_config:
                        import re
                        vlan_match = re.search(r'access\s+(\d+)', current_device_config.lower())
                        if vlan_match:
                            device_config_has_vlan = True
                            device_vlan_id = int(vlan_match.group(1))
                    
                    netbox_has_vlan = netbox_current.get('untagged_vlan') is not None
                    netbox_vlan_id = netbox_current.get('untagged_vlan')
                    
                    conflict_detected = False
                    conflict_reasons = []
                    if netbox_has_vlan and not device_config_has_vlan:
                        conflict_detected = True
                        conflict_reasons.append(f"NetBox has VLAN {netbox_vlan_id} configured but device has no VLAN config")
                    elif netbox_has_vlan and device_config_has_vlan and netbox_vlan_id != device_vlan_id:
                        conflict_detected = True
                        conflict_reasons.append(f"VLAN mismatch: NetBox has {netbox_vlan_id}, device has {device_vlan_id}")
                    
                    if conflict_detected:
                        logs.append(f"[WARN] Device config differs from NetBox config")
                        if conflict_reasons:
                            logs.append(f"  Conflicts detected: {', '.join(conflict_reasons)}")
                        logs.append("")
                        logs.append("Device Should Have (According to NetBox):")
                        # ISSUE 4 & 6 FIX: Show ALL VLANs (untagged + tagged) from NetBox
                        # Generate complete config from NetBox state
                        all_netbox_vlans = set()
                        if netbox_current.get('untagged_vlan'):
                            all_netbox_vlans.add(netbox_current['untagged_vlan'])
                        all_netbox_vlans.update(netbox_current.get('tagged_vlans', []))
                        
                        # Show bridge VLAN commands for all VLANs
                        target_interface_for_netbox = bond_member_of if bond_member_of else interface.name
                        for vlan_vid in sorted(all_netbox_vlans):
                            # Only show if not already in bridge (Issue 1)
                            if not self._is_vlan_in_bridge_vlans(vlan_vid, bridge_vlans):
                                logs.append(f"  nv set bridge domain br_default vlan {vlan_vid}")
                        
                        # Show interface access VLAN command
                        if netbox_current.get('untagged_vlan'):
                            logs.append(f"  nv set interface {target_interface_for_netbox} bridge domain br_default access {netbox_current['untagged_vlan']}")
                        logs.append("")
                        logs.append("Note: NetBox is the source of truth. Device may have stale/old configuration.")
                        logs.append("      Any differences will be reconciled during deployment.")
                    else:
                        logs.append("[OK] Device config matches NetBox - no conflicts detected")
                    logs.append("")
                    
                    # ISSUE 3 FIX: Include bridge VLANs in current config for diff generation
                    # Build current config that includes both interface-level and bridge-level
                    current_config_with_bridge = current_device_config or ""
                    if platform == 'cumulus' and bridge_vlans:
                        # Add bridge VLAN commands to current config for proper diff
                        bridge_vlan_cmds = []
                        for vlan_item in bridge_vlans:
                            if isinstance(vlan_item, (int, str)):
                                # Format as command
                                if isinstance(vlan_item, str) and '-' in vlan_item:
                                    # Range format
                                    bridge_vlan_cmds.append(f"nv set bridge domain br_default vlan {vlan_item}")
                                else:
                                    # Individual VLAN
                                    try:
                                        vlan_id = int(vlan_item) if isinstance(vlan_item, str) else vlan_item
                                        bridge_vlan_cmds.append(f"nv set bridge domain br_default vlan {vlan_id}")
                                    except (ValueError, TypeError):
                                        pass
                        
                        if bridge_vlan_cmds:
                            if current_config_with_bridge:
                                current_config_with_bridge = '\n'.join(bridge_vlan_cmds) + '\n' + current_config_with_bridge
                            else:
                                current_config_with_bridge = '\n'.join(bridge_vlan_cmds)
                    
                    # Regenerate diff with bridge VLANs included in current config
                    config_diff = self._generate_config_diff(
                        current_config_with_bridge,  # Use current config with bridge VLANs
                        config_command, 
                        platform, 
                        device=device, 
                        interface_name=target_interface_for_diff,
                        bridge_vlans=bridge_vlans  # Pass bridge VLANs for reference
                    )
                    
                    logs.append("--- Configuration Diff ---")
                    for line in config_diff.split('\n'):
                        if line.strip():
                            logs.append(f"  {line}")
                    logs.append("")
                    
                    # ISSUE 5 FIX: Generate NetBox diff with bond info for sync mode
                    # Get NetBox state for this interface
                    netbox_state = self._get_netbox_current_state(device, interface.name, vlan_id)
                    # Get bond info for NetBox diff
                    bond_info_for_netbox = None
                    bond_name_for_netbox = None
                    if bond_member_of:
                        bond_info_for_netbox = self._get_bond_interface_for_member(device, interface.name, platform=platform)
                        bond_name_for_netbox = bond_member_of
                        # If bond_info is None (NetBox doesn't have bond), create a minimal bond_info dict
                        # This ensures bond migration logic is triggered even if NetBox doesn't have the bond yet
                        if bond_info_for_netbox is None:
                            bond_info_for_netbox = {
                                'bond_name': bond_member_of,
                                'netbox_bond_name': None,
                                'device_bond_name': bond_member_of,
                                'netbox_missing_bond': True
                            }
                    
                    # Generate NetBox diff with bond migration info
                    netbox_diff = self._generate_netbox_diff(
                        netbox_state, 
                        netbox_state['proposed'],
                        bond_info=bond_info_for_netbox,
                        interface_name=interface.name,
                        bond_name=bond_name_for_netbox
                    )
                    
                    # ISSUE 7 FIX: Show NetBox Configuration Changes only once (not duplicate)
                    logs.append("--- NetBox Configuration Changes ---")
                    for line in netbox_diff.split('\n'):
                        if line.strip():
                            logs.append(f"  {line}")
                    logs.append("")
                    
                    # Configuration Changes (What Will Be Applied) - same as normal mode
                    logs.append("--- Configuration Changes (What Will Be Applied) ---")
                    logs.append("")
                    logs.append("Note: Only VLAN-related configurations will be changed.")
                    logs.append("      Other configurations (link state, type, breakout, etc.) are preserved.")
                    logs.append("")
                    
                    # Determine what's being replaced
                    target_interface_for_changes = bond_member_of if bond_member_of else interface.name
                    config_to_check_for_old_vlan = bond_interface_config if (bond_interface_config and bond_member_of) else current_device_config
                    if config_to_check_for_old_vlan:
                        import re
                        old_vlan_match = re.search(r'access\s+(\d+)', config_to_check_for_old_vlan)
                        if old_vlan_match:
                            old_vlan = old_vlan_match.group(1)
                            logs.append(f"Removed/Replaced:")
                            logs.append(f"  - nv set interface {target_interface_for_changes} bridge domain br_default access {old_vlan}")
                        else:
                            logs.append(f"Removed/Replaced:")
                            logs.append(f"  (no existing access VLAN to replace)")
                    else:
                        logs.append(f"Removed/Replaced:")
                        logs.append(f"  (no existing configuration to replace)")
                    logs.append("")
                    
                    # Show what's being added (already filtered by _generate_config_from_netbox)
                    logs.append("Added:")
                    config_lines_to_show = [line.strip() for line in config_command.split('\n') if line.strip()]
                    if config_lines_to_show:
                        for line in config_lines_to_show:
                            logs.append(f"  + {line}")
                    else:
                        logs.append("  (no new commands - all VLANs already exist on device)")
                    logs.append("")
                    
                    # Pre-Deployment Traffic Check (Cumulus only) - same as normal mode
                    # Check bonds from both NetBox and device config
                    target_interface_for_stats = interface.name
                    bond_interface_for_stats = None
                    try:
                        interface_obj = Interface.objects.get(device=device, name=interface.name)
                        if hasattr(interface_obj, 'lag') and interface_obj.lag:
                            bond_interface_for_stats = interface_obj.lag.name
                            target_interface_for_stats = bond_interface_for_stats
                        else:
                            bond_info_for_stats = self._get_bond_interface_for_member(device, interface.name, platform=platform)
                            bond_interface_for_stats = bond_info_for_stats['bond_name'] if bond_info_for_stats else None
                            if bond_interface_for_stats:
                                target_interface_for_stats = bond_interface_for_stats
                    except Interface.DoesNotExist:
                        bond_info_for_stats = self._get_bond_interface_for_member(device, interface.name, platform=platform)
                        bond_interface_for_stats = bond_info_for_stats['bond_name'] if bond_info_for_stats else None
                        if bond_interface_for_stats:
                            target_interface_for_stats = bond_interface_for_stats
                    
                    if platform == 'cumulus':
                        # Pass member interface name and bond interface (if detected) to traffic check
                        # This ensures we check the bond interface when bond is detected
                        traffic_stats = self._check_interface_traffic_stats(
                            device, 
                            interface.name,  # Member interface name (swp3)
                            platform, 
                            bond_interface=bond_interface_for_stats  # Bond name (bond3) if detected, None otherwise
                        )
                        logs.append("--- Pre-Deployment Traffic Check ---")
                        if traffic_stats.get('has_traffic'):
                            in_pkts = traffic_stats.get('in_pkts_total', 0)
                            out_pkts = traffic_stats.get('out_pkts_total', 0)
                            logs.append(f"[WARN] Active traffic detected on interface '{target_interface_for_stats}'")
                            logs.append(f"  in-pkts: {in_pkts:,}")
                            logs.append(f"  out-pkts: {out_pkts:,}")
                            logs.append(f"  WARNING: Replacing VLAN configuration will disrupt existing traffic!")
                        else:
                            logs.append(f"[OK] No active traffic detected on interface '{target_interface_for_stats}'")
                        logs.append("")
                    
                    # Note: "STARTING DEPLOYMENT" and "DEPLOYMENT EXECUTION LOGS" headers are added once 
                    # in the consolidated result, not per-interface to avoid duplicates
                    
                    # Check for configs that will be overridden (WARNING only, not blocking)
                    warnings = []
                    has_conflicts = False
                    
                    # 1. IP addresses
                    has_ip_config = interface.ip_addresses.exists()
                    if has_ip_config:
                        ip_list = [str(ip.address) for ip in interface.ip_addresses.all()]
                        warnings.append(f"IP addresses: {', '.join(ip_list)}")
                        has_conflicts = True
                    
                    # 2. VRF config
                    has_vrf_config = False
                    if hasattr(interface, 'vrf') and interface.vrf:
                        has_vrf_config = True
                        vrf_name = interface.vrf.name
                        warnings.append(f"VRF: {vrf_name}")
                        has_conflicts = True
                    # Also check IP addresses for VRF
                    if not has_vrf_config:
                        for ip_addr in interface.ip_addresses.all():
                            if hasattr(ip_addr, 'vrf') and ip_addr.vrf:
                                has_vrf_config = True
                                vrf_name = ip_addr.vrf.name if hasattr(ip_addr.vrf, 'name') else str(ip_addr.vrf)
                                warnings.append(f"VRF (on IP): {vrf_name}")
                                has_conflicts = True
                                break
                    
                    # 3. Existing access VLAN on interface (different from what we're deploying)
                    existing_access_vlan = None
                    if current_device_config and current_device_config.strip() and not "ERROR:" in current_device_config:
                        # Parse current config to find existing access VLAN
                        import re
                        # For Cumulus: "nv set interface swp32 bridge domain br_default access 3020"
                        if platform == 'cumulus':
                            access_match = re.search(r'access\s+(\d+)', current_device_config)
                            if access_match:
                                existing_access_vlan = int(access_match.group(1))
                        # For EOS: "switchport access vlan 3020"
                        elif platform == 'eos':
                            access_match = re.search(r'switchport\s+access\s+vlan\s+(\d+)', current_device_config, re.IGNORECASE)
                            if access_match:
                                existing_access_vlan = int(access_match.group(1))
                    
                    if existing_access_vlan and existing_access_vlan != vlan_id:
                        warnings.append(f"Existing access VLAN: {existing_access_vlan} (will be replaced with {vlan_id})")
                        has_conflicts = True
                    
                    # 4. Port-channel/Bond membership - handled automatically (config applied to bond)
                    # Only warn if user is applying to member interface (we'll auto-redirect to bond)
                    if hasattr(interface, 'lag') and interface.lag:
                        warnings.append(f"Interface is a bond member - VLAN config will be automatically applied to bond interface '{interface.lag.name}' instead of member '{interface.name}'")
                        has_conflicts = True
                    
                    # 5. Breakout interfaces - only warn if applying to parent (not child)
                    # Check if interface is a breakout parent (e.g., swp1-64 with 2x breakout)
                    # If applying to parent, warn; if applying to child (swp1s0), no warning needed
                    if platform == 'cumulus' and current_device_config:
                        import re
                        # Check if interface name matches a breakout parent pattern (e.g., swp1-64)
                        # and if the config shows breakout configuration
                        breakout_parent_pattern = re.match(r'^([a-zA-Z]+)(\d+)-(\d+)$', interface.name)
                        if breakout_parent_pattern:
                            # This is a parent interface (range) - check if it has breakout config
                            if 'breakout' in current_device_config.lower():
                                warnings.append(f"Interface '{interface.name}' is configured as a breakout parent. Changes may affect child interfaces (e.g., {interface.name.split('-')[0]}s0, {interface.name.split('-')[0]}s1).")
                                has_conflicts = True
                        # If interface is a breakout child (e.g., swp1s0), no warning - that's normal
                    
                    # 6. Tagged VLANs - Note: In Cumulus, tagged VLANs are bridge-level, not interface-level
                    # So we don't warn about removing tagged VLANs from interface - they're managed at bridge domain
                    # (This check removed - tagged VLANs are bridge-level in Cumulus)
                    
                    # 7. Bridge domain VLAN outside range (Cumulus only)
                    if platform == 'cumulus' and vlan_id:
                        bridge_vlans = device_config_result.get('_bridge_vlans', [])
                        if bridge_vlans:
                            # Check if VLAN is in the bridge VLAN list
                            if vlan_id not in bridge_vlans:
                                # Check if it's close to the range (within 100 of existing VLANs)
                                min_vlan = min(bridge_vlans)
                                max_vlan = max(bridge_vlans)
                                if vlan_id < min_vlan - 100 or vlan_id > max_vlan + 100:
                                    warnings.append(f"VLAN {vlan_id} is outside bridge domain range ({min_vlan}-{max_vlan}) - will be added to bridge")
                                    has_conflicts = True
                    
                    # 8. Interface disabled/enabled state
                    if hasattr(interface, 'enabled') and not interface.enabled:
                        warnings.append("Interface is disabled in NetBox (may affect deployment)")
                        has_conflicts = True
                    
                    # 9. Check for active traffic on interface (Cumulus only)
                    # Determine target interface (bond if member, otherwise original)
                    target_interface_for_stats = interface.name
                    # Check bond information from both NetBox and device config (side-by-side)
                    bond_info = self._get_bond_interface_for_member(device, interface.name, platform=platform)
                    bond_interface_for_stats = None
                    
                    # Also check device_config_result for bond_member_of (from JSON parsing)
                    bond_member_from_config = device_config_result.get('bond_member_of')
                    
                    # If bond_info is None but device config shows bond membership, create a bond_info dict
                    if not bond_info and bond_member_from_config:
                        # Device config shows bond membership but _get_bond_interface_for_member didn't find it
                        # This happens when NetBox doesn't have the bond defined
                        bond_info = {
                            'bond_name': bond_member_from_config,
                            'netbox_bond_name': None,
                            'device_bond_name': bond_member_from_config,
                            'has_mismatch': False,
                            'netbox_missing_bond': True,
                            'all_members': [],  # Will be populated if available
                            'netbox_members': []
                        }
                    
                    if bond_info:
                        bond_interface_for_stats = bond_info['bond_name']
                        target_interface_for_stats = bond_interface_for_stats
                        
                        # Always warn if interface is a bond member (inform user that config will be applied to bond)
                        bond_name = bond_info.get('bond_name', 'unknown')
                        warnings.append(f"BOND MEMBER: Interface '{interface.name}' is a member of bond '{bond_name}'. VLAN configuration will be applied to bond '{bond_name}', not to '{interface.name}' directly.")
                        has_conflicts = True  # Set as warning to inform user
                        
                        # Check for bond mismatches
                        if bond_info.get('has_mismatch'):
                            netbox_bond = bond_info.get('netbox_bond_name', 'N/A')
                            device_bond = bond_info.get('device_bond_name', 'N/A')
                            warnings.append(f"BOND MISMATCH: NetBox has bond '{netbox_bond}' but device config has bond '{device_bond}'. NetBox bond will be used as source of truth. Device bond will be migrated to match NetBox.")
                            has_conflicts = True
                        
                        # Check if NetBox is missing bond info
                        if bond_info.get('netbox_missing_bond'):
                            device_bond = bond_info.get('device_bond_name', 'N/A')
                            all_members = bond_info.get('all_members', [])
                            members_str = ', '.join(all_members) if all_members else 'unknown'
                            warnings.append(f"NETBOX MISSING BOND: Device has bond '{device_bond}' with members [{members_str}], but NetBox does not have this bond defined. In deployment mode, bond will be created in NetBox after successful config deployment. For now, please create bond '{device_bond}' in NetBox and add interfaces [{members_str}] to it, then re-run dry run.")
                            has_conflicts = True
                    
                    if platform == 'cumulus':
                        traffic_stats = self._check_interface_traffic_stats(device, interface.name, platform, bond_interface=bond_interface_for_stats)
                        if traffic_stats.get('has_traffic'):
                            in_pkts = traffic_stats.get('in_pkts_total', 0)
                            out_pkts = traffic_stats.get('out_pkts_total', 0)
                            warnings.append(f"ACTIVE TRAFFIC DETECTED: Interface '{target_interface_for_stats}' has active traffic (in-pkts: {in_pkts:,}, out-pkts: {out_pkts:,}). Replacing VLAN configuration will disrupt existing traffic.")
                            has_conflicts = True
                    
                    if has_conflicts:
                        logs.append("--- WARNING: Configuration Conflicts Detected ---")
                        logs.append("The following configurations will be overridden or may be affected during deployment:")
                        for warning in warnings:
                            logs.append(f"  - {warning}")
                        logs.append("")
                        logs.append("Note: In sync mode, deployment will proceed but these configs will be removed/modified.")
                        logs.append("")
                    
                    logs.append("=" * 80)
                    if has_conflicts:
                        logs.append("Status: Would sync from NetBox (WARNING: Config conflicts detected)")
                    else:
                        logs.append("Status: Would sync from NetBox")
                    logs.append("=" * 80)
                    
                    # Status fields (sync mode - no blocking, only warnings)
                    device_status_text = "PASS"  # Always PASS in sync mode
                    if has_conflicts:
                        interface_status_text = "WARN"
                        overall_status_text = "WARN"
                        risk_level = "MEDIUM"
                    else:
                        interface_status_text = "PASS"
                        overall_status_text = "PASS"
                        risk_level = "LOW"
                    
                    # Collect interface data for consolidated result (instead of appending individual results)
                    sync_dry_run_interface_data.append({
                        'interface': interface,
                        'interface_name': interface.name,
                        'vlan_id': vlan_id,
                        'vlan_name': vlan_name,
                        'vlan_display': vlan_display,
                        'logs': logs,
                        'config_command': config_command,
                        'device_status': device_status_text,
                        'interface_status': interface_status_text,
                        'overall_status': overall_status_text,
                        'risk_level': risk_level,
                    })
                    
                    # Track for dry run summary
                    dry_run_device_interfaces.append(interface.name)
                else:
                    # Actual deployment - generate preview logs first (same structure as dry run)
                    untagged_vid = config_info['untagged_vlan']
                    tagged_vids = config_info['tagged_vlans']
                    
                    # Generate preview logs with same structure as dry run (for consistency)
                    # This ensures deployment mode has the same logging structure as normal mode
                    preview_logs = []
                    preview_logs.append("=" * 80)
                    preview_logs.append("DEPLOYMENT MODE - CONFIGURATION PREVIEW")
                    preview_logs.append("=" * 80)
                    preview_logs.append("")
                    
                    # Get current device config for preview
                    device_config_result = self._get_current_device_config(device, interface.name, platform)
                    current_device_config = device_config_result.get('current_config', 'Unable to fetch')
                    bond_member_of = device_config_result.get('bond_member_of')
                    bond_interface_config = device_config_result.get('bond_interface_config')
                    bridge_vlans = device_config_result.get('_bridge_vlans', [])
                    
                    # Current Device Configuration section
                    preview_logs.append("--- Current Device Configuration (Real from Device) ---")
                    preview_logs.append("")
                    if bond_member_of:
                        preview_logs.append(f"Bond Membership: Interface '{interface.name}' is a member of bond '{bond_member_of}'")
                        preview_logs.append(f"Note: VLAN configuration will be applied to bond '{bond_member_of}', not to '{interface.name}' directly.")
                        preview_logs.append("")
                        preview_logs.append(f"Interface-Level Configuration (for '{interface.name}'):")
                        if current_device_config and current_device_config.strip() and not "ERROR:" in current_device_config:
                            for line in current_device_config.split('\n'):
                                if line.strip():
                                    preview_logs.append(f"  {line}")
                        else:
                            preview_logs.append("  (no configuration found for this interface)")
                        preview_logs.append("")
                        preview_logs.append(f"Bond Interface '{bond_member_of}' Configuration:")
                        if bond_interface_config and bond_interface_config.strip():
                            for line in bond_interface_config.split('\n'):
                                if line.strip():
                                    preview_logs.append(f"  {line}")
                        else:
                            preview_logs.append("  (unable to retrieve bond interface configuration)")
                    else:
                        preview_logs.append(f"Interface-Level Configuration:")
                        if current_device_config and current_device_config.strip() and not "ERROR:" in current_device_config:
                            for line in current_device_config.split('\n'):
                                if line.strip():
                                    preview_logs.append(f"  {line}")
                        else:
                            preview_logs.append("  (unable to retrieve or no configuration)")
                    preview_logs.append("")
                    
                    # Bridge-Level Configuration
                    if platform == 'cumulus':
                        preview_logs.append("Bridge-Level Configuration (br_default):")
                        if bridge_vlans and len(bridge_vlans) > 0:
                            vlan_list_str = self._format_vlan_list(bridge_vlans)
                            preview_logs.append(f"  nv set bridge domain br_default vlan {vlan_list_str}")
                        else:
                            preview_logs.append("  (bridge VLAN information not available)")
                        preview_logs.append("")
                    
                    # Proposed Device Configuration
                    target_interface_for_preview = bond_member_of if bond_member_of else interface.name
                    preview_logs.append("--- Proposed Device Configuration ---")
                    # Show bond creation note if bond is being created
                    if bond_creation_commands:
                        preview_logs.append(f"[NOTE] Bond '{bond_detected_early}' will be created on device (NetBox has bond, device doesn't)")
                        preview_logs.append(f"       Bond creation commands:")
                        for cmd in bond_creation_commands:
                            preview_logs.append(f"         {cmd}")
                        preview_logs.append("")
                    # Regenerate config_command with bond interface if needed
                    preview_config_command = config_command
                    if bond_member_of and target_interface_for_preview != interface.name:
                        if platform == 'cumulus':
                            regenerated_commands = []
                            
                            # IMPORTANT: Prepend bond creation commands if bond is being created
                            if bond_creation_commands:
                                regenerated_commands.extend(bond_creation_commands)
                            
                            all_vlans = set()
                            if untagged_vid:
                                all_vlans.add(untagged_vid)
                            all_vlans.update(tagged_vids)
                            for vlan_vid in sorted(all_vlans):
                                if not self._is_vlan_in_bridge_vlans(vlan_vid, bridge_vlans):
                                    regenerated_commands.append(f"nv set bridge domain br_default vlan {vlan_vid}")
                            if untagged_vid:
                                regenerated_commands.append(f"nv set interface {target_interface_for_preview} bridge domain br_default access {untagged_vid}")
                            preview_config_command = '\n'.join(regenerated_commands)
                    for line in preview_config_command.split('\n'):
                        if line.strip():
                            preview_logs.append(f"  {line}")
                    preview_logs.append("")
                    
                    # Current NetBox Configuration
                    netbox_current = {
                        'untagged_vlan': interface.untagged_vlan.vid if interface.untagged_vlan else None,
                        'tagged_vlans': list(interface.tagged_vlans.values_list('vid', flat=True)),
                        'mode': getattr(interface, 'mode', None),
                        'ip_addresses': [str(ip.address) for ip in interface.ip_addresses.all()],
                        'vrf': interface.vrf.name if hasattr(interface, 'vrf') and interface.vrf else None,
                        'cable_status': 'Connected' if interface.cable else 'Not Connected',
                        'enabled': interface.enabled if hasattr(interface, 'enabled') else True,
                        'port_channel_member': bool(interface.lag) if hasattr(interface, 'lag') else False,
                    }
                    preview_logs.append("--- Current NetBox Configuration (Source of Truth) ---")
                    preview_logs.append(f"802.1Q Mode: {netbox_current['mode'] or 'None'}")
                    preview_logs.append(f"Untagged VLAN: {netbox_current['untagged_vlan'] or 'None'}")
                    tagged_vlans_str = ', '.join(map(str, netbox_current['tagged_vlans'])) if netbox_current['tagged_vlans'] else 'None'
                    preview_logs.append(f"Tagged VLANs: [{tagged_vlans_str}]")
                    ip_addresses_str = ', '.join(netbox_current['ip_addresses']) if netbox_current['ip_addresses'] else 'None'
                    preview_logs.append(f"IP Addresses: {ip_addresses_str}")
                    preview_logs.append(f"VRF: {netbox_current['vrf'] or 'None'}")
                    preview_logs.append(f"Cable Status: {netbox_current['cable_status']}")
                    preview_logs.append(f"Enabled: {netbox_current['enabled']}")
                    preview_logs.append(f"Port-Channel Member: {netbox_current['port_channel_member']}")
                    preview_logs.append("")
                    
                    # Configuration Conflict Detection
                    preview_logs.append("--- Configuration Conflict Detection ---")
                    device_config_has_vlan = False
                    device_vlan_id = None
                    if current_device_config:
                        import re
                        vlan_match = re.search(r'access\s+(\d+)', current_device_config.lower())
                        if vlan_match:
                            device_config_has_vlan = True
                            device_vlan_id = int(vlan_match.group(1))
                    netbox_has_vlan = netbox_current.get('untagged_vlan') is not None
                    netbox_vlan_id = netbox_current.get('untagged_vlan')
                    conflict_detected = False
                    if netbox_has_vlan and not device_config_has_vlan:
                        conflict_detected = True
                        preview_logs.append(f"[WARN] Device config differs from NetBox config")
                        preview_logs.append(f"  Conflicts detected: NetBox has VLAN {netbox_vlan_id} configured but device has no VLAN config")
                        preview_logs.append("")
                        preview_logs.append("Device Should Have (According to NetBox):")
                        all_netbox_vlans = set()
                        if netbox_current.get('untagged_vlan'):
                            all_netbox_vlans.add(netbox_current['untagged_vlan'])
                        all_netbox_vlans.update(netbox_current.get('tagged_vlans', []))
                        for vlan_vid in sorted(all_netbox_vlans):
                            if not self._is_vlan_in_bridge_vlans(vlan_vid, bridge_vlans):
                                preview_logs.append(f"  nv set bridge domain br_default vlan {vlan_vid}")
                        if netbox_current.get('untagged_vlan'):
                            preview_logs.append(f"  nv set interface {target_interface_for_preview} bridge domain br_default access {netbox_current['untagged_vlan']}")
                        preview_logs.append("")
                        preview_logs.append("Note: NetBox is the source of truth. Device may have stale/old configuration.")
                        preview_logs.append("      Any differences will be reconciled during deployment.")
                    else:
                        preview_logs.append("[OK] Device config matches NetBox - no conflicts detected")
                    preview_logs.append("")
                    
                    # Config Diff
                    target_interface_for_diff = bond_member_of if bond_member_of else interface.name
                    current_config_with_bridge = current_device_config or ""
                    if platform == 'cumulus' and bridge_vlans:
                        bridge_vlan_cmds = []
                        for vlan_item in bridge_vlans:
                            if isinstance(vlan_item, (int, str)):
                                if isinstance(vlan_item, str) and '-' in vlan_item:
                                    bridge_vlan_cmds.append(f"nv set bridge domain br_default vlan {vlan_item}")
                                else:
                                    try:
                                        vlan_id = int(vlan_item) if isinstance(vlan_item, str) else vlan_item
                                        bridge_vlan_cmds.append(f"nv set bridge domain br_default vlan {vlan_id}")
                                    except (ValueError, TypeError):
                                        pass
                        if bridge_vlan_cmds:
                            if current_config_with_bridge:
                                current_config_with_bridge = '\n'.join(bridge_vlan_cmds) + '\n' + current_config_with_bridge
                            else:
                                current_config_with_bridge = '\n'.join(bridge_vlan_cmds)
                    config_diff = self._generate_config_diff(
                        current_config_with_bridge,
                        preview_config_command,
                        platform,
                        device=device,
                        interface_name=target_interface_for_diff,
                        bridge_vlans=bridge_vlans
                    )
                    preview_logs.append("--- Config Diff ---")
                    preview_logs.append("(Shows what will be removed/replaced and what will be added)")
                    preview_logs.append("")
                    for line in config_diff.split('\n'):
                        if line.strip():
                            preview_logs.append(f"  {line}")
                    preview_logs.append("")
                    
                    # NetBox Configuration Changes
                    netbox_state = self._get_netbox_current_state(device, interface.name, untagged_vid or (tagged_vids[0] if tagged_vids else None))
                    bond_info_for_netbox = None
                    bond_name_for_netbox = None
                    if bond_member_of:
                        bond_info_for_netbox = self._get_bond_interface_for_member(device, interface.name, platform=platform)
                        bond_name_for_netbox = bond_member_of
                        if bond_info_for_netbox is None:
                            bond_info_for_netbox = {
                                'bond_name': bond_member_of,
                                'netbox_bond_name': None,
                                'device_bond_name': bond_member_of,
                                'netbox_missing_bond': True
                            }
                    netbox_diff = self._generate_netbox_diff(
                        netbox_state,
                        netbox_state['proposed'],
                        bond_info=bond_info_for_netbox,
                        interface_name=interface.name,
                        bond_name=bond_name_for_netbox
                    )
                    preview_logs.append("--- NetBox Configuration Changes ---")
                    for line in netbox_diff.split('\n'):
                        if line.strip():
                            preview_logs.append(f"  {line}")
                    preview_logs.append("")
                    
                    # Configuration Changes (What Will Be Applied)
                    preview_logs.append("--- Configuration Changes (What Will Be Applied) ---")
                    preview_logs.append("")
                    preview_logs.append("Note: Only VLAN-related configurations will be changed.")
                    preview_logs.append("      Other configurations (link state, type, breakout, etc.) are preserved.")
                    preview_logs.append("")
                    config_to_check_for_old_vlan = bond_interface_config if (bond_interface_config and bond_member_of) else current_device_config
                    if config_to_check_for_old_vlan:
                        import re
                        old_vlan_match = re.search(r'access\s+(\d+)', config_to_check_for_old_vlan)
                        if old_vlan_match:
                            old_vlan = old_vlan_match.group(1)
                            preview_logs.append(f"Removed/Replaced:")
                            preview_logs.append(f"  - nv set interface {target_interface_for_preview} bridge domain br_default access {old_vlan}")
                        else:
                            preview_logs.append(f"Removed/Replaced:")
                            preview_logs.append(f"  (no existing access VLAN to replace)")
                    else:
                        preview_logs.append(f"Removed/Replaced:")
                        preview_logs.append(f"  (no existing configuration to replace)")
                    preview_logs.append("")
                    preview_logs.append("Added:")
                    config_lines_to_show = [line.strip() for line in preview_config_command.split('\n') if line.strip()]
                    if config_lines_to_show:
                        for line in config_lines_to_show:
                            preview_logs.append(f"  + {line}")
                    else:
                        preview_logs.append("  (no new commands - all VLANs already exist on device)")
                    preview_logs.append("")
                    
                    # Pre-Deployment Traffic Check
                    # Check bonds from both NetBox and device config
                    target_interface_for_stats = interface.name
                    bond_interface_for_stats = None
                    try:
                        interface_obj = Interface.objects.get(device=device, name=interface.name)
                        if hasattr(interface_obj, 'lag') and interface_obj.lag:
                            bond_interface_for_stats = interface_obj.lag.name
                            target_interface_for_stats = bond_interface_for_stats
                        else:
                            bond_info_for_stats = self._get_bond_interface_for_member(device, interface.name, platform=platform)
                            bond_interface_for_stats = bond_info_for_stats['bond_name'] if bond_info_for_stats else None
                            if bond_interface_for_stats:
                                target_interface_for_stats = bond_interface_for_stats
                    except Interface.DoesNotExist:
                        bond_info_for_stats = self._get_bond_interface_for_member(device, interface.name, platform=platform)
                        bond_interface_for_stats = bond_info_for_stats['bond_name'] if bond_info_for_stats else None
                        if bond_interface_for_stats:
                            target_interface_for_stats = bond_interface_for_stats
                    
                    if platform == 'cumulus':
                        # Pass member interface name and bond interface (if detected) to traffic check
                        # This ensures we check the bond interface when bond is detected
                        traffic_stats = self._check_interface_traffic_stats(
                            device, 
                            interface.name,  # Member interface name (swp3)
                            platform, 
                            bond_interface=bond_interface_for_stats  # Bond name (bond3) if detected, None otherwise
                        )
                        preview_logs.append("--- Pre-Deployment Traffic Check ---")
                        if traffic_stats.get('has_traffic'):
                            in_pkts = traffic_stats.get('in_pkts_total', 0)
                            out_pkts = traffic_stats.get('out_pkts_total', 0)
                            preview_logs.append(f"[WARN] Active traffic detected on interface '{target_interface_for_stats}'")
                            preview_logs.append(f"  in-pkts: {in_pkts:,}")
                            preview_logs.append(f"  out-pkts: {out_pkts:,}")
                            preview_logs.append(f"  WARNING: Replacing VLAN configuration will disrupt existing traffic!")
                        else:
                            preview_logs.append(f"[OK] No active traffic detected on interface '{target_interface_for_stats}'")
                        preview_logs.append("")
                    
                    # Note: "STARTING DEPLOYMENT" and "DEPLOYMENT EXECUTION LOGS" headers are added once 
                    # in the consolidated result, not per-interface to avoid duplicates
                    
                    # Pre-deployment traffic check (Cumulus only)
                    target_interface_for_stats = config_info.get('target_interface', interface.name)
                    pre_traffic_stats = None
                    if platform == 'cumulus':
                        pre_traffic_stats = self._check_interface_traffic_stats(device, interface.name, platform, bond_interface=target_interface_for_stats if target_interface_for_stats != interface.name else None)
                        if pre_traffic_stats.get('has_traffic'):
                            in_pkts = pre_traffic_stats.get('in_pkts_total', 0)
                            out_pkts = pre_traffic_stats.get('out_pkts_total', 0)
                            logger.warning(f"PRE-CHECK: Active traffic detected on {device.name}:{target_interface_for_stats} (in-pkts: {in_pkts:,}, out-pkts: {out_pkts:,})")
                    
                    # Use target_interface (bond if member) for deployment, but keep interface.name for display
                    target_interface = config_info.get('target_interface', interface.name)
                    
                    # IMPORTANT: If bond detected, regenerate config_command with bond interface name
                    # This ensures all commands use bond3 instead of swp3
                    # Get bridge VLANs to check if VLANs already exist
                    bridge_vlans_for_check = []
                    try:
                        device_config_result = self._get_current_device_config(device, interface.name, platform)
                        bridge_vlans_for_check = device_config_result.get('_bridge_vlans', [])
                    except Exception:
                        pass
                    
                    if target_interface != interface.name:
                        # Bond detected - regenerate config_command with bond interface
                        # IMPORTANT: Include bond creation commands if bond is being created
                        regenerated_commands = []
                        
                        # Prepend bond creation commands if they exist
                        if bond_creation_commands:
                            regenerated_commands.extend(bond_creation_commands)
                            logger.info(f"Including {len(bond_creation_commands)} bond creation commands in config")
                        
                        if platform == 'cumulus':
                            # Regenerate bridge VLAN commands
                            all_vlans = set()
                            if untagged_vid:
                                all_vlans.add(untagged_vid)
                            all_vlans.update(tagged_vids)
                            
                            # ISSUE 1 FIX: Only add VLANs that don't already exist in bridge
                            for vlan_vid in sorted(all_vlans):
                                if not self._is_vlan_in_bridge_vlans(vlan_vid, bridge_vlans_for_check):
                                    regenerated_commands.append(f"nv set bridge domain br_default vlan {vlan_vid}")
                                    logger.debug(f"VLAN {vlan_vid} not in bridge - will add")
                                else:
                                    logger.debug(f"VLAN {vlan_vid} already exists in bridge - skipping")
                            
                            # Set interface access VLAN using bond interface
                            if untagged_vid:
                                regenerated_commands.append(f"nv set interface {target_interface} bridge domain br_default access {untagged_vid}")
                            
                            config_command = '\n'.join(regenerated_commands)
                            logger.info(f"Regenerated config_command with bond interface {target_interface} instead of {interface.name} (includes {len(bond_creation_commands) if bond_creation_commands else 0} bond creation commands)")
                        # For EOS, would need similar regeneration
                    
                    # Collect interface data for batched deployment
                    vlan_id = untagged_vid or (tagged_vids[0] if tagged_vids else None)
                    interfaces_with_configs.append({
                        'interface': interface,
                        'config_command': config_command,
                        'target_interface': target_interface,
                        'vlan_id': vlan_id,
                        'preview_logs': preview_logs,
                        'pre_traffic_stats': pre_traffic_stats,
                        'target_interface_for_stats': target_interface_for_stats,
                        'config_info': config_info,
                        'untagged_vid': untagged_vid,
                        'tagged_vids': tagged_vids,
                        'bond_migrated': config_info.get('bond_migrated', False),
                        'old_bond_name': config_info.get('old_bond_name'),
                        'bond_traffic_warning': config_info.get('bond_traffic_warning')
                    })
            
            # Add consolidated dry run result for all interfaces on this device
            if dry_run and sync_dry_run_interface_data:
                # Create single consolidated result showing all interfaces
                consolidated_logs = []
                consolidated_logs.append("=" * 80)
                consolidated_logs.append(f"DEVICE-LEVEL DEPLOYMENT: {device.name}")
                consolidated_logs.append(f"Deploying {len(sync_dry_run_interface_data)} interface(s) - DRY RUN (SYNC MODE)")
                consolidated_logs.append("=" * 80)
                consolidated_logs.append("")
                
                # Add each interface's CURRENT state (not proposed)
                for idx, iface_data in enumerate(sync_dry_run_interface_data, 1):
                    consolidated_logs.append(f"[{idx}/{len(sync_dry_run_interface_data)}] Interface: {iface_data['interface_name']}")
                    consolidated_logs.append("=" * 80)
                    
                    # Parse logs to show only current state sections
                    # KEEP: NetBox Configuration Changes (shows bond migration - important!)
                    in_proposed_section = False
                    for line in iface_data['logs']:
                        # Detect start of proposed/diff/changes sections to skip
                        if any(marker in line for marker in [
                            '--- Proposed Device Configuration',
                            '--- Config Diff ---',
                            '--- Configuration Changes (What Will Be Applied)',
                            '--- Pre-Deployment Traffic Check'
                        ]):
                            in_proposed_section = True
                            continue
                        
                        # Detect end of sections we want to skip
                        if in_proposed_section and line.strip().startswith('---'):
                            in_proposed_section = False
                            # Fall through to add this line
                        
                        # Only add lines that are NOT in proposed sections
                        if not in_proposed_section:
                            consolidated_logs.append(line)
                    
                    consolidated_logs.append("")
                
                # Add consolidated proposed configuration section
                consolidated_logs.append("=" * 80)
                consolidated_logs.append("CONSOLIDATED PROPOSED CONFIGURATION (ALL INTERFACES)")
                consolidated_logs.append("=" * 80)
                consolidated_logs.append("")
                consolidated_logs.append("--- Proposed Device Configuration ---")
                consolidated_logs.append("Commands that will be applied in single batch:")
                consolidated_logs.append("")
                consolidated_logs.append("[NOTE] When bond is detected:")
                consolidated_logs.append("       - Commands use BOND interface (e.g., bond3), not member interface (e.g., swp3)")
                consolidated_logs.append("       - NetBox changes affect BOND, VLANs migrated from member to bond")
                consolidated_logs.append("       - Traffic checks run on BOND interface, not member")
                consolidated_logs.append("")
                for iface_data in sync_dry_run_interface_data:
                    if iface_data.get('config_command'):
                        # Check if bond by looking at commands (contains bond interface name)
                        has_bond = False
                        for line in iface_data['config_command'].split('\n'):
                            if line.strip() and 'bond' in line.lower() and 'nv set interface bond' in line:
                                has_bond = True
                                break
                        
                        if has_bond:
                            consolidated_logs.append(f"  Member Interface: {iface_data['interface_name']} → Target: BOND (detected)")
                        else:
                            consolidated_logs.append(f"  Interface: {iface_data['interface_name']}")
                        
                        for line in iface_data['config_command'].split('\n'):
                            if line.strip():
                                consolidated_logs.append(f"    {line.strip()}")
                        consolidated_logs.append("")
                
                # Add batching summary at the end
                consolidated_logs.append("=" * 80)
                consolidated_logs.append("BATCHED DEPLOYMENT SUMMARY - SYNC MODE")
                consolidated_logs.append("=" * 80)
                consolidated_logs.append("")
                consolidated_logs.append(f"[BATCH] All {len(sync_dry_run_interface_data)} interface(s) would be deployed together")
                consolidated_logs.append(f"        in a single atomic commit-confirm session.")
                consolidated_logs.append("")
                consolidated_logs.append("Interfaces in this batch:")
                for iface_data in sync_dry_run_interface_data:
                    consolidated_logs.append(f"  - {iface_data['interface_name']}")
                consolidated_logs.append("")
                consolidated_logs.append("Benefits of batched deployment:")
                consolidated_logs.append("  [OK] Single commit-confirm session (no conflicts)")
                consolidated_logs.append("  [OK] Atomic rollback (all-or-nothing)")
                consolidated_logs.append("  [OK] Faster execution (one SSH session)")
                consolidated_logs.append("  [OK] Consistent state (all interfaces updated simultaneously)")
                consolidated_logs.append("")
                
                # Determine overall status (worst case among all interfaces)
                overall_status = "PASS"
                risk_level = "LOW"
                for iface_data in sync_dry_run_interface_data:
                    if iface_data.get('overall_status') == "WARN":
                        overall_status = "WARN"
                        risk_level = "MEDIUM"
                        break
                
                # Create single consolidated result
                results.append({
                    'device': device,
                    'interface': f"Batched ({len(sync_dry_run_interface_data)} interfaces)",
                    'vlan_id': 'N/A',
                    'vlan_name': 'Sync Mode - Batch Deployment',
                    'status': 'success',
                    'message': f'Would sync {len(sync_dry_run_interface_data)} interface(s) from NetBox',
                    'deployment_logs': '\n'.join(consolidated_logs),
                    'dry_run': True,
                    'device_status': "PASS",
                    'interface_status': "INFO",
                    'overall_status': overall_status,
                    'risk_level': risk_level,
                    '_interface_count': len(sync_dry_run_interface_data),
                    '_interface_names': [iface_data['interface_name'] for iface_data in sync_dry_run_interface_data],
                })
            
            # Deploy all interfaces for this device in single commit-confirm session
            if interfaces_with_configs:
                batched_results = self._batch_deploy_interfaces_per_device(
                        device, 
                    interfaces_with_configs, 
                        platform, 
                    dry_run=dry_run
                )
                
                # _batch_deploy_interfaces_per_device returns a list with ONE consolidated result per device
                # Extract the single result
                if batched_results:
                    result = batched_results[0]
                    
                    # Post-deployment traffic checks for all interfaces (Cumulus only)
                    if not dry_run and platform == 'cumulus' and result.get('success') and result.get('committed'):
                        # Check traffic for each interface that was deployed
                        for item in interfaces_with_configs:
                            target_interface_for_stats = item.get('target_interface_for_stats', item['interface'].name)
                            target_interface = item.get('target_interface', item['interface'].name)
                            pre_traffic_stats = item.get('pre_traffic_stats')
                            
                            # Determine if bond was detected (target_interface != interface.name means bond)
                            bond_interface_for_post_check = target_interface if target_interface != item['interface'].name else None
                            
                            if pre_traffic_stats:
                                # Pass member interface name and bond interface (if detected) to traffic check
                                post_traffic_stats = self._check_interface_traffic_stats(
                                    device, 
                                    item['interface'].name,  # Member interface name (swp3)
                                    platform, 
                                    bond_interface=bond_interface_for_post_check  # Bond name (bond3) if detected, None otherwise
                                )
                                if post_traffic_stats:
                                    pre_in = pre_traffic_stats.get('in_pkts_total', 0)
                                    pre_out = pre_traffic_stats.get('out_pkts_total', 0)
                                    post_in = post_traffic_stats.get('in_pkts_total', 0)
                                    post_out = post_traffic_stats.get('out_pkts_total', 0)
                                    in_increment = post_in - pre_in
                                    out_increment = post_out - pre_out
                                    result['logs'].append("")
                                    result['logs'].append(f"--- Post-Deployment Traffic Check: {target_interface_for_stats} ---")
                                    result['logs'].append(f"Pre-deployment:  in-pkts: {pre_in:,}, out-pkts: {pre_out:,}")
                                    result['logs'].append(f"Post-deployment: in-pkts: {post_in:,}, out-pkts: {post_out:,}")
                                    result['logs'].append(f"Traffic change:  in-pkts: +{in_increment:,}, out-pkts: +{out_increment:,}")
                                    if post_traffic_stats.get('has_traffic'):
                                        result['logs'].append(f"[OK] Interface '{target_interface_for_stats}' is still passing traffic after deployment")
                                    else:
                                        result['logs'].append(f"[WARN] No traffic detected on interface '{target_interface_for_stats}' after deployment - verify connectivity")
                                    result['logs'].append("")
                    
                    # NetBox updates and bond sync (only if deployment succeeded and not dry run)
                    if not dry_run and result.get('success') and result.get('committed'):
                        interfaces_to_update_netbox = []
                        bonds_to_sync = set()  # Track bonds that need syncing
                        processed_bonds = set()  # Track bonds we've already synced
                        
                        for item in interfaces_with_configs:
                            interface = item['interface']
                            target_interface = item.get('target_interface', interface.name)
                            untagged_vid = item.get('untagged_vid')
                            tagged_vids = item.get('tagged_vids', [])
                            
                            # Determine which interface to update in NetBox
                            # If bond detected, update bond interface; otherwise update member interface
                            netbox_interface_to_update = target_interface if target_interface != interface.name else interface.name
                            
                            # Check if bond needs syncing or VLAN migration
                            if target_interface != interface.name:
                                # Bond detected - check if NetBox has this bond
                                bond_info = self._get_bond_interface_for_member(device, interface.name, platform=platform)
                                if bond_info:
                                    device_bond = bond_info.get('device_bond_name')
                                    if device_bond and device_bond not in processed_bonds:
                                        if bond_info.get('netbox_missing_bond'):
                                            # Bond doesn't exist in NetBox - sync it
                                            bonds_to_sync.add((device_bond, bond_info))
                                        else:
                                            # Bond exists in NetBox - check if VLANs need migration
                                            # Check if member interface has VLANs that should be on bond
                                            try:
                                                member_iface = Interface.objects.get(device=device, name=interface.name)
                                                if member_iface.untagged_vlan or member_iface.tagged_vlans.exists():
                                                    # Member has VLANs - need to migrate to bond
                                                    bonds_to_sync.add((device_bond, bond_info))
                                            except Interface.DoesNotExist:
                                                pass
                            
                            # For sync mode, we need to update NetBox with the actual VLANs deployed
                            # Use untagged VLAN if available, otherwise use first tagged VLAN
                            vlan_to_update = untagged_vid if untagged_vid else (tagged_vids[0] if tagged_vids else None)
                            
                            if vlan_to_update:
                                interfaces_to_update_netbox.append({
                                    'interface': interface,
                                    'interface_name': interface.name,
                                    'netbox_interface': netbox_interface_to_update,
                                    'target_interface': target_interface,
                                    'vlan_id': vlan_to_update
                                })
                        
                        # Sync bonds to NetBox first (before updating VLANs)
                        bond_sync_results = []
                        for device_bond, bond_info in bonds_to_sync:
                            all_members = bond_info.get('all_members', [])
                            if all_members:
                                # Check if bond exists in NetBox or needs to be created
                                if bond_info.get('netbox_missing_bond'):
                                    # Bond doesn't exist - create it and migrate VLANs
                                    bond_sync_result = self._sync_bond_to_netbox(device, device_bond, all_members, platform=platform)
                                else:
                                    # Bond exists - just migrate VLANs from members to bond
                                    bond_sync_result = self._migrate_vlans_to_bond(device, device_bond, all_members, platform=platform)
                                    # Convert migration result to same format as sync result
                                    bond_sync_result = {
                                        'success': bond_sync_result['success'],
                                        'bond_created': False,  # Bond already exists
                                        'members_added': 0,  # Members already added
                                        'vlans_migrated': bond_sync_result.get('vlans_migrated', 0),
                                        'vlans_migrated_from': bond_sync_result.get('vlans_migrated_from', []),
                                        'error': bond_sync_result.get('error'),
                                    }
                                
                                bond_sync_results.append({
                                    'device': device.name,
                                    'bond': device_bond,
                                    'success': bond_sync_result['success'],
                                    'bond_created': bond_sync_result.get('bond_created', False),
                                    'members_added': bond_sync_result.get('members_added', 0),
                                    'vlans_migrated': bond_sync_result.get('vlans_migrated', 0),
                                    'error': bond_sync_result.get('error'),
                                })
                                processed_bonds.add(device_bond)
                                
                                # Add bond sync/migration info to deployment logs
                                if bond_sync_result.get('success'):
                                    if bond_sync_result.get('bond_created', False):
                                        result['logs'].append("")
                                        result['logs'].append(f"[NetBox] Bond '{device_bond}' synced to NetBox (created: True, members: {bond_sync_result.get('members_added', 0)}, VLANs migrated: {bond_sync_result.get('vlans_migrated', 0)})")
                                    else:
                                        result['logs'].append("")
                                        result['logs'].append(f"[NetBox] Migrated VLANs from member interfaces to bond '{device_bond}' (VLANs migrated: {bond_sync_result.get('vlans_migrated', 0)})")
                                else:
                                    result['logs'].append("")
                                    result['logs'].append(f"[NetBox] Bond sync/migration failed: {bond_sync_result.get('error', 'Unknown error')}")
                        
                        # Update NetBox interfaces with VLAN assignments
                        netbox_update_results = {}  # Store results to avoid duplicate calls
                        for update_info in interfaces_to_update_netbox:
                            interface_name = update_info['interface_name']
                            netbox_interface_to_update = update_info['netbox_interface']
                            vlan_id = update_info['vlan_id']
                            
                            # Update NetBox interface (bond if detected, member otherwise)
                            netbox_result = self._update_netbox_interface(device, netbox_interface_to_update, vlan_id)
                            netbox_update_results[interface_name] = {
                                'result': netbox_result,
                                'netbox_interface': netbox_interface_to_update
                            }
                            
                            # Add NetBox update info to deployment logs
                            if netbox_result.get('success'):
                                if netbox_interface_to_update != interface_name:
                                    result['logs'].append("")
                                    result['logs'].append(f"[NetBox] Updated bond interface '{netbox_interface_to_update}' (member: '{interface_name}') with VLAN {vlan_id}")
                                else:
                                    result['logs'].append("")
                                    result['logs'].append(f"[NetBox] Updated interface '{interface_name}' with VLAN {vlan_id}")
                            else:
                                result['logs'].append("")
                                result['logs'].append(f"[NetBox] Failed to update interface '{netbox_interface_to_update}': {netbox_result.get('error', 'Unknown error')}")
                        
                        # Add bond sync summary if any bonds were synced
                        if bond_sync_results:
                            successful_syncs = [r for r in bond_sync_results if r['success']]
                            if successful_syncs:
                                logger.info(f"[BOND-SYNC] Successfully synced {len(successful_syncs)} bond(s) to NetBox for device {device.name}")
                    
                    # Add section identifier
                    result['section'] = 'tagged'
                    
                    # Convert logs list to string if needed
                    if isinstance(result.get('logs'), list):
                        result['deployment_logs'] = '\n'.join(result['logs'])
                    elif 'deployment_logs' not in result:
                        result['deployment_logs'] = result.get('message', '')
                    
                    results.append(result)
        
        # Process Section 2: Missing NetBox tags interfaces (only if deploy_missing_tags is True)
        interfaces_to_auto_tag = []
        interfaces_with_conflicting_tags = []  # Track interfaces with uplink/routed tags
        if deploy_missing_tags:
            for device in devices:
                device_interfaces = missing_tags_interfaces_by_device.get(device.name, [])
                
                if not device_interfaces:
                    continue
                
                # Collect all interfaces with their configs for batched deployment
                missing_tags_interfaces_with_configs = []
                dry_run_device_interfaces_missing_tags = []  # Track interfaces for dry run summary
                sync_dry_run_interface_data_missing_tags = []  # Collect all interface data for consolidated dry run result
                
                # Get device bridge VLANs ONCE per device (not per interface)
                device_bridge_vlans = []
                if device_interfaces:
                    try:
                        first_interface = device_interfaces[0]
                        device_config_result = self._get_current_device_config(device, first_interface.name, platform)
                        device_bridge_vlans = device_config_result.get('_bridge_vlans', [])
                    except Exception as e:
                        logger.warning(f"Could not fetch bridge VLANs for device {device.name}: {e}")
                
                for interface in device_interfaces:
                    # PRE-CHECK: Bond detection for missing_tags interfaces
                    bond_detected_early = None
                    netbox_bond = None
                    bond_creation_commands = []
                    bond_deletion_commands = []
                    bond_traffic_warning = None
                    old_bond_name = None
                    
                    try:
                        device_config_check = self._get_current_device_config(device, interface.name, platform)
                        bond_detected_early = device_config_check.get('bond_member_of')
                    except Exception:
                        pass
                    
                    if hasattr(interface, 'lag') and interface.lag:
                        netbox_bond = interface.lag.name
                    
                    # Handle bond scenarios
                    if netbox_bond and not bond_detected_early:
                        # Scenario 3: CREATE - NetBox has bond, device doesn't
                        logger.info(f"[BOND AUTO-CREATE] NetBox has bond {netbox_bond}, device doesn't - will create bond on device")
                        # Get all members of this bond from NetBox
                        member_interfaces = []
                        try:
                            lag_interfaces = Interface.objects.filter(device=device, lag=interface.lag)
                            member_interfaces = [iface.name for iface in lag_interfaces]
                        except Exception as e:
                            logger.warning(f"Could not get LAG members: {e}")
                            member_interfaces = [interface.name]
                        bond_creation_commands = self._generate_bond_creation_commands(netbox_bond, member_interfaces, platform)
                        bond_detected_early = netbox_bond
                    elif bond_detected_early and netbox_bond and bond_detected_early != netbox_bond:
                        old_bond_name = bond_detected_early
                        try:
                            traffic_check = self._check_interface_traffic_stats(device, old_bond_name, platform)
                            if traffic_check.get('has_traffic'):
                                bond_traffic_warning = f"[TRAFFIC] Bond '{old_bond_name}' is carrying traffic!"
                        except Exception:
                            pass
                        bond_deletion_commands = self._generate_bond_deletion_commands(old_bond_name, platform)
                        # Get all members of NetBox bond
                        member_interfaces = []
                        try:
                            lag_interfaces = Interface.objects.filter(device=device, lag=interface.lag)
                            member_interfaces = [iface.name for iface in lag_interfaces]
                        except Exception as e:
                            logger.warning(f"Could not get LAG members: {e}")
                            member_interfaces = [interface.name]
                        bond_creation_commands = self._generate_bond_creation_commands(netbox_bond, member_interfaces, platform)
                        bond_detected_early = netbox_bond
                    
                    # Generate config from NetBox state
                    # IMPORTANT: Pass force_bond_interface if bond was detected/created to ensure VLAN configs use bond interface
                    logger.info(f"[CONFIG GEN] Calling _generate_config_from_netbox() for {device.name}:{interface.name}, force_bond_interface={bond_detected_early}")
                    config_info = self._generate_config_from_netbox(
                        device, 
                        interface, 
                        platform, 
                        existing_bridge_vlans=device_bridge_vlans,
                        force_bond_interface=bond_detected_early if bond_detected_early else None
                    )
                    config_commands = config_info['commands']
                    
                    # PREPEND bond commands
                    if bond_deletion_commands or bond_creation_commands:
                        all_bond_commands = bond_deletion_commands + bond_creation_commands
                        config_commands = all_bond_commands + config_commands
                        config_info['commands'] = config_commands
                        config_info['bond_migrated'] = bool(bond_deletion_commands)
                        config_info['old_bond_name'] = old_bond_name
                        config_info['bond_traffic_warning'] = bond_traffic_warning
                    
                    # Combine commands into single config string (for deployment)
                    config_command = '\n'.join(config_commands) if isinstance(config_commands, list) else config_commands
                    
                    if dry_run:
                        # Dry run mode - show what would be deployed
                        device_config_result = self._get_current_device_config(device, interface.name, platform)
                        current_device_config = device_config_result.get('current_config', 'Unable to fetch')
                        config_source = device_config_result.get('source', 'error')
                        
                        # Get bond info early for config regeneration
                        bond_member_of = device_config_result.get('bond_member_of')
                        
                        untagged_vid = config_info['untagged_vlan']
                        tagged_vids = config_info['tagged_vlans']
                        
                        # Get VLAN ID and name for display
                        # Use untagged VLAN if available, otherwise first tagged VLAN
                        vlan_id = untagged_vid if untagged_vid else (tagged_vids[0] if tagged_vids else None)
                        vlan_name = 'N/A'
                        if vlan_id:
                            try:
                                vlan_obj = VLAN.objects.filter(vid=vlan_id).first()
                                if vlan_obj:
                                    vlan_name = vlan_obj.name or f"VLAN {vlan_id}"
                                else:
                                    vlan_name = f"VLAN {vlan_id}"
                            except Exception:
                                vlan_name = f"VLAN {vlan_id}"
                        
                        # Format VLAN display (show untagged and tagged if both exist)
                        if untagged_vid and tagged_vids:
                            vlan_display = f"{untagged_vid} (untagged) + {', '.join(map(str, tagged_vids))} (tagged)"
                        elif untagged_vid:
                            vlan_display = str(untagged_vid)
                        elif tagged_vids:
                            vlan_display = ', '.join(map(str, tagged_vids))
                        else:
                            vlan_display = 'N/A'
                        
                        netbox_state = {
                            'current': {
                                'untagged_vlan': interface.untagged_vlan.vid if interface.untagged_vlan else None,
                                'tagged_vlans': list(interface.tagged_vlans.values_list('vid', flat=True)),
                                'mode': getattr(interface, 'mode', None),
                            },
                            'proposed': {
                                'untagged_vlan': untagged_vid,
                                'tagged_vlans': tagged_vids,
                                'mode': config_info['mode'],
                            }
                        }
                        
                        # Generate deployment logs
                        logs = []
                        logs.append("=" * 80)
                        logs.append("SYNC MODE DRY RUN - PREVIEW ONLY (MISSING NETBOX TAGS INTERFACE)")
                        logs.append("=" * 80)
                        logs.append("")
                        logs.append("[NOTE] This interface will be deployed in a BATCHED commit with all other")
                        logs.append(f"       interfaces on device '{device.name}' in a single atomic session.")
                        logs.append("       All interface configs will be applied together with one commit-confirm.")
                        logs.append("")
                        logs.append(f"Device: {device.name}")
                        logs.append(f"Interface: {interface.name}")
                        logs.append(f"Platform: {platform.upper()}")
                        logs.append("")
                        logs.append("--- NetBox VLAN Configuration (Source of Truth) ---")
                        if untagged_vid:
                            logs.append(f"Untagged VLAN: {untagged_vid}")
                        if tagged_vids:
                            logs.append(f"Tagged VLANs: {', '.join(map(str, tagged_vids))}")
                        logs.append(f"Mode: {config_info['mode']}")
                        logs.append("")
                        logs.append("Note: This interface is currently untagged in NetBox.")
                        logs.append("      After successful deployment, it will be auto-tagged as 'vlan-mode:access' or 'vlan-mode:tagged'.")
                        logs.append("")
                        # If bond detected, regenerate config_command with bond interface name
                        # IMPORTANT: Include ALL VLANs (untagged + tagged) from this interface
                        # Also check if NetBox has bond but device doesn't (bond creation needed)
                        netbox_bond_for_dryrun_missing_tags = None
                        if hasattr(interface, 'lag') and interface.lag:
                            netbox_bond_for_dryrun_missing_tags = interface.lag.name
                        
                        if bond_member_of or netbox_bond_for_dryrun_missing_tags:
                            # Regenerate config with bond interface instead of member interface
                            # Use device bond if exists, otherwise use NetBox bond
                            target_interface = bond_member_of if bond_member_of else netbox_bond_for_dryrun_missing_tags
                            
                            # Regenerate config_command using target_interface (bond) - include ALL VLANs
                            if platform == 'cumulus':
                                regenerated_commands = []
                                
                                # IMPORTANT: Prepend bond creation commands if NetBox has bond but device doesn't
                                if netbox_bond_for_dryrun_missing_tags and not bond_member_of:
                                    # NetBox has bond, device doesn't - need to create bond
                                    # Get all members of this bond from NetBox
                                    member_interfaces = []
                                    try:
                                        lag_interfaces = Interface.objects.filter(device=device, lag=interface.lag)
                                        member_interfaces = [iface.name for iface in lag_interfaces]
                                    except Exception as e:
                                        logger.warning(f"Could not get LAG members: {e}")
                                        member_interfaces = [interface.name]
                                    
                                    bond_creation_commands_dryrun_missing_tags = self._generate_bond_creation_commands(
                                        netbox_bond_for_dryrun_missing_tags, 
                                        member_interfaces, 
                                        platform
                                    )
                                    regenerated_commands.extend(bond_creation_commands_dryrun_missing_tags)
                                    logger.info(f"[DRY RUN] Including {len(bond_creation_commands_dryrun_missing_tags)} bond creation commands for {netbox_bond_for_dryrun_missing_tags} (NetBox has bond, device doesn't)")
                                
                                # Collect ALL VLANs from this interface (untagged + tagged)
                                all_vlans = set()
                                if untagged_vid:
                                    all_vlans.add(untagged_vid)
                                all_vlans.update(tagged_vids)
                                
                                # Generate bridge VLAN commands for ALL VLANs
                                for vlan_vid in sorted(all_vlans):
                                    regenerated_commands.append(f"nv set bridge domain br_default vlan {vlan_vid}")
                                
                                # Set interface access VLAN using bond interface (if untagged VLAN exists)
                                if untagged_vid:
                                    regenerated_commands.append(f"nv set interface {target_interface} bridge domain br_default access {untagged_vid}")
                                
                                config_command = '\n'.join(regenerated_commands)
                            # For EOS, would need similar regeneration
                        
                        # Generate diff AFTER bond detection and config_command regeneration
                        target_interface_for_diff = bond_member_of if bond_member_of else interface.name
                        config_diff = self._generate_config_diff(
                            current_device_config, 
                            config_command, 
                            platform, 
                            device=device, 
                            interface_name=target_interface_for_diff
                        )
                        
                        # Current Device Configuration (shown FIRST for consistency)
                        logs.append("--- Current Device Configuration (Real from Device) ---")
                        logs.append("")
                        # Check if interface is a bond member
                        bond_interface_config = device_config_result.get('bond_interface_config')
                        
                        if bond_member_of:
                            logs.append(f"Bond Membership: Interface '{interface.name}' is a member of bond '{bond_member_of}'")
                            logs.append(f"Note: VLAN configuration will be applied to bond '{bond_member_of}', not to '{interface.name}' directly.")
                            logs.append("")
                            logs.append(f"Interface-Level Configuration (for '{interface.name}'):")
                            if current_device_config and current_device_config.strip() and not "ERROR:" in current_device_config:
                                for line in current_device_config.split('\n'):
                                    if line.strip():
                                        logs.append(f"  {line}")
                            else:
                                logs.append("  (no configuration found for this interface)")
                            logs.append("")
                            logs.append(f"Bond Interface '{bond_member_of}' Configuration:")
                            if bond_interface_config and bond_interface_config.strip():
                                for line in bond_interface_config.split('\n'):
                                    if line.strip():
                                        logs.append(f"  {line}")
                            else:
                                logs.append("  (unable to retrieve bond interface configuration)")
                        else:
                            # Not a bond member - show interface config normally
                            logs.append(f"Interface-Level Configuration:")
                            if current_device_config and current_device_config.strip() and not "ERROR:" in current_device_config:
                                for line in current_device_config.split('\n'):
                                    if line.strip():
                                        logs.append(f"  {line}")
                            else:
                                logs.append("  (unable to retrieve or no configuration)")
                        logs.append("")
                        
                        # Bridge-Level Configuration (for Cumulus)
                        bridge_vlans_sync = device_config_result.get('_bridge_vlans', [])
                        if platform == 'cumulus':
                            logs.append("Bridge-Level Configuration (br_default):")
                            if bridge_vlans_sync and len(bridge_vlans_sync) > 0:
                                vlan_list_str = self._format_vlan_list(bridge_vlans_sync)
                                logs.append(f"  nv set bridge domain br_default vlan {vlan_list_str}")
                            else:
                                logs.append("  (bridge VLAN information not available)")
                            logs.append("")
                        
                        # Proposed Device Configuration (shown AFTER current for consistency)
                        logs.append("--- Proposed Device Configuration ---")
                        # Show bond creation note if bond is being created
                        if bond_creation_commands:
                            logs.append(f"[NOTE] Bond '{bond_detected_early}' will be created on device (NetBox has bond, device doesn't)")
                            logs.append(f"       Bond creation commands:")
                            for cmd in bond_creation_commands:
                                logs.append(f"         {cmd}")
                            logs.append("")
                        # config_command already includes ALL VLANs (untagged + tagged) from this interface
                        # AND bond creation commands (if any) are prepended to config_command
                        for line in config_command.split('\n'):
                            if line.strip():
                                logs.append(f"  {line}")
                        logs.append("")
                        
                        logs.append("--- Configuration Diff ---")
                        for line in config_diff.split('\n'):
                            if line.strip():
                                logs.append(f"  {line}")
                        logs.append("")
                        # Check for configs that will be overridden (WARNING only, not blocking)
                        warnings = []
                        has_conflicts = False
                        
                        # 1. IP addresses
                        has_ip_config = interface.ip_addresses.exists()
                        if has_ip_config:
                            ip_list = [str(ip.address) for ip in interface.ip_addresses.all()]
                            warnings.append(f"IP addresses: {', '.join(ip_list)}")
                            has_conflicts = True
                        
                        # 2. VRF config
                        has_vrf_config = False
                        if hasattr(interface, 'vrf') and interface.vrf:
                            has_vrf_config = True
                            vrf_name = interface.vrf.name
                            warnings.append(f"VRF: {vrf_name}")
                            has_conflicts = True
                        # Also check IP addresses for VRF
                        if not has_vrf_config:
                            for ip_addr in interface.ip_addresses.all():
                                if hasattr(ip_addr, 'vrf') and ip_addr.vrf:
                                    has_vrf_config = True
                                    vrf_name = ip_addr.vrf.name if hasattr(ip_addr.vrf, 'name') else str(ip_addr.vrf)
                                    warnings.append(f"VRF (on IP): {vrf_name}")
                                    has_conflicts = True
                                    break
                        
                        # 3. Existing access VLAN on interface (different from what we're deploying)
                        existing_access_vlan = None
                        if current_device_config and current_device_config.strip() and not "ERROR:" in current_device_config:
                            # Parse current config to find existing access VLAN
                            import re
                            # For Cumulus: "nv set interface swp32 bridge domain br_default access 3020"
                            if platform == 'cumulus':
                                access_match = re.search(r'access\s+(\d+)', current_device_config)
                                if access_match:
                                    existing_access_vlan = int(access_match.group(1))
                            # For EOS: "switchport access vlan 3020"
                            elif platform == 'eos':
                                access_match = re.search(r'switchport\s+access\s+vlan\s+(\d+)', current_device_config, re.IGNORECASE)
                                if access_match:
                                    existing_access_vlan = int(access_match.group(1))
                        
                        if existing_access_vlan and existing_access_vlan != vlan_id:
                            warnings.append(f"Existing access VLAN: {existing_access_vlan} (will be replaced with {vlan_id})")
                            has_conflicts = True
                        
                        # 4. Port-channel/Bond membership - handled automatically (config applied to bond)
                        # Check both NetBox and device config for bond membership
                        bond_info_section2 = self._get_bond_interface_for_member(device, interface.name, platform=platform)
                        
                        # Also check device_config_result for bond_member_of (from JSON parsing)
                        bond_member_from_config_section2 = device_config_result.get('bond_member_of')
                        
                        # If bond_info is None but device config shows bond membership, create a bond_info dict
                        if not bond_info_section2 and bond_member_from_config_section2:
                            # Device config shows bond membership but _get_bond_interface_for_member didn't find it
                            # This happens when NetBox doesn't have the bond defined
                            bond_info_section2 = {
                                'bond_name': bond_member_from_config_section2,
                                'netbox_bond_name': None,
                                'device_bond_name': bond_member_from_config_section2,
                                'has_mismatch': False,
                                'netbox_missing_bond': True,
                                'all_members': [],  # Will be populated if available
                                'netbox_members': []
                            }
                        
                        if bond_info_section2:
                            bond_name_section2 = bond_info_section2.get('bond_name', 'unknown')
                            warnings.append(f"BOND MEMBER: Interface '{interface.name}' is a member of bond '{bond_name_section2}'. VLAN configuration will be applied to bond '{bond_name_section2}', not to '{interface.name}' directly.")
                            has_conflicts = True
                            
                            # Check for bond mismatches
                            if bond_info_section2.get('has_mismatch'):
                                netbox_bond = bond_info_section2.get('netbox_bond_name', 'N/A')
                                device_bond = bond_info_section2.get('device_bond_name', 'N/A')
                                warnings.append(f"BOND MISMATCH: NetBox has bond '{netbox_bond}' but device config has bond '{device_bond}'. NetBox bond will be used as source of truth. Device bond will be migrated to match NetBox.")
                                has_conflicts = True
                            
                            # Check if NetBox is missing bond info
                            if bond_info_section2.get('netbox_missing_bond'):
                                device_bond = bond_info_section2.get('device_bond_name', 'N/A')
                                all_members = bond_info_section2.get('all_members', [])
                                members_str = ', '.join(all_members) if all_members else 'unknown'
                                warnings.append(f"NETBOX MISSING BOND: Device has bond '{device_bond}' with members [{members_str}], but NetBox does not have this bond defined. In deployment mode, bond will be created in NetBox after successful config deployment. For now, please create bond '{device_bond}' in NetBox and add interfaces [{members_str}] to it, then re-run dry run.")
                                has_conflicts = True
                        elif hasattr(interface, 'lag') and interface.lag:
                            # NetBox has bond but device config check didn't find it (fallback to NetBox only)
                            warnings.append(f"Interface is a bond member (NetBox) - VLAN config will be automatically applied to bond interface '{interface.lag.name}' instead of member '{interface.name}'")
                            has_conflicts = True
                        
                        # 5. Breakout interfaces - only warn if applying to parent (not child)
                        # Check if interface is a breakout parent (e.g., swp1-64 with 2x breakout)
                        # If applying to parent, warn; if applying to child (swp1s0), no warning needed
                        if platform == 'cumulus' and current_device_config:
                            import re
                            # Check if interface name matches a breakout parent pattern (e.g., swp1-64)
                            # and if the config shows breakout configuration
                            breakout_parent_pattern = re.match(r'^([a-zA-Z]+)(\d+)-(\d+)$', interface.name)
                            if breakout_parent_pattern:
                                # This is a parent interface (range) - check if it has breakout config
                                if 'breakout' in current_device_config.lower():
                                    warnings.append(f"Interface '{interface.name}' is configured as a breakout parent. Changes may affect child interfaces (e.g., {interface.name.split('-')[0]}s0, {interface.name.split('-')[0]}s1).")
                                    has_conflicts = True
                            # If interface is a breakout child (e.g., swp1s0), no warning - that's normal
                        
                        # 6. Tagged VLANs (if we're deploying untagged/access, but interface has tagged VLANs)
                        if tagged_vids and len(tagged_vids) > 0:
                            # This is OK - we're syncing tagged VLANs from NetBox
                            pass
                        elif interface.tagged_vlans.exists() and not tagged_vids:
                            # Interface has tagged VLANs in NetBox but we're only deploying untagged
                            existing_tagged = list(interface.tagged_vlans.values_list('vid', flat=True))
                            warnings.append(f"Interface has tagged VLANs in NetBox: {', '.join(map(str, existing_tagged))} (will be removed)")
                            has_conflicts = True
                        
                        # 7. Bridge domain VLAN outside range (Cumulus only)
                        if platform == 'cumulus' and vlan_id:
                            bridge_vlans = device_config_result.get('_bridge_vlans', [])
                            if bridge_vlans:
                                # Check if VLAN is in the bridge VLAN list
                                if vlan_id not in bridge_vlans:
                                    # Check if it's close to the range (within 100 of existing VLANs)
                                    min_vlan = min(bridge_vlans)
                                    max_vlan = max(bridge_vlans)
                                    if vlan_id < min_vlan - 100 or vlan_id > max_vlan + 100:
                                        warnings.append(f"VLAN {vlan_id} is outside bridge domain range ({min_vlan}-{max_vlan}) - will be added to bridge")
                                        has_conflicts = True
                        
                        # 7. Interface disabled/enabled state
                        if hasattr(interface, 'enabled') and not interface.enabled:
                            warnings.append("Interface is disabled in NetBox (may affect deployment)")
                            has_conflicts = True
                        
                        if has_conflicts:
                            logs.append("--- WARNING: Configuration Conflicts Detected ---")
                            logs.append("The following configurations will be overridden or may be affected during deployment:")
                            for warning in warnings:
                                logs.append(f"  - {warning}")
                            logs.append("")
                            logs.append("Note: In sync mode, deployment will proceed but these configs will be removed/modified.")
                            logs.append("")
                        
                        logs.append("=" * 80)
                        if has_conflicts:
                            logs.append("Status: Would sync from NetBox (WARNING: Config conflicts detected, will be auto-tagged)")
                        else:
                            logs.append("Status: Would sync from NetBox (will be auto-tagged after deployment)")
                        logs.append("=" * 80)
                        
                        # Status fields (sync mode - no blocking, only warnings)
                        device_status_text = "PASS"  # Always PASS in sync mode
                        if has_conflicts:
                            interface_status_text = "WARN"
                            overall_status_text = "WARN"
                            risk_level = "MEDIUM"
                        else:
                            interface_status_text = "PASS"
                            overall_status_text = "PASS"
                            risk_level = "LOW"
                        
                        # Collect interface data for consolidated result (instead of appending individual results)
                        sync_dry_run_interface_data_missing_tags.append({
                            'interface': interface,
                            'interface_name': interface.name,
                            'vlan_id': vlan_id,
                            'vlan_name': vlan_name,
                            'vlan_display': vlan_display,
                            'logs': logs,
                            'config_command': config_command,
                            'device_status': device_status_text,
                            'interface_status': interface_status_text,
                            'overall_status': overall_status_text,
                            'risk_level': risk_level,
                        })
                        
                        # Track for dry run summary
                        dry_run_device_interfaces_missing_tags.append(interface.name)
                    else:
                        # Actual deployment
                        # Get current device config to check for bond membership
                        device_config_result = self._get_current_device_config(device, interface.name, platform)
                        bond_member_of = device_config_result.get('bond_member_of')
                        
                        untagged_vid = config_info['untagged_vlan']
                        tagged_vids = config_info['tagged_vlans']
                        
                        # Pre-deployment traffic check (Cumulus only)
                        target_interface_for_stats = config_info.get('target_interface', interface.name)
                        pre_traffic_stats = None
                        if platform == 'cumulus':
                            pre_traffic_stats = self._check_interface_traffic_stats(device, interface.name, platform, bond_interface=target_interface_for_stats if target_interface_for_stats != interface.name else None)
                            if pre_traffic_stats.get('has_traffic'):
                                in_pkts = pre_traffic_stats.get('in_pkts_total', 0)
                                out_pkts = pre_traffic_stats.get('out_pkts_total', 0)
                                logger.warning(f"PRE-CHECK: Active traffic detected on {device.name}:{target_interface_for_stats} (in-pkts: {in_pkts:,}, out-pkts: {out_pkts:,})")
                        
                        # Use target_interface (bond if member) for deployment, but keep interface.name for display
                        target_interface = config_info.get('target_interface', interface.name)
                        
                        # IMPORTANT: Check bond_member_of from device config if _generate_config_from_netbox didn't detect it
                        # This handles cases where NetBox doesn't have bond info but device config shows bond membership
                        if target_interface == interface.name and bond_member_of:
                            target_interface = bond_member_of
                            logger.info(f"Bond detected from device config: {interface.name} is member of {bond_member_of}, using {bond_member_of} for deployment")
                        
                        # IMPORTANT: If bond detected, regenerate config_command with bond interface name
                        # This ensures all commands use bond3 instead of swp3
                        if target_interface != interface.name:
                            # Bond detected - regenerate config_command with bond interface
                            if platform == 'cumulus':
                                regenerated_commands = []
                                
                                # IMPORTANT: Prepend bond creation commands if bond is being created
                                if bond_creation_commands:
                                    regenerated_commands.extend(bond_creation_commands)
                                    logger.info(f"Including {len(bond_creation_commands)} bond creation commands in untagged config")
                                
                                # Regenerate bridge VLAN commands
                                all_vlans = set()
                                if untagged_vid:
                                    all_vlans.add(untagged_vid)
                                all_vlans.update(tagged_vids)
                                
                                for vlan_vid in sorted(all_vlans):
                                    regenerated_commands.append(f"nv set bridge domain br_default vlan {vlan_vid}")
                                
                                # Set interface access VLAN using bond interface
                                if untagged_vid:
                                    regenerated_commands.append(f"nv set interface {target_interface} bridge domain br_default access {untagged_vid}")
                                
                                config_command = '\n'.join(regenerated_commands)
                                logger.info(f"Regenerated config_command with bond interface {target_interface} instead of {interface.name} (includes {len(bond_creation_commands) if bond_creation_commands else 0} bond creation commands)")
                                logger.debug(f"Regenerated config_command: {config_command}")
                            # For EOS, would need similar regeneration
                        
                        # CRITICAL: Ensure config_command uses target_interface (bond3) not interface.name (swp3)
                        # Replace any remaining instances of interface.name with target_interface in config_command
                        if target_interface != interface.name and platform == 'cumulus':
                            # Final safety check - replace any remaining member interface with bond interface
                            original_config_command = config_command
                            config_command = config_command.replace(f"interface {interface.name} ", f"interface {target_interface} ")
                            config_command = config_command.replace(f"interface {interface.name}\n", f"interface {target_interface}\n")
                            config_command = config_command.replace(f"nv set interface {interface.name} ", f"nv set interface {target_interface} ")
                            config_command = config_command.replace(f"nv set interface {interface.name}\n", f"nv set interface {target_interface}\n")
                            if config_command.strip().endswith(f"interface {interface.name}"):
                                config_command = config_command.replace(f"interface {interface.name}", f"interface {target_interface}")
                            if f"nv set interface {interface.name}" in config_command:
                                config_command = config_command.replace(f"nv set interface {interface.name}", f"nv set interface {target_interface}")
                            
                            if original_config_command != config_command:
                                logger.warning(f"CRITICAL FIX: Replaced {interface.name} with {target_interface} in config_command")
                                logger.debug(f"Original: {original_config_command}")
                                logger.debug(f"Fixed: {config_command}")
                            
                            # Verify no member interface remains
                            if f"nv set interface {interface.name}" in config_command:
                                logger.error(f"ERROR: Member interface {interface.name} still found in config_command after replacement!")
                                logger.error(f"Config command: {config_command}")
                                # Force regenerate one more time
                                regenerated_commands = []
                                
                                # IMPORTANT: Include bond creation commands if bond is being created
                                if bond_creation_commands:
                                    regenerated_commands.extend(bond_creation_commands)
                                    logger.info(f"Including {len(bond_creation_commands)} bond creation commands in forced regeneration")
                                
                                all_vlans = set()
                                if untagged_vid:
                                    all_vlans.add(untagged_vid)
                                all_vlans.update(tagged_vids)
                                for vlan_vid in sorted(all_vlans):
                                    regenerated_commands.append(f"nv set bridge domain br_default vlan {vlan_vid}")
                                if untagged_vid:
                                    regenerated_commands.append(f"nv set interface {target_interface} bridge domain br_default access {untagged_vid}")
                                config_command = '\n'.join(regenerated_commands)
                                logger.error(f"FORCED REGENERATION: {config_command}")
                        
                        # Collect interface data for batched deployment
                        vlan_id = untagged_vid or (tagged_vids[0] if tagged_vids else None)
                        missing_tags_interfaces_with_configs.append({
                            'interface': interface,
                            'config_command': config_command,
                            'target_interface': target_interface,
                            'vlan_id': vlan_id,
                            'preview_logs': logs if dry_run else [],
                            'pre_traffic_stats': pre_traffic_stats,
                            'target_interface_for_stats': target_interface_for_stats,
                            'config_info': config_info,
                            'untagged_vid': untagged_vid,
                            'tagged_vids': tagged_vids,
                            'bond_migrated': config_info.get('bond_migrated', False),
                            'old_bond_name': config_info.get('old_bond_name'),
                            'bond_traffic_warning': config_info.get('bond_traffic_warning')
                        })
            
            # Add consolidated dry run result for all missing_netbox_tags interfaces on this device
            if dry_run and sync_dry_run_interface_data_missing_tags:
                # Create single consolidated result showing all interfaces
                consolidated_logs = []
                consolidated_logs.append("=" * 80)
                consolidated_logs.append(f"DEVICE-LEVEL DEPLOYMENT: {device.name}")
                consolidated_logs.append(f"Deploying {len(sync_dry_run_interface_data_missing_tags)} interface(s) - DRY RUN (SYNC MODE - MISSING NETBOX TAGS)")
                consolidated_logs.append("=" * 80)
                consolidated_logs.append("")
                
                # Add each interface's CURRENT state (not proposed)
                for idx, iface_data in enumerate(sync_dry_run_interface_data_missing_tags, 1):
                    consolidated_logs.append(f"[{idx}/{len(sync_dry_run_interface_data_missing_tags)}] Interface: {iface_data['interface_name']}")
                    consolidated_logs.append("=" * 80)
                    
                    # Parse logs to show only current state sections
                    # KEEP: NetBox Configuration Changes (shows bond migration - important!)
                    in_proposed_section = False
                    for line in iface_data['logs']:
                        # Detect start of proposed/diff/changes sections to skip
                        if any(marker in line for marker in [
                            '--- Proposed Device Configuration',
                            '--- Config Diff ---',
                            '--- Configuration Changes (What Will Be Applied)',
                            '--- Pre-Deployment Traffic Check'
                        ]):
                            in_proposed_section = True
                            continue
                        
                        # Detect end of sections we want to skip
                        if in_proposed_section and line.strip().startswith('---'):
                            in_proposed_section = False
                            # Fall through to add this line
                        
                        # Only add lines that are NOT in proposed sections
                        if not in_proposed_section:
                            consolidated_logs.append(line)
                    
                    consolidated_logs.append("")
                
                # Add consolidated proposed configuration section
                consolidated_logs.append("=" * 80)
                consolidated_logs.append("CONSOLIDATED PROPOSED CONFIGURATION (ALL INTERFACES)")
                consolidated_logs.append("=" * 80)
                consolidated_logs.append("")
                consolidated_logs.append("--- Proposed Device Configuration ---")
                consolidated_logs.append("Commands that will be applied in single batch:")
                consolidated_logs.append("")
                consolidated_logs.append("[NOTE] When bond is detected:")
                consolidated_logs.append("       - Commands use BOND interface (e.g., bond3), not member interface (e.g., swp3)")
                consolidated_logs.append("       - NetBox changes affect BOND, VLANs migrated from member to bond")
                consolidated_logs.append("       - Traffic checks run on BOND interface, not member")
                consolidated_logs.append("")
                for iface_data in sync_dry_run_interface_data_missing_tags:
                    if iface_data.get('config_command'):
                        # Check if bond by looking at commands (contains bond interface name)
                        has_bond = False
                        for line in iface_data['config_command'].split('\n'):
                            if line.strip() and 'bond' in line.lower() and 'nv set interface bond' in line:
                                has_bond = True
                                break
                        
                        if has_bond:
                            consolidated_logs.append(f"  Member Interface: {iface_data['interface_name']} → Target: BOND (detected)")
                        else:
                            consolidated_logs.append(f"  Interface: {iface_data['interface_name']}")
                        
                        for line in iface_data['config_command'].split('\n'):
                            if line.strip():
                                consolidated_logs.append(f"    {line.strip()}")
                        consolidated_logs.append("")
                
                # Add batching summary at the end
                consolidated_logs.append("=" * 80)
                consolidated_logs.append("BATCHED DEPLOYMENT SUMMARY - SYNC MODE (MISSING NETBOX TAGS INTERFACES)")
                consolidated_logs.append("=" * 80)
                consolidated_logs.append("")
                consolidated_logs.append(f"[BATCH] All {len(sync_dry_run_interface_data_missing_tags)} missing_netbox_tags interface(s) would be deployed")
                consolidated_logs.append(f"        together in a single atomic commit-confirm session.")
                consolidated_logs.append("")
                consolidated_logs.append("Missing NetBox tags interfaces in this batch:")
                for iface_data in sync_dry_run_interface_data_missing_tags:
                    consolidated_logs.append(f"  - {iface_data['interface_name']}")
                consolidated_logs.append("")
                consolidated_logs.append("Auto-tagging after deployment:")
                consolidated_logs.append("  - All interfaces will be auto-tagged as 'vlan-mode:access' or 'vlan-mode:tagged'")
                consolidated_logs.append("  - Conflicting tags (uplink/routed) will be replaced if detected")
                consolidated_logs.append("")
                consolidated_logs.append("Benefits of batched deployment:")
                consolidated_logs.append("  [OK] Single commit-confirm session (no conflicts)")
                consolidated_logs.append("  [OK] Atomic rollback (all-or-nothing)")
                consolidated_logs.append("  [OK] Faster execution (one SSH session)")
                consolidated_logs.append("  [OK] Consistent state (all interfaces updated simultaneously)")
                consolidated_logs.append("")
                
                # Determine overall status (worst case among all interfaces)
                overall_status = "PASS"
                risk_level = "LOW"
                for iface_data in sync_dry_run_interface_data_missing_tags:
                    if iface_data.get('overall_status') == "WARN":
                        overall_status = "WARN"
                        risk_level = "MEDIUM"
                        break
                
                # Create single consolidated result
                results.append({
                    'device': device,
                    'interface': f"Batched ({len(sync_dry_run_interface_data_missing_tags)} missing_netbox_tags interfaces)",
                    'vlan_id': 'N/A',
                    'vlan_name': 'Sync Mode - Batch Deployment (Missing NetBox Tags)',
                    'status': 'success',
                    'message': f'Would sync {len(sync_dry_run_interface_data_missing_tags)} missing_netbox_tags interface(s) from NetBox',
                    'deployment_logs': '\n'.join(consolidated_logs),
                    'dry_run': True,
                    'section': 'untagged',
                    'device_status': "PASS",
                    'interface_status': "INFO",
                    'overall_status': overall_status,
                    'risk_level': risk_level,
                    '_interface_count': len(sync_dry_run_interface_data_missing_tags),
                    '_interface_names': [iface_data['interface_name'] for iface_data in sync_dry_run_interface_data_missing_tags],
                })
            
            # Deploy all missing_netbox_tags interfaces for this device in single commit-confirm session
            if missing_tags_interfaces_with_configs:
                batched_results = self._batch_deploy_interfaces_per_device(
                            device, 
                    missing_tags_interfaces_with_configs, 
                            platform, 
                    dry_run=dry_run
                )
                
                # _batch_deploy_interfaces_per_device returns a list with ONE consolidated result per device
                # Extract the single result
                if batched_results:
                    result = batched_results[0]
                    
                    # Post-deployment traffic checks for all interfaces (Cumulus only)
                    if not dry_run and platform == 'cumulus' and result.get('success') and result.get('committed'):
                        # Check traffic for each interface that was deployed
                        for item in missing_tags_interfaces_with_configs:
                            interface = item['interface']
                            target_interface_for_stats = item.get('target_interface_for_stats', interface.name)
                            pre_traffic_stats = item.get('pre_traffic_stats')
                            
                            if pre_traffic_stats:
                                post_traffic_stats = self._check_interface_traffic_stats(device, interface.name, platform, bond_interface=target_interface_for_stats if target_interface_for_stats != interface.name else None)
                                if post_traffic_stats:
                                    pre_in = pre_traffic_stats.get('in_pkts_total', 0)
                                    pre_out = pre_traffic_stats.get('out_pkts_total', 0)
                                    post_in = post_traffic_stats.get('in_pkts_total', 0)
                                    post_out = post_traffic_stats.get('out_pkts_total', 0)
                                    in_increment = post_in - pre_in
                                    out_increment = post_out - pre_out
                                    result['logs'].append("")
                                    result['logs'].append(f"--- Post-Deployment Traffic Check: {target_interface_for_stats} ---")
                                    result['logs'].append(f"Pre-deployment:  in-pkts: {pre_in:,}, out-pkts: {pre_out:,}")
                                    result['logs'].append(f"Post-deployment: in-pkts: {post_in:,}, out-pkts: {post_out:,}")
                                    result['logs'].append(f"Traffic change:  in-pkts: +{in_increment:,}, out-pkts: +{out_increment:,}")
                                    if post_traffic_stats.get('has_traffic'):
                                        result['logs'].append(f"[OK] Interface '{target_interface_for_stats}' is still passing traffic after deployment")
                                    else:
                                        result['logs'].append(f"[WARN] No traffic detected on interface '{target_interface_for_stats}' after deployment - verify connectivity")
                                    result['logs'].append("")
                    
                    # NetBox updates and bond sync (only if deployment succeeded and not dry run)
                    if not dry_run and result.get('success') and result.get('committed'):
                        interfaces_to_update_netbox = []
                        bonds_to_sync = set()  # Track bonds that need syncing
                        processed_bonds = set()  # Track bonds we've already synced
                        
                        for item in missing_tags_interfaces_with_configs:
                            interface = item['interface']
                            target_interface = item.get('target_interface', interface.name)
                            untagged_vid = item.get('untagged_vid')
                            
                            # Determine which interface to update in NetBox
                            # If bond detected, update bond interface; otherwise update member interface
                            netbox_interface_to_update = target_interface if target_interface != interface.name else interface.name
                            
                            # Check if bond needs syncing or VLAN migration
                            if target_interface != interface.name:
                                # Bond detected - check if NetBox has this bond
                                bond_info = self._get_bond_interface_for_member(device, interface.name, platform=platform)
                                if bond_info:
                                    device_bond = bond_info.get('device_bond_name')
                                    if device_bond and device_bond not in processed_bonds:
                                        if bond_info.get('netbox_missing_bond'):
                                            # Bond doesn't exist in NetBox - sync it
                                            bonds_to_sync.add((device_bond, bond_info))
                                        else:
                                            # Bond exists in NetBox - check if VLANs need migration
                                            # Check if member interface has VLANs that should be on bond
                                            try:
                                                member_iface = Interface.objects.get(device=device, name=interface.name)
                                                if member_iface.untagged_vlan or member_iface.tagged_vlans.exists():
                                                    # Member has VLANs - need to migrate to bond
                                                    bonds_to_sync.add((device_bond, bond_info))
                                            except Interface.DoesNotExist:
                                                pass
                            
                            # For missing_netbox_tags interfaces (Section 2), use untagged VLAN from NetBox
                            if untagged_vid:
                                interfaces_to_update_netbox.append({
                                    'interface': interface,
                                    'interface_name': interface.name,
                                    'netbox_interface': netbox_interface_to_update,
                                    'target_interface': target_interface,
                                    'vlan_id': untagged_vid
                                })
                        
                        # Sync bonds to NetBox first (before updating VLANs)
                        bond_sync_results = []
                        for device_bond, bond_info in bonds_to_sync:
                            all_members = bond_info.get('all_members', [])
                            if all_members:
                                # Check if bond exists in NetBox or needs to be created
                                if bond_info.get('netbox_missing_bond'):
                                    # Bond doesn't exist - create it and migrate VLANs
                                    bond_sync_result = self._sync_bond_to_netbox(device, device_bond, all_members, platform=platform)
                                else:
                                    # Bond exists - just migrate VLANs from members to bond
                                    bond_sync_result = self._migrate_vlans_to_bond(device, device_bond, all_members, platform=platform)
                                    # Convert migration result to same format as sync result
                                    bond_sync_result = {
                                        'success': bond_sync_result['success'],
                                        'bond_created': False,  # Bond already exists
                                        'members_added': 0,  # Members already added
                                        'vlans_migrated': bond_sync_result.get('vlans_migrated', 0),
                                        'vlans_migrated_from': bond_sync_result.get('vlans_migrated_from', []),
                                        'error': bond_sync_result.get('error'),
                                    }
                                
                                bond_sync_results.append({
                                    'device': device.name,
                                    'bond': device_bond,
                                    'success': bond_sync_result['success'],
                                    'bond_created': bond_sync_result.get('bond_created', False),
                                    'members_added': bond_sync_result.get('members_added', 0),
                                    'vlans_migrated': bond_sync_result.get('vlans_migrated', 0),
                                    'error': bond_sync_result.get('error'),
                                })
                                processed_bonds.add(device_bond)
                                
                                # Add bond sync/migration info to deployment logs
                                if bond_sync_result.get('success'):
                                    if bond_sync_result.get('bond_created', False):
                                        result['logs'].append("")
                                        result['logs'].append(f"[NetBox] Bond '{device_bond}' synced to NetBox (created: True, members: {bond_sync_result.get('members_added', 0)}, VLANs migrated: {bond_sync_result.get('vlans_migrated', 0)})")
                                    else:
                                        result['logs'].append("")
                                        result['logs'].append(f"[NetBox] Migrated VLANs from member interfaces to bond '{device_bond}' (VLANs migrated: {bond_sync_result.get('vlans_migrated', 0)})")
                                else:
                                    result['logs'].append("")
                                    result['logs'].append(f"[NetBox] Bond sync/migration failed: {bond_sync_result.get('error', 'Unknown error')}")
                        
                        # Update NetBox interfaces with VLAN assignments
                        netbox_update_results = {}  # Store results to avoid duplicate calls
                        for update_info in interfaces_to_update_netbox:
                            interface_name = update_info['interface_name']
                            netbox_interface_to_update = update_info['netbox_interface']
                            vlan_id = update_info['vlan_id']
                            
                            # Update NetBox interface (bond if detected, member otherwise)
                            netbox_result = self._update_netbox_interface(device, netbox_interface_to_update, vlan_id)
                            netbox_update_results[interface_name] = {
                                'result': netbox_result,
                                'netbox_interface': netbox_interface_to_update
                            }
                            
                            # Add NetBox update info to deployment logs
                            if netbox_result.get('success'):
                                if netbox_interface_to_update != interface_name:
                                    result['logs'].append("")
                                    result['logs'].append(f"[NetBox] Updated bond interface '{netbox_interface_to_update}' (member: '{interface_name}') with VLAN {vlan_id}")
                                else:
                                    result['logs'].append("")
                                    result['logs'].append(f"[NetBox] Updated interface '{interface_name}' with VLAN {vlan_id}")
                            else:
                                result['logs'].append("")
                                result['logs'].append(f"[NetBox] Failed to update interface '{netbox_interface_to_update}': {netbox_result.get('error', 'Unknown error')}")
                        
                        # Add bond sync summary if any bonds were synced
                        if bond_sync_results:
                            successful_syncs = [r for r in bond_sync_results if r['success']]
                            if successful_syncs:
                                logger.info(f"[BOND-SYNC] Successfully synced {len(successful_syncs)} bond(s) to NetBox for device {device.name}")
                    
                    # Add section identifier
                    result['section'] = 'untagged'
                    
                    # Convert logs list to string if needed
                    if isinstance(result.get('logs'), list):
                        result['deployment_logs'] = '\n'.join(result['logs'])
                    elif 'deployment_logs' not in result:
                        result['deployment_logs'] = result.get('message', '')
                    
                    # Track interfaces for auto-tagging if deployment succeeded
                    if result.get('success'):
                        for item in missing_tags_interfaces_with_configs:
                            interface = item['interface']
                            interfaces_to_auto_tag.append(interface)
                            # Check if this interface has conflicting vlan-mode tags that need replacement
                            interface.refresh_from_db()
                            interface_tags = set(interface.tags.values_list('name', flat=True))
                            # Any vlan-mode tag that's not access/tagged needs replacement
                            has_conflicting_tags = any(
                                tag.startswith('vlan-mode:') and 
                                not tag.startswith('vlan-mode:access') and 
                                not tag.startswith('vlan-mode:tagged')
                                for tag in interface_tags
                            )
                            if has_conflicting_tags:
                                interfaces_with_conflicting_tags.append(interface)
                    
                    results.append(result)
        
        # Auto-tag Section 2 interfaces after successful deployment
        if not dry_run and interfaces_to_auto_tag:
            auto_tag_results = []
            bond_sync_results = []
            processed_bonds = set()  # Track bonds we've already synced
            
            for interface in interfaces_to_auto_tag:
                # Check if this interface has conflicting tags that need replacement
                replace_tags = interface in interfaces_with_conflicting_tags
                tag_applied = self._auto_tag_interface_after_deployment(interface, replace_conflicting_tags=replace_tags)
                auto_tag_results.append({
                    'interface': f"{interface.device.name}:{interface.name}",
                    'tag_applied': tag_applied,
                    'success': tag_applied is not None,
                    'tags_replaced': replace_tags,
                })
                
                # Sync bond information to NetBox if device has bond but NetBox doesn't
                bond_info = self._get_bond_interface_for_member(interface.device, interface.name, platform=platform)
                if bond_info and bond_info.get('netbox_missing_bond'):
                    device_bond = bond_info.get('device_bond_name')
                    if device_bond and device_bond not in processed_bonds:
                        all_members = bond_info.get('all_members', [])
                        if all_members:
                            bond_sync_result = self._sync_bond_to_netbox(interface.device, device_bond, all_members, platform=platform)
                            bond_sync_results.append({
                                'device': interface.device.name,
                                'bond': device_bond,
                                'success': bond_sync_result['success'],
                                'bond_created': bond_sync_result.get('bond_created', False),
                                'members_added': bond_sync_result.get('members_added', 0),
                                'vlans_migrated': bond_sync_result.get('vlans_migrated', 0),
                                'vlans_migrated_from': bond_sync_result.get('vlans_migrated_from', []),
                                'error': bond_sync_result.get('error'),
                            })
                            processed_bonds.add(device_bond)
            
            # Add auto-tagging summary to results
            results.append({
                'device': 'AUTO-TAGGING',
                'interface': 'Summary',
                'status': 'info',
                'message': f"Auto-tagged {len([r for r in auto_tag_results if r['success']])} interfaces",
                'auto_tag_results': auto_tag_results,
                'dry_run': False,
            })
            
            # Add bond sync summary if any bonds were synced
            if bond_sync_results:
                successful_syncs = [r for r in bond_sync_results if r['success']]
                results.append({
                    'device': 'BOND-SYNC',
                    'interface': 'Summary',
                    'status': 'info',
                    'message': f"Synced {len(successful_syncs)} bond(s) to NetBox",
                    'bond_sync_results': bond_sync_results,
                    'dry_run': False,
                })
        
        return results

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
            # Dry run mode - use batched deployment preview (same structure as actual deployment)
            # First, run tag validation
            validation_results = self._validate_tags_for_dry_run(devices, interface_list)
            
            # Use batched deployment approach for dry run (same as sync mode and actual deployment)
            logger.info(f"[DRY RUN] Generating batched preview for {len(devices)} device(s), {len(interface_list)} interface(s)")
            
            for device in devices:
                interfaces_with_configs = []
                
                for interface_name in interface_list:
                    try:
                        interface_obj = Interface.objects.get(device=device, name=interface_name)
                    except Interface.DoesNotExist:
                        # Interface not found - add error result
                        results.append({
                            "device": device,
                            "interface": interface_name,
                            "vlan_id": vlan_id,
                            "vlan_name": vlan_name,
                            "status": "error",
                            "config_applied": "No",
                            "netbox_updated": "No",
                            "message": "Interface not found in NetBox",
                            "deployment_logs": "Interface not found in NetBox",
                        })
                        continue
                    
                    # Pre-check: Detect bond early (device config takes priority)
                    bond_detected_early = None
                    bond_info = self._get_bond_interface_for_member(device, interface_name, platform=platform)
                    if bond_info:
                        bond_detected_early = bond_info.get('bond_name')
                        logger.info(f"[BOND PRE-CHECK] Device has bond: {bond_detected_early} for member {interface_name}")
                    
                    # Check NetBox for bond (LAG)
                    netbox_bond = None
                    if hasattr(interface_obj, 'lag') and interface_obj.lag:
                        netbox_bond = interface_obj.lag.name
                        logger.info(f"[BOND PRE-CHECK] NetBox has bond: {netbox_bond} for interface {interface_name}")
                    
                    # Bond auto-creation or migration logic
                    bond_deletion_commands = []
                    bond_creation_commands = []
                    old_bond_name = None
                    bond_traffic_warning = False
                    
                    if netbox_bond and not bond_detected_early:
                        # NetBox has bond, device doesn't - CREATE bond on device
                        logger.info(f"[BOND AUTO-CREATE] Creating bond {netbox_bond} on device (missing)")
                        member_interfaces = []
                        try:
                            lag_interfaces = Interface.objects.filter(device=device, lag=interface_obj.lag)
                            member_interfaces = [iface.name for iface in lag_interfaces]
                        except Exception as e:
                            logger.warning(f"Could not get LAG members: {e}")
                            member_interfaces = [interface_name]
                        
                        bond_creation_commands = self._generate_bond_creation_commands(
                            netbox_bond, member_interfaces, platform
                        )
                        bond_detected_early = netbox_bond
                        
                    elif bond_detected_early and netbox_bond and bond_detected_early != netbox_bond:
                        # Name mismatch - DELETE old bond, CREATE new bond with NetBox name
                        logger.warning(f"[BOND MISMATCH] Device has {bond_detected_early}, NetBox has {netbox_bond} - migrating to NetBox name")
                        old_bond_name = bond_detected_early
                        
                        # Check for traffic on existing bond (disruption warning)
                        traffic_stats = self._check_interface_traffic_stats(device, interface_name, platform, bond_interface=bond_detected_early)
                        if traffic_stats.get('has_traffic'):
                            bond_traffic_warning = True
                            logger.warning(f"[TRAFFIC WARNING] Bond {bond_detected_early} is carrying traffic - migration will disrupt!")
                        
                        # Get all members for the bond
                        member_interfaces = []
                        try:
                            lag_interfaces = Interface.objects.filter(device=device, lag=interface_obj.lag)
                            member_interfaces = [iface.name for iface in lag_interfaces]
                        except Exception as e:
                            logger.warning(f"Could not get LAG members: {e}")
                            member_interfaces = [interface_name]
                        
                        # Generate deletion commands for old bond
                        bond_deletion_commands = self._generate_bond_deletion_commands(
                            bond_detected_early, member_interfaces, platform
                        )
                        
                        # Generate creation commands for new bond
                        bond_creation_commands = self._generate_bond_creation_commands(
                            netbox_bond, member_interfaces, platform
                        )
                        
                        # Force NetBox bond name for all subsequent config
                        bond_detected_early = netbox_bond
                    
                    # Determine target interface (use bond if detected/created)
                    target_interface = bond_detected_early if bond_detected_early else interface_name
                    
                    # Get untagged/tagged VLANs from NetBox
                    untagged_vid = None
                    tagged_vids = []
                    if interface_obj.untagged_vlan:
                        untagged_vid = interface_obj.untagged_vlan.vid
                    if interface_obj.tagged_vlans.exists():
                        tagged_vids = [v.vid for v in interface_obj.tagged_vlans.all()]
                    
                    # Generate configuration commands
                    try:
                        device_config_result = self._get_current_device_config(device, interface_name, platform)
                        bridge_vlans = device_config_result.get('_bridge_vlans', [])
                    except Exception as e:
                        logger.error(f"Failed to fetch bridge VLANs for {device.name}: {e}")
                        bridge_vlans = []
                    
                    config_command = self._generate_config_from_netbox(
                        device, interface_obj, platform,
                        existing_bridge_vlans=bridge_vlans,
                        force_bond_interface=bond_detected_early
                    )
                    
                    # Prepend bond deletion/creation commands if any
                    if bond_deletion_commands or bond_creation_commands:
                        combined_commands = []
                        combined_commands.extend(bond_deletion_commands)
                        combined_commands.extend(bond_creation_commands)
                        combined_commands.append(config_command)
                        config_command = '\n'.join(combined_commands)
                    
                    # Generate preview logs (current state, conflicts, proposed config, etc.)
                    preview_logs = []
                    preview_logs.append("=" * 80)
                    preview_logs.append(f"DRY RUN - Interface: {interface_name}")
                    preview_logs.append("=" * 80)
                    preview_logs.append("")
                    
                    # Show bond info if detected
                    if bond_detected_early:
                        preview_logs.append("--- Bond Information ---")
                        preview_logs.append(f"[NOTE] Interface '{interface_name}' is part of bond '{bond_detected_early}'")
                        preview_logs.append(f"       Configuration will be applied to bond '{bond_detected_early}'")
                        
                        # Show bond creation/migration warnings
                        if bond_creation_commands and not bond_deletion_commands:
                            preview_logs.append(f"[BOND AUTO-CREATE] Bond '{bond_detected_early}' will be created on device")
                            preview_logs.append("                    (NetBox has bond, device doesn't)")
                        elif bond_deletion_commands:
                            preview_logs.append(f"[BOND MIGRATION] Migrating from '{old_bond_name}' to '{bond_detected_early}'")
                            preview_logs.append(f"                 Old bond '{old_bond_name}' will be deleted")
                            preview_logs.append(f"                 New bond '{bond_detected_early}' will be created")
                            if bond_traffic_warning:
                                preview_logs.append(f"                 [TRAFFIC DISRUPTION WARNING] Bond '{old_bond_name}' is carrying traffic!")
                        preview_logs.append("")
                    
                    # Show current device config
                    preview_logs.append("--- Current Device Configuration ---")
                    device_config_result = self._get_current_device_config(device, interface_name, platform)
                    current_config = device_config_result.get('current_config', '(unable to fetch)')
                    if current_config and not current_config.startswith('ERROR:'):
                        for line in current_config.split('\n'):
                            if line.strip():
                                preview_logs.append(f"  {line}")
                    else:
                        preview_logs.append("  (no configuration or unable to fetch)")
                    preview_logs.append("")
                    
                    # Show NetBox current state
                    preview_logs.append("--- Current NetBox Configuration ---")
                    preview_logs.append(f"802.1Q Mode: {interface_obj.mode or 'N/A'}")
                    preview_logs.append(f"Untagged VLAN: {untagged_vid or 'None'}")
                    tagged_str = ', '.join(map(str, tagged_vids)) if tagged_vids else 'None'
                    preview_logs.append(f"Tagged VLANs: [{tagged_str}]")
                    preview_logs.append("")
                    
                    # Proposed Device Configuration (separate section for consistency)
                    preview_logs.append("--- Proposed Device Configuration ---")
                    # Show bond creation note if bond is being created
                    if bond_creation_commands:
                        preview_logs.append(f"[NOTE] Bond '{bond_detected_early}' will be created on device (NetBox has bond, device doesn't)")
                        preview_logs.append(f"       Bond creation commands:")
                        for cmd in bond_creation_commands:
                            preview_logs.append(f"         {cmd}")
                        preview_logs.append("")
                    if config_command:
                        for line in config_command.split('\n'):
                            if line.strip():
                                preview_logs.append(f"  {line}")
                    else:
                        preview_logs.append("  (no configuration commands to apply)")
                    preview_logs.append("")
                    
                    # Traffic check
                    pre_traffic_stats = {}
                    target_interface_for_stats = bond_detected_early if bond_detected_early else interface_name
                    if platform == 'cumulus':
                        preview_logs.append("--- Pre-Deployment Traffic Check ---")
                        pre_traffic_stats = self._check_interface_traffic_stats(device, interface_name, platform, bond_interface=bond_detected_early)
                        if pre_traffic_stats.get('has_traffic'):
                            in_pkts = pre_traffic_stats.get('in_pkts_total', 0)
                            out_pkts = pre_traffic_stats.get('out_pkts_total', 0)
                            preview_logs.append(f"[WARN] Active traffic on '{target_interface_for_stats}': in={in_pkts:,}, out={out_pkts:,}")
                        else:
                            preview_logs.append(f"[OK] No active traffic on '{target_interface_for_stats}'")
                        preview_logs.append("")
                    
                    # Store config info for later
                    config_info = {
                        'bond_migrated': bool(bond_deletion_commands),
                        'old_bond_name': old_bond_name,
                        'bond_traffic_warning': bond_traffic_warning
                    }
                    
                    # Add to batch
                    interfaces_with_configs.append({
                        'interface': interface_obj,
                        'config_command': config_command,
                        'target_interface': target_interface,
                        'vlan_id': vlan_id,
                        'preview_logs': preview_logs,
                        'pre_traffic_stats': pre_traffic_stats,
                        'target_interface_for_stats': target_interface_for_stats,
                        'config_info': config_info,
                        'untagged_vid': untagged_vid,
                        'tagged_vids': tagged_vids,
                        'bond_migrated': config_info.get('bond_migrated', False),
                        'old_bond_name': config_info.get('old_bond_name'),
                        'bond_traffic_warning': config_info.get('bond_traffic_warning')
                    })
                
                # Generate consolidated batched dry run result for this device
                if interfaces_with_configs:
                    batched_result = self._batch_deploy_interfaces_per_device(
                        device, interfaces_with_configs, platform, dry_run=True
                    )
                    results.extend(batched_result)

        else:
            # Deploy mode - use Nornir for parallel execution
            # First, build pre-deployment logs (same sections as dry run) for each device/interface
            pre_deployment_logs = {}  # {device_name: {interface_name: [logs]}}
            
            for device in devices:
                pre_deployment_logs[device.name] = {}
                for interface_name in interface_list:
                    # Build the same comprehensive logs as dry run (before actual deployment)
                    logs = []
                    
                    # Get current config before deployment (same logic as dry run)
                    current_config_before = None
                    bridge_vlans_before = []
                    bond_member_of = None
                    try:
                        device_config_result = self._get_current_device_config(device, interface_name, platform)
                        current_config_before = device_config_result.get('current_config', None)
                        bridge_vlans_before = device_config_result.get('_bridge_vlans', [])
                        bond_member_of = device_config_result.get('bond_member_of', None)  # Get bond info for proposed config generation
                        
                        if current_config_before and isinstance(current_config_before, str):
                            if current_config_before.startswith('ERROR:'):
                                current_config_before = None
                            elif "(no configuration" in current_config_before or "(interface" in current_config_before:
                                pass
                    except Exception as e:
                        logger.debug(f"Could not get current config before deployment: {e}")
                        current_config_before = None
                        bridge_vlans_before = []
                        bond_member_of = None
                    
                    # Get NetBox current state and generate diffs (same as dry run)
                    netbox_state = self._get_netbox_current_state(device, interface_name, vlan_id)
                    
                    # Get bond information for NetBox diff (if bond detected)
                    bond_info_for_netbox = None
                    bond_name_for_netbox = None
                    if bond_member_of:
                        bond_info_for_netbox = self._get_bond_interface_for_member(device, interface_name, platform=platform)
                        bond_name_for_netbox = bond_member_of
                    
                    netbox_diff = self._generate_netbox_diff(
                        netbox_state, 
                        netbox_state['proposed'],
                        bond_info=bond_info_for_netbox,
                        interface_name=interface_name,
                        bond_name=bond_name_for_netbox
                    )
                    
                    # Determine target interface for proposed config (bond if member, otherwise original)
                    target_interface_for_config = bond_member_of if bond_member_of else interface_name
                    
                    # Generate proposed config and config diff (same as dry run) (use target_interface which may be bond)
                    proposed_config = self._generate_vlan_config(target_interface_for_config, vlan_id, platform, device=device, bridge_vlans=bridge_vlans_before)
                    config_diff = self._generate_config_diff(current_config_before, proposed_config, platform, device=device, interface_name=target_interface_for_config, bridge_vlans=bridge_vlans_before)
                    
                    # Build all the sections (same as dry run)
                    logs.append("=" * 80)
                    logs.append("DEPLOYMENT MODE - CONFIGURATION PREVIEW")
                    logs.append("=" * 80)
                    logs.append("")
                    
                    # Current Device Configuration
                    logs.append("--- Current Device Configuration (Real from Device) ---")
                    logs.append("")
                    
                    # Check if interface is a bond member
                    if bond_member_of:
                        logs.append(f"Bond Membership: Interface '{interface_name}' is a member of bond '{bond_member_of}'")
                        logs.append(f"Note: VLAN configuration will be applied to bond '{bond_member_of}', not to '{interface_name}' directly.")
                        logs.append("")
                        logs.append(f"Interface-Level Configuration (for '{interface_name}'):")
                        if current_config_before and current_config_before.strip() and not "(no configuration" in current_config_before and not "ERROR:" in current_config_before:
                            for line in current_config_before.split('\n'):
                                if line.strip():
                                    logs.append(f"  {line}")
                        else:
                            logs.append("  (no configuration found for this interface)")
                        logs.append("")
                        # Show bond interface config if available
                        try:
                            device_config_result = self._get_current_device_config(device, interface_name, platform)
                            bond_interface_config = device_config_result.get('bond_interface_config')
                            if bond_interface_config and bond_interface_config.strip():
                                logs.append(f"Bond Interface '{bond_member_of}' Configuration:")
                                for line in bond_interface_config.split('\n'):
                                    if line.strip():
                                        logs.append(f"  {line}")
                                logs.append("")
                        except Exception:
                            pass
                    else:
                        # Not a bond member - show interface config normally
                        logs.append(f"Interface-Level Configuration:")
                        if current_config_before and current_config_before.strip() and not "(no configuration" in current_config_before and not "ERROR:" in current_config_before:
                            for line in current_config_before.split('\n'):
                                if line.strip():
                                    logs.append(f"  {line}")
                        else:
                            logs.append("  (no configuration found or unable to retrieve)")
                        logs.append("")
                    
                    # Bridge-Level Configuration (for Cumulus - always show)
                    if platform == 'cumulus':
                        logs.append("Bridge-Level Configuration (br_default):")
                        if bridge_vlans_before and len(bridge_vlans_before) > 0:
                            vlan_list_str = self._format_vlan_list(bridge_vlans_before)
                            logs.append(f"  nv set bridge domain br_default vlan {vlan_list_str}")
                        else:
                            logs.append("  (bridge VLAN information not available)")
                        logs.append("")
                    
                    # Current NetBox Configuration (shown AFTER Current Device Configuration for consistency)
                    logs.append("--- Current NetBox Configuration (Source of Truth) ---")
                    netbox_current = netbox_state['current']
                    logs.append(f"802.1Q Mode: {netbox_current['mode'] or 'None'}")
                    logs.append(f"Untagged VLAN: {netbox_current['untagged_vlan'] or 'None'}")
                    tagged_vlans_str = ', '.join(map(str, netbox_current['tagged_vlans'])) if netbox_current['tagged_vlans'] else 'None'
                    logs.append(f"Tagged VLANs: [{tagged_vlans_str}]")
                    ip_addresses_str = ', '.join(netbox_current['ip_addresses']) if netbox_current['ip_addresses'] else 'None'
                    logs.append(f"IP Addresses: {ip_addresses_str}")
                    logs.append(f"VRF: {netbox_current['vrf'] or 'None'}")
                    logs.append(f"Cable Status: {netbox_current['cable_status']}")
                    if netbox_current['connected_to']:
                        logs.append(f"Connected To: {netbox_current['connected_to']}")
                    logs.append(f"Enabled: {netbox_current['enabled']}")
                    logs.append(f"Port-Channel Member: {netbox_current['port_channel_member']}")
                    logs.append("")
                    
                    # Proposed Device Configuration (shown AFTER Current NetBox Configuration for consistency)
                    logs.append("--- Proposed Device Configuration ---")
                    for line in proposed_config.split('\n'):
                        if line.strip():
                            logs.append(f"  {line}")
                    logs.append("")
                    
                    # Configuration Conflict Detection
                    device_has_ip = bool(netbox_current['ip_addresses'])
                    device_has_vrf = bool(netbox_current['vrf'])
                    device_config_has_ip = 'ip address' in current_config_before.lower() if current_config_before else False
                    device_config_has_vrf = 'vrf' in current_config_before.lower() if current_config_before else False
                    device_config_has_vlan = False
                    device_vlan_id = None
                    if current_config_before:
                        import re
                        vlan_match = re.search(r'access\s+(\d+)', current_config_before.lower())
                        if vlan_match:
                            device_config_has_vlan = True
                            device_vlan_id = int(vlan_match.group(1))
                    netbox_has_vlan = netbox_current.get('untagged_vlan') is not None
                    netbox_vlan_id = netbox_current.get('untagged_vlan')
                    conflict_detected = False
                    conflict_reasons = []
                    if device_config_has_ip != device_has_ip:
                        conflict_detected = True
                        conflict_reasons.append("IP address mismatch")
                    if device_config_has_vrf != device_has_vrf:
                        conflict_detected = True
                        conflict_reasons.append("VRF mismatch")
                    if netbox_has_vlan and not device_config_has_vlan:
                        conflict_detected = True
                        conflict_reasons.append(f"NetBox has VLAN {netbox_vlan_id} configured but device has no VLAN config")
                    elif netbox_has_vlan and device_config_has_vlan and netbox_vlan_id != device_vlan_id:
                        conflict_detected = True
                        conflict_reasons.append(f"VLAN mismatch: NetBox has {netbox_vlan_id}, device has {device_vlan_id}")
                    elif not netbox_has_vlan and device_config_has_vlan:
                        conflict_detected = True
                        conflict_reasons.append(f"Device has VLAN {device_vlan_id} configured but NetBox has no VLAN")
                    
                    logs.append("--- Configuration Conflict Detection ---")
                    if conflict_detected:
                        logs.append(f"[WARN] Device config differs from NetBox config")
                        if conflict_reasons:
                            logs.append(f"  Conflicts detected: {', '.join(conflict_reasons)}")
                        logs.append("")
                        logs.append("Device Should Have (According to NetBox):")
                        # ISSUE 1 FIX: Generate config from NetBox's ACTUAL configuration, not from proposed_config
                        # proposed_config contains the VLAN from form input, but we need to show what NetBox actually has
                        # Determine target interface (bond if member, otherwise original)
                        target_interface_for_netbox = target_interface_for_config if 'target_interface_for_config' in locals() else interface_name
                        if bond_member_of:
                            target_interface_for_netbox = bond_member_of
                        elif 'bond_info_for_netbox' in locals() and bond_info_for_netbox:
                            target_interface_for_netbox = bond_info_for_netbox.get('bond_name', interface_name)
                        
                        # Generate config from NetBox's actual state
                        netbox_config_lines = []
                        if platform == 'cumulus':
                            # Show bridge VLAN commands for all VLANs in NetBox
                            all_netbox_vlans = set()
                            if netbox_current.get('untagged_vlan'):
                                all_netbox_vlans.add(netbox_current['untagged_vlan'])
                            all_netbox_vlans.update(netbox_current.get('tagged_vlans', []))
                            
                            for vlan_vid in sorted(all_netbox_vlans):
                                # Only show if not already in bridge (to avoid duplicates)
                                if not self._is_vlan_in_bridge_vlans(vlan_vid, bridge_vlans_before):
                                    netbox_config_lines.append(f"nv set bridge domain br_default vlan {vlan_vid}")
                            
                            # Show interface access VLAN command (untagged VLAN)
                            if netbox_current.get('untagged_vlan'):
                                netbox_config_lines.append(f"nv set interface {target_interface_for_netbox} bridge domain br_default access {netbox_current['untagged_vlan']}")
                        elif platform == 'eos':
                            # EOS commands
                            if netbox_current.get('untagged_vlan'):
                                netbox_config_lines.append(f"interface {target_interface_for_netbox}")
                                netbox_config_lines.append(f"  switchport access vlan {netbox_current['untagged_vlan']}")
                        
                        # Display the config
                        if netbox_config_lines:
                            for line in netbox_config_lines:
                                logs.append(f"  {line}")
                        else:
                            logs.append("  (no VLAN configuration in NetBox)")
                        logs.append("")
                        logs.append("Note: NetBox is the source of truth. Device may have stale/old configuration.")
                        logs.append("      Any differences will be reconciled during deployment.")
                    else:
                        logs.append("[OK] Device config matches NetBox - no conflicts detected")
                    logs.append("")
                    
                    # Config Diff
                    logs.append("--- Config Diff ---")
                    logs.append("(Shows what will be removed/replaced and what will be added)")
                    logs.append("")
                    for line in config_diff.split('\n'):
                        if line.strip():
                            logs.append(f"  {line}")
                    logs.append("")
                    
                    # NetBox Configuration Changes
                    logs.append("--- NetBox Configuration Changes ---")
                    for line in netbox_diff.split('\n'):
                        if line.strip():
                            logs.append(f"  {line}")
                    logs.append("")
                    
                    # Pre-deployment traffic check (Cumulus only)
                    target_interface_for_stats = interface_name
                    bond_interface_for_stats = None
                    try:
                        interface_obj = Interface.objects.get(device=device, name=interface_name)
                        if hasattr(interface_obj, 'lag') and interface_obj.lag:
                            bond_interface_for_stats = interface_obj.lag.name
                            target_interface_for_stats = bond_interface_for_stats
                        else:
                            # Check device config for bond membership
                            bond_info_for_stats = self._get_bond_interface_for_member(device, interface_name, platform=platform)
                            bond_interface_for_stats = bond_info_for_stats['bond_name'] if bond_info_for_stats else None
                            if bond_interface_for_stats:
                                target_interface_for_stats = bond_interface_for_stats
                    except Interface.DoesNotExist:
                        # Fall back to device config check
                        bond_info_for_stats = self._get_bond_interface_for_member(device, interface_name, platform=platform)
                        bond_interface_for_stats = bond_info_for_stats['bond_name'] if bond_info_for_stats else None
                        if bond_interface_for_stats:
                            target_interface_for_stats = bond_interface_for_stats
                    
                    if platform == 'cumulus':
                        logs.append("--- Pre-Deployment Traffic Check ---")
                        pre_traffic_stats = self._check_interface_traffic_stats(device, interface_name, platform, bond_interface=bond_interface_for_stats)
                        if pre_traffic_stats.get('has_traffic'):
                            in_pkts = pre_traffic_stats.get('in_pkts_total', 0)
                            out_pkts = pre_traffic_stats.get('out_pkts_total', 0)
                            logs.append(f"[WARN] ACTIVE TRAFFIC DETECTED on interface '{target_interface_for_stats}'")
                            logs.append(f"  in-pkts: {in_pkts:,}")
                            logs.append(f"  out-pkts: {out_pkts:,}")
                            logs.append(f"  WARNING: Replacing VLAN configuration will disrupt existing traffic!")
                        elif pre_traffic_stats.get('error'):
                            logs.append(f"[INFO] Could not check traffic stats: {pre_traffic_stats.get('error')}")
                        else:
                            logs.append(f"[OK] No active traffic detected on interface '{target_interface_for_stats}'")
                        logs.append("")
                        # Store for post-deployment comparison
                        pre_deployment_logs[device.name][f"{interface_name}_pre_traffic"] = pre_traffic_stats
                    
                    logs.append("=" * 80)
                    logs.append("STARTING DEPLOYMENT")
                    logs.append("=" * 80)
                    logs.append("")
                    
                    pre_deployment_logs[device.name][interface_name] = logs
            
            # ================================================================
            # BATCHED DEPLOYMENT - All interfaces per device in single session
            # ================================================================
            logger.info(f"[BATCH] Deploying {len(interface_list)} interface(s) per device in ONE atomic session")
            
            for device in devices:
                interfaces_with_configs = []
                
                for interface_name in interface_list:
                    try:
                        interface_obj = Interface.objects.get(device=device, name=interface_name)
                    except Interface.DoesNotExist:
                        results.append({
                            "device": device, "interface": interface_name, "vlan_id": vlan_id, "vlan_name": vlan_name,
                            "status": "error", "config_applied": "No", "netbox_updated": "No",
                            "message": "Interface not found in NetBox", "deployment_logs": "Interface not found",
                            "device_status": "FAIL", "interface_status": "FAIL", "overall_status": "FAILED", "risk_level": "HIGH",
                        })
                        continue
                    
                    # Bond detection & migration
                    bond_detected_early = None
                    netbox_bond = None
                    bond_creation_commands = []
                    bond_deletion_commands = []
                    old_bond_name = None
                    
                    try:
                        device_config_check = self._get_current_device_config(device, interface_name, platform)
                        bond_detected_early = device_config_check.get('bond_member_of')
                    except Exception:
                        pass
                    
                    if hasattr(interface_obj, 'lag') and interface_obj.lag:
                        netbox_bond = interface_obj.lag.name
                    
                    if netbox_bond and not bond_detected_early:
                        bond_creation_commands = self._generate_bond_creation_commands(netbox_bond, [interface_name], platform)
                        bond_detected_early = netbox_bond
                    elif bond_detected_early and netbox_bond and bond_detected_early != netbox_bond:
                        old_bond_name = bond_detected_early
                        bond_deletion_commands = self._generate_bond_deletion_commands(old_bond_name, platform)
                        bond_creation_commands = self._generate_bond_creation_commands(netbox_bond, [interface_name], platform)
                        bond_detected_early = netbox_bond
                    
                    # Generate VLAN config
                    config_commands = []
                    target_interface = bond_detected_early if bond_detected_early else interface_name
                    
                    if bond_deletion_commands:
                        config_commands.extend(bond_deletion_commands)
                    if bond_creation_commands:
                        config_commands.extend(bond_creation_commands)
                    
                    if platform == 'cumulus':
                        config_commands.append(f"nv set bridge domain br_default vlan {vlan_id}")
                        config_commands.append(f"nv set interface {target_interface} bridge domain br_default access {vlan_id}")
                    elif platform == 'eos':
                        config_commands.append(f"interface {target_interface}")
                        config_commands.append(f"   switchport mode access")
                        config_commands.append(f"   switchport access vlan {vlan_id}")
                    
                    interfaces_with_configs.append({
                        'interface': interface_obj,
                        'vlan_id': vlan_id,
                        'target_interface': target_interface,
                        'config_commands': config_commands,
                        'bond_migrated': bool(bond_deletion_commands),
                        'old_bond_name': old_bond_name,
                    })
                
                # Deploy all interfaces for this device in ONE batch
                if interfaces_with_configs:
                    batched_results_list = self._batch_deploy_interfaces_per_device(device, interfaces_with_configs, platform, dry_run=False)
                    # _batch_deploy_interfaces_per_device returns a list with ONE consolidated result per device
                    # Extract the single result
                    batched_result = batched_results_list[0] if batched_results_list else {}
                    deployment_success = batched_result.get('success', False)
                    
                    # Convert logs list to string if needed
                    deployment_logs = batched_result.get('logs', '')
                    if isinstance(deployment_logs, list):
                        deployment_logs = '\n'.join(deployment_logs)
                    
                    # NetBox updates and bond sync (only if deployment succeeded)
                    interfaces_to_update_netbox = []
                    bonds_to_sync = set()  # Track bonds that need syncing
                    processed_bonds = set()  # Track bonds we've already synced
                    
                    if update_netbox and deployment_success and vlan:
                        for iface_data in interfaces_with_configs:
                            interface_name = iface_data['interface'].name
                            target_interface = iface_data.get('target_interface', interface_name)
                            
                            # Determine which interface to update in NetBox
                            # If bond detected, update bond interface; otherwise update member interface
                            netbox_interface_to_update = target_interface if target_interface != interface_name else interface_name
                            
                            # Check if bond needs syncing or VLAN migration
                            if target_interface != interface_name:
                                # Bond detected - check if NetBox has this bond
                                bond_info = self._get_bond_interface_for_member(device, interface_name, platform=platform)
                                if bond_info:
                                    device_bond = bond_info.get('device_bond_name')
                                    if device_bond and device_bond not in processed_bonds:
                                        if bond_info.get('netbox_missing_bond'):
                                            # Bond doesn't exist in NetBox - sync it
                                            bonds_to_sync.add((device_bond, bond_info))
                                        else:
                                            # Bond exists in NetBox - check if VLANs need migration
                                            # Check if member interface has VLANs that should be on bond
                                            try:
                                                member_iface = Interface.objects.get(device=device, name=interface_name)
                                                if member_iface.untagged_vlan or member_iface.tagged_vlans.exists():
                                                    # Member has VLANs - need to migrate to bond
                                                    bonds_to_sync.add((device_bond, bond_info))
                                            except Interface.DoesNotExist:
                                                pass
                            
                            interfaces_to_update_netbox.append({
                                'interface_name': interface_name,
                                'netbox_interface': netbox_interface_to_update,
                                'target_interface': target_interface,
                                'iface_data': iface_data
                            })
                    
                    # Sync bonds to NetBox first (before updating VLANs)
                    bond_sync_results = []
                    for device_bond, bond_info in bonds_to_sync:
                        all_members = bond_info.get('all_members', [])
                        if all_members:
                            # Check if bond exists in NetBox or needs to be created
                            if bond_info.get('netbox_missing_bond'):
                                # Bond doesn't exist - create it and migrate VLANs
                                bond_sync_result = self._sync_bond_to_netbox(device, device_bond, all_members, platform=platform)
                            else:
                                # Bond exists - just migrate VLANs from members to bond
                                bond_sync_result = self._migrate_vlans_to_bond(device, device_bond, all_members, platform=platform)
                                # Convert migration result to same format as sync result
                                bond_sync_result = {
                                    'success': bond_sync_result['success'],
                                    'bond_created': False,  # Bond already exists
                                    'members_added': 0,  # Members already added
                                    'vlans_migrated': bond_sync_result.get('vlans_migrated', 0),
                                    'vlans_migrated_from': bond_sync_result.get('vlans_migrated_from', []),
                                    'error': bond_sync_result.get('error'),
                                }
                            
                            bond_sync_results.append({
                                'device': device.name,
                                'bond': device_bond,
                                'success': bond_sync_result['success'],
                                'bond_created': bond_sync_result.get('bond_created', False),
                                'members_added': bond_sync_result.get('members_added', 0),
                                'vlans_migrated': bond_sync_result.get('vlans_migrated', 0),
                                'error': bond_sync_result.get('error'),
                            })
                            processed_bonds.add(device_bond)
                            
                            # Add bond sync/migration info to deployment logs
                            if bond_sync_result.get('success'):
                                if bond_sync_result.get('bond_created', False):
                                    deployment_logs += f"\n[NetBox] Bond '{device_bond}' synced to NetBox (created: True, members: {bond_sync_result.get('members_added', 0)}, VLANs migrated: {bond_sync_result.get('vlans_migrated', 0)})"
                                else:
                                    deployment_logs += f"\n[NetBox] Migrated VLANs from member interfaces to bond '{device_bond}' (VLANs migrated: {bond_sync_result.get('vlans_migrated', 0)})"
                            else:
                                deployment_logs += f"\n[NetBox] Bond sync/migration failed: {bond_sync_result.get('error', 'Unknown error')}"
                    
                    # Update NetBox interfaces with VLAN assignments
                    netbox_update_results = {}  # Store results to avoid duplicate calls
                    for update_info in interfaces_to_update_netbox:
                        interface_name = update_info['interface_name']
                        netbox_interface_to_update = update_info['netbox_interface']
                        
                        # Update NetBox interface (bond if detected, member otherwise)
                        netbox_result = self._update_netbox_interface(device, netbox_interface_to_update, vlan_id)
                        netbox_update_results[interface_name] = {
                            'result': netbox_result,
                            'netbox_interface': netbox_interface_to_update
                        }
                        
                        # Add NetBox update info to deployment logs
                        if netbox_result.get('success'):
                            if netbox_interface_to_update != interface_name:
                                deployment_logs += f"\n[NetBox] Updated bond interface '{netbox_interface_to_update}' (member: '{interface_name}') with VLAN {vlan_id}"
                            else:
                                deployment_logs += f"\n[NetBox] Updated interface '{interface_name}' with VLAN {vlan_id}"
                        else:
                            deployment_logs += f"\n[NetBox] Failed to update interface '{netbox_interface_to_update}': {netbox_result.get('error', 'Unknown error')}"
                    
                    # Create one result per interface (all share the same deployment status)
                    for iface_data in interfaces_with_configs:
                        interface_name = iface_data['interface'].name
                        
                        # Determine netbox_updated status from stored results
                        netbox_updated = "No"
                        if update_netbox and deployment_success and vlan:
                            update_result = netbox_update_results.get(interface_name)
                            if update_result:
                                netbox_updated = "Yes" if update_result['result'].get('success') else "Failed"
                        
                        results.append({
                            "device": device, 
                            "interface": interface_name, 
                            "vlan_id": vlan_id, 
                            "vlan_name": vlan_name,
                            "status": "success" if deployment_success else "error",
                            "config_applied": "Yes" if deployment_success else "Failed",
                            "netbox_updated": netbox_updated,
                            "message": batched_result.get('message', 'Deployed'),
                            "deployment_logs": deployment_logs,
                            "device_status": "PASS" if deployment_success else "FAIL",
                            "interface_status": "PASS" if deployment_success else "FAIL",
                            "overall_status": "PASS" if deployment_success else "FAILED",
                            "risk_level": "LOW" if deployment_success else "HIGH",
                        })
                    
                    # Add bond sync summary if any bonds were synced
                    if bond_sync_results:
                        successful_syncs = [r for r in bond_sync_results if r['success']]
                        if successful_syncs:
                            logger.info(f"[BOND-SYNC] Successfully synced {len(successful_syncs)} bond(s) to NetBox for device {device.name}")

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

    def _get_bond_interface_for_member(self, device, interface_name, platform=None):
        """
        Get bond interface name if the given interface is a bond member.
        ALWAYS checks both NetBox and device config side-by-side (not as fallback).
        NetBox is preferred as source of truth, but device config is always checked for comparison.
        
        Args:
            device: Device object
            interface_name: Interface name to check
            platform: Platform type (required for device config check)
        
        Returns:
            dict or None: {
                'bond_name': str,  # Preferred bond name (NetBox if available, else device)
                'netbox_bond_name': str or None,  # NetBox bond name (e.g., 'bond_swp3')
                'device_bond_name': str or None,  # Device config bond name (e.g., 'bond3')
                'has_mismatch': bool,  # True if NetBox and device have different bond names
                'netbox_missing_bond': bool,  # True if device has bond but NetBox doesn't
                'needs_migration': bool,  # True if device has different bond name (for migration commands)
                'all_members': list,  # All members of device bond (for migration)
                'netbox_members': list,  # All members from NetBox (if available)
            } or None if interface is not a bond member in either source
        """
        netbox_bond_name = None
        device_bond_name = None
        all_members = []
        netbox_members = []
        
        # Step 1: ALWAYS check NetBox
        try:
            interface = Interface.objects.get(device=device, name=interface_name)
            if hasattr(interface, 'lag') and interface.lag:
                netbox_bond_name = interface.lag.name
                # Get all members of this bond from NetBox
                try:
                    bond_interface = Interface.objects.get(device=device, name=netbox_bond_name)
                    # Get all interfaces that are members of this bond
                    member_interfaces = Interface.objects.filter(device=device, lag=bond_interface.lag)
                    netbox_members = [iface.name for iface in member_interfaces]
                except Interface.DoesNotExist:
                    pass
                except Exception as e:
                    logger.debug(f"Error getting NetBox bond members: {e}")
        except Interface.DoesNotExist:
            pass
        except Exception as e:
            logger.debug(f"Error checking NetBox for bond membership: {e}")
        
        # Step 2: ALWAYS check device config (side-by-side, not fallback)
        device_bond_name = None
        if platform and platform == 'cumulus':
            try:
                from netbox_automation_plugin.core.napalm_integration import NAPALMDeviceManager
                napalm_manager = NAPALMDeviceManager(device)
                
                if napalm_manager.connect():
                    connection = napalm_manager.connection
                    try:
                        # Get device config
                        config_show_output = None
                        if hasattr(connection, 'cli'):
                            config_show_output = connection.cli(['nv config show -o json'])
                            
                            # Extract output
                            config_json_str = None
                            if config_show_output:
                                if isinstance(config_show_output, dict):
                                    if 'nv config show -o json' in config_show_output:
                                        config_json_str = config_show_output['nv config show -o json']
                                    else:
                                        config_json_str = list(config_show_output.values())[0] if config_show_output else None
                                else:
                                    config_json_str = str(config_show_output).strip()
                            
                            if config_json_str and config_json_str.strip():
                                import json
                                config_data = json.loads(config_json_str)
                                
                                # Find interface config (this method already handles bond member detection)
                                interface_config = self._find_interface_config_in_json(config_data, interface_name)
                                
                                if isinstance(interface_config, dict):
                                    device_bond_name = interface_config.get('_bond_member_of')
                                    
                                    # If we found a bond in device config, get all its members
                                    if device_bond_name:
                                        all_members = self._get_all_bond_members_from_config(config_data, device_bond_name)
                    except Exception as e:
                        logger.debug(f"Error checking device config for bond membership: {e}")
                    finally:
                        napalm_manager.disconnect()
            except Exception as e:
                logger.debug(f"Error connecting to device to check bond membership: {e}")
        
        # Step 3: Determine status and preferred bond name
        # NetBox is source of truth, but we compare both
        has_mismatch = False
        netbox_missing_bond = False
        needs_migration = False
        preferred_bond_name = None
        
        if netbox_bond_name and device_bond_name:
            # Both have bond info - compare
            if netbox_bond_name != device_bond_name:
                has_mismatch = True
                needs_migration = True
            preferred_bond_name = netbox_bond_name  # NetBox is source of truth
        elif netbox_bond_name:
            # Only NetBox has bond info
            preferred_bond_name = netbox_bond_name
        elif device_bond_name:
            # Only device has bond info - NetBox is missing it
            netbox_missing_bond = True
            preferred_bond_name = device_bond_name  # Use device as fallback for deployment
        else:
            # Neither has bond info - not a bond member
            return None
        
        return {
            'bond_name': preferred_bond_name,
            'netbox_bond_name': netbox_bond_name,
            'device_bond_name': device_bond_name,
            'has_mismatch': has_mismatch,
            'netbox_missing_bond': netbox_missing_bond,
            'needs_migration': needs_migration,
            'all_members': all_members,
            'netbox_members': netbox_members,
        }

    def _get_all_bond_members_from_config(self, config_data, bond_name):
        """
        Get all member interfaces of a bond from device config.
        
        Args:
            config_data: Parsed JSON config from 'nv config show -o json'
            bond_name: Bond interface name (e.g., 'bond3')
        
        Returns:
            list: List of interface names that are members of the bond
        """
        members = []
        
        # Navigate to interface section
        interfaces = None
        for item in config_data:
            if isinstance(item, dict) and 'set' in item:
                set_data = item['set']
                if isinstance(set_data, dict) and 'interface' in set_data:
                    interfaces = set_data['interface']
                    break
        
        if not interfaces or not isinstance(interfaces, dict):
            return members
        
        # Find the bond configuration
        bond_config = interfaces.get(bond_name, {})
        if isinstance(bond_config, dict) and 'bond' in bond_config:
            bond_members = bond_config.get('bond', {}).get('member', {})
            if isinstance(bond_members, dict):
                # Extract all member interface names
                members = list(bond_members.keys())
        
        return members

    def _check_interface_traffic_stats(self, device, interface_name, platform, bond_interface=None):
        """
        Check interface traffic statistics to detect active traffic.
        Runs the command 3 times with 1 second intervals and checks if counters are incrementing.
        
        Args:
            device: Device object
            interface_name: Interface name to check
            platform: Platform type ('cumulus' or 'eos')
            bond_interface: Bond interface name if interface is a bond member (optional)
        
        Returns:
            dict: {
                'has_traffic': bool,  # True only if counters are incrementing between samples
                'in_pkts_samples': list of ints (3 samples),
                'out_pkts_samples': list of ints (3 samples),
                'in_pkts_total': int (last sample),
                'out_pkts_total': int (last sample),
                'error': str (if failed)
            }
        """
        # Determine which interface to check (bond if member, otherwise original)
        target_interface = bond_interface if bond_interface else interface_name
        
        if platform != 'cumulus':
            # Only Cumulus supports nv show interface link stats
            return {
                'has_traffic': False,
                'in_pkts_samples': [],
                'out_pkts_samples': [],
                'in_pkts_total': 0,
                'out_pkts_total': 0,
                'error': 'Traffic stats check only supported for Cumulus'
            }
        
        try:
            from netbox_automation_plugin.core.napalm_integration import NAPALMDeviceManager
            import time
            import json
            
            napalm_manager = NAPALMDeviceManager(device)
            
            if not napalm_manager.connect():
                return {
                    'has_traffic': False,
                    'in_pkts_samples': [],
                    'out_pkts_samples': [],
                    'in_pkts_total': 0,
                    'out_pkts_total': 0,
                    'error': 'Failed to connect to device'
                }
            
            try:
                connection = napalm_manager.connection
                in_pkts_samples = []
                out_pkts_samples = []
                
                # Run command 3 times with 1 second intervals
                for i in range(3):
                    try:
                        # Use -o json flag for proper JSON parsing
                        cmd = f'nv show interface {target_interface} link stats -o json'
                        if hasattr(connection, 'cli'):
                            stats_output = connection.cli([cmd])
                        elif hasattr(connection, 'device') and hasattr(connection.device, 'send_command'):
                            stats_output = connection.device.send_command(cmd, read_timeout=10)
                        else:
                            return {
                                'has_traffic': False,
                                'in_pkts_samples': [],
                                'out_pkts_samples': [],
                                'in_pkts_total': 0,
                                'out_pkts_total': 0,
                                'error': 'No CLI method available'
                            }
                        
                        # Extract and parse JSON output
                        stats_json_str = None
                        if isinstance(stats_output, dict):
                            if cmd in stats_output:
                                stats_json_str = stats_output[cmd]
                            else:
                                stats_json_str = list(stats_output.values())[0] if stats_output else None
                        else:
                            stats_json_str = str(stats_output).strip()
                        
                        if stats_json_str:
                            try:
                                stats_data = json.loads(stats_json_str)
                                
                                # Extract in-pkts and out-pkts from JSON
                                # JSON structure: {"in-pkts": 23228402, "out-pkts": 131905897, ...}
                                in_pkts = stats_data.get('in-pkts', 0)
                                out_pkts = stats_data.get('out-pkts', 0)
                                
                                # Convert to int if needed (JSON might return as int already)
                                in_pkts = int(in_pkts) if in_pkts is not None else 0
                                out_pkts = int(out_pkts) if out_pkts is not None else 0
                                
                                in_pkts_samples.append(in_pkts)
                                out_pkts_samples.append(out_pkts)
                            except (json.JSONDecodeError, ValueError, KeyError) as e:
                                logger.debug(f"Error parsing JSON stats for sample {i+1}: {e}")
                                # If we can't parse, assume no traffic
                                in_pkts_samples.append(0)
                                out_pkts_samples.append(0)
                        else:
                            in_pkts_samples.append(0)
                            out_pkts_samples.append(0)
                        
                        # Wait 1 second before next sample (except for last iteration)
                        if i < 2:
                            time.sleep(1)
                    except Exception as e:
                        logger.debug(f"Error getting traffic stats sample {i+1}: {e}")
                        in_pkts_samples.append(0)
                        out_pkts_samples.append(0)
                        if i < 2:
                            time.sleep(1)
                
                # Check if counters are incrementing (traffic is flowing)
                has_traffic = False
                if len(in_pkts_samples) >= 2:
                    # Check if in-pkts or out-pkts increased between ANY consecutive samples
                    # This indicates active traffic flow
                    in_pkts_increasing = any(in_pkts_samples[i+1] > in_pkts_samples[i] for i in range(len(in_pkts_samples)-1))
                    out_pkts_increasing = any(out_pkts_samples[i+1] > out_pkts_samples[i] for i in range(len(out_pkts_samples)-1))
                    has_traffic = in_pkts_increasing or out_pkts_increasing
                
                return {
                    'has_traffic': has_traffic,
                    'in_pkts_samples': in_pkts_samples,
                    'out_pkts_samples': out_pkts_samples,
                    'in_pkts_total': in_pkts_samples[-1] if in_pkts_samples else 0,
                    'out_pkts_total': out_pkts_samples[-1] if out_pkts_samples else 0,
                    'error': None
                }
            finally:
                napalm_manager.disconnect()
        except Exception as e:
            logger.warning(f"Error checking traffic stats for {device.name}:{target_interface}: {e}")
            return {
                'has_traffic': False,
                'in_pkts_samples': [],
                'out_pkts_samples': [],
                'in_pkts_total': 0,
                'out_pkts_total': 0,
                'error': str(e)
            }

    def _generate_vlan_config(self, interface_name, vlan_id, platform, include_bridge_vlan=True, device=None, bridge_vlans=None):
        """
        Generate platform-specific VLAN configuration command.
        
        For Cumulus: Adds VLAN to bridge first (additive), then sets interface access VLAN.
        For EOS: Sets interface access VLAN directly.
        
        If interface is a bond member, applies config to bond interface instead.
        If bond migration is needed (NetBox has bond_Swp1 but device has bond1),
        generates commands to create bond_Swp1 and migrate all members.

        Supported platforms:
        - cumulus: Cumulus Linux NVUE
        - eos: Arista EOS

        Args:
            interface_name: Interface name (e.g., 'bond1', 'Ethernet1', 'swp3')
            vlan_id: VLAN ID (1-4094)
            platform: Platform type ('cumulus' or 'eos')
            include_bridge_vlan: If True, add bridge VLAN command for Cumulus (default: True)
            device: Device object (optional, required to check bond membership and bridge VLANs)
            bridge_vlans: List of existing bridge VLANs (optional, if not provided will fetch from device)

        Returns:
            str or list: Configuration command(s) for the platform
                          For Cumulus with bridge: list of commands
                          Otherwise: string
        """
        # Check if interface is a bond member - if so, use bond interface
        # First check NetBox, then fall back to device config
        target_interface = interface_name
        bond_info = None
        if device:
            bond_info = self._get_bond_interface_for_member(device, interface_name, platform=platform)
            
            # If _get_bond_interface_for_member returns None, try to get bond info from device config
            # This handles cases where NetBox doesn't have the bond defined but device config shows bond membership
            if not bond_info:
                # Get current device config to check for bond_member_of
                device_config_result = self._get_current_device_config(device, interface_name, platform)
                bond_member_from_config = device_config_result.get('bond_member_of')
                
                if bond_member_from_config:
                    # Device config shows bond membership but _get_bond_interface_for_member didn't find it
                    # Create a bond_info dict for consistency
                    bond_info = {
                        'bond_name': bond_member_from_config,
                        'netbox_bond_name': None,
                        'device_bond_name': bond_member_from_config,
                        'has_mismatch': False,
                        'netbox_missing_bond': True,
                        'all_members': [],
                        'netbox_members': []
                    }
                    target_interface = bond_member_from_config
            
            if bond_info:
                target_interface = bond_info['bond_name']
        
        if platform == 'cumulus':
            commands = []
            
            # If bond migration is needed, create new bond and migrate all members
            if bond_info and bond_info.get('needs_migration'):
                netbox_bond = bond_info['bond_name']  # e.g., 'bond_swp3'
                device_bond = bond_info['device_bond_name']  # e.g., 'bond3'
                all_members = bond_info.get('all_members', [])
                
                # Create new bond interface
                commands.append(f"nv set interface {netbox_bond} type bond")
                
                # Add all members to the new bond
                for member in all_members:
                    commands.append(f"nv set interface {netbox_bond} bond member {member}")
                
                # Add bond to bridge domain
                commands.append(f"nv set interface {netbox_bond} bridge domain br_default")
            
            # ISSUE 1 FIX: Add VLAN to bridge first (additive - safe, won't remove existing VLANs)
            # But only if it doesn't already exist in bridge VLANs
            if include_bridge_vlan:
                # Get current bridge VLANs from device config to check if VLAN already exists
                # Use provided bridge_vlans if available, otherwise fetch from device
                if bridge_vlans is None:
                    bridge_vlans = []
                    if device:
                        try:
                            device_config_result = self._get_current_device_config(device, interface_name, platform)
                            bridge_vlans = device_config_result.get('_bridge_vlans', [])
                            # Also try to get from JSON if available
                            if not bridge_vlans:
                                # Try to get from config_data if available
                                config_data = device_config_result.get('_config_data')
                                if config_data:
                                    bridge_vlans = self._get_bridge_vlans_from_json(config_data)
                        except Exception as e:
                            logger.debug(f"Could not get bridge VLANs for check: {e}")
                
                # Only add bridge VLAN command if VLAN doesn't already exist
                # bridge_vlans can be: list of ints, list of strings like "3019-3099" or "10,3000-3199", or mixed
                if not self._is_vlan_in_bridge_vlans(vlan_id, bridge_vlans):
                    commands.append(f"nv set bridge domain br_default vlan {vlan_id}")
                    logger.debug(f"VLAN {vlan_id} not in bridge - will add")
                else:
                    logger.debug(f"VLAN {vlan_id} already exists in bridge (range or individual) - skipping bridge VLAN command")
            
            # Set interface access VLAN - use target_interface (bond if member, NetBox bond name if migration)
            commands.append(f"nv set interface {target_interface} bridge domain br_default access {vlan_id}")
            
            # Return as newline-separated string for compatibility
            return "\n".join(commands)

        elif platform == 'eos':
            # Arista EOS commands (hierarchical config format for NAPALM)
            # NAPALM EOS expects config in "configure terminal" format
            # Use target_interface (bond if member)
            commands = [
        f"interface {target_interface}",
        f"   switchport mode access",
        f"   switchport access vlan {vlan_id}",
            ]
            return "\n".join(commands)

        else:
            # Unsupported platform
            raise ValueError(f"Unsupported platform: {platform}. Supported platforms: cumulus, eos")

    def _deploy_config_to_device(self, device, interface_name, config_command, platform, vlan_id, original_interface_name=None):
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
            interface_name: Name of the interface being configured (target interface - bond if member)
            config_command: Configuration command(s) to deploy
            platform: Platform type ('cumulus' or 'eos')
            vlan_id: VLAN ID being deployed
            original_interface_name: Original interface name (member interface) if interface_name is a bond (optional)

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
                # IMPORTANT: Replace interface name in config_command if bond detected
                # This ensures all commands use bond3 instead of swp3
                corrected_config_command = config_command
                if original_interface_name and original_interface_name != interface_name:
                    # Replace original interface name (swp3) with target interface (bond3) in ALL commands
                    # Use multiple replacement patterns to catch all variations
                    corrected_lines = []
                    for line in config_command.split('\n'):
                        if line.strip():
                            # Replace in each line - multiple patterns to catch all cases
                            corrected_line = line
                            # Pattern 1: "interface swp3 " -> "interface bond3 "
                            corrected_line = corrected_line.replace(f"interface {original_interface_name} ", f"interface {interface_name} ")
                            # Pattern 2: "interface swp3\n" -> "interface bond3\n"
                            corrected_line = corrected_line.replace(f"interface {original_interface_name}\n", f"interface {interface_name}\n")
                            # Pattern 3: "nv set interface swp3 " -> "nv set interface bond3 "
                            corrected_line = corrected_line.replace(f"nv set interface {original_interface_name} ", f"nv set interface {interface_name} ")
                            # Pattern 4: "nv set interface swp3\n" -> "nv set interface bond3\n"
                            corrected_line = corrected_line.replace(f"nv set interface {original_interface_name}\n", f"nv set interface {interface_name}\n")
                            # Pattern 5: "interface swp3" at end of line -> "interface bond3"
                            if corrected_line.strip().endswith(f"interface {original_interface_name}"):
                                corrected_line = corrected_line.replace(f"interface {original_interface_name}", f"interface {interface_name}")
                            # Pattern 6: "nv set interface swp3" at end of line -> "nv set interface bond3"
                            if f"nv set interface {original_interface_name}" in corrected_line:
                                corrected_line = corrected_line.replace(f"nv set interface {original_interface_name}", f"nv set interface {interface_name}")
                            corrected_lines.append(corrected_line)
                    corrected_config_command = '\n'.join(corrected_lines)
                    logger.info(f"Replaced interface name from {original_interface_name} to {interface_name} in config command")
                    logger.debug(f"Original config_command: {config_command}")
                    logger.debug(f"Corrected config_command: {corrected_config_command}")
                    logs.append(f"  [INFO] Replaced interface name from {original_interface_name} to {interface_name} in all commands")
                
                # For Cumulus NVUE, the config_command is already an NVUE command (e.g., "nv set interface ...")
                # NAPALM's commit_config() will handle "nv config apply --confirm {timeout}s" automatically
                # So we only need the NVUE set command, not the apply command
                config_text = corrected_config_command
                # Log only first line to reduce noise
                first_line = config_text.split('\n')[0] if config_text else ''
                logs.append(f"[2.2] Deploying {len(config_text.splitlines())} command(s) to {device.name} (interface: {interface_name})")
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
                logs.append(f"[FAIL] Unsupported platform: {platform}")
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
            logs.append(f"[OK] NAPALM manager initialized")
            
            # For Cumulus, check if VLAN already exists on bridge before adding
            # IMPORTANT: Order matters - bridge VLAN must be added BEFORE interface access VLAN
            if platform == 'cumulus':
                bridge_vlans = []
                bridge_vlan_needed = False
                try:
                    # Connect to device to get current bridge VLANs
                    if napalm_manager.connect():
                        connection = napalm_manager.connection
                        try:
                            # Get bridge VLANs from device config
                            if hasattr(connection, 'cli'):
                                config_show_output = connection.cli(['nv config show -o json'])
                            elif hasattr(connection, 'device') and hasattr(connection.device, 'send_command'):
                                config_show_output = connection.device.send_command('nv config show -o json', read_timeout=60)
                            else:
                                config_show_output = None
                            
                            if config_show_output:
                                # Extract JSON string
                                if isinstance(config_show_output, dict):
                                    config_json_str = config_show_output.get('nv config show -o json') or list(config_show_output.values())[0] if config_show_output else None
                                else:
                                    config_json_str = str(config_show_output).strip()
                                
                                if config_json_str:
                                    import json
                                    config_data = json.loads(config_json_str)
                                    bridge_vlans = self._get_bridge_vlans_from_json(config_data)
                                    logger.debug(f"Bridge VLANs on {device.name}: {bridge_vlans}")
                        except Exception as e:
                            logger.warning(f"Could not get bridge VLANs from {device.name}: {e}")
                            # Continue without bridge VLAN check - will add command anyway (idempotent)
                        finally:
                            napalm_manager.disconnect()
                except Exception as e:
                    logger.warning(f"Could not connect to {device.name} to check bridge VLANs: {e}")
                    # Continue without bridge VLAN check - will add command anyway (idempotent)
                
                # ISSUE 1 FIX: Filter out ALL bridge VLAN commands that already exist in bridge
                # Parse config_text and remove bridge VLAN commands for VLANs that already exist
                import re
                logger.info(f"[FILTER] Starting bridge VLAN filtering for {device.name}")
                logger.info(f"[FILTER] Current bridge VLANs on device: {bridge_vlans}")
                logger.info(f"[FILTER] Original config_text has {len(config_text.splitlines())} line(s)")
                
                config_lines = [line.strip() for line in config_text.split('\n') if line.strip()]
                final_commands = []
                
                for line in config_lines:
                    # Check if this is a bridge VLAN command
                    bridge_vlan_match = re.match(r'nv set bridge domain br_default vlan (\d+)', line)
                    if bridge_vlan_match:
                        vlan_id_in_cmd = int(bridge_vlan_match.group(1))
                        # Only add if VLAN doesn't already exist in bridge
                        is_in_bridge = self._is_vlan_in_bridge_vlans(vlan_id_in_cmd, bridge_vlans)
                        if not is_in_bridge:
                            final_commands.append(line)
                            logger.info(f"[FILTER] VLAN {vlan_id_in_cmd} NOT in bridge - KEEPING command: {line}")
                        else:
                            logger.info(f"[FILTER] VLAN {vlan_id_in_cmd} already exists in bridge - REMOVING command: {line}")
                    else:
                        # Not a bridge VLAN command (e.g., interface access command) - always add
                        final_commands.append(line)
                        logger.debug(f"[FILTER] Non-bridge command - KEEPING: {line}")
                
                # Combine commands in correct order
                config_text = "\n".join(final_commands)
                # Update config_command with corrected config_text for use in logs
                config_command = config_text
                
                if len(config_lines) != len(final_commands):
                    removed_count = len(config_lines) - len(final_commands)
                    logger.info(f"[FILTER] Filtered out {removed_count} bridge VLAN command(s) that already exist in bridge")
                    logs.append(f"[INFO] Filtered out {removed_count} bridge VLAN command(s) that already exist in bridge")
                else:
                    logger.info(f"[FILTER] No bridge VLAN commands filtered - all VLANs are new or bridge_vlans list was empty")

            # Deploy using safe deployment with post-checks
            # Both EOS and Cumulus support commit-confirm workflow:
            # - EOS: Uses "configure session" with commit timer
            # - Cumulus: Uses "nv config apply --confirm {timeout}s"
            # Use merge mode (replace=False) since we're only adding VLAN config
            # Set timeout to 90 seconds for rollback timer
            # Check connectivity and interfaces (the interface we're configuring should stay up)
            # Get current config before deployment (for display in logs)
            # Use same logic as dry run mode - handles ranges, retries, fallbacks properly
            logs.append(f"[2.4] Collecting current configuration...")
            current_config_before = None
            bridge_vlans_before = []
            bond_member_of = None
            bond_interface_config = None
            try:
                # If original_interface_name is provided (bond member case), get config for the member interface
                # This will include bond membership info and bond interface config
                config_interface_name = original_interface_name if original_interface_name else interface_name
                device_config_result = self._get_current_device_config(device, config_interface_name, platform)
                current_config_before = device_config_result.get('current_config', None)
                bridge_vlans_before = device_config_result.get('_bridge_vlans', [])  # Get bridge VLANs if available
                bond_member_of = device_config_result.get('bond_member_of', None)
                bond_interface_config = device_config_result.get('bond_interface_config', None)
                
                # If we got config for member interface but target is bond, also get bond config directly
                # This ensures we have the full bond config even if member interface lookup didn't return it
                if original_interface_name and interface_name != original_interface_name:
                    try:
                        bond_config_result = self._get_current_device_config(device, interface_name, platform)
                        if bond_config_result.get('current_config'):
                            # If we didn't get bond config from member lookup, use direct bond lookup
                            if not bond_interface_config:
                                bond_interface_config = bond_config_result.get('current_config', None)
                    except Exception:
                        pass  # Ignore errors, use what we have
                
                # Clean up the config string (remove error messages if any)
                if current_config_before and isinstance(current_config_before, str):
                    if current_config_before.startswith('ERROR:'):
                        current_config_before = None
                    elif "(no configuration" in current_config_before or "(interface" in current_config_before:
                        # Keep minimal config messages but don't treat as full config
                        pass
            except Exception as e:
                logger.debug(f"Could not get current config before deployment: {e}")
                current_config_before = None
                bridge_vlans_before = []
            
            # IMPORTANT: Update interface_name to bond interface if bond detected
            # This ensures all sections (proposed config, diff, Removed/Replaced, Added) use bond interface name
            if bond_member_of and interface_name != bond_member_of:
                logger.info(f"Updating interface_name from {interface_name} to {bond_member_of} for bond member")
                interface_name = bond_member_of
            
            # Get NetBox current state and generate diffs (same as dry run)
            # Use original_interface_name for NetBox state (NetBox has the member interface, not the bond)
            netbox_interface_name = original_interface_name if original_interface_name else interface_name
            netbox_state = self._get_netbox_current_state(device, netbox_interface_name, vlan_id)
            
            # Get bond information for NetBox diff (if bond detected)
            bond_info_for_netbox = None
            bond_name_for_netbox = None
            if bond_member_of:
                bond_info_for_netbox = self._get_bond_interface_for_member(device, netbox_interface_name, platform=platform)
                bond_name_for_netbox = bond_member_of
            
            netbox_diff = self._generate_netbox_diff(
                netbox_state, 
                netbox_state['proposed'],
                bond_info=bond_info_for_netbox,
                interface_name=netbox_interface_name,
                bond_name=bond_name_for_netbox
            )
            
            # Generate proposed config and config diff (same as dry run)
            # Use interface_name (target interface - bond if member) for config generation
            # Get bridge VLANs if available for checking
            bridge_vlans_for_config = []
            try:
                device_config_result = self._get_current_device_config(device, interface_name, platform)
                bridge_vlans_for_config = device_config_result.get('_bridge_vlans', [])
            except Exception:
                pass
            proposed_config = self._generate_vlan_config(interface_name, vlan_id, platform, device=device, bridge_vlans=bridge_vlans_for_config)
            # For config diff, use the bond interface config if available, otherwise use member config
            config_for_diff = bond_interface_config if (bond_interface_config and original_interface_name) else current_config_before
            config_diff = self._generate_config_diff(config_for_diff, proposed_config, platform, device=device, interface_name=interface_name, bridge_vlans=bridge_vlans_before)
            
            # Display current configuration (Always shown - same as dry run)
            logs.append(f"")
            logs.append(f"--- Current Device Configuration (Real from Device) ---")
            logs.append(f"")
            
            # If this is a bond member, show bond membership info and both configs
            if original_interface_name and bond_member_of:
                logs.append(f"Bond Membership:")
                logs.append(f"  Interface '{original_interface_name}' is a member of bond '{bond_member_of}'")
                logs.append(f"")
                logs.append(f"Interface-Level Configuration (for '{original_interface_name}'):")
                if current_config_before and current_config_before.strip() and not "(no configuration" in current_config_before and not "ERROR:" in current_config_before:
                    for line in current_config_before.split('\n'):
                        if line.strip():
                            logs.append(f"  {line}")
                else:
                    logs.append(f"  (no configuration found or unable to retrieve)")
                logs.append(f"")
                if bond_interface_config:
                    logs.append(f"Bond Interface '{bond_member_of}' Configuration:")
                    for line in bond_interface_config.split('\n'):
                        if line.strip():
                            logs.append(f"  {line}")
                    logs.append(f"")
            else:
                # Not a bond member - show interface config normally
                logs.append(f"Interface-Level Configuration:")
                if current_config_before and current_config_before.strip() and not "(no configuration" in current_config_before and not "ERROR:" in current_config_before:
                    for line in current_config_before.split('\n'):
                        if line.strip():
                            logs.append(f"  {line}")
                else:
                    logs.append(f"  (no configuration found or unable to retrieve)")
                logs.append(f"")
            
            # Bridge-Level Configuration (for Cumulus - always show)
            if platform == 'cumulus':
                logs.append(f"Bridge-Level Configuration (br_default):")
                if bridge_vlans_before and len(bridge_vlans_before) > 0:
                    # Format VLAN list nicely - show ranges if possible (as it appears in config)
                    vlan_list_str = self._format_vlan_list(bridge_vlans_before)
                    # Show actual NVUE command that configures this
                    logs.append(f"  nv set bridge domain br_default vlan {vlan_list_str}")
                else:
                    logs.append(f"  (bridge VLAN information not available)")
                logs.append(f"")
            
            # Proposed Device Configuration - shown AFTER bond detection so it shows bond3
            logs.append(f"--- Proposed Device Configuration ---")
            for line in proposed_config.split('\n'):
                if line.strip():
                    logs.append(f"  {line}")
            logs.append(f"")
            
            # Current NetBox Configuration (Always shown - source of truth)
            logs.append(f"--- Current NetBox Configuration (Source of Truth) ---")
            netbox_current = netbox_state['current']
            logs.append(f"802.1Q Mode: {netbox_current['mode'] or 'None'}")
            logs.append(f"Untagged VLAN: {netbox_current['untagged_vlan'] or 'None'}")
            tagged_vlans_str = ', '.join(map(str, netbox_current['tagged_vlans'])) if netbox_current['tagged_vlans'] else 'None'
            logs.append(f"Tagged VLANs: [{tagged_vlans_str}]")
            ip_addresses_str = ', '.join(netbox_current['ip_addresses']) if netbox_current['ip_addresses'] else 'None'
            logs.append(f"IP Addresses: {ip_addresses_str}")
            logs.append(f"VRF: {netbox_current['vrf'] or 'None'}")
            logs.append(f"Cable Status: {netbox_current['cable_status']}")
            if netbox_current['connected_to']:
                logs.append(f"Connected To: {netbox_current['connected_to']}")
            logs.append(f"Enabled: {netbox_current['enabled']}")
            logs.append(f"Port-Channel Member: {netbox_current['port_channel_member']}")
            logs.append(f"")
            
            # Configuration Conflict Detection (Always shown - useful for understanding issues)
            device_has_ip = bool(netbox_current['ip_addresses'])
            device_has_vrf = bool(netbox_current['vrf'])
            device_config_has_ip = 'ip address' in current_config_before.lower() if current_config_before else False
            device_config_has_vrf = 'vrf' in current_config_before.lower() if current_config_before else False
            device_config_has_vlan = False
            device_vlan_id = None
            # Check bond interface config if this is a bond member, otherwise check member config
            config_to_check = bond_interface_config if (bond_interface_config and original_interface_name) else current_config_before
            if config_to_check:
                import re
                vlan_match = re.search(r'access\s+(\d+)', config_to_check.lower())
                if vlan_match:
                    device_config_has_vlan = True
                    device_vlan_id = int(vlan_match.group(1))
            netbox_has_vlan = netbox_current.get('untagged_vlan') is not None
            netbox_vlan_id = netbox_current.get('untagged_vlan')
            conflict_detected = False
            conflict_reasons = []
            if device_config_has_ip != device_has_ip:
                conflict_detected = True
                conflict_reasons.append("IP address mismatch")
            if device_config_has_vrf != device_has_vrf:
                conflict_detected = True
                conflict_reasons.append("VRF mismatch")
            if netbox_has_vlan and not device_config_has_vlan:
                conflict_detected = True
                conflict_reasons.append(f"NetBox has VLAN {netbox_vlan_id} configured but device has no VLAN config")
            elif netbox_has_vlan and device_config_has_vlan and netbox_vlan_id != device_vlan_id:
                conflict_detected = True
                conflict_reasons.append(f"VLAN mismatch: NetBox has {netbox_vlan_id}, device has {device_vlan_id}")
            elif not netbox_has_vlan and device_config_has_vlan:
                conflict_detected = True
                conflict_reasons.append(f"Device has VLAN {device_vlan_id} configured but NetBox has no VLAN")
            
            logs.append(f"--- Configuration Conflict Detection ---")
            if conflict_detected:
                logs.append(f"[WARN] Device config differs from NetBox config")
                if conflict_reasons:
                    logs.append(f"  Conflicts detected: {', '.join(conflict_reasons)}")
                logs.append(f"")
                logs.append(f"Device Should Have (According to NetBox):")
                # ISSUE 1 FIX: Generate config from NetBox's ACTUAL configuration, not from proposed_config
                # proposed_config contains the VLAN from form input, but we need to show what NetBox actually has
                # Determine target interface (bond if member, otherwise original)
                target_interface_for_netbox = interface_name
                bond_info_local = locals().get('bond_info')
                bond_member_of_local = locals().get('bond_member_of')
                if bond_info_local and bond_info_local.get('bond_name'):
                    target_interface_for_netbox = bond_info_local['bond_name']
                elif bond_member_of_local:
                    target_interface_for_netbox = bond_member_of_local
                
                # Generate config from NetBox's actual state
                netbox_config_lines = []
                if platform == 'cumulus':
                    # Show bridge VLAN commands for all VLANs in NetBox
                    all_netbox_vlans = set()
                    if netbox_current.get('untagged_vlan'):
                        all_netbox_vlans.add(netbox_current['untagged_vlan'])
                    all_netbox_vlans.update(netbox_current.get('tagged_vlans', []))
                    
                    for vlan_vid in sorted(all_netbox_vlans):
                        # Only show if not already in bridge (to avoid duplicates)
                        if not self._is_vlan_in_bridge_vlans(vlan_vid, bridge_vlans_before):
                            netbox_config_lines.append(f"nv set bridge domain br_default vlan {vlan_vid}")
                    
                    # Show interface access VLAN command (untagged VLAN)
                    if netbox_current.get('untagged_vlan'):
                        netbox_config_lines.append(f"nv set interface {target_interface_for_netbox} bridge domain br_default access {netbox_current['untagged_vlan']}")
                elif platform == 'eos':
                    # EOS commands
                    if netbox_current.get('untagged_vlan'):
                        netbox_config_lines.append(f"interface {target_interface_for_netbox}")
                        netbox_config_lines.append(f"  switchport access vlan {netbox_current['untagged_vlan']}")
                
                # Display the config
                if netbox_config_lines:
                    for line in netbox_config_lines:
                        logs.append(f"  {line}")
                else:
                    logs.append(f"  (no VLAN configuration in NetBox)")
                logs.append(f"")
                logs.append(f"Note: NetBox is the source of truth. Device may have stale/old configuration.")
                logs.append(f"      Any differences will be reconciled during deployment.")
            else:
                logs.append(f"[OK] Device config matches NetBox - no conflicts detected")
            logs.append(f"")
            
            # Config Diff
            logs.append(f"--- Config Diff ---")
            logs.append(f"(Shows what will be removed/replaced and what will be added)")
            logs.append(f"")
            for line in config_diff.split('\n'):
                if line.strip():
                    logs.append(f"  {line}")
            logs.append(f"")
            
            # NetBox Configuration Changes
            logs.append(f"--- NetBox Configuration Changes ---")
            for line in netbox_diff.split('\n'):
                if line.strip():
                    logs.append(f"  {line}")
            logs.append(f"")
            
            # Show what will be added/replaced (only VLAN-related configs)
            logs.append(f"--- Configuration Changes (What Will Be Applied) ---")
            logs.append(f"")
            logs.append(f"Note: Only VLAN-related configurations will be changed.")
            logs.append(f"      Other configurations (link state, type, breakout, etc.) are preserved.")
            logs.append(f"")
            
            # Determine what's being replaced
            # Check bond config if this is a bond member, otherwise check member config
            config_to_check_for_old_vlan = bond_interface_config if (bond_interface_config and original_interface_name) else current_config_before
            if config_to_check_for_old_vlan:
                # Check if interface has existing access VLAN
                import re
                old_vlan_match = re.search(r'access\s+(\d+)', config_to_check_for_old_vlan)
                if old_vlan_match:
                    old_vlan = old_vlan_match.group(1)
                    logs.append(f"Removed/Replaced:")
                    # Use interface_name which is the target interface (bond3 if bond member)
                    logs.append(f"  - nv set interface {interface_name} bridge domain br_default access {old_vlan}")
                else:
                    logs.append(f"Removed/Replaced:")
                    logs.append(f"  (no existing access VLAN to replace)")
            else:
                logs.append(f"Removed/Replaced:")
                logs.append(f"  (no existing configuration to replace)")
            logs.append(f"")
            
            # Show what's being added - use config_text which has the correct bond interface name (after replacement)
            # ISSUE 1 FIX: Filter out bridge VLAN commands that already exist in bridge
            logs.append(f"Added:")
            # Use config_text which is the final corrected command that will be sent to device
            # This ensures the diff shows bond3 instead of swp3
            config_lines_to_show = [line.strip() for line in config_text.split('\n') if line.strip()]
            
            # Get bridge VLANs to check if VLANs already exist
            bridge_vlans_for_display = []
            try:
                device_config_result = self._get_current_device_config(device, interface_name, platform)
                bridge_vlans_for_display = device_config_result.get('_bridge_vlans', [])
            except Exception:
                pass
            
            import re
            for line in config_lines_to_show:
                # Check if this is a bridge VLAN command and if VLAN already exists
                bridge_vlan_match = re.match(r'nv set bridge domain br_default vlan (\d+)', line)
                if bridge_vlan_match:
                    vlan_id_to_check = int(bridge_vlan_match.group(1))
                    if not self._is_vlan_in_bridge_vlans(vlan_id_to_check, bridge_vlans_for_display):
                        logs.append(f"  + {line}")
                    else:
                        logger.debug(f"Skipping bridge VLAN command for {vlan_id_to_check} in display - already exists in bridge")
                else:
                    # Not a bridge VLAN command (e.g., interface access command) - always show
                    logs.append(f"  + {line}")
            logs.append(f"")
            
            logs.append(f"[2.5] Starting safe deployment with 90s rollback timer...")
            logs.append(f"      Mode: Merge (incremental changes)")
            logs.append(f"      Checks: connectivity")
            logs.append(f"      Interface: {interface_name}")
            logs.append(f"      VLAN ID: {vlan_id}")
            logs.append(f"")
            logs.append(f"      Actual commands being sent to device:")
            logs.append(f"      (Note: Bridge VLANs already on device are filtered out)")
            # Log the actual config_text that will be sent (after interface name replacement)
            for line in config_text.split('\n'):
                if line.strip():
                    logs.append(f"        {line.strip()}")

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
                logs.append(f"[2.6] Deployment execution logs:")
                for log_line in deploy_result["logs"]:
                    logs.append(f"      {log_line}")

            logger.info(f"Deployment result for {device.name}: success={deploy_result.get('success')}, "
                       f"committed={deploy_result.get('committed')}, rolled_back={deploy_result.get('rolled_back')}")

            logs.append(f"[2.7] Deployment completed:")
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
            logs.append(f"[FAIL] Exception during deployment: {str(e)}")
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
                    logs.append(f"[OK] Disconnected successfully")
                except Exception as e:
                    logger.warning(f"Error disconnecting from {device.name}: {e}")
                    logs.append(f"[WARN] Warning during disconnect: {e}")

    def _update_netbox_interface(self, device, interface_name, vlan):
        """
        Update NetBox interface with VLAN assignment.
        Replaces ALL existing configs that conflict with VLAN deployment to match device config.
        
        What we REMOVE/REPLACE (conflicts with VLAN deployment):
        - IP addresses (routed → bridged conversion)
        - VRF (routed → bridged conversion)
        - Tagged VLANs (cleared for access mode deployment)
        - Old untagged VLAN (replaced with new VLAN)
        - Old mode (replaced with 'tagged')
        
        What we KEEP (doesn't conflict with VLAN deployment):
        - Port-channel membership (physical relationship)
        - Cable connections (physical relationship)
        - Description (metadata)
        - Enabled status (operational state)
        - MTU (doesn't conflict)
        - Tags (metadata, may include automation tags)
        
        This ensures NetBox state matches the actual device configuration after deployment.

        Returns:
            dict: {"success": bool, "error": str}
        """
        try:
            from ipam.models import IPAddress
            from ipam.models import VRF
            
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

                # Track what we're removing for logging
                removed_configs = []

                # Remove IP addresses (routed → bridged conversion)
                # IP addresses conflict with VLAN/bridge configuration
                ip_addresses = interface.ip_addresses.all()
                for ip_addr in ip_addresses:
                    ip_addr.assigned_object = None
                    ip_addr.assigned_object_type = None
                    ip_addr.save()
                    removed_configs.append(f"IP address {ip_addr.address}")
                    logger.info(f"Removed IP address {ip_addr.address} from interface {interface_name} on {device.name}")

                # Remove VRF (routed → bridged conversion)
                # VRF conflicts with VLAN/bridge configuration
                if hasattr(interface, 'vrf') and interface.vrf:
                    old_vrf = interface.vrf.name
                    interface.vrf = None
                    removed_configs.append(f"VRF {old_vrf}")
                    logger.info(f"Removed VRF {old_vrf} from interface {interface_name} on {device.name}")

                # Clear tagged VLANs (for access mode deployment, we only set untagged)
                # Tagged VLANs conflict with access mode deployment
                old_tagged = list(interface.tagged_vlans.values_list('vid', flat=True))
                if old_tagged:
                    interface.tagged_vlans.clear()
                    removed_configs.append(f"Tagged VLANs: {', '.join(map(str, old_tagged))}")
                    logger.info(f"Cleared tagged VLANs {old_tagged} from interface {interface_name} on {device.name}")

                # Replace old untagged VLAN if different
                old_untagged = interface.untagged_vlan.vid if interface.untagged_vlan else None
                if old_untagged and old_untagged != vlan.vid:
                    removed_configs.append(f"Untagged VLAN {old_untagged}")
                    logger.info(f"Replacing untagged VLAN {old_untagged} with {vlan.vid} on interface {interface_name} on {device.name}")

                # Replace old mode if different
                old_mode = interface.mode if hasattr(interface, 'mode') else None
                if old_mode and old_mode != 'tagged':
                    removed_configs.append(f"Mode {old_mode}")
                    logger.info(f"Replacing mode {old_mode} with 'tagged' on interface {interface_name} on {device.name}")

                # Set new VLAN configuration (tagged mode for VLAN-aware bridges)
                # Note: Even for access ports, we use 'tagged' mode in NetBox because
                # Cumulus/Mellanox devices use VLAN-aware bridges where all ports are in tagged mode
                interface.mode = 'tagged'
                interface.untagged_vlan = vlan
                interface.save()

                if removed_configs:
                    logger.info(f"Updated NetBox interface {interface_name} on {device.name}: removed {', '.join(removed_configs)}, set mode=tagged, untagged_vlan={vlan.vid}")
                else:
                    logger.info(f"Updated NetBox interface {interface_name} on {device.name}: set mode=tagged, untagged_vlan={vlan.vid}")

                return {
                    "success": True,
                    "error": None
                }

        except Exception as e:
            logger.error(f"Error updating NetBox interface {interface_name} on {device.name}: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def _migrate_vlans_to_bond(self, device, bond_name, member_interfaces, platform=None):
        """
        Migrate VLANs from member interfaces to bond interface in NetBox.
        This is called when bond exists in NetBox but VLANs are still on member interfaces.
        
        Args:
            device: Device object
            bond_name: Bond interface name (e.g., 'bond3')
            member_interfaces: List of interface names that are members of the bond
            platform: Platform type (optional)
        
        Returns:
            dict: {
                "success": bool,
                "vlans_migrated": int,  # Number of member interfaces that had VLANs moved
                "vlans_migrated_from": list,  # List of interface names that had VLANs migrated
                "error": str or None
            }
        """
        try:
            from dcim.models import Interface
            
            with transaction.atomic():
                # Get bond interface
                try:
                    bond_interface = Interface.objects.get(device=device, name=bond_name)
                except Interface.DoesNotExist:
                    return {
                        "success": False,
                        "vlans_migrated": 0,
                        "vlans_migrated_from": [],
                        "error": f"Bond interface {bond_name} not found in NetBox"
                    }
                
                # Collect VLANs from all member interfaces
                all_untagged_vlans = set()
                all_tagged_vlans = set()
                members_with_vlans = []
                
                for member_name in member_interfaces:
                    try:
                        member_interface = Interface.objects.get(device=device, name=member_name)
                        
                        # Collect VLANs from this member
                        if member_interface.untagged_vlan:
                            all_untagged_vlans.add(member_interface.untagged_vlan)
                            if member_name not in members_with_vlans:
                                members_with_vlans.append(member_name)
                        if member_interface.tagged_vlans.exists():
                            all_tagged_vlans.update(member_interface.tagged_vlans.all())
                            if member_name not in members_with_vlans:
                                members_with_vlans.append(member_name)
                    except Interface.DoesNotExist:
                        logger.warning(f"Interface {member_name} not found in NetBox during VLAN migration")
                    except Exception as e:
                        logger.warning(f"Error collecting VLANs from {member_name}: {e}")
                
                # Only migrate if there are VLANs on members
                vlans_migrated = 0
                if all_untagged_vlans or all_tagged_vlans:
                    # Set VLANs on bond interface (consolidate from all members)
                    if all_untagged_vlans:
                        if len(all_untagged_vlans) > 1:
                            logger.warning(f"Bond {bond_name} members have multiple untagged VLANs: {all_untagged_vlans} - using first one")
                        bond_interface.untagged_vlan = list(all_untagged_vlans)[0]
                        bond_interface.mode = 'tagged'
                    if all_tagged_vlans:
                        bond_interface.tagged_vlans.set(all_tagged_vlans)
                        bond_interface.mode = 'tagged'
                    bond_interface.save()
                    logger.info(f"Migrated VLANs to bond {bond_name}: untagged={list(all_untagged_vlans)}, tagged={[v.vid for v in all_tagged_vlans]}")
                    
                    # Clear VLANs from member interfaces (they're now on the bond)
                    for member_name in members_with_vlans:
                        try:
                            member_interface = Interface.objects.get(device=device, name=member_name)
                            old_untagged = member_interface.untagged_vlan.vid if member_interface.untagged_vlan else None
                            old_tagged = list(member_interface.tagged_vlans.values_list('vid', flat=True))
                            
                            member_interface.untagged_vlan = None
                            member_interface.tagged_vlans.clear()
                            member_interface.mode = None
                            member_interface.save()
                            vlans_migrated += 1
                            
                            logger.info(f"Removed VLANs from member {member_name}: untagged={old_untagged}, tagged={old_tagged}")
                        except Interface.DoesNotExist:
                            logger.warning(f"Interface {member_name} not found during VLAN migration")
                        except Exception as e:
                            logger.warning(f"Error removing VLANs from {member_name}: {e}")
                
                return {
                    "success": True,
                    "vlans_migrated": vlans_migrated,
                    "vlans_migrated_from": members_with_vlans,
                    "error": None
                }
        
        except Exception as e:
            logger.error(f"Error migrating VLANs to bond {bond_name} for device {device.name}: {e}")
            return {
                "success": False,
                "vlans_migrated": 0,
                "vlans_migrated_from": [],
                "error": str(e)
            }

    def _sync_bond_to_netbox(self, device, bond_name, member_interfaces, platform=None):
        """
        Create or update bond interface in NetBox based on device configuration.
        This is called when device has a bond but NetBox doesn't have it defined.
        
        IMPORTANT: Also migrates VLANs from member interfaces to the bond interface.
        This ensures NetBox state matches the device reality where VLANs are configured
        on the bond, not on individual members.
        
        Args:
            device: Device object
            bond_name: Bond interface name from device config (e.g., 'bond3')
            member_interfaces: List of interface names that are members of the bond
            platform: Platform type (optional)
        
        Returns:
            dict: {
                "success": bool,
                "bond_created": bool,
                "members_added": int,
                "vlans_migrated": int,  # Number of member interfaces that had VLANs moved
                "vlans_migrated_from": list,  # List of interface names that had VLANs migrated
                "error": str or None
            }
        """
        try:
            from dcim.models import InterfaceTypeChoices
            
            with transaction.atomic():
                # Check if bond interface already exists in NetBox
                bond_interface = Interface.objects.filter(
                    device=device,
                    name=bond_name
                ).first()
                
                bond_created = False
                if not bond_interface:
                    # Create bond interface in NetBox
                    bond_interface = Interface(
                        device=device,
                        name=bond_name,
                        type=InterfaceTypeChoices.TYPE_LAG,  # Link Aggregation Group (bond)
                        enabled=True
                    )
                    bond_interface.save()
                    bond_created = True
                    logger.info(f"Created bond interface {bond_name} in NetBox for device {device.name}")
                
                # Collect VLANs from all member interfaces (to consolidate on bond)
                all_untagged_vlans = set()
                all_tagged_vlans = set()
                members_with_vlans = []
                
                # Add member interfaces to the bond AND collect their VLANs
                members_added = 0
                for member_name in member_interfaces:
                    try:
                        member_interface = Interface.objects.get(device=device, name=member_name)
                        
                        # Collect VLANs from this member
                        if member_interface.untagged_vlan:
                            all_untagged_vlans.add(member_interface.untagged_vlan)
                            members_with_vlans.append(member_name)
                        if member_interface.tagged_vlans.exists():
                            all_tagged_vlans.update(member_interface.tagged_vlans.all())
                            if member_name not in members_with_vlans:
                                members_with_vlans.append(member_name)
                        
                        # Set LAG membership
                        if not member_interface.lag or member_interface.lag != bond_interface:
                            member_interface.lag = bond_interface
                            member_interface.save()
                            members_added += 1
                            logger.info(f"Added interface {member_name} to bond {bond_name} in NetBox for device {device.name}")
                    except Interface.DoesNotExist:
                        logger.warning(f"Interface {member_name} not found in NetBox, skipping bond membership")
                    except Exception as e:
                        logger.warning(f"Error adding {member_name} to bond {bond_name}: {e}")
                
                # Migrate VLANs from members to bond
                vlans_migrated = 0
                if all_untagged_vlans or all_tagged_vlans:
                    # Set VLANs on bond interface (consolidate from all members)
                    # Note: If multiple members have different untagged VLANs, we take the first one
                    # This should be rare in properly configured networks
                    if all_untagged_vlans:
                        if len(all_untagged_vlans) > 1:
                            logger.warning(f"Bond {bond_name} members have multiple untagged VLANs: {all_untagged_vlans} - using first one")
                        bond_interface.untagged_vlan = list(all_untagged_vlans)[0]
                        bond_interface.mode = 'tagged'
                    if all_tagged_vlans:
                        bond_interface.tagged_vlans.set(all_tagged_vlans)
                        bond_interface.mode = 'tagged'
                    bond_interface.save()
                    logger.info(f"Migrated VLANs to bond {bond_name}: untagged={list(all_untagged_vlans)}, tagged={[v.vid for v in all_tagged_vlans]}")
                    
                    # Clear VLANs from member interfaces (they're now on the bond)
                    for member_name in members_with_vlans:
                        try:
                            member_interface = Interface.objects.get(device=device, name=member_name)
                            old_untagged = member_interface.untagged_vlan.vid if member_interface.untagged_vlan else None
                            old_tagged = list(member_interface.tagged_vlans.values_list('vid', flat=True))
                            
                            member_interface.untagged_vlan = None
                            member_interface.tagged_vlans.clear()
                            member_interface.mode = None
                            member_interface.save()
                            vlans_migrated += 1
                            
                            logger.info(f"Removed VLANs from member {member_name}: untagged={old_untagged}, tagged={old_tagged}")
                        except Interface.DoesNotExist:
                            logger.warning(f"Interface {member_name} not found during VLAN migration")
                        except Exception as e:
                            logger.warning(f"Error removing VLANs from {member_name}: {e}")
                
                return {
                    "success": True,
                    "bond_created": bond_created,
                    "members_added": members_added,
                    "vlans_migrated": vlans_migrated,
                    "vlans_migrated_from": members_with_vlans,  # List of interface names
                    "error": None
                }
        
        except Exception as e:
            logger.error(f"Error syncing bond {bond_name} to NetBox for device {device.name}: {e}")
            return {
                "success": False,
                "bond_created": False,
                "members_added": 0,
                "vlans_migrated": 0,
                "vlans_migrated_from": [],
                "error": str(e)
            }

    def _verify_netbox_update(self, device, interface_name, vlan_id):
        """
        Verify NetBox was updated correctly after deployment.
        Checks that NetBox interface state matches what we deployed.
        
        Returns:
            dict: {
                'success': bool,
                'verified': bool,
                'issues': list of str,
                'details': dict with verification results
            }
        """
        try:
            interface = Interface.objects.get(device=device, name=interface_name)
            interface.refresh_from_db()
            
            issues = []
            details = {}
            
            # Verify mode is set to 'tagged'
            current_mode = interface.mode if hasattr(interface, 'mode') else None
            if current_mode != 'tagged':
                issues.append(f"Mode is '{current_mode}' but expected 'tagged'")
            details['mode'] = {
                'expected': 'tagged',
                'actual': current_mode,
                'verified': current_mode == 'tagged'
            }
            
            # Verify untagged VLAN matches deployed VLAN
            current_untagged = interface.untagged_vlan.vid if interface.untagged_vlan else None
            if current_untagged != vlan_id:
                issues.append(f"Untagged VLAN is {current_untagged} but expected {vlan_id}")
            details['untagged_vlan'] = {
                'expected': vlan_id,
                'actual': current_untagged,
                'verified': current_untagged == vlan_id
            }
            
            # Verify tagged VLANs are cleared (for access mode deployment)
            current_tagged = list(interface.tagged_vlans.values_list('vid', flat=True))
            if current_tagged:
                issues.append(f"Tagged VLANs should be empty but found: {current_tagged}")
            details['tagged_vlans'] = {
                'expected': [],
                'actual': current_tagged,
                'verified': len(current_tagged) == 0
            }
            
            # Verify IP addresses are removed
            current_ip_addresses = [str(ip.address) for ip in interface.ip_addresses.all()]
            if current_ip_addresses:
                issues.append(f"IP addresses should be removed but found: {current_ip_addresses}")
            details['ip_addresses'] = {
                'expected': [],
                'actual': current_ip_addresses,
                'verified': len(current_ip_addresses) == 0
            }
            
            # Verify VRF is removed
            current_vrf = interface.vrf.name if hasattr(interface, 'vrf') and interface.vrf else None
            if current_vrf:
                issues.append(f"VRF should be removed but found: {current_vrf}")
            details['vrf'] = {
                'expected': None,
                'actual': current_vrf,
                'verified': current_vrf is None
            }
            
            # Overall verification status
            verified = len(issues) == 0
            
            if verified:
                logger.info(f"NetBox verification PASSED for {device.name}:{interface_name} - all checks passed")
            else:
                logger.warning(f"NetBox verification FAILED for {device.name}:{interface_name} - issues: {', '.join(issues)}")
            
            return {
                'success': True,
                'verified': verified,
                'issues': issues,
                'details': details
            }
            
        except Interface.DoesNotExist:
            return {
                'success': False,
                'verified': False,
                'issues': [f"Interface {interface_name} not found in NetBox"],
                'details': {}
            }
        except Exception as e:
            logger.error(f"Error verifying NetBox update for {device.name}:{interface_name}: {e}")
            return {
                'success': False,
                'verified': False,
                'issues': [f"Verification error: {str(e)}"],
                'details': {}
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

    def _build_device_summaries(self, results):
        """Build per-device summary statistics."""
        device_data = {}
        
        for r in results:
            device = r.get("device")
            if not device:
                continue
            
            device_name = device.name if hasattr(device, 'name') else str(device)
            
            if device_name not in device_data:
                device_data[device_name] = {
                    "device": device,
                    "device_name": device_name,
                    "total": 0,
                    "pass": 0,
                    "warn": 0,
                    "blocked": 0,
                }
            
            device_data[device_name]["total"] += 1
            
            # Check both overall_status (dry run) and status (deployment)
            overall_status = r.get("overall_status", "").upper()
            status = r.get("status", "").lower()
            
            # Determine status: prefer overall_status, fallback to status
            if overall_status:
                if overall_status == "PASS":
                    device_data[device_name]["pass"] += 1
                elif overall_status == "WARN":
                    device_data[device_name]["warn"] += 1
                elif overall_status == "BLOCKED":
                    device_data[device_name]["blocked"] += 1
            elif status:
                # For deployment results: "success" = PASS, "error" = BLOCKED
                if status == "success":
                    device_data[device_name]["pass"] += 1
                elif status == "error":
                    device_data[device_name]["blocked"] += 1
                # Check message for WARN indicators
                message = r.get("message", "").upper()
                if "WARN" in message and status == "success":
                    device_data[device_name]["warn"] += 1
                    device_data[device_name]["pass"] -= 1  # Adjust: WARN takes precedence
        
        # Convert to list and determine overall device status
        device_summaries = []
        for device_name, data in device_data.items():
            # Determine device overall status
            if data["blocked"] > 0:
                device_status = "blocked"
            elif data["warn"] > 0:
                device_status = "warn"
            else:
                device_status = "pass"
            
            data["device_status"] = device_status
            device_summaries.append(data)
        
        # Sort by device name
        device_summaries.sort(key=lambda x: x["device_name"])
        
        return device_summaries

    def _calculate_status_counts(self, results):
        """Calculate counts for each status type."""
        counts = {
            "pass": 0,
            "warn": 0,
            "blocked": 0,
            "total": len(results),
        }
        
        for r in results:
            overall_status = r.get("overall_status", "").upper()
            if overall_status == "PASS":
                counts["pass"] += 1
            elif overall_status == "WARN":
                counts["warn"] += 1
            elif overall_status == "BLOCKED":
                counts["blocked"] += 1
        
        return counts

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
                        "Interface '" + iface_name + "' does not exist on device '" + device.name + "'"
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
        excluded_device_ids = request.GET.getlist('excluded_device_ids[]')

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

        # Filter out excluded devices if any
        if excluded_device_ids:
            excluded_ids = [int(did) for did in excluded_device_ids if str(did).isdigit()]
            if excluded_ids:
                devices = devices.exclude(id__in=excluded_ids)
                logger.info(f"Excluded {len(excluded_ids)} devices. Remaining: {devices.count()} devices")

        if not devices.exists():
            return JsonResponse({'interfaces': [], 'device_count': 0})

        # Get interfaces for each device - return ALL interfaces grouped by device
        interfaces_by_device = {}
        for device in devices:
            interfaces = list(
                Interface.objects.filter(device=device)
                .exclude(name__in=['eth0', 'lo', 'mgmt', 'management', 'loopback', 'Loopback0'])
                .values_list('name', flat=True)
                .order_by('name')
            )
            # Sort naturally (swp1, swp2, swp10 instead of swp1, swp10, swp2)
            interfaces = sorted(interfaces, key=self._natural_sort_key)
            interfaces_by_device[device.name] = interfaces
            # Debug: Log first few interfaces per device
            logger.debug(f"Device {device.name}: {len(interfaces)} interfaces, first 5: {interfaces[:5]}")

        # Return interfaces grouped by device (for accordion display)
        return JsonResponse({
            'interfaces_by_device': interfaces_by_device,
            'device_count': len(devices),
            'total_interfaces': sum(len(ifaces) for ifaces in interfaces_by_device.values())
        })

    def _natural_sort_key(self, s):
        """
        Sort interface names naturally (e.g., swp1, swp2, swp10 instead of swp1, swp10, swp2).
        """
        import re
        return [int(text) if text.isdigit() else text.lower()
                for text in re.split('([0-9]+)', s)]


class GetInterfacesForSyncView(View):
    """
    AJAX endpoint to get interfaces with VLAN config from NetBox for selected devices.
    Used by JavaScript to populate interface checkboxes in sync mode.
    
    Returns interfaces separated into two sections:
    - Section 1 (tagged): Interfaces with vlan-mode:access or vlan-mode:tagged tags
    - Section 2 (missing_netbox_tags): Interfaces with VLAN config but missing proper vlan-mode tags
    """
    
    def get(self, request):
        device_ids = request.GET.getlist('device_ids[]')
        
        # Group mode filter parameters
        site_id = request.GET.get('site_id')
        location_id = request.GET.get('location_id')
        manufacturer_id = request.GET.get('manufacturer_id')
        role_id = request.GET.get('role_id')
        excluded_device_ids = request.GET.getlist('excluded_device_ids[]')
        
        # Get devices either by IDs (Single mode) or by filters (Group mode)
        if device_ids:
            # Single mode: Use provided device IDs
            device_ids = [int(did) for did in device_ids if str(did).isdigit()]
            if not device_ids:
                return JsonResponse({'error': 'No devices selected'}, status=400)
            devices = Device.objects.filter(id__in=device_ids).order_by('name')
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
            ).select_related('device_type', 'device_type__manufacturer').order_by('name')
            
            logger.info(f"Sync mode - Group mode: Found {devices.count()} devices matching filters (site={site_id}, location={location_id}, manufacturer={manufacturer_id}, role={role_id})")
        else:
            return JsonResponse({'error': 'No devices selected or incomplete group filters'}, status=400)
        
        # Filter out excluded devices if any
        if excluded_device_ids:
            excluded_ids = [int(did) for did in excluded_device_ids if str(did).isdigit()]
            if excluded_ids:
                devices = devices.exclude(id__in=excluded_ids)
                logger.info(f"Sync mode - Excluded {len(excluded_ids)} devices. Remaining: {devices.count()} devices")
        
        if not devices.exists():
            return JsonResponse({'tagged_interfaces': {}, 'untagged_interfaces': {}, 'device_count': 0, 'total_tagged': 0, 'total_untagged': 0})  # Keep JSON key for backward compatibility
        tagged_interfaces_by_device = {}
        missing_tags_interfaces_by_device = {}  # Internal variable name uses missing_netbox_tags
        
        # Management interfaces to exclude
        management_interfaces = {'eth0', 'lo', 'mgmt', 'management', 'loopback', 'Loopback0'}
        
        for device in devices:
            device_interfaces = Interface.objects.filter(
                device=device
            ).select_related('untagged_vlan').prefetch_related('tagged_vlans', 'tags').order_by('name')
            
            # Separate into tagged and missing_netbox_tags
            tagged_interfaces = []
            missing_tags_interfaces = []
            
            for iface in device_interfaces:
                # Skip management interfaces
                if iface.name.lower() in [m.lower() for m in management_interfaces]:
                    continue
                
                # Only process interfaces with VLAN config
                if not (iface.untagged_vlan or iface.tagged_vlans.exists()):
                    continue
                
                # Check interface tags to categorize them
                interface_tags = set(iface.tags.values_list('name', flat=True))
                has_vlan_mode_access_tagged = any(
                    tag.startswith('vlan-mode:access') or tag.startswith('vlan-mode:tagged')
                    for tag in interface_tags
                )
                has_vlan_mode_uplink_routed = any(
                    tag.startswith('vlan-mode:uplink') or tag.startswith('vlan-mode:routed')
                    for tag in interface_tags
                )
                has_any_tags = iface.tags.exists()
                
                # Serialize interface with VLAN config
                iface_data = {
                    'name': iface.name,
                    'id': iface.id,
                    'mode': getattr(iface, 'mode', None),
                    'untagged_vlan': {
                        'id': iface.untagged_vlan.id,
                        'vid': iface.untagged_vlan.vid,
                        'name': iface.untagged_vlan.name,
                    } if iface.untagged_vlan else None,
                    'tagged_vlans': [
                        {'id': v.id, 'vid': v.vid, 'name': v.name}
                        for v in iface.tagged_vlans.all().order_by('vid')
                    ],
                }
                
                # Explicit duplicate prevention: if interface has vlan-mode:access or vlan-mode:tagged,
                # it MUST go to Section 1 only, never Section 2
                if has_vlan_mode_access_tagged:
                    # Section 1: Has vlan-mode:access or vlan-mode:tagged tag
                    # Skip strict filtering - these are already validated
                    # Store the actual vlan-mode tags for display
                    vlan_mode_tags = [
                        tag for tag in interface_tags 
                        if tag.startswith('vlan-mode:access') or tag.startswith('vlan-mode:tagged')
                    ]
                    iface_data['vlan_mode_tags'] = vlan_mode_tags
                    iface_data['current_tags'] = list(interface_tags)
                    iface_data['has_any_tags'] = has_any_tags
                    tagged_interfaces.append(iface_data)
                    # Explicitly skip Section 2 to prevent duplicates
                    continue
                else:
                    # Section 2: All interfaces with VLAN config that don't have vlan-mode:access/tagged
                    # Include all interfaces with VLAN config - no strict filtering
                    
                    # Check for any vlan-mode tags (other than access/tagged)
                    other_vlan_mode_tags = [
                        tag for tag in interface_tags 
                        if tag.startswith('vlan-mode:') and 
                        not tag.startswith('vlan-mode:access') and 
                        not tag.startswith('vlan-mode:tagged')
                    ]
                    
                    # Check for any other tags (non-vlan-mode tags like custom tags)
                    non_vlan_mode_tags = [
                        tag for tag in interface_tags 
                        if not tag.startswith('vlan-mode:')
                    ]
                    
                    # Combine all tags that will be replaced/warned about
                    all_other_tags = other_vlan_mode_tags + non_vlan_mode_tags
                    
                    # Store tag information for frontend display
                    iface_data['current_tags'] = list(interface_tags)  # All current tags
                    iface_data['has_any_tags'] = has_any_tags
                    
                    if other_vlan_mode_tags:
                        # Has vlan-mode tags that need replacement (uplink, routed, etc.)
                        iface_data['has_conflicting_tags'] = True
                        iface_data['conflicting_tags'] = other_vlan_mode_tags
                        iface_data['warning'] = f"Interface labeled as {', '.join(other_vlan_mode_tags)}. These labels will be replaced with vlan-mode:access or vlan-mode:tagged after successful deployment."
                    elif has_any_tags:
                        # Has other tags (non-vlan-mode) but also has VLAN config
                        # Still include it, but show info (tags won't be replaced, just adding vlan-mode tag)
                        iface_data['has_conflicting_tags'] = False
                        iface_data['other_tags'] = non_vlan_mode_tags
                        iface_data['info'] = f"Interface has tags: {', '.join(non_vlan_mode_tags)}. Will add vlan-mode:access or vlan-mode:tagged tag."
                    else:
                        # No tags at all - completely untagged
                        iface_data['has_conflicting_tags'] = False
                        iface_data['info'] = "Missing NetBox tags interface - will be auto-tagged after deployment."
                    
                    missing_tags_interfaces.append(iface_data)
            
            # Safety check: Verify no duplicates between Section 1 and Section 2
            tagged_interface_ids = {iface_data['id'] for iface_data in tagged_interfaces}
            missing_tags_interface_ids = {iface_data['id'] for iface_data in missing_tags_interfaces}
            duplicates = tagged_interface_ids & missing_tags_interface_ids
            if duplicates:
                logger.warning(f"Found duplicate interfaces between Section 1 and Section 2 for device {device.name}: {duplicates}")
                # Remove duplicates from Section 2 (Section 1 takes priority)
                missing_tags_interfaces = [iface_data for iface_data in missing_tags_interfaces if iface_data['id'] not in duplicates]
            
            if tagged_interfaces:
                tagged_interfaces_by_device[device.name] = tagged_interfaces
            if missing_tags_interfaces:
                missing_tags_interfaces_by_device[device.name] = missing_tags_interfaces
        
        # Count interfaces with conflicting tags (uplink/routed)
        total_conflicting = 0
        for device_name, ifaces in missing_tags_interfaces_by_device.items():
            for iface_data in ifaces:
                if iface_data.get('has_conflicting_tags', False):
                    total_conflicting += 1
        
        # Calculate device count properly
        if device_ids:
            device_count = len(device_ids)
        else:
            try:
                device_count = devices.count() if hasattr(devices, 'count') else len(list(devices))
            except:
                device_count = 0
        
        return JsonResponse({
            'tagged_interfaces': tagged_interfaces_by_device,
            'untagged_interfaces': missing_tags_interfaces_by_device,  # Keep JSON key 'untagged_interfaces' for backward compatibility
            'device_count': device_count,
            'total_tagged': sum(len(ifaces) for ifaces in tagged_interfaces_by_device.values()),
            'total_untagged': sum(len(ifaces) for ifaces in missing_tags_interfaces_by_device.values()),
            'total_conflicting': total_conflicting,
        })


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
