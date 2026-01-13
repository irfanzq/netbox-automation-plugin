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
        # Form uses untagged_vlan (IntegerField), not a ModelChoiceField, so no queryset to set
        return render(request, self.template_name_form, {"form": form})

    def _generate_dry_run_preview(self, device, interface_list, platform, vlan_id, bond_info_map, validation_results,
                                   sync_netbox_to_device=False, untagged_vlan_id=None, tagged_vlan_ids=None, vlan=None, primary_vlan_id=None,
                                   device_lldp_data=None, device_config_data=None, device_uptime=None):
        """
        Generate dry run preview for all interfaces on a single device.
        Called by Nornir in parallel for each device.

        PERFORMANCE: This method receives pre-fetched device data from Nornir batch deployment.
        It does NOT make any device connections - all data is passed as parameters.

        Args:
            device: Device object
            interface_list: List of interface names for this device (already filtered)
            platform: Platform type ('cumulus' or 'eos')
            vlan_id: VLAN ID to deploy
            bond_info_map: Bond information map
            validation_results: Validation results from _validate_tags_for_dry_run
            sync_netbox_to_device: Whether in sync mode
            untagged_vlan_id: Untagged VLAN ID (normal mode)
            tagged_vlan_ids: Tagged VLAN IDs (normal mode)
            vlan: VLAN object (normal mode)
            primary_vlan_id: Primary VLAN ID for display
            device_lldp_data: Pre-fetched LLDP data from Nornir (dict)
            device_config_data: Pre-fetched device config from Nornir (dict or str)
            device_uptime: Pre-fetched device uptime from Nornir (str)

        Returns:
            Dictionary mapping interface names to preview results
        """
        import logging
        logger = logging.getLogger('netbox_automation_plugin')

        device_results = {}
        device_validation = validation_results['device_validation'].get(device.name, {})

        # Get device info once for all interfaces
        device_ip = str(device.primary_ip4.address).split('/')[0] if device.primary_ip4 else (str(device.primary_ip6.address).split('/')[0] if device.primary_ip6 else 'N/A')
        device_site = device.site.name if device.site else 'N/A'
        device_location = device.location.name if device.location else 'N/A'
        device_role = device.role.name if device.role else 'N/A'

        logger.info(f"[DRY RUN PREVIEW] Device {device.name}: Generating preview for {len(interface_list)} interfaces...")

        # Use pre-fetched LLDP data (passed from Nornir batch deployment)
        # No device connection needed here!
        if device_lldp_data is None:
            device_lldp_data = {}
            logger.warning(f"[DRY RUN PREVIEW] No LLDP data provided for {device.name}")
        else:
            total_neighbors = sum(len(neighbors) for neighbors in device_lldp_data.values())
            logger.info(f"[DRY RUN PREVIEW] Using pre-fetched LLDP data for {device.name}: {len(device_lldp_data)} interfaces with {total_neighbors} total neighbors")

        # Use pre-fetched device config (passed from Nornir batch deployment)
        # Parse it locally for each interface without reconnecting
        logger.info(f"[DRY RUN PREVIEW] Device {device.name}: Parsing pre-fetched config for {len(interface_list)} interfaces...")

        device_config_cache = {}
        connection_error_msg = None
        config_error_msg = None

        if device_config_data:
            # Check if this is a connection error or config error
            # device_config_data can be:
            # - dict with '_connection_error' or '_config_error' keys (error cases)
            # - list (Cumulus JSON config - successful)
            # - str (EOS config - successful)
            if isinstance(device_config_data, dict):
                if '_connection_error' in device_config_data:
                    connection_error_msg = device_config_data['_connection_error']
                    logger.error(f"[DRY RUN PREVIEW] Device {device.name}: Connection error: {connection_error_msg}")
                    # Create error entries for all interfaces
                    for actual_interface_name in interface_list:
                        device_config_cache[actual_interface_name] = {
                            'success': False,
                            'current_config': f"ERROR: Connection failed - {connection_error_msg}",
                            'source': 'error',
                            'timestamp': 'N/A',
                            'error': connection_error_msg,
                            'device_connected': False,
                            'bond_member_of': None,
                            'bond_interface_config': None
                        }
                elif '_config_error' in device_config_data:
                    config_error_msg = device_config_data['_config_error']
                    logger.error(f"[DRY RUN PREVIEW] Device {device.name}: Config collection error: {config_error_msg}")
                    # Create error entries for all interfaces
                    for actual_interface_name in interface_list:
                        device_config_cache[actual_interface_name] = {
                            'success': False,
                            'current_config': f"ERROR: Config collection failed - {config_error_msg}",
                            'source': 'error',
                            'timestamp': 'N/A',
                            'error': config_error_msg,
                            'device_connected': True,  # Device was connected, but config retrieval failed
                            'bond_member_of': None,
                            'bond_interface_config': None
                        }
                else:
                    # Valid config data dict (shouldn't happen for Cumulus/EOS, but handle gracefully)
                    logger.warning(f"[DRY RUN PREVIEW] Device {device.name}: Unexpected dict format (no error keys): {list(device_config_data.keys())[:5]}")
                    for actual_interface_name in interface_list:
                        device_config_cache[actual_interface_name] = {
                            'success': False,
                            'current_config': 'Unable to fetch',
                            'source': 'error',
                            'timestamp': 'N/A',
                            'error': 'Unexpected config data format (dict without error keys)',
                            'device_connected': False,
                            'bond_member_of': None,
                            'bond_interface_config': None
                        }
            elif isinstance(device_config_data, (list, str)):
                # Valid config data - list for Cumulus JSON, string for EOS
                # Parse the pre-fetched config for each interface
                logger.debug(f"[DRY RUN PREVIEW] Device {device.name}: Config data type: {type(device_config_data).__name__}, length: {len(device_config_data) if hasattr(device_config_data, '__len__') else 'N/A'}")
                for actual_interface_name in interface_list:
                    # Parse config locally without device connection
                    config_result = self._parse_device_config_for_interface(
                        device=device,
                        interface_name=actual_interface_name,
                        platform=platform,
                        config_data=device_config_data,
                        device_uptime=device_uptime
                    )
                    device_config_cache[actual_interface_name] = config_result
            else:
                # device_config_data is an unexpected type
                logger.warning(f"[DRY RUN PREVIEW] Device {device.name}: Unexpected config data type: {type(device_config_data)}")
                for actual_interface_name in interface_list:
                    device_config_cache[actual_interface_name] = {
                        'success': False,
                        'current_config': 'Unable to fetch',
                        'source': 'error',
                        'timestamp': 'N/A',
                        'error': f'Unexpected config data format (type: {type(device_config_data).__name__})',
                        'device_connected': False,
                        'bond_member_of': None,
                        'bond_interface_config': None
                    }
        else:
            logger.warning(f"[DRY RUN PREVIEW] No device config provided for {device.name}")
            # Create error entries for all interfaces when no data provided
            for actual_interface_name in interface_list:
                device_config_cache[actual_interface_name] = {
                    'success': False,
                    'current_config': 'Unable to fetch',
                    'source': 'error',
                    'timestamp': 'N/A',
                    'error': 'No device config data provided',
                    'device_connected': False,
                    'bond_member_of': None,
                    'bond_interface_config': None
                }

        logger.info(f"[DRY RUN PREVIEW] Device {device.name}: Config parsed, now generating previews...")

        for actual_interface_name in interface_list:
            try:
                interface_key = f"{device.name}:{actual_interface_name}"
                interface_validation = validation_results['interface_validation'].get(interface_key, {})

                # Get interface details
                interface_details = self._get_interface_details(device, actual_interface_name)

                # Get current device config from cache (already fetched above)
                device_config_result = device_config_cache.get(actual_interface_name, {})
                config_source = device_config_result.get('source', 'error')
                config_timestamp = device_config_result.get('timestamp', 'N/A')
                device_uptime = device_config_result.get('device_uptime', None)
                bridge_vlans = device_config_result.get('_bridge_vlans', [])
                bond_member_of = device_config_result.get('bond_member_of', None)

                # Determine target interface (bond if member, otherwise original)
                target_interface_for_config = bond_member_of if bond_member_of else actual_interface_name

                # ISSUE #1 FIX: Always get member interface config (not bond config)
                # Member config will be shown in "Interface: swpX" section
                # Bond config will be shown in "Bond Interface: bondX" section
                current_device_config = device_config_result.get('current_config', 'Unable to fetch')

                # Get proposed config and extract VLAN info for sync mode
                sync_mode_untagged_vlan = None
                sync_mode_tagged_vlans = []
                vlans_already_in_bridge = []
                vlans_to_add_to_bridge = []

                if not sync_netbox_to_device:
                    # Normal mode: use form VLAN (both untagged and tagged)
                    proposed_config = self._generate_vlan_config(
                        target_interface_for_config,
                        untagged_vlan=untagged_vlan_id,
                        tagged_vlans=tagged_vlan_ids,
                        platform=platform,
                        device=device,
                        bridge_vlans=bridge_vlans
                    )
                else:
                    # Sync mode: use NetBox VLANs
                    from dcim.models import Interface
                    interface_obj = Interface.objects.filter(device=device, name=actual_interface_name).first()
                    if interface_obj:
                        # IMPORTANT: Pass bond_info_map to use NetBox bond info instead of querying device
                        config_info = self._generate_config_from_netbox(device, interface_obj, platform, bond_info_map=bond_info_map)
                        proposed_config = '\n'.join(config_info.get('commands', []))
                        # Extract VLAN info from NetBox for sync mode
                        sync_mode_untagged_vlan = config_info.get('untagged_vlan')
                        sync_mode_tagged_vlans = config_info.get('tagged_vlans', [])
                        # Use target_interface from config_info (bond if member, original otherwise)
                        target_interface_for_config = config_info.get('target_interface', actual_interface_name)
                        # Extract bridge VLAN info for display
                        vlans_already_in_bridge = config_info.get('vlans_already_in_bridge', [])
                        vlans_to_add_to_bridge = config_info.get('vlans_to_add_to_bridge', [])
                        logger.debug(f"[SYNC MODE] Interface {actual_interface_name} → target: {target_interface_for_config}")

                        # DEBUG: Add debug info to proposed config for display
                        debug_info = []
                        debug_info.append(f"# DEBUG: NetBox has untagged={sync_mode_untagged_vlan}, tagged={sync_mode_tagged_vlans}")
                        debug_info.append(f"# DEBUG: Generated {len(config_info.get('commands', []))} commands: {config_info.get('commands', [])}")
                        debug_info.append(f"# DEBUG: Target interface: {target_interface_for_config}")
                        if debug_info and proposed_config:
                            proposed_config = '\n'.join(debug_info) + '\n' + proposed_config
                        elif debug_info and not proposed_config:
                            proposed_config = '\n'.join(debug_info) + '\n# No commands generated'
                    else:
                        proposed_config = ""

                # Generate config diff
                config_diff = self._generate_config_diff(current_device_config, proposed_config, platform, device=device, interface_name=target_interface_for_config, bridge_vlans=bridge_vlans)

                # Get NetBox current and proposed state (pass mode and tagged VLANs)
                # In sync mode, use VLANs from NetBox interface; in normal mode, use form input
                mode = 'sync' if sync_netbox_to_device else 'normal'
                actual_tagged_vlan_ids = sync_mode_tagged_vlans if sync_netbox_to_device else tagged_vlan_ids
                actual_primary_vlan_id = sync_mode_untagged_vlan if sync_netbox_to_device else primary_vlan_id

                netbox_state = self._get_netbox_current_state(
                    device,
                    actual_interface_name,
                    actual_primary_vlan_id,
                    mode=mode,
                    tagged_vlan_ids=actual_tagged_vlan_ids
                )

                # Get bond information for NetBox diff
                bond_info_for_netbox = None
                bond_name_for_netbox = None
                if bond_member_of:
                    bond_info_for_netbox = self._get_bond_interface_for_member(device, actual_interface_name, platform=platform)
                    bond_name_for_netbox = bond_member_of

                netbox_diff = self._generate_netbox_diff(
                    netbox_state,
                    netbox_state['proposed'],
                    bond_info=bond_info_for_netbox,
                    interface_name=actual_interface_name,
                    bond_name=bond_name_for_netbox
                )

                # Generate validation table
                validation_table = self._generate_validation_table(device_validation, interface_validation)

                # Generate risk assessment
                current_vlan = netbox_state['current']['untagged_vlan']
                risk_assessment = self._generate_risk_assessment(device_validation, interface_validation, current_vlan, primary_vlan_id)

                # Generate rollback info
                rollback_info = self._generate_rollback_info(device, actual_interface_name, primary_vlan_id, platform, timeout=90, current_config=current_device_config)

                # Determine overall status
                is_blocked = (device_validation.get('status') == 'block' or interface_validation.get('status') == 'block')
                if is_blocked:
                    overall_status = "error"
                    status_message = "Would BLOCK deployment"
                    overall_status_text = "BLOCKED"
                elif device_validation.get('status') == 'warn' or interface_validation.get('status') == 'warn':
                    overall_status = "success"
                    status_message = "Would WARN but allow deployment"
                    overall_status_text = "WARN"
                else:
                    overall_status = "success"
                    status_message = "Would PASS validation"
                    overall_status_text = "PASS"

                # Extract status text for table display
                device_status_text = "PASS" if device_validation.get('status') == 'pass' else "BLOCK"
                interface_status_text = interface_validation.get('status', 'pass').upper()
                if interface_status_text not in ['PASS', 'WARN', 'BLOCK']:
                    interface_status_text = "PASS"

                # Extract risk level
                risk_level = "LOW"
                if "HIGH" in risk_assessment or "HIGH Risk" in risk_assessment:
                    risk_level = "HIGH"
                elif "MEDIUM" in risk_assessment or "MEDIUM Risk" in risk_assessment:
                    risk_level = "MEDIUM"

                # Get VLAN info for display
                vlan_name = "N/A"
                if not sync_netbox_to_device:
                    # Normal mode
                    vlan_name = vlan.name if vlan else f"VLAN {primary_vlan_id}" if primary_vlan_id else "VLANs"
                else:
                    # Sync mode
                    from dcim.models import Interface
                    try:
                        interface_obj = Interface.objects.get(device=device, name=actual_interface_name)
                        if interface_obj.untagged_vlan:
                            vlan_name = interface_obj.untagged_vlan.name or f"VLAN {interface_obj.untagged_vlan.vid}"
                        elif interface_obj.tagged_vlans.exists():
                            first_tagged = interface_obj.tagged_vlans.first()
                            vlan_name = first_tagged.name or f"VLAN {first_tagged.vid}"
                    except Interface.DoesNotExist:
                        vlan_name = "N/A"

                # Get bond interface config if bond member
                bond_interface_config = None
                if bond_member_of:
                    bond_config_result = self._get_current_device_config(device, bond_member_of, platform)
                    bond_interface_config = bond_config_result.get('current_config', '')

                # Get LLDP neighbors for this interface from device-level collection
                lldp_neighbors = []
                lldp_neighbor_count = 0
                if device_lldp_data and actual_interface_name in device_lldp_data:
                    lldp_neighbors = device_lldp_data[actual_interface_name]
                    lldp_neighbor_count = len(lldp_neighbors)

                # Store result for this interface
                device_results[actual_interface_name] = {
                    'interface_name': actual_interface_name,
                    'target_interface': target_interface_for_config,
                    'bond_member_of': bond_member_of,
                    'bond_interface_config': bond_interface_config,
                    'current_config': current_device_config,
                    'proposed_config': proposed_config,
                    'config_diff': config_diff,
                    'netbox_state': netbox_state,
                    'netbox_diff': netbox_diff,
                    'validation_table': validation_table,
                    'risk_assessment': risk_assessment,
                    'rollback_info': rollback_info,
                    'overall_status': overall_status,
                    'status_message': status_message,
                    'overall_status_text': overall_status_text,
                    'device_status_text': device_status_text,
                    'interface_status_text': interface_status_text,
                    'risk_level': risk_level,
                    'vlan_id': primary_vlan_id,
                    'vlan_name': vlan_name,
                    'config_source': config_source,
                    'config_timestamp': config_timestamp,
                    'device_uptime': device_uptime,
                    'device_ip': device_ip,
                    'device_site': device_site,
                    'device_location': device_location,
                    'device_role': device_role,
                    'interface_details': interface_details,
                    'bridge_vlans': bridge_vlans,
                    'vlans_already_in_bridge': vlans_already_in_bridge,
                    'vlans_to_add_to_bridge': vlans_to_add_to_bridge,
                    'device_connected': device_config_result.get('device_connected', False),
                    'error_details': device_config_result.get('error', None),
                    'lldp_neighbors': lldp_neighbors,
                    'lldp_neighbor_count': lldp_neighbor_count,
                }

                logger.debug(f"[DRY RUN PREVIEW] Device {device.name}, Interface {actual_interface_name}: Preview generated successfully")

            except Exception as e:
                logger.error(f"[DRY RUN PREVIEW] Device {device.name}, Interface {actual_interface_name}: Error generating preview: {e}")
                import traceback
                logger.error(traceback.format_exc())

                # Store error result
                device_results[actual_interface_name] = {
                    'interface_name': actual_interface_name,
                    'error': str(e),
                    'overall_status': 'error',
                    'status_message': f'Preview generation failed: {str(e)}',
                }

        logger.info(f"[DRY RUN PREVIEW] Device {device.name}: Preview completed for {len(device_results)} interfaces")
        return device_results

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

    def _validate_tags_for_dry_run(self, devices, interface_list, sync_mode=False):
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
            for iface_entry in interface_list:
                # Handle both formats: "interface_name" (normal mode) and "device:interface_name" (sync mode)
                if ':' in iface_entry:
                    # Sync mode format: "device:interface"
                    entry_device_name, iface_name = iface_entry.split(':', 1)
                    # Only process if this interface belongs to current device
                    if entry_device_name != device.name:
                        continue
                    key = iface_entry  # Already in "device:interface" format
                else:
                    # Normal mode format: just "interface_name"
                    iface_name = iface_entry
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

                    # Check cable (skip in sync mode)
                    if not sync_mode and not interface.cable:
                        results['interface_validation'][key] = {
                            'status': 'block',
                            'message': f"Interface not cabled - would block deployment"
                        }
                        continue

                    # Check connected device status (skip in sync mode)
                    if not sync_mode:
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
                    # REQUIRED: Interface must be tagged as 'access' or 'tagged' to allow deployment (SKIP in sync mode)
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
                    elif sync_mode:
                        # Sync mode: Allow deployment even without vlan-mode tags
                        results['interface_validation'][key] = {
                            'status': 'pass',
                            'message': f"Sync mode - interface validation passed (tags not required)"
                        }
                    else:
                        # BLOCK: Interface must be tagged as 'access' or 'tagged' for VLAN deployment (normal mode only)
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
        Handles both integers and strings (including ranges like "3019-3099").
        Example: [10, 3000, 3001, 3002, ..., 3199] -> "10,3000-3199"
        Example: ["3000", "3019-3099"] -> "3000,3019-3099"
        """
        if not vlan_list:
            return "None"

        # Convert all VLANs to integers, handling ranges
        vlan_ids = set()
        for vlan_item in vlan_list:
            if isinstance(vlan_item, int):
                vlan_ids.add(vlan_item)
            elif isinstance(vlan_item, str):
                # Handle ranges like "3019-3099" or single VLANs like "3000"
                if '-' in vlan_item:
                    # Range format: "3019-3099"
                    try:
                        start, end = map(int, vlan_item.split('-', 1))
                        vlan_ids.update(range(start, end + 1))
                    except (ValueError, IndexError):
                        # Invalid range format, skip
                        logger.warning(f"Invalid VLAN range format: {vlan_item}")
                        continue
                else:
                    # Single VLAN: "3000"
                    try:
                        vlan_ids.add(int(vlan_item))
                    except ValueError:
                        # Invalid VLAN ID, skip
                        logger.warning(f"Invalid VLAN ID format: {vlan_item}")
                        continue
            else:
                # Try to convert to int
                try:
                    vlan_ids.add(int(vlan_item))
                except (ValueError, TypeError):
                    logger.warning(f"Invalid VLAN item type: {type(vlan_item)}, value: {vlan_item}")
                    continue

        if len(vlan_ids) == 0:
            return "None"

        # Sort the list
        sorted_vlans = sorted(vlan_ids)

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

        PERFORMANCE: Uses instance-level cache to avoid fetching the same device config multiple times
        during a single request (e.g., dry run with 32 interfaces).

        Returns:
            dict: {
                'success': bool,
                'current_config': str,  # Current config from device
                'source': 'device'|'netbox'|'error',
                'timestamp': str,  # Timestamp of config fetch
                'error': str (if failed)
            }
        """
        # PERFORMANCE FIX: Cache device config per request to avoid 32 connections for 32 interfaces
        # Initialize cache if not exists
        if not hasattr(self, '_device_config_cache'):
            self._device_config_cache = {}

        # Check cache first (cache key is device name + interface name)
        cache_key = f"{device.name}:{interface_name}"
        if cache_key in self._device_config_cache:
            logger.debug(f"[CACHE HIT] Using cached config for {cache_key}")
            return self._device_config_cache[cache_key]

        logger.debug(f"[CACHE MISS] Fetching config for {cache_key}")

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
                            result = {
                                'success': True,
                                'current_config': current_config if current_config is not None else f"(no output from device for interface {interface_name})",
                                'source': 'device',
                                'timestamp': timestamp,
                                'device_uptime': device_uptime,
                                '_bridge_vlans': bridge_vlans,  # Include bridge VLANs for checking if VLAN already exists
                                'bond_member_of': bond_member_of,  # Bond interface name if this interface is a bond member
                                'bond_interface_config': '\n'.join(bond_interface_config_commands) if bond_interface_config_commands else None  # Bond interface config commands
                            }
                            # Cache the result
                            self._device_config_cache[cache_key] = result
                            return result
                        except Exception as e2:
                            logger.warning(f"Could not get interface config for {device.name}:{interface_name}: {e2}")
                            napalm_manager.disconnect()
                            # Device was connected but config retrieval failed - not "unreachable"
                            result = {
                                'success': False,
                                'current_config': f"ERROR: Could not retrieve config from device: {str(e2)}",
                                'source': 'error',
                                'timestamp': timestamp,
                                'error': str(e2),
                                'device_connected': True,  # Device was connected, but config retrieval failed
                                'bond_member_of': None,
                                'bond_interface_config': None
                            }
                            # Cache the result (even errors, to avoid retrying)
                            self._device_config_cache[cache_key] = result
                            return result
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
                            result = {
                                'success': True,
                                'current_config': current_config,
                                'source': 'device',
                                'timestamp': timestamp,
                                'bond_member_of': None,  # EOS bond detection not implemented yet
                                'bond_interface_config': None
                            }
                            # Cache the result
                            self._device_config_cache[cache_key] = result
                            return result
                        except Exception as e2:
                            logger.warning(f"Could not get interface config for {device.name}:{interface_name}: {e2}")
                            napalm_manager.disconnect()
                            # Device was connected but config retrieval failed - not "unreachable"
                            result = {
                                'success': False,
                                'current_config': f"interface {interface_name} - ERROR: Could not retrieve config from device: {str(e2)}",
                                'source': 'error',
                                'timestamp': timestamp,
                                'error': str(e2),
                                'device_connected': True  # Device was connected, but config retrieval failed
                            }
                            # Cache the result (even errors, to avoid retrying)
                            self._device_config_cache[cache_key] = result
                            return result
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


    def _parse_device_config_for_interface(self, device, interface_name, platform, config_data, device_uptime=None):
        """
        Parse pre-fetched device config for a specific interface (NO device connection).

        This method is used in dry run preview to parse the config that was already fetched
        by Nornir batch deployment, avoiding multiple device connections.

        Args:
            device: Device object
            interface_name: Interface name to parse config for
            platform: Platform type ('cumulus' or 'eos')
            config_data: Pre-fetched device config (dict for Cumulus JSON, str for EOS)
            device_uptime: Pre-fetched device uptime (str)

        Returns:
            dict: Same structure as _get_current_device_config
                {
                    'success': bool,
                    'current_config': str,
                    'source': 'device'|'error',
                    'timestamp': str,
                    'device_uptime': str,
                    '_bridge_vlans': list,
                    'bond_member_of': str or None,
                    'bond_interface_config': str or None
                }
        """
        import logging
        logger = logging.getLogger('netbox_automation_plugin')

        from django.utils import timezone
        timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')

        # Default values
        current_config = None
        bridge_vlans = []
        bond_member_of = None
        bond_interface_config_commands = []

        try:
            if platform == 'cumulus' and config_data:
                # Parse Cumulus JSON config (same logic as _get_current_device_config)
                import json
                import re

                # config_data should be a list of dicts with 'set' key
                if isinstance(config_data, list):
                    # Extract bridge VLANs
                    try:
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
                                                if isinstance(vlan_data, dict):
                                                    for vlan_key in vlan_data.keys():
                                                        if isinstance(vlan_key, str):
                                                            # Parse VLAN string (handles "10,3000-3199", "3019-3099", etc.)
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
                        logger.debug(f"Could not parse bridge VLANs: {e}")

                    # Check if interface is a bond member
                    try:
                        for item in config_data:
                            if isinstance(item, dict) and 'set' in item:
                                set_data = item['set']
                                if isinstance(set_data, dict) and 'interface' in set_data:
                                    interface_data = set_data['interface']
                                    if isinstance(interface_data, dict):
                                        # Look for bond interfaces
                                        for iface_name, iface_config in interface_data.items():
                                            if isinstance(iface_config, dict) and 'bond' in iface_config:
                                                bond_config = iface_config['bond']
                                                if isinstance(bond_config, dict) and 'member' in bond_config:
                                                    members = bond_config['member']
                                                    if isinstance(members, dict) and interface_name in members:
                                                        bond_member_of = iface_name
                                                        logger.debug(f"Interface {interface_name} is a member of bond {bond_member_of}")
                                                        break
                                        if bond_member_of:
                                            break
                    except Exception as e:
                        logger.debug(f"Could not check bond membership: {e}")

                    # Parse interface config
                    try:
                        # Use the target interface (bond if member, otherwise original)
                        target_interface = bond_member_of if bond_member_of else interface_name

                        # Use _find_interface_config_in_json to handle ranges and bond members
                        interface_config = self._find_interface_config_in_json(config_data, interface_name)
                        
                        command_lines = []
                        if interface_config:
                            # Remove metadata keys before processing
                            if isinstance(interface_config, dict):
                                inherited_from = interface_config.pop('_inherited_from', None)
                                bond_member_of_from_config = interface_config.pop('_bond_member_of', None)
                                
                                # Convert config dict to nv commands using the proper parser
                                if interface_config:  # Only if there's actual config (not just metadata)
                                    command_lines = self._parse_json_to_nv_commands(interface_config, "", target_interface)
                                
                                # Add inheritance note if config came from range
                                if inherited_from:
                                    command_lines.insert(0, f"# Config inherited from range(s): {', '.join(inherited_from)}")
                                
                                # Restore metadata for later use
                                if inherited_from:
                                    interface_config['_inherited_from'] = inherited_from
                                if bond_member_of_from_config:
                                    interface_config['_bond_member_of'] = bond_member_of_from_config

                        if command_lines:
                            current_config = '\n'.join(command_lines)
                        else:
                            current_config = f"(no configuration found for interface {interface_name})"

                    except Exception as e:
                        logger.debug(f"Could not parse interface config: {e}")
                        current_config = f"(error parsing config: {e})"

                elif isinstance(config_data, str):
                    # Fallback: config_data is a string (shouldn't happen for Cumulus)
                    current_config = f"(config data is string, expected JSON)"

            elif platform == 'eos' and config_data:
                # Parse EOS config (string format)
                if isinstance(config_data, str):
                    # Extract interface section
                    lines = config_data.split('\n')
                    interface_lines = []
                    in_interface = False
                    for line in lines:
                        if f"interface {interface_name}" in line:
                            in_interface = True
                            interface_lines.append(line)
                        elif in_interface:
                            if line.startswith('interface '):
                                # Hit another interface, stop
                                break
                            interface_lines.append(line)

                    if interface_lines:
                        current_config = '\n'.join(interface_lines)
                    else:
                        current_config = f"(no configuration found for interface {interface_name})"
                else:
                    current_config = f"(config data is not string for EOS)"

            else:
                current_config = f"(no config data provided)"

            # Remove duplicates and sort bridge_vlans (same as _get_bridge_vlans_from_json)
            bridge_vlans = sorted(list(set(bridge_vlans))) if bridge_vlans else []
            if bridge_vlans:
                logger.debug(f"Parsed {len(bridge_vlans)} unique bridge VLAN IDs for {device.name}:{interface_name}: {bridge_vlans[:10]}{'...' if len(bridge_vlans) > 10 else ''}")

            # Return result in same format as _get_current_device_config
            return {
                'success': True if current_config and not current_config.startswith('(') else False,
                'current_config': current_config if current_config else f"(no configuration found for interface {interface_name})",
                'source': 'device',
                'timestamp': timestamp,
                'device_uptime': device_uptime,
                '_bridge_vlans': bridge_vlans,
                'bond_member_of': bond_member_of,
                'bond_interface_config': '\n'.join(bond_interface_config_commands) if bond_interface_config_commands else None
            }

        except Exception as e:
            logger.error(f"Error parsing config for {device.name}:{interface_name}: {e}")
            return {
                'success': False,
                'current_config': f"ERROR: Could not parse config: {str(e)}",
                'source': 'error',
                'timestamp': timestamp,
                'error': str(e),
                'device_uptime': device_uptime,
                '_bridge_vlans': [],
                'bond_member_of': None,
                'bond_interface_config': None
            }

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
            result = {
                'success': True,
                'current_config': config,
                'source': 'netbox',
                'timestamp': timestamp
            }
            # Cache the result
            self._device_config_cache[cache_key] = result
            return result
        except Interface.DoesNotExist:
            timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            result = {
                'success': False,
                'current_config': f"Interface {interface_name} not found in NetBox",
                'source': 'error',
                'timestamp': timestamp,
                'error': 'Interface not found'
            }
            # Cache the result
            self._device_config_cache[cache_key] = result
            return result

    def _get_netbox_current_state(self, device, interface_name, vlan_id, mode='normal', tagged_vlan_ids=None):
        """
        Get current NetBox interface state (comprehensive - VLAN-relevant only).

        Args:
            device: NetBox Device object
            interface_name: Interface name
            vlan_id: VLAN ID to deploy (for normal mode) or None (for sync mode)
            mode: 'normal' or 'sync' - determines how tagged VLANs are handled
            tagged_vlan_ids: List of tagged VLAN IDs to set (for normal mode) or None

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

            # Proposed state - depends on mode
            proposed_mode = 'tagged'  # Always set to tagged
            proposed_untagged = vlan_id if vlan_id else current_untagged

            # CRITICAL FIX: Handle tagged VLANs based on mode
            # In sync mode: preserve existing tagged VLANs from NetBox
            # In normal mode: set tagged VLANs from form input (tagged_vlan_ids)
            if mode == 'sync':
                proposed_tagged = current_tagged  # Preserve existing tagged VLANs in sync mode
            else:
                # Normal mode: use tagged VLANs from form input
                if tagged_vlan_ids:
                    proposed_tagged = list(tagged_vlan_ids) if isinstance(tagged_vlan_ids, (list, tuple)) else [tagged_vlan_ids]
                else:
                    proposed_tagged = []  # No tagged VLANs specified in form

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

                # Parse proposed config to check if we're just changing the access VLAN on the same interface
                proposed_lines = [line.strip() for line in proposed_config.split('\n') if line.strip()]
                proposed_access_vlan_configs = []
                for line in proposed_lines:
                    if line.startswith('nv set') and 'bridge domain' in line and 'access' in line:
                        proposed_access_vlan_configs.append(line)
                
                # Check if we're migrating from member interface to bond interface
                # If current config is on a different interface than proposed, show the removal
                # If current and proposed are on the same interface (just VLAN change), don't show removal
                should_show_removal = False
                if current_vlan_configs and proposed_access_vlan_configs:
                    # Extract interface names from current and proposed configs
                    current_interface = None
                    proposed_interface = None
                    
                    for current_item in current_vlan_configs:
                        # Parse: "nv set interface swp3 bridge domain br_default access 3000"
                        parts = current_item.split()
                        if len(parts) >= 3 and parts[0] == 'nv' and parts[1] == 'set' and parts[2] == 'interface':
                            current_interface = parts[3]
                            break
                    
                    for proposed_item in proposed_access_vlan_configs:
                        # Parse: "nv set interface bond3 bridge domain br_default access 3000"
                        parts = proposed_item.split()
                        if len(parts) >= 3 and parts[0] == 'nv' and parts[1] == 'set' and parts[2] == 'interface':
                            proposed_interface = parts[3]
                            break
                    
                    # Only show removal if interfaces are different (migration from member to bond)
                    # If same interface, new access VLAN command automatically replaces old one
                    if current_interface and proposed_interface and current_interface != proposed_interface:
                        should_show_removal = True
                
                # Show current VLAN configs with "-" signs (what will be removed/replaced)
                # Only show if we're migrating from member interface to bond interface
                if current_vlan_configs and should_show_removal:
                    for item in current_vlan_configs:
                        diff_lines.append(f"  - {item}")
                elif current_vlan_configs and not should_show_removal:
                    # Same interface, just VLAN change - don't show removal (new command replaces old)
                    pass
                else:
                    # No current VLAN configs to remove
                    diff_lines.append("  (no current VLAN configuration to remove)")
                diff_lines.append("")

                # Show proposed configs with "+" signs (what will be added)
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

        # BOND DETECTION: Show bond creation/migration messages
        # Check for bond_name and interface_name (bond_info can be None if NetBox doesn't have bond yet)
        if bond_name and interface_name:
            # Check if bond exists in NetBox
            bond_exists_in_netbox = False
            device_has_bond = False
            if bond_info:
                bond_exists_in_netbox = bond_info.get('netbox_bond_name') is not None
                device_has_bond = bond_info.get('device_bond_name') is not None

            # Show appropriate message based on bond status
            diff_lines.append("=" * 60)
            diff_lines.append("BOND DETECTED - VLAN MIGRATION")
            diff_lines.append("=" * 60)
            diff_lines.append("")

            if not bond_exists_in_netbox and device_has_bond:
                diff_lines.append(f"[BOND CREATION] Bond '{bond_name}' will be CREATED in NetBox")
                diff_lines.append(f"  Source: Device has bond, NetBox doesn't")
                diff_lines.append(f"  Member interface: {interface_name}")
                diff_lines.append("")
            elif bond_exists_in_netbox and not device_has_bond:
                diff_lines.append(f"[BOND EXISTS] Bond '{bond_name}' already exists in NetBox")
                diff_lines.append(f"  Device will create bond from NetBox configuration")
                diff_lines.append("")
            elif bond_exists_in_netbox and device_has_bond:
                diff_lines.append(f"[BOND EXISTS] Bond '{bond_name}' exists in both NetBox and device")
                diff_lines.append("")

            # ISSUE #3 FIX: Show VLAN migration message with NEW VLANs from form (not current VLANs)
            diff_lines.append(f"[VLAN MIGRATION] Moving VLANs from interface to bond:")
            diff_lines.append("")
            diff_lines.append(f"Member Interface '{interface_name}' (VLANs will be REMOVED):")
            old_untagged = current_state['current']['untagged_vlan'] or 'None'
            old_tagged = ', '.join(map(str, sorted(current_state['current']['tagged_vlans']))) or 'None'
            diff_lines.append(f"  Untagged VLAN: {old_untagged} → None")
            diff_lines.append(f"  Tagged VLANs: [{old_tagged}] → []")
            diff_lines.append("")
            diff_lines.append(f"Bond Interface '{bond_name}' (VLANs will be ADDED):")
            # Use proposed state (NEW VLANs from form), not current state
            new_untagged = proposed_state['untagged_vlan'] or 'None'
            new_tagged = ', '.join(map(str, sorted(proposed_state['tagged_vlans']))) if proposed_state['tagged_vlans'] else 'None'
            diff_lines.append(f"  Untagged VLAN: None → {new_untagged}")
            if new_tagged != 'None':
                diff_lines.append(f"  Tagged VLANs: [] → [{new_tagged}]")
            diff_lines.append("")
            diff_lines.append("=" * 60)
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

    def _get_interfaces_for_sync(self, devices, selected_interface_names=None, include_untagged=False):
        """
        Get interfaces from NetBox for selected devices that have VLAN configuration.
        Separates into tagged and untagged sections.

        Args:
            devices: QuerySet or list of Device objects
            selected_interface_names: Optional list of interface names selected by user.
                                     Format: ["device1:swp1", "device1:swp2", "device2:Ethernet1"]
                                     If None, returns all interfaces with VLAN config.
            include_untagged: If True, include untagged interfaces (Section 2). Default: False

        Returns:
            dict: {
                'tagged': {device_name: [Interface objects]},
                'untagged': {device_name: [Interface objects]}
            }
        """
        tagged_interfaces_by_device = {}
        untagged_interfaces_by_device = {}

        # Management interfaces to exclude
        management_interfaces = {'eth0', 'lo', 'mgmt', 'management', 'loopback', 'Loopback0'}

        for device in devices:
            device_interfaces = Interface.objects.filter(
                device=device
            ).select_related('untagged_vlan').prefetch_related('tagged_vlans', 'tags')

            tagged_interfaces = []
            untagged_interfaces = []

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
                elif include_untagged:
                    # Section 2: All interfaces with VLAN config that DON'T have vlan-mode:access/tagged
                    # No strict filtering - include all interfaces with VLAN config
                    # This includes: untagged, uplink/routed, needs-review, or any other vlan-mode tags
                    untagged_interfaces.append(iface)
                # Note: Interfaces without VLAN config are already filtered out above

            # Safety check: Verify no duplicates between Section 1 and Section 2
            tagged_interface_ids = {iface.id for iface in tagged_interfaces}
            untagged_interface_ids = {iface.id for iface in untagged_interfaces}
            duplicates = tagged_interface_ids & untagged_interface_ids
            if duplicates:
                logger.warning(f"Found duplicate interfaces between Section 1 and Section 2 for device {device.name}: {duplicates}")
                # Remove duplicates from Section 2 (Section 1 takes priority)
                untagged_interfaces = [iface for iface in untagged_interfaces if iface.id not in duplicates]

            if tagged_interfaces:
                tagged_interfaces_by_device[device.name] = tagged_interfaces
            if untagged_interfaces:
                untagged_interfaces_by_device[device.name] = untagged_interfaces

        return {
            'tagged': tagged_interfaces_by_device,
            'untagged': untagged_interfaces_by_device,
        }

    def _generate_config_from_netbox(self, device, interface, platform, bond_info_map=None):
        """
        Generate platform-specific config based on NetBox interface state.

        If interface is a bond member, applies config to bond interface instead.

        Args:
            device: Device object
            interface: Interface object from NetBox
            platform: Platform type ('cumulus' or 'eos')
            bond_info_map: Optional dict mapping device names to interface bond info
                          Format: {device_name: {interface_name: {'bond_name': str, 'bond_id': str}}}

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
        # DEBUG: Log entry to this method (using ERROR level to ensure it shows)
        logger.error(f"[DEBUG ENTRY] _generate_config_from_netbox called for {device.name}:{interface.name}")

        mode = getattr(interface, 'mode', None)
        untagged_vlan = interface.untagged_vlan.vid if interface.untagged_vlan else None
        tagged_vlans = list(interface.tagged_vlans.values_list('vid', flat=True))

        # DEBUG: Log what NetBox has for this interface (using ERROR level to ensure it shows)
        logger.error(f"[NETBOX CONFIG] {device.name}:{interface.name} - Mode: {mode}, Untagged: {untagged_vlan}, Tagged: {tagged_vlans}")

        # Check if interface is a bond member - if so, use bond interface
        # Priority: 1) NetBox lag attribute, 2) bond_info_map, 3) device config
        target_interface = interface.name
        is_bond_member = False

        # First check NetBox lag attribute
        if hasattr(interface, 'lag') and interface.lag:
            target_interface = interface.lag.name
            is_bond_member = True
            logger.debug(f"[BOND DETECTION] {interface.name} → {target_interface} (from NetBox lag)")
        # Then check bond_info_map if provided
        elif bond_info_map and device.name in bond_info_map:
            device_bonds = bond_info_map[device.name]
            if interface.name in device_bonds:
                target_interface = device_bonds[interface.name]['bond_name']
                is_bond_member = True
                logger.debug(f"[BOND DETECTION] {interface.name} → {target_interface} (from bond_info_map)")
        # Fall back to device config if NetBox doesn't have bond info and no bond_info_map
        elif not bond_info_map:
            bond_info = self._get_bond_interface_for_member(device, interface.name, platform=platform)
            if bond_info:
                target_interface = bond_info['bond_name']
                is_bond_member = True
                logger.debug(f"[BOND DETECTION] {interface.name} → {target_interface} (from device config)")

        if not is_bond_member:
            logger.debug(f"[BOND DETECTION] {interface.name} → standalone interface")

        commands = []
        bridge_vlans = []
        vlans_to_add = []
        vlans_already_in_bridge = []

        if platform == 'cumulus':
            # Cumulus: VLANs are bridge-level, access is interface-level
            # IMPORTANT: Check existing bridge VLANs from device config to avoid re-adding VLANs
            # Get current bridge VLANs from device config
            device_bridge_vlans = []
            try:
                device_config_result = self._get_current_device_config(device, target_interface, platform)
                device_bridge_vlans = device_config_result.get('_bridge_vlans', [])
                # Also try to get from JSON if available
                if not device_bridge_vlans:
                    config_data = device_config_result.get('_config_data')
                    if config_data:
                        device_bridge_vlans = self._get_bridge_vlans_from_json(config_data)
            except Exception as e:
                logger.debug(f"Could not get bridge VLANs for check: {e}")

            # 1. Add VLANs to bridge (untagged + tagged) - only add missing VLANs
            # Collect all VLANs that need to be added to bridge
            all_vlans = set()
            if untagged_vlan:
                all_vlans.add(untagged_vlan)
            all_vlans.update(tagged_vlans)

            # Track which VLANs are added vs skipped
            vlans_to_add = []
            vlans_already_in_bridge = []

            # Generate bridge VLAN commands - only for VLANs not already in bridge
            # bridge_vlans can be: list of ints, list of strings like "3019-3099" or "10,3000-3199", or mixed
            for vlan in sorted(all_vlans):
                if not self._is_vlan_in_bridge_vlans(vlan, device_bridge_vlans):
                    bridge_cmd = f"nv set bridge domain br_default vlan {vlan}"
                    commands.append(bridge_cmd)
                    vlans_to_add.append(vlan)
                    logger.debug(f"VLAN {vlan} not in bridge - will add")
                else:
                    vlans_already_in_bridge.append(vlan)
                    logger.debug(f"VLAN {vlan} already exists in bridge (range or individual) - skipping bridge VLAN command")

            bridge_vlans = sorted(all_vlans)

            # 2. Set interface VLAN configuration - use target_interface (bond if member)
            # IMPORTANT: In Cumulus NVUE, interfaces ONLY use 'access' mode
            # Tagged VLANs are ONLY configured on the bridge domain (done above)
            # There is NO 'tagged' or 'untagged' command for interfaces
            
            # CRITICAL: Validate target_interface - must be a single interface name, not comma-separated list
            # This can happen if interface.name or lag.name contains invalid data
            if ',' in target_interface:
                logger.error(f"[NETBOX CONFIG] ERROR: target_interface contains comma-separated values: '{target_interface}'")
                logger.error(f"[NETBOX CONFIG] Original interface.name: '{interface.name}', lag.name: '{interface.lag.name if hasattr(interface, 'lag') and interface.lag else None}'")
                # Take only the first part before comma
                target_interface = target_interface.split(',')[0].strip()
                logger.error(f"[NETBOX CONFIG] Using first part only: '{target_interface}'")
            
            logger.error(f"[NETBOX CONFIG] {device.name}:{interface.name} - About to check untagged_vlan: {untagged_vlan}, type: {type(untagged_vlan)}")
            if untagged_vlan:
                # Set interface to access mode with untagged VLAN
                access_cmd = f"nv set interface {target_interface} bridge domain br_default access {untagged_vlan}"
                commands.append(access_cmd)
                logger.error(f"[NETBOX CONFIG] Generated access command for {target_interface}: {access_cmd}")
                logger.error(f"[NETBOX CONFIG] Commands list now has {len(commands)} items")
            else:
                logger.error(f"[NETBOX CONFIG] No untagged VLAN for {interface.name} (target: {target_interface}) - skipping access command")

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

        result = {
            'commands': commands,
            'mode': mode or 'access',
            'untagged_vlan': untagged_vlan,
            'tagged_vlans': sorted(tagged_vlans),
            'bridge_vlans': bridge_vlans,
            'target_interface': target_interface,
            'is_bond_member': is_bond_member,
            'vlans_to_add_to_bridge': vlans_to_add if platform == 'cumulus' else [],
            'vlans_already_in_bridge': vlans_already_in_bridge if platform == 'cumulus' else [],
        }

        # DEBUG: Log the final result (using ERROR level to ensure it shows)
        logger.error(f"[NETBOX CONFIG] {device.name}:{interface.name} → Returning {len(commands)} commands: {commands}")

        return result

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

        # Determine tag based on VLAN config:
        # - If interface has BOTH tagged AND untagged VLANs → vlan-mode:tagged
        # - If interface has ONLY untagged VLAN (no tagged) → vlan-mode:access
        # - If interface has ONLY tagged VLANs (no untagged) → vlan-mode:tagged
        if has_tagged and has_untagged:
            # Both tagged and untagged VLANs → tagged mode
            tag_name = "vlan-mode:tagged"
        elif has_untagged:
            # Only untagged VLAN → access mode
            tag_name = "vlan-mode:access"
        elif has_tagged:
            # Only tagged VLANs (unusual but possible) → tagged mode
            tag_name = "vlan-mode:tagged"
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

        # Get interfaces for each device from NetBox (filtered by user selection)
        # Returns dict with 'tagged' and 'untagged' sections
        # Always include all interfaces with VLAN configs (both tagged and untagged)
        interfaces_dict = self._get_interfaces_for_sync(
            devices,
            selected_interface_names,
            include_untagged=True  # Always deploy to all interfaces with VLAN configs
        )

        tagged_interfaces_by_device = interfaces_dict['tagged']
        untagged_interfaces_by_device = interfaces_dict['untagged']

        results = []

        # Detect platform - all devices should be same platform
        platform = self._get_device_platform(devices[0]) if devices else 'cumulus'

        logger.info(f"VLAN Sync: {len(devices)} devices, platform: {platform}, dry_run: {dry_run}")

        # ========================================================================
        # DRY RUN MODE - Use Nornir batch deployment (ONE log per device)
        # ========================================================================
        if dry_run:
            logger.info(f"[SYNC DRY RUN] Using Nornir batch deployment for {len(devices)} devices")

            # Build interface list in "device:interface" format for all interfaces (tagged + untagged)
            interface_list = []
            interface_configs_map = {}  # Map of "device:interface" -> config_info

            # Build bond_info_map FIRST (before generating configs)
            # This map will contain bonds from BOTH NetBox AND device config
            bond_info_map = {}
            bonds_to_create_in_netbox = {}  # Track bonds that exist on device but not in NetBox
            bonds_to_create_on_device = {}  # Track bonds that exist in NetBox but not on device (Case 2)

            for device in devices:
                device_bond_map = {}
                device_bonds_to_create = {}
                device_bonds_to_create_on_device = {}  # Case 2: bonds in NetBox but not on device

                # Step 1: Check all interfaces for bond membership from NetBox
                all_device_interfaces = list(tagged_interfaces_by_device.get(device.name, [])) + list(untagged_interfaces_by_device.get(device.name, []))
                logger.error(f"[SYNC DRY RUN] Checking {len(all_device_interfaces)} interfaces on {device.name} for bond membership")
                for interface in all_device_interfaces:
                    # Check bond membership from NetBox
                    try:
                        if hasattr(interface, 'lag') and interface.lag:
                            device_bond_map[interface.name] = {
                                'bond_name': interface.lag.name,
                                'bond_id': str(interface.lag.id),
                                'source': 'netbox'
                            }
                            logger.error(f"[SYNC DRY RUN] {device.name}:{interface.name} - Found LAG in NetBox: {interface.lag.name}")
                        else:
                            logger.error(f"[SYNC DRY RUN] {device.name}:{interface.name} - No LAG in NetBox")
                    except Exception as e:
                        logger.error(f"[SYNC DRY RUN] Error checking bond membership for {interface.name}: {e}")

                # Step 2: Check device config for bonds that might not be in NetBox
                # Use _get_current_device_config() which is cached and returns bond_member_of directly
                logger.error(f"[SYNC DRY RUN] Step 2: Checking device config for bonds not in NetBox")
                for interface in all_device_interfaces:
                    # Skip if already found in NetBox
                    if interface.name in device_bond_map:
                        logger.error(f"[SYNC DRY RUN] {device.name}:{interface.name} - Skipping (already in device_bond_map)")
                        continue

                    # Check device config for bond membership using cached method
                    logger.error(f"[SYNC DRY RUN] {device.name}:{interface.name} - Calling _get_current_device_config()")
                    try:
                        device_config_result = self._get_current_device_config(device, interface.name, platform)
                        bond_member_of = device_config_result.get('bond_member_of', None)
                        logger.error(f"[SYNC DRY RUN] {device.name}:{interface.name} - bond_member_of from device config: {bond_member_of}")

                        if bond_member_of:
                            # Check if this bond exists in NetBox
                            from dcim.models import Interface as InterfaceModel
                            bond_exists_in_netbox = InterfaceModel.objects.filter(device=device, name=bond_member_of).exists()
                            logger.error(f"[SYNC DRY RUN] {device.name}:{interface.name} - Bond {bond_member_of} exists in NetBox: {bond_exists_in_netbox}")

                            if not bond_exists_in_netbox:
                                # Bond exists on device but not in NetBox - track it
                                device_bond_map[interface.name] = {
                                    'bond_name': bond_member_of,
                                    'bond_id': None,  # No NetBox ID yet
                                    'source': 'device'
                                }

                                # Track this bond for creation in NetBox
                                if bond_member_of not in device_bonds_to_create:
                                    device_bonds_to_create[bond_member_of] = {
                                        'members': [],
                                        'vlans_to_migrate': {}  # Map of member_name -> {untagged, tagged}
                                    }
                                device_bonds_to_create[bond_member_of]['members'].append(interface.name)

                                # Collect VLANs from this member interface for migration
                                vlans_info = {
                                    'untagged': interface.untagged_vlan.vid if interface.untagged_vlan else None,
                                    'tagged': list(interface.tagged_vlans.values_list('vid', flat=True))
                                }
                                device_bonds_to_create[bond_member_of]['vlans_to_migrate'][interface.name] = vlans_info

                                logger.error(f"[SYNC DRY RUN] Detected bond {bond_member_of} on device {device.name} (not in NetBox) - member: {interface.name}, VLANs: {vlans_info}")
                            else:
                                # Bond exists in both device and NetBox - just track it
                                device_bond_map[interface.name] = {
                                    'bond_name': bond_member_of,
                                    'bond_id': None,
                                    'source': 'device'
                                }
                                logger.error(f"[SYNC DRY RUN] {device.name}:{interface.name} - Bond {bond_member_of} exists in both device and NetBox")
                    except Exception as e:
                        logger.error(f"[SYNC DRY RUN] Error checking device config for {device.name}:{interface.name}: {e}")

                # Step 3: Check for bonds in NetBox but NOT on device (Case 2)
                # Track bonds that need to be created on the device
                device_bonds_to_create_on_device = {}  # {bond_name: {'members': [], 'bond_interface': Interface}}
                logger.error(f"[SYNC DRY RUN] Step 3: Checking for bonds in NetBox but not on device")

                # Build a map of NetBox bonds and their members
                netbox_bonds = {}  # {bond_name: [member_interfaces]}
                for interface in all_device_interfaces:
                    if hasattr(interface, 'lag') and interface.lag:
                        bond_name = interface.lag.name
                        if bond_name not in netbox_bonds:
                            netbox_bonds[bond_name] = []
                        netbox_bonds[bond_name].append(interface.name)

                # For each NetBox bond, check if it exists on the device
                for bond_name, member_names in netbox_bonds.items():
                    logger.error(f"[SYNC DRY RUN] Checking NetBox bond {bond_name} with members {member_names}")

                    # Check if ANY member of this bond has the bond configured on the device
                    bond_exists_on_device = False
                    for member_name in member_names:
                        try:
                            device_config_result = self._get_current_device_config(device, member_name, platform)
                            device_bond_name = device_config_result.get('bond_member_of', None)
                            if device_bond_name == bond_name:
                                bond_exists_on_device = True
                                logger.error(f"[SYNC DRY RUN] Bond {bond_name} exists on device (member {member_name} has bond_member_of={device_bond_name})")
                                break
                        except Exception as e:
                            logger.error(f"[SYNC DRY RUN] Error checking device config for {member_name}: {e}")

                    if not bond_exists_on_device:
                        # Bond exists in NetBox but NOT on device - need to create it on device
                        logger.error(f"[SYNC DRY RUN] Bond {bond_name} exists in NetBox but NOT on device - will create on device")

                        # Get the bond interface object from NetBox
                        from dcim.models import Interface as InterfaceModel
                        try:
                            bond_interface = InterfaceModel.objects.get(device=device, name=bond_name)
                            device_bonds_to_create_on_device[bond_name] = {
                                'members': member_names,
                                'bond_interface': bond_interface
                            }
                        except InterfaceModel.DoesNotExist:
                            logger.error(f"[SYNC DRY RUN] Bond interface {bond_name} not found in NetBox (should not happen)")

                if device_bond_map:
                    bond_info_map[device.name] = device_bond_map
                if device_bonds_to_create:
                    bonds_to_create_in_netbox[device.name] = device_bonds_to_create
                if device_bonds_to_create_on_device:
                    bonds_to_create_on_device[device.name] = device_bonds_to_create_on_device

            logger.info(f"[SYNC DRY RUN] Built bond_info_map: {bond_info_map}")
            logger.info(f"[SYNC DRY RUN] Bonds to create in NetBox: {bonds_to_create_in_netbox}")
            logger.info(f"[SYNC DRY RUN] Bonds to create on device: {bonds_to_create_on_device}")

            # Add tagged interfaces
            for device in devices:
                device_interfaces = tagged_interfaces_by_device.get(device.name, [])
                for interface in device_interfaces:
                    interface_key = f"{device.name}:{interface.name}"
                    interface_list.append(interface_key)
                    # Generate config from NetBox state - pass bond_info_map
                    config_info = self._generate_config_from_netbox(device, interface, platform, bond_info_map=bond_info_map)
                    interface_configs_map[interface_key] = {
                        'config_info': config_info,
                        'interface_obj': interface,
                        'section': 'tagged'
                    }

            # Add untagged interfaces
            for device in devices:
                device_interfaces = untagged_interfaces_by_device.get(device.name, [])
                for interface in device_interfaces:
                    interface_key = f"{device.name}:{interface.name}"
                    interface_list.append(interface_key)
                    # Generate config from NetBox state - pass bond_info_map
                    config_info = self._generate_config_from_netbox(device, interface, platform, bond_info_map=bond_info_map)
                    interface_configs_map[interface_key] = {
                        'config_info': config_info,
                        'interface_obj': interface,
                        'section': 'untagged'
                    }

            logger.info(f"[SYNC DRY RUN] Total interfaces to preview: {len(interface_list)}")

            # Run tag validation for dry run (sync mode - skip cable checks)
            validation_results = self._validate_tags_for_dry_run(devices, interface_list, sync_mode=True)

            # Create preview callback for sync mode
            def sync_preview_callback(device, device_interfaces, platform, vlan_id, bond_info_map,
                                     device_lldp_data=None, device_config_data=None, device_uptime=None):
                """
                Generate dry run preview for sync mode.
                Returns dict mapping interface names to preview results.

                PERFORMANCE: Receives pre-fetched device data from Nornir (no device connections here).
                """
                logger.info(f"[SYNC PREVIEW CALLBACK] Called for device {device.name} with {len(device_interfaces)} interfaces")
                logger.info(f"[SYNC PREVIEW CALLBACK] device_lldp_data: {type(device_lldp_data)} ({len(device_lldp_data) if device_lldp_data else 0} items)")
                logger.info(f"[SYNC PREVIEW CALLBACK] device_config_data: {type(device_config_data)} ({len(device_config_data) if device_config_data else 0} items)")
                logger.info(f"[SYNC PREVIEW CALLBACK] device_uptime: {device_uptime}")

                device_results = {}

                for actual_interface_name in device_interfaces:
                    interface_key = f"{device.name}:{actual_interface_name}"

                    # Get config info from map
                    if interface_key not in interface_configs_map:
                        device_results[actual_interface_name] = {
                            'interface_name': actual_interface_name,
                            'error': f'Interface {interface_key} not found in config map',
                            'overall_status': 'error',
                            'status_message': 'Configuration not found',
                        }
                        continue

                    config_data = interface_configs_map[interface_key]
                    config_info = config_data['config_info']
                    interface_obj = config_data['interface_obj']
                    section = config_data['section']

                    # Get VLAN IDs from config_info
                    untagged_vlan_id = config_info.get('untagged_vlan')
                    tagged_vlan_ids = config_info.get('tagged_vlans', [])
                    primary_vlan_id = untagged_vlan_id if untagged_vlan_id else (tagged_vlan_ids[0] if tagged_vlan_ids else None)

                    # Use the existing preview generation method with pre-fetched data
                    try:
                        preview_result = self._generate_dry_run_preview(
                            device=device,
                            interface_list=[actual_interface_name],
                            platform=platform,
                            vlan_id=primary_vlan_id,
                            bond_info_map=bond_info_map,
                            validation_results=validation_results,
                            sync_netbox_to_device=True,
                            untagged_vlan_id=untagged_vlan_id,
                            tagged_vlan_ids=tagged_vlan_ids,
                            vlan=None,
                            primary_vlan_id=primary_vlan_id,
                            device_lldp_data=device_lldp_data,
                            device_config_data=device_config_data,
                            device_uptime=device_uptime
                        )

                        # Extract the result for this interface
                        if actual_interface_name in preview_result:
                            device_results[actual_interface_name] = preview_result[actual_interface_name]
                        else:
                            device_results[actual_interface_name] = {
                                'interface_name': actual_interface_name,
                                'error': 'Preview generation returned no data',
                                'overall_status': 'error',
                                'status_message': 'Preview failed',
                            }
                    except Exception as e:
                        logger.error(f"[SYNC DRY RUN] Preview generation failed for {device.name}:{actual_interface_name}: {e}")
                        device_results[actual_interface_name] = {
                            'interface_name': actual_interface_name,
                            'error': str(e),
                            'overall_status': 'error',
                            'status_message': f'Preview generation failed: {str(e)}',
                        }

                return device_results

            # Use Nornir for parallel preview generation
            logger.info(f"[SYNC DRY RUN] Initializing NornirDeviceManager with {len(devices)} devices: {[d.name for d in devices]}")
            nornir_manager = NornirDeviceManager(devices=devices)
            nornir_manager.initialize()
            logger.info(f"[SYNC DRY RUN] NornirDeviceManager initialized successfully")

            # Call Nornir with dry_run=True and preview callback
            # Use a dummy VLAN ID since sync mode uses per-interface VLANs
            logger.info(f"[SYNC DRY RUN] Calling nornir_manager.deploy_vlan() with {len(interface_list)} interfaces")
            logger.info(f"[SYNC DRY RUN] First 5 interfaces: {interface_list[:5]}")
            logger.info(f"[SYNC DRY RUN] dry_run=True, preview_callback={'provided' if sync_preview_callback else 'None'}")

            nornir_results = nornir_manager.deploy_vlan(
                interface_list=interface_list,
                vlan_id=0,  # Dummy VLAN ID (not used in sync mode)
                platform=platform,
                timeout=90,
                bond_info_map=bond_info_map if bond_info_map else None,
                dry_run=True,
                preview_callback=sync_preview_callback
            )

            logger.info(f"[SYNC DRY RUN] nornir_manager.deploy_vlan() returned {len(nornir_results)} device results")

            # Process Nornir results and build final results list (ONE log per device)
            results = []
            for device in devices:
                device_results_map = nornir_results.get(device.name, {})

                if not device_results_map:
                    # No results for this device
                    results.append({
                        "device": device,  # Pass Device object for linkify to work
                        "interface": "N/A",
                        "vlan_id": "N/A",
                        "vlan_name": "N/A",
                        "status": "ERROR",
                        "netbox_updated": "Preview",
                        "message": "No preview data generated",
                        "deployment_logs": "Error: No preview data",
                        "validation_status": "",
                        "device_config_diff": "",
                        "netbox_diff": "",
                        "config_source": "error",
                        "risk_assessment": "",
                        "rollback_info": "",
                        "device_status": "ERROR",
                        "interface_status": "ERROR",
                        "overall_status": "ERROR",
                        "risk_level": "HIGH",
                    })
                    continue

                # Build ONE comprehensive log for this device covering ALL interfaces
                device_logs = []
                device_logs.append("=" * 80)
                device_logs.append(f"SYNC MODE DRY RUN - DEVICE: {device.name}")
                device_logs.append("=" * 80)
                device_logs.append("")

                # DEBUG: Show execution trace
                device_logs.append("=" * 80)
                device_logs.append("DEBUG: EXECUTION TRACE")
                device_logs.append("=" * 80)
                device_logs.append(f"1. _handle_sync_mode_deployment() was called")
                device_logs.append(f"2. Nornir manager initialized with {len(devices)} device(s)")
                device_logs.append(f"3. deploy_vlan() called with {len(interface_list)} interface(s)")
                device_logs.append(f"4. Nornir results received: {len(device_results_map)} interface(s) for this device")
                device_logs.append(f"5. Device found in results: {'YES' if device_results_map else 'NO'}")
                device_logs.append("")

                device_logs.append(f"Total Interfaces: {len(device_results_map)}")
                device_logs.append("")

                # Collect summary info and device-level data
                total_interfaces = len(device_results_map)
                blocked_count = 0
                warning_count = 0
                pass_count = 0
                error_count = 0

                # Collect device-level info from first interface (all interfaces share same device connection)
                first_interface_preview = next(iter(device_results_map.values()), {})
                config_source = first_interface_preview.get('config_source', 'device')
                config_timestamp = first_interface_preview.get('config_timestamp', 'N/A')
                device_uptime = first_interface_preview.get('device_uptime', None)
                bridge_vlans = first_interface_preview.get('bridge_vlans', [])
                device_connected = first_interface_preview.get('device_connected', False)
                error_details = first_interface_preview.get('error_details', None)

                # Show device-level pre-deployment checks ONCE at the top
                device_logs.append("=" * 80)
                device_logs.append("PRE-DEPLOYMENT CHECKS")
                device_logs.append("=" * 80)
                device_logs.append("")

                # 1. Device Connection & Uptime
                device_logs.append("1. Device Connection & Uptime:")
                if config_source == 'device':
                    device_logs.append(f"   [OK] Connected successfully")
                    if device_uptime:
                        device_logs.append(f"   Uptime: {device_uptime}")
                    if config_timestamp != 'N/A':
                        device_logs.append(f"   Config fetched: {config_timestamp}")
                elif config_source == 'netbox':
                    device_logs.append(f"   [WARN] Device unreachable - using NetBox inference")
                    device_logs.append(f"   Note: Actual device config may differ from NetBox state")
                else:
                    device_logs.append(f"   [FAIL] Config retrieval failed")
                    device_logs.append(f"   DEBUG: config_source = '{config_source}'")
                    device_logs.append(f"   DEBUG: device_connected = {device_connected}")
                    if error_details:
                        # error_details contains the actual error message (connection or config collection error)
                        if device_connected:
                            device_logs.append(f"   Config Collection Error:")
                            # Split multi-line error messages and indent each line
                            for line in str(error_details).split('\n'):
                                device_logs.append(f"      {line}")
                        else:
                            device_logs.append(f"   Connection Error:")
                            # Split multi-line error messages and indent each line
                            for line in str(error_details).split('\n'):
                                device_logs.append(f"      {line}")
                    else:
                        device_logs.append(f"   Error: Unknown error during config retrieval")
                device_logs.append("")

                device_logs.append("=" * 80)
                device_logs.append("INTERFACE DETAILS")
                device_logs.append("=" * 80)
                device_logs.append("")

                # Collect all device configs and NetBox diffs for consolidation
                all_current_configs = []
                all_proposed_configs = []
                all_netbox_diffs = []

                # DEBUG: Track config collection
                debug_config_collection = []

                # ISSUE #4 FIX: Group interfaces by validation status and VLAN
                # First pass: collect all data and group interfaces
                interface_groups = {}  # Key: (status, vlan_id, bond_status), Value: list of interface names
                interface_data_map = {}  # Store full data for each interface

                for interface_name, interface_preview in sorted(device_results_map.items()):
                    # Check for errors
                    if 'error' in interface_preview:
                        error_count += 1
                        # Show errors individually
                        if 'ERROR' not in interface_groups:
                            interface_groups['ERROR'] = []
                        interface_groups['ERROR'].append(interface_name)
                        interface_data_map[interface_name] = interface_preview
                        continue

                    # Extract preview data
                    overall_status_text = interface_preview.get('overall_status_text', 'UNKNOWN')
                    if overall_status_text == 'BLOCKED':
                        blocked_count += 1
                    elif overall_status_text == 'WARN':
                        warning_count += 1
                    elif overall_status_text == 'PASS':
                        pass_count += 1
                    else:
                        error_count += 1

                    # Extract data
                    vlan_id = interface_preview.get('vlan_id', 'N/A')
                    vlan_name = interface_preview.get('vlan_name', 'N/A')
                    target_interface = interface_preview.get('target_interface', interface_name)
                    bond_member_of = interface_preview.get('bond_member_of')
                    current_device_config = interface_preview.get('current_config', 'Unable to fetch')
                    proposed_config = interface_preview.get('proposed_config', '')
                    netbox_diff = interface_preview.get('netbox_diff', '')
                    validation_table = interface_preview.get('validation_table', '')
                    interface_details = interface_preview.get('interface_details', {})

                    # Collect configs for consolidation
                    # DEBUG: Track what's happening with config collection
                    current_config_status = f"Interface {interface_name}: current_device_config="
                    if not current_device_config:
                        current_config_status += "None/Empty"
                    elif current_device_config == 'Unable to fetch':
                        current_config_status += "'Unable to fetch'"
                    elif current_device_config.startswith('ERROR:'):
                        current_config_status += f"ERROR (first 50 chars: {current_device_config[:50]})"
                    else:
                        current_config_status += f"OK (length: {len(current_device_config)})"

                    proposed_config_status = f", proposed_config="
                    if not proposed_config:
                        proposed_config_status += "None/Empty"
                    elif proposed_config.strip():
                        proposed_config_status += f"OK (length: {len(proposed_config)})"
                    else:
                        proposed_config_status += "Whitespace only"

                    debug_config_collection.append(current_config_status + proposed_config_status)

                    if current_device_config and current_device_config != 'Unable to fetch':
                        all_current_configs.append(f"# Interface: {interface_name}")
                        all_current_configs.append(current_device_config)
                        # If bond member, also add bond config
                        if bond_member_of:
                            bond_interface_config = interface_preview.get('bond_interface_config')
                            if bond_interface_config:
                                all_current_configs.append(f"# Bond Interface: {bond_member_of} (parent of {interface_name})")
                                all_current_configs.append(bond_interface_config)
                    if proposed_config and proposed_config.strip():  # Only add if not empty
                        all_proposed_configs.append(f"# Interface: {target_interface}")
                        # Add bridge VLAN comment if available (Cumulus only)
                        vlans_already = interface_preview.get('vlans_already_in_bridge', [])
                        if platform == 'cumulus' and vlans_already:
                            vlan_list_str = ', '.join(map(str, sorted(vlans_already)))
                            all_proposed_configs.append(f"# Bridge VLANs already present: {vlan_list_str}")
                        all_proposed_configs.append(proposed_config)
                    elif not proposed_config or not proposed_config.strip():
                        # No proposed config - interface already matches NetBox or has no VLAN config
                        all_proposed_configs.append(f"# Interface: {target_interface}")
                        all_proposed_configs.append("# No changes needed - interface already matches NetBox configuration")
                    if netbox_diff:
                        all_netbox_diffs.append(f"# Interface: {interface_name}")
                        all_netbox_diffs.append(netbox_diff)

                    # Group by: status, VLAN, bond status
                    bond_status = 'bond_member' if bond_member_of else 'standalone'
                    group_key = (overall_status_text, vlan_id, bond_status)

                    if group_key not in interface_groups:
                        interface_groups[group_key] = []
                    interface_groups[group_key].append(interface_name)
                    interface_data_map[interface_name] = interface_preview

                # Second pass: Display grouped interfaces
                for group_key, interface_names in sorted(interface_groups.items()):
                    if group_key == 'ERROR':
                        # Show errors individually
                        for iface_name in interface_names:
                            device_logs.append("-" * 80)
                            device_logs.append(f"Interface: {iface_name}")
                            device_logs.append("-" * 80)
                            device_logs.append(f"[ERROR] {interface_data_map[iface_name].get('error', 'Unknown error')}")
                            device_logs.append("")
                        continue

                    status, vlan_id, bond_status = group_key
                    num_interfaces = len(interface_names)

                    device_logs.append("-" * 80)
                    if num_interfaces == 1:
                        device_logs.append(f"Interface: {interface_names[0]}")
                    else:
                        device_logs.append(f"Interfaces ({num_interfaces}): {', '.join(interface_names)}")
                    device_logs.append("-" * 80)

                    # Show common attributes for the group (use first interface as representative)
                    first_iface = interface_names[0]
                    interface_preview = interface_data_map[first_iface]
                    vlan_name = interface_preview.get('vlan_name', 'N/A')
                    target_interface = interface_preview.get('target_interface', first_iface)
                    bond_member_of = interface_preview.get('bond_member_of')
                    interface_details = interface_preview.get('interface_details', {})
                    validation_table = interface_preview.get('validation_table', '')

                    # Add interface details to device log
                    device_logs.append(f"VLAN: {vlan_id} ({vlan_name})")
                    if num_interfaces == 1:
                        device_logs.append(f"Target: {target_interface}")
                    if bond_member_of:
                        device_logs.append(f"Bond Member: {bond_member_of}")
                    device_logs.append(f"Type: {interface_details.get('type', 'Unknown')}")
                    device_logs.append(f"Cable: {'[OK] Connected' if interface_details.get('cabled') else '[WARN] Not cabled'}")
                    device_logs.append(f"Status: {status}")
                    device_logs.append("")

                    # Add validation table (show once for group)
                    if validation_table:
                        device_logs.append("Validation:")
                        device_logs.append(validation_table)
                        device_logs.append("")

                # After processing all interfaces, show NetBox configuration FIRST (source of truth)
                # Show Current NetBox Configuration (what's in NetBox now - source of truth)
                device_logs.append("=" * 80)
                device_logs.append("CURRENT NETBOX CONFIGURATION")
                device_logs.append("=" * 80)
                device_logs.append("")

                # Collect current NetBox config for all interfaces
                netbox_current_configs = []
                for interface_name in sorted(device_results_map.keys()):
                    try:
                        interface_obj = Interface.objects.get(device=device, name=interface_name)

                        # Check if interface is a bond member
                        bond_member_of = None
                        if interface_obj.lag:
                            bond_member_of = interface_obj.lag.name

                        # Get VLAN info from NetBox
                        untagged_vlan = interface_obj.untagged_vlan
                        tagged_vlans = list(interface_obj.tagged_vlans.all())

                        # Build display string
                        vlan_info = []
                        if untagged_vlan:
                            vlan_info.append(f"VLAN {untagged_vlan.vid} ({untagged_vlan.name}) [untagged]")
                        if tagged_vlans:
                            tagged_str = ', '.join([f"{v.vid} ({v.name})" for v in tagged_vlans])
                            vlan_info.append(f"VLANs {tagged_str} [tagged]")

                        if vlan_info:
                            target_display = f"{interface_name} ({bond_member_of})" if bond_member_of else interface_name
                            netbox_current_configs.append(f"# Interface: {target_display}")
                            for info in vlan_info:
                                netbox_current_configs.append(f"  {info}")
                        else:
                            netbox_current_configs.append(f"# Interface: {interface_name}")
                            netbox_current_configs.append(f"  No VLAN configured")
                    except Interface.DoesNotExist:
                        netbox_current_configs.append(f"# Interface: {interface_name}")
                        netbox_current_configs.append(f"  [ERROR] Interface not found in NetBox")
                    except Exception as e:
                        netbox_current_configs.append(f"# Interface: {interface_name}")
                        netbox_current_configs.append(f"  [ERROR] {e}")

                if netbox_current_configs:
                    for line in netbox_current_configs:
                        device_logs.append(line)
                    device_logs.append("")
                else:
                    device_logs.append("(no NetBox configuration)")
                    device_logs.append("")

                # Show consolidated NetBox changes (GROUPED)
                device_logs.append("=" * 80)
                device_logs.append("NETBOX CONFIGURATION CHANGES")
                device_logs.append("=" * 80)
                device_logs.append("")

                # Group NetBox changes by bond status and change type
                has_netbox_changes = False
                netbox_groups = {}  # Key: (bond_name or 'standalone', change_type), Value: list of changes

                # DEBUG: Show bond detection info
                device_logs.append("# DEBUG: Bond Detection Info")
                device_logs.append(f"# Device {device.name} in bonds_to_create_in_netbox: {device.name in bonds_to_create_in_netbox}")
                device_logs.append(f"# Device {device.name} in bonds_to_create_on_device: {device.name in bonds_to_create_on_device}")
                if device.name in bond_info_map:
                    device_logs.append(f"# bond_info_map for {device.name}:")
                    for iface_name, bond_data in bond_info_map[device.name].items():
                        device_logs.append(f"#   {iface_name} -> {bond_data['bond_name']} (source: {bond_data['source']})")
                else:
                    device_logs.append(f"# bond_info_map: No bonds found for {device.name}")
                if device.name in bonds_to_create_in_netbox:
                    device_logs.append(f"# bonds_to_create_in_netbox for {device.name}: {bonds_to_create_in_netbox[device.name]}")
                else:
                    device_logs.append(f"# bonds_to_create_in_netbox: No bonds to create for {device.name}")
                if device.name in bonds_to_create_on_device:
                    device_logs.append(f"# bonds_to_create_on_device for {device.name}:")
                    for bond_name, bond_data in bonds_to_create_on_device[device.name].items():
                        device_logs.append(f"#   {bond_name}: members={bond_data['members']}")
                else:
                    device_logs.append(f"# bonds_to_create_on_device: No bonds to create on device for {device.name}")

                # Show which interfaces were checked
                all_device_interfaces = list(tagged_interfaces_by_device.get(device.name, [])) + list(untagged_interfaces_by_device.get(device.name, []))
                device_logs.append(f"# Interfaces checked: {[iface.name for iface in all_device_interfaces]}")
                device_logs.append("")

                # Check if this device has bonds to create in NetBox
                if device.name in bonds_to_create_in_netbox:
                    device_bonds = bonds_to_create_in_netbox[device.name]
                    for bond_name, bond_data in device_bonds.items():
                        has_netbox_changes = True

                        # Group bond creation
                        group_key = (bond_name, 'bond_create')
                        if group_key not in netbox_groups:
                            netbox_groups[group_key] = {
                                'action': 'create',
                                'members': bond_data['members'],
                                'vlans_to_migrate': bond_data['vlans_to_migrate']
                            }

                # Parse all_netbox_diffs to extract interface changes
                if all_netbox_diffs:
                    has_netbox_changes = True
                    current_interface = None
                    for line in all_netbox_diffs:
                        if line.startswith("# Interface:"):
                            current_interface = line.replace("# Interface:", "").strip()
                        # We'll just keep the old format for sync mode since it's more complex
                        # with bond creation and migration

                # Display grouped NetBox changes
                if has_netbox_changes:
                    # Show bond creation first
                    bond_create_groups = {k: v for k, v in netbox_groups.items() if k[1] == 'bond_create'}
                    if bond_create_groups:
                        device_logs.append("Bond Interfaces (will be CREATED in NetBox):")
                        device_logs.append("")
                        for (bond_name, change_type), bond_data in sorted(bond_create_groups.items()):
                            device_logs.append(f"  {bond_name}:")
                            device_logs.append(f"    Members: {', '.join(bond_data['members'])}")
                            device_logs.append("")

                            # Show VLAN migration details grouped
                            device_logs.append("    VLAN Migration:")
                            for member_name, vlans_info in bond_data['vlans_to_migrate'].items():
                                changes = []
                                if vlans_info['untagged']:
                                    changes.append(f"Untagged VLAN {vlans_info['untagged']}")
                                if vlans_info['tagged']:
                                    tagged_str = ', '.join(map(str, vlans_info['tagged']))
                                    changes.append(f"Tagged VLANs [{tagged_str}]")

                                if changes:
                                    device_logs.append(f"      {member_name} → {bond_name}: {', '.join(changes)}")
                                device_logs.append(f"      {member_name}: Clear all VLANs")
                            device_logs.append("")

                    # Show other NetBox changes (from all_netbox_diffs)
                    if all_netbox_diffs:
                        # For sync mode, we'll keep the detailed diff format since it's more complex
                        # Just add a header to separate it
                        if bond_create_groups:
                            device_logs.append("Interface VLAN Updates:")
                            device_logs.append("")

                        for line in all_netbox_diffs:
                            device_logs.append(line)
                        device_logs.append("")
                else:
                    device_logs.append("(no NetBox changes)")
                    device_logs.append("")

                # Now show device configuration changes
                device_logs.append("=" * 80)
                device_logs.append("DEVICE CONFIGURATION CHANGES")
                device_logs.append("=" * 80)
                device_logs.append("")

                # DEBUG: Show config collection status
                device_logs.append("# DEBUG: Config Collection Status")
                device_logs.append(f"# all_current_configs: {len(all_current_configs)} items")
                device_logs.append(f"# all_proposed_configs: {len(all_proposed_configs)} items")
                for debug_line in debug_config_collection:
                    device_logs.append(f"# {debug_line}")
                device_logs.append("")

                if all_current_configs and all_proposed_configs:
                    # Use _generate_config_diff for consistent diff format (same as normal mode)
                    # This includes the smart logic to not show removals when same interface, just VLAN change
                    current_config_text = '\n'.join(all_current_configs) if all_current_configs else "(no current configuration)"
                    proposed_config_text = '\n'.join(all_proposed_configs) if all_proposed_configs else "(no proposed configuration)"
                    
                    config_diff = self._generate_config_diff(current_config_text, proposed_config_text, platform, device=device, interface_name="ALL_INTERFACES", bridge_vlans=bridge_vlans if 'bridge_vlans' in locals() else [])
                    if config_diff:
                        for line in config_diff.split('\n'):
                            if line.strip():
                                device_logs.append(line)
                    else:
                        device_logs.append("(no configuration changes)")
                    device_logs.append("")
                else:
                    device_logs.append("(no device configuration changes)")
                    device_logs.append("")

                # ISSUE #5 FIX: Add interface-level pre-deployment checks before summary
                device_logs.append("=" * 80)
                device_logs.append("INTERFACE-LEVEL PRE-DEPLOYMENT CHECKS")
                device_logs.append("=" * 80)
                device_logs.append("")

                # Build map of interfaces to check (deduplicate bonds)
                interfaces_to_check = {}  # {target_interface: (physical_interface, bond_name_or_none)}
                for interface_name, interface_preview in device_results_map.items():
                    if 'error' in interface_preview:
                        continue
                    bond_member_of = interface_preview.get('bond_member_of')
                    target_interface = bond_member_of if bond_member_of else interface_name

                    # Store first occurrence (for LLDP checks on physical interface)
                    if target_interface not in interfaces_to_check:
                        interfaces_to_check[target_interface] = (interface_name, bond_member_of)

                # 1. LLDP Neighbor Data Collection (baseline for post-deployment verification)
                device_logs.append("1. LLDP Neighbor Data Collection (Baseline):")
                lldp_collected_count = 0
                lldp_no_data_count = 0

                for target_interface, (physical_interface, bond_name) in sorted(interfaces_to_check.items()):
                    interface_preview = device_results_map.get(physical_interface, {})

                    # Get actual LLDP neighbors from device (collected in Nornir batch deployment)
                    lldp_neighbors = interface_preview.get('lldp_neighbors', [])

                    if lldp_neighbors:
                        # We have LLDP data - just show what we collected
                        actual_hostnames = [n.get('hostname', '') for n in lldp_neighbors]
                        device_logs.append(f"   Interface {physical_interface} → {', '.join(actual_hostnames)}")
                        lldp_collected_count += 1
                    else:
                        # No LLDP data collected
                        device_logs.append(f"   Interface {physical_interface} → No LLDP data")
                        lldp_no_data_count += 1

                if lldp_collected_count == 0 and lldp_no_data_count == 0:
                    device_logs.append("   No interfaces to check")
                device_logs.append("")

                # 2. Interface State (collected in Nornir batch deployment baseline)
                device_logs.append("2. Interface State:")
                device_logs.append("   [INFO] Interface state will be collected during deployment baseline")
                device_logs.append("")

                # 3. Traffic Analysis (collected in Nornir batch deployment baseline)
                device_logs.append("3. Traffic Analysis:")
                device_logs.append("   [INFO] Traffic stats will be collected during deployment baseline")
                device_logs.append("")

                # Add summary at the end
                device_logs.append("=" * 80)
                device_logs.append("DEVICE SUMMARY")
                device_logs.append("=" * 80)
                device_logs.append(f"Total Interfaces: {total_interfaces}")
                device_logs.append(f"  PASS: {pass_count}")
                device_logs.append(f"  WARN: {warning_count}")
                device_logs.append(f"  BLOCKED: {blocked_count}")
                device_logs.append(f"  ERROR: {error_count}")
                device_logs.append("")

                # Determine overall device status
                if blocked_count > 0 or error_count > 0:
                    overall_device_status = "ERROR"
                    overall_device_status_text = "BLOCKED" if blocked_count > 0 else "ERROR"
                elif warning_count > 0:
                    overall_device_status = "WARNING"
                    overall_device_status_text = "WARN"
                else:
                    overall_device_status = "SUCCESS"
                    overall_device_status_text = "PASS"

                # Create ONE result entry for this device
                results.append({
                    "device": device,  # Pass Device object for linkify to work
                    "interface": f"{total_interfaces} interfaces",
                    "vlan_id": "Multiple VLANs",
                    "vlan_name": "Sync Mode",
                    "status": overall_device_status,
                    "netbox_updated": "Preview",
                    "message": f"{pass_count} PASS, {warning_count} WARN, {blocked_count} BLOCKED, {error_count} ERROR",
                    "deployment_logs": '\n'.join(device_logs),
                    "validation_status": "",
                    "device_config_diff": "",
                    "netbox_diff": "",
                    "config_source": "batch",
                    "risk_assessment": "",
                    "rollback_info": "",
                    "device_status": overall_device_status_text,
                    "interface_status": overall_device_status_text,
                    "overall_status": overall_device_status_text,
                    "risk_level": "HIGH" if blocked_count > 0 else ("MEDIUM" if warning_count > 0 else "LOW"),
                })

            logger.info(f"[SYNC DRY RUN] Generated {len(results)} device-level results")
            return results

        # ========================================================================
        # DEPLOYMENT MODE - Use Nornir batch deployment (parallel)
        # ========================================================================

        logger.info(f"[SYNC DEPLOYMENT] Starting Nornir batch deployment for {len(devices)} devices")

        # Build interface list in "device:interface" format for Nornir
        interface_list = []
        for device in devices:
            tagged_ifaces = tagged_interfaces_by_device.get(device.name, [])
            untagged_ifaces = untagged_interfaces_by_device.get(device.name, [])
            all_ifaces = list(tagged_ifaces) + list(untagged_ifaces)

            for interface in all_ifaces:
                interface_list.append(f"{device.name}:{interface.name}")

        logger.info(f"[SYNC DEPLOYMENT] Built interface list: {len(interface_list)} interfaces across {len(devices)} devices")

        # Build bond_info_map FIRST (before deployment) - same as dry run
        # This map will contain bonds from BOTH NetBox AND device config
        bond_info_map = {}
        bonds_to_create_in_netbox = {}  # Track bonds that exist on device but not in NetBox
        bonds_to_create_on_device = {}  # Track bonds that exist in NetBox but not on device (Case 2)

        for device in devices:
            device_bond_map = {}
            device_bonds_to_create = {}
            device_bonds_to_create_on_device = {}  # Case 2: bonds in NetBox but not on device

            # Step 1: Check all interfaces for bond membership from NetBox
            all_device_interfaces = list(tagged_interfaces_by_device.get(device.name, [])) + list(untagged_interfaces_by_device.get(device.name, []))
            for interface in all_device_interfaces:
                # Check bond membership from NetBox
                try:
                    if hasattr(interface, 'lag') and interface.lag:
                        device_bond_map[interface.name] = {
                            'bond_name': interface.lag.name,
                            'bond_id': str(interface.lag.id),
                            'source': 'netbox'
                        }
                except Exception as e:
                    logger.debug(f"Error checking bond membership for {interface.name}: {e}")

            # Step 2: Check device config for bonds that might not be in NetBox
            # Use _get_current_device_config() which is cached and returns bond_member_of directly
            # This matches the dry run logic for consistency
            logger.info(f"[SYNC DEPLOYMENT] Step 2: Checking device config for bonds not in NetBox")
            for interface in all_device_interfaces:
                # Skip if already found in NetBox
                if interface.name in device_bond_map:
                    logger.debug(f"[SYNC DEPLOYMENT] {device.name}:{interface.name} - Skipping (already in device_bond_map)")
                    continue

                # Check device config for bond membership using cached method (same as dry run)
                logger.debug(f"[SYNC DEPLOYMENT] {device.name}:{interface.name} - Calling _get_current_device_config()")
                try:
                    device_config_result = self._get_current_device_config(device, interface.name, platform)
                    bond_member_of = device_config_result.get('bond_member_of', None)
                    logger.info(f"[SYNC DEPLOYMENT] {device.name}:{interface.name} - bond_member_of from device config: {bond_member_of}")

                    if bond_member_of:
                        # Check if this bond exists in NetBox
                        from dcim.models import Interface as InterfaceModel
                        bond_exists_in_netbox = InterfaceModel.objects.filter(device=device, name=bond_member_of).exists()
                        logger.info(f"[SYNC DEPLOYMENT] {device.name}:{interface.name} - Bond {bond_member_of} exists in NetBox: {bond_exists_in_netbox}")

                        if not bond_exists_in_netbox:
                            # Bond exists on device but not in NetBox - track it
                            device_bond_map[interface.name] = {
                                'bond_name': bond_member_of,
                                'bond_id': None,  # No NetBox ID yet
                                'source': 'device'
                            }

                            # Track this bond for creation in NetBox
                            if bond_member_of not in device_bonds_to_create:
                                device_bonds_to_create[bond_member_of] = {
                                    'members': [],
                                    'vlans_to_migrate': {}  # Map of member_name -> {untagged, tagged}
                                }
                            device_bonds_to_create[bond_member_of]['members'].append(interface.name)

                            # Collect VLANs from this member interface for migration
                            vlans_info = {
                                'untagged': interface.untagged_vlan.vid if interface.untagged_vlan else None,
                                'tagged': list(interface.tagged_vlans.values_list('vid', flat=True))
                            }
                            device_bonds_to_create[bond_member_of]['vlans_to_migrate'][interface.name] = vlans_info

                            logger.info(f"[SYNC DEPLOYMENT] Detected bond {bond_member_of} on device {device.name} (not in NetBox) - member: {interface.name}, VLANs: {vlans_info}")
                        else:
                            # Bond exists in both device and NetBox - just track it
                            device_bond_map[interface.name] = {
                                'bond_name': bond_member_of,
                                'bond_id': None,
                                'source': 'device'
                            }
                            logger.info(f"[SYNC DEPLOYMENT] {device.name}:{interface.name} - Bond {bond_member_of} exists in both device and NetBox")
                except Exception as e:
                    logger.error(f"[SYNC DEPLOYMENT] Error checking device config for {device.name}:{interface.name}: {e}")

                    # Track this bond for creation in NetBox
                    if bond_name not in device_bonds_to_create:
                        device_bonds_to_create[bond_name] = {
                            'members': [],
                            'vlans_to_migrate': {}  # Map of member_name -> {untagged, tagged}
                        }
                    device_bonds_to_create[bond_name]['members'].append(interface.name)

                    # Collect VLANs from this member interface for migration
                    vlans_info = {
                        'untagged': interface.untagged_vlan.vid if interface.untagged_vlan else None,
                        'tagged': list(interface.tagged_vlans.values_list('vid', flat=True))
                    }
                    device_bonds_to_create[bond_name]['vlans_to_migrate'][interface.name] = vlans_info

                    logger.info(f"[SYNC DEPLOYMENT] Detected bond {bond_name} on device {device.name} (not in NetBox) - member: {interface.name}, VLANs: {vlans_info}")

            # Step 3: Check for bonds in NetBox but NOT on device (Case 2)
            netbox_bonds = {}  # {bond_name: [member_interfaces]}
            for interface in all_device_interfaces:
                if hasattr(interface, 'lag') and interface.lag:
                    bond_name = interface.lag.name
                    if bond_name not in netbox_bonds:
                        netbox_bonds[bond_name] = []
                    netbox_bonds[bond_name].append(interface.name)

            # For each NetBox bond, check if it exists on the device
            for bond_name, member_names in netbox_bonds.items():
                bond_exists_on_device = False
                for member_name in member_names:
                    try:
                        device_config_result = self._get_current_device_config(device, member_name, platform)
                        device_bond_name = device_config_result.get('bond_member_of', None)
                        if device_bond_name == bond_name:
                            bond_exists_on_device = True
                            break
                    except Exception as e:
                        logger.debug(f"Error checking device config for {member_name}: {e}")

                if not bond_exists_on_device:
                    # Bond exists in NetBox but NOT on device - need to create it on device
                    logger.info(f"[SYNC DEPLOYMENT] Bond {bond_name} exists in NetBox but NOT on device - will create on device")

                    from dcim.models import Interface as InterfaceModel
                    try:
                        bond_interface = InterfaceModel.objects.get(device=device, name=bond_name)
                        device_bonds_to_create_on_device[bond_name] = {
                            'members': member_names,
                            'bond_interface': bond_interface
                        }
                    except InterfaceModel.DoesNotExist:
                        logger.error(f"Bond interface {bond_name} not found in NetBox")

            if device_bond_map:
                bond_info_map[device.name] = device_bond_map
            if device_bonds_to_create:
                bonds_to_create_in_netbox[device.name] = device_bonds_to_create
            if device_bonds_to_create_on_device:
                bonds_to_create_on_device[device.name] = device_bonds_to_create_on_device

        logger.info(f"[SYNC DEPLOYMENT] Built bond_info_map: {bond_info_map}")
        logger.info(f"[SYNC DEPLOYMENT] Bonds to create in NetBox: {bonds_to_create_in_netbox}")
        logger.info(f"[SYNC DEPLOYMENT] Bonds to create on device: {bonds_to_create_on_device}")

        # Create bonds on device FIRST (Case 2: bonds in NetBox but not on device)
        # This must be done BEFORE VLAN deployment so the bond interfaces exist
        for device in devices:
            if device.name in bonds_to_create_on_device:
                logger.info(f"[SYNC DEPLOYMENT] Creating bonds on device {device.name} (bonds exist in NetBox but not on device)")

                from netbox_automation_plugin.core.napalm_integration import NAPALMDeviceManager
                napalm_manager = NAPALMDeviceManager(device)

                if napalm_manager.connect():
                    try:
                        connection = napalm_manager.connection

                        for bond_name, bond_data in bonds_to_create_on_device[device.name].items():
                            members = bond_data['members']
                            bond_interface = bond_data['bond_interface']

                            logger.info(f"[SYNC DEPLOYMENT] Creating bond {bond_name} on device {device.name} with members {members}")

                            # Generate bond creation commands
                            bond_commands = []
                            bond_commands.append(f"nv set interface {bond_name} type bond")

                            # Add all members
                            for member in members:
                                bond_commands.append(f"nv set interface {bond_name} bond member {member}")

                            # LACP settings
                            bond_commands.append(f"nv set interface {bond_name} bond lacp-rate fast")
                            bond_commands.append(f"nv set interface {bond_name} bond lacp-bypass on")

                            # Add bond to bridge domain
                            bond_commands.append(f"nv set interface {bond_name} bridge domain br_default")

                            # Apply bond creation commands
                            logger.info(f"[SYNC DEPLOYMENT] Applying bond creation commands for {bond_name}: {bond_commands}")

                            if hasattr(connection, 'cli'):
                                # Execute commands one by one
                                for cmd in bond_commands:
                                    try:
                                        connection.cli([cmd])
                                        logger.info(f"[SYNC DEPLOYMENT] Executed: {cmd}")
                                    except Exception as e:
                                        logger.error(f"[SYNC DEPLOYMENT] Failed to execute '{cmd}': {e}")

                                # Apply configuration
                                try:
                                    connection.cli(['nv config apply'])
                                    logger.info(f"[SYNC DEPLOYMENT] Bond {bond_name} created on device {device.name}")
                                except Exception as e:
                                    logger.error(f"[SYNC DEPLOYMENT] Failed to apply bond config for {bond_name}: {e}")

                    except Exception as e:
                        logger.error(f"[SYNC DEPLOYMENT] Error creating bonds on device {device.name}: {e}")
                    finally:
                        napalm_manager.disconnect()
                else:
                    logger.error(f"[SYNC DEPLOYMENT] Failed to connect to device {device.name} for bond creation")

        # Initialize Nornir and deploy using batch deployment
        nornir_manager = NornirDeviceManager(devices=devices)
        nornir_manager.initialize()

        # Build interface_vlan_map for sync mode (maps "device:interface" -> config info)
        interface_vlan_map = {}
        for device in devices:
            device_interfaces = list(tagged_interfaces_by_device.get(device.name, [])) + list(untagged_interfaces_by_device.get(device.name, []))
            for interface in device_interfaces:
                interface_key = f"{device.name}:{interface.name}"
                # Generate config from NetBox state
                config_info = self._generate_config_from_netbox(device, interface, platform, bond_info_map=bond_info_map)
                interface_vlan_map[interface_key] = {
                    'untagged_vlan': config_info.get('untagged_vlan'),
                    'tagged_vlans': config_info.get('tagged_vlans', []),
                    'commands': config_info.get('commands', []),
                    'target_interface': config_info.get('target_interface', interface.name)
                }
                logger.debug(f"[SYNC DEPLOYMENT] Built config for {interface_key}: {len(config_info.get('commands', []))} commands")

        logger.info(f"[SYNC DEPLOYMENT] Deploying to {len(interface_list)} interfaces across {len(devices)} devices in parallel")
        nornir_results = nornir_manager.deploy_vlan(
            interface_list=interface_list,
            vlan_id=0,  # Dummy VLAN ID (ignored when interface_vlan_map is provided)
            platform=platform,
            timeout=90,
            bond_info_map=bond_info_map if bond_info_map else None,
            bonds_to_create_on_device=bonds_to_create_on_device if bonds_to_create_on_device else None,
            dry_run=False,
            interface_vlan_map=interface_vlan_map if interface_vlan_map else None
        )

        logger.info(f"[SYNC DEPLOYMENT] Nornir deployment completed for {len(nornir_results)} devices")

        # Build device_configs map for result processing (needed by the result processing code below)
        device_configs = {}
        for device in devices:
            device_interfaces = list(tagged_interfaces_by_device.get(device.name, [])) + list(untagged_interfaces_by_device.get(device.name, []))
            if device.name not in device_configs:
                device_configs[device.name] = {}

            for interface in device_interfaces:
                # Generate config info from NetBox state
                config_info = self._generate_config_from_netbox(device, interface, platform, bond_info_map=bond_info_map)
                device_configs[device.name][interface.name] = config_info

        logger.info(f"[SYNC DEPLOYMENT] Built device_configs map for {sum(len(ifaces) for ifaces in device_configs.values())} interfaces")

        # Process deployment results and build consolidated device-level logs (matching dry run format)
        results = []
        interfaces_to_auto_tag = []  # Track interfaces that need auto-tagging

        # Create bonds in NetBox if needed (AFTER deployment, only if deployment succeeded)
        # This handles the case where bonds were detected on device but not in NetBox
        # We deploy configs to bonds on device, then sync the bond structure to NetBox
        for device in devices:
            if device.name in bonds_to_create_in_netbox:
                # Check if deployment was successful for this device
                device_results = nornir_results.get(device.name, {})
                deployment_succeeded = False
                
                if device_results:
                    # Check if at least one interface deployment succeeded
                    for interface_name, interface_result in device_results.items():
                        if interface_result.get('success', False):
                            deployment_succeeded = True
                            break
                
                if deployment_succeeded:
                    device_bonds = bonds_to_create_in_netbox[device.name]
                    for bond_name, bond_data in device_bonds.items():
                        logger.info(f"[SYNC DEPLOYMENT] Creating bond {bond_name} in NetBox for device {device.name} (deployment succeeded)")
                        logger.info(f"[SYNC DEPLOYMENT] Bond members: {', '.join(bond_data['members'])}")
                        logger.info(f"[SYNC DEPLOYMENT] Migrating VLANs from member interfaces to bond")
                        sync_result = self._sync_bond_to_netbox(
                            device=device,
                            bond_name=bond_name,
                            member_interfaces=bond_data['members'],
                            platform=platform,
                            migrate_vlans=True  # Migrate all VLANs from member interfaces to bond
                        )
                        if sync_result.get('success'):
                            logger.info(f"[SYNC DEPLOYMENT] Bond {bond_name} created in NetBox successfully")
                            logger.info(f"[SYNC DEPLOYMENT]   - Members added: {sync_result.get('members_added', 0)}")
                            logger.info(f"[SYNC DEPLOYMENT]   - VLANs migrated: {sync_result.get('vlans_migrated', 0)}")
                            logger.info(f"[SYNC DEPLOYMENT]   - Members cleared: {sync_result.get('members_cleared', 0)}")
                        else:
                            logger.error(f"[SYNC DEPLOYMENT] Failed to create bond {bond_name} in NetBox: {sync_result.get('error')}")
                else:
                    logger.warning(f"[SYNC DEPLOYMENT] Skipping bond creation in NetBox for device {device.name} - deployment did not succeed")
                    device_bonds = bonds_to_create_in_netbox[device.name]
                    for bond_name in device_bonds.keys():
                        logger.warning(f"[SYNC DEPLOYMENT]   - Bond {bond_name} will not be created in NetBox until deployment succeeds")

        for device in devices:
            device_results = nornir_results.get(device.name, {})

            if not device_results:
                # No results for this device - add error entry
                results.append({
                    "device": device,
                    "interface": "N/A",
                    "vlan_id": "N/A",
                    "vlan_name": "N/A",
                    "status": "ERROR",
                    "netbox_updated": "No",
                    "message": "No deployment results",
                    "deployment_logs": "Error: No deployment data",
                    "dry_run": False,
                })
                continue

            # Get all interfaces for this device from device_configs
            device_interfaces_map = device_configs.get(device.name, {})
            device_interface_names = list(device_interfaces_map.keys())

            if not device_interface_names:
                continue

            # Build ONE comprehensive log for this device covering ALL interfaces
            device_logs = []
            device_logs.append("=" * 80)
            device_logs.append(f"SYNC MODE DEPLOYMENT - DEVICE: {device.name}")
            device_logs.append("=" * 80)
            device_logs.append("")
            device_logs.append(f"Total Interfaces: {len(device_interface_names)}")
            device_logs.append("")

            # Get device-level info from first interface result
            first_interface_result = device_results.get(device_interface_names[0], {})
            deployment_logs_from_napalm = first_interface_result.get('logs', [])

            # Show Current NetBox Configuration FIRST (source of truth)
            device_logs.append("=" * 80)
            device_logs.append("CURRENT NETBOX CONFIGURATION")
            device_logs.append("=" * 80)
            device_logs.append("")

            # Collect current NetBox config for all interfaces
            netbox_current_configs = []
            for interface_name in device_interface_names:
                try:
                    interface_obj = Interface.objects.get(device=device, name=interface_name)

                    # Check if interface is a bond member
                    bond_member_of = None
                    if interface_obj.lag:
                        bond_member_of = interface_obj.lag.name

                    # Get VLAN info from NetBox
                    untagged_vlan = interface_obj.untagged_vlan
                    tagged_vlans = list(interface_obj.tagged_vlans.all())

                    # Build display string
                    vlan_info = []
                    if untagged_vlan:
                        vlan_info.append(f"VLAN {untagged_vlan.vid} ({untagged_vlan.name}) [untagged]")
                    if tagged_vlans:
                        tagged_str = ', '.join([f"{v.vid} ({v.name})" for v in tagged_vlans])
                        vlan_info.append(f"VLANs {tagged_str} [tagged]")

                    if vlan_info:
                        target_display = f"{interface_name} ({bond_member_of})" if bond_member_of else interface_name
                        netbox_current_configs.append(f"# Interface: {target_display}")
                        for info in vlan_info:
                            netbox_current_configs.append(f"  {info}")
                    else:
                        netbox_current_configs.append(f"# Interface: {interface_name}")
                        netbox_current_configs.append(f"  No VLAN configured")
                except Interface.DoesNotExist:
                    netbox_current_configs.append(f"# Interface: {interface_name}")
                    netbox_current_configs.append(f"  [ERROR] Interface not found in NetBox")
                except Exception as e:
                    netbox_current_configs.append(f"# Interface: {interface_name}")
                    netbox_current_configs.append(f"  [ERROR] {e}")

            if netbox_current_configs:
                for line in netbox_current_configs:
                    device_logs.append(line)
                device_logs.append("")
            else:
                device_logs.append("(no NetBox configuration)")
                device_logs.append("")

            # Show device-level pre-deployment checks from Nornir baseline
            device_logs.append("=" * 80)
            device_logs.append("PRE-DEPLOYMENT CHECKS (from Nornir baseline)")
            device_logs.append("=" * 80)
            device_logs.append("")

            # Get baseline data from Nornir deployment results
            # Try to get from first interface, but also check other interfaces if first one doesn't have baseline
            baseline_data = first_interface_result.get('baseline', {})
            
            # If baseline is empty, try to find it in other interface results
            if not baseline_data or (not baseline_data.get('uptime') and not baseline_data.get('interfaces')):
                for interface_name in device_interface_names[1:]:  # Skip first one, already checked
                    interface_result = device_results.get(interface_name, {})
                    candidate_baseline = interface_result.get('baseline', {})
                    if candidate_baseline and (candidate_baseline.get('uptime') or candidate_baseline.get('interfaces')):
                        baseline_data = candidate_baseline
                        logger.debug(f"Found baseline data in interface {interface_name} result")
                        break

            # 1. Device Connection & Uptime (from baseline)
            device_logs.append("1. Device Connection & Uptime:")
            uptime_data = baseline_data.get('uptime')
            if uptime_data and uptime_data != -1:
                device_logs.append(f"   [OK] Connected successfully")
                # Format uptime nicely
                uptime_seconds = int(uptime_data) if uptime_data else 0
                uptime_days = uptime_seconds // 86400
                uptime_hours = (uptime_seconds % 86400) // 3600
                uptime_mins = (uptime_seconds % 3600) // 60
                if uptime_days > 0:
                    uptime_str = f"{uptime_days}d {uptime_hours}h {uptime_mins}m ({uptime_seconds}s)"
                elif uptime_hours > 0:
                    uptime_str = f"{uptime_hours}h {uptime_mins}m ({uptime_seconds}s)"
                else:
                    uptime_str = f"{uptime_mins}m ({uptime_seconds}s)"
                device_logs.append(f"   Uptime: {uptime_str}")
            else:
                device_logs.append(f"   [INFO] Uptime data not available")
            device_logs.append("")

            # 2. Interface State (from baseline)
            # Handle both baseline['interface'] (single) and baseline['interfaces'] (multiple)
            device_logs.append("2. Interface State:")
            interface_baseline = baseline_data.get('interface', {})
            if not interface_baseline and 'interfaces' in baseline_data and baseline_data['interfaces']:
                # Use first successful interface from baseline['interfaces'] (skip ones with errors)
                for iface_name, iface_data in baseline_data['interfaces'].items():
                    if 'error' not in iface_data:
                        interface_baseline = iface_data
                        logger.debug(f"Using baseline data from interface {iface_name}")
                        break
                # If all have errors, use first one anyway for display
                if not interface_baseline and baseline_data['interfaces']:
                    first_iface_name = next(iter(baseline_data['interfaces']))
                    interface_baseline = baseline_data['interfaces'][first_iface_name]
            
            if interface_baseline and 'error' not in interface_baseline:
                is_up = interface_baseline.get('is_up', False)
                is_enabled = interface_baseline.get('is_enabled', False)
                status = "UP" if is_up else "DOWN"
                admin_status = "Enabled" if is_enabled else "Disabled"
                device_logs.append(f"   Status: {status} (Admin: {admin_status})")
            else:
                device_logs.append(f"   [INFO] Interface state data not available")
            device_logs.append("")

            # 3. Traffic Statistics (from baseline)
            device_logs.append("3. Traffic Statistics:")
            if interface_baseline and 'error' not in interface_baseline:
                in_pkts = interface_baseline.get('in_pkts', 0)
                out_pkts = interface_baseline.get('out_pkts', 0)
                in_bytes = interface_baseline.get('in_bytes', 0)
                out_bytes = interface_baseline.get('out_bytes', 0)
                if in_pkts or out_pkts or in_bytes or out_bytes:
                    device_logs.append(f"   RX: {in_pkts:,} pkts ({in_bytes:,} bytes)")
                    device_logs.append(f"   TX: {out_pkts:,} pkts ({out_bytes:,} bytes)")
                else:
                    device_logs.append(f"   [INFO] No traffic detected (all counters are 0)")
            else:
                device_logs.append(f"   [INFO] Traffic statistics not available")
            device_logs.append("")

            device_logs.append("=" * 80)
            device_logs.append("DEPLOYMENT EXECUTION")
            device_logs.append("=" * 80)
            device_logs.append("")

            # Add NAPALM deployment logs (from first interface - they're the same for all)
            if deployment_logs_from_napalm:
                if isinstance(deployment_logs_from_napalm, list):
                    device_logs.extend(deployment_logs_from_napalm)
                else:
                    device_logs.append(str(deployment_logs_from_napalm))
            device_logs.append("")

            # Get LLDP baseline from deployment results (collected during deployment)
            # Show per-interface LLDP for deployed interfaces (not device-level)
            device_logs.append("4. LLDP Neighbors (Interface-Level Baseline):")
            baseline_data = first_interface_result.get('baseline', {})
            
            # Try to get per-interface LLDP data (new format)
            lldp_interfaces = baseline_data.get('lldp_interfaces', {})
            if lldp_interfaces:
                # Show per-interface LLDP for deployed interfaces
                for iface_name in sorted(lldp_interfaces.keys()):
                    iface_lldp = lldp_interfaces[iface_name]
                    neighbor_count = iface_lldp.get('count', 0)
                    neighbors = iface_lldp.get('neighbors', [])
                    
                    if neighbor_count > 0:
                        # Show neighbor hostnames if available
                        neighbor_hostnames = []
                        for neighbor in neighbors:
                            hostname = neighbor.get('hostname', '') or neighbor.get('remote_system_name', '')
                            if hostname:
                                neighbor_hostnames.append(hostname)
                        
                        if neighbor_hostnames:
                            device_logs.append(f"   {iface_name}: {neighbor_count} neighbor(s) → {', '.join(neighbor_hostnames)}")
                        else:
                            device_logs.append(f"   {iface_name}: {neighbor_count} neighbor(s)")
                    else:
                        device_logs.append(f"   {iface_name}: No LLDP neighbors")
            else:
                # Fallback to old format (device-level)
                lldp_all_interfaces = baseline_data.get('lldp_all_interfaces', {})
                if lldp_all_interfaces:
                    # Filter to only show interfaces we're deploying
                    for iface_name in sorted(device_interface_names):
                        if iface_name in lldp_all_interfaces:
                            neighbor_count = lldp_all_interfaces[iface_name]
                            if neighbor_count > 0:
                                device_logs.append(f"   {iface_name}: {neighbor_count} neighbor(s)")
                            else:
                                device_logs.append(f"   {iface_name}: No LLDP neighbors")
                else:
                    device_logs.append("   (LLDP data not collected)")
            device_logs.append("")

            # Show interface details for each interface - GROUP SIMILAR INTERFACES
            device_logs.append("=" * 80)
            device_logs.append("INTERFACE DETAILS")
            device_logs.append("=" * 80)
            device_logs.append("")

            interface_statuses = []  # Track status for summary

            # Group interfaces by (deployment_status, vlan_id)
            interface_groups = {}  # Key: (status, vlan_id), Value: list of interface names
            interface_data_map = {}  # Store full data for each interface

            for actual_interface_name in device_interface_names:
                interface_result = device_results.get(actual_interface_name, {})

                # Determine deployment status
                success = interface_result.get('success', False)
                committed = interface_result.get('committed', False)
                error = interface_result.get('error')
                # Also check message field if error is not set (some failures set message but not error)
                if not error and not success and interface_result.get('message'):
                    # If deployment failed and there's a message, treat it as an error
                    error = interface_result.get('message')

                if error:
                    status = "ERROR"
                    interface_statuses.append("ERROR")
                elif committed:
                    status = "PASS"
                    interface_statuses.append("PASS")
                    # Track for auto-tagging
                    device_untagged = untagged_interfaces_by_device.get(device.name, [])
                    for iface in device_untagged:
                        if iface.name == actual_interface_name:
                            interfaces_to_auto_tag.append(iface)
                            break
                elif success:
                    status = "WARN"
                    interface_statuses.append("WARN")
                else:
                    status = "ERROR"
                    interface_statuses.append("ERROR")

                # Get VLAN info and bond membership
                vlan_id = None
                vlan_name = None
                tagged_vlan_str = None
                bond_member_of = None
                target_interface = actual_interface_name
                try:
                    interface_obj = Interface.objects.get(device=device, name=actual_interface_name)
                    untagged_vlan = interface_obj.untagged_vlan
                    tagged_vlans = list(interface_obj.tagged_vlans.all())

                    if untagged_vlan:
                        vlan_id = untagged_vlan.vid
                        vlan_name = untagged_vlan.name
                    if tagged_vlans:
                        tagged_vlan_str = ', '.join([f"{v.vid} ({v.name})" for v in tagged_vlans])

                    # Check bond membership
                    if interface_obj.lag:
                        bond_member_of = interface_obj.lag.name
                        target_interface = bond_member_of
                    elif bond_info_map and device.name in bond_info_map:
                        device_bond_map = bond_info_map[device.name]
                        if actual_interface_name in device_bond_map:
                            bond_member_of = device_bond_map[actual_interface_name]['bond_name']
                            target_interface = bond_member_of
                except Exception as e:
                    vlan_id = "ERROR"
                    vlan_name = str(e)

                # Group by status, VLAN, and target interface (bond or physical)
                # CRITICAL: Use a sentinel value for None vlan_id to avoid TypeError when sorting tuples
                # Python can't compare None with int when sorting, so use 0 as sentinel
                vlan_id_for_key = vlan_id if vlan_id is not None else 0
                group_key = (status, vlan_id_for_key, target_interface)
                if group_key not in interface_groups:
                    interface_groups[group_key] = []
                interface_groups[group_key].append(actual_interface_name)

                # Store data for later display
                interface_data_map[actual_interface_name] = {
                    'status': status,
                    'vlan_id': vlan_id,
                    'vlan_name': vlan_name,
                    'tagged_vlans': tagged_vlan_str,
                    'error': error,
                    'bond_member_of': bond_member_of,
                    'target_interface': target_interface
                }

            # Display grouped interfaces
            for group_key, interface_names in sorted(interface_groups.items()):
                status, vlan_id, target_interface = group_key

                # Get data from first interface in group (all should be same)
                first_iface = interface_names[0]
                iface_data = interface_data_map[first_iface]

                # Show group header
                if len(interface_names) == 1:
                    # Single interface
                    if iface_data['bond_member_of']:
                        device_logs.append(f"--- Interface: {interface_names[0]} ---")
                    else:
                        device_logs.append(f"--- Interface: {interface_names[0]} ---")
                else:
                    # Multiple interfaces
                    device_logs.append(f"--- Interfaces ({len(interface_names)}): {', '.join(sorted(interface_names))} ---")
                device_logs.append("")

                # Show VLAN info
                if iface_data['vlan_id'] and iface_data['vlan_id'] != "ERROR":
                    device_logs.append(f"  VLAN: {iface_data['vlan_id']} ({iface_data['vlan_name']})")
                if iface_data['tagged_vlans']:
                    device_logs.append(f"  Tagged VLANs: {iface_data['tagged_vlans']}")
                if iface_data['vlan_id'] == "ERROR":
                    device_logs.append(f"  [WARN] Could not get VLAN info: {iface_data['vlan_name']}")

                # Show target interface (bond) if different from physical interface
                if iface_data['bond_member_of']:
                    device_logs.append(f"  Target: {iface_data['bond_member_of']}")

                device_logs.append("")

                # Show deployment status
                device_logs.append(f"  Deployment Status:")
                if status == "ERROR":
                    device_logs.append(f"    [ERROR] Deployment failed")
                    # Show error message if available
                    if iface_data['error']:
                        device_logs.append(f"    Error: {iface_data['error']}")
                    else:
                        # Fallback to message field if error not set (check if message indicates failure)
                        interface_result = device_results.get(first_iface, {})
                        error_message = interface_result.get('message', '')
                        if error_message and ('fail' in error_message.lower() or 'error' in error_message.lower() or 'baseline' in error_message.lower()):
                            device_logs.append(f"    Error: {error_message}")
                    # Show traceback if available (for debugging)
                    interface_result = device_results.get(first_iface, {})
                    if 'traceback' in interface_result:
                        device_logs.append(f"    ")
                        device_logs.append(f"    Full Traceback:")
                        for line in interface_result['traceback'].split('\n'):
                            if line.strip():
                                device_logs.append(f"      {line}")
                elif status == "PASS":
                    device_logs.append(f"    [OK] Successfully deployed and committed")
                elif status == "WARN":
                    device_logs.append(f"    [WARN] Deployed but not committed")
                device_logs.append("")

            # INTERFACE-LEVEL POST-DEPLOYMENT CHECKS
            device_logs.append("=" * 80)
            device_logs.append("INTERFACE-LEVEL POST-DEPLOYMENT CHECKS")
            device_logs.append("=" * 80)
            device_logs.append("")

            # Collect post-deployment data for all interfaces
            post_deployment_data_sync = {}
            for actual_interface_name in device_interface_names:
                interface_result = device_results.get(actual_interface_name, {})

                # Only check interfaces that were successfully deployed
                if not interface_result.get('committed'):
                    continue

                try:
                    interface_obj = Interface.objects.get(device=device, name=actual_interface_name)

                    # Check if this interface is a bond member
                    bond_member_of = None
                    if interface_obj.lag:
                        bond_member_of = interface_obj.lag.name

                    target_interface_for_checks = bond_member_of if bond_member_of else actual_interface_name

                    # Skip if we already checked this bond
                    if target_interface_for_checks in post_deployment_data_sync:
                        continue

                    post_data = {}

                    # Get expected VLAN from NetBox
                    expected_vlan = interface_obj.untagged_vlan.vid if interface_obj.untagged_vlan else None

                    # 1. Verify VLAN Configuration (on target interface - bond or physical)
                    # IMPORTANT: Use target_interface_for_checks (bond if detected) not actual_interface_name (member)
                    # because VLAN config is applied to the bond interface, not the member interface
                    try:
                        device_config_result = self._get_current_device_config(device, target_interface_for_checks, platform)
                        current_config = device_config_result.get('current_config', '')

                        # Parse current VLAN from config
                        current_vlan = None
                        if platform == 'cumulus' and 'access' in current_config:
                            import re
                            match = re.search(r'access\s+(\d+)', current_config)
                            if match:
                                current_vlan = int(match.group(1))

                        # Check if it matches expected VLAN
                        vlan_matches = (current_vlan == expected_vlan)
                        post_data['current_vlan'] = current_vlan
                        post_data['expected_vlan'] = expected_vlan
                        post_data['vlan_matches'] = vlan_matches
                    except Exception as e:
                        post_data['vlan_error'] = str(e)

                    # 2. Interface State - collected in Nornir deployment baseline/verification
                    # Get from deployment result instead of re-collecting
                    post_data['interface_state'] = {'info': 'Collected in Nornir deployment'}

                    # 3. Traffic Statistics - collected in Nornir deployment baseline/verification
                    # Get from deployment result instead of re-collecting
                    if platform == 'cumulus':
                        post_data['traffic_stats'] = {'info': 'Collected in Nornir deployment'}

                    post_deployment_data_sync[target_interface_for_checks] = post_data
                except Exception as e:
                    logger.debug(f"Could not get post-deployment data for {actual_interface_name}: {e}")

            # Display post-deployment checks
            if post_deployment_data_sync:
                device_logs.append("1. VLAN Configuration Verification:")
                for target_iface, post_data in sorted(post_deployment_data_sync.items()):
                    if 'vlan_error' in post_data:
                        device_logs.append(f"   {target_iface}: [ERROR] {post_data['vlan_error']}")
                    elif post_data.get('vlan_matches'):
                        device_logs.append(f"   {target_iface}: [OK] VLAN {post_data['current_vlan']} applied successfully")
                    else:
                        expected = post_data.get('expected_vlan', 'N/A')
                        actual = post_data.get('current_vlan', 'None')
                        device_logs.append(f"   {target_iface}: [WARN] Expected VLAN {expected}, found {actual}")
                device_logs.append("")

                device_logs.append("2. Interface State:")
                for target_iface, post_data in sorted(post_deployment_data_sync.items()):
                    iface_state = post_data.get('interface_state', {})
                    if iface_state.get('error'):
                        device_logs.append(f"   {target_iface}: [WARN] {iface_state['error']}")
                    elif iface_state.get('is_up'):
                        device_logs.append(f"   {target_iface}: [OK] UP")
                    else:
                        device_logs.append(f"   {target_iface}: [WARN] DOWN")
                device_logs.append("")

                if platform == 'cumulus':
                    device_logs.append("2. Traffic Analysis:")
                    for target_iface, post_data in sorted(post_deployment_data_sync.items()):
                        traffic_stats = post_data.get('traffic_stats', {})
                        if traffic_stats.get('error'):
                            device_logs.append(f"   {target_iface}: [WARN] {traffic_stats['error']}")
                        elif traffic_stats.get('has_traffic'):
                            in_pkts = traffic_stats.get('in_pkts_total', 0)
                            out_pkts = traffic_stats.get('out_pkts_total', 0)
                            device_logs.append(f"   {target_iface}: [OK] Traffic resumed (RX: {in_pkts:,} pkts, TX: {out_pkts:,} pkts)")
                        else:
                            device_logs.append(f"   {target_iface}: [INFO] No traffic detected")
                    device_logs.append("")
            else:
                device_logs.append("[INFO] No successfully deployed interfaces to verify")
                device_logs.append("")

            # Add device summary
            device_logs.append("=" * 80)
            device_logs.append("DEVICE SUMMARY")
            device_logs.append("=" * 80)
            device_logs.append("")
            device_logs.append(f"Total Interfaces: {len(device_interface_names)}")

            # Count statuses
            pass_count = interface_statuses.count("PASS")
            warn_count = interface_statuses.count("WARN")
            error_count = interface_statuses.count("ERROR")

            device_logs.append(f"  PASS: {pass_count}")
            device_logs.append(f"  WARN: {warn_count}")
            device_logs.append(f"  ERROR: {error_count}")
            device_logs.append("")

            # Determine overall device status
            if error_count > 0:
                overall_device_status = "ERROR"
                overall_device_status_text = "ERROR"
            elif warn_count > 0:
                overall_device_status = "warning"
                overall_device_status_text = "WARN"
            else:
                overall_device_status = "success"
                overall_device_status_text = "PASS"

            # Create ONE result entry for this device
            results.append({
                "device": device,
                "interface": f"{len(device_interface_names)} interfaces",
                "vlan_id": "Multiple VLANs",
                "vlan_name": "Sync Mode",
                "status": overall_device_status,
                "netbox_updated": "Yes" if pass_count > 0 else "No",
                "message": f"{pass_count} PASS, {warn_count} WARN, {error_count} ERROR",
                "deployment_logs": '\n'.join(device_logs),
                "device_status": overall_device_status_text,
                "interface_status": overall_device_status_text,
                "overall_status": overall_device_status_text,
                "risk_level": "HIGH" if error_count > 0 else "MEDIUM" if warn_count > 0 else "LOW",
                "dry_run": False,
                "committed": pass_count > 0,
                "success": pass_count > 0,
            })

        logger.info(f"[SYNC DEPLOYMENT] Generated {len(results)} device-level results")

        # Auto-tag interfaces that were successfully deployed (Section 2 only)
        auto_tag_results = []
        if interfaces_to_auto_tag:
            logger.info(f"[SYNC DEPLOYMENT] Auto-tagging {len(interfaces_to_auto_tag)} interfaces")
            for interface in interfaces_to_auto_tag:
                try:
                    # Refresh interface to get latest VLAN config
                    interface.refresh_from_db()
                    
                    # Determine correct tag based on VLAN config
                    has_untagged = interface.untagged_vlan is not None
                    has_tagged = interface.tagged_vlans.exists()
                    
                    # Use same logic as _auto_tag_interface_after_deployment:
                    # - If interface has BOTH tagged AND untagged VLANs → vlan-mode:tagged
                    # - If interface has ONLY untagged VLAN (no tagged) → vlan-mode:access
                    # - If interface has ONLY tagged VLANs (no untagged) → vlan-mode:tagged
                    if has_tagged and has_untagged:
                        tag_name = "vlan-mode:tagged"
                    elif has_untagged:
                        tag_name = "vlan-mode:access"
                    elif has_tagged:
                        tag_name = "vlan-mode:tagged"
                    else:
                        # No VLAN config - skip
                        logger.warning(f"Interface {interface.device.name}:{interface.name} has no VLAN config, skipping auto-tag")
                        auto_tag_results.append({
                            'interface': f"{interface.device.name}:{interface.name}",
                            'success': False,
                            'message': 'No VLAN config - skipped'
                        })
                        continue
                    
                    # Get or create the tag
                    vlan_mode_tag, _ = Tag.objects.get_or_create(
                        name=tag_name,
                        defaults={'slug': tag_name.replace(':', '-'), 'color': '4caf50'}
                    )
                    
                    # Remove any existing vlan-mode:access or vlan-mode:tagged tags first
                    existing_vlan_mode_tags = [
                        tag for tag in interface.tags.all()
                        if tag.name.startswith('vlan-mode:access') or tag.name.startswith('vlan-mode:tagged')
                    ]
                    if existing_vlan_mode_tags:
                        for old_tag in existing_vlan_mode_tags:
                            interface.tags.remove(old_tag)
                    
                    # Add the correct tag
                    interface.tags.add(vlan_mode_tag)
                    interface.save()
                    
                    auto_tag_results.append({
                        'interface': f"{interface.device.name}:{interface.name}",
                        'success': True,
                        'message': f'Tagged with {tag_name}'
                    })
                    logger.info(f"Auto-tagged {interface.device.name}:{interface.name} with '{tag_name}'")
                except Exception as e:
                    auto_tag_results.append({
                        'interface': f"{interface.device.name}:{interface.name}",
                        'success': False,
                        'message': f'Failed to tag: {str(e)}'
                    })
                    logger.error(f"Failed to auto-tag {interface.device.name}:{interface.name}: {e}")

            # Add summary result for auto-tagging
            successful_tags = len([r for r in auto_tag_results if r['success']])
            results.append({
                'device': 'AUTO-TAG',
                'interface': 'Summary',
                'vlan_id': 'N/A',
                'vlan_name': 'N/A',
                'status': 'INFO',
                'netbox_updated': 'Yes',
                'message': f"Auto-tagged {successful_tags}/{len(interfaces_to_auto_tag)} interfaces with 'vlan-mode'",
                'deployment_logs': '\n'.join([f"{r['interface']}: {r['message']}" for r in auto_tag_results]),
                'dry_run': False,
                'auto_tag_results': auto_tag_results,
            })

        return results

    def _run_vlan_deployment(self, devices, cleaned_data):
        """
        Core VLAN deployment logic.
        Environment-agnostic - uses NornirDeviceManager from core.
        Supports both Cumulus and EOS platforms.
        """
        logger.info(f"[_run_vlan_deployment ENTRY] Called with {len(devices)} devices, cleaned_data keys: {list(cleaned_data.keys())}")
        logger.info(f"[_run_vlan_deployment] dry_run={cleaned_data.get('dry_run')}, sync_netbox_to_device={cleaned_data.get('sync_netbox_to_device')}")

        # Get VLAN IDs from form (normal mode)
        untagged_vlan_id = cleaned_data.get('untagged_vlan')
        tagged_vlans_str = cleaned_data.get('tagged_vlans', '').strip()

        # Parse tagged VLANs from comma-separated string
        tagged_vlan_ids = []
        if tagged_vlans_str:
            try:
                tagged_vlan_ids = [int(x.strip()) for x in tagged_vlans_str.split(',') if x.strip()]
            except ValueError:
                logger.warning(f"Could not parse tagged VLANs: {tagged_vlans_str}")
                tagged_vlan_ids = []

        # For logging/display purposes, use untagged VLAN ID if available, otherwise first tagged VLAN
        primary_vlan_id = untagged_vlan_id if untagged_vlan_id else (tagged_vlan_ids[0] if tagged_vlan_ids else None)

        # Try to get VLAN object and name from NetBox (best effort - may have multiple VLANs with same ID)
        vlan = None
        vlan_name = f"VLAN {primary_vlan_id}" if primary_vlan_id else "VLANs"
        try:
            # Try to find VLAN by filtering by first device's location/site
            first_device = devices[0] if devices else None
            if first_device and primary_vlan_id:
                # Try location first
                if first_device.location:
                    vlans = VLAN.objects.filter(
                        vid=primary_vlan_id,
                        group__name__icontains=first_device.location.name
                    )
                    if vlans.exists():
                        vlan = vlans.first()

                # Try site if not found by location
                if not vlan and first_device.site:
                    vlans = VLAN.objects.filter(vid=primary_vlan_id, site=first_device.site)
                    if vlans.exists():
                        vlan = vlans.first()

                # Just get any VLAN with this ID if still not found
                if not vlan:
                    vlan = VLAN.objects.filter(vid=primary_vlan_id).first()

                if vlan:
                    vlan_name = vlan.name
        except Exception as e:
            logger.warning(f"Could not look up VLAN name for ID {primary_vlan_id}: {e}")

        scope = cleaned_data.get('deployment_scope')
        dry_run = cleaned_data.get('dry_run', False)
        deploy_changes = cleaned_data.get('deploy_changes', False)
        sync_netbox_to_device = cleaned_data.get('sync_netbox_to_device', False)

        # If deploy_changes is True, we apply to devices and NetBox
        # If dry_run is True, we only preview (no changes to devices or NetBox)
        update_netbox = deploy_changes  # Only update NetBox if deploying changes

        # Get combined interface list from form validation
        interface_list = cleaned_data.get('combined_interfaces', [])

        results = []

        # Detect platform - all devices should be same platform (enforced by manufacturer filter)
        platform = self._get_device_platform(devices[0]) if devices else 'cumulus'

        logger.info(f"VLAN Deployment: {len(devices)} devices, {len(interface_list)} interfaces, platform: {platform}, sync_mode: {sync_netbox_to_device}")
        logger.info(f"[_run_vlan_deployment] About to check if dry_run={dry_run}")

        if dry_run:
            logger.info(f"[_run_vlan_deployment] ENTERING DRY RUN MODE")
            # Dry run mode - use Nornir for parallel preview generation
            # First, run tag validation
            validation_results = self._validate_tags_for_dry_run(devices, interface_list)

            # Build bond_info_map for preview callback
            # Also detect bonds that exist in NetBox but not on device (Case 2)
            bond_info_map = {}
            bonds_to_create_on_device = {}  # Case 2: bonds in NetBox but not on device
            logger.info(f"[DRY RUN] Building bond_info_map for {len(devices)} devices, {len(interface_list)} interfaces")
            for device in devices:
                device_bond_map = {}
                device_bonds_to_create_on_device = {}

                # Get all interfaces for this device
                device_interfaces = []
                for interface_name in interface_list:
                    # Parse "device:interface" format if in sync mode
                    if sync_netbox_to_device and ':' in interface_name:
                        iface_device_name, actual_interface_name = interface_name.split(':', 1)
                        if iface_device_name != device.name:
                            continue
                        device_interfaces.append(actual_interface_name)
                    else:
                        device_interfaces.append(interface_name)

                # Step 1: Check device config for bonds that exist on device
                for actual_interface_name in device_interfaces:
                    # Check bond membership
                    try:
                        device_config_result = self._get_current_device_config(device, actual_interface_name, platform)
                        bond_member_of = device_config_result.get('bond_member_of', None)
                        if bond_member_of:
                            # Store in dictionary format to match sync mode
                            device_bond_map[actual_interface_name] = {
                                'bond_name': bond_member_of,
                                'bond_id': None,
                                'source': 'device'
                            }
                            logger.info(f"[DRY RUN] Bond detected on device: {device.name}:{actual_interface_name} → {bond_member_of}")
                    except Exception as e:
                        logger.warning(f"[DRY RUN] Could not check bond for {device.name}:{actual_interface_name}: {e}")

                # Step 2: Check for bonds in NetBox but NOT on device (Case 2)
                netbox_bonds = {}  # {bond_name: [member_interfaces]}
                for actual_interface_name in device_interfaces:
                    try:
                        interface_obj = Interface.objects.get(device=device, name=actual_interface_name)
                        if hasattr(interface_obj, 'lag') and interface_obj.lag:
                            bond_name = interface_obj.lag.name
                            if bond_name not in netbox_bonds:
                                netbox_bonds[bond_name] = []
                            netbox_bonds[bond_name].append(actual_interface_name)
                    except Interface.DoesNotExist:
                        pass
                    except Exception as e:
                        logger.debug(f"Error checking NetBox bond for {actual_interface_name}: {e}")

                # For each NetBox bond, check if it exists on the device
                for bond_name, member_names in netbox_bonds.items():
                    bond_exists_on_device = False
                    for member_name in member_names:
                        try:
                            device_config_result = self._get_current_device_config(device, member_name, platform)
                            device_bond_name = device_config_result.get('bond_member_of', None)
                            if device_bond_name == bond_name:
                                bond_exists_on_device = True
                                break
                        except Exception as e:
                            logger.debug(f"Error checking device config for {member_name}: {e}")

                    if not bond_exists_on_device:
                        # Bond exists in NetBox but NOT on device - need to create it on device
                        logger.info(f"[DRY RUN] Bond {bond_name} exists in NetBox but NOT on device - will create on device")

                        try:
                            bond_interface = Interface.objects.get(device=device, name=bond_name)
                            device_bonds_to_create_on_device[bond_name] = {
                                'members': member_names,
                                'bond_interface': bond_interface
                            }
                        except Interface.DoesNotExist:
                            logger.error(f"Bond interface {bond_name} not found in NetBox")

                if device_bond_map:
                    bond_info_map[device.name] = device_bond_map
                if device_bonds_to_create_on_device:
                    bonds_to_create_on_device[device.name] = device_bonds_to_create_on_device

            logger.info(f"[DRY RUN] Bond info map: {bond_info_map}")
            logger.info(f"[DRY RUN] Bonds to create on device: {bonds_to_create_on_device}")

            # Create preview callback that captures context
            # PERFORMANCE: This callback receives pre-fetched device data from Nornir
            def preview_callback(device, device_interfaces, platform, vlan_id, bond_info_map,
                                device_lldp_data=None, device_config_data=None, device_uptime=None):
                return self._generate_dry_run_preview(
                    device=device,
                    interface_list=device_interfaces,
                    platform=platform,
                    vlan_id=vlan_id,
                    bond_info_map=bond_info_map,
                    validation_results=validation_results,
                    sync_netbox_to_device=sync_netbox_to_device,
                    untagged_vlan_id=untagged_vlan_id,
                    tagged_vlan_ids=tagged_vlan_ids,
                    vlan=vlan,
                    primary_vlan_id=primary_vlan_id,
                    device_lldp_data=device_lldp_data,
                    device_config_data=device_config_data,
                    device_uptime=device_uptime
                )

            # Use Nornir for parallel preview generation
            logger.info(f"[DRY RUN] Starting Nornir parallel preview for {len(devices)} devices...")
            nornir_manager = NornirDeviceManager(devices=devices)
            nornir_manager.initialize()

            nornir_results = nornir_manager.deploy_vlan(
                interface_list=interface_list,
                vlan_id=primary_vlan_id,
                platform=platform,
                timeout=90,
                bond_info_map=bond_info_map if bond_info_map else None,
                bonds_to_create_on_device=bonds_to_create_on_device if bonds_to_create_on_device else None,
                dry_run=True,
                preview_callback=preview_callback
            )

            logger.info(f"[DRY RUN] Nornir preview completed for {len(nornir_results)} devices")

            # Calculate summary statistics from Nornir results
            total_devices = len(devices)
            total_interfaces = 0
            would_pass = 0
            would_warn = 0
            would_block = 0

            for device_name, device_results in nornir_results.items():
                for interface_name, interface_result in device_results.items():
                    total_interfaces += 1
                    status_text = interface_result.get('overall_status_text', 'PASS')
                    if status_text == 'BLOCKED':
                        would_block += 1
                    elif status_text == 'WARN':
                        would_warn += 1
                    else:
                        would_pass += 1

            # Process Nornir results and build final results list (ONE log per device)
            logger.info(f"[DRY RUN] Processing Nornir results for {len(nornir_results)} devices...")

            for device in devices:
                device_validation = validation_results['device_validation'].get(device.name, {})
                device_results = nornir_results.get(device.name, {})

                if not device_results:
                    # No results for this device
                    results.append({
                        "device": device,
                        "interface": "N/A",
                        "vlan_id": "N/A",
                        "vlan_name": "N/A",
                        "status": "ERROR",
                        "netbox_updated": "Preview",
                        "message": "No preview data generated",
                        "deployment_logs": "Error: No preview data",
                        "validation_status": "",
                        "device_config_diff": "",
                        "netbox_diff": "",
                        "config_source": "error",
                        "risk_assessment": "",
                        "rollback_info": "",
                        "device_status": "ERROR",
                        "interface_status": "ERROR",
                        "overall_status": "ERROR",
                        "risk_level": "HIGH",
                    })
                    continue

                # Get device info
                device_ip = str(device.primary_ip4.address).split('/')[0] if device.primary_ip4 else (str(device.primary_ip6.address).split('/')[0] if device.primary_ip6 else 'N/A')
                device_site = device.site.name if device.site else 'N/A'
                device_location = device.location.name if device.location else 'N/A'
                device_role = device.role.name if device.role else 'N/A'

                # Build ONE comprehensive log for this device covering ALL interfaces
                device_logs = []
                device_logs.append("=" * 80)
                device_logs.append(f"NORMAL MODE DRY RUN - DEVICE: {device.name}")
                device_logs.append("=" * 80)
                device_logs.append("")

                # DEBUG: Show execution trace
                device_logs.append("=" * 80)
                device_logs.append("DEBUG: EXECUTION TRACE")
                device_logs.append("=" * 80)
                device_logs.append(f"1. _run_vlan_deployment() was called")
                device_logs.append(f"2. dry_run=True detected, entering dry run mode")
                device_logs.append(f"3. Nornir manager initialized with {len(devices)} device(s)")
                device_logs.append(f"4. deploy_vlan() called with {len(interface_list)} interface(s)")
                device_logs.append(f"5. Nornir results received: {len(device_results)} interface(s) for this device")
                device_logs.append(f"6. Device found in results: {'YES' if device_results else 'NO'}")
                device_logs.append("")

                device_logs.append(f"Total Interfaces: {len(device_results)}")
                device_logs.append(f"VLAN: {primary_vlan_id} ({vlan.name if vlan else 'N/A'})")
                device_logs.append("")

                # Collect summary info and device-level data
                total_interfaces = len(device_results)
                blocked_count = 0
                warning_count = 0
                pass_count = 0
                error_count = 0

                # Collect device-level info from first interface (all interfaces share same device connection)
                first_interface_preview = next(iter(device_results.values()), {})
                config_source = first_interface_preview.get('config_source', 'device')
                config_timestamp = first_interface_preview.get('config_timestamp', 'N/A')
                device_uptime = first_interface_preview.get('device_uptime', None)
                bridge_vlans = first_interface_preview.get('bridge_vlans', [])
                device_connected = first_interface_preview.get('device_connected', False)
                error_details = first_interface_preview.get('error_details', None)

                # Show device-level pre-deployment checks ONCE at the top
                device_logs.append("=" * 80)
                device_logs.append("PRE-DEPLOYMENT CHECKS")
                device_logs.append("=" * 80)
                device_logs.append("")

                # 1. Device Connection & Uptime
                device_logs.append("1. Device Connection & Uptime:")
                if config_source == 'device':
                    device_logs.append(f"   [OK] Connected successfully")
                    if device_uptime:
                        device_logs.append(f"   Uptime: {device_uptime}")
                    if config_timestamp != 'N/A':
                        device_logs.append(f"   Config fetched: {config_timestamp}")
                elif config_source == 'netbox':
                    device_logs.append(f"   [WARN] Device unreachable - using NetBox inference")
                    device_logs.append(f"   Note: Actual device config may differ from NetBox state")
                else:
                    device_logs.append(f"   [FAIL] Config retrieval failed")
                    device_logs.append(f"   DEBUG: config_source = '{config_source}'")
                    device_logs.append(f"   DEBUG: device_connected = {device_connected}")
                    if error_details:
                        # error_details contains the actual error message (connection or config collection error)
                        if device_connected:
                            device_logs.append(f"   Config Collection Error:")
                            # Split multi-line error messages and indent each line
                            for line in str(error_details).split('\n'):
                                device_logs.append(f"      {line}")
                        else:
                            device_logs.append(f"   Connection Error:")
                            # Split multi-line error messages and indent each line
                            for line in str(error_details).split('\n'):
                                device_logs.append(f"      {line}")
                    else:
                        device_logs.append(f"   Error: Unknown error during config retrieval")
                device_logs.append("")

                device_logs.append("=" * 80)
                device_logs.append("INTERFACE DETAILS")
                device_logs.append("=" * 80)
                device_logs.append("")

                # Collect all device configs and NetBox diffs for consolidation
                all_current_configs = []
                all_proposed_configs = []
                all_netbox_diffs = []

                # ISSUE #4 FIX: Group interfaces by validation status and common attributes
                # First pass: collect all data and group interfaces
                interface_groups = {}  # Key: (status, bond_status, type), Value: list of interface names
                interface_data_map = {}  # Store full data for each interface

                for actual_interface_name, interface_preview in sorted(device_results.items()):
                    # Check for errors
                    if 'error' in interface_preview:
                        error_count += 1
                        # Show errors individually
                        if 'ERROR' not in interface_groups:
                            interface_groups['ERROR'] = []
                        interface_groups['ERROR'].append(actual_interface_name)
                        interface_data_map[actual_interface_name] = interface_preview
                        continue

                    # Extract preview data
                    overall_status_text = interface_preview.get('overall_status_text', 'PASS')
                    if overall_status_text == 'BLOCKED':
                        blocked_count += 1
                    elif overall_status_text == 'WARN':
                        warning_count += 1
                    elif overall_status_text == 'PASS':
                        pass_count += 1
                    else:
                        error_count += 1

                    # Extract all preview data for this interface
                    target_interface_for_config = interface_preview.get('target_interface', actual_interface_name)
                    bond_member_of = interface_preview.get('bond_member_of', None)
                    current_device_config = interface_preview.get('current_config', 'Unable to fetch')
                    proposed_config = interface_preview.get('proposed_config', '')
                    netbox_diff = interface_preview.get('netbox_diff', '')
                    interface_details = interface_preview.get('interface_details', {})
                    validation_table = interface_preview.get('validation_table', '')

                    # Collect configs for consolidation
                    if current_device_config and current_device_config != 'Unable to fetch':
                        all_current_configs.append(f"# Interface: {actual_interface_name}")
                        all_current_configs.append(current_device_config)
                        # If bond member, also add bond config
                        if bond_member_of:
                            bond_interface_config = interface_preview.get('bond_interface_config')
                            if bond_interface_config:
                                all_current_configs.append(f"# Bond Interface: {bond_member_of} (parent of {actual_interface_name})")
                                all_current_configs.append(bond_interface_config)
                    if proposed_config:
                        all_proposed_configs.append(f"# Interface: {target_interface_for_config}")
                        # Add bridge VLAN comment if available (Cumulus only)
                        vlans_already = interface_preview.get('vlans_already_in_bridge', [])
                        if platform == 'cumulus' and vlans_already:
                            vlan_list_str = ', '.join(map(str, sorted(vlans_already)))
                            all_proposed_configs.append(f"# Bridge VLANs already present: {vlan_list_str}")
                        all_proposed_configs.append(proposed_config)
                    if netbox_diff:
                        all_netbox_diffs.append(f"# Interface: {actual_interface_name}")
                        all_netbox_diffs.append(netbox_diff)

                    # Group by: status, bond status, interface type
                    iface_type = interface_details.get('type', 'Unknown')
                    bond_status = 'bond_member' if bond_member_of else 'standalone'
                    group_key = (overall_status_text, bond_status, iface_type)

                    if group_key not in interface_groups:
                        interface_groups[group_key] = []
                    interface_groups[group_key].append(actual_interface_name)
                    interface_data_map[actual_interface_name] = interface_preview

                # Second pass: Display grouped interfaces
                group_idx = 1
                for group_key, interface_names in sorted(interface_groups.items()):
                    if group_key == 'ERROR':
                        # Show errors individually
                        for iface_name in interface_names:
                            device_logs.append("-" * 80)
                            device_logs.append(f"Interface: {iface_name}")
                            device_logs.append("-" * 80)
                            device_logs.append(f"[ERROR] {interface_data_map[iface_name].get('error', 'Unknown error')}")
                            device_logs.append("")
                        continue

                    status, bond_status, iface_type = group_key
                    num_interfaces = len(interface_names)

                    device_logs.append("-" * 80)
                    if num_interfaces == 1:
                        device_logs.append(f"Interface: {interface_names[0]}")
                    else:
                        device_logs.append(f"Interface Group {group_idx} ({num_interfaces} interfaces): {', '.join(interface_names)}")
                        group_idx += 1
                    device_logs.append("-" * 80)

                    # Show common attributes for the group (use first interface as representative)
                    first_iface = interface_names[0]
                    interface_preview = interface_data_map[first_iface]
                    bond_member_of = interface_preview.get('bond_member_of', None)
                    interface_details = interface_preview.get('interface_details', {})
                    validation_table = interface_preview.get('validation_table', '')
                    risk_assessment = interface_preview.get('risk_assessment', '')

                    # Build interface section in device log (common attributes for group)
                    device_logs.append(f"Type: {interface_details.get('type', 'Unknown')}")
                    if num_interfaces == 1:
                        device_logs.append(f"Description: {interface_details.get('description', 'No description')}")
                    device_logs.append(f"Cable: {'[OK] Connected' if interface_details.get('cabled') else '[WARN] Not cabled'}")
                    if num_interfaces == 1 and interface_details.get('connected_device'):
                        device_logs.append(f"Connected To: {interface_details.get('connected_device')} ({interface_details.get('connected_role', 'Unknown')})")
                    if bond_member_of:
                        device_logs.append(f"Bond Member: {bond_member_of} (VLAN will be configured on bond)")

                    device_logs.append(f"Status: {status}")
                    device_logs.append("")

                    # Add validation table (show once for group)
                    if validation_table:
                        device_logs.append("Validation:")
                        device_logs.append(validation_table)
                        device_logs.append("")

                    # Add risk assessment (show once for group)
                    if risk_assessment:
                        device_logs.append(risk_assessment)
                        device_logs.append("")

                # After processing all interfaces, show consolidated device config changes
                device_logs.append("=" * 80)
                device_logs.append("DEVICE CONFIGURATION CHANGES")
                device_logs.append("=" * 80)
                device_logs.append("")

                if all_current_configs and all_proposed_configs:
                    device_logs.append("Current Device Configuration:")
                    device_logs.append("-" * 80)

                    # Add bridge configuration at the top (Cumulus only)
                    if platform == 'cumulus' and bridge_vlans and len(bridge_vlans) > 0:
                        vlan_list_str = self._format_vlan_list(bridge_vlans)
                        device_logs.append(f"# Bridge Domain br_default - Current VLANs: {vlan_list_str}")
                        # Show actual NVUE command with the formatted list
                        device_logs.append(f"nv set bridge domain br_default vlan {vlan_list_str}")
                        device_logs.append("")

                    for line in all_current_configs:
                        device_logs.append(line)
                    device_logs.append("")
                    device_logs.append("Proposed Device Configuration:")
                    device_logs.append("-" * 80)

                    # ISSUE #2 FIX: Consolidate bridge VLAN commands from all interfaces
                    if platform == 'cumulus':
                        # Extract all bridge VLAN commands and collect unique VLANs
                        bridge_vlan_commands = []
                        non_bridge_lines = []
                        all_vlans_to_add = set()

                        for line in all_proposed_configs:
                            if line.startswith('nv set bridge domain br_default vlan '):
                                # Extract VLAN ID from command
                                vlan_part = line.replace('nv set bridge domain br_default vlan ', '').strip()
                                try:
                                    vlan_id = int(vlan_part)
                                    all_vlans_to_add.add(vlan_id)
                                except ValueError:
                                    # If not a simple int, keep the command as-is
                                    bridge_vlan_commands.append(line)
                            else:
                                non_bridge_lines.append(line)

                        # Show consolidated bridge VLAN command at the top if we have VLANs
                        if all_vlans_to_add:
                            sorted_vlans = sorted(list(all_vlans_to_add))
                            vlan_list_str = self._format_vlan_list(sorted_vlans)
                            device_logs.append(f"# Bridge Domain br_default - Adding VLANs: {vlan_list_str}")
                            device_logs.append(f"nv set bridge domain br_default vlan {vlan_list_str}")
                            device_logs.append("")

                        # Show non-bridge commands
                        for line in non_bridge_lines:
                            device_logs.append(line)
                    else:
                        # Non-Cumulus platforms: just show all lines as-is
                        for line in all_proposed_configs:
                            device_logs.append(line)

                    device_logs.append("")
                else:
                    device_logs.append("(no device configuration changes)")
                    device_logs.append("")

                # Show consolidated NetBox changes (GROUPED)
                device_logs.append("=" * 80)
                device_logs.append("NETBOX CONFIGURATION CHANGES")
                device_logs.append("=" * 80)
                device_logs.append("")

                if all_netbox_diffs:
                    # Group NetBox changes by bond status and change type
                    netbox_groups = {}  # Key: (bond_name or 'standalone', change_type), Value: list of (interface_name, changes)

                    for actual_interface_name, interface_preview in sorted(device_results.items()):
                        if 'error' in interface_preview:
                            continue

                        netbox_diff = interface_preview.get('netbox_diff', '')
                        if not netbox_diff or netbox_diff == "No changes (NetBox already has this configuration)":
                            continue

                        bond_member_of = interface_preview.get('bond_member_of', None)

                        # Get NetBox state to extract current/proposed VLANs
                        try:
                            netbox_state = self._get_netbox_current_state(device, actual_interface_name, primary_vlan_id, mode='normal')
                            current = netbox_state.get('current', {})
                            proposed = netbox_state.get('proposed', {})

                            # Extract VLAN changes
                            current_untagged = current.get('untagged_vlan')
                            proposed_untagged = proposed.get('untagged_vlan')
                            current_tagged = current.get('tagged_vlans', [])
                            proposed_tagged = proposed.get('tagged_vlans', [])

                            # Group by bond status
                            if bond_member_of:
                                # Member interface - VLANs will be removed
                                group_key = (bond_member_of, 'member_clear')
                                if group_key not in netbox_groups:
                                    netbox_groups[group_key] = []
                                netbox_groups[group_key].append({
                                    'interface': actual_interface_name,
                                    'current_untagged': current_untagged,
                                    'proposed_untagged': proposed_untagged,
                                    'current_tagged': current_tagged,
                                    'proposed_tagged': proposed_tagged
                                })

                                # Bond interface - VLANs will be added
                                group_key = (bond_member_of, 'bond_add')
                                if group_key not in netbox_groups:
                                    netbox_groups[group_key] = []
                                # Only add bond once (check if not already added)
                                if not any(item['interface'] == bond_member_of for item in netbox_groups[group_key]):
                                    netbox_groups[group_key].append({
                                        'interface': bond_member_of,
                                        'current_untagged': None,  # Bond doesn't have VLANs yet
                                        'proposed_untagged': primary_vlan_id,  # Will get the VLAN from form
                                        'current_tagged': [],
                                        'proposed_tagged': tagged_vlan_ids if tagged_vlan_ids else []
                                    })
                            else:
                                # Standalone interface
                                group_key = ('standalone', 'update')
                                if group_key not in netbox_groups:
                                    netbox_groups[group_key] = []
                                netbox_groups[group_key].append({
                                    'interface': actual_interface_name,
                                    'current_untagged': current_untagged,
                                    'proposed_untagged': proposed_untagged,
                                    'current_tagged': current_tagged,
                                    'proposed_tagged': proposed_tagged
                                })
                        except Exception as e:
                            logger.warning(f"Could not parse NetBox state for {actual_interface_name}: {e}")
                            continue

                    # Display grouped NetBox changes
                    if netbox_groups:
                        # Check if bonds are being created in NetBox (bonds exist on device but not in NetBox)
                        # In this case, show bond interfaces directly, not member interfaces
                        # Note: bonds_to_create_in_netbox means bonds exist on device but not in NetBox
                        # So bonds already exist on device - we just need to create them in NetBox
                        # bonds_to_create_in_netbox is defined in the outer scope of _run_vlan_deployment
                        bonds_being_created_in_netbox = device.name in bonds_to_create_in_netbox if bonds_to_create_in_netbox else False
                        
                        if bonds_being_created_in_netbox:
                            # Bonds are being created in NetBox - show bond interfaces directly
                            device_logs.append("Bond Interfaces (will be CREATED in NetBox with VLANs):")
                            device_logs.append("")
                            
                            # Get bond groups (VLANs being added to bonds)
                            bond_groups = {k: v for k, v in netbox_groups.items() if k[1] == 'bond_add'}
                            if bond_groups:
                                for (bond_name, change_type), interfaces in sorted(bond_groups.items()):
                                    for item in interfaces:
                                        iface = item['interface']
                                        curr_untag = item['current_untagged']
                                        prop_untag = item['proposed_untagged']
                                        curr_tag = item['current_tagged']
                                        prop_tag = item['proposed_tagged']

                                        changes = []
                                        if curr_untag != prop_untag:
                                            changes.append(f"Untagged VLAN {curr_untag} → {prop_untag}")
                                        if curr_tag != prop_tag:
                                            curr_tag_str = f"[{', '.join(map(str, curr_tag))}]" if curr_tag else "[]"
                                            prop_tag_str = f"[{', '.join(map(str, prop_tag))}]" if prop_tag else "[]"
                                            changes.append(f"Tagged VLANs {curr_tag_str} → {prop_tag_str}")

                                        if changes:
                                            device_logs.append(f"  {iface}: {', '.join(changes)}")
                            
                            device_logs.append("")
                            device_logs.append("  Note: Bond interfaces will be created in NetBox and VLANs will be migrated from member interfaces.")
                            device_logs.append("")
                        else:
                            # Bonds already exist in NetBox - show member interfaces being cleared and bonds being updated
                            # First show member interface changes (VLANs being removed)
                            member_groups = {k: v for k, v in netbox_groups.items() if k[1] == 'member_clear'}
                            if member_groups:
                                device_logs.append("Member Interfaces (VLANs will be REMOVED and migrated to bond):")
                                device_logs.append("")
                                for (bond_name, change_type), interfaces in sorted(member_groups.items()):
                                    for item in interfaces:
                                        iface = item['interface']
                                        curr_untag = item['current_untagged']
                                        prop_untag = item['proposed_untagged']
                                        curr_tag = item['current_tagged']
                                        prop_tag = item['proposed_tagged']

                                        changes = []
                                        if curr_untag != prop_untag:
                                            changes.append(f"Untagged VLAN {curr_untag} → {prop_untag}")
                                        if curr_tag != prop_tag:
                                            curr_tag_str = f"[{', '.join(map(str, curr_tag))}]" if curr_tag else "[]"
                                            prop_tag_str = f"[{', '.join(map(str, prop_tag))}]" if prop_tag else "[]"
                                            changes.append(f"Tagged VLANs {curr_tag_str} → {prop_tag_str}")

                                        if changes:
                                            device_logs.append(f"  {iface}: {', '.join(changes)}")
                                
                                # Also include ALL bond members that might not be in device_results
                                # This handles cases where a bond member wasn't directly selected but should have VLANs removed
                                try:
                                    from dcim.models import Interface
                                    all_bond_names = set([k[0] for k in member_groups.keys()])
                                    for bond_name in all_bond_names:
                                        # Get all members of this bond from NetBox
                                        try:
                                            bond_interface = Interface.objects.get(device=device, name=bond_name)
                                            bond_members = Interface.objects.filter(device=device, lag=bond_interface)
                                            
                                            # Check each member to see if it's already in the list
                                            for member in bond_members:
                                                member_name = member.name
                                                # Skip if already in the list
                                                already_listed = any(
                                                    item['interface'] == member_name 
                                                    for interfaces in member_groups.values() 
                                                    for item in interfaces
                                                )
                                                
                                                if not already_listed:
                                                    # Get current VLAN config for this member
                                                    curr_untag = member.untagged_vlan.vid if member.untagged_vlan else None
                                                    curr_tag = list(member.tagged_vlans.values_list('vid', flat=True))
                                                    
                                                    # Member interfaces will have VLANs cleared (set to None/empty)
                                                    if curr_untag or curr_tag:
                                                        changes = []
                                                        if curr_untag:
                                                            changes.append(f"Untagged VLAN {curr_untag} → None")
                                                        if curr_tag:
                                                            curr_tag_str = f"[{', '.join(map(str, curr_tag))}]"
                                                            changes.append(f"Tagged VLANs {curr_tag_str} → []")
                                                        
                                                        if changes:
                                                            device_logs.append(f"  {member_name}: {', '.join(changes)}")
                                        except Interface.DoesNotExist:
                                            # Bond doesn't exist in NetBox yet - skip
                                            continue
                                except Exception as e:
                                    logger.debug(f"Could not fetch all bond members for display: {e}")
                                
                                device_logs.append("")

                            # Then show bond interface changes (VLANs being added)
                            bond_groups = {k: v for k, v in netbox_groups.items() if k[1] == 'bond_add'}
                            if bond_groups:
                                device_logs.append("Bond Interfaces (VLANs will be ADDED):")
                                device_logs.append("")
                                for (bond_name, change_type), interfaces in sorted(bond_groups.items()):
                                    for item in interfaces:
                                        iface = item['interface']
                                        curr_untag = item['current_untagged']
                                        prop_untag = item['proposed_untagged']
                                        curr_tag = item['current_tagged']
                                        prop_tag = item['proposed_tagged']

                                        changes = []
                                        if curr_untag != prop_untag:
                                            changes.append(f"Untagged VLAN {curr_untag} → {prop_untag}")
                                        if curr_tag != prop_tag:
                                            curr_tag_str = f"[{', '.join(map(str, curr_tag))}]" if curr_tag else "[]"
                                            prop_tag_str = f"[{', '.join(map(str, prop_tag))}]" if prop_tag else "[]"
                                            changes.append(f"Tagged VLANs {curr_tag_str} → {prop_tag_str}")

                                        if changes:
                                            device_logs.append(f"  {iface}: {', '.join(changes)}")
                                device_logs.append("")

                        # Finally show standalone interface changes
                        standalone_groups = {k: v for k, v in netbox_groups.items() if k[1] == 'update'}
                        if standalone_groups:
                            device_logs.append("Standalone Interfaces (VLAN updates):")
                            device_logs.append("")
                            for (group_name, change_type), interfaces in sorted(standalone_groups.items()):
                                for item in interfaces:
                                    iface = item['interface']
                                    curr_untag = item['current_untagged']
                                    prop_untag = item['proposed_untagged']
                                    curr_tag = item['current_tagged']
                                    prop_tag = item['proposed_tagged']

                                    changes = []
                                    if curr_untag != prop_untag:
                                        changes.append(f"Untagged VLAN {curr_untag} → {prop_untag}")
                                    if curr_tag != prop_tag:
                                        curr_tag_str = f"[{', '.join(map(str, curr_tag))}]" if curr_tag else "[]"
                                        prop_tag_str = f"[{', '.join(map(str, prop_tag))}]" if prop_tag else "[]"
                                        changes.append(f"Tagged VLANs {curr_tag_str} → {prop_tag_str}")

                                    if changes:
                                        device_logs.append(f"  {iface}: {', '.join(changes)}")
                            device_logs.append("")
                    else:
                        device_logs.append("(no NetBox changes)")
                        device_logs.append("")
                else:
                    device_logs.append("(no NetBox changes)")
                    device_logs.append("")

                # ISSUE #5 FIX: Add interface-level pre-deployment checks before summary
                device_logs.append("=" * 80)
                device_logs.append("INTERFACE-LEVEL PRE-DEPLOYMENT CHECKS")
                device_logs.append("=" * 80)
                device_logs.append("")

                # 1. LLDP Neighbor Data Collection (baseline for post-deployment verification)
                device_logs.append("1. LLDP Neighbor Data Collection (Baseline):")
                lldp_collected_count = 0
                lldp_no_data_count = 0

                for actual_interface_name, interface_preview in sorted(device_results.items()):
                    if 'error' in interface_preview:
                        continue

                    # Get actual LLDP neighbors from device (collected in Nornir batch deployment)
                    lldp_neighbors = interface_preview.get('lldp_neighbors', [])

                    if lldp_neighbors:
                        # We have LLDP data - just show what we collected
                        actual_hostnames = [n.get('hostname', '') for n in lldp_neighbors]
                        device_logs.append(f"   Interface {actual_interface_name} → {', '.join(actual_hostnames)}")
                        lldp_collected_count += 1
                    else:
                        # No LLDP data collected
                        device_logs.append(f"   Interface {actual_interface_name} → No LLDP data")
                        lldp_no_data_count += 1

                if lldp_collected_count == 0 and lldp_no_data_count == 0:
                    device_logs.append("   No interfaces to check")
                device_logs.append("")

                # 2. Interface State
                device_logs.append("2. Interface State:")
                up_count = 0
                down_count = 0
                for actual_interface_name, interface_preview in sorted(device_results.items()):
                    if 'error' in interface_preview:
                        continue
                    interface_details = interface_preview.get('interface_details', {})
                    # TODO: Add actual interface state when available from device
                    # For now, assume all are UP if no error
                    up_count += 1
                device_logs.append(f"   Interfaces UP: {up_count}")
                if down_count > 0:
                    device_logs.append(f"   Interfaces DOWN: {down_count} [WARN]")
                device_logs.append("")

                # 3. Traffic Analysis (check on bond if detected, otherwise on member)
                device_logs.append("3. Traffic Analysis:")
                traffic_detected = []
                no_traffic = []
                checked_interfaces = set()  # Track which interfaces we've already checked

                for actual_interface_name, interface_preview in sorted(device_results.items()):
                    if 'error' in interface_preview:
                        continue

                    # CRITICAL: Check traffic on bond interface if bond is detected
                    bond_member_of = interface_preview.get('bond_member_of')
                    target_interface_for_stats = bond_member_of if bond_member_of else actual_interface_name

                    # Skip if we already checked this interface (avoid duplicate bond checks)
                    if target_interface_for_stats in checked_interfaces:
                        continue
                    checked_interfaces.add(target_interface_for_stats)

                    if platform == 'cumulus':
                        # Get traffic stats for the target interface (bond or member)
                        traffic_stats = self._check_interface_traffic_stats(device, target_interface_for_stats, platform, bond_interface=None)
                        if traffic_stats:
                            rx_pkts = traffic_stats.get('rx_packets', 0)
                            tx_pkts = traffic_stats.get('tx_packets', 0)
                            if rx_pkts > 0 or tx_pkts > 0:
                                display_name = f"{target_interface_for_stats} (bond)" if bond_member_of else target_interface_for_stats
                                traffic_detected.append(f"{display_name} (RX: {rx_pkts:,}, TX: {tx_pkts:,})")
                            else:
                                display_name = f"{target_interface_for_stats} (bond)" if bond_member_of else target_interface_for_stats
                                no_traffic.append(display_name)

                if traffic_detected:
                    device_logs.append(f"   [WARN] Active traffic detected on {len(traffic_detected)} interface(s):")
                    for traffic_info in traffic_detected:
                        device_logs.append(f"     {traffic_info}")
                if no_traffic:
                    device_logs.append(f"   [OK] No traffic on {len(no_traffic)} interface(s): {', '.join(no_traffic)}")
                if not traffic_detected and not no_traffic:
                    device_logs.append("   No traffic data available")
                device_logs.append("")

                # Add summary at the end
                device_logs.append("=" * 80)
                device_logs.append("DEVICE SUMMARY")
                device_logs.append("=" * 80)
                device_logs.append(f"Total Interfaces: {total_interfaces}")
                device_logs.append(f"  PASS: {pass_count}")
                device_logs.append(f"  WARN: {warning_count}")
                device_logs.append(f"  BLOCKED: {blocked_count}")
                device_logs.append(f"  ERROR: {error_count}")
                device_logs.append("")

                # Determine overall device status
                if blocked_count > 0 or error_count > 0:
                    overall_device_status = "ERROR"
                    overall_device_status_text = "BLOCKED" if blocked_count > 0 else "ERROR"
                elif warning_count > 0:
                    overall_device_status = "WARNING"
                    overall_device_status_text = "WARN"
                else:
                    overall_device_status = "SUCCESS"
                    overall_device_status_text = "PASS"

                # Create ONE result entry for this device
                results.append({
                    "device": device,
                    "interface": f"{total_interfaces} interfaces",
                    "vlan_id": primary_vlan_id,
                    "vlan_name": vlan.name if vlan else 'N/A',
                    "status": overall_device_status,
                    "netbox_updated": "Preview",
                    "message": f"{pass_count} PASS, {warning_count} WARN, {blocked_count} BLOCKED, {error_count} ERROR",
                    "deployment_logs": '\n'.join(device_logs),
                    "validation_status": "",
                    "device_config_diff": "",
                    "netbox_diff": "",
                    "config_source": "batch",
                    "risk_assessment": "",
                    "rollback_info": "",
                    "device_status": overall_device_status_text,
                    "interface_status": overall_device_status_text,
                    "overall_status": overall_device_status_text,
                    "risk_level": "HIGH" if blocked_count > 0 else ("MEDIUM" if warning_count > 0 else "LOW"),
                })

            logger.info(f"[DRY RUN] Generated {len(results)} device-level results")

        else:
            # ========================================================================
            # DEPLOYMENT MODE - Deploy with consolidated device-level logging
            # ========================================================================
            logger.info(f"[DEPLOYMENT] Starting deployment for {len(devices)} devices")

            # Try to get VLAN object and name from NetBox (best effort - may have multiple VLANs with same ID)
            vlan = None
            vlan_name = f"VLAN {primary_vlan_id}" if primary_vlan_id else "VLANs"
            try:
                # Try to find VLAN by filtering by first device's location/site
                first_device = devices[0] if devices else None
                if first_device and primary_vlan_id:
                    # Try location first
                    if first_device.location:
                        vlans = VLAN.objects.filter(
                            vid=primary_vlan_id,
                            group__name__icontains=first_device.location.name
                        )
                        if vlans.exists():
                            vlan = vlans.first()

                    # Try site if not found by location
                    if not vlan and first_device.site:
                        vlans = VLAN.objects.filter(vid=primary_vlan_id, site=first_device.site)
                        if vlans.exists():
                            vlan = vlans.first()

                    # Just get any VLAN with this ID if still not found
                    if not vlan:
                        vlan = VLAN.objects.filter(vid=primary_vlan_id).first()

                    if vlan:
                        vlan_name = vlan.name
            except Exception as e:
                logger.warning(f"Could not look up VLAN name for ID {primary_vlan_id}: {e}")

            # Build bond_info_map first: {device_name: {interface_name: bond_name}}
            # Also detect bonds that exist in NetBox but not on device (Case 2)
            # And bonds that exist on device but not in NetBox (Case 1)
            bond_info_map = {}
            bonds_to_create_on_device = {}  # Case 2: bonds in NetBox but not on device
            bonds_to_create_in_netbox = {}  # Case 1: bonds on device but not in NetBox
            logger.info(f"[DEPLOYMENT] Building bond_info_map for {len(devices)} devices")
            for device in devices:
                device_bond_map = {}
                device_bonds_to_create_on_device = {}
                device_bonds_to_create_in_netbox = {}

                # Get all interfaces for this device
                device_interfaces = []
                for interface_name in interface_list:
                    # In sync mode, interface_name is in "device:interface" format
                    if sync_netbox_to_device and ':' in interface_name:
                        iface_device_name, actual_interface_name = interface_name.split(':', 1)
                        if iface_device_name != device.name:
                            continue
                        device_interfaces.append(actual_interface_name)
                    else:
                        device_interfaces.append(interface_name)

                # Step 1: Check device config for bonds that exist on device
                for actual_interface_name in device_interfaces:
                    # Check if interface is a bond member on device
                    try:
                        device_config_result = self._get_current_device_config(device, actual_interface_name, platform)
                        bond_member_of = device_config_result.get('bond_member_of', None)
                        if bond_member_of:
                            # Store in dictionary format to match sync mode
                            device_bond_map[actual_interface_name] = {
                                'bond_name': bond_member_of,
                                'bond_id': None,
                                'source': 'device'
                            }
                            logger.info(f"[DEPLOYMENT] Bond detected on device: {device.name}:{actual_interface_name} -> {bond_member_of}")
                            
                            # Check if this bond exists in NetBox
                            from dcim.models import Interface as InterfaceModel
                            bond_exists_in_netbox = InterfaceModel.objects.filter(device=device, name=bond_member_of).exists()
                            
                            if not bond_exists_in_netbox:
                                # Bond exists on device but not in NetBox - track it for creation
                                if bond_member_of not in device_bonds_to_create_in_netbox:
                                    device_bonds_to_create_in_netbox[bond_member_of] = {
                                        'members': [],
                                        'vlans_to_migrate': {}  # Map of member_name -> {untagged, tagged}
                                    }
                                device_bonds_to_create_in_netbox[bond_member_of]['members'].append(actual_interface_name)
                                
                                # Collect VLANs from this member interface for migration
                                try:
                                    interface_obj = Interface.objects.get(device=device, name=actual_interface_name)
                                    vlans_info = {
                                        'untagged': interface_obj.untagged_vlan.vid if interface_obj.untagged_vlan else None,
                                        'tagged': list(interface_obj.tagged_vlans.values_list('vid', flat=True))
                                    }
                                    device_bonds_to_create_in_netbox[bond_member_of]['vlans_to_migrate'][actual_interface_name] = vlans_info
                                    logger.info(f"[DEPLOYMENT] Detected bond {bond_member_of} on device {device.name} (not in NetBox) - member: {actual_interface_name}, VLANs: {vlans_info}")
                                except Interface.DoesNotExist:
                                    # Interface not in NetBox yet - will be created/updated during NetBox update
                                    logger.debug(f"[DEPLOYMENT] Interface {actual_interface_name} not in NetBox yet")
                                    device_bonds_to_create_in_netbox[bond_member_of]['vlans_to_migrate'][actual_interface_name] = {
                                        'untagged': untagged_vlan_id,  # Will be set from deployment
                                        'tagged': tagged_vlan_ids if tagged_vlan_ids else []
                                    }
                    except Exception as e:
                        logger.warning(f"[DEPLOYMENT] Could not check bond for {device.name}:{actual_interface_name}: {e}")

                # Step 2: Check for bonds in NetBox but NOT on device (Case 2)
                # NOTE: Bond detection should check BOTH NetBox AND device config
                # This is correct - we need to detect bonds from either source
                netbox_bonds = {}  # {bond_name: [member_interfaces]}
                for actual_interface_name in device_interfaces:
                    try:
                        interface_obj = Interface.objects.get(device=device, name=actual_interface_name)
                        if hasattr(interface_obj, 'lag') and interface_obj.lag:
                            bond_name = interface_obj.lag.name
                            
                            # CRITICAL: Validate bond name from NetBox - must be a single interface name
                            # Bond detection from both NetBox and device config is correct and needed
                            # However, config generation in normal mode uses ONLY form input (vlan_id), NOT NetBox VLAN data
                            # Skip invalid bond names that contain commas (data corruption)
                            if ',' in bond_name:
                                logger.warning(f"[DEPLOYMENT] NetBox has invalid bond name '{bond_name}' for interface {actual_interface_name} - contains comma")
                                logger.warning(f"[DEPLOYMENT] Skipping this NetBox bond entry - will use device config only")
                                continue  # Skip this invalid NetBox bond entry
                            
                            if bond_name not in netbox_bonds:
                                netbox_bonds[bond_name] = []
                            netbox_bonds[bond_name].append(actual_interface_name)
                    except Interface.DoesNotExist:
                        pass
                    except Exception as e:
                        logger.debug(f"Error checking NetBox bond for {actual_interface_name}: {e}")

                # For each NetBox bond, check if it exists on the device
                for bond_name, member_names in netbox_bonds.items():
                    bond_exists_on_device = False
                    for member_name in member_names:
                        try:
                            device_config_result = self._get_current_device_config(device, member_name, platform)
                            device_bond_name = device_config_result.get('bond_member_of', None)
                            if device_bond_name == bond_name:
                                bond_exists_on_device = True
                                break
                        except Exception as e:
                            logger.debug(f"Error checking device config for {member_name}: {e}")

                    if not bond_exists_on_device:
                        # Bond exists in NetBox but NOT on device - need to create it on device
                        logger.info(f"[DEPLOYMENT] Bond {bond_name} exists in NetBox but NOT on device - will create on device")

                        try:
                            bond_interface = Interface.objects.get(device=device, name=bond_name)
                            device_bonds_to_create_on_device[bond_name] = {
                                'members': member_names,
                                'bond_interface': bond_interface
                            }
                        except Interface.DoesNotExist:
                            logger.error(f"Bond interface {bond_name} not found in NetBox")

                if device_bond_map:
                    bond_info_map[device.name] = device_bond_map
                if device_bonds_to_create_on_device:
                    bonds_to_create_on_device[device.name] = device_bonds_to_create_on_device
                if device_bonds_to_create_in_netbox:
                    bonds_to_create_in_netbox[device.name] = device_bonds_to_create_in_netbox

            logger.info(f"[DEPLOYMENT] Bond info map: {bond_info_map}")
            logger.info(f"[DEPLOYMENT] Bonds to create on device: {bonds_to_create_on_device}")
            logger.info(f"[DEPLOYMENT] Bonds to create in NetBox: {bonds_to_create_in_netbox}")

            # Initialize Nornir and deploy
            nornir_manager = NornirDeviceManager(devices=devices)
            nornir_manager.initialize()

            logger.info(f"[DEPLOYMENT] Deploying VLAN {primary_vlan_id} to {len(interface_list)} interfaces across {len(devices)} devices")
            nornir_results = nornir_manager.deploy_vlan(
                interface_list=interface_list,
                vlan_id=primary_vlan_id,
                platform=platform,
                timeout=90,
                bond_info_map=bond_info_map if bond_info_map else None,
                bonds_to_create_on_device=bonds_to_create_on_device if bonds_to_create_on_device else None
            )

            logger.info(f"[DEPLOYMENT] Nornir deployment completed for {len(nornir_results)} devices")

            # Process Nornir results and build consolidated device-level logs (matching dry run format)
            for device in devices:
                device_results = nornir_results.get(device.name, {})

                if not device_results:
                    # No results for this device
                    results.append({
                        "device": device,
                        "interface": "N/A",
                        "vlan_id": "N/A",
                        "vlan_name": "N/A",
                        "status": "ERROR",
                        "netbox_updated": "No",
                        "message": "No deployment results",
                        "deployment_logs": "Error: No deployment data",
                        "dry_run": False,
                    })
                    continue

                # Get device-level interfaces for this device
                device_interfaces = []
                for interface_name in interface_list:
                    if sync_netbox_to_device and ':' in interface_name:
                        iface_device_name, actual_interface_name = interface_name.split(':', 1)
                        if iface_device_name != device.name:
                            continue
                    else:
                        actual_interface_name = interface_name
                    device_interfaces.append(actual_interface_name)

                if not device_interfaces:
                    continue

                # Build ONE comprehensive log for this device covering ALL interfaces
                device_logs = []
                device_logs.append("=" * 80)
                device_logs.append(f"NORMAL MODE DEPLOYMENT - DEVICE: {device.name}")
                device_logs.append("=" * 80)
                device_logs.append("")
                device_logs.append(f"Total Interfaces: {len(device_interfaces)}")
                device_logs.append(f"VLAN: {primary_vlan_id} ({vlan.name if vlan else 'N/A'})")
                device_logs.append("")

                # Get device-level info from first interface result
                first_interface_result = device_results.get(device_interfaces[0], {})
                deployment_logs_from_napalm = first_interface_result.get('logs', [])

                # Build consolidated device config section (all interfaces together) - MOVED BEFORE PRE-DEPLOYMENT CHECKS
                device_logs.append("=" * 80)
                device_logs.append("DEVICE CONFIGURATION CHANGES")
                device_logs.append("=" * 80)
                device_logs.append("")

                # Collect all current and proposed configs for all interfaces
                all_current_configs = []
                all_proposed_configs = []

                for actual_interface_name in device_interfaces:
                    bond_info = bond_info_map.get(device.name, {}).get(actual_interface_name, None)
                    bond_member_of = bond_info['bond_name'] if bond_info else None
                    target_interface = bond_member_of if bond_member_of else actual_interface_name

                    # Get current config
                    try:
                        device_config_result = self._get_current_device_config(device, actual_interface_name, platform)
                        current_config = device_config_result.get('current_config', None)
                        bridge_vlans = device_config_result.get('_bridge_vlans', [])

                        if current_config and isinstance(current_config, str):
                            if not current_config.startswith('ERROR:'):
                                all_current_configs.append(f"# Interface: {target_interface}")
                                all_current_configs.append(current_config)
                                all_current_configs.append("")
                    except Exception as e:
                        logger.debug(f"Could not get current config for {actual_interface_name}: {e}")

                    # Generate proposed config
                    try:
                        proposed_config = self._generate_vlan_config(
                            target_interface,
                            untagged_vlan=untagged_vlan_id,
                            tagged_vlans=tagged_vlan_ids,
                            platform=platform,
                            device=device,
                            bridge_vlans=bridge_vlans if 'bridge_vlans' in locals() else []
                        )
                        if proposed_config:
                            all_proposed_configs.append(f"# Interface: {target_interface}")
                            all_proposed_configs.append(proposed_config)
                            all_proposed_configs.append("")
                    except Exception as e:
                        logger.debug(f"Could not generate proposed config for {actual_interface_name}: {e}")

                # Show unified diff
                current_config_text = '\n'.join(all_current_configs) if all_current_configs else "(no current configuration)"
                proposed_config_text = '\n'.join(all_proposed_configs) if all_proposed_configs else "(no proposed configuration)"

                config_diff = self._generate_config_diff(current_config_text, proposed_config_text, platform, device=device, interface_name="ALL_INTERFACES", bridge_vlans=[])
                if config_diff:
                    for line in config_diff.split('\n'):
                        if line.strip():
                            device_logs.append(line)
                else:
                    device_logs.append("(no configuration changes)")
                device_logs.append("")

                # Build consolidated NetBox config section (GROUPED) - MOVED BEFORE PRE-DEPLOYMENT CHECKS
                device_logs.append("=" * 80)
                device_logs.append("NETBOX CONFIGURATION CHANGES")
                device_logs.append("=" * 80)
                device_logs.append("")

                # Group NetBox changes by bond status and change type
                netbox_groups = {}  # Key: (bond_name or 'standalone', change_type), Value: list of (interface_name, changes)

                for actual_interface_name in device_interfaces:
                    bond_info = bond_info_map.get(device.name, {}).get(actual_interface_name, None)
                    bond_member_of = bond_info['bond_name'] if bond_info else None

                    # Get NetBox state and diff (normal mode - will clear tagged VLANs)
                    try:
                        netbox_state = self._get_netbox_current_state(device, actual_interface_name, primary_vlan_id, mode='normal')

                        bond_info_for_netbox = None
                        bond_name_for_netbox = None
                        if bond_member_of:
                            bond_info_for_netbox = self._get_bond_interface_for_member(device, actual_interface_name, platform=platform)
                            bond_name_for_netbox = bond_member_of

                        netbox_diff = self._generate_netbox_diff(
                            netbox_state,
                            netbox_state['proposed'],
                            bond_info=bond_info_for_netbox,
                            interface_name=actual_interface_name,
                            bond_name=bond_name_for_netbox
                        )

                        if netbox_diff and netbox_diff != "No changes (NetBox already has this configuration)":
                            current = netbox_state.get('current', {})
                            proposed = netbox_state.get('proposed', {})

                            # Extract VLAN changes
                            current_untagged = current.get('untagged_vlan')
                            proposed_untagged = proposed.get('untagged_vlan')
                            current_tagged = current.get('tagged_vlans', [])
                            proposed_tagged = proposed.get('tagged_vlans', [])

                            # Group by bond status
                            if bond_member_of:
                                # Member interface - VLANs will be removed
                                group_key = (bond_member_of, 'member_clear')
                                if group_key not in netbox_groups:
                                    netbox_groups[group_key] = []
                                netbox_groups[group_key].append({
                                    'interface': actual_interface_name,
                                    'current_untagged': current_untagged,
                                    'proposed_untagged': proposed_untagged,
                                    'current_tagged': current_tagged,
                                    'proposed_tagged': proposed_tagged
                                })

                                # Bond interface - VLANs will be added
                                group_key = (bond_member_of, 'bond_add')
                                if group_key not in netbox_groups:
                                    netbox_groups[group_key] = []
                                # Only add bond once (check if not already added)
                                if not any(item['interface'] == bond_member_of for item in netbox_groups[group_key]):
                                    netbox_groups[group_key].append({
                                        'interface': bond_member_of,
                                        'current_untagged': None,  # Bond doesn't have VLANs yet
                                        'proposed_untagged': primary_vlan_id,  # Will get the VLAN from form
                                        'current_tagged': [],
                                        'proposed_tagged': tagged_vlan_ids if tagged_vlan_ids else []
                                    })
                            else:
                                # Standalone interface
                                group_key = ('standalone', 'update')
                                if group_key not in netbox_groups:
                                    netbox_groups[group_key] = []
                                netbox_groups[group_key].append({
                                    'interface': actual_interface_name,
                                    'current_untagged': current_untagged,
                                    'proposed_untagged': proposed_untagged,
                                    'current_tagged': current_tagged,
                                    'proposed_tagged': proposed_tagged
                                })
                    except Exception as e:
                        logger.debug(f"Could not generate NetBox diff for {actual_interface_name}: {e}")

                # Display grouped NetBox changes
                if netbox_groups:
                    # First show member interface changes (VLANs being removed)
                    member_groups = {k: v for k, v in netbox_groups.items() if k[1] == 'member_clear'}
                    if member_groups:
                        device_logs.append("Member Interfaces (VLANs will be REMOVED and migrated to bond):")
                        device_logs.append("")
                        for (bond_name, change_type), interfaces in sorted(member_groups.items()):
                            for item in interfaces:
                                iface = item['interface']
                                curr_untag = item['current_untagged']
                                prop_untag = item['proposed_untagged']
                                curr_tag = item['current_tagged']
                                prop_tag = item['proposed_tagged']

                                changes = []
                                if curr_untag != prop_untag:
                                    changes.append(f"Untagged VLAN {curr_untag} → {prop_untag}")
                                if curr_tag != prop_tag:
                                    curr_tag_str = f"[{', '.join(map(str, curr_tag))}]" if curr_tag else "[]"
                                    prop_tag_str = f"[{', '.join(map(str, prop_tag))}]" if prop_tag else "[]"
                                    changes.append(f"Tagged VLANs {curr_tag_str} → {prop_tag_str}")

                                if changes:
                                    device_logs.append(f"  {iface}: {', '.join(changes)}")
                        device_logs.append("")

                    # Then show bond interface changes (VLANs being added)
                    bond_groups = {k: v for k, v in netbox_groups.items() if k[1] == 'bond_add'}
                    if bond_groups:
                        device_logs.append("Bond Interfaces (VLANs will be ADDED):")
                        device_logs.append("")
                        for (bond_name, change_type), interfaces in sorted(bond_groups.items()):
                            for item in interfaces:
                                iface = item['interface']
                                curr_untag = item['current_untagged']
                                prop_untag = item['proposed_untagged']
                                curr_tag = item['current_tagged']
                                prop_tag = item['proposed_tagged']

                                changes = []
                                if curr_untag != prop_untag:
                                    changes.append(f"Untagged VLAN {curr_untag} → {prop_untag}")
                                if curr_tag != prop_tag:
                                    curr_tag_str = f"[{', '.join(map(str, curr_tag))}]" if curr_tag else "[]"
                                    prop_tag_str = f"[{', '.join(map(str, prop_tag))}]" if prop_tag else "[]"
                                    changes.append(f"Tagged VLANs {curr_tag_str} → {prop_tag_str}")

                                if changes:
                                    device_logs.append(f"  {iface}: {', '.join(changes)}")
                        device_logs.append("")

                    # Finally show standalone interface changes
                    standalone_groups = {k: v for k, v in netbox_groups.items() if k[1] == 'update'}
                    if standalone_groups:
                        device_logs.append("Standalone Interfaces (VLAN updates):")
                        device_logs.append("")
                        for (group_name, change_type), interfaces in sorted(standalone_groups.items()):
                            for item in interfaces:
                                iface = item['interface']
                                curr_untag = item['current_untagged']
                                prop_untag = item['proposed_untagged']
                                curr_tag = item['current_tagged']
                                prop_tag = item['proposed_tagged']

                                changes = []
                                if curr_untag != prop_untag:
                                    changes.append(f"Untagged VLAN {curr_untag} → {prop_untag}")
                                if curr_tag != prop_tag:
                                    curr_tag_str = f"[{', '.join(map(str, curr_tag))}]" if curr_tag else "[]"
                                    prop_tag_str = f"[{', '.join(map(str, prop_tag))}]" if prop_tag else "[]"
                                    changes.append(f"Tagged VLANs {curr_tag_str} → {prop_tag_str}")

                                if changes:
                                    device_logs.append(f"  {iface}: {', '.join(changes)}")
                        device_logs.append("")
                else:
                    device_logs.append("(no NetBox changes)")
                device_logs.append("")

                # Show device-level pre-deployment checks from Nornir baseline
                device_logs.append("=" * 80)
                device_logs.append("PRE-DEPLOYMENT CHECKS (from Nornir baseline)")
                device_logs.append("=" * 80)
                device_logs.append("")

                # Get baseline data from Nornir deployment results
                # Try to get from first interface, but also check other interfaces if first one doesn't have baseline
                baseline_data = first_interface_result.get('baseline', {})
                
                # If baseline is empty, try to find it in other interface results
                if not baseline_data or (not baseline_data.get('uptime') and not baseline_data.get('interfaces')):
                    for interface_name in device_interfaces[1:]:  # Skip first one, already checked
                        interface_result = device_results.get(interface_name, {})
                        candidate_baseline = interface_result.get('baseline', {})
                        if candidate_baseline and (candidate_baseline.get('uptime') or candidate_baseline.get('interfaces')):
                            baseline_data = candidate_baseline
                            logger.debug(f"Found baseline data in interface {interface_name} result")
                            break

                # 1. Device Connection & Uptime (from baseline)
                device_logs.append("1. Device Connection & Uptime:")
                uptime_data = baseline_data.get('uptime')
                if uptime_data and uptime_data != -1:
                    device_logs.append(f"   [OK] Connected successfully")
                    # Format uptime nicely
                    uptime_seconds = int(uptime_data) if uptime_data else 0
                    uptime_days = uptime_seconds // 86400
                    uptime_hours = (uptime_seconds % 86400) // 3600
                    uptime_mins = (uptime_seconds % 3600) // 60
                    if uptime_days > 0:
                        uptime_str = f"{uptime_days}d {uptime_hours}h {uptime_mins}m ({uptime_seconds}s)"
                    elif uptime_hours > 0:
                        uptime_str = f"{uptime_hours}h {uptime_mins}m ({uptime_seconds}s)"
                    else:
                        uptime_str = f"{uptime_mins}m ({uptime_seconds}s)"
                    device_logs.append(f"   Uptime: {uptime_str}")
                else:
                    device_logs.append(f"   [INFO] Uptime data not available")
                device_logs.append("")

                # 2. Interface State (from baseline)
                # Handle both baseline['interface'] (single) and baseline['interfaces'] (multiple)
                device_logs.append("2. Interface State:")
                interface_baseline = baseline_data.get('interface', {})
                if not interface_baseline and 'interfaces' in baseline_data and baseline_data['interfaces']:
                    # Use first successful interface from baseline['interfaces'] (skip ones with errors)
                    for iface_name, iface_data in baseline_data['interfaces'].items():
                        if 'error' not in iface_data:
                            interface_baseline = iface_data
                            logger.debug(f"Using baseline data from interface {iface_name}")
                            break
                    # If all have errors, use first one anyway for display
                    if not interface_baseline and baseline_data['interfaces']:
                        first_iface_name = next(iter(baseline_data['interfaces']))
                        interface_baseline = baseline_data['interfaces'][first_iface_name]
                
                if interface_baseline and 'error' not in interface_baseline:
                    is_up = interface_baseline.get('is_up', False)
                    is_enabled = interface_baseline.get('is_enabled', False)
                    status = "UP" if is_up else "DOWN"
                    admin_status = "Enabled" if is_enabled else "Disabled"
                    device_logs.append(f"   Status: {status} (Admin: {admin_status})")
                else:
                    device_logs.append(f"   [INFO] Interface state data not available")
                device_logs.append("")

                # 3. Traffic Statistics (from baseline)
                device_logs.append("3. Traffic Statistics:")
                if interface_baseline and 'error' not in interface_baseline:
                    in_pkts = interface_baseline.get('in_pkts', 0)
                    out_pkts = interface_baseline.get('out_pkts', 0)
                    in_bytes = interface_baseline.get('in_bytes', 0)
                    out_bytes = interface_baseline.get('out_bytes', 0)
                    if in_pkts or out_pkts or in_bytes or out_bytes:
                        device_logs.append(f"   RX: {in_pkts:,} pkts ({in_bytes:,} bytes)")
                        device_logs.append(f"   TX: {out_pkts:,} pkts ({out_bytes:,} bytes)")
                    else:
                        device_logs.append(f"   [INFO] No traffic detected (all counters are 0)")
                else:
                    device_logs.append(f"   [INFO] Traffic statistics not available")
                device_logs.append("")

                device_logs.append("=" * 80)
                device_logs.append("DEPLOYMENT EXECUTION")
                device_logs.append("=" * 80)
                device_logs.append("")

                # Add NAPALM deployment logs (from first interface - they're the same for all)
                if deployment_logs_from_napalm:
                    if isinstance(deployment_logs_from_napalm, list):
                        device_logs.extend(deployment_logs_from_napalm)
                    else:
                        device_logs.append(str(deployment_logs_from_napalm))
                device_logs.append("")

                # Get LLDP baseline from deployment results (collected during deployment)
                device_logs.append("4. LLDP Neighbors (Interface-Level Baseline):")
                baseline_data = first_interface_result.get('baseline', {})
                
                # Try to get per-interface LLDP data (new format)
                lldp_interfaces = baseline_data.get('lldp_interfaces', {})
                if lldp_interfaces:
                    # Show per-interface LLDP for deployed interfaces
                    for iface_name in sorted(lldp_interfaces.keys()):
                        iface_lldp = lldp_interfaces[iface_name]
                        neighbor_count = iface_lldp.get('count', 0)
                        neighbors = iface_lldp.get('neighbors', [])
                        
                        if neighbor_count > 0:
                            # Show neighbor hostnames if available
                            neighbor_hostnames = []
                            for neighbor in neighbors:
                                hostname = neighbor.get('hostname', '') or neighbor.get('remote_system_name', '')
                                if hostname:
                                    neighbor_hostnames.append(hostname)
                            
                            if neighbor_hostnames:
                                device_logs.append(f"   {iface_name}: {neighbor_count} neighbor(s) → {', '.join(neighbor_hostnames)}")
                            else:
                                device_logs.append(f"   {iface_name}: {neighbor_count} neighbor(s)")
                        else:
                            device_logs.append(f"   {iface_name}: No LLDP neighbors")
                else:
                    # Fallback to old format (device-level)
                    lldp_all_interfaces = baseline_data.get('lldp_all_interfaces', {})
                    if lldp_all_interfaces:
                        # Filter to only show interfaces we're deploying
                        for iface_name in sorted(device_interfaces):
                            if iface_name in lldp_all_interfaces:
                                neighbor_count = lldp_all_interfaces[iface_name]
                                if neighbor_count > 0:
                                    device_logs.append(f"   {iface_name}: {neighbor_count} neighbor(s)")
                                else:
                                    device_logs.append(f"   {iface_name}: No LLDP neighbors")
                    else:
                        device_logs.append("   (LLDP data not collected)")
                device_logs.append("")

                # Show interface details for each interface - GROUP SIMILAR INTERFACES
                device_logs.append("=" * 80)
                device_logs.append("INTERFACE DETAILS")
                device_logs.append("=" * 80)
                device_logs.append("")

                interface_statuses = []  # Track status for summary

                # Group interfaces by (deployment_status, bond_status, cable_status, traffic_status)
                interface_groups = {}  # Key: (status, bond_status, cable_status, traffic_status), Value: list of interface names
                interface_data_map = {}  # Store full data for each interface

                for actual_interface_name in device_interfaces:
                    interface_result = device_results.get(actual_interface_name, {})

                    # Determine deployment status
                    success = interface_result.get('success', False)
                    committed = interface_result.get('committed', False)
                    error = interface_result.get('error')

                    if success and committed:
                        status = "PASS"
                        interface_statuses.append("PASS")
                    elif success and not committed:
                        status = "WARN"
                        interface_statuses.append("WARN")
                    else:
                        status = "ERROR"
                        interface_statuses.append("ERROR")

                    # Get bond info
                    bond_info = bond_info_map.get(device.name, {}).get(actual_interface_name, None)
                    bond_member_of = bond_info['bond_name'] if bond_info else None
                    bond_status = f"bond:{bond_member_of}" if bond_member_of else "standalone"

                    # Get cable status
                    cable_status = "unknown"
                    connected_to = None
                    try:
                        interface_obj = Interface.objects.filter(device=device, name=actual_interface_name).first()
                        if interface_obj:
                            if interface_obj.cable:
                                cable_status = "connected"
                                if interface_obj.link_peers:
                                    peer_info = []
                                    for peer in interface_obj.link_peers:
                                        if hasattr(peer, 'device'):
                                            peer_info.append(f"{peer.device.name}")
                                    if peer_info:
                                        connected_to = ', '.join(peer_info)
                            else:
                                cable_status = "no_cable"
                    except Exception:
                        cable_status = "error"

                    # Get traffic status (Cumulus only)
                    traffic_status = "no_traffic"
                    traffic_info = None
                    target_interface_for_stats = bond_member_of if bond_member_of else actual_interface_name
                    if platform == 'cumulus':
                        pre_traffic_stats = self._check_interface_traffic_stats(device, target_interface_for_stats, platform, bond_interface=None)
                        if pre_traffic_stats.get('has_traffic'):
                            traffic_status = "has_traffic"
                            in_pkts = pre_traffic_stats.get('in_pkts_total', 0)
                            out_pkts = pre_traffic_stats.get('out_pkts_total', 0)
                            in_bytes = pre_traffic_stats.get('in_bytes_total', 0)
                            out_bytes = pre_traffic_stats.get('out_bytes_total', 0)
                            traffic_info = f"RX: {in_pkts:,} pkts ({in_bytes:,} bytes), TX: {out_pkts:,} pkts ({out_bytes:,} bytes)"
                        elif pre_traffic_stats.get('error'):
                            traffic_status = "error"
                            traffic_info = pre_traffic_stats.get('error')

                    # Group by status, bond, cable, traffic
                    group_key = (status, bond_status, cable_status, traffic_status)
                    if group_key not in interface_groups:
                        interface_groups[group_key] = []
                    interface_groups[group_key].append(actual_interface_name)

                    # Store data for later display
                    interface_data_map[actual_interface_name] = {
                        'status': status,
                        'bond_member_of': bond_member_of,
                        'cable_status': cable_status,
                        'connected_to': connected_to,
                        'traffic_status': traffic_status,
                        'traffic_info': traffic_info,
                        'target_interface_for_stats': target_interface_for_stats,
                        'error': error
                    }

                # Display grouped interfaces
                for group_key, interface_names in sorted(interface_groups.items()):
                    status, bond_status, cable_status, traffic_status = group_key

                    # Show group header
                    if len(interface_names) == 1:
                        device_logs.append(f"--- Interface: {interface_names[0]} ---")
                    else:
                        device_logs.append(f"--- Interfaces: {', '.join(sorted(interface_names))} ({len(interface_names)} interfaces) ---")
                    device_logs.append("")

                    # Get data from first interface in group (all should be same)
                    first_iface = interface_names[0]
                    iface_data = interface_data_map[first_iface]

                    # Show bond info
                    if iface_data['bond_member_of']:
                        device_logs.append(f"  Bond Detection:")
                        device_logs.append(f"    [INFO] Member of bond '{iface_data['bond_member_of']}'")
                        device_logs.append(f"    Target: VLAN config applied to '{iface_data['bond_member_of']}'")
                        device_logs.append("")

                    # Show cable status
                    device_logs.append(f"  Physical Connectivity:")
                    if cable_status == "connected":
                        device_logs.append(f"    [OK] Cable connected")
                        if iface_data['connected_to']:
                            device_logs.append(f"    Connected to: {iface_data['connected_to']}")
                    elif cable_status == "no_cable":
                        device_logs.append(f"    [WARN] No cable detected in NetBox")
                    else:
                        device_logs.append(f"    (unable to check cable status)")
                    device_logs.append("")

                    # Show traffic status (Cumulus only)
                    if platform == 'cumulus':
                        device_logs.append(f"  Traffic Statistics (on {iface_data['target_interface_for_stats']}):")
                        if traffic_status == "has_traffic":
                            device_logs.append(f"    {iface_data['traffic_info']}")
                            device_logs.append(f"    [WARN] Active traffic detected - deployment will disrupt traffic!")
                        elif traffic_status == "error":
                            device_logs.append(f"    (traffic statistics not available: {iface_data['traffic_info']})")
                        else:
                            device_logs.append(f"    [OK] No active traffic detected")
                        device_logs.append("")

                    # Show deployment status
                    device_logs.append(f"  Deployment Status:")
                    if status == "PASS":
                        device_logs.append(f"    [OK] Successfully deployed and committed")
                    elif status == "WARN":
                        device_logs.append(f"    [WARN] Deployed but not committed")
                    else:
                        device_logs.append(f"    [ERROR] Deployment failed")
                        if iface_data['error']:
                            device_logs.append(f"    Error: {iface_data['error']}")
                        # Show traceback if available (for debugging)
                        interface_result = device_results.get(first_iface, {})
                        if 'traceback' in interface_result:
                            device_logs.append(f"    ")
                            device_logs.append(f"    Full Traceback:")
                            for line in interface_result['traceback'].split('\n'):
                                if line.strip():
                                    device_logs.append(f"      {line}")
                    device_logs.append("")

                # INTERFACE-LEVEL POST-DEPLOYMENT CHECKS
                device_logs.append("=" * 80)
                device_logs.append("INTERFACE-LEVEL POST-DEPLOYMENT CHECKS")
                device_logs.append("=" * 80)
                device_logs.append("")

                # Collect post-deployment data for all interfaces
                post_deployment_data = {}
                for actual_interface_name in device_interfaces:
                    interface_result = device_results.get(actual_interface_name, {})

                    # Only check interfaces that were successfully deployed
                    if not (interface_result.get('success') and interface_result.get('committed')):
                        continue

                    bond_info = bond_info_map.get(device.name, {}).get(actual_interface_name, None)
                    bond_member_of = bond_info['bond_name'] if bond_info else None
                    target_interface_for_checks = bond_member_of if bond_member_of else actual_interface_name

                    # Skip if we already checked this bond
                    if target_interface_for_checks in post_deployment_data:
                        continue

                    post_data = {}

                    # 1. Verify VLAN Configuration (on target interface - bond or physical)
                    # IMPORTANT: Use target_interface_for_checks (bond if detected) not actual_interface_name (member)
                    # because VLAN config is applied to the bond interface, not the member interface
                    try:
                        device_config_result = self._get_current_device_config(device, target_interface_for_checks, platform)
                        current_config = device_config_result.get('current_config', '')

                        # Parse current VLAN from config
                        current_vlan = None
                        if platform == 'cumulus' and 'access' in current_config:
                            import re
                            match = re.search(r'access\s+(\d+)', current_config)
                            if match:
                                current_vlan = int(match.group(1))

                        # Check if it matches expected VLAN
                        expected_vlan = untagged_vlan_id
                        vlan_matches = (current_vlan == expected_vlan)
                        post_data['current_vlan'] = current_vlan
                        post_data['expected_vlan'] = expected_vlan
                        post_data['vlan_matches'] = vlan_matches
                    except Exception as e:
                        post_data['vlan_error'] = str(e)

                    # 2. Interface State - collected in Nornir deployment baseline/verification
                    # Get from deployment result instead of re-collecting
                    post_data['interface_state'] = {'info': 'Collected in Nornir deployment'}

                    # 3. Traffic Statistics - collected in Nornir deployment baseline/verification
                    # Get from deployment result instead of re-collecting
                    if platform == 'cumulus':
                        post_data['traffic_stats'] = {'info': 'Collected in Nornir deployment'}

                    post_deployment_data[target_interface_for_checks] = post_data

                # Display post-deployment checks
                if post_deployment_data:
                    device_logs.append("1. VLAN Configuration Verification:")
                    for target_iface, post_data in sorted(post_deployment_data.items()):
                        if 'vlan_error' in post_data:
                            device_logs.append(f"   {target_iface}: [ERROR] {post_data['vlan_error']}")
                        elif post_data.get('vlan_matches'):
                            device_logs.append(f"   {target_iface}: [OK] VLAN {post_data['current_vlan']} applied successfully")
                        else:
                            expected = post_data.get('expected_vlan', 'N/A')
                            actual = post_data.get('current_vlan', 'None')
                            device_logs.append(f"   {target_iface}: [WARN] Expected VLAN {expected}, found {actual}")
                    device_logs.append("")

                    device_logs.append("2. Interface State:")
                    for target_iface, post_data in sorted(post_deployment_data.items()):
                        iface_state = post_data.get('interface_state', {})
                        if iface_state.get('error'):
                            device_logs.append(f"   {target_iface}: [WARN] {iface_state['error']}")
                        elif iface_state.get('is_up'):
                            device_logs.append(f"   {target_iface}: [OK] UP")
                        else:
                            device_logs.append(f"   {target_iface}: [WARN] DOWN")
                    device_logs.append("")

                    if platform == 'cumulus':
                        device_logs.append("3. Traffic Analysis:")
                        for target_iface, post_data in sorted(post_deployment_data.items()):
                            traffic_stats = post_data.get('traffic_stats', {})
                            if traffic_stats.get('error'):
                                device_logs.append(f"   {target_iface}: [WARN] {traffic_stats['error']}")
                            elif traffic_stats.get('has_traffic'):
                                in_pkts = traffic_stats.get('in_pkts_total', 0)
                                out_pkts = traffic_stats.get('out_pkts_total', 0)
                                device_logs.append(f"   {target_iface}: [OK] Traffic resumed (RX: {in_pkts:,} pkts, TX: {out_pkts:,} pkts)")
                            else:
                                device_logs.append(f"   {target_iface}: [INFO] No traffic detected")
                        device_logs.append("")
                else:
                    device_logs.append("[INFO] No successfully deployed interfaces to verify")
                    device_logs.append("")

                # Add device summary
                device_logs.append("=" * 80)
                device_logs.append("DEVICE SUMMARY")
                device_logs.append("=" * 80)
                device_logs.append("")
                device_logs.append(f"Total Interfaces: {len(device_interfaces)}")

                # Count statuses
                pass_count = interface_statuses.count("PASS")
                warn_count = interface_statuses.count("WARN")
                error_count = interface_statuses.count("ERROR")

                device_logs.append(f"  PASS: {pass_count}")
                device_logs.append(f"  WARN: {warn_count}")
                device_logs.append(f"  ERROR: {error_count}")
                device_logs.append("")

                # Determine overall device status
                if error_count > 0:
                    overall_device_status = "ERROR"
                    overall_device_status_text = "ERROR"
                elif warn_count > 0:
                    overall_device_status = "warning"
                    overall_device_status_text = "WARN"
                else:
                    overall_device_status = "success"
                    overall_device_status_text = "PASS"

                # Determine if NetBox should be updated
                netbox_updated = "No"
                if update_netbox and pass_count > 0:
                    # Update NetBox for all successfully deployed interfaces
                    device_logs.append("=" * 80)
                    device_logs.append("NETBOX UPDATE")
                    device_logs.append("=" * 80)
                    device_logs.append("")

                    # BOND CREATION: Use bonds_to_create_in_netbox tracked during early detection
                    # This handles bonds that were detected on device but not in NetBox
                    if device.name in bonds_to_create_in_netbox:
                        device_bonds = bonds_to_create_in_netbox[device.name]
                        for bond_name, bond_data in device_bonds.items():
                            # Only create bond if deployment succeeded for at least one member
                            deployment_succeeded = False
                            for member_name in bond_data['members']:
                                if member_name in device_interfaces:
                                    interface_result = device_results.get(member_name, {})
                                    if interface_result.get('success') and interface_result.get('committed'):
                                        deployment_succeeded = True
                                        break
                            
                            if deployment_succeeded:
                                device_logs.append(f"[BOND] Creating bond {bond_name} in NetBox and migrating VLANs...")
                                device_logs.append(f"     Bond members: {', '.join(bond_data['members'])}")
                                sync_result = self._sync_bond_to_netbox(
                                    device=device,
                                    bond_name=bond_name,
                                    member_interfaces=bond_data['members'],
                                    platform=platform,
                                    migrate_vlans=True  # Migrate all VLANs from member interfaces to bond
                                )
                                if sync_result.get('success'):
                                    device_logs.append(f"[OK] Bond {bond_name} created in NetBox")
                                    device_logs.append(f"     Members added: {len(bond_data['members'])} ({', '.join(bond_data['members'])})")
                                    vlans_migrated = sync_result.get('vlans_migrated', 0)
                                    members_cleared = sync_result.get('members_cleared', 0)
                                    if vlans_migrated > 0:
                                        device_logs.append(f"     VLANs migrated to bond: {vlans_migrated}")
                                    if members_cleared > 0:
                                        device_logs.append(f"     Member interfaces cleared: {members_cleared}")
                                    netbox_updated = "Yes"
                                else:
                                    device_logs.append(f"[ERROR] Failed to create bond {bond_name}: {sync_result.get('error')}")
                                device_logs.append("")
                            else:
                                device_logs.append(f"[WARN] Skipping bond {bond_name} creation - deployment did not succeed for any members")
                                device_logs.append("")
                    
                    # Also check for bonds that might have been missed (fallback to old method)
                    # This handles edge cases where bonds were detected during deployment but not tracked earlier
                    bonds_to_sync_fallback = {}  # {bond_name: [member_interfaces]}
                    for actual_interface_name in device_interfaces:
                        interface_result = device_results.get(actual_interface_name, {})
                        if interface_result.get('success') and interface_result.get('committed'):
                            # Skip if already handled by bonds_to_create_in_netbox
                            bond_info = bond_info_map.get(device.name, {}).get(actual_interface_name, None)
                            if bond_info:
                                bond_name = bond_info['bond_name']
                                # Check if this bond was already handled
                                if device.name in bonds_to_create_in_netbox and bond_name in bonds_to_create_in_netbox[device.name]:
                                    continue  # Already handled above
                            
                            # Check if device has bond but NetBox doesn't (fallback detection)
                            bond_info = self._get_bond_interface_for_member(device, actual_interface_name, platform=platform)
                            if bond_info and bond_info.get('netbox_missing_bond'):
                                bond_name = bond_info['bond_name']
                                all_members = bond_info.get('all_members', [actual_interface_name])
                                if bond_name not in bonds_to_sync_fallback:
                                    bonds_to_sync_fallback[bond_name] = all_members

                    # Sync bonds to NetBox (fallback method - for bonds detected during deployment)
                    for bond_name, members in bonds_to_sync_fallback.items():
                        device_logs.append(f"[BOND] Creating bond {bond_name} in NetBox (fallback detection) and migrating VLANs...")
                        sync_result = self._sync_bond_to_netbox(
                            device=device,
                            bond_name=bond_name,
                            member_interfaces=members,
                            platform=platform,
                            migrate_vlans=True  # Migrate all VLANs from member interfaces to bond
                        )
                        if sync_result.get('success'):
                            device_logs.append(f"[OK] Bond {bond_name} created in NetBox")
                            device_logs.append(f"     Members added: {len(members)} ({', '.join(members)})")
                            vlans_migrated = sync_result.get('vlans_migrated', 0)
                            members_cleared = sync_result.get('members_cleared', 0)
                            if vlans_migrated > 0:
                                device_logs.append(f"     VLANs migrated to bond: {vlans_migrated}")
                            if members_cleared > 0:
                                device_logs.append(f"     Member interfaces cleared: {members_cleared}")
                            netbox_updated = "Yes"
                        else:
                            device_logs.append(f"[ERROR] Failed to create bond {bond_name}: {sync_result.get('error')}")
                        device_logs.append("")

                    for actual_interface_name in device_interfaces:
                        interface_result = device_results.get(actual_interface_name, {})
                        if interface_result.get('success') and interface_result.get('committed'):
                            try:
                                # Check if this interface is a bond member
                                bond_info = bond_info_map.get(device.name, {}).get(actual_interface_name, None)
                                bond_member_of = bond_info['bond_name'] if bond_info else None

                                # If interface is bond member, update bond instead of member interface
                                if bond_member_of:
                                    target_interface_name = bond_member_of
                                    device_logs.append(f"[INFO] {actual_interface_name} is member of {bond_member_of}, updating bond instead")
                                else:
                                    target_interface_name = actual_interface_name

                                interface_obj = Interface.objects.get(device=device, name=target_interface_name)

                                # Update untagged VLAN
                                if untagged_vlan_id and vlan:
                                    interface_obj.untagged_vlan = vlan
                                    interface_obj.mode = 'access'
                                    interface_obj.save()
                                    device_logs.append(f"[OK] Updated {target_interface_name}: untagged VLAN {untagged_vlan_id}")
                                    netbox_updated = "Yes"

                                # Update tagged VLANs if any
                                if tagged_vlan_ids:
                                    # Check current tagged VLANs in NetBox
                                    current_tagged_vids = set(interface_obj.tagged_vlans.values_list('vid', flat=True))
                                    new_tagged_vids = set(tagged_vlan_ids)

                                    if current_tagged_vids == new_tagged_vids:
                                        # Tagged VLANs already match - no update needed
                                        device_logs.append(f"[INFO] {target_interface_name}: tagged VLANs {sorted(tagged_vlan_ids)} already present in NetBox")
                                    else:
                                        # Update tagged VLANs
                                        interface_obj.tagged_vlans.clear()
                                        vlans_added = []
                                        for tagged_vlan_id in tagged_vlan_ids:
                                            tagged_vlan_obj = VLAN.objects.filter(vid=tagged_vlan_id).first()
                                            if tagged_vlan_obj:
                                                interface_obj.tagged_vlans.add(tagged_vlan_obj)
                                                vlans_added.append(tagged_vlan_id)
                                        interface_obj.mode = 'tagged-all' if not untagged_vlan_id else 'tagged'
                                        interface_obj.save()

                                        # Log what changed
                                        if current_tagged_vids:
                                            device_logs.append(f"[OK] Updated {target_interface_name}: tagged VLANs {sorted(current_tagged_vids)} → {sorted(vlans_added)}")
                                        else:
                                            device_logs.append(f"[OK] Updated {target_interface_name}: added tagged VLANs {sorted(vlans_added)}")
                                        netbox_updated = "Yes"
                            except Interface.DoesNotExist:
                                device_logs.append(f"[WARN] Interface {target_interface_name} not found in NetBox")
                            except Exception as e:
                                device_logs.append(f"[ERROR] Failed to update {target_interface_name}: {e}")

                    device_logs.append("")

                # Create ONE result entry for this device
                results.append({
                    "device": device,
                    "interface": f"{len(device_interfaces)} interfaces",
                    "vlan_id": primary_vlan_id,
                    "vlan_name": vlan.name if vlan else 'N/A',
                    "status": overall_device_status,
                    "config_applied": "Yes" if pass_count > 0 else "No",
                    "netbox_updated": netbox_updated,
                    "message": f"{pass_count} PASS, {warn_count} WARN, {error_count} ERROR",
                    "deployment_logs": '\n'.join(device_logs),
                    "device_status": overall_device_status_text,
                    "interface_status": overall_device_status_text,
                    "overall_status": overall_device_status_text,
                    "risk_level": "HIGH" if error_count > 0 else "MEDIUM" if warn_count > 0 else "LOW",
                    "dry_run": False,
                })

            logger.info(f"[DEPLOYMENT] Generated {len(results)} device-level results")
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

    def _generate_vlan_config(self, interface_name, untagged_vlan=None, tagged_vlans=None, platform=None, include_bridge_vlan=True, device=None, bridge_vlans=None, vlan_id=None):
        """
        Generate platform-specific VLAN configuration command.

        For Cumulus: Adds VLANs to bridge first (additive), then sets interface access/tagged VLANs.
        For EOS: Sets interface access/tagged VLANs directly.

        If interface is a bond member, applies config to bond interface instead.
        If bond migration is needed (NetBox has bond_Swp1 but device has bond1),
        generates commands to create bond_Swp1 and migrate all members.

        Supported platforms:
        - cumulus: Cumulus Linux NVUE
        - eos: Arista EOS

        Args:
            interface_name: Interface name (e.g., 'bond1', 'Ethernet1', 'swp3')
            untagged_vlan: Untagged VLAN ID (1-4094) or None
            tagged_vlans: List of tagged VLAN IDs (1-4094) or None
            platform: Platform type ('cumulus' or 'eos')
            include_bridge_vlan: If True, add bridge VLAN command for Cumulus (default: True)
            device: Device object (optional, required to check bond membership and bridge VLANs)
            bridge_vlans: List of existing bridge VLANs (optional, if not provided will fetch from device)
            vlan_id: DEPRECATED - Single VLAN ID for backward compatibility (use untagged_vlan instead)

        Returns:
            str: Configuration command(s) for the platform (newline-separated)
        """
        # Backward compatibility: if vlan_id is provided but untagged_vlan is not, use vlan_id
        if vlan_id is not None and untagged_vlan is None:
            untagged_vlan = vlan_id

        # Ensure we have at least one VLAN
        if untagged_vlan is None and (not tagged_vlans or len(tagged_vlans) == 0):
            raise ValueError("At least one VLAN (untagged or tagged) must be provided")

        # Normalize tagged_vlans to list of ints
        if tagged_vlans is None:
            tagged_vlans = []
        elif not isinstance(tagged_vlans, list):
            tagged_vlans = list(tagged_vlans)

        # Convert VLAN objects to IDs if needed
        if untagged_vlan and hasattr(untagged_vlan, 'vid'):
            untagged_vlan = untagged_vlan.vid
        tagged_vlans = [v.vid if hasattr(v, 'vid') else v for v in tagged_vlans]
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

            # BOND CREATION LOGIC - Handle all scenarios
            if bond_info:
                bond_name = bond_info['bond_name']
                netbox_bond_name = bond_info.get('netbox_bond_name')
                device_bond_name = bond_info.get('device_bond_name')
                netbox_missing_bond = bond_info.get('netbox_missing_bond', False)
                needs_migration = bond_info.get('needs_migration', False)
                all_members = bond_info.get('all_members', [])
                netbox_members = bond_info.get('netbox_members', [])

                # Scenario 1: NetBox has bond but device doesn't - CREATE BOND ON DEVICE
                if netbox_bond_name and not device_bond_name:
                    # Use NetBox members if available, otherwise use current interface
                    members_to_add = netbox_members if netbox_members else [interface_name]

                    commands.append("#" + "=" * 60)
                    commands.append("# BOND CREATION - NetBox has bond, device doesn't")
                    commands.append("#" + "=" * 60)
                    commands.append(f"# Creating bond {netbox_bond_name} on device (from NetBox)")
                    commands.append(f"# Member interface: {interface_name}")
                    commands.append("")
                    commands.append(f"nv set interface {netbox_bond_name} type bond")

                    # Add all members
                    for member in members_to_add:
                        commands.append(f"nv set interface {netbox_bond_name} bond member {member}")

                    # LACP settings
                    commands.append(f"nv set interface {netbox_bond_name} bond lacp-rate fast")
                    commands.append(f"nv set interface {netbox_bond_name} bond lacp-bypass on")

                    # Add bond to bridge domain
                    commands.append(f"nv set interface {netbox_bond_name} bridge domain br_default")
                    commands.append("")

                    # Remove VLANs from member interfaces (VLANs will be on bond instead)
                    commands.append(f"# VLAN MIGRATION: Removing VLANs from member interface {interface_name}")
                    commands.append(f"nv unset interface {interface_name} bridge domain br_default access")
                    commands.append("")

                # Scenario 2: Device has bond but NetBox doesn't - will be synced to NetBox later
                # (handled in deployment/dry run by calling _sync_bond_to_netbox)
                elif device_bond_name and not netbox_bond_name:
                    # NetBox will be updated, but device already has bond - no device commands needed
                    # Just add a comment for clarity and remove VLANs from member interface
                    commands.append("#" + "=" * 60)
                    commands.append("# BOND SYNC - Device has bond, NetBox doesn't")
                    commands.append("#" + "=" * 60)
                    commands.append(f"# Bond {device_bond_name} exists on device")
                    commands.append(f"# Bond will be created in NetBox during deployment")
                    commands.append(f"# Member interface: {interface_name}")
                    commands.append("")
                    commands.append(f"# VLAN MIGRATION: Removing VLANs from member interface {interface_name}")
                    commands.append(f"nv unset interface {interface_name} bridge domain br_default access")
                    commands.append("")

                # Scenario 3: Both have bond but different names - MIGRATE TO NETBOX BOND NAME
                elif needs_migration and netbox_bond_name != device_bond_name:
                    commands.append("#" + "=" * 60)
                    commands.append("# BOND MIGRATION - Different bond names")
                    commands.append("#" + "=" * 60)
                    commands.append(f"# Migrating from device bond '{device_bond_name}' to NetBox bond '{netbox_bond_name}'")
                    commands.append(f"# All members will be moved to new bond")
                    commands.append("")
                    commands.append(f"nv set interface {netbox_bond_name} type bond")

                    # Add all members to the new bond
                    for member in all_members:
                        commands.append(f"nv set interface {netbox_bond_name} bond member {member}")

                    # LACP settings
                    commands.append(f"nv set interface {netbox_bond_name} bond lacp-rate fast")
                    commands.append(f"nv set interface {netbox_bond_name} bond lacp-bypass on")

                    # Add bond to bridge domain
                    commands.append(f"nv set interface {netbox_bond_name} bridge domain br_default")
                    commands.append("")

                    # Remove VLANs from old device bond (VLANs will be on new NetBox bond)
                    commands.append(f"# VLAN MIGRATION: Removing VLANs from old bond {device_bond_name}")
                    commands.append(f"nv unset interface {device_bond_name} bridge domain br_default access")
                    commands.append("")

                # Scenario 4: Both have same bond - no bond creation needed, just VLAN config
                # But still need to remove VLANs from member interface
                elif netbox_bond_name and device_bond_name and netbox_bond_name == device_bond_name:
                    commands.append("#" + "=" * 60)
                    commands.append("# BOND EXISTS - Same bond in NetBox and device")
                    commands.append("#" + "=" * 60)
                    commands.append(f"# Bond {bond_name} exists in both NetBox and device")
                    commands.append(f"# No bond creation needed, only VLAN configuration")
                    commands.append("")
                    commands.append(f"# VLAN MIGRATION: Removing VLANs from member interface {interface_name}")
                    commands.append(f"nv unset interface {interface_name} bridge domain br_default access")
                    commands.append("")
                # (falls through to VLAN config below)

            # ISSUE 1 FIX: Add VLANs to bridge first (additive - safe, won't remove existing VLANs)
            # But only if they don't already exist in bridge VLANs
            vlans_already_in_bridge = []  # Track VLANs already in bridge for logging
            vlans_to_add_to_bridge = []   # Track VLANs to be added to bridge for logging

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

                # Collect all VLANs that need to be added to bridge
                all_vlans_to_add = set()
                if untagged_vlan:
                    all_vlans_to_add.add(untagged_vlan)
                for vlan in tagged_vlans:
                    all_vlans_to_add.add(vlan)

                # Only add bridge VLAN command if VLAN doesn't already exist
                # bridge_vlans can be: list of ints, list of strings like "3019-3099" or "10,3000-3199", or mixed
                for vlan in all_vlans_to_add:
                    if not self._is_vlan_in_bridge_vlans(vlan, bridge_vlans):
                        commands.append(f"nv set bridge domain br_default vlan {vlan}")
                        vlans_to_add_to_bridge.append(vlan)
                        logger.debug(f"VLAN {vlan} not in bridge - will add")
                    else:
                        vlans_already_in_bridge.append(vlan)
                        logger.debug(f"VLAN {vlan} already exists in bridge (range or individual) - skipping bridge VLAN command")

                # Add informational comment about bridge VLANs
                if vlans_already_in_bridge:
                    commands.append(f"# Bridge VLANs already present: {', '.join(map(str, sorted(vlans_already_in_bridge)))}")
                if vlans_to_add_to_bridge:
                    commands.append(f"# Bridge VLANs to be added: {', '.join(map(str, sorted(vlans_to_add_to_bridge)))}")

            # Set interface VLAN configuration - use target_interface (bond if member, NetBox bond name if migration)
            # IMPORTANT: In Cumulus NVUE:
            # - Untagged VLAN (access mode): nv set interface {iface} bridge domain br_default access {vlan_id}
            # - Tagged VLANs: ONLY exist at bridge domain level, NOT at interface level
            # - Tagged VLANs are added to bridge domain above, interface just needs to be in bridge

            if untagged_vlan:
                # Set interface to access mode with untagged VLAN
                commands.append(f"nv set interface {target_interface} bridge domain br_default access {untagged_vlan}")

            # NOTE: Tagged VLANs are already added to bridge domain above (lines 5607-5652)
            # In Cumulus, tagged VLANs do NOT have interface-level configuration
            # They are only configured at bridge domain level

            # Return as newline-separated string for compatibility
            return "\n".join(commands)

        elif platform == 'eos':
            # Arista EOS commands (hierarchical config format for NAPALM)
            # NAPALM EOS expects config in "configure terminal" format
            # Use target_interface (bond if member)
            commands = [f"interface {target_interface}"]

            if untagged_vlan and not tagged_vlans:
                # Access mode: single untagged VLAN
                commands.append(f"   switchport mode access")
                commands.append(f"   switchport access vlan {untagged_vlan}")
            elif untagged_vlan or tagged_vlans:
                # Trunk mode: untagged VLAN (if any) + tagged VLANs
                commands.append(f"   switchport mode trunk")
                if untagged_vlan:
                    commands.append(f"   switchport trunk native vlan {untagged_vlan}")
                if tagged_vlans:
                    # For multiple tagged VLANs, use comma-separated list
                    tagged_vlans_str = ','.join(map(str, tagged_vlans))
                    commands.append(f"   switchport trunk allowed vlan {tagged_vlans_str}")

            return "\n".join(commands)

        else:
            # Unsupported platform
            raise ValueError(f"Unsupported platform: {platform}. Supported platforms: cumulus, eos")

    def _update_netbox_interface(self, device, interface_name, untagged_vlan=None, tagged_vlans=None):
        """
        Update NetBox interface with VLAN assignment.
        Replaces ALL existing configs that conflict with VLAN deployment to match device config.

        Args:
            device: Device object
            interface_name: Interface name
            untagged_vlan: VLAN object for untagged VLAN (optional)
            tagged_vlans: List of VLAN objects for tagged VLANs (optional)

        What we REMOVE/REPLACE (conflicts with VLAN deployment):
        - IP addresses (routed → bridged conversion)
        - VRF (routed → bridged conversion)
        - Old tagged VLANs (replaced with new tagged VLANs)
        - Old untagged VLAN (replaced with new untagged VLAN)
        - Old mode (replaced with 'tagged' if VLANs present, None if no VLANs)

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

                # Get old VLANs for logging
                old_untagged = interface.untagged_vlan.vid if interface.untagged_vlan else None
                old_tagged = list(interface.tagged_vlans.values_list('vid', flat=True))

                # Replace tagged VLANs
                interface.tagged_vlans.clear()
                if tagged_vlans:
                    for vlan_obj in tagged_vlans:
                        interface.tagged_vlans.add(vlan_obj)
                    if old_tagged:
                        removed_configs.append(f"Tagged VLANs: {', '.join(map(str, old_tagged))}")
                    logger.info(f"Set tagged VLANs {[v.vid for v in tagged_vlans]} on interface {interface_name} on {device.name}")
                elif old_tagged:
                    removed_configs.append(f"Tagged VLANs: {', '.join(map(str, old_tagged))}")
                    logger.info(f"Cleared tagged VLANs {old_tagged} from interface {interface_name} on {device.name}")

                # Replace untagged VLAN
                if old_untagged:
                    if untagged_vlan and old_untagged != untagged_vlan.vid:
                        removed_configs.append(f"Untagged VLAN {old_untagged}")
                        logger.info(f"Replacing untagged VLAN {old_untagged} with {untagged_vlan.vid} on interface {interface_name} on {device.name}")
                    elif not untagged_vlan:
                        removed_configs.append(f"Untagged VLAN {old_untagged}")
                        logger.info(f"Removing untagged VLAN {old_untagged} from interface {interface_name} on {device.name}")

                # Set new VLAN configuration
                interface.untagged_vlan = untagged_vlan

                # Set mode: 'tagged' if any VLANs are assigned, None if no VLANs
                if untagged_vlan or tagged_vlans:
                    old_mode = interface.mode if hasattr(interface, 'mode') else None
                    if old_mode != 'tagged':
                        if old_mode:
                            removed_configs.append(f"Mode {old_mode}")
                        interface.mode = 'tagged'
                        logger.info(f"Set mode to 'tagged' on interface {interface_name} on {device.name}")
                else:
                    # No VLANs - clear mode
                    old_mode = interface.mode if hasattr(interface, 'mode') else None
                    if old_mode:
                        removed_configs.append(f"Mode {old_mode}")
                    interface.mode = None
                    logger.info(f"Cleared mode on interface {interface_name} on {device.name} (no VLANs)")

                interface.save()

                vlan_info = []
                if untagged_vlan:
                    vlan_info.append(f"untagged_vlan={untagged_vlan.vid}")
                if tagged_vlans:
                    vlan_info.append(f"tagged_vlans={[v.vid for v in tagged_vlans]}")

                if removed_configs:
                    logger.info(f"Updated NetBox interface {interface_name} on {device.name}: removed {', '.join(removed_configs)}, set {', '.join(vlan_info) if vlan_info else 'no VLANs'}")
                else:
                    logger.info(f"Updated NetBox interface {interface_name} on {device.name}: set {', '.join(vlan_info) if vlan_info else 'no VLANs'}")

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

    def _sync_bond_to_netbox(self, device, bond_name, member_interfaces, platform=None, migrate_vlans=True):
        """
        Create or update bond interface in NetBox based on device configuration.
        Optionally migrates all VLANs (tagged + untagged) from member interfaces to bond.

        This is called:
        - In sync mode: When device has a bond but NetBox doesn't, or when bond exists but VLANs need migration (migrate_vlans=True)
        - In normal mode: When device has a bond but NetBox doesn't, to create bond structure only (migrate_vlans=False)

        Args:
            device: Device object
            bond_name: Bond interface name from device config (e.g., 'bond3')
            member_interfaces: List of interface names that are members of the bond
            platform: Platform type (optional)
            migrate_vlans: If True, migrate all VLANs from members to bond and clear members. If False, only create/update bond structure.

        Returns:
            dict: {
                "success": bool,
                "bond_created": bool,
                "members_added": int,
                "vlans_migrated": int,  # Number of VLANs migrated to bond (0 if migrate_vlans=False)
                "members_cleared": int,  # Number of member interfaces that had VLANs cleared (0 if migrate_vlans=False)
                "error": str or None
            }
        """
        try:
            from dcim.choices import InterfaceTypeChoices

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

                # Add member interfaces to the bond
                members_added = 0
                for member_name in member_interfaces:
                    try:
                        member_interface = Interface.objects.get(device=device, name=member_name)
                        if not member_interface.lag or member_interface.lag != bond_interface:
                            member_interface.lag = bond_interface
                            member_interface.save()
                            members_added += 1
                            logger.info(f"Added interface {member_name} to bond {bond_name} in NetBox for device {device.name}")
                    except Interface.DoesNotExist:
                        logger.warning(f"Interface {member_name} not found in NetBox, skipping bond membership")
                    except Exception as e:
                        logger.warning(f"Error adding {member_name} to bond {bond_name}: {e}")

                # Migrate ALL VLANs (tagged + untagged) from ALL member interfaces to bond (only if migrate_vlans=True)
                vlans_migrated = 0
                members_cleared = 0

                if migrate_vlans:
                    # Collect all VLANs from all member interfaces
                    all_untagged_vlans = []
                    all_tagged_vlans = set()

                    for member_name in member_interfaces:
                        try:
                            member_interface = Interface.objects.get(device=device, name=member_name)
                            # Collect untagged VLAN
                            if member_interface.untagged_vlan:
                                all_untagged_vlans.append(member_interface.untagged_vlan)
                            # Collect tagged VLANs
                            tagged_vlans = member_interface.tagged_vlans.all()
                            all_tagged_vlans.update(tagged_vlans)
                        except Interface.DoesNotExist:
                            continue

                    # Apply collected VLANs to bond interface
                    bond_interface.refresh_from_db()

                    # Set untagged VLAN (use first one if multiple, or None if none)
                    if all_untagged_vlans:
                        bond_interface.untagged_vlan = all_untagged_vlans[0]
                        vlans_migrated += 1
                        logger.info(f"Migrated untagged VLAN {all_untagged_vlans[0].vid} to bond {bond_name} on {device.name}")
                    else:
                        bond_interface.untagged_vlan = None

                    # Set tagged VLANs
                    if all_tagged_vlans:
                        bond_interface.tagged_vlans.set(all_tagged_vlans)
                        vlans_migrated += len(all_tagged_vlans)
                        logger.info(f"Migrated {len(all_tagged_vlans)} tagged VLAN(s) to bond {bond_name} on {device.name}")
                    else:
                        bond_interface.tagged_vlans.clear()

                    # Set mode based on VLANs
                    if bond_interface.untagged_vlan or all_tagged_vlans:
                        bond_interface.mode = 'tagged' if all_tagged_vlans else 'access'
                    else:
                        bond_interface.mode = None

                    bond_interface.save()
                    
                    # Auto-tag bond interface based on VLAN configuration
                    # Use same logic as _auto_tag_interface_after_deployment:
                    # - If bond has BOTH tagged AND untagged VLANs → vlan-mode:tagged
                    # - If bond has ONLY untagged VLAN (no tagged) → vlan-mode:access
                    # - If bond has ONLY tagged VLANs (no untagged) → vlan-mode:tagged
                    bond_interface.refresh_from_db()
                    has_untagged = bond_interface.untagged_vlan is not None
                    has_tagged = bond_interface.tagged_vlans.exists()
                    
                    if has_tagged and has_untagged:
                        # Both tagged and untagged VLANs → tagged mode
                        tag_name = "vlan-mode:tagged"
                    elif has_untagged:
                        # Only untagged VLAN → access mode
                        tag_name = "vlan-mode:access"
                    elif has_tagged:
                        # Only tagged VLANs → tagged mode
                        tag_name = "vlan-mode:tagged"
                    else:
                        # No VLAN config - skip tagging
                        tag_name = None
                    
                    if tag_name:
                        try:
                            from extras.models import Tag
                            # Get or create the tag
                            tag, created = Tag.objects.get_or_create(
                                name=tag_name,
                                defaults={'slug': tag_name.replace(':', '-')}
                            )
                            
                            # Remove any existing vlan-mode:access or vlan-mode:tagged tags first
                            existing_vlan_mode_tags = [
                                t for t in bond_interface.tags.all()
                                if t.name.startswith('vlan-mode:access') or t.name.startswith('vlan-mode:tagged')
                            ]
                            if existing_vlan_mode_tags:
                                bond_interface.tags.remove(*existing_vlan_mode_tags)
                            
                            # Add the new tag
                            bond_interface.tags.add(tag)
                            logger.info(f"Applied tag '{tag_name}' to bond {bond_name} on {device.name}")
                        except Exception as e:
                            logger.warning(f"Failed to apply tag '{tag_name}' to bond {bond_name} on {device.name}: {e}")

                    # Clear VLANs from ALL member interfaces
                    for member_name in member_interfaces:
                        try:
                            member_interface = Interface.objects.get(device=device, name=member_name)
                            if member_interface.untagged_vlan or member_interface.tagged_vlans.exists():
                                member_interface.untagged_vlan = None
                                member_interface.tagged_vlans.clear()
                                member_interface.mode = None
                                member_interface.save()
                                members_cleared += 1
                                logger.info(f"Cleared VLANs from member interface {member_name} on {device.name}")
                        except Interface.DoesNotExist:
                            continue

                return {
                    "success": True,
                    "bond_created": bond_created,
                    "members_added": members_added,
                    "vlans_migrated": vlans_migrated,
                    "members_cleared": members_cleared,
                    "error": None
                }

        except Exception as e:
            logger.error(f"Error syncing bond {bond_name} to NetBox for device {device.name}: {e}")
            return {
                "success": False,
                "bond_created": False,
                "members_added": 0,
                "vlans_migrated": 0,
                "members_cleared": 0,
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
    - Section 2 (untagged): Interfaces with VLAN config but NO tags at all (completely blank)
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
            return JsonResponse({'tagged_interfaces': {}, 'untagged_interfaces': {}, 'device_count': 0, 'total_tagged': 0, 'total_untagged': 0})
        tagged_interfaces_by_device = {}
        untagged_interfaces_by_device = {}

        # Management interfaces to exclude
        management_interfaces = {'eth0', 'lo', 'mgmt', 'management', 'loopback', 'Loopback0'}

        for device in devices:
            device_interfaces = Interface.objects.filter(
                device=device
            ).select_related('untagged_vlan').prefetch_related('tagged_vlans', 'tags').order_by('name')

            # Separate into tagged and untagged
            tagged_interfaces = []
            untagged_interfaces = []

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
                        iface_data['info'] = "Untagged interface - will be auto-tagged after deployment."

                    untagged_interfaces.append(iface_data)

            # Safety check: Verify no duplicates between Section 1 and Section 2
            tagged_interface_ids = {iface_data['id'] for iface_data in tagged_interfaces}
            untagged_interface_ids = {iface_data['id'] for iface_data in untagged_interfaces}
            duplicates = tagged_interface_ids & untagged_interface_ids
            if duplicates:
                logger.warning(f"Found duplicate interfaces between Section 1 and Section 2 for device {device.name}: {duplicates}")
                # Remove duplicates from Section 2 (Section 1 takes priority)
                untagged_interfaces = [iface_data for iface_data in untagged_interfaces if iface_data['id'] not in duplicates]

            if tagged_interfaces:
                tagged_interfaces_by_device[device.name] = tagged_interfaces
            if untagged_interfaces:
                untagged_interfaces_by_device[device.name] = untagged_interfaces

        # Count interfaces with conflicting tags (uplink/routed)
        total_conflicting = 0
        for device_name, ifaces in untagged_interfaces_by_device.items():
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
            'untagged_interfaces': untagged_interfaces_by_device,
            'device_count': device_count,
            'total_tagged': sum(len(ifaces) for ifaces in tagged_interfaces_by_device.values()),
            'total_untagged': sum(len(ifaces) for ifaces in untagged_interfaces_by_device.values()),
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
