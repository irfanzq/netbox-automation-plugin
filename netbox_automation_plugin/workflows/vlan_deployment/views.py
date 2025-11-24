from django.shortcuts import render
from django.views import View
from django.http import HttpResponse, JsonResponse
from django.utils.translation import gettext_lazy as _
from django.db import transaction

from dcim.models import Device, Interface
from ipam.models import VLAN

from ...core.napalm_integration import NAPALMDeviceManager
from .forms import VLANDeploymentForm
from .tables import VLANDeploymentResultTable
import logging

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

        context = {
            "form": form,
            "table": table,
            "summary": summary,
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
            role = cleaned_data.get('role')

            devices = Device.objects.filter(
                site=site,
                location=location,
                role=role,
            ).select_related('primary_ip4', 'primary_ip6', 'site', 'location', 'role', 'device_type', 'device_type__manufacturer')

            # Only keep devices with primary IP
            devices = [d for d in devices if d.primary_ip4 or d.primary_ip6]
            return devices

        return []

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

        # Note: We use NAPALMDeviceManager per-device in _deploy_config_to_device
        # This allows proper connection management and safe deployment per device

        for device in devices:
            device_name = device.name

            # Detect platform for this device
            platform = self._get_device_platform(device)

            for interface_name in interface_list:
                result_entry = {
                    "device": device,
                    "interface": interface_name,
                    "vlan_id": vlan_id,
                    "vlan_name": vlan_name,
                    "status": "pending",
                    "config_applied": "No",
                    "netbox_updated": "No",
                    "message": "",
                    "deployment_logs": "",
                }

                # Initialize deployment logs
                logs = []

                try:
                    logs.append(f"=== VLAN Deployment Started ===")
                    logs.append(f"Device: {device.name}")
                    logs.append(f"Interface: {interface_name}")
                    logs.append(f"VLAN ID: {vlan_id}")
                    logs.append(f"VLAN Name: {vlan_name}")
                    logs.append(f"Platform: {platform}")
                    logs.append(f"Mode: {'Dry Run' if dry_run else 'Deploy Changes'}")
                    logs.append("")

                    # Generate platform-specific VLAN config command
                    logs.append(f"[Step 1] Generating configuration command...")
                    config_command = self._generate_vlan_config(interface_name, vlan_id, platform)
                    logs.append(f"✓ Generated command: {config_command}")
                    logs.append("")

                    if dry_run:
                        # Dry run - just show what would be deployed
                        logs.append(f"[Dry Run Mode] No changes will be applied")
                        logs.append(f"Command that would be deployed: {config_command}")
                        result_entry["status"] = "success"
                        result_entry["config_applied"] = "Dry Run"
                        result_entry["message"] = f"Platform: {platform} | Would apply: {config_command}"
                    else:
                        # Apply configuration to device using safe deployment
                        logs.append(f"[Step 2] Deploying configuration to device...")
                        deploy_result = self._deploy_config_to_device(
                            device, interface_name, config_command, platform, vlan_id
                        )

                        # Add deployment logs from the result
                        if deploy_result.get("logs"):
                            logs.extend(deploy_result["logs"])

                        logs.append("")

                        if deploy_result["success"]:
                            result_entry["status"] = "success"
                            result_entry["config_applied"] = "Yes"

                            logs.append(f"✓ Configuration deployment: SUCCESS")
                            logs.append(f"✓ Configuration committed: {deploy_result.get('committed', False)}")

                            # Build detailed message from deployment result
                            message_parts = [deploy_result.get("message", "Configuration applied successfully")]

                            # Add verification details if available
                            if deploy_result.get("verification_results"):
                                logs.append("")
                                logs.append(f"[Step 3] Post-deployment verification results:")
                                verif_results = deploy_result["verification_results"]
                                verif_messages = []
                                for check_name, check_result in verif_results.items():
                                    if check_result.get("success"):
                                        logs.append(f"  ✓ {check_name}: OK - {check_result.get('message', '')}")
                                        verif_messages.append(f"{check_name}: OK")
                                    else:
                                        logs.append(f"  ✗ {check_name}: FAILED - {check_result.get('message', 'Failed')}")
                                        verif_messages.append(f"{check_name}: {check_result.get('message', 'Failed')}")
                                if verif_messages:
                                    message_parts.append(f"Verification: {', '.join(verif_messages)}")

                            result_entry["message"] = " | ".join(message_parts)

                            # Update NetBox if requested and config was committed (not rolled back)
                            if update_netbox and deploy_result.get("committed", False):
                                logs.append("")
                                logs.append(f"[Step 4] Updating NetBox interface assignment...")
                                if vlan:
                                    netbox_result = self._update_netbox_interface(
                                        device, interface_name, vlan
                                    )
                                    if netbox_result["success"]:
                                        result_entry["netbox_updated"] = "Yes"
                                        result_entry["message"] += " | NetBox updated"
                                        logs.append(f"✓ NetBox interface updated successfully")
                                    else:
                                        result_entry["netbox_updated"] = "Failed"
                                        result_entry["message"] += f" | NetBox update failed: {netbox_result['error']}"
                                        logs.append(f"✗ NetBox update failed: {netbox_result['error']}")
                                else:
                                    result_entry["netbox_updated"] = "Skipped"
                                    result_entry["message"] += " | NetBox update skipped (VLAN not found)"
                                    logs.append(f"⚠ NetBox update skipped (VLAN not found in NetBox)")
                            elif deploy_result.get("rolled_back", False):
                                result_entry["netbox_updated"] = "Skipped"
                                result_entry["message"] += " | NetBox update skipped (deployment rolled back)"
                                logs.append(f"⚠ NetBox update skipped (deployment was rolled back)")
                        else:
                            result_entry["status"] = "error"
                            result_entry["config_applied"] = "Failed"
                            result_entry["message"] = f"Config deployment failed: {deploy_result.get('message', 'Unknown error')}"

                            logs.append(f"✗ Configuration deployment: FAILED")
                            logs.append(f"Error: {deploy_result.get('message', 'Unknown error')}")

                            # If rolled back, indicate that
                            if deploy_result.get("rolled_back", False):
                                result_entry["message"] += " (auto-rollback performed)"
                                logs.append(f"⚠ Auto-rollback was performed")

                except Exception as e:
                    result_entry["status"] = "error"
                    result_entry["message"] = f"Error: {str(e)}"
                    logs.append(f"✗ EXCEPTION: {str(e)}")
                    import traceback
                    logs.append(f"Traceback:")
                    logs.append(traceback.format_exc())

                # Add final status to logs
                logs.append("")
                logs.append(f"=== Deployment Completed ===")
                logs.append(f"Final Status: {result_entry['status'].upper()}")
                logs.append(f"Config Applied: {result_entry['config_applied']}")
                logs.append(f"NetBox Updated: {result_entry['netbox_updated']}")

                # Store logs in result entry
                result_entry["deployment_logs"] = "\n".join(logs)

                results.append(result_entry)

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
            # Pre-deployment validation: Check if interface exists in NetBox
            logs.append(f"[2.1] Pre-deployment validation")
            from dcim.models import Interface
            try:
                interface = Interface.objects.get(device=device, name=interface_name)
                logs.append(f"✓ Interface {interface_name} exists in NetBox for {device.name}")
                logger.info(f"Interface validation passed: {device.name} has {interface_name}")
            except Interface.DoesNotExist:
                error_msg = f"Interface {interface_name} does not exist on device {device.name} in NetBox"
                logs.append(f"✗ {error_msg}")
                logger.error(error_msg)
                return {
                    "success": False,
                    "committed": False,
                    "rolled_back": False,
                    "message": error_msg,
                    "verification_results": {},
                    "logs": logs,
                    "error": error_msg
                }

            logs.append(f"[2.2] Platform detection: {platform}")

            # Convert platform-specific commands to NAPALM config format
            if platform == 'cumulus':
                # For Cumulus NVUE, the config_command is already an NVUE command (e.g., "nv set interface ...")
                # NAPALM's commit_config() will handle "nv config apply --confirm {timeout}s" automatically
                # So we only need the NVUE set command, not the apply command
                config_text = config_command
                logs.append(f"[2.3] Cumulus NVUE command prepared: {config_text}")
                logger.info(f"Deploying to Cumulus device {device.name}: {config_text}")

            elif platform == 'eos':
                # For Arista EOS, the config_command already contains multi-line CLI commands
                # NAPALM will handle the commit-confirm workflow using configure session
                # EOS uses configure session with commit timer for safe deployment
                config_text = config_command
                logs.append(f"[2.3] Arista EOS command prepared: {config_text}")
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
            logs.append(f"[2.4] Initializing NAPALM connection to {device.name}...")
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
            logs.append(f"[2.5] Starting safe deployment with 90s rollback timer...")
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
                    logs.append(f"[2.8] Disconnecting from {device.name}...")
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

                # Set untagged VLAN (access mode)
                interface.mode = 'access'
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
    """

    def get(self, request):
        device_ids = request.GET.getlist('device_ids[]')

        if not device_ids:
            return JsonResponse({'interfaces': []})

        # Get all devices
        devices = Device.objects.filter(id__in=device_ids)

        if not devices.exists():
            return JsonResponse({'interfaces': []})

        # Get interfaces for each device
        device_interface_sets = []
        for device in devices:
            interfaces = set(
                Interface.objects.filter(device=device).values_list('name', flat=True)
            )
            device_interface_sets.append(interfaces)

        # Find common interfaces (intersection of all sets)
        if device_interface_sets:
            common_interfaces = set.intersection(*device_interface_sets)
            # Sort for consistent display
            common_interfaces = sorted(common_interfaces, key=self._natural_sort_key)
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
