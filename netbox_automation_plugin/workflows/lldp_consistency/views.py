from django.http import HttpResponse
from django.shortcuts import render
from django.views import View
from django.utils.translation import gettext_lazy as _
from datetime import datetime

from dcim.models import Device, Interface, FrontPort, RearPort
from netbox.plugins import get_plugin_config

from .forms import LLDPConsistencyCheckForm
from .tables import LLDPConsistencyResultTable
from ...core.nornir_integration import NornirDeviceManager


class LLDPConsistencyCheckView(View):
    """
    LLDP Consistency Check:
    - Collect LLDP, config, and NetBox state
    - Compare Config vs LLDP vs NetBox
    - Present mismatches in a table and optional CSV
    """

    template_name_form = "netbox_automation_plugin/lldp_consistency_form.html"
    template_name_results = "netbox_automation_plugin/lldp_consistency_results.html"

    def get(self, request):
        form = LLDPConsistencyCheckForm()
        return render(request, self.template_name_form, {"form": form})

    def post(self, request):
        # CSV export path – check if CSV button was clicked FIRST (uses cached results)
        # This must be checked BEFORE form validation since the CSV form doesn't have device fields
        if "export_csv" in request.POST:
            # Retrieve cached results from session
            cached_results = request.session.get('lldp_consistency_results')
            if cached_results:
                csv_content = self._build_csv(cached_results)
                response = HttpResponse(csv_content, content_type="text/csv; charset=utf-8-sig")
                response["Content-Disposition"] = 'attachment; filename="lldp_consistency_check.csv"'
                return response
            else:
                # No cached results, show error on form
                form = LLDPConsistencyCheckForm()
                form.add_error(None, _("Results expired. Please run the check again."))
                return render(request, self.template_name_form, {"form": form})

        # Normal form submission - validate the form
        form = LLDPConsistencyCheckForm(request.POST)
        if not form.is_valid():
            return render(request, self.template_name_form, {"form": form})

        # Check if at least one filter or device selection is made
        data = form.cleaned_data
        has_selection = (
            data.get("devices") or
            data.get("manufacturer") or
            data.get("site") or
            data.get("role") or
            data.get("status")
        )

        if not has_selection:
            form.add_error(None, _("Please select at least one filter (Manufacturer, Site, Role, or Status) or choose specific devices."))
            return render(request, self.template_name_form, {"form": form})

        devices = self._get_devices(form.cleaned_data)
        if not devices:
            form.add_error(None, _("No devices found matching the selection (with primary IP)."))
            return render(request, self.template_name_form, {"form": form})

        # Run the consistency check (only on initial form submission)
        results = self._run_consistency_check(devices)

        # Store results in session for CSV export (serialize device objects)
        serialized_results = self._serialize_results_for_session(results)
        request.session['lldp_consistency_results'] = serialized_results
        request.session['lldp_consistency_device_count'] = len(devices)

        table = LLDPConsistencyResultTable(results, orderable=True)
        summary = self._build_summary(results, len(devices))

        # Add version timestamp to verify latest code is running
        code_version = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        context = {
            "form": form,
            "table": table,
            "summary": summary,
            "form_data": form.cleaned_data,  # Pass form data for CSV export
            "code_version": code_version,  # Show when code was executed
        }
        return render(request, self.template_name_results, context)

    def _get_devices(self, data):
        """
        Resolve devices from explicit selection or filter fields.
        """
        specific_devices = data.get("devices")
        if specific_devices:
            devices = list(specific_devices)
        else:
            device_filter = {}
            if data.get("manufacturer"):
                device_filter["device_type__manufacturer"] = data["manufacturer"]
            if data.get("site"):
                device_filter["site"] = data["site"]
            if data.get("role"):
                device_filter["role"] = data["role"]
            if data.get("status"):
                device_filter["status__in"] = data["status"]

            qs = Device.objects.filter(**device_filter).select_related(
                "device_type",
                "device_type__manufacturer",
                "site",
                "role",
                "primary_ip4",
                "primary_ip6",
            )
            devices = list(qs)

        # Only keep devices with a primary IP
        devices = [d for d in devices if d.primary_ip4 or d.primary_ip6]
        return devices

    def _run_consistency_check(self, devices):
        """
        Core logic derived from scripts/sync_lldp_interfaces.py but read-only.
        """
        manager = NornirDeviceManager(devices=devices)
        manager.initialize()

        lldp_data = manager.get_lldp_neighbors_detail()
        config_data = manager.get_config(retrieve="running")
        interface_data = manager.get_interfaces()

        results = []

        for device in devices:
            device_name = device.name

            if lldp_data.get(device_name, {}).get("failed", True):
                results.append(
                    {
                        "device": device,
                        "interface": "",
                        "lldp_neighbor": "",
                        "lldp_port": "",
                        "netbox_peer": "",
                        "config_description": "",
                        "netbox_description": "",
                        "status": "error",
                        "mismatch_type": "LLDP collection failed",
                        "notes": lldp_data.get(device_name, {}).get("error", ""),
                    }
                )
                continue

            if config_data.get(device_name, {}).get("failed", True):
                results.append(
                    {
                        "device": device,
                        "interface": "",
                        "lldp_neighbor": "",
                        "lldp_port": "",
                        "netbox_peer": "",
                        "config_description": "",
                        "netbox_description": "",
                        "status": "error",
                        "mismatch_type": "Config collection failed",
                        "notes": config_data.get(device_name, {}).get("error", ""),
                    }
                )
                continue

            lldp_neighbors = dict(lldp_data[device_name])
            lldp_neighbors.pop("failed", None)

            running_config = config_data[device_name].get("running", "")
            interfaces_info = dict(interface_data.get(device_name, {}))
            interfaces_info.pop("failed", None)

            interface_descriptions = self._parse_interface_descriptions(running_config)

            for local_interface, neighbors in lldp_neighbors.items():
                if not neighbors or not isinstance(neighbors, list):
                    continue

                selected_neighbor = self._select_neighbor(neighbors)
                if not selected_neighbor:
                    continue

                neighbor_hostname = selected_neighbor["hostname"]
                neighbor_port = selected_neighbor["port"]

                remote_device_exists, remote_interface_exists, actual_device_name = self._lookup_remote(
                    neighbor_hostname, neighbor_port
                )

                config_description = interface_descriptions.get(local_interface, "")
                netbox_interface = Interface.objects.filter(device=device, name=local_interface).first()
                netbox_description = netbox_interface.description if netbox_interface else ""

                netbox_has_cable = bool(netbox_interface.cable) if netbox_interface else False
                netbox_cable_matches, netbox_cable_info, netbox_connection_info, path_type = self._check_netbox_cable_match(
                    netbox_interface, actual_device_name, neighbor_port
                )

                config_matches_lldp = self._check_description_match(
                    config_description, neighbor_hostname, neighbor_port
                )
                netbox_description_matches_lldp = self._check_description_match(
                    netbox_description, neighbor_hostname, neighbor_port
                )

                netbox_matches_lldp = netbox_description_matches_lldp or netbox_cable_matches
                
                # Check if NetBox has any info (description or cable)
                netbox_has_description = bool(netbox_description)
                netbox_has_info = netbox_has_description or netbox_has_cable

                status, mismatch_type, notes = self._classify_result(
                    config_description=config_description,
                    config_matches_lldp=config_matches_lldp,
                    netbox_matches_lldp=netbox_matches_lldp,
                    netbox_description_matches_lldp=netbox_description_matches_lldp,
                    netbox_cable_matches_lldp=netbox_cable_matches,
                    netbox_has_info=netbox_has_info,
                    netbox_has_description=netbox_has_description,
                    netbox_has_cable=netbox_has_cable,
                    netbox_cable_info=netbox_cable_info,
                    netbox_connection_info=netbox_connection_info,
                    remote_device_exists=remote_device_exists,
                    remote_interface_exists=remote_interface_exists,
                )

                results.append(
                    {
                        "device": device,
                        "interface": local_interface,
                        "lldp_neighbor": neighbor_hostname,
                        "lldp_port": neighbor_port,
                        "config_description": config_description,
                        "netbox_description": netbox_description,
                        "netbox_cable": netbox_cable_info,
                        "netbox_connection": netbox_connection_info,
                        "path_type": path_type,
                        "status": status,
                        "mismatch_type": mismatch_type,
                        "notes": notes,
                    }
                )

        return results

    def _parse_interface_descriptions(self, running_config: str):
        """
        Parse interface descriptions from running config.
        Supports Cumulus Linux, Arista EOS, and Juniper formats.
        """
        import re

        descriptions = {}

        if not running_config:
            return descriptions

        current_interface = None

        for line in running_config.split("\n"):
            line = line.strip()

            # Check for interface block start (Cumulus/EOS/IOS format)
            interface_match = re.match(r"^interface\s+(\S+)", line, re.IGNORECASE)
            if interface_match:
                current_interface = interface_match.group(1)
                continue

            # Check for end of interface block (exclamation mark or blank line after config)
            if line == "!" or (not line and current_interface):
                # Keep current_interface for next potential config line
                # Don't reset to None here
                pass

            # Parse description within interface block
            if current_interface:
                desc_match = re.match(r"^description\s+(.+)", line, re.IGNORECASE)
                if desc_match:
                    descriptions[current_interface] = desc_match.group(1).strip()
                    # DON'T reset current_interface here - keep parsing the interface block
                    # current_interface = None  # <-- REMOVED THIS BUG

            # Juniper/VyOS format: set interfaces <name> description "..."
            juniper_match = re.match(
                r'^set\s+interfaces\s+(\S+)\s+description\s+"?([^"]+)"?',
                line,
                re.IGNORECASE,
            )
            if juniper_match:
                interface_name = juniper_match.group(1)
                description = juniper_match.group(2).strip('"')
                descriptions[interface_name] = description

        return descriptions

    def _select_neighbor(self, neighbors):
        """
        Choose a single LLDP neighbor with a valid hostname and port.
        """
        for neighbor in neighbors:
            neighbor_hostname = (
                neighbor.get("remote_system_name", "") or neighbor.get("hostname", "")
            ).strip()

            if ":" in neighbor_hostname and len(neighbor_hostname.split(":")) >= 5:
                continue

            remote_port = neighbor.get("remote_port", "").strip()
            remote_port_desc = neighbor.get("remote_port_description", "").strip()

            if remote_port and ":" in remote_port and len(remote_port.split(":")) >= 5:
                neighbor_port = remote_port_desc or remote_port
            else:
                neighbor_port = remote_port or remote_port_desc or neighbor.get("port", "").strip()

            if neighbor_hostname and neighbor_port:
                return {
                    "hostname": neighbor_hostname,
                    "port": neighbor_port,
                }

        return None

    def _lookup_remote(self, neighbor_hostname: str, neighbor_port: str):
        """
        Determine whether the remote device/interface exist in NetBox.
        """
        remote_device_exists = Device.objects.filter(name=neighbor_hostname).exists()
        actual_device_name = neighbor_hostname

        if not remote_device_exists and "." in neighbor_hostname:
            short_hostname = neighbor_hostname.split(".")[0]
            remote_device_exists = Device.objects.filter(name=short_hostname).exists()
            if remote_device_exists:
                actual_device_name = short_hostname

        remote_interface_exists = False
        if remote_device_exists:
            remote_interface_exists = Interface.objects.filter(
                device__name=actual_device_name,
                name=neighbor_port,
            ).exists()

        return remote_device_exists, remote_interface_exists, actual_device_name

    def _check_netbox_cable_match(self, netbox_interface, actual_device_name, neighbor_port):
        """
        Check whether the existing NetBox cable matches the LLDP neighbor.
        Returns cable info (immediate), connection info (final), and path type.
        """
        netbox_cable_matches = False
        netbox_cable_info = ""
        netbox_connection_info = ""
        path_type = "No Cable"

        if netbox_interface and netbox_interface.link_peers:
            for peer in netbox_interface.link_peers:
                if hasattr(peer, "device") and hasattr(peer, "name"):
                    remote_device = peer.device.name
                    remote_interface = peer.name

                    # NetBox Cable = immediate cable connection (link_peers)
                    netbox_cable_info = f"{remote_device}:{remote_interface}"

                    # Determine path type based on peer object type
                    if isinstance(peer, Interface):
                        # Direct cable to device interface
                        path_type = "Direct"
                    elif isinstance(peer, (FrontPort, RearPort)):
                        # Cable goes through patch panel
                        path_type = "Via Patch Panel"
                    else:
                        # Other types (CircuitTermination, PowerPort, etc.)
                        path_type = "Other"

                    # NetBox Connection = final destination (connected_endpoints)
                    if netbox_interface.connected_endpoints:
                        for endpoint in netbox_interface.connected_endpoints:
                            if hasattr(endpoint, "device") and hasattr(endpoint, "name"):
                                netbox_connection_info = f"{endpoint.device.name}:{endpoint.name}"
                                break
                    else:
                        # No connected_endpoints, use cable info
                        netbox_connection_info = netbox_cable_info

                    # Check if connection matches LLDP neighbor
                    # Always check connected_endpoints (works for both direct and patch panel)
                    if netbox_connection_info:
                        connection_parts = netbox_connection_info.split(":")
                        if len(connection_parts) == 2:
                            if (
                                connection_parts[0].lower() == actual_device_name.lower()
                                and connection_parts[1].lower() == neighbor_port.lower()
                            ):
                                netbox_cable_matches = True
                    break

        return netbox_cable_matches, netbox_cable_info, netbox_connection_info, path_type

    def _check_description_match(self, description: str, neighbor_hostname: str, neighbor_port: str) -> bool:
        """
        Check if interface description contains both hostname and port.
        """
        if not description:
            return False

        description_lower = description.lower()
        return neighbor_hostname.lower() in description_lower and neighbor_port.lower() in description_lower

    def _classify_result(
        self,
        config_description: str,
        config_matches_lldp: bool,
        netbox_matches_lldp: bool,
        netbox_description_matches_lldp: bool,
        netbox_cable_matches_lldp: bool,
        netbox_has_info: bool,
        netbox_has_description: bool,
        netbox_has_cable: bool,
        netbox_cable_info: str,
        netbox_connection_info: str,
        remote_device_exists: bool,
        remote_interface_exists: bool,
    ):
        """
        Derive a high-level status and mismatch type for UI/CSV.
        Distinguishes between "NetBox has no info" (warning) vs "NetBox has wrong info" (error).
        """
        # Remote not present in NetBox at all
        if not remote_device_exists:
            return (
                "warning",
                "Remote device not in NetBox",
                "LLDP reports remote device that does not exist in NetBox.",
            )

        if remote_device_exists and not remote_interface_exists:
            return (
                "warning",
                "Remote interface not in NetBox",
                "LLDP reports remote interface that does not exist in NetBox.",
            )

        if not config_description:
            if netbox_matches_lldp:
                return (
                    "ok",
                    "NetBox already matches LLDP",
                    "NetBox description/cable match LLDP; device config has no description.",
                )
            else:
                # Config has no description, NetBox doesn't match
                if not netbox_has_info:
                    # Build detailed note about what's missing in NetBox
                    missing_parts = []
                    if not netbox_has_description:
                        missing_parts.append("no description")
                    if not netbox_cable_info:
                        missing_parts.append("no cable")
                    if not netbox_connection_info:
                        missing_parts.append("no connection")
                    netbox_missing = ", ".join(missing_parts) if missing_parts else "no info"

                    return (
                        "warning",
                        "Missing info in config and NetBox",
                        f"Device config has no description; NetBox has {netbox_missing}.",
                    )
                else:
                    return (
                        "warning",
                        "Missing config description",
                        "Device config has no description; NetBox has info but it doesn't match LLDP.",
                    )

        if config_matches_lldp and netbox_matches_lldp:
            return ("ok", "Config/NetBox/LLDP consistent", "All three sources are consistent.")

        if not config_matches_lldp and netbox_matches_lldp:
            return (
                "warning",
                "Config vs LLDP mismatch",
                "NetBox matches LLDP but running config description does not.",
            )

        if config_matches_lldp and not netbox_matches_lldp:
            # Config matches, but NetBox doesn't
            if not netbox_has_info:
                # NetBox has no info at all
                missing_items = []
                if not netbox_has_description:
                    missing_items.append("description")
                if not netbox_has_cable:
                    missing_items.append("cable")
                missing_detail = " or ".join(missing_items) or "description/cable"
                return (
                    "warning",
                    "NetBox missing info",
                    f"NetBox doesn't have {missing_detail} info; running config matches LLDP.",
                )
            else:
                # NetBox has info but it's wrong
                mismatch_source = []
                if netbox_has_description and not netbox_description_matches_lldp:
                    mismatch_source.append("description")
                if netbox_has_cable and not netbox_cable_matches_lldp:
                    mismatch_source.append("cable")
                detail = ", ".join(mismatch_source) or "description/cable"
                return (
                    "warning",
                    "NetBox vs LLDP mismatch",
                    f"NetBox {detail} do not match LLDP, but running config does.",
                )

        # Neither config nor NetBox match LLDP
        # Distinguish between "no info" vs "wrong info"
        if not netbox_has_info:
            # NetBox has no info, config is wrong
            # Build detailed note about what's missing in NetBox
            missing_parts = []
            if not netbox_has_description:
                missing_parts.append("no description")
            if not netbox_cable_info:
                missing_parts.append("no cable")
            if not netbox_connection_info:
                missing_parts.append("no connection")
            netbox_missing = ", ".join(missing_parts) if missing_parts else "no info"

            return (
                "warning",
                "Config mismatch, NetBox missing info",
                f"Running config description doesn't match LLDP; NetBox has {netbox_missing}.",
            )
        else:
            # Both have info but both are wrong
            mismatch_details = []
            if netbox_has_description and not netbox_description_matches_lldp:
                mismatch_details.append("description")
            if netbox_has_cable and not netbox_cable_matches_lldp:
                mismatch_details.append("cable")
            detail = ", ".join(mismatch_details) or "description/cable"
            return (
                "error",
                "Config & NetBox vs LLDP mismatch",
                f"Neither running config description nor NetBox {detail} match the LLDP neighbor.",
            )

    def _build_summary(self, results, device_count: int):
        """
        Build a simple aggregate summary for the results header.
        """
        summary = {
            "device_count": device_count,
            "interface_count": 0,
            "ok": 0,
            "warning": 0,
            "error": 0,
        }

        for r in results:
            if r["interface"]:
                summary["interface_count"] += 1
            status = r.get("status")
            if status in summary:
                summary[status] += 1

        return summary

    def _clean_csv_value(self, value):
        """
        Clean a value for CSV export - remove em dashes and other problematic Unicode characters
        that Excel doesn't handle well. Returns empty string for None/empty values.
        """
        if value is None:
            return ""
        
        # Convert to string and strip
        text = str(value)
        
        # Normalize Unicode and remove all dash-like characters
        import unicodedata
        # Normalize to NFKD to decompose characters
        text = unicodedata.normalize('NFKD', text)
        
        # Remove all dash-like Unicode characters
        # U+2014 = em dash, U+2013 = en dash, U+2212 = minus sign, U+2015 = horizontal bar
        dash_chars = [
            "\u2014",  # Em dash
            "\u2013",  # En dash
            "\u2212",  # Minus sign
            "\u2015",  # Horizontal bar
            "\u2500",  # Box drawing horizontal
            "—",       # Em dash (literal)
            "–",       # En dash (literal)
            "−",       # Minus sign (literal)
        ]
        
        for dash in dash_chars:
            text = text.replace(dash, "")
        
        # Strip whitespace after removing dashes
        text = text.strip()
        
        return text

    def _build_csv(self, results):
        """
        Render results as CSV text for download.
        Excel-compatible: removes em dashes and uses UTF-8 BOM.
        """
        import csv
        from io import StringIO

        output = StringIO()
        # Add UTF-8 BOM for Excel compatibility
        output.write('\ufeff')
        
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        # Match the exact column order from the UI table
        writer.writerow(
            [
                "Device",
                "Interface",
                "LLDP Neighbor Device",
                "LLDP Neighbor Port",
                "Config Description",
                "NetBox Description",
                "NetBox Cable",
                "NetBox Connection",
                "Path Type",
                "Status",
                "Mismatch Type",
                "Notes",
            ]
        )

        for r in results:
            # Skip debug entries (entries with status="debug" or device=None)
            if r.get("status") == "debug" or r.get("device") is None:
                continue

            # Handle both Device objects and serialized device dicts
            device = r.get("device")
            if isinstance(device, dict):
                # Serialized format from session
                device_name = device.get("name", "")
            else:
                # Device object from fresh run
                device_name = getattr(device, "name", str(device))

            # Clean all text values to remove em dashes and problematic Unicode
            # Match the exact column order from the UI table
            writer.writerow(
                [
                    self._clean_csv_value(device_name),
                    self._clean_csv_value(r.get("interface", "")),
                    self._clean_csv_value(r.get("lldp_neighbor", "")),
                    self._clean_csv_value(r.get("lldp_port", "")),
                    self._clean_csv_value(r.get("config_description", "")),
                    self._clean_csv_value(r.get("netbox_description", "")),
                    self._clean_csv_value(r.get("netbox_cable", "")),
                    self._clean_csv_value(r.get("netbox_connection", "")),
                    self._clean_csv_value(r.get("path_type", "")),
                    self._clean_csv_value(r.get("status", "")),
                    self._clean_csv_value(r.get("mismatch_type", "")),
                    self._clean_csv_value(r.get("notes", "")),
                ]
            )

        return output.getvalue()

    def _serialize_results_for_session(self, results):
        """
        Serialize results for session storage.
        Convert Device objects to device IDs and names.
        """
        serialized = []
        for r in results:
            serialized_row = dict(r)  # Copy the dict
            # Convert Device object to serializable format
            if "device" in serialized_row and serialized_row["device"] is not None:
                device = serialized_row["device"]
                serialized_row["device"] = {
                    "id": device.id,
                    "name": device.name
                }
            serialized.append(serialized_row)
        return serialized


