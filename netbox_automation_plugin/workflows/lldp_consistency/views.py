from django.http import HttpResponse
from django.shortcuts import render
from django.views import View
from django.utils.translation import gettext_lazy as _

from dcim.models import Device, Interface
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

        results = self._run_consistency_check(devices)

        # CSV export path – check if CSV button was clicked
        if "export_csv" in request.POST:
            csv_content = self._build_csv(results)
            response = HttpResponse(csv_content, content_type="text/csv; charset=utf-8-sig")
            response["Content-Disposition"] = 'attachment; filename="lldp_consistency_check.csv"'
            return response

        table = LLDPConsistencyResultTable(results, orderable=True)
        summary = self._build_summary(results, len(devices))

        context = {
            "form": form,
            "table": table,
            "summary": summary,
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
                netbox_cable_matches, netbox_cable_info = self._check_netbox_cable_match(
                    netbox_interface, actual_device_name, neighbor_port
                )

                config_matches_lldp = self._check_description_match(
                    config_description, neighbor_hostname, neighbor_port
                )
                netbox_description_matches_lldp = self._check_description_match(
                    netbox_description, neighbor_hostname, neighbor_port
                )

                netbox_matches_lldp = netbox_description_matches_lldp or netbox_cable_matches

                status, mismatch_type, notes = self._classify_result(
                    config_description=config_description,
                    config_matches_lldp=config_matches_lldp,
                    netbox_matches_lldp=netbox_matches_lldp,
                    netbox_description_matches_lldp=netbox_description_matches_lldp,
                    netbox_cable_matches_lldp=netbox_cable_matches,
                    remote_device_exists=remote_device_exists,
                    remote_interface_exists=remote_interface_exists,
                )

                results.append(
                    {
                        "device": device,
                        "interface": local_interface,
                        "lldp_neighbor": neighbor_hostname,
                        "lldp_port": neighbor_port,
                        "netbox_peer": netbox_cable_info,
                        "config_description": config_description,
                        "netbox_description": netbox_description,
                        "status": status,
                        "mismatch_type": mismatch_type,
                        "notes": notes,
                    }
                )

        return results

    def _parse_interface_descriptions(self, running_config: str):
        """
        Parse interface descriptions from running config.
        Copied from scripts/sync_lldp_interfaces.py with minor adaptations.
        """
        import re

        descriptions = {}

        if not running_config:
            return descriptions

        current_interface = None

        for line in running_config.split("\n"):
            line = line.strip()

            interface_match = re.match(r"^interface\s+(\S+)", line, re.IGNORECASE)
            if interface_match:
                current_interface = interface_match.group(1)
                continue

            if current_interface:
                desc_match = re.match(r"^description\s+(.+)", line, re.IGNORECASE)
                if desc_match:
                    descriptions[current_interface] = desc_match.group(1).strip()
                    current_interface = None

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
        """
        netbox_cable_matches = False
        netbox_cable_info = ""

        if netbox_interface and netbox_interface.link_peers:
            for peer in netbox_interface.link_peers:
                if hasattr(peer, "device") and hasattr(peer, "name"):
                    remote_device = peer.device.name
                    remote_interface = peer.name
                    netbox_cable_info = f"{remote_device}:{remote_interface}"
                    if (
                        remote_device.lower() == actual_device_name.lower()
                        and remote_interface.lower() == neighbor_port.lower()
                    ):
                        netbox_cable_matches = True
                    break

        return netbox_cable_matches, netbox_cable_info

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
        remote_device_exists: bool,
        remote_interface_exists: bool,
    ):
        """
        Derive a high-level status and mismatch type for UI/CSV.
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
                return (
                    "warning",
                    "Missing config description",
                    "Device config has no description; LLDP shows a neighbor but NetBox does not match.",
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
            mismatch_source = []
            if not netbox_description_matches_lldp:
                mismatch_source.append("description")
            if not netbox_cable_matches_lldp:
                mismatch_source.append("cable")
            detail = ", ".join(mismatch_source) or "description/cable"
            return (
                "warning",
                "NetBox vs LLDP mismatch",
                f"NetBox {detail} do not match LLDP, but running config does.",
            )

        # Neither config nor NetBox match LLDP
        return (
            "error",
            "Config & NetBox vs LLDP mismatch",
            "Neither running config description nor NetBox description/cable match the LLDP neighbor.",
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
        writer.writerow(
            [
                "device",
                "interface",
                "config_description",
                "netbox_description",
                "netbox_peer",
                "lldp_neighbor_device",
                "lldp_neighbor_port",
                "status",
                "mismatch_type",
                "notes",
            ]
        )

        for r in results:
            # Clean all text values to remove em dashes and problematic Unicode
            writer.writerow(
                [
                    self._clean_csv_value(getattr(r["device"], "name", r["device"])),
                    self._clean_csv_value(r.get("interface", "")),
                    self._clean_csv_value(r.get("config_description", "")),
                    self._clean_csv_value(r.get("netbox_description", "")),
                    self._clean_csv_value(r.get("netbox_peer", "")),
                    self._clean_csv_value(r.get("lldp_neighbor", "")),
                    self._clean_csv_value(r.get("lldp_port", "")),
                    self._clean_csv_value(r.get("status", "")),
                    self._clean_csv_value(r.get("mismatch_type", "")),
                    self._clean_csv_value(r.get("notes", "")),
                ]
            )

        return output.getvalue()


