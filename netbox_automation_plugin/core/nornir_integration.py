"""
Nornir Integration for NetBox Automation Plugin (Production)

This module provides Nornir integration to connect to NetBox devices in parallel
using NAPALM drivers, including support for napalm-cumulus.
"""

from typing import Any, Dict, List, Optional, TYPE_CHECKING
from nornir.core.inventory import Inventory, Host, Hosts, Groups, Defaults, ConnectionOptions
from nornir.core.task import Task, Result
from nornir_napalm.plugins.tasks import napalm_get
import logging

if TYPE_CHECKING:
    from dcim.models import Device

logger = logging.getLogger(__name__)


class NetBoxORMInventory:
    """
    Custom Nornir inventory plugin that reads from NetBox ORM
    """

    def __init__(
        self,
        devices: Optional[List["Device"]] = None,
        device_filter: Optional[Dict[str, Any]] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize inventory from NetBox devices

        Args:
            devices: List of NetBox Device objects
            device_filter: Django ORM filter dict
            username: SSH username (overrides plugin config)
            password: SSH password (overrides plugin config)
        """
        from dcim.models import Device

        # Get credentials from plugin config or parameters
        try:
            from netbox.plugins import get_plugin_config
            napalm_config = get_plugin_config('netbox_automation_plugin', 'napalm', {})
            default_username = napalm_config.get('username', 'cumulus')
            default_password = napalm_config.get('password', 'cumulus')
        except Exception as e:
            logger.warning(f"Could not load plugin config, using defaults: {e}")
            default_username = 'cumulus'
            default_password = 'cumulus'

        self.username = username if username is not None else default_username
        self.password = password if password is not None else default_password

        # Query devices
        if devices:
            self.devices = devices
        elif device_filter:
            self.devices = Device.objects.filter(**device_filter).select_related(
                'device_type',
                'device_type__manufacturer',
                'site',
                'role',
                'primary_ip4',
                'primary_ip6'
            )
        else:
            self.devices = []

    def load(self) -> Inventory:
        """Load inventory from NetBox devices"""
        hosts = Hosts()

        for device in self.devices:
            # Get primary IP
            if device.primary_ip4:
                hostname = str(device.primary_ip4.address).split('/')[0]
            elif device.primary_ip6:
                hostname = str(device.primary_ip6.address).split('/')[0]
            else:
                logger.warning(f"Device {device.name} has no primary IP, skipping")
                continue

            # Determine NAPALM driver
            manufacturer = device.device_type.manufacturer.name.lower() if device.device_type and device.device_type.manufacturer else ''

            if 'cumulus' in manufacturer or 'mellanox' in manufacturer or 'nvidia' in manufacturer:
                platform = 'cumulus'
            elif 'arista' in manufacturer:
                platform = 'eos'
            elif 'cisco' in manufacturer:
                if 'nexus' in device.device_type.model.lower() if device.device_type else '':
                    platform = 'nxos'
                else:
                    platform = 'ios'
            elif 'juniper' in manufacturer:
                platform = 'junos'
            else:
                platform = 'ios'

            # Create host entry
            hosts[device.name] = Host(
                name=device.name,
                hostname=hostname,
                platform=platform,
                username=self.username,
                password=self.password,
                data={
                    'device_id': device.id,
                    'manufacturer': manufacturer,
                    'model': device.device_type.model if device.device_type else '',
                    'site': device.site.name if device.site else '',
                    'role': device.role.name if device.role else ''
                },
                connection_options={
                    'napalm': ConnectionOptions(
                        extras={
                            'optional_args': {}
                        }
                    )
                }
            )

        return Inventory(
            hosts=hosts,
            groups=Groups(),
            defaults=Defaults()
        )


class NornirDeviceManager:
    """
    Manager class for running Nornir tasks against NetBox devices
    Production version - direct connections only
    """

    def __init__(
        self,
        devices: Optional[List["Device"]] = None,
        device_filter: Optional[Dict[str, Any]] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        num_workers: Optional[int] = None
    ):
        """
        Initialize Nornir device manager

        Args:
            devices: List of NetBox Device objects (optional)
            device_filter: Django ORM filter to select devices (optional)
            username: SSH username (optional, overrides plugin config)
            password: SSH password (optional, overrides plugin config)
            num_workers: Number of parallel workers (optional, overrides plugin config)
        """
        # Read configuration from plugin config
        try:
            from netbox.plugins import get_plugin_config
            nornir_config = get_plugin_config('netbox_automation_plugin', 'nornir', {})
            default_num_workers = nornir_config.get('runner', {}).get('options', {}).get('num_workers', 20)
        except Exception as e:
            logger.warning(f"Could not load plugin config, using defaults: {e}")
            default_num_workers = 20

        self.devices = devices
        self.device_filter = device_filter
        self.username = username
        self.password = password
        self.num_workers = num_workers if num_workers is not None else default_num_workers
        self.nr = None
        
    def initialize(self):
        """Initialize Nornir with NetBox inventory using ThreadedRunner for parallel execution"""
        import logging
        logger = logging.getLogger('netbox_automation_plugin.nornir')

        # Build custom inventory from NetBox devices
        inventory = NetBoxORMInventory(
            devices=self.devices,
            device_filter=self.device_filter,
            username=self.username,
            password=self.password
        )

        # Initialize Nornir with ThreadedRunner
        from nornir import InitNornir
        from nornir.core.plugins.runners import ThreadedRunner

        self.nr = InitNornir(
            runner={
                "plugin": "threaded",
                "options": {
                    "num_workers": self.num_workers,
                },
            },
            inventory=inventory.load(),
            logging={"enabled": True, "level": "INFO"}
        )

        logger.info(f"Nornir initialized with {len(self.nr.inventory.hosts)} hosts, {self.num_workers} workers")

    def get_lldp_neighbors(self) -> Dict[str, Any]:
        """
        Collect LLDP neighbors from all devices

        Returns:
            Dict mapping device names to LLDP neighbor data
        """
        if not self.nr:
            raise RuntimeError("Nornir not initialized. Call initialize() first.")

        results = self.nr.run(task=napalm_get, getters=['lldp_neighbors'])
        
        output = {}
        for device_name, multi_result in results.items():
            if multi_result.failed:
                output[device_name] = {
                    'failed': True,
                    'error': str(multi_result.exception) if multi_result.exception else 'Unknown error'
                }
            else:
                lldp_data = multi_result[0].result.get('lldp_neighbors', {})
                output[device_name] = lldp_data
                output[device_name]['failed'] = False

        return output

    def get_lldp_neighbors_detail(self) -> Dict[str, Any]:
        """
        Collect detailed LLDP neighbors from all devices

        Returns:
            Dict mapping device names to detailed LLDP neighbor data
        """
        if not self.nr:
            raise RuntimeError("Nornir not initialized. Call initialize() first.")

        results = self.nr.run(task=napalm_get, getters=['lldp_neighbors_detail'])
        
        output = {}
        for device_name, multi_result in results.items():
            if multi_result.failed:
                output[device_name] = {
                    'failed': True,
                    'error': str(multi_result.exception) if multi_result.exception else 'Unknown error'
                }
            else:
                lldp_data = multi_result[0].result.get('lldp_neighbors_detail', {})
                output[device_name] = lldp_data
                output[device_name]['failed'] = False

        return output

    def get_config(self, retrieve: str = 'running') -> Dict[str, Any]:
        """
        Collect configurations from all devices

        Args:
            retrieve: Which config to retrieve ('running', 'startup', 'candidate', or 'all')

        Returns:
            Dict mapping device names to configuration data
        """
        if not self.nr:
            raise RuntimeError("Nornir not initialized. Call initialize() first.")

        results = self.nr.run(task=napalm_get, getters=['config'], retrieve=retrieve)
        
        output = {}
        for device_name, multi_result in results.items():
            if multi_result.failed:
                output[device_name] = {
                    'failed': True,
                    'error': str(multi_result.exception) if multi_result.exception else 'Unknown error'
                }
            else:
                config_data = multi_result[0].result.get('config', {})
                output[device_name] = config_data
                output[device_name]['failed'] = False

        return output

    def get_interfaces(self) -> Dict[str, Any]:
        """
        Collect interface information from all devices

        Returns:
            Dict mapping device names to interface data
        """
        if not self.nr:
            raise RuntimeError("Nornir not initialized. Call initialize() first.")

        results = self.nr.run(task=napalm_get, getters=['interfaces'])
        
        output = {}
        for device_name, multi_result in results.items():
            if multi_result.failed:
                output[device_name] = {
                    'failed': True,
                    'error': str(multi_result.exception) if multi_result.exception else 'Unknown error'
                }
            else:
                interface_data = multi_result[0].result.get('interfaces', {})
                output[device_name] = interface_data
                output[device_name]['failed'] = False

        return output

    def get_facts(self) -> Dict[str, Any]:
        """
        Collect device facts from all devices

        Returns:
            Dict mapping device names to facts data
        """
        if not self.nr:
            raise RuntimeError("Nornir not initialized. Call initialize() first.")

        results = self.nr.run(task=napalm_get, getters=['facts'])
        
        output = {}
        for device_name, multi_result in results.items():
            if multi_result.failed:
                output[device_name] = {
                    'failed': True,
                    'error': str(multi_result.exception) if multi_result.exception else 'Unknown error'
                }
            else:
                facts_data = multi_result[0].result.get('facts', {})
                output[device_name] = facts_data
                output[device_name]['failed'] = False

        return output

    def close(self):
        """Close all connections"""
        if self.nr:
            self.nr.close_connections()
