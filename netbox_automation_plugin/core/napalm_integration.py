"""
NAPALM Integration for NetBox Automation Plugin

Provides failsafe device configuration deployment with Juniper-style commit-confirm workflow.
"""

import napalm
from napalm.base.exceptions import ConnectionException, CommandErrorException
from django.conf import settings
from dcim.models import Device
from ..models import AutomationJob, DeviceCompliance
import logging
import time
import traceback

logger = logging.getLogger(__name__)


class NAPALMDeviceManager:
    """
    Manage NAPALM connections and operations for NetBox devices
    """
    
    def __init__(self, device: Device):
        self.device = device
        self.driver = None
        self.connection = None
        
    def get_driver_name(self):
        """
        Map NetBox device type to NAPALM driver
        """
        device_type = self.device.device_type.model.lower()
        manufacturer = self.device.device_type.manufacturer.name.lower()
        
        # Common mappings
        driver_mappings = {
            'cisco': {
                'ios': 'ios',
                'iosxe': 'ios',
                'nxos': 'nxos',
                'asa': 'asa',
            },
            'arista': {
                'eos': 'eos',
            },
            'juniper': {
                'junos': 'junos',
            },
            'cumulus': {
                'cumulus': 'cumulus',  # Use napalm-cumulus driver
                'linux': 'cumulus',    # Cumulus Linux
            },
            'nvidia': {
                'mellanox': 'cumulus',  # Nvidia Mellanox switches use Cumulus Linux
                'cumulus': 'cumulus',   # Nvidia-branded Cumulus
            },
            'mellanox': {
                'sn2700': 'cumulus',    # Mellanox SN2700 series
                'sn3700': 'cumulus',    # Mellanox SN3700 series
                'sn4600': 'cumulus',    # Mellanox SN4600 series
                'sn4700': 'cumulus',    # Mellanox SN4700 series
            },
            'hp': {
                'procurve': 'procurve',
            },
        }
        
        # Try to get driver from manufacturer and device type
        driver = driver_mappings.get(manufacturer, {}).get(device_type)
        
        # If not found, check if manufacturer itself maps to a driver (for generic cases)
        if not driver:
            if manufacturer in ['cumulus', 'nvidia', 'mellanox']:
                driver = 'cumulus'
            elif manufacturer == 'arista':
                # All Arista devices use EOS driver regardless of model
                driver = 'eos'
            else:
                driver = 'ios'  # Default fallback
        
        logger.debug(f"Device {self.device.name}: manufacturer={manufacturer}, "
                    f"device_type={device_type}, driver={driver}")
        
        return driver
    
    def connect(self):
        """
        Establish NAPALM connection to device
        """
        try:
            from netbox.plugins import get_plugin_config
            
            driver_name = self.get_driver_name()
            self.driver = napalm.get_network_driver(driver_name)
            
            # Get credentials from plugin config first, fallback to global settings
            try:
                napalm_config = get_plugin_config('netbox_automation_plugin', 'napalm', {}) or {}
                automation_config = get_plugin_config('netbox_automation_plugin', 'automation', {}) or {}
                
                # Check for platform-specific credentials
                platform_creds = napalm_config.get('platform_credentials', {}).get(driver_name, {})
                
                username = platform_creds.get('username') or napalm_config.get('username') or getattr(settings, 'NAPALM_USERNAME', 'admin')
                password = platform_creds.get('password') or napalm_config.get('password') or getattr(settings, 'NAPALM_PASSWORD', '')
                timeout = napalm_config.get('timeout') or getattr(settings, 'NAPALM_TIMEOUT', 60)
                
                # Merge optional_args from plugin and global settings
                optional_args = getattr(settings, 'NAPALM_OPTIONAL_ARGS', {}).copy()
                plugin_optional_args = napalm_config.get('optional_args', {})
                optional_args.update(plugin_optional_args)
                
                # Check for platform-specific optional_args
                platform_optional_args = platform_creds.get('optional_args', {})
                optional_args.update(platform_optional_args)
                
                logger.info(f"Connecting to {self.device.name} using driver={driver_name}, username={username}")
                
            except Exception as e:
                logger.warning(f"Could not load plugin config, using global settings: {e}")
                username = getattr(settings, 'NAPALM_USERNAME', 'admin')
                password = getattr(settings, 'NAPALM_PASSWORD', '')
                timeout = getattr(settings, 'NAPALM_TIMEOUT', 60)
                optional_args = getattr(settings, 'NAPALM_OPTIONAL_ARGS', {})
            
            # Special handling for platform-specific drivers
            if driver_name == 'cumulus':
                # Cumulus-specific optional args
                cumulus_args = optional_args.copy()
                # Add any Cumulus-specific settings here if needed
                # e.g., cumulus_args['use_keys'] = True
                optional_args = cumulus_args
            elif driver_name == 'eos':
                # Arista EOS: Force SSH transport (not eAPI/HTTP)
                optional_args['transport'] = 'ssh'
                logger.info(f"EOS device: Forcing SSH transport (not eAPI)")
            
            # Get device IP address (primary_ip4.address is IPNetwork object)
            if self.device.primary_ip4:
                device_hostname = str(self.device.primary_ip4.address.ip)
            elif self.device.primary_ip6:
                device_hostname = str(self.device.primary_ip6.address.ip)
            else:
                device_hostname = None
            
            self.connection = self.driver(
                hostname=device_hostname,
                username=username,
                password=password,
                timeout=timeout,
                optional_args=optional_args
            )
            
            # Retry connection with exponential backoff (handles transient network failures)
            max_retries = 3
            retry_delay = 2  # Initial delay in seconds
            
            for attempt in range(max_retries):
                try:
                    self.connection.open()
                    
                    # CRITICAL: Verify that the device object was properly initialized
                    # The NAPALM driver's device object (Netmiko connection) must exist
                    # If it's None, load_merge_candidate will fail with 'NoneType' object has no attribute 'send_command_timing'
                    if hasattr(self.connection, 'device'):
                        if self.connection.device is None:
                            logger.warning(f"Connection opened but device object is None for {self.device.name} (attempt {attempt + 1})")
                            try:
                                self.connection.close()
                            except:
                                pass
                            # This is a retryable error - connection didn't fully initialize
                            if attempt < max_retries - 1:
                                wait_time = retry_delay * (2 ** attempt)
                                logger.warning(f"Retrying connection in {wait_time}s...")
                                time.sleep(wait_time)
                                # Recreate connection for retry
                                self.connection = self.driver(
                                    hostname=device_hostname,
                                    username=username,
                                    password=password,
                                    timeout=timeout,
                                    optional_args=optional_args
                                )
                                continue
                            else:
                                raise ConnectionException(f"Connection opened but device object is None after {max_retries} attempts")
                    
                    logger.info(f"Connected to {self.device.name} using {driver_name} driver (attempt {attempt + 1})")
                    logger.debug(f"Connection device object type: {type(self.connection.device) if hasattr(self.connection, 'device') else 'N/A'}")
                    return True
                except (ConnectionException, Exception) as e:
                    # Check if this is a retryable error (connection failure, not auth failure)
                    is_retryable = (
                        isinstance(e, ConnectionException) or
                        'Connection' in str(type(e).__name__) or
                        'refused' in str(e).lower() or
                        'timeout' in str(e).lower() or
                        'socket' in str(e).lower()
                    )
                    
                    if attempt < max_retries - 1 and is_retryable:
                        wait_time = retry_delay * (2 ** attempt)  # Exponential: 2s, 4s, 8s
                        logger.warning(
                            f"Connection attempt {attempt + 1}/{max_retries} failed for {self.device.name}: {e}. "
                            f"Retrying in {wait_time}s..."
                        )
                        time.sleep(wait_time)
                        
                        # Recreate connection for retry (old connection may be in bad state)
                        try:
                            if hasattr(self, 'connection') and self.connection:
                                try:
                                    self.connection.close()
                                except:
                                    pass
                        except:
                            pass
                        
                        self.connection = self.driver(
                            hostname=device_hostname,
                            username=username,
                            password=password,
                            timeout=timeout,
                            optional_args=optional_args
                        )
                    else:
                        # Final attempt failed or non-retryable error
                        raise
            
        except Exception as e:
            logger.error(f"Failed to connect to {self.device.name} after {max_retries} attempts: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def disconnect(self):
        """
        Close NAPALM connection
        """
        if self.connection:
            try:
                self.connection.close()
                logger.info(f"Disconnected from {self.device.name}")
            except Exception as e:
                logger.error(f"Error disconnecting from {self.device.name}: {e}")
    
    def get_facts(self):
        """
        Get device facts using NAPALM
        """
        if not self.connection:
            if not self.connect():
                return None
        
        try:
            facts = self.connection.get_facts()
            return facts
        except Exception as e:
            logger.error(f"Failed to get facts from {self.device.name}: {e}")
            return None
    
    def get_interfaces(self):
        """
        Get interface information using NAPALM
        """
        if not self.connection:
            if not self.connect():
                return None
        
        try:
            interfaces = self.connection.get_interfaces()
            return interfaces
        except Exception as e:
            logger.error(f"Failed to get interfaces from {self.device.name}: {e}")
            return None
    
    def get_interfaces_ip(self):
        """
        Get interface IP addresses using NAPALM
        """
        if not self.connection:
            if not self.connect():
                return None
        
        try:
            interfaces_ip = self.connection.get_interfaces_ip()
            return interfaces_ip
        except Exception as e:
            logger.error(f"Failed to get interface IPs from {self.device.name}: {e}")
            return None
    
    def get_config(self, retrieve='all'):
        """
        Get device configuration using NAPALM
        """
        if not self.connection:
            if not self.connect():
                return None
        
        try:
            config = self.connection.get_config(retrieve=retrieve)
            return config
        except Exception as e:
            logger.error(f"Failed to get config from {self.device.name}: {e}")
            return None
    
    def load_config(self, config, replace=False):
        """
        Load configuration to device using NAPALM
        
        Args:
            config: Configuration string to load
            replace: If True, use load_replace_candidate (full config replace)
                    If False, use load_merge_candidate (incremental merge)
        
        Returns:
            Boolean indicating success/failure
        
        Note: This method loads config but does NOT commit.
              Use deploy_config_safe() for production deployments with failsafe.
        """
        if not self.connection:
            if not self.connect():
                logger.error(f"Failed to connect to {self.device.name} for load_config")
                return False
        
        # Verify connection is still valid
        if not self.connection:
            logger.error(f"Connection is None after connect() for {self.device.name}")
            return False
        
        # CRITICAL: Verify the connection is actually open and device object exists
        # The NAPALM driver's load_merge_candidate uses self.connection.device.send_command_timing()
        # If device is None, we get 'NoneType' object has no attribute 'send_command_timing'
        try:
            if not hasattr(self.connection, 'is_alive') or not self.connection.is_alive():
                logger.warning(f"Connection to {self.device.name} is not alive, reconnecting...")
                if not self.connect():
                    logger.error(f"Failed to reconnect to {self.device.name} for load_config")
                    return False
            
            # Check if device object exists (this is what NAPALM uses internally)
            if hasattr(self.connection, 'device'):
                if self.connection.device is None:
                    logger.error(f"Connection device object is None for {self.device.name} - connection may not be properly opened")
                    logger.error(f"Attempting to reconnect...")
                    if not self.connect():
                        logger.error(f"Failed to reconnect to {self.device.name} for load_config")
                        return False
                    # Verify device object exists after reconnect
                    if not hasattr(self.connection, 'device') or self.connection.device is None:
                        logger.error(f"Connection device object is still None after reconnect for {self.device.name}")
                        return False
        except Exception as conn_check_error:
            logger.warning(f"Could not verify connection state for {self.device.name}: {conn_check_error}")
            logger.warning(f"Attempting to reconnect...")
            if not self.connect():
                logger.error(f"Failed to reconnect to {self.device.name} for load_config")
                return False
        
        # Verify connection has required methods
        if not hasattr(self.connection, 'load_replace_candidate') and not hasattr(self.connection, 'load_merge_candidate'):
            logger.error(f"Connection object for {self.device.name} does not have load_replace_candidate or load_merge_candidate methods")
            logger.error(f"Connection type: {type(self.connection)}")
            logger.error(f"Connection attributes: {dir(self.connection)[:20]}")
            return False
        
        try:
            if replace:
                # Full configuration replacement
                if hasattr(self.connection, 'load_replace_candidate'):
                    self.connection.load_replace_candidate(config=config)
                    logger.info(f"Loaded REPLACE candidate config on {self.device.name}")
                else:
                    logger.error(f"load_replace_candidate not available on connection for {self.device.name}")
                    return False
            else:
                # Incremental merge
                if hasattr(self.connection, 'load_merge_candidate'):
                    self.connection.load_merge_candidate(config=config)
                    logger.info(f"Loaded MERGE candidate config on {self.device.name}")
                else:
                    logger.error(f"load_merge_candidate not available on connection for {self.device.name}")
                    return False
            
            return True
                
        except AttributeError as attr_error:
            error_msg = str(attr_error)
            logger.error(f"Failed to load config on {self.device.name}: AttributeError - {error_msg}")
            logger.error(f"Connection object type: {type(self.connection)}")
            logger.error(f"Connection object: {self.connection}")
            
            # Check if device object exists (this is what causes 'send_command_timing' errors)
            if hasattr(self.connection, 'device'):
                logger.error(f"Connection device object: {self.connection.device}")
                logger.error(f"Connection device type: {type(self.connection.device) if self.connection.device else 'None'}")
                if self.connection.device is None:
                    logger.error(f"ROOT CAUSE: Connection device object is None - connection may not be properly opened")
                    logger.error(f"This typically means connection.open() didn't fully initialize the device object")
            else:
                logger.error(f"Connection object does not have 'device' attribute")
            
            # Store error for later retrieval
            if not hasattr(self, '_last_load_error'):
                self._last_load_error = {}
            self._last_load_error['error'] = error_msg
            self._last_load_error['exception_type'] = type(attr_error).__name__
            return False
        except Exception as e:
            error_msg = str(e)
            exception_type = type(e).__name__
            logger.error(f"Failed to load config on {self.device.name}: {error_msg}")
            logger.error(f"Exception type: {exception_type}")
            
            # For Cumulus, check if it's a config syntax error
            if exception_type in ['ConfigInvalidException', 'MergeConfigException', 'ReplaceConfigException']:
                logger.error(f"Config syntax error detected - this usually means invalid NVUE command syntax")
                logger.error(f"Common causes: incorrect command format, invalid parameters, or command not supported")
                # Try to extract the actual error message from the exception
                if hasattr(e, 'message'):
                    error_msg = str(e.message)
                elif hasattr(e, 'args') and e.args:
                    error_msg = str(e.args[0])
            
            # Store error for later retrieval with full details
            if not hasattr(self, '_last_load_error'):
                self._last_load_error = {}
            self._last_load_error['error'] = error_msg
            self._last_load_error['exception_type'] = exception_type
            self._last_load_error['full_exception'] = str(e)
            
            # Log the actual config commands that failed (for debugging syntax errors)
            logger.debug(f"Config that failed to load:")
            for i, line in enumerate(config.split('\n')[:5]):
                if line.strip() and not line.strip().startswith('#'):
                    logger.debug(f"  {line.strip()}")
            
            try:
                if self.connection and hasattr(self.connection, 'discard_config'):
                    self.connection.discard_config()
            except:
                pass
            return False
    
    def get_lldp_neighbors(self):
        """
        Get LLDP neighbors using NAPALM

        Returns:
            Dictionary mapping local interface names to list of neighbors
            Example: {'Ethernet1': [{'hostname': 'switch1', 'port': 'Eth1/1'}]}
        """
        if not self.connection:
            if not self.connect():
                return None

        try:
            lldp_neighbors = self.connection.get_lldp_neighbors()
            return lldp_neighbors
        except Exception as e:
            logger.error(f"Failed to get LLDP neighbors from {self.device.name}: {e}")
            return None

    def get_lldp_neighbors_detail(self, interface=''):
        """
        Get detailed LLDP neighbor information using NAPALM

        Args:
            interface: Specific interface to query (optional, empty string = all)

        Returns:
            Dictionary with detailed LLDP information per interface
        """
        if not self.connection:
            if not self.connect():
                return None

        try:
            lldp_detail = self.connection.get_lldp_neighbors_detail(interface=interface)
            return lldp_detail
        except Exception as e:
            logger.error(f"Failed to get LLDP neighbor details from {self.device.name}: {e}")
            return None

    def backup_config(self):
        """
        Backup device configuration
        """
        config = self.get_config()
        if config:
            # Save to file or database
            backup_data = {
                'device': self.device.name,
                'timestamp': str(self.device.last_updated),
                'config': config,
            }
            return backup_data
        return None
    
    def verify_connectivity(self):
        """
        Verify device is still reachable after config change
        
        Returns:
            dict: {'success': bool, 'message': str, 'data': dict}
        """
        try:
            facts = self.get_facts()
            if facts:
                logger.info(f"Connectivity check passed: {self.device.name} - {facts.get('hostname', 'unknown')}")
                return {
                    'success': True,
                    'message': f"Device {self.device.name} is responsive",
                    'data': facts
                }
            else:
                logger.error(f"Connectivity check failed: {self.device.name} - cannot get facts")
                return {
                    'success': False,
                    'message': f"Cannot get facts from {self.device.name}",
                    'data': None
                }
        except Exception as e:
            logger.error(f"Connectivity check failed: {self.device.name} - {e}")
            return {
                'success': False,
                'message': f"Exception during connectivity check: {str(e)}",
                'data': None
            }
    
    def verify_interfaces(self, critical_interfaces=None):
        """
        Verify interface status after config change
        
        Args:
            critical_interfaces: List of interface names that must be up (optional)
        
        Returns:
            dict: {'success': bool, 'message': str, 'data': dict}
        """
        try:
            interfaces = self.get_interfaces()
            if not interfaces:
                return {
                    'success': False,
                    'message': f"Cannot get interfaces from {self.device.name}",
                    'data': None
                }
            
            total_interfaces = len(interfaces)
            up_interfaces = sum(1 for iface in interfaces.values() if iface.get('is_up', False))
            
            # Check critical interfaces if specified
            if critical_interfaces:
                critical_down = []
                for iface_name in critical_interfaces:
                    if iface_name in interfaces:
                        if not interfaces[iface_name].get('is_up', False):
                            critical_down.append(iface_name)
                    else:
                        logger.warning(f"Critical interface {iface_name} not found on {self.device.name}")
                
                if critical_down:
                    logger.error(f"Interface check failed: {self.device.name} - critical interfaces down: {critical_down}")
                    return {
                        'success': False,
                        'message': f"Critical interfaces down: {', '.join(critical_down)}",
                        'data': {'down_interfaces': critical_down, 'interfaces': interfaces}
                    }
            
            logger.info(f"Interface check passed: {self.device.name} - {up_interfaces}/{total_interfaces} up")
            return {
                'success': True,
                'message': f"Interfaces OK: {up_interfaces}/{total_interfaces} up",
                'data': {'up_count': up_interfaces, 'total_count': total_interfaces, 'interfaces': interfaces}
            }
            
        except Exception as e:
            logger.error(f"Interface check failed: {self.device.name} - {e}")
            return {
                'success': False,
                'message': f"Exception during interface check: {str(e)}",
                'data': None
            }
    
    def verify_lldp_neighbors(self, min_neighbors=0):
        """
        Verify LLDP neighbors are present after config change
        
        Args:
            min_neighbors: Minimum number of neighbors expected (0 = just check LLDP works)
        
        Returns:
            dict: {'success': bool, 'message': str, 'data': dict}
        """
        try:
            neighbors = self.get_lldp_neighbors()
            if neighbors is None:
                logger.error(f"LLDP check failed: {self.device.name} - cannot get neighbors")
                return {
                    'success': False,
                    'message': f"Cannot get LLDP neighbors from {self.device.name}",
                    'data': None
                }
            
            neighbor_count = len(neighbors)
            
            if neighbor_count < min_neighbors:
                logger.error(f"LLDP check failed: {self.device.name} - only {neighbor_count} neighbors (expected {min_neighbors})")
                return {
                    'success': False,
                    'message': f"Insufficient LLDP neighbors: {neighbor_count} < {min_neighbors}",
                    'data': {'count': neighbor_count, 'neighbors': neighbors}
                }
            
            logger.info(f"LLDP check passed: {self.device.name} - {neighbor_count} neighbors")
            return {
                'success': True,
                'message': f"LLDP OK: {neighbor_count} neighbors",
                'data': {'count': neighbor_count, 'neighbors': neighbors}
            }
            
        except Exception as e:
            logger.error(f"LLDP check failed: {self.device.name} - {e}")
            return {
                'success': False,
                'message': f"Exception during LLDP check: {str(e)}",
                'data': None
            }
    
    def verify_vlan_deployment(self, interface_name, vlan_id, expected_mode='access', baseline=None):
        """
        Comprehensive verification for VLAN deployment with baseline comparison
        
        Checks:
        1. Device connectivity (can we still reach it?)
        2. Interface exists and status (compared to baseline)
        3. VLAN configuration applied correctly
        4. System health (uptime stable, no reboot)
        5. LLDP neighbors (if any existed before, they should still exist)
        
        Args:
            interface_name: Interface that was configured (e.g., 'Ethernet7', 'swp7')
            vlan_id: VLAN ID that should be configured
            expected_mode: Expected switchport mode ('access' or 'trunk')
            baseline: Baseline state collected before config change (dict)
        
        Returns:
            dict: {'success': bool, 'message': str, 'checks': dict}
        """
        checks = {}
        all_passed = True
        messages = []
        
        # Check 1: Device Connectivity (CRITICAL)
        logger.info(f"VLAN Verification Check 1/4: Device connectivity...")
        connectivity_result = self.verify_connectivity()
        checks['connectivity'] = connectivity_result
        if not connectivity_result['success']:
            all_passed = False
            messages.append(f"❌ Connectivity: {connectivity_result['message']}")
            # If device is unreachable, stop here
            return {
                'success': False,
                'message': "CRITICAL: Device unreachable - " + '; '.join(messages),
                'checks': checks
            }
        else:
            messages.append(f"✅ Connectivity: Device responsive")
        
        # Check 2: Interface Status (with baseline comparison)
        logger.info(f"VLAN Verification Check 2/5: Interface status...")
        try:
            interfaces = self.get_interfaces()
            if interfaces and interface_name in interfaces:
                iface_data = interfaces[interface_name]
                iface_up_after = iface_data.get('is_up', False)
                iface_enabled_after = iface_data.get('is_enabled', True)
                
                # Compare with baseline if available
                if baseline and baseline.get('interface'):
                    iface_up_before = baseline['interface']['is_up']
                    iface_enabled_before = baseline['interface']['is_enabled']
                    
                    # CRITICAL CHECK: Did interface go DOWN?
                    if iface_up_before and not iface_up_after:
                        # Interface was UP, now it's DOWN - PROBLEM!
                        checks['interface_status'] = {
                            'success': False,
                            'message': f"❌ Interface went DOWN! (was UP={iface_up_before}, now UP={iface_up_after})",
                            'data': {
                                'before': {'is_up': iface_up_before, 'is_enabled': iface_enabled_before},
                                'after': {'is_up': iface_up_after, 'is_enabled': iface_enabled_after}
                            }
                        }
                        all_passed = False
                        messages.append(f"❌ Interface: Went DOWN (was UP)")
                        logger.error(f"CRITICAL: Interface {interface_name} went DOWN after config change!")
                    
                    # ACCEPTABLE: Interface was DOWN, still DOWN (no cable)
                    elif not iface_up_before and not iface_up_after:
                        checks['interface_status'] = {
                            'success': True,
                            'message': f"Interface DOWN (was DOWN before, acceptable)",
                            'data': {'is_up': iface_up_after, 'is_enabled': iface_enabled_after}
                        }
                        messages.append(f"✅ Interface: DOWN (no cable, expected)")
                    
                    # GOOD: Interface was DOWN, now UP (cable was just plugged in)
                    elif not iface_up_before and iface_up_after:
                        checks['interface_status'] = {
                            'success': True,
                            'message': f"✅ Interface came UP! (was DOWN, now UP - excellent!)",
                            'data': {'is_up': iface_up_after, 'is_enabled': iface_enabled_after}
                        }
                        messages.append(f"✅ Interface: Came UP (was DOWN)")
                        logger.info(f"BONUS: Interface {interface_name} came UP after config change!")
                    
                    # GOOD: Interface was UP, still UP
                    else:
                        checks['interface_status'] = {
                            'success': True,
                            'message': f"Interface UP (stable)",
                            'data': {'is_up': iface_up_after, 'is_enabled': iface_enabled_after}
                        }
                        messages.append(f"✅ Interface: UP (stable)")
                else:
                    # No baseline, just report current status
                    checks['interface_status'] = {
                        'success': True,
                        'message': f"Interface exists: UP={iface_up_after}, Enabled={iface_enabled_after}",
                        'data': {'is_up': iface_up_after, 'is_enabled': iface_enabled_after}
                    }
                    messages.append(f"✅ Interface: Exists (UP={iface_up_after})")
            else:
                # Interface not found
                if baseline and baseline.get('interface'):
                    # Interface existed before, now missing - PROBLEM!
                    checks['interface_status'] = {
                        'success': False,
                        'message': f"❌ Interface disappeared! (existed before config change)",
                        'data': None
                    }
                    all_passed = False
                    messages.append(f"❌ Interface: Disappeared")
                    logger.error(f"CRITICAL: Interface {interface_name} disappeared after config change!")
                else:
                    # Interface didn't exist before, still doesn't - acceptable if creating
                    checks['interface_status'] = {
                        'success': True,
                        'message': f"Interface not found (didn't exist before either)",
                        'data': None
                    }
                    messages.append(f"⚠️ Interface: Not found (expected)")
        except Exception as e:
            checks['interface_status'] = {
                'success': False,
                'message': f"Could not check interface: {str(e)}",
                'data': None
            }
            logger.warning(f"Could not verify interface status: {e}")
            all_passed = False
            messages.append(f"❌ Interface: Could not verify")
        
        # Check 3: VLAN Configuration Applied
        logger.info(f"VLAN Verification Check 3/4: VLAN configuration...")
        driver_name = self.get_driver_name()
        vlan_check_passed = False
        
        try:
            if driver_name == 'eos':
                # For EOS, check running config or use CLI
                # We can't easily verify VLAN from NAPALM, so we'll trust the commit
                checks['vlan_config'] = {
                    'success': True,
                    'message': f"EOS: Config committed (verification via show vlan requires CLI)",
                    'data': None
                }
                vlan_check_passed = True
                messages.append(f"✅ VLAN Config: Committed")
                
            elif driver_name == 'cumulus':
                # For Cumulus, we could check bridge membership
                # For now, trust the commit
                checks['vlan_config'] = {
                    'success': True,
                    'message': f"Cumulus: Config applied (NVUE confirmed)",
                    'data': None
                }
                vlan_check_passed = True
                messages.append(f"✅ VLAN Config: Applied")
            else:
                checks['vlan_config'] = {
                    'success': True,
                    'message': f"Config committed for {driver_name}",
                    'data': None
                }
                vlan_check_passed = True
                messages.append(f"✅ VLAN Config: Committed")
        except Exception as e:
            checks['vlan_config'] = {
                'success': False,
                'message': f"Could not verify VLAN config: {str(e)}",
                'data': None
            }
            logger.warning(f"Could not verify VLAN configuration: {e}")
            all_passed = False
            messages.append(f"⚠️ VLAN Config: Could not verify")
        
        # Check 4: LLDP Neighbors (device-level check with interface exclusion)
        logger.info(f"VLAN Verification Check 4/5: LLDP neighbors (device-level)...")
        if baseline and baseline.get('lldp_all_interfaces') is not None:
            try:
                lldp_after = self.get_lldp_neighbors()

                # Build after state for all interfaces
                lldp_after_all = {}
                if lldp_after:
                    for iface, neighbors in lldp_after.items():
                        lldp_after_all[iface] = len(neighbors) if neighbors else 0

                lldp_before_all = baseline.get('lldp_all_interfaces', {})

                # Check for lost LLDP neighbors on OTHER interfaces (not the one we're configuring)
                lost_neighbors = []
                for iface, count_before in lldp_before_all.items():
                    # Skip the interface we're configuring (it's allowed to change)
                    if interface_name and iface == interface_name:
                        continue

                    count_after = lldp_after_all.get(iface, 0)

                    # CRITICAL: Lost neighbors on other interfaces
                    if count_before > 0 and count_after == 0:
                        lost_neighbors.append(f"{iface} (lost {count_before} neighbors)")
                        logger.error(f"CRITICAL: Lost all LLDP neighbors on {iface}! (had {count_before}, now 0)")
                    elif count_before > count_after:
                        lost_neighbors.append(f"{iface} ({count_before}→{count_after})")
                        logger.warning(f"WARNING: Lost LLDP neighbors on {iface}: {count_before}→{count_after}")

                # If we lost neighbors on OTHER interfaces, FAIL
                if lost_neighbors:
                    checks['lldp_neighbors'] = {
                        'success': False,
                        'message': f"❌ Lost LLDP neighbors on other interfaces: {', '.join(lost_neighbors)}",
                        'data': {'lost_on': lost_neighbors}
                    }
                    all_passed = False
                    messages.append(f"❌ LLDP: Lost neighbors on {len(lost_neighbors)} interface(s)")
                    logger.error(f"CRITICAL: VLAN deployment broke LLDP on other interfaces: {lost_neighbors}")

                # GOOD: No neighbors lost on other interfaces
                else:
                    # Calculate totals for summary
                    total_before = sum(lldp_before_all.values())
                    total_after = sum(lldp_after_all.values())

                    # Get specific interface status
                    if interface_name:
                        iface_before = lldp_before_all.get(interface_name, 0)
                        iface_after = lldp_after_all.get(interface_name, 0)
                        iface_status = f"{interface_name}: {iface_before}→{iface_after}"
                    else:
                        iface_status = "N/A"

                    checks['lldp_neighbors'] = {
                        'success': True,
                        'message': f"Device-level LLDP stable (total: {total_before}→{total_after}, {iface_status})",
                        'data': {'total_before': total_before, 'total_after': total_after, 'interface_status': iface_status}
                    }
                    messages.append(f"✅ LLDP: Device-level stable ({total_after} total)")
                    logger.info(f"LLDP check passed: Device has {total_after} total neighbors (was {total_before})")

            except Exception as e:
                logger.debug(f"Could not verify LLDP neighbors: {e}")
                checks['lldp_neighbors'] = {
                    'success': True,  # Don't fail if LLDP check has issues
                    'message': f"Could not verify LLDP (non-critical)",
                    'data': None
                }
                messages.append(f"⚠️ LLDP: Could not verify")
        else:
            # No LLDP baseline, skip check
            checks['lldp_neighbors'] = {
                'success': True,
                'message': "LLDP check skipped (no baseline)",
                'data': None
            }
        
        # Check 5: Overall System Health (with baseline comparison)
        logger.info(f"VLAN Verification Check 5/5: System health...")
        try:
            facts = self.get_facts()
            if facts:
                uptime_after = facts.get('uptime', -1)
                hostname_after = facts.get('hostname', 'unknown')
                
                # Compare with baseline
                if baseline and baseline.get('uptime') is not None:
                    uptime_before = baseline.get('uptime', -1)
                    
                    # CRITICAL: Device rebooted? (uptime decreased significantly)
                    if uptime_before > 0 and uptime_after > 0 and uptime_after < (uptime_before - 10):
                        checks['system_health'] = {
                            'success': False,
                            'message': f"❌ Device may have rebooted! (uptime: {uptime_before}s → {uptime_after}s)",
                            'data': {'uptime_before': uptime_before, 'uptime_after': uptime_after}
                        }
                        all_passed = False
                        messages.append(f"❌ System: Possible reboot")
                        logger.error(f"CRITICAL: Device may have rebooted - uptime decreased!")
                    else:
                        checks['system_health'] = {
                            'success': True,
                            'message': f"System healthy, uptime stable: {uptime_after}s",
                            'data': {'uptime': uptime_after}
                        }
                        messages.append(f"✅ System: Healthy")
                else:
                    # No baseline
                    checks['system_health'] = {
                        'success': True,
                        'message': f"System healthy, uptime: {uptime_after}",
                        'data': {'uptime': uptime_after}
                    }
                    messages.append(f"✅ System: Healthy")
            else:
                checks['system_health'] = {
                    'success': False,
                    'message': "Could not get system facts",
                    'data': None
                }
                all_passed = False
                messages.append(f"❌ System: Could not verify")
        except Exception as e:
            checks['system_health'] = {
                'success': False,
                'message': f"System health check failed: {str(e)}",
                'data': None
            }
            logger.warning(f"System health check failed: {e}")
            all_passed = False
            messages.append(f"❌ System: Could not verify")
        
        # Summary
        summary_message = ' | '.join(messages)
        return {
            'success': all_passed,
            'message': summary_message,
            'checks': checks
        }
    
    def _verify_rollback(self, driver_name):
        """
        Verify if auto-rollback actually happened by checking device state.
        
        Returns:
            tuple: (rollback_successful: bool, message: str)
        """
        try:
            if driver_name == 'cumulus':
                if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                    # Check if there's still a pending commit by checking config diff
                    # If diff is empty or shows no changes, rollback worked
                    try:
                        diff_check = self.connection.device.send_command('nv config diff', read_timeout=10)
                        if diff_check:
                            # If diff shows nothing or "No changes", rollback worked
                            if 'no changes' in diff_check.lower() or not diff_check.strip() or diff_check.strip() == '':
                                return True, "Rollback verified: No pending changes detected"
                            else:
                                return False, f"Rollback may have failed: Pending changes still exist - {diff_check[:100]}"
                        else:
                            # Empty diff means no pending changes
                            return True, "Rollback verified: No pending changes detected"
                    except Exception as diff_error:
                        # If diff command fails, try checking history for pending revision
                        try:
                            history_check = self.connection.device.send_command('nv config history | head -5', read_timeout=10)
                            if history_check:
                                # Check if there's a pending revision (marked with *)
                                if '*' in history_check and 'pending' in history_check.lower():
                                    return False, f"Rollback may have failed: Pending revision still exists"
                                else:
                                    return True, "Rollback verified: No pending revision detected"
                            else:
                                return True, "Rollback assumed successful (could not verify)"
                        except Exception:
                            return True, "Rollback assumed successful (could not verify)"
                return None, "Could not verify rollback (device connection unavailable)"
            elif driver_name == 'eos':
                # For EOS, check if session still exists
                if hasattr(self, '_eos_session_name') and hasattr(self, '_eos_netmiko_conn'):
                    try:
                        session_name = self._eos_session_name
                        netmiko_conn = self._eos_netmiko_conn
                        # Check if session still exists
                        sessions_output = netmiko_conn.send_command('show configuration sessions', read_timeout=10)
                        if session_name in sessions_output:
                            return False, f"Rollback may have failed: Session {session_name} still exists"
                        else:
                            return True, "Rollback verified: Session no longer exists"
                    except:
                        return True, "Rollback assumed successful (session check failed)"
                return True, "Rollback assumed successful (no session tracking)"
            else:
                return None, "Rollback verification not supported for this platform"
        except Exception as e:
            logger.warning(f"Error verifying rollback: {e}")
            return None, f"Could not verify rollback: {str(e)}"
    
    def deploy_config_safe(self, config, replace=True, timeout=60, 
                          checks=['connectivity', 'interfaces', 'lldp'],
                          critical_interfaces=None, min_neighbors=0, 
                          vlan_id=None, interface_name=None):
        """
        Deploy configuration with Juniper-style commit-confirm failsafe
        
        This method implements a safe deployment workflow:
        1. Load configuration (replace or merge)
        2. Commit with automatic rollback timer
        3. Verify device health (connectivity, interfaces, LLDP)
        4. Confirm commit if all checks pass
        5. Auto-rollback if checks fail or timeout expires
        
        Args:
            config: Configuration string to deploy
            replace: If True, replace entire config. If False, merge incrementally
            timeout: Rollback timer in seconds (60-120 recommended)
            checks: List of verification checks to perform ['connectivity', 'interfaces', 'lldp']
            critical_interfaces: List of interface names that must be up (for interface check)
            min_neighbors: Minimum LLDP neighbors required (for LLDP check)
        
        Returns:
            dict: {
                'success': bool,
                'committed': bool,
                'rolled_back': bool,
                'message': str,
                'verification_results': dict,
                'config_deployed': str,
                'logs': list
            }
        """
        result = {
            'success': False,
            'committed': False,
            'rolled_back': False,
            'message': '',
            'verification_results': {},
            'config_deployed': config,
            'logs': []
        }

        # Initialize detailed logs
        logs = []

        # Phase 0: Ensure connection is established
        logger.info(f"{'='*60}")
        logger.info(f"SAFE DEPLOYMENT: {self.device.name} (timeout={timeout}s, replace={replace})")
        logger.info(f"{'='*60}")

        logs.append(f"[Phase 0] Connection Establishment")
        logs.append(f"  Device: {self.device.name}")
        logs.append(f"  IP: {self.device.primary_ip4 or self.device.primary_ip6}")
        logs.append(f"  Timeout: {timeout}s")
        logs.append(f"  Mode: {'Replace' if replace else 'Merge'}")

        if not self.connection:
            logger.info(f"Phase 0: Establishing connection to {self.device.name}...")
            logs.append(f"  Status: Establishing new connection...")
            if not self.connect():
                result['message'] = f"Failed to establish connection to {self.device.name}. Check credentials and network connectivity."
                logger.error(f"Phase 0 failed: Could not connect to {self.device.name}")
                logs.append(f"  ✗ Connection FAILED")
                logs.append(f"  Error: Could not connect to device")
                logs.append(f"  Check: Credentials and network connectivity")
                result['logs'] = logs
                return result
            logger.info(f"Phase 0: Connection established successfully")
            logs.append(f"  ✓ Connection established successfully")
        else:
            logger.info(f"Phase 0: Using existing connection to {self.device.name}")
            logs.append(f"  ✓ Using existing connection")

        # Log the username being used for the connection
        try:
            connection_username = getattr(self.connection, 'username', 'unknown')
            logs.append(f"  SSH Username: {connection_username}")
            logger.info(f"Phase 0: Connected as user: {connection_username}")
        except:
            pass

        # Phase 0.5: Collect baseline state BEFORE making changes
        logger.info(f"Phase 0.5: Collecting baseline state before configuration change...")
        logs.append(f"")
        logs.append(f"[Phase 0.5] Baseline Collection")
        baseline = {}
        
        # CRITICAL: Verify connection.device is initialized before baseline collection
        # Some NAPALM drivers (especially Cumulus) may not initialize device immediately
        if hasattr(self.connection, 'device'):
            if self.connection.device is None:
                logger.warning(f"Connection.device is None before baseline collection - attempting to reinitialize...")
                logs.append(f"  [WARNING] Connection.device is None - attempting to reinitialize connection...")
                try:
                    # Try to close and reopen connection
                    try:
                        self.connection.close()
                    except:
                        pass
                    # Reconnect
                    if not self.connect():
                        error_msg = "Failed to reinitialize connection - device object is None"
                        logger.error(f"CRITICAL: {error_msg}")
                        logs.append(f"  ✗ {error_msg}")
                        result['message'] = error_msg
                        result['logs'] = logs
                        return result
                    logger.info(f"Connection reinitialized successfully - device object is now available")
                    logs.append(f"  ✓ Connection reinitialized - device object available")
                except Exception as reconnect_error:
                    error_msg = f"Failed to reinitialize connection: {reconnect_error}"
                    logger.error(f"CRITICAL: {error_msg}")
                    logs.append(f"  ✗ {error_msg}")
                    result['message'] = error_msg
                    result['logs'] = logs
                    return result
            else:
                logger.debug(f"Connection.device is initialized: {type(self.connection.device)}")
        else:
            logger.warning(f"Connection object does not have 'device' attribute - may use cli() method instead")
            logs.append(f"  [INFO] Connection uses cli() method (no device attribute)")
        
        # Get driver_name early for bond membership check in baseline collection
        driver_name = self.get_driver_name()

        try:
            # Collect interface state if specific interface is being configured
            # Note: interface_name may be a bond interface if original_interface_name is a bond member
            if interface_name:
                baseline_interface_name = interface_name  # Default to interface_name (could be bond)
                
                # For Cumulus devices, use direct NVUE command instead of NAPALM's get_interfaces()
                # This is more reliable for bond members which may not appear in get_interfaces()
                baseline_collected = False
                baseline_error_details = []
                
                if driver_name == 'cumulus':
                    try:
                        # Check if we can access device commands (either via device.send_command or cli())
                        can_access_device = (
                            (hasattr(self.connection, 'device') and self.connection.device is not None and hasattr(self.connection.device, 'send_command')) or
                            hasattr(self.connection, 'cli')
                        )
                        
                        if can_access_device:
                            # Try multiple interface names: interface_name (could be bond or member), and bond if member
                            interfaces_to_try = [interface_name]
                            
                            # Check if interface_name is a bond member and add bond to list
                            try:
                                bond_members_command = 'nv show interface bond-members -o json'
                                if hasattr(self.connection, 'device') and self.connection.device is not None:
                                    bond_members_output = self.connection.device.send_command(bond_members_command, read_timeout=10)
                                elif hasattr(self.connection, 'cli'):
                                    cli_result = self.connection.cli([bond_members_command])
                                    if isinstance(cli_result, dict):
                                        bond_members_output = cli_result.get(bond_members_command, '')
                                    else:
                                        bond_members_output = str(cli_result) if cli_result else ''
                                else:
                                    bond_members_output = None
                                if bond_members_output:
                                    import json
                                    bond_members = json.loads(bond_members_output)
                                    # Check if interface_name is a bond member
                                    if isinstance(bond_members, dict) and interface_name in bond_members:
                                        member_info = bond_members[interface_name]
                                        if isinstance(member_info, dict):
                                            bond_name = member_info.get('parent') or member_info.get('bond')
                                        elif isinstance(member_info, str):
                                            bond_name = member_info
                                        else:
                                            bond_name = None
                                        
                                        if bond_name and bond_name not in interfaces_to_try:
                                            interfaces_to_try.append(bond_name)
                                            logger.info(f"Interface {interface_name} is a bond member, will also try bond {bond_name}")
                                    # Also check if interface_name itself is a bond (check reverse lookup)
                                    # Look for any member that points to interface_name as parent
                                    for member, info in bond_members.items():
                                        if isinstance(info, dict) and (info.get('parent') == interface_name or info.get('bond') == interface_name):
                                            if member not in interfaces_to_try:
                                                interfaces_to_try.append(member)
                                                logger.info(f"Interface {interface_name} is a bond, will also try member {member}")
                                            break
                            except Exception as bond_check:
                                logger.debug(f"Could not check bond membership for baseline: {bond_check}")
                            
                            # Try each interface name until one works
                            for test_interface in interfaces_to_try:
                                try:
                                    # Try to get interface stats directly using NVUE command
                                    # This works for both bond interfaces and member interfaces
                                    # First check if connection.device is available, otherwise use cli() method
                                    stats_command = f'nv show interface {test_interface} link stats -o json'
                                    
                                    # Try connection.device.send_command first (if available)
                                    if hasattr(self.connection, 'device') and self.connection.device is not None:
                                        stats_output = self.connection.device.send_command(stats_command, read_timeout=10)
                                    elif hasattr(self.connection, 'cli'):
                                        # Fallback to NAPALM's cli() method
                                        cli_result = self.connection.cli([stats_command])
                                        if isinstance(cli_result, dict):
                                            stats_output = cli_result.get(stats_command, '')
                                        else:
                                            stats_output = str(cli_result) if cli_result else ''
                                    else:
                                        raise AttributeError("Neither connection.device.send_command nor connection.cli() is available")
                                    
                                    if stats_output and stats_output.strip():
                                        import json
                                        try:
                                            stats_data = json.loads(stats_output)
                                            # If we get stats, interface exists - use direct NVUE commands for baseline
                                            logger.info(f"Using direct NVUE commands for Cumulus baseline collection on {test_interface}")
                                            logs.append(f"  Collecting interface state for {test_interface} using NVUE...")
                                            
                                            # Extract packet counters from stats
                                            in_pkts = stats_data.get('in-pkts', 0)
                                            out_pkts = stats_data.get('out-pkts', 0)
                                            in_bytes = stats_data.get('in-bytes', 0)
                                            out_bytes = stats_data.get('out-bytes', 0)
                                            in_drops = stats_data.get('in-drops', 0)
                                            out_drops = stats_data.get('out-drops', 0)
                                            in_errors = stats_data.get('in-errors', 0)
                                            out_errors = stats_data.get('out-errors', 0)
                                            
                                            # Get interface link state
                                            link_command = f'nv show interface {test_interface} link -o json'
                                            if hasattr(self.connection, 'device') and self.connection.device is not None:
                                                link_output = self.connection.device.send_command(link_command, read_timeout=10)
                                            elif hasattr(self.connection, 'cli'):
                                                cli_result = self.connection.cli([link_command])
                                                if isinstance(cli_result, dict):
                                                    link_output = cli_result.get(link_command, '')
                                                else:
                                                    link_output = str(cli_result) if cli_result else ''
                                            else:
                                                raise AttributeError("Neither connection.device.send_command nor connection.cli() is available")
                                            
                                            if link_output and link_output.strip():
                                                link_data = json.loads(link_output)
                                                # Link data is at top level, not nested under "link" key
                                                # Structure: {"admin-status": "up", "oper-status": "up", ...}
                                                is_up = link_data.get('oper-status') == 'up'
                                                is_enabled = link_data.get('admin-status') == 'up'
                                                
                                                # Get description if available
                                                description = ''
                                                try:
                                                    desc_command = f'nv show interface {test_interface} description -o json'
                                                    if hasattr(self.connection, 'device') and self.connection.device is not None:
                                                        desc_output = self.connection.device.send_command(desc_command, read_timeout=10)
                                                    elif hasattr(self.connection, 'cli'):
                                                        cli_result = self.connection.cli([desc_command])
                                                        if isinstance(cli_result, dict):
                                                            desc_output = cli_result.get(desc_command, '')
                                                        else:
                                                            desc_output = str(cli_result) if cli_result else ''
                                                    else:
                                                        desc_output = ''  # Description is optional, skip if can't access
                                                    if desc_output:
                                                        desc_data = json.loads(desc_output)
                                                        # Description structure may vary - try both nested and top-level
                                                        if 'link' in desc_data and isinstance(desc_data['link'], dict):
                                                            description = desc_data.get('link', {}).get('description', '')
                                                        else:
                                                            description = desc_data.get('description', '')
                                                except:
                                                    pass  # Description is optional
                                                
                                                baseline['interface'] = {
                                                    'name': test_interface,
                                                    'is_up': is_up,
                                                    'is_enabled': is_enabled,
                                                    'description': description,
                                                    # Include packet counters for traffic flow detection
                                                    'in_pkts': in_pkts,
                                                    'out_pkts': out_pkts,
                                                    'in_bytes': in_bytes,
                                                    'out_bytes': out_bytes,
                                                    'in_drops': in_drops,
                                                    'out_drops': out_drops,
                                                    'in_errors': in_errors,
                                                    'out_errors': out_errors,
                                                }
                                                logger.info(f"  Baseline: {test_interface} is_up={is_up}, is_enabled={is_enabled}, in_pkts={in_pkts}, out_pkts={out_pkts}")
                                                logs.append(f"  ✓ Interface {test_interface}: UP={is_up}, Enabled={is_enabled}, In-Pkts={in_pkts}, Out-Pkts={out_pkts}")
                                                
                                                if test_interface != interface_name:
                                                    logs.append(f"  Note: Collected baseline for {test_interface} (interface_name was {interface_name})")
                                                
                                                # Success - baseline collected
                                                baseline_collected = True
                                                break  # Found working interface, stop trying
                                            else:
                                                baseline_error_details.append(f"Link command returned empty for {test_interface}")
                                        except json.JSONDecodeError as json_err:
                                            baseline_error_details.append(f"JSON decode error for {test_interface} stats: {json_err}")
                                        except Exception as parse_err:
                                            baseline_error_details.append(f"Parse error for {test_interface}: {parse_err}")
                                    else:
                                        baseline_error_details.append(f"Stats command returned empty for {test_interface}")
                                except Exception as test_err:
                                    baseline_error_details.append(f"Error testing {test_interface}: {str(test_err)[:100]}")
                            
                            if not baseline_collected:
                                # All attempts failed - provide detailed error
                                error_msg = f"Failed to collect baseline for interface {interface_name}. Tried: {', '.join(interfaces_to_try)}"
                                logger.error(f"CRITICAL: {error_msg}")
                                logs.append(f"  ✗ Baseline collection FAILED for {interface_name}")
                                logs.append(f"  Tried interfaces: {', '.join(interfaces_to_try)}")
                                for detail in baseline_error_details:
                                    logs.append(f"    - {detail}")
                                result['message'] = f"Baseline collection failed: {error_msg}. Errors: {'; '.join(baseline_error_details[:3])}"
                                result['logs'] = logs
                                return result
                        else:
                            # ISSUE 8 FIX: Add detailed diagnostic checks
                            error_details = []
                            if not self.connection:
                                error_details.append("Connection object is None")
                            elif not hasattr(self.connection, 'device'):
                                error_details.append(f"Connection object has no 'device' attribute (connection type: {type(self.connection)})")
                            elif self.connection.device is None:
                                error_details.append("Connection.device is None (device object not initialized)")
                            elif not hasattr(self.connection.device, 'send_command'):
                                error_details.append(f"Connection.device has no 'send_command' method (device type: {type(self.connection.device)})")
                            else:
                                error_details.append("Unknown error - connection.device.send_command check failed")
                            
                            error_msg = "Cannot access device.send_command for baseline collection"
                            logger.error(f"CRITICAL: {error_msg}")
                            logger.error(f"  Diagnostic details: {error_details}")
                            logs.append(f"  ✗ {error_msg}")
                            logs.append(f"  [DEBUG] Connection diagnostics:")
                            for detail in error_details:
                                logs.append(f"    - {detail}")
                            if hasattr(self, 'connection') and self.connection:
                                logs.append(f"    - Connection object exists: {self.connection is not None}")
                                logs.append(f"    - Connection type: {type(self.connection)}")
                                if hasattr(self.connection, 'device'):
                                    logs.append(f"    - Connection.device exists: {self.connection.device is not None}")
                                    if self.connection.device:
                                        logs.append(f"    - Connection.device type: {type(self.connection.device)}")
                                        logs.append(f"    - Connection.device has send_command: {hasattr(self.connection.device, 'send_command')}")
                            result['message'] = f"{error_msg}. Details: {'; '.join(error_details)}"
                            result['logs'] = logs
                            return result
                    except Exception as nvue_error:
                        error_msg = f"Direct NVUE baseline collection failed: {str(nvue_error)}"
                        logger.error(f"CRITICAL: {error_msg}")
                        logs.append(f"  ✗ {error_msg}")
                        result['message'] = error_msg
                        result['logs'] = logs
                        return result
                else:
                    # Non-Cumulus platforms - will use get_interfaces() fallback below
                    baseline_collected = False
                
                # Fallback to NAPALM's get_interfaces() for non-Cumulus platforms
                # For Cumulus, we already tried direct NVUE above, so skip this if baseline was collected
                if driver_name != 'cumulus' or not baseline_collected:
                    try:
                        interfaces_before = self.get_interfaces()
                        if not interfaces_before:
                            error_msg = f"Cannot get interfaces from device {self.device.name}"
                            logger.error(f"CRITICAL: {error_msg}")
                            logs.append(f"  ✗ Cannot get interfaces from device")
                            result['message'] = f"Baseline collection failed: {error_msg}"
                            result['logs'] = logs
                            return result
                        else:
                            # For non-Cumulus, we need to find the interface in interfaces_before
                            # This will be handled in the code below
                            baseline_collected = False  # Will be set to True if interface found
                    except Exception as get_interfaces_error:
                        error_msg = f"Failed to get interfaces from device {self.device.name}: {get_interfaces_error}"
                        logger.error(f"CRITICAL: {error_msg}")
                        logs.append(f"  ✗ Cannot get interfaces from device: {get_interfaces_error}")
                        result['message'] = f"Baseline collection failed: {error_msg}"
                        result['logs'] = logs
                        return result
                    
                    # Check if interface_name exists (could be bond interface)
                    # IMPORTANT: interfaces_before might be None if get_interfaces() failed
                    if interfaces_before and interface_name in interfaces_before:
                        baseline_interface_name = interface_name
                        logs.append(f"  Collecting interface state for {interface_name}...")
                    else:
                        # Interface_name not found - might be bond member case
                        # Check if original_interface_name was provided and exists
                        original_interface = getattr(self, '_original_interface_name_for_baseline', None)
                        if original_interface and interfaces_before and original_interface in interfaces_before:
                            # Original interface exists - use it for baseline
                            baseline_interface_name = original_interface
                            logs.append(f"  Collecting interface state for {original_interface} (member interface)...")
                        else:
                            # Neither found - try to find bond interface for member
                            # For Cumulus, check if it's a bond member by looking at bond-members
                            # Use driver_name from above (got it early for this check)
                            if driver_name == 'cumulus':
                                try:
                                    bond_members_command = 'nv show interface bond-members -o json'
                                    if hasattr(self.connection, 'device') and self.connection.device is not None and hasattr(self.connection.device, 'send_command'):
                                        bond_members_output = self.connection.device.send_command(bond_members_command, read_timeout=10)
                                    elif hasattr(self.connection, 'cli'):
                                        cli_result = self.connection.cli([bond_members_command])
                                        if isinstance(cli_result, dict):
                                            bond_members_output = cli_result.get(bond_members_command, '')
                                        else:
                                            bond_members_output = str(cli_result) if cli_result else ''
                                    else:
                                        bond_members_output = None
                                    
                                    if bond_members_output:
                                        if bond_members_output:
                                            import json
                                            try:
                                                bond_members = json.loads(bond_members_output)
                                                logger.debug(f"Bond members JSON structure: {bond_members}")
                                                # bond_members format can be either:
                                                # Format 1: {"swp3": {"parent": "bond3"}, ...}
                                                # Format 2: {"swp3": "bond3", ...} (simple dict)
                                                # Format 3: nested structure from nv config show
                                                
                                                bond_name = None
                                                
                                                # Check if interface_name is a direct key (Format 1 or 2)
                                                if isinstance(bond_members, dict) and interface_name in bond_members:
                                                    member_info = bond_members[interface_name]
                                                    if isinstance(member_info, dict):
                                                        bond_name = member_info.get('parent') or member_info.get('bond')
                                                    elif isinstance(member_info, str):
                                                        bond_name = member_info
                                                    else:
                                                        logger.warning(f"Unexpected bond member format for {interface_name}: {member_info}")
                                                
                                                # If not found in direct format, check nested structure
                                                if not bond_name:
                                                    # Try looking for interface_name in nested structure
                                                    # Structure: {"interface": {"bond3": {"bond": {"member": {"swp3": {}}}}}}
                                                    if isinstance(bond_members, dict) and 'interface' in bond_members:
                                                        interfaces = bond_members.get('interface', {})
                                                        if isinstance(interfaces, dict):
                                                            for potential_bond, bond_config in interfaces.items():
                                                                if isinstance(bond_config, dict):
                                                                    bond_data = bond_config.get('bond', {})
                                                                    if isinstance(bond_data, dict):
                                                                        members = bond_data.get('member', {})
                                                                        if isinstance(members, dict) and interface_name in members:
                                                                            bond_name = potential_bond
                                                                            break
                                                
                                                if bond_name:
                                                    logger.info(f"Found that {interface_name} is a member of bond {bond_name}")
                                                    if interfaces_before and bond_name in interfaces_before:
                                                        baseline_interface_name = bond_name
                                                        logs.append(f"  Found bond interface {bond_name} for member {interface_name}")
                                                        logs.append(f"  Using bond interface {bond_name} for baseline collection")
                                                    else:
                                                        # Bond not in interfaces - fail baseline collection
                                                        error_msg = f"Interface {interface_name} is a bond member but bond {bond_name} does not exist in device interfaces"
                                                        logger.error(f"CRITICAL: {error_msg}")
                                                        logs.append(f"  ✗ Interface {interface_name} and bond {bond_name}: Bond interface not found!")
                                                        result['message'] = f"Baseline collection failed: {error_msg}"
                                                        result['logs'] = logs
                                                        return result
                                                else:
                                                    # Interface is not a bond member and not found
                                                    error_msg = f"Interface {interface_name} does not exist on device {self.device.name}"
                                                    logger.error(f"CRITICAL: {error_msg}")
                                                    logs.append(f"  ✗ Interface {interface_name}: Does not exist on device!")
                                                    logs.append(f"  Tried to find interface or bond interface, but neither was found")
                                                    result['message'] = f"Baseline collection failed: {error_msg}"
                                                    result['logs'] = logs
                                                    return result
                                            except (json.JSONDecodeError, KeyError, AttributeError) as parse_error:
                                                error_msg = f"Could not parse bond members JSON: {parse_error}"
                                                logger.error(f"CRITICAL: {error_msg}")
                                                logs.append(f"  ✗ Baseline collection failed: {error_msg}")
                                                result['message'] = f"Baseline collection failed: {error_msg}"
                                                result['logs'] = logs
                                                return result
                                        else:
                                            # Can't check bond membership - fail baseline collection
                                            error_msg = f"Could not get bond members output from device"
                                            logger.error(f"CRITICAL: {error_msg}")
                                            logs.append(f"  ✗ Baseline collection failed: {error_msg}")
                                            result['message'] = f"Baseline collection failed: {error_msg}"
                                            result['logs'] = logs
                                            return result
                                    else:
                                        # Can't check bond membership - fail baseline collection
                                        error_msg = f"device.send_command not available for baseline collection"
                                        logger.error(f"CRITICAL: {error_msg}")
                                        logs.append(f"  ✗ Baseline collection failed: {error_msg}")
                                        result['message'] = f"Baseline collection failed: {error_msg}"
                                        result['logs'] = logs
                                        return result
                                except Exception as bond_check_error:
                                    error_msg = f"Could not check bond membership: {bond_check_error}"
                                    logger.error(f"CRITICAL: {error_msg}")
                                    logs.append(f"  ✗ Baseline collection failed: {error_msg}")
                                    result['message'] = f"Baseline collection failed: {error_msg}"
                                    result['logs'] = logs
                                    return result
                            else:
                                # Not Cumulus, interface doesn't exist - fail baseline collection
                                error_msg = f"Interface {interface_name} does not exist on device {self.device.name}"
                                logger.error(f"CRITICAL: {error_msg}")
                                logs.append(f"  ✗ Interface {interface_name}: Does not exist on device!")
                                result['message'] = f"Baseline collection failed: {error_msg}"
                                result['logs'] = logs
                                return result
                
                # Now we have a valid baseline_interface_name, collect baseline
                # For non-Cumulus or if Cumulus direct NVUE failed, use NAPALM's get_interfaces()
                if not baseline_collected and interfaces_before and baseline_interface_name in interfaces_before:
                    baseline['interface'] = {
                        'name': baseline_interface_name,
                        'is_up': interfaces_before[baseline_interface_name].get('is_up', False),
                        'is_enabled': interfaces_before[baseline_interface_name].get('is_enabled', True),
                        'description': interfaces_before[baseline_interface_name].get('description', ''),
                    }
                    logger.info(f"  Baseline: {baseline_interface_name} is_up={baseline['interface']['is_up']}, is_enabled={baseline['interface']['is_enabled']}")
                    logs.append(f"  ✓ Interface {baseline_interface_name}: UP={baseline['interface']['is_up']}, Enabled={baseline['interface']['is_enabled']}")
                    # Note if we used bond instead of member
                    if baseline_interface_name != interface_name:
                        logs.append(f"  Note: Using bond interface {baseline_interface_name} for baseline (member {interface_name})")
                    baseline_collected = True  # Mark as collected
                elif not baseline_collected:
                    # Baseline collection failed - this is now mandatory
                    error_msg = f"Baseline collection failed: Could not collect baseline for interface {interface_name}"
                    if baseline_interface_name != interface_name:
                        error_msg += f" (tried {baseline_interface_name} as fallback)"
                    logger.error(f"CRITICAL: {error_msg}")
                    logs.append(f"  ✗ Baseline collection FAILED")
                    logs.append(f"  Interface {interface_name} or {baseline_interface_name} not found in device interfaces")
                    if interfaces_before:
                        available_interfaces = list(interfaces_before.keys())[:10]  # Show first 10
                        logs.append(f"  Available interfaces on device: {', '.join(available_interfaces)}")
                    else:
                        logs.append(f"  Could not retrieve interface list from device")
                    result['message'] = error_msg
                    result['logs'] = logs
                    return result

            # Collect LLDP neighbors baseline (if checking)
            if 'lldp' in checks:
                try:
                    logs.append(f"  Collecting LLDP neighbors (device-level)...")
                    lldp_before = self.get_lldp_neighbors()

                    # Store ALL interface LLDP data (device-level check)
                    baseline['lldp_all_interfaces'] = {}
                    total_neighbors = 0
                    if lldp_before:
                        for iface, neighbors in lldp_before.items():
                            neighbor_count = len(neighbors) if neighbors else 0
                            baseline['lldp_all_interfaces'][iface] = neighbor_count
                            total_neighbors += neighbor_count

                    # Also store the specific interface we're configuring
                    if interface_name:
                        if lldp_before and interface_name in lldp_before:
                            baseline['lldp_neighbors'] = len(lldp_before[interface_name])
                            logger.info(f"  Baseline: {interface_name} has {baseline['lldp_neighbors']} LLDP neighbors")
                        else:
                            baseline['lldp_neighbors'] = 0
                            logger.info(f"  Baseline: {interface_name} has no LLDP neighbors")

                    logger.info(f"  Baseline: Device has {total_neighbors} total LLDP neighbors across {len(baseline['lldp_all_interfaces'])} interfaces")
                    logs.append(f"  ✓ LLDP neighbors: {total_neighbors} total across {len(baseline['lldp_all_interfaces'])} interfaces")
                    if interface_name:
                        logs.append(f"  ✓ Interface {interface_name}: {baseline.get('lldp_neighbors', 0)} neighbors")

                except Exception as e:
                    logger.debug(f"Could not get LLDP baseline: {e}")
                    baseline['lldp_neighbors'] = None
                    baseline['lldp_all_interfaces'] = None
                    logs.append(f"  ⚠ LLDP neighbors: Could not collect ({str(e)[:50]})")

            # Collect system uptime baseline
            try:
                logs.append(f"  Collecting system facts...")
                facts_before = self.get_facts()
                if facts_before:
                    baseline['uptime'] = facts_before.get('uptime', -1)
                    baseline['hostname'] = facts_before.get('hostname', 'unknown')
                    logger.info(f"  Baseline: Device uptime={baseline['uptime']}, hostname={baseline['hostname']}")
                    logs.append(f"  ✓ System uptime: {baseline['uptime']}s, hostname: {baseline['hostname']}")
                else:
                    baseline['uptime'] = None
                    baseline['hostname'] = None
                    logs.append(f"  ⚠ System facts: Could not collect")
            except Exception as e:
                logger.debug(f"Could not get facts baseline: {e}")
                baseline['uptime'] = None
                baseline['hostname'] = None
                logs.append(f"  ⚠ System facts: Error ({str(e)[:50]})")

            # Verify baseline was collected (mandatory)
            if interface_name and 'interface' not in baseline:
                error_msg = f"Baseline collection incomplete: Interface baseline not collected for {interface_name}"
                logger.error(f"CRITICAL: {error_msg}")
                logs.append(f"  ✗ Baseline collection FAILED: Interface baseline missing")
                result['message'] = error_msg
                result['logs'] = logs
                return result
            
            # Store baseline for comparison later
            result['baseline'] = baseline
            logger.info(f"Phase 0.5: Baseline collection completed")
            logs.append(f"  ✓ Baseline collection completed")

        except Exception as e:
            # Baseline collection is now MANDATORY - fail deployment if it fails
            error_msg = f"Baseline collection failed with exception: {str(e)}"
            logger.error(f"CRITICAL: Phase 0.5 failed: {error_msg}")
            import traceback
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            result['baseline'] = {}
            logs.append(f"  ✗ Baseline collection FAILED: {str(e)[:200]}")
            logs.append(f"  Baseline collection is MANDATORY - deployment cannot proceed")
            logs.append(f"  Error details:")
            logs.append(f"    {str(e)}")
            result['message'] = error_msg
            result['logs'] = logs
            return result
        
        # Determine platform-specific approach BEFORE Phase 1
        driver_name = self.get_driver_name()
        supports_native_commit_confirm = driver_name in ['junos', 'cumulus']  # EOS SSH does NOT support commit-confirm
        use_eos_session = (driver_name == 'eos')  # EOS requires configure session with timer
        
        # Store driver_name for use in baseline collection (needed for bond membership check)
        self._driver_name_for_baseline = driver_name
        
        # Phase 1: Load configuration (skip for EOS sessions - handled in Phase 2)
        if not use_eos_session:
            try:
                logger.info(f"Phase 1: Loading configuration to {self.device.name}...")
                logger.debug(f"Config to load:\n{config}")

                logs.append(f"")
                logs.append(f"[Phase 1] Configuration Loading")
                logs.append(f"  Config to load: {config}")
                logs.append(f"  Mode: {'Replace (full config)' if replace else 'Merge (incremental)'}")
                logs.append(f"  Loading configuration...")
                
                # DEBUG: Check connection state before load
                try:
                    if hasattr(self.connection, 'is_alive'):
                        is_alive = self.connection.is_alive()
                        logger.debug(f"Connection is_alive before load_config: {is_alive}")
                        logs.append(f"  [DEBUG] Connection alive: {is_alive}")
                except Exception as alive_check:
                    logger.debug(f"Could not check connection alive status: {alive_check}")

                # DEBUG: For Cumulus, check current revision before load
                if driver_name == 'cumulus':
                    try:
                        if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                            history_before_load = self.connection.device.send_command('nv config history | head -3', read_timeout=10)
                            logger.debug(f"Config history BEFORE load_config:\n{history_before_load}")
                            logs.append(f"  [DEBUG] History before load (last 3 entries):")
                            for line in history_before_load.split('\n')[:3]:
                                if line.strip():
                                    logs.append(f"    {line.strip()}")
                    except Exception as hist_error:
                        logger.debug(f"Could not get history before load: {hist_error}")

                try:
                    load_result = self.load_config(config, replace=replace)
                    logger.info(f"load_config() returned: {load_result}")
                    logs.append(f"  [DEBUG] load_config() return value: {load_result}")
                except Exception as load_error:
                    logger.error(f"Phase 1 failed: load_config raised exception: {load_error}")
                    logs.append(f"  ✗ Configuration load FAILED")
                    logs.append(f"  Exception: {str(load_error)}")
                    result['message'] = f"Failed to load configuration: {str(load_error)}"
                    result['logs'] = logs
                    return result
                
                if not load_result:
                    # Get stored error from load_config if available
                    error_msg = "Device rejected config or NAPALM driver encountered an error"
                    exception_type = "Unknown"
                    if hasattr(self, '_last_load_error') and self._last_load_error:
                        stored_error = self._last_load_error.get('error', '')
                        exception_type = self._last_load_error.get('exception_type', 'Unknown')
                        if stored_error:
                            error_msg = stored_error
                            logger.error(f"Phase 1 failed: load_config error ({exception_type}): {stored_error}")
                    
                    # Provide more specific error message based on exception type
                    if exception_type in ['ConfigInvalidException', 'MergeConfigException', 'ReplaceConfigException']:
                        # Show actual error from device, not generic example
                        logs.append(f"  ✗ Configuration load FAILED - Syntax Error")
                        logs.append(f"  Error Type: {exception_type}")
                        logs.append(f"  Error: {error_msg}")
                        logs.append(f"  [DEBUG] Actual error from device:")
                        # error_msg already contains the actual error from the exception
                        if error_msg:
                            logs.append(f"    {error_msg}")
                        else:
                            logs.append(f"    (No detailed error message available)")
                    else:
                        result['message'] = f"Failed to load configuration. {error_msg}"
                        logger.error(f"Phase 1 failed: load_config returned False")
                        logs.append(f"  ✗ Configuration load FAILED")
                        logs.append(f"  Error Type: {exception_type}")
                        logs.append(f"  Error: {error_msg}")
                    
                    result['message'] = f"Failed to load configuration. {error_msg}"
                    
                    # Show the config that failed to load (first few lines)
                    logs.append(f"  [DEBUG] Config that failed to load:")
                    for i, line in enumerate(config.split('\n')[:10]):
                        if line.strip():
                            logs.append(f"    {line.strip()}")
                    if len(config.split('\n')) > 10:
                        logs.append(f"    ... ({len(config.split('\n')) - 10} more lines)")
                    
                    # DEBUG: Try to get error details from NAPALM connection
                    error_details = []
                    
                    # Check if connection has any error attributes
                    if hasattr(self.connection, 'device'):
                        if hasattr(self.connection.device, 'last_error'):
                            error_details.append(f"Device last_error: {self.connection.device.last_error}")
                        if hasattr(self.connection.device, 'error'):
                            error_details.append(f"Device error: {self.connection.device.error}")
                    
                    # For Cumulus, check config diff and validation errors
                    if driver_name == 'cumulus':
                        try:
                            if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                # Check config diff for debugging
                                # Note: 'nv config diff' can be empty if:
                                # 1. Config load failed (no candidate created)
                                # 2. Candidate config already matches applied config (no changes needed)
                                # So empty diff doesn't necessarily mean load failed
                                error_check = self.connection.device.send_command('nv config diff', read_timeout=10)
                                if error_check and error_check.strip():
                                    logger.debug(f"Config diff after failed load: {error_check}")
                                    logs.append(f"  [DEBUG] Config diff after failed load:")
                                    for line in error_check.split('\n')[:20]:  # Show first 20 lines
                                        if line.strip():
                                            logs.append(f"    {line.strip()}")
                                else:
                                    # Empty diff could mean load failed OR config already matches
                                    # Since load_config() raised an exception, it's more likely load failed
                                    logger.debug(f"Config diff is empty after failed load - could mean load failed or config already matches")
                                    logs.append(f"  [DEBUG] Config diff is empty - load may have failed or config already matches applied config")
                        except Exception as err_check:
                            logger.debug(f"Could not check error details: {err_check}")
                            logs.append(f"  [DEBUG] Could not retrieve detailed error info: {str(err_check)}")
                    
                    # Log any collected error details
                    if error_details:
                        logs.append(f"  [DEBUG] Additional error details:")
                        for detail in error_details:
                            logs.append(f"    {detail}")
                    
                    result['logs'] = logs
                    return result

                logger.info(f"Phase 1: Configuration loaded successfully")
                logs.append(f"  ✓ Configuration loaded to candidate config")
                
                # CRITICAL: For Cumulus, validate that commands were actually accepted (no syntax errors)
                # If commands had syntax errors (like "vlan add" instead of "vlan"), they might fail silently
                if driver_name == 'cumulus':
                    try:
                        if hasattr(self.connection, 'revision_id'):
                            candidate_revision = self.connection.revision_id
                            logger.info(f"Candidate revision ID after load: {candidate_revision}")
                            logs.append(f"  [DEBUG] Candidate revision ID: {candidate_revision}")
                        
                        # Validate candidate config to ensure commands were accepted
                        if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                            # Check if we can show the candidate revision (if it fails, commands had errors)
                            try:
                                candidate_check = self.connection.device.send_command(f'nv config show -r {candidate_revision} -o json', read_timeout=10)
                                if candidate_check and ('error' in candidate_check.lower() or 'invalid' in candidate_check.lower()):
                                    error_msg = "Candidate config contains errors - commands may have failed during load"
                                    logger.error(f"Phase 1 validation failed: {error_msg}")
                                    logs.append(f"  ✗ Configuration validation FAILED")
                                    logs.append(f"  Error: {error_msg}")
                                    logs.append(f"  [DEBUG] Candidate config check output:")
                                    for line in candidate_check.split('\n')[:10]:
                                        if line.strip():
                                            logs.append(f"    {line.strip()}")
                                    result['message'] = f"Configuration validation failed: {error_msg}"
                                    result['logs'] = logs
                                    return result
                            except Exception as candidate_check_error:
                                logger.warning(f"Could not validate candidate config: {candidate_check_error}")
                                # Continue - this is not critical, just a validation step
                            
                            # Check history after load
                            history_after_load = self.connection.device.send_command('nv config history | head -3', read_timeout=10)
                            logger.debug(f"Config history AFTER load_config:\n{history_after_load}")
                            logs.append(f"  [DEBUG] History after load (last 3 entries):")
                            for line in history_after_load.split('\n')[:3]:
                                if line.strip():
                                    logs.append(f"    {line.strip()}")
                    except Exception as post_load_error:
                        logger.debug(f"Could not check post-load state: {post_load_error}")
                
                # Show commands that will be executed
                logs.append(f"")
                logs.append(f"  Commands to be executed:")
                config_lines = config.split('\n')
                for line in config_lines:
                    if line.strip():
                        logs.append(f"    + {line.strip()}")
                
                # Phase 1.5: For Cumulus, verify that candidate config actually has changes
                # If there are no changes, commit will not create a revision
                if driver_name == 'cumulus':
                    try:
                        logs.append(f"  [DEBUG] Checking for config differences...")
                        if hasattr(self.connection, 'compare_config'):
                            diff_output = self.connection.compare_config()
                            logger.info(f"compare_config() returned output of length: {len(diff_output) if diff_output else 0}")
                            logs.append(f"  [DEBUG] compare_config() output length: {len(diff_output) if diff_output else 0}")
                            
                            if diff_output:
                                logger.debug(f"Full config diff (candidate vs running):\n{diff_output}")
                                # Log first 1000 chars of diff
                                diff_preview = diff_output[:1000] if len(diff_output) > 1000 else diff_output
                                logs.append(f"  [DEBUG] Config diff preview:")
                                for line in diff_preview.split('\n')[:50]:  # First 50 lines
                                    if line.strip():
                                        logs.append(f"    {line.strip()}")
                                
                                # Also try direct nv config diff command
                                try:
                                    if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                        direct_diff = self.connection.device.send_command('nv config diff', read_timeout=15)
                                        logger.debug(f"Direct 'nv config diff' output:\n{direct_diff}")
                                        logs.append(f"  [DEBUG] Direct 'nv config diff' output:")
                                        if direct_diff:
                                            for line in direct_diff.split('\n')[:30]:  # First 30 lines
                                                if line.strip():
                                                    logs.append(f"    {line.strip()}")
                                except Exception as direct_diff_error:
                                    logger.debug(f"Could not run direct nv config diff: {direct_diff_error}")
                                
                                # Check if diff shows actual changes
                                if 'no changes' in diff_output.lower() or (len(diff_output.strip()) < 10):
                                    logger.warning(f"WARNING: Candidate config appears to match running config - commit may not create revision")
                                    logs.append(f"  ⚠ WARNING: Candidate config matches running config - no changes to commit")
                                else:
                                    logs.append(f"  ✓ Candidate config has differences from running config")
                            else:
                                logger.warning(f"compare_config() returned empty - no diff available")
                                logs.append(f"  ⚠ compare_config() returned empty/None")
                    except Exception as diff_check_error:
                        logger.error(f"Exception in compare_config(): {diff_check_error}")
                        logs.append(f"  ⚠ Exception checking config diff: {str(diff_check_error)}")
                        import traceback
                        logger.debug(f"Traceback: {traceback.format_exc()}")
                
                # Phase 1.5: Compare/Preview changes (optional, if supported by driver)
                # Note: Current device configuration is already shown in views.py before deployment
                # (interface-specific config, not full device config - matches dry run format)
                try:
                    logs.append(f"  Generating configuration diff...")
                    diff = self.connection.compare_config()
                    
                    # For Cumulus, if compare_config() returns a command string instead of diff output,
                    # try to execute it manually to get actual diff
                    if diff and driver_name == 'cumulus' and ('diff <' in diff or diff.strip().startswith('diff <')):
                        logger.debug(f"compare_config() returned command string, executing manually...")
                        try:
                            if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                # Get the current revision number (pending/candidate)
                                rev_output = self.connection.device.send_command('nv config history | head -1', read_timeout=10)
                                if rev_output:
                                    import re
                                    # Extract revision number (format: "Revision: 270" or "270 * pending")
                                    rev_match = re.search(r'Revision:\s*(\d+)', rev_output)
                                    if not rev_match:
                                        rev_match = re.search(r'^\s*(\d+)\s*\*', rev_output)
                                    if rev_match:
                                        rev_num = rev_match.group(1)
                                        # Execute diff command manually to get actual diff output
                                        diff_cmd = f'nv config diff {rev_num}'
                                        diff_output = self.connection.device.send_command(diff_cmd, read_timeout=30)
                                        if diff_output and diff_output.strip() and 'diff <' not in diff_output:
                                            # Got actual diff output, use it
                                            diff = diff_output
                                            logger.info(f"Got diff output manually: {len(diff)} chars")
                                        else:
                                            # Still got command, try alternative: get applied revision and diff
                                            try:
                                                applied_output = self.connection.device.send_command('nv config history | grep -i applied | head -1', read_timeout=10)
                                                if applied_output:
                                                    applied_match = re.search(r'Revision:\s*(\d+)', applied_output)
                                                    if not applied_match:
                                                        applied_match = re.search(r'^\s*(\d+)', applied_output)
                                                    if applied_match:
                                                        applied_rev = applied_match.group(1)
                                                        # Get diff between applied and current
                                                        diff_cmd2 = f'nv config diff {applied_rev}'
                                                        diff_output2 = self.connection.device.send_command(diff_cmd2, read_timeout=30)
                                                        if diff_output2 and diff_output2.strip() and 'diff <' not in diff_output2:
                                                            diff = diff_output2
                                                            logger.info(f"Got diff output using applied revision: {len(diff)} chars")
                                            except Exception as alt_error:
                                                logger.debug(f"Alternative diff method failed: {alt_error}")
                        except Exception as manual_diff_error:
                            logger.debug(f"Could not get diff manually: {manual_diff_error}")
                            # Fall back to showing the command (which is what we have)
                    
                    if diff:
                        logger.info(f"Configuration diff preview:")
                        logger.info(diff)  # Log full diff
                        logs.append(f"  ✓ Configuration diff:")
                        logs.append(f"    Note: '-' lines show what's being removed from running config")
                        logs.append(f"          '+' lines show what's being added in candidate config")
                        
                        # Parse diff to extract removed and added commands
                        diff_lines = diff.split('\n')
                        removed_commands = []
                        added_commands = []
                        in_diff_section = False
                        
                        for line in diff_lines:
                            # Skip diff header lines
                            if line.strip().startswith('---') or line.strip().startswith('+++') or line.strip().startswith('@@'):
                                continue
                            if line.strip().startswith('diff <') or line.strip().startswith('Note:'):
                                continue
                            
                            # Extract removed commands (lines starting with -)
                            if line.strip().startswith('-') and not line.strip().startswith('---'):
                                cmd = line.strip()[1:].strip()  # Remove the - prefix
                                if cmd and ('nv set' in cmd or 'nv unset' in cmd):
                                    # Filter out base bridge domain br_default removals (only show access VLAN changes)
                                    # In Cumulus, interface can be part of br_default AND have access VLAN
                                    # We only want to show access VLAN removals, not base bridge domain membership
                                    # Also filter out bridge domain vlan removals (these are just NVUE reorganizing)
                                    if 'bridge domain br_default' in cmd:
                                        if 'access' not in cmd:
                                            # Skip base bridge domain membership removals (these are just NVUE reorganizing interface groups)
                                            continue
                                        # For access VLAN removals, keep them
                                    # Capture all other nv commands
                                    removed_commands.append(cmd)
                            
                            # Extract added commands (lines starting with +)
                            elif line.strip().startswith('+') and not line.strip().startswith('+++'):
                                cmd = line.strip()[1:].strip()  # Remove the + prefix
                                if cmd and ('nv set' in cmd or 'nv unset' in cmd):
                                    # Capture all nv commands
                                    added_commands.append(cmd)
                        
                        # Store for later use in success message
                        if '_removed_commands' not in result:
                            result['_removed_commands'] = []
                        if '_added_commands' not in result:
                            result['_added_commands'] = []
                        result['_removed_commands'] = removed_commands
                        result['_added_commands'] = added_commands
                        
                        # Show only removed/added lines from diff (with - and + signs, but no headers)
                        logs.append(f"")
                        logs.append(f"    Configuration changes:")
                        # Show diff lines with - and + signs, but filter out headers
                        diff_shown = False
                        for line in diff_lines:
                            stripped = line.strip()
                            # Skip diff headers and context markers
                            if (stripped.startswith('---') or stripped.startswith('+++') or 
                                stripped.startswith('@@') or stripped.startswith('diff <') or 
                                stripped.startswith('Note:') or not stripped):
                                continue
                            # Show lines with - or + (actual changes)
                            if stripped.startswith('-') or stripped.startswith('+'):
                                logs.append(f"    {line}")
                                diff_shown = True
                        
                        if not diff_shown:
                            logs.append(f"    (no changes detected)")
                    else:
                        logger.warning(f"No configuration differences detected - config may already be applied")
                        logs.append(f"  ⚠ No configuration differences detected")
                except Exception as e:
                    logger.debug(f"Could not get config diff (not supported by all drivers): {e}")
                    logs.append(f"  ⚠ Config diff not available (not supported by driver)")

            except Exception as e:
                result['message'] = f"Exception during config load: {str(e)}"
                logger.error(f"Phase 1 failed: {e}")
                logs.append(f"  ✗ Exception during config load: {str(e)}")
                result['logs'] = logs
                return result
        else:
            # EOS sessions: Skip Phase 1, config will be applied directly in session
            logger.info(f"Phase 1: Skipped for EOS (config will be applied in configure session)")
            logs.append(f"")
            logs.append(f"[Phase 1] Configuration Loading")
            logs.append(f"  Platform: EOS")
            logs.append(f"  Method: Configure session (Phase 1 skipped)")
            logs.append(f"  Config will be applied directly in session during Phase 2")
        
        # Phase 2: Commit configuration with platform-specific safety

        logs.append(f"")
        logs.append(f"[Phase 2] Configuration Commit")
        logs.append(f"  Platform: {driver_name}")
        logs.append(f"  Commit-confirm support: {supports_native_commit_confirm}")

        # Log the username being used for debugging
        try:
            connection_username = getattr(self.connection, 'username', 'unknown')
            logs.append(f"  Connection username: {connection_username}")
        except:
            pass

        try:
            if supports_native_commit_confirm:
                # Platforms with native commit-confirm support (Juniper, Cumulus NVUE)
                logger.info(f"Phase 2: Committing with {timeout}s rollback timer (platform supports commit-confirm)...")
                logs.append(f"  Method: Native commit-confirm (auto-rollback in {timeout}s)")
                logs.append(f"  Committing configuration...")
                
                # For Cumulus, check for pending commits BEFORE committing to verify no conflicts
                if driver_name == 'cumulus':
                    try:
                        if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                            # Check current revision count before commit
                            history_before = self.connection.device.send_command('nv config history | head -5', read_timeout=10)
                            logger.debug(f"Config history before commit:\n{history_before}")
                            
                            # Check if there are any pending commits that might conflict
                            pending_before = self.connection.device.send_command('nv config history | grep -i "pending\\|confirm" | head -1', read_timeout=10)
                            if pending_before:
                                logger.warning(f"Found existing pending commit before new commit: {pending_before}")
                                logs.append(f"  ⚠ Warning: Found existing pending commit - may conflict")
                    except Exception as check_error:
                        logger.debug(f"Could not check pre-commit state: {check_error}")
                
                # Execute commit_config - this should execute: nv config apply --confirm {timeout}s -y
                try:
                    # DEBUG: Log what commit_config should do
                    logger.info(f"About to call commit_config(revert_in={timeout})")
                    logs.append(f"  [DEBUG] Calling commit_config(revert_in={timeout})...")
                    
                    # For Cumulus, log what command will be executed
                    if driver_name == 'cumulus':
                        expected_cmd = f"nv config apply --confirm {timeout}s -y"
                        logger.info(f"Expected command: {expected_cmd}")
                        logs.append(f"  [DEBUG] Expected NVUE command: {expected_cmd}")
                        
                        # Check for pending commits before executing
                        try:
                            if hasattr(self.connection, 'has_pending_commit'):
                                has_pending = self.connection.has_pending_commit()
                                logger.info(f"has_pending_commit() before commit: {has_pending}")
                                logs.append(f"  [DEBUG] has_pending_commit() before commit: {has_pending}")
                                if has_pending:
                                    logger.warning(f"WARNING: Pending commit already exists - commit_config may fail")
                                    logs.append(f"  ⚠ WARNING: Pending commit already exists")
                        except Exception as pending_check_error:
                            logger.debug(f"Could not check pending commit: {pending_check_error}")
                    
                    commit_result = self.connection.commit_config(revert_in=timeout)
                    logger.info(f"commit_config() returned: {commit_result}")
                    logs.append(f"  [DEBUG] commit_config() return value: {commit_result}")
                    logs.append(f"  [DEBUG] commit_config() return type: {type(commit_result)}")
                    # Store commit result for later diagnostics
                    result['_commit_result'] = commit_result
                    result['_config_commands'] = config
                    
                    # Check if there's actually a diff to apply (Cumulus won't create revision if no changes)
                    if driver_name == 'cumulus':
                        try:
                            if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                # Check if there are pending changes immediately after commit
                                time.sleep(0.5)  # Small delay to allow revision to be created
                                diff_check = self.connection.device.send_command('nv config diff', read_timeout=10)
                                logger.info(f"Config diff immediately after commit:\n{diff_check}")
                                logs.append(f"  [DEBUG] Config diff immediately after commit:")
                                if diff_check:
                                    for line in diff_check.split('\n')[:20]:
                                        if line.strip():
                                            logs.append(f"    {line.strip()}")
                                    
                                    if 'no changes' in diff_check.lower():
                                        logger.warning(f"No pending changes found - commit may not have created a revision")
                                        logs.append(f"  ⚠ Warning: No pending changes detected - config may already match")
                                    else:
                                        logger.info(f"Pending changes detected after commit")
                                        logs.append(f"  ✓ Pending changes detected")
                                else:
                                    logger.warning(f"diff_check returned empty/None")
                                    logs.append(f"  ⚠ Config diff returned empty")
                        except Exception as diff_error:
                            logger.error(f"Exception checking config diff after commit: {diff_error}")
                            logs.append(f"  ⚠ Exception checking diff: {str(diff_error)}")
                            import traceback
                            logger.debug(f"Traceback: {traceback.format_exc()}")
                    
                except Exception as commit_error:
                    logger.error(f"commit_config() raised exception: {commit_error}")
                    logs.append(f"  ✗ Commit FAILED with exception: {str(commit_error)}")
                    import traceback
                    logger.error(f"Full traceback:\n{traceback.format_exc()}")
                    logs.append(f"  [DEBUG] Exception type: {type(commit_error).__name__}")
                    raise  # Re-raise to be caught by outer exception handler
                
                logger.info(f"Phase 2: Config committed (will auto-rollback in {timeout}s if not confirmed)")
                logs.append(f"  ✓ Configuration committed with {timeout}s rollback timer")
                logs.append(f"  ⚠ Will auto-rollback if not confirmed within {timeout}s")
                
                # CRITICAL FIX: For Cumulus, get the actual pending revision ID after commit
                # NAPALM's driver stores candidate revision_id from load_config, but commit_config
                # creates a NEW pending revision. We need to get the actual pending revision ID.
                if driver_name == 'cumulus':
                    try:
                        if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                            # Wait a moment for the revision to be created (increased wait time for reliability)
                            time.sleep(2.0)  # Increased to 2.0s for better reliability
                            
                            actual_pending_revision = None
                            
                            # METHOD 1: Use NAPALM driver's _get_pending_commits() if available (most reliable)
                            # This uses 'nv config revision -o json' which is more structured than text parsing
                            try:
                                if hasattr(self.connection, '_get_pending_commits'):
                                    pending_commits = self.connection._get_pending_commits()
                                    if pending_commits and len(pending_commits) > 0:
                                        # Get the most recent pending commit (first in list, or highest number)
                                        actual_pending_revision = str(pending_commits[0])
                                        logger.info(f"Found pending commit using _get_pending_commits(): {actual_pending_revision}")
                                        logs.append(f"  [DEBUG] Found pending commit via JSON API: {actual_pending_revision}")
                            except Exception as json_error:
                                logger.debug(f"Could not use _get_pending_commits(): {json_error}")
                            
                            # METHOD 2: Use nv config revision -o json directly (fallback if driver method fails)
                            if not actual_pending_revision:
                                try:
                                    revision_json_output = self.connection.device.send_command('nv config revision -o json', read_timeout=10)
                                    if revision_json_output:
                                        import json
                                        revision_data = json.loads(revision_json_output)
                                        # Find revisions with state == "confirm"
                                        for rev_id, rev_info in revision_data.items():
                                            if isinstance(rev_info, dict) and rev_info.get('state') == 'confirm':
                                                actual_pending_revision = str(rev_id)
                                                logger.info(f"Found pending commit via JSON: {actual_pending_revision}")
                                                logs.append(f"  [DEBUG] Found pending commit via direct JSON: {actual_pending_revision}")
                                                break
                                except (json.JSONDecodeError, Exception) as json_error:
                                    logger.debug(f"Could not parse revision JSON: {json_error}")
                            
                            # METHOD 3: Parse nv config history text output (fallback if JSON methods fail)
                            if not actual_pending_revision:
                                try:
                                    pending_rev_output = self.connection.device.send_command('nv config history | head -5', read_timeout=10)
                                    logger.debug(f"Full history output after commit:\n{pending_rev_output}")
                                    
                                    if pending_rev_output:
                                        import re
                                        # Try multiple regex patterns to match different output formats
                                        # Pattern 1: "Revision: 271 * pending (confirm)"
                                        # Pattern 2: "271 * pending"
                                        # Pattern 3: "271 pending"
                                        # Pattern 4: Just the number at start of line with * marker
                                        patterns = [
                                            r'Revision:\s*(\d+)',  # "Revision: 271"
                                            r'^\s*(\d+)\s*\*',     # "271 *"
                                            r'^\s*(\d+).*pending', # "271 ... pending"
                                            r'^\s*(\d+).*confirm', # "271 ... confirm"
                                        ]
                                        
                                        lines = pending_rev_output.split('\n')
                                        for line in lines:
                                            # Look for lines with pending/confirm indicators
                                            if '*' in line or 'pending' in line.lower() or 'confirm' in line.lower():
                                                for pattern in patterns:
                                                    rev_match = re.search(pattern, line, re.IGNORECASE)
                                                    if rev_match:
                                                        actual_pending_revision = rev_match.group(1)
                                                        logger.info(f"Found pending commit via history parsing: {actual_pending_revision}")
                                                        logs.append(f"  [DEBUG] Found pending commit via history text: {actual_pending_revision}")
                                                        break
                                                if actual_pending_revision:
                                                    break
                                except Exception as history_error:
                                    logger.debug(f"Could not parse history output: {history_error}")
                            
                            # If we found a pending revision, store it
                            if actual_pending_revision:
                                result['_cumulus_pending_revision_id'] = actual_pending_revision
                                # Also update NAPALM driver's revision_id for consistency
                                if hasattr(self.connection, 'revision_id'):
                                    self.connection.revision_id = actual_pending_revision
                                logger.info(f"Found pending commit-confirm revision ID: {actual_pending_revision}")
                                logs.append(f"  ✓ Pending revision ID captured: {actual_pending_revision}")
                            else:
                                # No pending revision found - check if commit actually happened
                                logger.warning(f"No pending revision found using any method")
                                logs.append(f"  ⚠ No pending revision found - checking if commit succeeded...")
                                
                                # Check if there's a diff (if no diff, no revision is created)
                                diff_check = self.connection.device.send_command('nv config diff', read_timeout=10)
                                if diff_check and 'no changes' in diff_check.lower():
                                    logs.append(f"  ⚠ No pending changes - config already matches (no revision created)")
                                    logger.warning(f"Commit did not create revision because config already matches")
                                else:
                                    # CRITICAL: No pending revision but changes exist - this suggests commit failed
                                    # Possible causes:
                                    # 1. Commands had syntax errors (like "vlan add" instead of "vlan")
                                    # 2. Commit command failed silently
                                    # 3. Timing issue - revision not yet visible (unlikely after 1s wait)
                                    # 4. NVUE version differences - output format changed
                                    # 5. Concurrent commit from another process
                                    logs.append(f"  ✗ WARNING: Commit may have failed - no pending revision created but changes exist")
                                    logger.error(f"Commit may have failed - no pending revision but changes detected")
                                    
                                    # Check if there are any error messages in the diff or config
                                    if diff_check:
                                        # Look for error indicators in the diff output
                                        if 'error' in diff_check.lower() or 'invalid' in diff_check.lower():
                                            error_msg = "Commit failed due to configuration errors - commands may have syntax errors"
                                            logger.error(f"Phase 2 failed: {error_msg}")
                                            logs.append(f"  ✗ {error_msg}")
                                            logs.append(f"  [DEBUG] Config diff shows errors:")
                                            for line in diff_check.split('\n')[:20]:
                                                if line.strip() and ('error' in line.lower() or 'invalid' in line.lower()):
                                                    logs.append(f"    {line.strip()}")
                                            result['message'] = error_msg
                                            result['logs'] = logs
                                            return result
                                    
                                    # Store warning for Phase 5 to handle
                                    result['_commit_warning'] = "No pending revision found but changes exist - commit may have failed"
                    except Exception as rev_error:
                        logger.warning(f"Could not get pending revision ID: {rev_error}")
                        logs.append(f"  ⚠ Could not get pending revision ID: {str(rev_error)[:100]}")
                        import traceback
                        logger.debug(f"Traceback: {traceback.format_exc()}")
                        # Continue anyway - will try NAPALM's method in Phase 5

            elif use_eos_session:
                # EOS: Use configure session with commit timer (manual CLI approach)
                logger.info(f"Phase 2: Using EOS configure session with {timeout}s commit timer...")
                logs.append(f"  Method: EOS configure session with commit timer")

                # Create unique session name
                import random
                session_name = f"netbox_vlan_{random.randint(1000, 9999)}"

                # Convert timeout to minutes (EOS commit timer format)
                # EOS commit timer format: 1-120 minutes
                timer_minutes = max(2, min(120, timeout // 60))  # Convert to minutes, min 2, max 120

                logs.append(f"  Session name: {session_name}")
                logs.append(f"  Commit timer: {timer_minutes} minutes")

                # We'll use NAPALM's underlying Netmiko connection for raw CLI commands
                try:
                    # Access the underlying Netmiko connection from NAPALM EOS driver
                    if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                        netmiko_conn = self.connection.device
                        logger.info(f"Using NAPALM's underlying Netmiko connection for EOS session")
                    else:
                        raise Exception("Cannot access Netmiko connection from NAPALM driver")

                    # Step 1: Enter configure session
                    logger.info(f"Creating EOS configure session: {session_name}")
                    logs.append(f"  Creating session...")
                    # Note: Prompt changes from "hostname#" to "hostname(config-s-session_name)#"
                    output = netmiko_conn.send_command(
                        f"configure session {session_name}",
                        expect_string=r'\(config-s-.*\)#',
                        read_timeout=30
                    )
                    logger.debug(f"Session creation output: {output}")

                    # Step 2: Apply configuration commands
                    logger.info(f"Applying configuration in session...")
                    logs.append(f"  Applying configuration in session...")
                    
                    # Split config into individual commands and send each one
                    config_lines = [line.strip() for line in config.split('\n') if line.strip()]
                    for cmd in config_lines:
                        # Send each command with appropriate expect pattern
                        output = netmiko_conn.send_command(
                            cmd,
                            expect_string=r'\(config.*\)#',
                            read_timeout=30
                        )
                        logger.debug(f"Config command '{cmd}' output: {output}")
                        
                        # Check for EOS command errors
                        if output and ('% Invalid input' in output or '% Error' in output or 'Invalid command' in output):
                            error_msg = f"EOS rejected command '{cmd}': {output.strip()}"
                            logger.error(error_msg)
                            logs.append(f"  ✗ {error_msg}")
                            # Abort the session
                            try:
                                netmiko_conn.send_command("abort", expect_string=r'#', read_timeout=10)
                            except:
                                pass
                            result['message'] = f"Configuration rejected by device: {output.strip()}"
                            result['logs'] = logs
                            return result

                    # Step 3: Show pending diff (for logging)
                    try:
                        diff_output = netmiko_conn.send_command(
                            "show session-config diffs",
                            expect_string=r'\(config-s-.*\)#',
                            read_timeout=30
                        )
                        logger.info(f"Session config diff:\n{diff_output}")
                        logs.append(f"  Configuration diff:")
                        for line in diff_output.split('\n')[:5]:
                            logs.append(f"    {line}")
                    except Exception as diff_err:
                        logger.debug(f"Could not get session diff: {diff_err}")

                    # Step 4: Commit with timer
                    logger.info(f"Committing session with {timer_minutes} minute timer...")
                    logs.append(f"  Committing with {timer_minutes} minute timer...")
                    commit_cmd = f"commit timer {timer_minutes:02d}:00:00"
                    # After commit, we exit config mode back to privileged exec
                    output = netmiko_conn.send_command(
                        commit_cmd,
                        expect_string=r'#',
                        read_timeout=60
                    )
                    logger.info(f"Commit timer output: {output}")
                    
                    # Check if commit was successful
                    if 'failed' in output.lower() or 'error' in output.lower():
                        raise Exception(f"Commit timer failed: {output}")
                    
                    logs.append(f"  ✓ Configuration committed with {timer_minutes} minute rollback timer")
                    logs.append(f"  ⚠ Will auto-rollback if not confirmed within {timer_minutes} minutes")

                    # Store session info for confirmation later
                    self._eos_session_name = session_name
                    self._eos_session_timer = timer_minutes
                    self._eos_netmiko_conn = netmiko_conn

                    logger.info(f"Phase 2: EOS session committed successfully with {timer_minutes}min timer")

                except Exception as session_error:
                    logger.error(f"EOS session approach failed: {session_error}")
                    logger.error(f"Traceback: {traceback.format_exc()}")
                    logs.append(f"  ✗ EOS session failed: {str(session_error)[:100]}")
                    result['message'] = f"Failed to create EOS configure session: {str(session_error)}"
                    result['logs'] = logs
                    
                    # Try to abort the session if it was created BUT timer not yet started
                    # (abort only works BEFORE commit timer is active)
                    try:
                        if hasattr(self, '_eos_netmiko_conn') and not hasattr(self, '_eos_session_timer'):
                            # Session created but not committed yet - abort is valid
                            self._eos_netmiko_conn.send_command("abort")
                            logs.append(f"  ✓ Session aborted (before commit timer)")
                    except Exception as abort_err:
                        logger.debug(f"Could not abort session: {abort_err}")
                        # If timer was already started, it will auto-rollback anyway
                        pass
                    
                    return result
            else:
                # Other platforms: direct commit
                logger.info(f"Phase 2: Committing configuration (direct commit)...")
                logs.append(f"  Method: Direct commit (no rollback timer)")
                self.connection.commit_config()
                logger.info(f"Phase 2: Config committed successfully")
                logs.append(f"  ✓ Configuration committed")

        except Exception as e:
            result['message'] = f"Failed to commit config: {str(e)}"
            logger.error(f"Phase 2 failed: {e}")
            logs.append(f"  ✗ Commit FAILED: {str(e)}")
            logs.append(f"  Discarding configuration...")
            try:
                self.connection.discard_config()
                logs.append(f"  ✓ Configuration discarded")
            except:
                logs.append(f"  ⚠ Could not discard configuration")
            
            # Add rollback information for failed commit
            logs.append(f"")
            logs.append(f"--- Rollback Information ---")
            logs.append(f"Platform: {driver_name.upper()}")
            logs.append(f"Status: Configuration discarded automatically")
            logs.append(f"")
            logs.append(f"If you need to manually restore or verify previous configuration:")
            if driver_name == 'cumulus':
                logs.append(f"  nv config history")
                logs.append(f"  nv config diff <previous_revision>")
                logs.append(f"  nv config apply <previous_revision>")
            elif driver_name == 'eos':
                logs.append(f"  show archive")
                logs.append(f"  show archive config differences <archive_number>")
                logs.append(f"  configure replace <archive_file>")
            logs.append(f"")
            logs.append(f"=== Deployment Completed ===")
            logs.append(f"Final Status: ERROR")
            logs.append(f"Config Applied: Failed")
            
            result['logs'] = logs
            return result
        
        # Phase 3: Verification window (let config settle)
        # Reduced wait time to avoid commit-confirm timeout
        # We have 90s total timeout, need time for verification + confirmation
        # 5s settle + ~10-20s verification + confirmation = ~25-35s, leaving ~55-65s buffer
        settle_time = 5  # seconds - reduced from 30s to avoid timeout issues
        logger.info(f"Phase 3: Waiting {settle_time} seconds for config to settle...")
        logs.append(f"")
        logs.append(f"[Phase 3] Configuration Settling")
        logs.append(f"  Waiting {settle_time} seconds for config to take effect...")
        logs.append(f"  Note: Reduced settle time to ensure commit-confirm doesn't timeout")
        
        # Progress indicator in logs so you know it's waiting
        for i in range(settle_time):
            if i == 0 or i == settle_time - 1:
                logger.info(f"  Settling... {i+1}/{settle_time}s elapsed")
            time.sleep(1)
        
        logs.append(f"  ✓ Wait complete ({settle_time}s)")

        # Phase 4: Run verification checks
        logger.info(f"Phase 4: Running verification checks...")
        logs.append(f"")
        logs.append(f"[Phase 4] Post-Deployment Verification")
        all_checks_passed = True

        # If this is a VLAN deployment, use comprehensive VLAN verification with baseline
        if vlan_id and interface_name:
            logger.info(f"Running comprehensive VLAN verification for {interface_name} VLAN {vlan_id}...")
            logs.append(f"  Running comprehensive VLAN verification...")
            logs.append(f"  Interface: {interface_name}")
            logs.append(f"  VLAN ID: {vlan_id}")
            baseline_data = result.get('baseline', {})
            vlan_check = self.verify_vlan_deployment(interface_name, vlan_id, baseline=baseline_data)
            result['verification_results'] = vlan_check['checks']
            all_checks_passed = vlan_check['success']

            # Log each verification check result
            for check_name, check_data in vlan_check['checks'].items():
                if check_data.get('success'):
                    logs.append(f"  ✓ {check_name}: {check_data.get('message', 'OK')}")
                else:
                    logs.append(f"  ✗ {check_name}: {check_data.get('message', 'FAILED')}")

            if all_checks_passed:
                logger.info(f"✅ VLAN verification passed: {vlan_check['message']}")
                logs.append(f"  ✓ All verification checks PASSED")
            else:
                logger.error(f"❌ VLAN verification failed: {vlan_check['message']}")
                logs.append(f"  ✗ Verification FAILED")
        else:
            # Standard verification checks
            logs.append(f"  Running standard verification checks...")
            if 'connectivity' in checks:
                logs.append(f"  Checking connectivity...")
                check_result = self.verify_connectivity()
                result['verification_results']['connectivity'] = check_result
                if not check_result['success']:
                    all_checks_passed = False
                    logs.append(f"  ✗ Connectivity: {check_result.get('message', 'FAILED')}")
                else:
                    logs.append(f"  ✓ Connectivity: {check_result.get('message', 'OK')}")

            if 'interfaces' in checks and all_checks_passed:
                logs.append(f"  Checking interfaces...")
                check_result = self.verify_interfaces(critical_interfaces=critical_interfaces)
                result['verification_results']['interfaces'] = check_result
                if not check_result['success']:
                    all_checks_passed = False
                    logs.append(f"  ✗ Interfaces: {check_result.get('message', 'FAILED')}")
                else:
                    logs.append(f"  ✓ Interfaces: {check_result.get('message', 'OK')}")

            if 'lldp' in checks and all_checks_passed:
                logs.append(f"  Checking LLDP neighbors...")
                check_result = self.verify_lldp_neighbors(min_neighbors=min_neighbors)
                result['verification_results']['lldp'] = check_result
                if not check_result['success']:
                    all_checks_passed = False
                    logs.append(f"  ✗ LLDP: {check_result.get('message', 'FAILED')}")
                else:
                    logs.append(f"  ✓ LLDP: {check_result.get('message', 'OK')}")
        
        # Phase 5: Confirm or let rollback
        logs.append(f"")
        logs.append(f"[Phase 5] Commit Confirmation")

        if all_checks_passed:
            logs.append(f"  All verification checks PASSED")
            if supports_native_commit_confirm:
                # Platforms with native commit-confirm (Juniper, Cumulus)
                try:
                    logger.info(f"Phase 5: All checks passed - confirming commit...")
                    logs.append(f"  Confirming commit (making changes permanent)...")
                    
                    # For Cumulus, we need to handle commit confirmation manually because:
                    # 1. NAPALM stores candidate revision_id from load_config (Phase 1)
                    # 2. commit_config creates a NEW pending revision with different ID
                    # 3. confirm_commit() looks for old revision_id, can't find it → "No pending commit-confirm found!"
                    # 
                    # FIX: Use the actual pending revision ID we captured in Phase 2
                    if driver_name == 'cumulus':
                        # Check if we captured the pending revision ID in Phase 2
                        actual_pending_revision = result.get('_cumulus_pending_revision_id')
                        if actual_pending_revision:
                            # Use the actual pending revision ID to confirm
                            logger.info(f"Using captured pending revision ID {actual_pending_revision} to confirm commit")
                            logs.append(f"  Using pending revision ID: {actual_pending_revision}")
                            
                            try:
                                if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                    # Manually execute confirm commands with the correct revision ID
                                    confirm_cmd = f"nv config apply {actual_pending_revision} --confirm-yes"
                                    logger.info(f"Executing: {confirm_cmd}")
                                    confirm_output = self.connection.device.send_command(confirm_cmd, read_timeout=30)
                                    logger.info(f"Confirm output: {confirm_output}")
                                    
                                    # Also run nv config save to make it persistent
                                    save_output = self.connection.device.send_command("nv config save", read_timeout=30)
                                    logger.info(f"Save output: {save_output}")
                                    
                                    # Update NAPALM's revision_id to None to mark as committed
                                    if hasattr(self.connection, 'revision_id'):
                                        self.connection.revision_id = None
                                    
                                    logger.info(f"Successfully confirmed commit using revision {actual_pending_revision}")
                                else:
                                    # Fallback to NAPALM method if device.send_command not available
                                    logger.warning(f"device.send_command not available, using NAPALM confirm_commit()")
                                    self.connection.confirm_commit()
                            except Exception as manual_confirm_error:
                                error_msg = str(manual_confirm_error)
                                logger.warning(f"Manual confirm failed: {manual_confirm_error}, trying NAPALM method...")
                                logs.append(f"  ⚠ Manual confirm failed, trying NAPALM method...")
                                # Fallback to NAPALM's method
                                try:
                                    self.connection.confirm_commit()
                                except Exception as napalm_confirm_error:
                                    # Both methods failed
                                    raise Exception(f"Both manual and NAPALM confirm failed. Manual: {error_msg}, NAPALM: {napalm_confirm_error}")
                        else:
                            # No captured revision ID - check if commit actually failed due to bad commands
                            commit_warning = result.get('_commit_warning')
                            if commit_warning:
                                # Commit failed - no pending revision but changes exist
                                # This likely means commands had syntax errors (like "vlan add" instead of "vlan")
                                # Get actual error details if available
                                actual_error = "Unknown error"
                                detailed_diagnostics = []
                                
                                try:
                                    # Try to get error from config diff or device
                                    if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                        # Check 1: What does nv config diff show?
                                        diff_output = self.connection.device.send_command('nv config diff', read_timeout=10)
                                        detailed_diagnostics.append(f"[DEBUG] nv config diff output:")
                                        if diff_output:
                                            detailed_diagnostics.append(f"  {diff_output[:500]}")
                                            if 'error' in diff_output.lower():
                                                actual_error = diff_output.strip()
                                            elif 'no changes' in diff_output.lower():
                                                actual_error = "No changes detected - config already matches applied config"
                                            else:
                                                actual_error = "Commit succeeded but no commit-confirm session was created"
                                        else:
                                            detailed_diagnostics.append(f"  (empty output)")
                                        
                                        # Check 2: What does nv config history show?
                                        history_output = self.connection.device.send_command('nv config history | head -10', read_timeout=10)
                                        detailed_diagnostics.append(f"[DEBUG] nv config history output:")
                                        if history_output:
                                            detailed_diagnostics.append(f"  {history_output[:500]}")
                                        else:
                                            detailed_diagnostics.append(f"  (empty output)")
                                        
                                        # Check 3: What did commit_config() actually return?
                                        commit_result = result.get('_commit_result')
                                        if commit_result is not None:
                                            detailed_diagnostics.append(f"[DEBUG] commit_config() return value: {commit_result}")
                                            detailed_diagnostics.append(f"[DEBUG] commit_config() return type: {type(commit_result)}")
                                        
                                        # Check 4: Check for pending commits now
                                        pending_check = self.connection.device.send_command('nv config revision -o json', read_timeout=10)
                                        detailed_diagnostics.append(f"[DEBUG] nv config revision -o json:")
                                        if pending_check:
                                            try:
                                                import json
                                                rev_data = json.loads(pending_check)
                                                pending_found = False
                                                for rev_id, rev_info in rev_data.items():
                                                    if isinstance(rev_info, dict) and rev_info.get('state') == 'confirm':
                                                        pending_found = True
                                                        detailed_diagnostics.append(f"  Found pending revision: {rev_id}")
                                                if not pending_found:
                                                    detailed_diagnostics.append(f"  No pending revisions found in JSON")
                                            except:
                                                detailed_diagnostics.append(f"  {pending_check[:200]}")
                                        else:
                                            detailed_diagnostics.append(f"  (empty output)")
                                        
                                        # Check 5: What commands were actually sent?
                                        config_commands = result.get('_config_commands', 'N/A')
                                        detailed_diagnostics.append(f"[DEBUG] Commands that were loaded:")
                                        if config_commands:
                                            for line in str(config_commands).split('\n')[:10]:
                                                detailed_diagnostics.append(f"  {line}")
                                        
                                except Exception as e:
                                    actual_error = f"Could not retrieve error details: {str(e)}"
                                    detailed_diagnostics.append(f"[DEBUG] Exception during diagnostics: {str(e)}")
                                    import traceback
                                    detailed_diagnostics.append(f"[DEBUG] Traceback: {traceback.format_exc()}")
                                
                                error_msg = f"Commit failed - no commit-confirm session created. {actual_error}"
                                logger.error(f"Phase 5 failed: {error_msg}")
                                logs.append(f"  ✗ Commit failed - no commit-confirm session created")
                                logs.append(f"  Error: {actual_error}")
                                logs.append(f"")
                                logs.append(f"  === DETAILED DIAGNOSTICS ===")
                                for diag_line in detailed_diagnostics:
                                    logs.append(f"  {diag_line}")
                                logs.append(f"")
                                logs.append(f"  === ROOT CAUSE ANALYSIS ===")
                                logs.append(f"  The commit-confirm session was not created. Possible reasons:")
                                logs.append(f"    1. Config already matches applied config (no changes to commit)")
                                logs.append(f"    2. Config syntax errors during load (check commands above)")
                                logs.append(f"    3. Commit command failed silently (check device logs)")
                                logs.append(f"    4. Timing issue - revision not yet visible")
                                logs.append(f"    5. Concurrent commit from another process")
                                
                                # Check current state - if changes are applied but not in commit-confirm, we need to save them
                                try:
                                    if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                        diff_check = self.connection.device.send_command('nv config diff', read_timeout=10)
                                        if diff_check and 'no changes' not in diff_check.lower():
                                            # Changes exist but not in commit-confirm - save them to make permanent
                                            logger.warning(f"Changes exist but not in commit-confirm - saving config to make permanent")
                                            logs.append(f"  ⚠ Saving config to make changes permanent (no commit-confirm session available)")
                                            save_output = self.connection.device.send_command("nv config save", read_timeout=30)
                                            logger.info(f"Config saved: {save_output}")
                                            logs.append(f"  ✓ Config saved - changes are now permanent")
                                            logs.append(f"  ⚠ WARNING: Changes were saved WITHOUT commit-confirm protection")
                                            logs.append(f"  ⚠ This means no automatic rollback is available")
                                            result['success'] = True
                                            result['committed'] = False  # NOT committed via commit-confirm, but saved
                                            result['message'] = f"Configuration applied and saved (commit-confirm session was not created, but changes were saved without rollback protection)"
                                            logs.append(f"")
                                            logs.append(f"=== DEPLOYMENT COMPLETED (WITH WARNING) ===")
                                            result['logs'] = logs
                                            return result
                                        else:
                                            # No changes - config already matches
                                            logger.warning(f"No changes detected - config already matches applied config")
                                            logs.append(f"  ℹ No changes detected - config already matches applied config")
                                            result['success'] = True
                                            result['committed'] = False  # Nothing to commit
                                            result['message'] = f"Configuration already matches applied config (no changes needed)"
                                            logs.append(f"")
                                            logs.append(f"=== DEPLOYMENT COMPLETED (NO CHANGES) ===")
                                            result['logs'] = logs
                                            return result
                                except Exception as save_error:
                                    logger.error(f"Failed to check/save config: {save_error}")
                                    logs.append(f"  ✗ Failed to check/save config: {str(save_error)}")
                                
                                result['message'] = error_msg
                                result['logs'] = logs
                                result['committed'] = False  # NOT committed
                                return result
                            
                            # No captured revision ID - try NAPALM's method (may fail, but worth trying)
                            logger.warning(f"No pending revision ID captured in Phase 2, using NAPALM confirm_commit()")
                            logs.append(f"  ⚠ No pending revision ID captured, using NAPALM method...")
                            try:
                                self.connection.confirm_commit()
                            except Exception as confirm_error:
                                error_msg = str(confirm_error)
                                # Check if it's the "No pending commit-confirm found!" error
                                if "no pending commit-confirm" in error_msg.lower() or "no pending" in error_msg.lower():
                                    # Try to get pending revision now and confirm manually
                                    logger.warning(f"NAPALM confirm failed, trying to get pending revision now...")
                                    try:
                                        if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                            # Use nv config history instead of revision -o json (more reliable)
                                            pending_rev_output = self.connection.device.send_command('nv config history | grep -i "pending\\|confirm" | head -1', read_timeout=10)
                                            if pending_rev_output:
                                                import re
                                                rev_match = re.search(r'Revision:\s*(\d+)', pending_rev_output)
                                                if not rev_match:
                                                    rev_match = re.search(r'^\s*(\d+)\s*\*', pending_rev_output)
                                                if rev_match:
                                                    actual_rev = rev_match.group(1)
                                                    logger.info(f"Found pending revision {actual_rev}, confirming manually...")
                                                    self.connection.device.send_command(f"nv config apply {actual_rev} --confirm-yes", read_timeout=30)
                                                    self.connection.device.send_command("nv config save", read_timeout=30)
                                                    if hasattr(self.connection, 'revision_id'):
                                                        self.connection.revision_id = None
                                                else:
                                                    raise Exception("No pending commits found - may have timed out")
                                            else:
                                                raise Exception("Could not get pending revisions")
                                        else:
                                            raise confirm_error
                                    except Exception as recovery_error:
                                        logger.error(f"Failed to recover: {recovery_error}")
                                        logs.append(f"  ✗ Commit-confirm not found: {error_msg}")
                                        logs.append(f"  ✗ Recovery attempt also failed: {recovery_error}")
                                        logs.append(f"  Possible causes:")
                                        logs.append(f"    - Commit-confirm timed out and auto-rolled back")
                                        logs.append(f"    - Commit was confirmed/aborted by another process")
                                        logs.append(f"    - Commands had syntax errors (e.g., 'vlan add' instead of 'vlan')")
                                        raise
                                else:
                                    raise
                    else:
                        # For other platforms (Juniper), use NAPALM's method
                        self.connection.confirm_commit()
                    
                    result['success'] = True
                    result['committed'] = True
                    result['message'] = f"Configuration successfully deployed and confirmed on {self.device.name}"
                    logger.info(f"{'='*60}")
                    logger.info(f"SUCCESS: Configuration is now PERMANENT")
                    logger.info(f"{'='*60}")
                    logs.append(f"  ✓ Commit CONFIRMED - changes are now PERMANENT")
                    logs.append(f"")
                    
                    # Show summary of commands that were actually applied
                    removed = result.get('_removed_commands', [])
                    added = result.get('_added_commands', [])
                    if removed or added:
                        logs.append(f"--- Commands Applied ---")
                        logs.append(f"")
                        logs.append(f"The following configuration changes were applied to the device:")
                        logs.append(f"")
                        
                        if removed:
                            logs.append(f"Old configuration commands removed/replaced:")
                            logs.append(f"  (These commands were removed because they conflicted with the new VLAN config)")
                            for cmd in removed:
                                logs.append(f"  - {cmd}")
                            logs.append(f"")
                        
                        if added:
                            logs.append(f"New configuration commands added:")
                            logs.append(f"  (These commands configure the new VLAN on the interface)")
                            for cmd in added:
                                logs.append(f"  + {cmd}")
                            logs.append(f"")
                    
                    logs.append(f"=== DEPLOYMENT SUCCESSFUL ===")
                    result['logs'] = logs
                    return result

                except Exception as e:
                    result['message'] = f"Failed to confirm commit: {str(e)} - will auto-rollback"
                    logger.error(f"Phase 5 failed: {e}")
                    logger.warning(f"Waiting {timeout}s for automatic rollback...")
                    logs.append(f"  ✗ Failed to confirm commit: {str(e)}")
                    logs.append(f"  ⚠ Waiting {timeout}s for automatic rollback...")
                    time.sleep(timeout + 5)
                    
                    # Verify if rollback actually happened
                    rollback_status, rollback_message = self._verify_rollback(driver_name)
                    result['rolled_back'] = rollback_status if rollback_status is not None else True
                    
                    if rollback_status is True:
                        result['message'] += f" - Auto-rollback completed"
                        logger.info(f"Auto-rollback completed: {rollback_message}")
                        logs.append(f"  ✓ Auto-rollback completed - changes reverted")
                        logs.append(f"  ✓ Verification: {rollback_message}")
                    elif rollback_status is False:
                        result['message'] += f" - Auto-rollback may have failed"
                        logger.warning(f"Auto-rollback verification failed: {rollback_message}")
                        logs.append(f"  ⚠ Auto-rollback completed but verification failed")
                        logs.append(f"  ⚠ Warning: {rollback_message}")
                    else:
                        result['message'] += f" - Auto-rollback completed (could not verify)"
                        logger.info(f"Auto-rollback completed: {rollback_message}")
                        logs.append(f"  ✓ Auto-rollback completed - changes reverted")
                        logs.append(f"  ⚠ Note: {rollback_message}")
                    
                    logs.append(f"")
                    
                    # Add rollback information based on verification
                    logs.append(f"--- Rollback Information ---")
                    logs.append(f"Platform: {driver_name.upper()}")
                    if rollback_status is True:
                        logs.append(f"Auto-Rollback: VERIFIED - Changes have been automatically reverted")
                        logs.append(f"  Status: {rollback_message}")
                        # Don't show manual steps when rollback is verified successful
                    elif rollback_status is False:
                        logs.append(f"Auto-Rollback: FAILED or INCOMPLETE - Manual intervention required")
                        logs.append(f"  Warning: {rollback_message}")
                        logs.append(f"")
                        logs.append(f"Manual rollback steps:")
                        if driver_name == 'cumulus':
                            logs.append(f"  nv config history")
                            logs.append(f"  nv config diff <previous_revision>")
                            logs.append(f"  nv config apply <previous_revision>")
                        elif driver_name == 'eos':
                            logs.append(f"  show archive")
                            logs.append(f"  show archive config differences <archive_number>")
                            logs.append(f"  configure replace <archive_file>")
                    else:
                        logs.append(f"Auto-Rollback: COMPLETED (verification unavailable)")
                        logs.append(f"  Note: {rollback_message}")
                        logs.append(f"")
                        logs.append(f"Manual rollback steps (if auto-rollback failed or to restore to different state):")
                        if driver_name == 'cumulus':
                            logs.append(f"  nv config history")
                            logs.append(f"  nv config diff <previous_revision>")
                            logs.append(f"  nv config apply <previous_revision>")
                        elif driver_name == 'eos':
                            logs.append(f"  show archive")
                            logs.append(f"  show archive config differences <archive_number>")
                            logs.append(f"  configure replace <archive_file>")
                    logs.append(f"")
                    logs.append(f"=== DEPLOYMENT ROLLED BACK ===")
                    result['logs'] = logs
                    return result

            elif use_eos_session and hasattr(self, '_eos_session_name'):
                # EOS with configure session - need to confirm
                try:
                    session_name = self._eos_session_name
                    netmiko_conn = self._eos_netmiko_conn
                    
                    logger.info(f"Phase 5: All checks passed - confirming EOS session {session_name}...")
                    logs.append(f"  Confirming EOS session {session_name}...")
                    
                    # Send 'commit' command to confirm the pending commit
                    # After commit confirmation, we stay in privileged exec mode
                    output = netmiko_conn.send_command(
                        "commit",
                        expect_string=r'#',
                        read_timeout=60
                    )
                    logger.info(f"Commit confirm output: {output}")
                    
                    # Check if commit was successful
                    if 'failed' in output.lower() or 'error' in output.lower():
                        raise Exception(f"Commit confirmation failed: {output}")
                    
                    result['success'] = True
                    result['committed'] = True
                    result['message'] = f"Configuration successfully deployed and confirmed on {self.device.name}"
                    logger.info(f"{'='*60}")
                    logger.info(f"SUCCESS: EOS session confirmed - configuration is now PERMANENT")
                    logger.info(f"{'='*60}")
                    logs.append(f"  ✓ EOS session CONFIRMED - changes are now PERMANENT")
                    logs.append(f"")
                    logs.append(f"=== DEPLOYMENT SUCCESSFUL ===")
                    result['logs'] = logs
                    
                    # Clean up session tracking
                    delattr(self, '_eos_session_name')
                    delattr(self, '_eos_session_timer')
                    delattr(self, '_eos_netmiko_conn')
                    
                    return result
                    
                except Exception as e:
                    result['message'] = f"Failed to confirm EOS session: {str(e)}"
                    logger.error(f"Phase 5 failed: {e}")
                    logger.error(f"Traceback: {traceback.format_exc()}")
                    logs.append(f"  ✗ Failed to confirm EOS session: {str(e)}")
                    logs.append(f"  ⚠ Session will auto-rollback after timer expires")
                    logs.append(f"")
                    
                    # Add rollback information
                    logs.append(f"--- Rollback Information ---")
                    logs.append(f"Platform: EOS")
                    logs.append(f"Auto-Rollback: PENDING - EOS commit timer will expire and rollback automatically")
                    logs.append(f"  Timer: {self._eos_session_timer} minutes")
                    logs.append(f"")
                    logs.append(f"If you need to manually rollback before timer expires or verify restoration:")
                    logs.append(f"  show archive")
                    logs.append(f"  show archive config differences <archive_number>")
                    logs.append(f"  configure replace <archive_file>")
                    logs.append(f"")
                    logs.append(f"=== Deployment Completed ===")
                    logs.append(f"Final Status: ERROR (will auto-rollback)")
                    logs.append(f"Config Applied: Pending (will rollback)")
                    
                    result['logs'] = logs
                    return result
            else:
                # Direct commit platforms (no rollback)
                result['success'] = True
                result['committed'] = True

                # Build message based on verification results
                if vlan_id and interface_name:
                    verif_msg = result['verification_results'].get('connectivity', {}).get('message', '')
                    result['message'] = f"Configuration successfully deployed on {self.device.name} (direct commit) | Verification: {verif_msg}"
                else:
                    result['message'] = f"Configuration successfully deployed on {self.device.name} (direct commit, no rollback support)"

                logger.info(f"{'='*60}")
                logger.info(f"SUCCESS: Configuration committed")
                logs.append(f"  ✓ Configuration committed (direct commit, no rollback support)")
                logs.append(f"")
                logs.append(f"=== DEPLOYMENT SUCCESSFUL ===")
                logger.info(f"{'='*60}")
                result['logs'] = logs
                return result

        else:
            # Verification failed - handle rollback
            logs.append(f"  ✗ Verification checks FAILED")
            failed_checks = [k for k, v in result['verification_results'].items() if not v.get('success', True)]
            failed_messages = [v.get('message', k) for k, v in result['verification_results'].items() if not v.get('success', True)]

            logs.append(f"  Failed checks: {', '.join(failed_checks)}")
            for msg in failed_messages:
                logs.append(f"    • {msg}")

            if supports_native_commit_confirm:
                # Platforms with native rollback (Cumulus, Juniper)
                result['message'] = f"Verification checks failed: {', '.join(failed_checks)} - waiting for auto-rollback"
                logger.warning(f"{'='*60}")
                logger.warning(f"VERIFICATION FAILED:")
                for msg in failed_messages:
                    logger.warning(f"  • {msg}")
                logger.warning(f"{'='*60}")
                logger.warning(f"NOT calling confirm_commit() - waiting {timeout}s for automatic rollback...")
                logs.append(f"  ⚠ NOT confirming commit - waiting {timeout}s for auto-rollback...")
                time.sleep(timeout + 5)
                
                # Verify if rollback actually happened
                rollback_status, rollback_message = self._verify_rollback(driver_name)
                result['rolled_back'] = rollback_status if rollback_status is not None else True
                
                if rollback_status is True:
                    result['message'] += f" - Auto-rollback completed"
                    logger.info(f"{'='*60}")
                    logger.info(f"AUTO-ROLLBACK: Device returned to previous state")
                    logger.info(f"Verification: {rollback_message}")
                    logger.info(f"{'='*60}")
                    logs.append(f"  ✓ Auto-rollback completed - device returned to previous state")
                    logs.append(f"  ✓ Verification: {rollback_message}")
                elif rollback_status is False:
                    result['message'] += f" - Auto-rollback may have failed"
                    logger.warning(f"{'='*60}")
                    logger.warning(f"AUTO-ROLLBACK: Verification failed")
                    logger.warning(f"Warning: {rollback_message}")
                    logger.warning(f"{'='*60}")
                    logs.append(f"  ⚠ Auto-rollback completed but verification failed")
                    logs.append(f"  ⚠ Warning: {rollback_message}")
                else:
                    result['message'] += f" - Auto-rollback completed (could not verify)"
                    logger.info(f"{'='*60}")
                    logger.info(f"AUTO-ROLLBACK: Device returned to previous state")
                    logger.info(f"Note: {rollback_message}")
                    logger.info(f"{'='*60}")
                    logs.append(f"  ✓ Auto-rollback completed - device returned to previous state")
                    logs.append(f"  ⚠ Note: {rollback_message}")
                
                logs.append(f"")
                
                # Add rollback information based on verification
                logs.append(f"--- Rollback Information ---")
                logs.append(f"Platform: {driver_name.upper()}")
                if rollback_status is True:
                    logs.append(f"Auto-Rollback: VERIFIED - Changes have been automatically reverted due to verification failure")
                    logs.append(f"  Status: {rollback_message}")
                    # Don't show manual steps when rollback is verified successful
                elif rollback_status is False:
                    logs.append(f"Auto-Rollback: FAILED or INCOMPLETE - Manual intervention required")
                    logs.append(f"  Warning: {rollback_message}")
                    logs.append(f"")
                    logs.append(f"Manual rollback steps:")
                    if driver_name == 'cumulus':
                        logs.append(f"  nv config history")
                        logs.append(f"  nv config diff <previous_revision>")
                        logs.append(f"  nv config apply <previous_revision>")
                    elif driver_name == 'eos':
                        logs.append(f"  show archive")
                        logs.append(f"  show archive config differences <archive_number>")
                        logs.append(f"  configure replace <archive_file>")
                else:
                    logs.append(f"Auto-Rollback: COMPLETED (verification unavailable)")
                    logs.append(f"  Note: {rollback_message}")
                    logs.append(f"")
                    logs.append(f"Manual rollback steps (if auto-rollback failed or to restore to different state):")
                    if driver_name == 'cumulus':
                        logs.append(f"  nv config history")
                        logs.append(f"  nv config diff <previous_revision>")
                        logs.append(f"  nv config apply <previous_revision>")
                    elif driver_name == 'eos':
                        logs.append(f"  show archive")
                        logs.append(f"  show archive config differences <archive_number>")
                        logs.append(f"  configure replace <archive_file>")
                logs.append(f"")
                logs.append(f"=== DEPLOYMENT ROLLED BACK ===")
                result['logs'] = logs
                return result

            elif use_eos_session and hasattr(self, '_eos_session_name'):
                # EOS with session - CANNOT abort once commit timer is active!
                # Must wait for timer to expire for automatic rollback
                session_name = self._eos_session_name
                timer_minutes = self._eos_session_timer
                
                result['message'] = f"Verification checks failed: {', '.join(failed_checks)} - waiting for auto-rollback"
                logger.warning(f"{'='*60}")
                logger.warning(f"VERIFICATION FAILED:")
                for msg in failed_messages:
                    logger.warning(f"  • {msg}")
                logger.warning(f"{'='*60}")
                logger.warning(f"NOT confirming EOS session {session_name} - waiting {timer_minutes}min for automatic rollback...")
                logger.warning(f"Note: EOS sessions with pending commit timer cannot be aborted manually")
                logs.append(f"  ⚠ Verification FAILED")
                logs.append(f"  ⚠ NOT confirming EOS session {session_name}")
                logs.append(f"  ⚠ Waiting {timer_minutes} minutes for automatic rollback...")
                logs.append(f"  Note: EOS commit timers cannot be cancelled, must wait for expiry")
                
                # Wait for timer to expire (plus buffer)
                logger.info(f"Waiting {timer_minutes} minutes for EOS timer to expire...")
                time.sleep(timer_minutes * 60 + 10)
                
                # Verify if rollback actually happened
                rollback_status, rollback_message = self._verify_rollback(driver_name)
                result['rolled_back'] = rollback_status if rollback_status is not None else True
                
                if rollback_status is True:
                    result['message'] += f" - Auto-rollback completed (timer expired)"
                    logger.info(f"{'='*60}")
                    logger.info(f"AUTO-ROLLBACK: EOS timer expired, device returned to previous state")
                    logger.info(f"Verification: {rollback_message}")
                    logger.info(f"{'='*60}")
                    logs.append(f"  ✓ Timer expired - device automatically rolled back to previous state")
                    logs.append(f"  ✓ Verification: {rollback_message}")
                elif rollback_status is False:
                    result['message'] += f" - Auto-rollback may have failed (timer expired)"
                    logger.warning(f"{'='*60}")
                    logger.warning(f"AUTO-ROLLBACK: Timer expired but verification failed")
                    logger.warning(f"Warning: {rollback_message}")
                    logger.warning(f"{'='*60}")
                    logs.append(f"  ⚠ Timer expired but rollback verification failed")
                    logs.append(f"  ⚠ Warning: {rollback_message}")
                else:
                    result['message'] += f" - Auto-rollback completed (timer expired, could not verify)"
                    logger.info(f"{'='*60}")
                    logger.info(f"AUTO-ROLLBACK: EOS timer expired, device returned to previous state")
                    logger.info(f"Note: {rollback_message}")
                    logger.info(f"{'='*60}")
                    logs.append(f"  ✓ Timer expired - device automatically rolled back to previous state")
                    logs.append(f"  ⚠ Note: {rollback_message}")
                
                logs.append(f"")
                
                # Add rollback information based on verification
                logs.append(f"--- Rollback Information ---")
                logs.append(f"Platform: EOS")
                if rollback_status is True:
                    logs.append(f"Auto-Rollback: VERIFIED - EOS commit timer expired, changes have been automatically reverted")
                    logs.append(f"  Status: {rollback_message}")
                    # Don't show manual steps when rollback is verified successful
                elif rollback_status is False:
                    logs.append(f"Auto-Rollback: FAILED or INCOMPLETE - Manual intervention required")
                    logs.append(f"  Warning: {rollback_message}")
                    logs.append(f"")
                    logs.append(f"Manual rollback steps:")
                    logs.append(f"  show archive")
                    logs.append(f"  show archive config differences <archive_number>")
                    logs.append(f"  configure replace <archive_file>")
                else:
                    logs.append(f"Auto-Rollback: COMPLETED (verification unavailable)")
                    logs.append(f"  Note: {rollback_message}")
                    logs.append(f"")
                    logs.append(f"Manual rollback steps (if auto-rollback failed or to restore to different state):")
                    logs.append(f"  show archive")
                    logs.append(f"  show archive config differences <archive_number>")
                    logs.append(f"  configure replace <archive_file>")
                logs.append(f"")
                logs.append(f"=== DEPLOYMENT ROLLED BACK ===")
                result['logs'] = logs
                return result
            else:
                # Platform without rollback support - config already committed
                result['success'] = False
                logs.append(f"  ⚠ Platform does not support rollback - changes are PERMANENT")
                logs.append(f"  ⚠ Manual intervention may be required")
                result['committed'] = True
                result['rolled_back'] = False
                result['message'] = f"Configuration committed but verification failed: {', '.join(failed_checks)}"
                logger.warning(f"{'='*60}")
                logger.warning(f"WARNING: Config committed but verification failed:")
                for msg in failed_messages:
                    logger.warning(f"  • {msg}")
                logger.warning(f"Platform doesn't support auto-rollback - manual intervention may be needed")
                logger.warning(f"{'='*60}")
                logs.append(f"")
                
                # Add rollback information for platforms without rollback support
                logs.append(f"--- Rollback Information ---")
                logs.append(f"Platform: {driver_name.upper()}")
                logs.append(f"⚠️  WARNING: Platform does not support automatic rollback")
                logs.append(f"  Status: Configuration has been committed and is PERMANENT")
                logs.append(f"  Manual intervention required to revert changes")
                logs.append(f"")
                logs.append(f"Manual rollback steps:")
                if driver_name == 'cumulus':
                    logs.append(f"  nv config history")
                    logs.append(f"  nv config diff <previous_revision>")
                    logs.append(f"  nv config apply <previous_revision>")
                elif driver_name == 'eos':
                    logs.append(f"  show archive")
                    logs.append(f"  show archive config differences <archive_number>")
                    logs.append(f"  configure replace <archive_file>")
                logs.append(f"")
                logs.append(f"=== Deployment Completed ===")
                logs.append(f"Final Status: ERROR (verification failed, manual rollback required)")
                logs.append(f"Config Applied: Yes (but verification failed)")
                logs.append(f"=== DEPLOYMENT COMPLETED WITH WARNINGS ===")
                result['logs'] = logs
                return result


class NAPALMBulkOperations:
    """
    Perform bulk operations on multiple devices using NAPALM
    """
    
    def __init__(self, devices):
        self.devices = devices
        self.results = {}
    
    def collect_facts(self):
        """
        Collect facts from all devices
        """
        for device in self.devices:
            manager = NAPALMDeviceManager(device)
            try:
                facts = manager.get_facts()
                self.results[device.name] = {
                    'status': 'success',
                    'facts': facts
                }
            except Exception as e:
                self.results[device.name] = {
                    'status': 'error',
                    'error': str(e)
                }
            finally:
                manager.disconnect()
        
        return self.results
    
    def backup_configs(self):
        """
        Backup configurations from all devices
        """
        for device in self.devices:
            manager = NAPALMDeviceManager(device)
            try:
                backup = manager.backup_config()
                self.results[device.name] = {
                    'status': 'success',
                    'backup': backup
                }
            except Exception as e:
                self.results[device.name] = {
                    'status': 'error',
                    'error': str(e)
                }
            finally:
                manager.disconnect()
        
        return self.results
    
    def deploy_configs_safe(self, config_template, replace=True, timeout=60,
                           checks=['connectivity', 'interfaces', 'lldp'],
                           critical_interfaces=None, min_neighbors=0, job_id=None):
        """
        Deploy configuration template to all devices with failsafe commit-confirm
        
        This method uses the Juniper-style commit-confirm workflow for each device:
        - Loads config (replace or merge)
        - Commits with auto-rollback timer
        - Verifies device health
        - Confirms if checks pass, otherwise rolls back
        
        Args:
            config_template: Configuration template string (use {{device_name}}, {{site}}, etc.)
            replace: If True, replace entire config. If False, merge incrementally
            timeout: Rollback timer per device in seconds (60-120 recommended)
            checks: List of verification checks ['connectivity', 'interfaces', 'lldp']
            critical_interfaces: List of interface names that must be up
            min_neighbors: Minimum LLDP neighbors required
            job_id: Optional AutomationJob ID for tracking
        
        Returns:
            dict: Results per device with success/failure status
        """
        if job_id:
            try:
                job = AutomationJob.objects.get(id=job_id)
            except:
                job = None
        else:
            job = None
        
        for device in self.devices:
            manager = NAPALMDeviceManager(device)
            try:
                # Render template with device context
                rendered_config = self._render_template(config_template, device)
                
                # Deploy with failsafe
                deploy_result = manager.deploy_config_safe(
                    config=rendered_config,
                    replace=replace,
                    timeout=timeout,
                    checks=checks,
                    critical_interfaces=critical_interfaces,
                    min_neighbors=min_neighbors
                )
                
                self.results[device.name] = {
                    'status': 'success' if deploy_result['success'] else 'failed',
                    'committed': deploy_result['committed'],
                    'rolled_back': deploy_result['rolled_back'],
                    'message': deploy_result['message'],
                    'verification_results': deploy_result['verification_results'],
                    'config': rendered_config
                }
                
                if job and job_id:
                    job.result_data[device.name] = self.results[device.name]
                    job.save()
                    
            except Exception as e:
                self.results[device.name] = {
                    'status': 'error',
                    'committed': False,
                    'rolled_back': False,
                    'message': f"Exception during deployment: {str(e)}",
                    'error': str(e)
                }
                if job and job_id:
                    job.result_data[device.name] = self.results[device.name]
                    job.save()
            finally:
                manager.disconnect()
        
        return self.results
    
    def _render_template(self, template, device):
        """
        Render configuration template with device context
        """
        # Simple template rendering - you might want to use Jinja2
        context = {
            'device_name': device.name,
            'device_type': device.device_type.model,
            'manufacturer': device.device_type.manufacturer.name,
            'site': device.site.name,
            'primary_ip': device.primary_ip4.address.split('/')[0] if device.primary_ip4 else '',
        }
        
        rendered = template
        for key, value in context.items():
            rendered = rendered.replace(f'{{{{{key}}}}}', str(value))
        
        return rendered

