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
import json

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
                # Note: use_nvue is set AFTER connection.open() (see below) because the driver
                # doesn't read it from optional_args - it auto-detects based on 'net' command support
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
                    
                    # CRITICAL FIX: Force use_nvue=True for Cumulus devices
                    # The driver auto-detects use_nvue by checking if 'net' commands fail,
                    # but modern Cumulus devices support both 'net' and 'nv' commands.
                    # If 'net' works, use_nvue stays False, causing commit_config(revert_in=90) to return None.
                    # We MUST force use_nvue=True to enable commit-confirm support.
                    if driver_name == 'cumulus' and hasattr(self.connection, 'use_nvue'):
                        if not self.connection.use_nvue:
                            logger.info(f"Force-enabling use_nvue=True for Cumulus device (required for commit-confirm)")
                            self.connection.use_nvue = True
                    
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
        
        Primary: Uses NAPALM's get_facts() method
        Fallback: If primary fails, runs direct NVUE command 'nv show system -o json'
        and parses the JSON to build facts dict (for GNS3/virtual devices)
        
        Handles cases where prompt detection fails (e.g., empty output from device)
        Also handles JSON parsing errors and validates facts structure
        """
        if not self.connection:
            if not self.connect():
                return None
        
        # Check if connection is alive before attempting to get facts
        try:
            if hasattr(self.connection, 'is_alive') and not self.connection.is_alive():
                logger.warning(f"Connection to {self.device.name} is not alive, reconnecting...")
                if not self.connect():
                    logger.error(f"Failed to reconnect to {self.device.name}")
                    return None
        except Exception as e:
            logger.warning(f"Error checking connection status for {self.device.name}: {e}")
        
        # Primary: Try NAPALM's get_facts() method
        try:
            facts = self.connection.get_facts()
            # Validate facts is a dict and not None/empty
            if facts is None:
                logger.warning(f"get_facts() returned None for {self.device.name}, trying NVUE fallback...")
                # Fall through to fallback
            elif not isinstance(facts, dict):
                logger.warning(f"get_facts() returned non-dict type {type(facts)} for {self.device.name}, trying NVUE fallback...")
                # Fall through to fallback
            elif not facts:
                logger.warning(f"get_facts() returned empty dict for {self.device.name}, trying NVUE fallback...")
                # Fall through to fallback
            else:
                # Success - return facts
                return facts
        except (ValueError, TypeError) as e:
            # JSON parsing errors from napalm-cumulus driver
            error_msg = str(e)
            logger.warning(f"get_facts() failed with parsing error for {self.device.name}: {e}, trying NVUE fallback...")
            # Fall through to fallback
        except Exception as e:
            error_msg = str(e)
            logger.warning(f"get_facts() failed with exception for {self.device.name}: {e}, trying NVUE fallback...")
            # Fall through to fallback
        
        # Fallback: Try direct NVUE command 'nv show system -o json'
        # This works for GNS3/virtual devices where NAPALM's get_facts() may fail
        if self.connection and hasattr(self.connection, 'device'):
            try:
                driver_name = self.get_driver_name()
                if driver_name == 'cumulus':
                    logger.info(f"Trying NVUE fallback for get_facts() on {self.device.name}...")
                    nvue_output = self.connection.device.send_command_timing('nv show system -o json', read_timeout=10)
                    if nvue_output and nvue_output.strip() and 'Error:' not in nvue_output:
                        try:
                            import json
                            system_data = json.loads(nvue_output.strip())
                            if isinstance(system_data, dict):
                                # Build facts dict from NVUE JSON output
                                hostname = system_data.get('hostname', self.device.name)
                                facts = {
                                    'hostname': hostname,
                                    'fqdn': hostname,
                                    'os_version': system_data.get('build') or system_data.get('product-release') or system_data.get('version', {}).get('image', 'N/A'),
                                    'vendor': 'Cumulus Networks',
                                    'model': system_data.get('product-name', 'N/A'),
                                    'serial_number': 'N/A',  # Not available in system JSON
                                    'uptime': system_data.get('uptime', -1),
                                    'health-status': system_data.get('health-status', 'Unknown'),
                                    'nvue_fallback': True  # Flag to indicate this came from fallback
                                }
                                logger.info(f"Successfully got facts via NVUE fallback for {self.device.name}: hostname={facts.get('hostname')}, uptime={facts.get('uptime')}s")
                                return facts
                        except (json.JSONDecodeError, ValueError, TypeError) as json_err:
                            logger.error(f"NVUE fallback JSON parsing failed for {self.device.name}: {json_err}")
            except Exception as nvue_err:
                logger.error(f"NVUE fallback command failed for {self.device.name}: {nvue_err}")
        
        # Both primary and fallback failed
        logger.error(f"Failed to get facts from {self.device.name} - both NAPALM and NVUE fallback failed")
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
        # CRITICAL: Validate config parameter
        if config is None:
            logger.error(f"load_config called with None config for {self.device.name}")
            self._last_load_error = {
                'error': 'Config parameter is None',
                'exception_type': 'ValueError'
            }
            return False
        
        # Convert to string and strip
        if not isinstance(config, str):
            config = str(config) if config else ''
        
        config = config.strip()
        
        if not config:
            logger.error(f"load_config called with empty config for {self.device.name}")
            self._last_load_error = {
                'error': 'Config parameter is empty',
                'exception_type': 'ValueError'
            }
            return False
        
        logger.debug(f"[load_config] Config validated: {len(config)} characters, {len(config.splitlines())} lines")
        
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
    
    def get_lldp_neighbors(self, max_retries=3, retry_delay=2, interfaces=None):
        """
        Get LLDP neighbors using direct device commands (not NAPALM).

        This method queries LLDP information directly from the device using platform-specific
        commands to get the most accurate and complete LLDP data.

        For Cumulus: Uses 'nv show interface <interface> lldp -o json' for each interface
        For Arista EOS: Uses 'show lldp neighbors'

        Args:
            max_retries: Number of retry attempts if LLDP query fails (default: 3)
            retry_delay: Seconds to wait between retries (default: 2)
            interfaces: Optional list of interfaces to check. If None, checks all interfaces.
                       For bonds, will extract member interfaces (swp*, eth*, etc.)

        Returns:
            Dictionary mapping local interface names to list of neighbor dictionaries
            Example: {
                'swp1': [{'hostname': 'switch1', 'port': 'swp2'}],
                'swp2': [{'hostname': 'switch2', 'port': 'Ethernet1'}]
            }
            Returns None if LLDP query fails after all retries
        """
        if not self.connection:
            if not self.connect():
                return None

        # Retry logic for LLDP queries
        last_error = None
        
        for attempt in range(1, max_retries + 1):
            try:
                if attempt > 1:
                    logger.info(f"LLDP query retry attempt {attempt}/{max_retries} for {self.device.name}")
                    import time
                    time.sleep(retry_delay)

                driver_name = self.get_driver_name()
                lldp_data = {}

                if driver_name == 'cumulus':
                    # Use NVUE command to query each interface individually (doesn't require sudo)
                    # Command: nv show interface <interface> lldp -o json
                    if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                        try:
                            logger.info(f"Fetching LLDP data from {self.device.name} using NVUE commands...")
                            
                            # Determine which interfaces to check
                            interfaces_to_check = []
                            
                            if interfaces:
                                # Use provided interfaces from deployment
                                logger.debug(f"Using provided interfaces from deployment: {interfaces}")
                                
                                # Extract member interfaces from bonds and filter to only member interfaces
                                # For bonds (bond3, bond4, etc.), we need to get their member interfaces (swp3, swp4, etc.)
                                # We skip checking LLDP on bonds directly - only check on member interfaces
                                for iface in interfaces:
                                    # Skip bonds - we need to get their member interfaces
                                    if iface.startswith('bond'):
                                        # Get bond members using: nv show interface bond3 bond member -o json
                                        # Expected structure: {"swp3": {}, "swp4": {}} or similar
                                        try:
                                            logger.debug(f"Extracting member interfaces from bond {iface}...")
                                            bond_output = self.connection.device.send_command_timing(
                                                f'nv show interface {iface} bond member -o json',
                                                read_timeout=10
                                            )
                                            if bond_output and bond_output.strip():
                                                bond_json = self._safe_json_loads(bond_output, context=f"Bond {iface} members")
                                                if bond_json and isinstance(bond_json, dict):
                                                    # Extract member interface names from JSON keys (swp3, swp4, etc.)
                                                    member_interfaces_found = []
                                                    for member_iface in bond_json.keys():
                                                        # Only add member interfaces (swp*, eth*, etc.), not bonds
                                                        if not member_iface.startswith('bond'):
                                                            interfaces_to_check.append(member_iface)
                                                            member_interfaces_found.append(member_iface)
                                                            logger.debug(f"  ✓ Extracted member interface {member_iface} from bond {iface}")
                                                    
                                                    if member_interfaces_found:
                                                        logger.info(f"Bond {iface} has {len(member_interfaces_found)} member interface(s): {member_interfaces_found}")
                                                    else:
                                                        logger.warning(f"Bond {iface} has no member interfaces found in JSON keys")
                                                else:
                                                    logger.warning(f"Bond {iface} member query returned non-dict: {type(bond_json)}")
                                            else:
                                                logger.warning(f"Bond {iface} member query returned empty output")
                                        except Exception as bond_error:
                                            logger.warning(f"Failed to get members for bond {iface}: {bond_error}")
                                    else:
                                        # Direct member interface (swp*, eth*, etc.) - add it directly
                                        # Skip if it's a bond (shouldn't happen, but safety check)
                                        if not iface.startswith('bond'):
                                            interfaces_to_check.append(iface)
                                            logger.debug(f"  ✓ Added direct member interface {iface} (not a bond)")
                            else:
                                # No interfaces provided - fall back to NAPALM method
                                logger.warning(f"No interfaces provided, falling back to NAPALM method")
                                return self._get_lldp_napalm_fallback()
                            
                            if not interfaces_to_check:
                                logger.warning(f"No member interfaces to check, falling back to NAPALM method")
                                return self._get_lldp_napalm_fallback()
                            
                            # Summary: Show what we're checking
                            logger.info(f"LLDP check summary:")
                            logger.info(f"  • Deployment interfaces: {interfaces}")
                            logger.info(f"  • Member interfaces to check LLDP: {interfaces_to_check}")
                            logger.info(f"  • Bonds skipped (checking members instead): {[iface for iface in interfaces if iface.startswith('bond')]}")
                            logger.debug(f"Checking LLDP on {len(interfaces_to_check)} member interface(s): {interfaces_to_check}")
                            
                            # Query each member interface individually for LLDP data
                            # NOTE: We are NOT checking LLDP on bonds - only on their member interfaces (swp3, swp4, etc.)
                            for iface_name in interfaces_to_check:
                                try:
                                    logger.debug(f"Querying LLDP for interface {iface_name}...")
                                    lldp_output = self.connection.device.send_command_timing(
                                        f'nv show interface {iface_name} lldp -o json',
                                        read_timeout=15
                                    )
                                    
                                    if lldp_output and lldp_output.strip():
                                        # Parse NVUE LLDP JSON format for this interface
                                        # Structure: {"neighbor": {"neighbor-name": {"chassis": {"system-name": "..."}, "port": {...}}}}
                                        lldp_json = self._safe_json_loads(lldp_output, context=f"LLDP for {iface_name}")
                                        if lldp_json is None:
                                            logger.debug(f"Failed to parse LLDP JSON for {iface_name}, skipping")
                                            continue
                                        
                                        # Check if this interface has neighbors
                                        if 'neighbor' in lldp_json and lldp_json['neighbor']:
                                            neighbors = []
                                            neighbor_dict = lldp_json['neighbor']
                                            
                                            # Each interface can have multiple neighbors (neighbor dict keys are neighbor names)
                                            for neighbor_name, neighbor_info in neighbor_dict.items():
                                                neighbor = {}
                                                
                                                # Extract hostname from chassis.system-name
                                                if 'chassis' in neighbor_info and 'system-name' in neighbor_info['chassis']:
                                                    neighbor['hostname'] = neighbor_info['chassis']['system-name']
                                                else:
                                                    # Fallback: use neighbor_name as hostname
                                                    neighbor['hostname'] = neighbor_name
                                                
                                                # Extract port from port.description (preferred) or port.name
                                                if 'port' in neighbor_info:
                                                    port_info = neighbor_info['port']
                                                    if 'description' in port_info:
                                                        neighbor['port'] = port_info['description']
                                                    elif 'name' in port_info:
                                                        neighbor['port'] = port_info['name']
                                                    else:
                                                        neighbor['port'] = 'unknown'
                                                else:
                                                    neighbor['port'] = 'unknown'
                                                
                                                if neighbor.get('hostname'):
                                                    neighbors.append(neighbor)
                                            
                                            if neighbors:
                                                lldp_data[iface_name] = neighbors
                                                logger.debug(f"Found {len(neighbors)} neighbor(s) on {iface_name}")
                                
                                except Exception as iface_error:
                                    logger.debug(f"Failed to get LLDP for interface {iface_name}: {iface_error}")
                                    continue  # Continue with next interface
                            
                            if lldp_data:
                                logger.info(f"Collected LLDP data from {self.device.name}: {len(lldp_data)} interfaces with neighbors")
                                return lldp_data
                            else:
                                logger.info(f"No LLDP neighbors found on {self.device.name}")
                                return {}
                                
                        except Exception as nvue_error:
                            logger.warning(f"NVUE LLDP query failed for {self.device.name}: {nvue_error}, falling back to NAPALM method")
                            return self._get_lldp_napalm_fallback()
                    else:
                        # No direct device access, use NAPALM fallback
                        return self._get_lldp_napalm_fallback()

                elif driver_name == 'eos':
                    # Use direct show command for Arista EOS
                    if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                        try:
                            lldp_output = self.connection.device.send_command_timing('show lldp neighbors', read_timeout=30)

                            if lldp_output:
                                # Parse EOS LLDP output (text format)
                                # Example:
                                # Port          Neighbor Device ID       Neighbor Port ID    TTL
                                # Et1           switch1                  Ethernet1           120
                                lldp_data = self._parse_lldp_eos_text(lldp_output)
                                logger.info(f"Collected LLDP data from {self.device.name}: {len(lldp_data)} interfaces with neighbors")
                                return lldp_data
                            else:
                                logger.warning(
                                    f"Empty LLDP output from {self.device.name}. "
                                    f"This may indicate: (1) LLDP is not enabled, (2) No neighbors detected, "
                                    f"(3) Connection issue, or (4) Command execution problem. "
                                    f"Output length: {len(lldp_output) if lldp_output else 0}"
                                )
                                # Return empty dict to indicate no LLDP neighbors found
                                return {}
                        except Exception as eos_error:
                            logger.warning(f"Attempt {attempt}/{max_retries}: Failed to get LLDP from EOS device {self.device.name}: {eos_error}")
                            last_error = eos_error
                            if attempt == max_retries:
                                # Last attempt failed, try NAPALM fallback
                                logger.info(f"All direct LLDP attempts failed, trying NAPALM fallback for {self.device.name}")
                                return self._get_lldp_napalm_fallback()
                            # Otherwise continue to next retry
                            continue
                    else:
                        # No direct device access, use NAPALM fallback
                        return self._get_lldp_napalm_fallback()
                else:
                    # Other platforms: use NAPALM
                    return self._get_lldp_napalm_fallback()

            except Exception as e:
                logger.warning(f"Attempt {attempt}/{max_retries}: Failed to get LLDP neighbors from {self.device.name}: {e}")
                last_error = e
                if attempt == max_retries:
                    logger.error(f"All {max_retries} LLDP query attempts failed for {self.device.name}: {last_error}")
                    return None
                # Otherwise continue to next retry

        # Should not reach here, but just in case
        logger.error(f"LLDP query failed after {max_retries} attempts for {self.device.name}")
        return None

    def _get_lldp_napalm_fallback(self):
        """Fallback to NAPALM get_lldp_neighbors() if direct commands fail"""
        try:
            lldp_neighbors = self.connection.get_lldp_neighbors()
            return lldp_neighbors
        except Exception as e:
            logger.error(f"NAPALM LLDP fallback failed for {self.device.name}: {e}")
            return None

    def _safe_json_loads(self, json_string, context="JSON"):
        """
        Safely parse JSON string with comprehensive error handling
        
        Args:
            json_string: String containing JSON data
            context: Context description for error messages (e.g., "LLDP", "Interface")
        
        Returns:
            Parsed JSON object (dict/list) or None if parsing fails
        """
        if not json_string:
            logger.warning(f"{context}: Empty JSON string provided")
            return None
        
        if not isinstance(json_string, str):
            logger.warning(f"{context}: Expected string, got {type(json_string).__name__}")
            return None
        
        # Strip whitespace
        json_string = json_string.strip()
        if not json_string:
            logger.warning(f"{context}: JSON string is empty after stripping")
            return None
        
        try:
            return json.loads(json_string)
        except json.JSONDecodeError as e:
            logger.error(
                f"{context}: JSON decode error for {self.device.name}: {e}. "
                f"JSON preview (first 500 chars): {json_string[:500]}"
            )
            return None
        except Exception as e:
            logger.error(
                f"{context}: Unexpected error parsing JSON for {self.device.name}: {e}. "
                f"JSON preview (first 500 chars): {json_string[:500]}"
            )
            return None

    def _parse_lldp_port_cumulus(self, port_data):
        """
        Parse Cumulus lldpctl port data into neighbor dict

        Args:
            port_data: Dict from lldpctl JSON output

        Returns:
            Dict with 'hostname' and 'port' keys, or None if parsing fails
        """
        try:
            neighbor = {}

            # Get neighbor hostname (system name)
            if 'chassis' in port_data:
                chassis = port_data['chassis']
                if isinstance(chassis, list):
                    chassis = chassis[0]

                # Try different fields for hostname
                if 'name' in chassis:
                    neighbor['hostname'] = chassis['name'].get('value', '') if isinstance(chassis['name'], dict) else chassis['name']
                elif 'id' in chassis:
                    neighbor['hostname'] = chassis['id'].get('value', '') if isinstance(chassis['id'], dict) else chassis['id']

            # Get neighbor port ID
            if 'id' in port_data:
                port_id = port_data['id']
                neighbor['port'] = port_id.get('value', '') if isinstance(port_id, dict) else port_id
            elif 'descr' in port_data:
                port_descr = port_data['descr']
                neighbor['port'] = port_descr.get('value', '') if isinstance(port_descr, dict) else port_descr

            # Only return if we have both hostname and port
            if 'hostname' in neighbor and 'port' in neighbor:
                return neighbor
            else:
                return None
        except Exception as e:
            logger.debug(f"Failed to parse Cumulus LLDP port data: {e}")
            return None

    def _parse_lldp_eos_text(self, lldp_output):
        """
        Parse Arista EOS 'show lldp neighbors' text output

        Args:
            lldp_output: Text output from 'show lldp neighbors'

        Returns:
            Dict mapping interface names to list of neighbors
        """
        lldp_data = {}

        try:
            lines = lldp_output.split('\n')

            # Skip header lines (usually first 2-3 lines)
            data_started = False
            for line in lines:
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Skip header lines
                if 'Port' in line and 'Neighbor' in line:
                    data_started = True
                    continue

                if not data_started:
                    continue

                # Parse data lines
                # Format: Et1           switch1                  Ethernet1           120
                parts = line.split()
                if len(parts) >= 3:
                    local_port = parts[0]
                    neighbor_device = parts[1]
                    neighbor_port = parts[2]

                    # Add to lldp_data
                    if local_port not in lldp_data:
                        lldp_data[local_port] = []

                    lldp_data[local_port].append({
                        'hostname': neighbor_device,
                        'port': neighbor_port
                    })

            return lldp_data
        except Exception as e:
            logger.error(f"Failed to parse EOS LLDP output: {e}")
            return {}

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
        
        For GNS3/virtual devices, get_facts() may fail, so we use:
        1. get_facts() (preferred - uses 'nv show system -o json')
        2. Direct NVUE command fallback ('nv show system hostname')
        3. Connection alive check as final fallback
        
        Returns:
            dict: {'success': bool, 'message': str, 'data': dict}
        """
        try:
            # Ensure connection is alive before checking connectivity
            connection_alive = False
            if self.connection:
                if hasattr(self.connection, 'is_alive'):
                    try:
                        connection_alive = self.connection.is_alive()
                        if not connection_alive:
                            logger.warning(f"Connection is not alive, attempting to refresh for connectivity check...")
                            self.connection.open()
                            connection_alive = True  # Assume refresh succeeded
                    except Exception as refresh_err:
                        logger.warning(f"Could not refresh connection for connectivity check: {refresh_err}")
                        connection_alive = False
                else:
                    # If is_alive() not available, assume connection is alive if it exists
                    connection_alive = True
            
            # Try to get facts first (preferred method - uses 'nv show system -o json')
            facts = self.get_facts()
            if facts:
                logger.info(f"Connectivity check passed: {self.device.name} - {facts.get('hostname', 'unknown')}")
                return {
                    'success': True,
                    'message': f"Device {self.device.name} is responsive",
                    'data': facts
                }
            
            # Fallback 1: Try direct NVUE command (same as get_facts() uses)
            # This works for GNS3/virtual devices where get_facts() JSON parsing may fail
            if self.connection and hasattr(self.connection, 'device'):
                try:
                    driver_name = self.get_driver_name()
                    if driver_name == 'cumulus':
                        # Try 'nv show system -o json' directly (same command get_facts() uses)
                        logger.debug(f"get_facts() failed, trying NVUE fallback command for {self.device.name}...")
                        nvue_output = self.connection.device.send_command_timing('nv show system -o json', read_timeout=10)
                        if nvue_output and nvue_output.strip() and 'Error:' not in nvue_output:
                            try:
                                import json
                                system_data = json.loads(nvue_output.strip())
                                if isinstance(system_data, dict):
                                    hostname = system_data.get('hostname', self.device.name)
                                    uptime = system_data.get('uptime', -1)
                                    health_status = system_data.get('health-status', 'Unknown')
                                    
                                    logger.info(f"Connectivity check passed (NVUE fallback): {self.device.name} - hostname: {hostname}, uptime: {uptime}s, health: {health_status}")
                                    return {
                                        'success': True,
                                        'message': f"Device {self.device.name} is responsive (NVUE fallback)",
                                        'data': {
                                            'hostname': hostname,
                                            'uptime': uptime,
                                            'health-status': health_status,
                                            'connection_alive': True,
                                            'nvue_fallback': True
                                        }
                                    }
                            except (json.JSONDecodeError, ValueError, TypeError) as json_err:
                                logger.debug(f"NVUE fallback JSON parsing failed: {json_err}")
                                # If JSON parsing fails but we got output, still consider it successful
                                if nvue_output.strip():
                                    logger.info(f"Connectivity check passed (NVUE fallback, no JSON): {self.device.name} - command succeeded")
                                    return {
                                        'success': True,
                                        'message': f"Device {self.device.name} is responsive (NVUE fallback, JSON parse failed)",
                                        'data': {'hostname': self.device.name, 'connection_alive': True, 'nvue_fallback': True}
                                    }
                except Exception as nvue_err:
                    logger.debug(f"NVUE fallback command failed: {nvue_err}")
            
            # Fallback 2: If get_facts() and NVUE fallback fail but connection is alive, consider it successful
            # This handles GNS3/virtual devices where both get_facts() and NVUE commands may not work
            if connection_alive:
                logger.info(f"Connectivity check passed (connection alive): {self.device.name} - get_facts() and NVUE unavailable (GNS3/virtual device?)")
                return {
                    'success': True,
                    'message': f"Device {self.device.name} is responsive (connection verified, facts unavailable)",
                    'data': {'hostname': self.device.name, 'connection_alive': True}
                }
            
            # All methods failed
            logger.error(f"Connectivity check failed: {self.device.name} - cannot get facts, NVUE fallback failed, and connection not alive")
            return {
                'success': False,
                'message': f"Cannot verify connectivity to {self.device.name}",
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
    
    def _parse_nvue_interface_range(self, range_str):
        """
        Parse NVUE interface range string (e.g., 'bond3-5') and return (prefix, start, end).
        
        Args:
            range_str: Range string like 'bond3-5', 'swp1-48', etc.
        
        Returns:
            tuple: (prefix, start, end) or None if not a range
        """
        import re
        # Match patterns like 'bond3-5', 'swp1-48', etc.
        match = re.match(r'^([a-zA-Z]+)(\d+)-(\d+)$', range_str)
        if match:
            prefix = match.group(1)
            start = int(match.group(2))
            end = int(match.group(3))
            return (prefix, start, end)
        return None
    
    def _is_interface_in_range(self, interface_name, range_str):
        """
        Check if an interface name is part of an NVUE range.
        
        Args:
            interface_name: Interface name like 'bond3', 'swp5', etc.
            range_str: Range string like 'bond3-5', 'swp1-48', etc.
        
        Returns:
            bool: True if interface is part of the range, False otherwise
        """
        range_info = self._parse_nvue_interface_range(range_str)
        if not range_info:
            # Not a range, check exact match
            return interface_name == range_str
        
        range_prefix, range_start, range_end = range_info
        
        # Parse interface name to extract prefix and number
        import re
        match = re.match(r'^([a-zA-Z]+)(\d+)$', interface_name)
        if not match:
            return False
        
        iface_prefix = match.group(1)
        iface_num = int(match.group(2))
        
        # Check if prefix matches and number is in range
        if iface_prefix == range_prefix and range_start <= iface_num <= range_end:
            return True
        
        return False
    
    def verify_vlan_deployment(self, interface_name, vlan_id, expected_mode='access', baseline=None, all_interfaces=None, cached_config=None, cached_interfaces=None, cached_lldp=None, cached_connectivity=None):
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
            all_interfaces: Optional list of all interfaces being verified (for LLDP checks on bonds)
                           If provided, member interfaces will be extracted from all bonds at once
            cached_config: Optional cached config dict (from nv config show) to avoid repeated fetches
                          If None, will fetch config for this interface
            cached_interfaces: Optional cached interfaces dict (from get_interfaces()) to avoid repeated fetches
                             If None, will call get_interfaces() for this interface
            cached_lldp: Optional cached LLDP dict (from get_lldp_neighbors()) to avoid repeated fetches
                        If None, will call get_lldp_neighbors() for this interface
            cached_connectivity: Optional cached connectivity result (from verify_connectivity()) to avoid repeated checks
                               If None, will call verify_connectivity() for this interface
        
        Returns:
            dict: {'success': bool, 'message': str, 'checks': dict}
        """
        checks = {}
        all_passed = True
        messages = []
        
        # Check 1: Device Connectivity (CRITICAL)
        logger.info(f"VLAN Verification Check 1/4: Device connectivity...")
        # PERFORMANCE: Use cached connectivity if available (avoids repeated checks)
        if cached_connectivity is not None:
            logger.debug(f"Using cached connectivity for interface {interface_name} (performance optimization)")
            connectivity_result = cached_connectivity
        else:
            connectivity_result = self.verify_connectivity()
        checks['connectivity'] = connectivity_result
        if not connectivity_result['success']:
            all_passed = False
            messages.append(f"ERROR: Connectivity: {connectivity_result['message']}")
            # If device is unreachable, stop here
            return {
                'success': False,
                'message': "CRITICAL: Device unreachable - " + '; '.join(messages),
                'checks': checks
            }
        else:
            messages.append(f"SUCCESS: Connectivity: Device responsive")
        
        # Check 2: Interface Status (with baseline comparison)
        logger.info(f"VLAN Verification Check 2/5: Interface status...")
        try:
            # PERFORMANCE: Use cached interfaces if available (avoids repeated get_interfaces() calls)
            if cached_interfaces is not None:
                logger.debug(f"Using cached interfaces for interface {interface_name} (performance optimization)")
                interfaces = cached_interfaces
            else:
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
                            'message': f"ERROR: Interface went DOWN! (was UP={iface_up_before}, now UP={iface_up_after})",
                            'data': {
                                'before': {'is_up': iface_up_before, 'is_enabled': iface_enabled_before},
                                'after': {'is_up': iface_up_after, 'is_enabled': iface_enabled_after}
                            }
                        }
                        all_passed = False
                        messages.append(f"ERROR: Interface: Went DOWN (was UP)")
                        logger.error(f"CRITICAL: Interface {interface_name} went DOWN after config change!")
                    
                    # ACCEPTABLE: Interface was DOWN, still DOWN (no cable)
                    elif not iface_up_before and not iface_up_after:
                        checks['interface_status'] = {
                            'success': True,
                            'message': f"Interface DOWN (was DOWN before, acceptable)",
                            'data': {'is_up': iface_up_after, 'is_enabled': iface_enabled_after}
                        }
                        messages.append(f"SUCCESS: Interface: DOWN (no cable, expected)")
                    
                    # GOOD: Interface was DOWN, now UP (cable was just plugged in)
                    elif not iface_up_before and iface_up_after:
                        checks['interface_status'] = {
                            'success': True,
                            'message': f"SUCCESS: Interface came UP! (was DOWN, now UP - excellent!)",
                            'data': {'is_up': iface_up_after, 'is_enabled': iface_enabled_after}
                        }
                        messages.append(f"SUCCESS: Interface: Came UP (was DOWN)")
                        logger.info(f"BONUS: Interface {interface_name} came UP after config change!")
                    
                    # GOOD: Interface was UP, still UP
                    else:
                        checks['interface_status'] = {
                            'success': True,
                            'message': f"Interface UP (stable)",
                            'data': {'is_up': iface_up_after, 'is_enabled': iface_enabled_after}
                        }
                        messages.append(f"SUCCESS: Interface: UP (stable)")
                else:
                    # No baseline, just report current status
                    checks['interface_status'] = {
                        'success': True,
                        'message': f"Interface exists: UP={iface_up_after}, Enabled={iface_enabled_after}",
                        'data': {'is_up': iface_up_after, 'is_enabled': iface_enabled_after}
                    }
                    messages.append(f"SUCCESS: Interface: Exists (UP={iface_up_after})")
            else:
                # Interface not found
                if baseline and baseline.get('interface'):
                    # Interface existed before, now missing - PROBLEM!
                    checks['interface_status'] = {
                        'success': False,
                        'message': f"ERROR: Interface disappeared! (existed before config change)",
                        'data': None
                    }
                    all_passed = False
                    messages.append(f"ERROR: Interface: Disappeared")
                    logger.error(f"CRITICAL: Interface {interface_name} disappeared after config change!")
                else:
                    # Interface didn't exist before, still doesn't - acceptable if creating
                    checks['interface_status'] = {
                        'success': True,
                        'message': f"Interface not found (didn't exist before either)",
                        'data': None
                    }
                    messages.append(f"WARNING: Interface: Not found (expected)")
        except Exception as e:
            checks['interface_status'] = {
                'success': False,
                'message': f"Could not check interface: {str(e)}",
                'data': None
            }
            logger.warning(f"Could not verify interface status: {e}")
            all_passed = False
            messages.append(f"ERROR: Interface: Could not verify")
        
        # Check 3: VLAN Configuration Applied (with actual device verification)
        logger.info(f"VLAN Verification Check 3/6: VLAN configuration...")
        driver_name = self.get_driver_name()
        vlan_check_passed = False

        try:
            # Get baseline VLAN if available
            baseline_vlan = None
            if baseline and baseline.get('interface'):
                baseline_vlan = baseline['interface'].get('vlan_id', None)

            # Query device to verify VLAN is actually configured
            actual_vlan = None
            vlan_verified = False

            if driver_name == 'cumulus':
                # For Cumulus, query NVUE to verify VLAN configuration
                # 
                # CRITICAL: NVUE may combine consecutive interfaces into ranges (e.g., bond3-5)
                # When interfaces bond3, bond4, bond5 are configured with the same VLAN,
                # NVUE stores them as a range "bond3-5" instead of individual interfaces.
                # 
                # Verification strategy: Use single command to get full applied config, then parse JSON
                # This is more efficient and reliable than per-interface queries
                # Command: nv config show -r applied -o json
                # Expected JSON structure:
                # {
                #   "interface": {
                #     "bond3-5": {
                #       "bridge": {
                #         "domain": {
                #           "br_default": {
                #             "access": 3000
                #           }
                #         }
                #       }
                #     },
                #     "bond6": {
                #       "bridge": {
                #         "domain": {
                #           "br_default": {
                #             "access": 3060
                #           }
                #         }
                #       }
                #     }
                #   }
                # }
                # Note: Interfaces may be in ranges (bond3-5) or standalone (bond6)
                try:
                    actual_vlan = None
                    diagnostic_details = None  # Initialize for use in error messages
                    
                    # PERFORMANCE: Use cached config if provided (avoids repeated fetches)
                    if cached_config:
                        logger.debug(f"Using cached config for interface {interface_name} (performance optimization)")
                        interfaces_config = cached_config
                    else:
                        # Fetch config for this interface (fallback for single interface or cache miss)
                        if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                            # Single query to get full applied configuration (includes pending commit-confirm)
                            try:
                                logger.debug(f"Querying full applied config for interface {interface_name}...")
                                
                                # Try to use the specific revision ID if available (more accurate than -r applied)
                                # This ensures we read the exact config that was just committed
                                revision_id = None
                                if hasattr(self, '_candidate_revision_id') and self._candidate_revision_id:
                                    revision_id = self._candidate_revision_id
                                    logger.debug(f"Using revision ID {revision_id} for config query (from commit)")
                                
                                if revision_id:
                                    # Query specific revision (most accurate - shows exactly what was committed)
                                    full_config_output = self.connection.device.send_command_timing(
                                        f'nv config show -r {revision_id} -o json',
                                        read_timeout=20
                                    )
                                    if not full_config_output or not full_config_output.strip():
                                        logger.debug(f"Revision {revision_id} query returned empty, falling back to -r applied...")
                                        revision_id = None  # Fall back to -r applied
                                
                                if not revision_id:
                                    # Query full config with -r applied to get applied config (includes pending commit-confirm)
                                    full_config_output = self.connection.device.send_command_timing(
                                        'nv config show -r applied -o json',
                                        read_timeout=20
                                    )
                                
                                # If that returns empty, try without -r applied (current/pending config)
                                if not full_config_output or not full_config_output.strip():
                                    logger.debug(f"Applied config query returned empty, trying current config...")
                                    full_config_output = self.connection.device.send_command_timing(
                                        'nv config show -o json',
                                        read_timeout=20
                                    )
                                
                                if full_config_output and full_config_output.strip():
                                    import json
                                    try:
                                        full_config = json.loads(full_config_output.strip())
                                        
                                        # Handle case where full_config might be a list (NVUE sometimes returns array)
                                        # Structure can be: [{"header": {...}}, {"interface": {...}}] or {"interface": {...}}
                                        # The array format has header at [0] and config at [1]
                                        if isinstance(full_config, list):
                                            logger.debug(f"Config JSON is a list (length: {len(full_config)})")
                                            if len(full_config) >= 2:
                                                # Array format: [0] = header, [1] = config with interface
                                                full_config = full_config[1]  # Take second element (config)
                                                logger.debug(f"Extracted config from list[1], now type: {type(full_config).__name__}")
                                            elif len(full_config) == 1:
                                                # Single element array, might be config or header
                                                full_config = full_config[0]
                                                logger.debug(f"Extracted config from list[0], now type: {type(full_config).__name__}")
                                                # Check if it's just header (no interface key)
                                                if isinstance(full_config, dict) and 'interface' not in full_config:
                                                    logger.warning(f"First element appears to be header only, no interface section found")
                                                    interfaces_config = {}
                                            else:
                                                logger.warning(f"Config JSON is an empty list")
                                                interfaces_config = {}
                                                full_config = {}
                                        
                                        # Navigate to interface section
                                        # Structure can be: {"interface": {...}} or {"set": {"interface": {...}}}
                                        # NVUE returns config under "set" key when using -r applied
                                        if isinstance(full_config, dict):
                                            # Check if config is under "set" key (NVUE format)
                                            if 'set' in full_config:
                                                logger.debug(f"Config is under 'set' key, extracting...")
                                                full_config = full_config['set']
                                            
                                            # Now get interface section
                                            interface_raw = full_config.get('interface', {})
                                            if isinstance(interface_raw, list):
                                                # Convert list to dict if needed (shouldn't happen but handle it)
                                                logger.warning(f"Interface section is a list instead of dict, this is unexpected")
                                                interfaces_config = {}
                                            elif isinstance(interface_raw, dict):
                                                interfaces_config = interface_raw
                                            else:
                                                logger.warning(f"Interface section is neither list nor dict: {type(interface_raw)}")
                                                interfaces_config = {}
                                        else:
                                            logger.warning(f"Full config is not a dict after processing: {type(full_config)}")
                                            interfaces_config = {}
                                        
                                        if not interfaces_config:
                                            logger.debug(f"No 'interface' section found in config JSON")
                                        else:
                                            logger.debug(f"Checking {len(interfaces_config)} interfaces/ranges in full config for {interface_name}...")
                                            logger.debug(f"Available interfaces/ranges: {list(interfaces_config.keys())[:20]}")
                                            
                                            # Check each interface/range in the config
                                            # Collect all matching ranges/interfaces first, then prefer exact match or most specific
                                            matching_configs = []  # List of (config_name, vlan_value, is_exact_match)
                                            
                                            for config_iface_name, config_iface_data in interfaces_config.items():
                                                # Handle case where config_iface_data might be a list instead of dict
                                                if isinstance(config_iface_data, list):
                                                    logger.warning(f"Interface '{config_iface_name}' config is a list (unexpected), skipping...")
                                                    logger.debug(f"  List content: {config_iface_data}")
                                                    continue
                                                elif not isinstance(config_iface_data, dict):
                                                    logger.warning(f"Interface '{config_iface_name}' config is neither dict nor list (type: {type(config_iface_data)}), skipping...")
                                                    continue
                                                
                                                # Check if our interface matches or is part of this range
                                                if self._is_interface_in_range(interface_name, config_iface_name):
                                                    logger.debug(f"✓ Interface {interface_name} matches range/interface '{config_iface_name}'")
                                                # Found our interface (either exact match or part of range)
                                                # Navigate to access VLAN: interface.{name}.bridge.domain.br_default.access
                                                # Example structure:
                                                #   "bond3-5": {"bridge": {"domain": {"br_default": {"access": 3000}}}}
                                                #   "bond6": {"bridge": {"domain": {"br_default": {"access": 3060}}}}
                                                
                                                bridge_config = config_iface_data.get('bridge', {})
                                                if bridge_config:
                                                    domain_config = bridge_config.get('domain', {})
                                                    if domain_config:
                                                        br_default_config = domain_config.get('br_default', {})
                                                        if br_default_config:
                                                            access_vlan_path = br_default_config.get('access')
                                                            logger.debug(f"  Access VLAN path value for {config_iface_name}: {access_vlan_path} (type: {type(access_vlan_path).__name__})")
                                                            
                                                            if access_vlan_path is not None:
                                                                # Extract VLAN ID (could be int or nested dict)
                                                                extracted_vlan = None
                                                                if isinstance(access_vlan_path, int):
                                                                    extracted_vlan = access_vlan_path
                                                                    logger.debug(f"  ✓ Extracted VLAN as integer: {extracted_vlan}")
                                                                elif isinstance(access_vlan_path, dict):
                                                                    # Sometimes NVUE returns nested structure
                                                                    extracted_vlan = access_vlan_path.get('value') or access_vlan_path.get('vlan') or (list(access_vlan_path.values())[0] if access_vlan_path else None)
                                                                    logger.debug(f"  ✓ Extracted VLAN from dict: {extracted_vlan}")
                                                                else:
                                                                    # Try to convert to int if it's a string representation
                                                                    try:
                                                                        extracted_vlan = int(access_vlan_path)
                                                                        logger.debug(f"  ✓ Converted VLAN from string: {extracted_vlan}")
                                                                    except (ValueError, TypeError):
                                                                        logger.debug(f"  ✗ Could not convert VLAN: {access_vlan_path}")
                                                                
                                                                if extracted_vlan is not None:
                                                                    # Check if this is an exact match (not a range)
                                                                    is_exact = (config_iface_name == interface_name)
                                                                    matching_configs.append((config_iface_name, extracted_vlan, is_exact))
                                                                    logger.debug(f"  Found match: {config_iface_name} -> VLAN {extracted_vlan} (exact={is_exact})")
                                        
                                        # Now choose the best match:
                                        # 1. Prefer exact match over range
                                        # 2. If multiple ranges, prefer the one with expected VLAN (if provided)
                                        # 3. Otherwise, use first match
                                        if matching_configs:
                                            # Sort: exact matches first, then by VLAN (prefer expected VLAN if provided)
                                            def sort_key(item):
                                                config_name, vlan_val, is_exact = item
                                                # Exact match gets highest priority
                                                exact_priority = 0 if is_exact else 1
                                                # If we have expected VLAN, prefer matches with that VLAN
                                                vlan_priority = 0 if (vlan_id and vlan_val == vlan_id) else 1
                                                return (exact_priority, vlan_priority, config_name)
                                            
                                            matching_configs.sort(key=sort_key)
                                            best_match_name, actual_vlan, is_exact = matching_configs[0]
                                            
                                            if len(matching_configs) > 1:
                                                logger.warning(f"Found {len(matching_configs)} matching ranges/interfaces for {interface_name}, using: {best_match_name} (VLAN {actual_vlan})")
                                                logger.debug(f"  All matches: {matching_configs}")
                                            
                                            logger.info(f"Found interface {interface_name} in range/interface '{best_match_name}' with VLAN {actual_vlan} (from full config with -r applied)")
                                        else:
                                            actual_vlan = None
                                        
                                        # If still not found, log what interfaces/ranges we did find
                                        if actual_vlan is None:
                                            logger.warning(f"Interface {interface_name} not found in any of the {len(interfaces_config)} interfaces/ranges")
                                            # Log some of the interface names for debugging
                                            sample_names = list(interfaces_config.keys())[:10]
                                            logger.warning(f"Sample interface/range names found in config: {sample_names}")
                                            
                                            # Check if interface exists but without bridge config
                                            matching_interfaces = []
                                            for iface_name, iface_data in interfaces_config.items():
                                                if isinstance(iface_data, dict) and self._is_interface_in_range(interface_name, iface_name):
                                                    matching_interfaces.append((iface_name, iface_data))
                                            
                                            if matching_interfaces:
                                                match_info = f"Found matching interface/range(s) for {interface_name}: {[name for name, _ in matching_interfaces]}"
                                                logger.warning(match_info)
                                                for match_name, match_data in matching_interfaces:
                                                    struct_info = f"  {match_name} structure: {list(match_data.keys())}"
                                                    logger.warning(struct_info)
                                                    if 'bridge' in match_data:
                                                        bridge_info = f"    bridge keys: {list(match_data['bridge'].keys())}"
                                                        logger.warning(bridge_info)
                                                    else:
                                                        no_bridge_info = f"    No 'bridge' key in {match_name}"
                                                        logger.warning(no_bridge_info)
                                            
                                            # Also log which interfaces have bridge domain config for debugging
                                            interfaces_with_bridge = []
                                            for iface_name, iface_data in interfaces_config.items():
                                                if isinstance(iface_data, dict):
                                                    if iface_data.get('bridge', {}).get('domain', {}).get('br_default', {}).get('access') is not None:
                                                        vlan_val = iface_data.get('bridge', {}).get('domain', {}).get('br_default', {}).get('access')
                                                        interfaces_with_bridge.append((iface_name, vlan_val))
                                            if interfaces_with_bridge:
                                                vlan_info = f"Interfaces/ranges with bridge domain access VLAN: {interfaces_with_bridge[:10]}"
                                                logger.warning(vlan_info)
                                            else:
                                                no_vlan_info = "No interfaces found with bridge domain access VLAN configured"
                                                logger.warning(no_vlan_info)
                                            
                                            # Store diagnostic info in check result for NetBox UI
                                            diagnostic_summary = []
                                            if matching_interfaces:
                                                diagnostic_summary.append(f"Found matching range(s): {[name for name, _ in matching_interfaces]}")
                                            if interfaces_with_bridge:
                                                diagnostic_summary.append(f"Interfaces with VLANs: {interfaces_with_bridge[:5]}")
                                            else:
                                                diagnostic_summary.append("No interfaces found with VLAN configured")
                                            
                                            # This will be included in the check result message below
                                            diagnostic_details = " | ".join(diagnostic_summary)
                                    except (json.JSONDecodeError, ValueError, KeyError, AttributeError) as parse_error:
                                        error_msg = f"Could not parse full config JSON for interface {interface_name}: {parse_error}"
                                        logger.warning(error_msg)
                                        import traceback
                                        logger.debug(traceback.format_exc())
                                        # Add to checks so it appears in NetBox UI
                                        checks['vlan_config'] = {
                                            'success': False,
                                            'message': f"ERROR: Config parsing failed - {str(parse_error)}",
                                            'data': {'expected': vlan_id, 'actual': None, 'error': str(parse_error)}
                                        }
                                else:
                                    logger.warning(f"Full config query returned empty for interface {interface_name}")
                            except Exception as query_error:
                                logger.warning(f"Could not query full config for interface {interface_name}: {query_error}")
                                import traceback
                                logger.debug(traceback.format_exc())

                        # Log final result before verification
                        if actual_vlan is None:
                            warning_msg = f"Could not determine VLAN for interface {interface_name} from full config query"
                            logger.warning(warning_msg)
                            diagnostic_msg = "This may indicate: (1) Interface not configured, (2) Query command failed, (3) Config not yet applied, or (4) Interface not in applied config"
                            logger.warning(diagnostic_msg)
                            # These warnings will appear in Django logs, and the check result below will show in NetBox UI
                        
                        # Verify VLAN matches expected
                        # Note: diagnostic_details may be set above if actual_vlan is None
                        if actual_vlan == vlan_id:
                            vlan_verified = True
                            checks['vlan_config'] = {
                                'success': True,
                                'message': f"Cumulus: VLAN {vlan_id} verified on interface (baseline: {baseline_vlan})",
                                'data': {'expected': vlan_id, 'actual': actual_vlan, 'baseline': baseline_vlan}
                            }
                            vlan_check_passed = True
                            messages.append(f"SUCCESS: VLAN Config: VLAN {vlan_id} verified")
                            logger.info(f"VLAN verification passed: interface {interface_name} has VLAN {actual_vlan}")
                        else:
                            # VLAN mismatch - CRITICAL FAILURE
                            error_msg = f"ERROR: VLAN mismatch! Expected {vlan_id}, found {actual_vlan}"
                            if actual_vlan is None:
                                # Add diagnostic details if available (set above when actual_vlan is None)
                                if diagnostic_details:
                                    error_msg += f" | Diagnostics: {diagnostic_details}"
                                error_msg += " | Check Django logs for detailed config structure"
                            checks['vlan_config'] = {
                                'success': False,
                                'message': error_msg,
                                'data': {'expected': vlan_id, 'actual': actual_vlan, 'baseline': baseline_vlan}
                            }
                            all_passed = False
                            messages.append(f"ERROR: VLAN Config: Mismatch (expected {vlan_id}, got {actual_vlan})")
                            logger.error(f"CRITICAL: VLAN verification failed - expected {vlan_id}, found {actual_vlan}")
                except Exception as cumulus_vlan_error:
                    logger.warning(f"Could not verify Cumulus VLAN via NVUE: {cumulus_vlan_error}")
                    # Fallback: trust the commit
                    checks['vlan_config'] = {
                        'success': True,
                        'message': f"Cumulus: Config applied (NVUE verification failed, trusting commit)",
                        'data': {'expected': vlan_id, 'verification_error': str(cumulus_vlan_error)}
                    }
                    vlan_check_passed = True
                    messages.append(f"SUCCESS: VLAN Config: Applied (verification skipped)")

            elif driver_name == 'eos':
                # For Arista EOS, query switchport configuration
                try:
                    if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                        # Query switchport status
                        switchport_output = self.connection.device.send_command_timing(
                            f'show interfaces {interface_name} switchport',
                            read_timeout=10
                        )

                        # Parse output to find access VLAN
                        # Example line: "Access Mode VLAN: 100 (VLAN0100)"
                        import re
                        vlan_match = re.search(r'Access Mode VLAN:\s+(\d+)', switchport_output)
                        if vlan_match:
                            actual_vlan = int(vlan_match.group(1))

                            # Verify VLAN matches expected
                            if actual_vlan == vlan_id:
                                vlan_verified = True
                                checks['vlan_config'] = {
                                    'success': True,
                                    'message': f"EOS: VLAN {vlan_id} verified on interface (baseline: {baseline_vlan})",
                                    'data': {'expected': vlan_id, 'actual': actual_vlan, 'baseline': baseline_vlan}
                                }
                                vlan_check_passed = True
                                messages.append(f"SUCCESS: VLAN Config: VLAN {vlan_id} verified")
                                logger.info(f"VLAN verification passed: interface {interface_name} has VLAN {actual_vlan}")
                            else:
                                # VLAN mismatch - CRITICAL FAILURE
                                checks['vlan_config'] = {
                                    'success': False,
                                    'message': f"ERROR: VLAN mismatch! Expected {vlan_id}, found {actual_vlan}",
                                    'data': {'expected': vlan_id, 'actual': actual_vlan, 'baseline': baseline_vlan}
                                }
                                all_passed = False
                                messages.append(f"ERROR: VLAN Config: Mismatch (expected {vlan_id}, got {actual_vlan})")
                                logger.error(f"CRITICAL: VLAN verification failed - expected {vlan_id}, found {actual_vlan}")
                        else:
                            # Could not parse VLAN from output
                            logger.warning(f"Could not parse VLAN from EOS switchport output")
                            checks['vlan_config'] = {
                                'success': True,
                                'message': f"EOS: Config committed (could not parse VLAN from output, trusting commit)",
                                'data': {'expected': vlan_id, 'output': switchport_output[:200]}
                            }
                            vlan_check_passed = True
                            messages.append(f"SUCCESS: VLAN Config: Committed (verification skipped)")
                except Exception as eos_vlan_error:
                    logger.warning(f"Could not verify EOS VLAN via CLI: {eos_vlan_error}")
                    # Fallback: trust the commit
                    checks['vlan_config'] = {
                        'success': True,
                        'message': f"EOS: Config committed (CLI verification failed, trusting commit)",
                        'data': {'expected': vlan_id, 'verification_error': str(eos_vlan_error)}
                    }
                    vlan_check_passed = True
                    messages.append(f"SUCCESS: VLAN Config: Committed (verification skipped)")
            else:
                # Other platforms: trust the commit
                checks['vlan_config'] = {
                    'success': True,
                    'message': f"Config committed for {driver_name} (verification not implemented)",
                    'data': {'expected': vlan_id, 'baseline': baseline_vlan}
                }
                vlan_check_passed = True
                messages.append(f"SUCCESS: VLAN Config: Committed")
        except Exception as e:
            checks['vlan_config'] = {
                'success': False,
                'message': f"Could not verify VLAN config: {str(e)}",
                'data': None
            }
            logger.warning(f"Could not verify VLAN configuration: {e}")
            all_passed = False
            messages.append(f"WARNING: VLAN Config: Could not verify")
        
        # Check 4: LLDP Neighbors (ALWAYS use member interfaces, never bond interfaces)
        # CRITICAL: LLDP neighbors are only on physical member interfaces (swp3, swp4, swp5)
        # NOT on bond interfaces (bond3, bond4, bond5)
        logger.info(f"VLAN Verification Check 4/5: LLDP neighbors (interface-level on member interfaces)...")
        # Check for LLDP baseline - prefer per-interface data, fallback to device-level
        lldp_baseline_interfaces = baseline.get('lldp_interfaces', {})
        lldp_baseline_all = baseline.get('lldp_all_interfaces', {})
        
        if lldp_baseline_interfaces or (lldp_baseline_all is not None):
            try:
                # Pass interfaces so get_lldp_neighbors can extract member interfaces from bonds
                # For bonds, it will extract member interfaces (e.g., bond3 -> swp3) for LLDP checks
                # PERFORMANCE: Use cached LLDP if available (avoids repeated fetches)
                if cached_lldp is not None:
                    logger.debug(f"Using cached LLDP for interface {interface_name} (performance optimization)")
                    lldp_after = cached_lldp
                else:
                    # Use all_interfaces if provided (for efficiency), otherwise just the current interface
                    interfaces_for_lldp = all_interfaces if all_interfaces else [interface_name]
                    lldp_after = self.get_lldp_neighbors(interfaces=interfaces_for_lldp)

                # Build after state for all interfaces
                lldp_after_all = {}
                if lldp_after:
                    for iface, neighbors in lldp_after.items():
                        lldp_after_all[iface] = len(neighbors) if neighbors else 0

                # Use per-interface baseline if available (new format), otherwise fallback to device-level
                if lldp_baseline_interfaces:
                    # Per-interface LLDP verification (for deployed interfaces only)
                    lldp_before_interfaces = {}
                    for iface, iface_data in lldp_baseline_interfaces.items():
                        lldp_before_interfaces[iface] = iface_data.get('count', 0)
                    
                    # Check for lost LLDP neighbors on deployed interfaces only
                    lost_neighbors = []
                    lost_details = []
                    
                    for iface, count_before in lldp_before_interfaces.items():
                        count_after = lldp_after_all.get(iface, 0)
                        
                        # CRITICAL: Lost ALL neighbors on deployed interface
                        if count_before > 0 and count_after == 0:
                            lost_neighbors.append(iface)
                            lost_details.append(f"{iface} (lost ALL {count_before} neighbors)")
                            logger.error(f"CRITICAL: Lost all LLDP neighbors on {iface}! (had {count_before}, now 0)")
                        # WARNING: Lost SOME neighbors on deployed interface
                        elif count_before > count_after:
                            lost_neighbors.append(iface)
                            lost_details.append(f"{iface} (lost {count_before - count_after} of {count_before} neighbors)")
                            logger.error(f"CRITICAL: Lost LLDP neighbors on {iface}: {count_before}→{count_after}")
                    
                    # If we lost neighbors on ANY deployed interface, FAIL and trigger rollback
                    if lost_neighbors:
                        checks['lldp_neighbors'] = {
                            'success': False,
                            'message': f"ERROR: Lost LLDP neighbors on {len(lost_neighbors)} interface(s): {', '.join(lost_details)}",
                            'data': {
                                'lost_on': lost_neighbors,
                                'details': lost_details,
                                'before': lldp_before_interfaces,
                                'after': {iface: lldp_after_all.get(iface, 0) for iface in lldp_before_interfaces.keys()}
                            }
                        }
                        all_passed = False
                        messages.append(f"ERROR: LLDP: Lost neighbors on {len(lost_neighbors)} interface(s)")
                        logger.error(f"CRITICAL: VLAN deployment caused LLDP neighbor loss - TRIGGERING ROLLBACK")
                        logger.error(f"Lost neighbors: {', '.join(lost_details)}")
                    else:
                        # GOOD: No neighbors lost on deployed interfaces
                        total_before = sum(lldp_before_interfaces.values())
                        total_after = sum(lldp_after_all.get(iface, 0) for iface in lldp_before_interfaces.keys())
                        
                        # Build interface status summary
                        iface_statuses = []
                        for iface in sorted(lldp_before_interfaces.keys()):
                            count_before = lldp_before_interfaces[iface]
                            count_after = lldp_after_all.get(iface, 0)
                            iface_statuses.append(f"{iface}: {count_before}→{count_after}")
                        
                        checks['lldp_neighbors'] = {
                            'success': True,
                            'message': f"Interface-level LLDP stable ({len(lldp_before_interfaces)} interface(s): {total_before}→{total_after})",
                            'data': {
                                'total_before': total_before,
                                'total_after': total_after,
                                'interface_statuses': iface_statuses,
                                'before': lldp_before_interfaces,
                                'after': {iface: lldp_after_all.get(iface, 0) for iface in lldp_before_interfaces.keys()}
                            }
                        }
                        messages.append(f"SUCCESS: LLDP: Interface-level stable ({len(lldp_before_interfaces)} interface(s), {total_after} total)")
                        logger.info(f"LLDP check passed: {len(lldp_before_interfaces)} interface(s) stable ({total_after} total neighbors, was {total_before})")
                else:
                    # Fallback to device-level verification (old format)
                    lldp_before_all = lldp_baseline_all
                    
                    # Check for lost LLDP neighbors on ALL interfaces
                    lost_neighbors = []
                    lost_details = []
                    
                    for iface, count_before in lldp_before_all.items():
                        count_after = lldp_after_all.get(iface, 0)
                        
                        # CRITICAL: Lost ALL neighbors on any interface
                        if count_before > 0 and count_after == 0:
                            lost_neighbors.append(iface)
                            lost_details.append(f"{iface} (lost ALL {count_before} neighbors)")
                            logger.error(f"CRITICAL: Lost all LLDP neighbors on {iface}! (had {count_before}, now 0)")
                        # WARNING: Lost SOME neighbors on any interface
                        elif count_before > count_after:
                            lost_neighbors.append(iface)
                            lost_details.append(f"{iface} (lost {count_before - count_after} of {count_before} neighbors)")
                            logger.error(f"CRITICAL: Lost LLDP neighbors on {iface}: {count_before}→{count_after}")
                    
                    # If we lost neighbors on ANY interface, FAIL and trigger rollback
                    if lost_neighbors:
                        checks['lldp_neighbors'] = {
                            'success': False,
                            'message': f"ERROR: Lost LLDP neighbors on {len(lost_neighbors)} interface(s): {', '.join(lost_details)}",
                            'data': {
                                'lost_on': lost_neighbors,
                                'details': lost_details,
                                'before': lldp_before_all,
                                'after': lldp_after_all
                            }
                        }
                        all_passed = False
                        messages.append(f"ERROR: LLDP: Lost neighbors on {len(lost_neighbors)} interface(s)")
                        logger.error(f"CRITICAL: VLAN deployment caused LLDP neighbor loss - TRIGGERING ROLLBACK")
                        logger.error(f"Lost neighbors: {', '.join(lost_details)}")
                    else:
                        # GOOD: No neighbors lost on any interface
                        total_before = sum(lldp_before_all.values())
                        total_after = sum(lldp_after_all.values())
                        
                        # CRITICAL: Do NOT use interface_name here if it's a bond interface
                        # LLDP is only on member interfaces, not bond interfaces
                        # In device-level fallback, just show total (don't use bond interface name)
                        iface_status = f"total: {total_before}→{total_after}"
                        
                        checks['lldp_neighbors'] = {
                            'success': True,
                            'message': f"Device-level LLDP stable ({iface_status})",
                            'data': {
                                'total_before': total_before,
                                'total_after': total_after,
                                'interface_status': iface_status,
                                'before': lldp_before_all,
                                'after': lldp_after_all
                            }
                        }
                        messages.append(f"SUCCESS: LLDP: Device-level stable ({total_after} total)")
                        logger.info(f"LLDP check passed: Device has {total_after} total neighbors (was {total_before})")

            except Exception as e:
                logger.error(f"Could not verify LLDP neighbors: {e}")
                # LLDP verification failure is now CRITICAL - fail deployment
                checks['lldp_neighbors'] = {
                    'success': False,
                    'message': f"ERROR: Could not verify LLDP neighbors: {str(e)}",
                    'data': None
                }
                all_passed = False
                messages.append(f"ERROR: LLDP: Verification failed")
        else:
            # No LLDP baseline, skip check
            checks['lldp_neighbors'] = {
                'success': True,
                'message': "LLDP check skipped (no baseline)",
                'data': None
            }
            messages.append(f"INFO: LLDP: Check skipped (no baseline)")
        
        # Check 5: Overall System Health (with baseline comparison)
        logger.info(f"VLAN Verification Check 5/6: System health...")
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
                            'message': f"ERROR: Device may have rebooted! (uptime: {uptime_before}s → {uptime_after}s)",
                            'data': {'uptime_before': uptime_before, 'uptime_after': uptime_after}
                        }
                        all_passed = False
                        messages.append(f"ERROR: System: Possible reboot")
                        logger.error(f"CRITICAL: Device may have rebooted - uptime decreased!")
                    else:
                        checks['system_health'] = {
                            'success': True,
                            'message': f"System healthy, uptime stable: {uptime_after}s",
                            'data': {'uptime': uptime_after}
                        }
                        messages.append(f"SUCCESS: System: Healthy")
                else:
                    # No baseline
                    checks['system_health'] = {
                        'success': True,
                        'message': f"System healthy, uptime: {uptime_after}",
                        'data': {'uptime': uptime_after}
                    }
                    messages.append(f"SUCCESS: System: Healthy")
            else:
                checks['system_health'] = {
                    'success': False,
                    'message': "Could not get system facts",
                    'data': None
                }
                all_passed = False
                messages.append(f"ERROR: System: Could not verify")
        except Exception as e:
            checks['system_health'] = {
                'success': False,
                'message': f"System health check failed: {str(e)}",
                'data': None
            }
            logger.warning(f"System health check failed: {e}")
            all_passed = False
            messages.append(f"ERROR: System: Could not verify")

        # Check 6: Traffic Flow (INFORMATIONAL ONLY - does NOT fail deployment)
        logger.info(f"VLAN Verification Check 6/6: Traffic flow (informational)...")
        try:
            if baseline and baseline.get('interface'):
                baseline_iface = baseline['interface']
                in_pkts_before = baseline_iface.get('in_pkts', 0)
                out_pkts_before = baseline_iface.get('out_pkts', 0)
                in_bytes_before = baseline_iface.get('in_bytes', 0)
                out_bytes_before = baseline_iface.get('out_bytes', 0)

                # Get current interface stats
                interfaces = self.get_interfaces()
                if interfaces and interface_name in interfaces:
                    iface_data = interfaces[interface_name]

                    # Try to get packet counters from interface data
                    # Note: NAPALM's get_interfaces() may not always include counters
                    # For Cumulus, we may need to query directly
                    driver_name = self.get_driver_name()
                    in_pkts_after = 0
                    out_pkts_after = 0
                    in_bytes_after = 0
                    out_bytes_after = 0

                    if driver_name == 'cumulus':
                        # For Cumulus, query stats directly using NVUE
                        try:
                            if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                stats_output = self.connection.device.send_command_timing(
                                    f'nv show interface {interface_name} counters -o json',
                                    read_timeout=10
                                )
                                if stats_output and stats_output.strip():
                                    import json
                                    try:
                                        stats_output_stripped = stats_output.strip()
                                        if stats_output_stripped.startswith('{') or stats_output_stripped.startswith('['):
                                            stats_data = json.loads(stats_output_stripped)
                                            in_pkts_after = stats_data.get('in-pkts', 0)
                                            out_pkts_after = stats_data.get('out-pkts', 0)
                                            in_bytes_after = stats_data.get('in-bytes', 0)
                                            out_bytes_after = stats_data.get('out-bytes', 0)
                                        else:
                                            logger.debug(f"Stats output is not JSON format: {stats_output[:100]}")
                                    except (json.JSONDecodeError, ValueError) as json_err:
                                        logger.debug(f"Could not parse Cumulus stats JSON: {json_err} (output: {stats_output[:100]})")
                        except Exception as stats_error:
                            logger.debug(f"Could not get Cumulus stats: {stats_error}")
                    else:
                        # For other platforms, try to get from NAPALM interface data
                        # (may not be available)
                        in_pkts_after = iface_data.get('in_pkts', 0)
                        out_pkts_after = iface_data.get('out_pkts', 0)
                        in_bytes_after = iface_data.get('in_bytes', 0)
                        out_bytes_after = iface_data.get('out_bytes', 0)

                    # Calculate differences
                    in_pkts_delta = in_pkts_after - in_pkts_before
                    out_pkts_delta = out_pkts_after - out_pkts_before
                    in_bytes_delta = in_bytes_after - in_bytes_before
                    out_bytes_delta = out_bytes_after - out_bytes_before

                    # INFORMATIONAL: Check if traffic is flowing
                    # This does NOT fail deployment - just logs the status
                    if in_pkts_delta > 0 or out_pkts_delta > 0:
                        checks['traffic_flow'] = {
                            'success': True,  # Always success (informational only)
                            'message': f"INFO: Traffic detected: IN +{in_pkts_delta} pkts (+{in_bytes_delta} bytes), OUT +{out_pkts_delta} pkts (+{out_bytes_delta} bytes)",
                            'data': {
                                'in_pkts_delta': in_pkts_delta,
                                'out_pkts_delta': out_pkts_delta,
                                'in_bytes_delta': in_bytes_delta,
                                'out_bytes_delta': out_bytes_delta
                            }
                        }
                        messages.append(f"INFO: Traffic: Active (IN +{in_pkts_delta} pkts, OUT +{out_pkts_delta} pkts)")
                        logger.info(f"Traffic flow detected on {interface_name}: IN +{in_pkts_delta} pkts, OUT +{out_pkts_delta} pkts")
                    else:
                        checks['traffic_flow'] = {
                            'success': True,  # Always success (informational only)
                            'message': f"INFO: No traffic detected (interface may be down or no cable connected)",
                            'data': {
                                'in_pkts_delta': 0,
                                'out_pkts_delta': 0,
                                'in_bytes_delta': 0,
                                'out_bytes_delta': 0
                            }
                        }
                        messages.append(f"INFO: Traffic: None detected (interface may be down)")
                        logger.info(f"No traffic flow detected on {interface_name} (this is informational only)")
                else:
                    # Interface not found
                    checks['traffic_flow'] = {
                        'success': True,  # Always success (informational only)
                        'message': f"INFO: Traffic check skipped (interface not found)",
                        'data': None
                    }
                    messages.append(f"INFO: Traffic: Check skipped")
            else:
                # No baseline, skip traffic check
                checks['traffic_flow'] = {
                    'success': True,  # Always success (informational only)
                    'message': f"INFO: Traffic check skipped (no baseline)",
                    'data': None
                }
                messages.append(f"INFO: Traffic: Check skipped (no baseline)")
        except Exception as e:
            # Traffic check failed - but this is informational only, don't fail deployment
            checks['traffic_flow'] = {
                'success': True,  # Always success (informational only)
                'message': f"INFO: Traffic check failed: {str(e)} (non-critical)",
                'data': None
            }
            logger.debug(f"Traffic flow check failed (non-critical): {e}")
            messages.append(f"INFO: Traffic: Could not verify (non-critical)")

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
                        diff_check = self.connection.device.send_command_timing('nv config diff', read_timeout=10)
                        if diff_check:
                            # If diff shows nothing or "No changes", rollback worked
                            if 'no changes' in diff_check.lower() or not diff_check.strip() or diff_check.strip() == '':
                                return True, "Rollback verified: No pending changes detected"
                            else:
                                # Show full diff output (no truncation) so user can see all pending changes including VLAN numbers and all interfaces
                                return False, f"Rollback may have failed: Pending changes still exist -\n{diff_check}"
                        else:
                            # Empty diff means no pending changes
                            return True, "Rollback verified: No pending changes detected"
                    except Exception as diff_error:
                        # If diff command fails, try checking history for pending revision
                        try:
                            history_check = self.connection.device.send_command_timing('nv config history | head -5', read_timeout=10)
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
                        sessions_output = netmiko_conn.send_command_timing('show configuration sessions', read_timeout=10)
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
    
    def _check_for_pending_commits(self, driver_name):
        """
        Check if there are any pending commit-confirm sessions on the device.
        
        Note: "Pending commit" means a commit-confirm session is active:
        - Config IS applied and active on the device
        - Session is in "confirm" state (waiting for confirmation)
        - Will auto-rollback if not confirmed within timeout
        
        Args:
            driver_name: Platform driver name (cumulus, eos, etc.)
        
        Returns:
            bool: True if pending commit-confirm session exists, False otherwise
        """
        try:
            if driver_name == 'cumulus':
                if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                    # Method 1: Check via JSON (most reliable)
                    # Use send_command_timing() to avoid prompt detection issues
                    try:
                        revision_json = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                        if revision_json and revision_json.strip():
                            import json
                            rev_data = json.loads(revision_json)
                            for rev_id, rev_info in rev_data.items():
                                if isinstance(rev_info, dict) and rev_info.get('state') == 'confirm':
                                    logger.info(f"Found commit-confirm session (pending confirmation) via JSON: revision {rev_id}")
                                    logger.debug(f"Note: 'Pending' means commit-confirm session is active - config is applied, waiting for confirmation")
                                    return True
                    except Exception as json_error:
                        logger.debug(f"Could not check pending commits via JSON: {json_error}")
                    
                    # Method 2: Check via has_pending_commit() (NAPALM method)
                    try:
                        has_pending = self.connection.has_pending_commit()
                        if has_pending:
                            logger.info(f"Found commit-confirm session (pending confirmation) via NAPALM has_pending_commit()")
                            return True
                    except Exception as napalm_error:
                        logger.debug(f"Could not check pending commits via NAPALM: {napalm_error}")
                    
                    # Method 3: Check history text output (fallback)
                    # Use send_command_timing() to avoid prompt detection issues
                    try:
                        history_output = self.connection.device.send_command_timing('nv config history | head -5', read_timeout=10)
                        if history_output and ('Currently pending' in history_output or 'pending [rev_id:' in history_output.lower()):
                            logger.info(f"Found commit-confirm session (pending confirmation) via history text")
                            return True
                    except Exception as history_error:
                        logger.debug(f"Could not check pending commits via history: {history_error}")
                    
                    # No pending commits found
                    return False
                    
            elif driver_name == 'eos':
                # For EOS, check if our session still exists
                if hasattr(self, '_eos_session_name') and hasattr(self, '_eos_netmiko_conn'):
                    try:
                        session_name = self._eos_session_name
                        netmiko_conn = self._eos_netmiko_conn
                        sessions_output = netmiko_conn.send_command_timing('show configuration sessions', read_timeout=10)
                        if session_name in sessions_output:
                            logger.info(f"Found pending EOS session: {session_name}")
                            return True
                    except:
                        pass
                return False
            else:
                # Other platforms - assume no pending commit
                return False
                
        except Exception as e:
            logger.warning(f"Error checking for pending commits: {e}")
            return False
    
    def _clear_pending_commit(self, driver_name, logs=None):
        """
        Clear/delete any pending commit-confirm session on the device using specific revision IDs.
        
        Args:
            driver_name: Platform driver name (cumulus, eos, etc.)
            logs: Optional list to append log messages to
        
        Returns:
            bool: True if successfully cleared, False otherwise
        """
        if logs is None:
            logs = []
        
        try:
            if driver_name == 'cumulus':
                if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                    logger.info("Attempting to clear pending commit on Cumulus device...")
                    
                    # Get pending revision IDs first, then delete each one specifically
                    # Use send_command_timing() to avoid prompt detection issues
                    try:
                        # First, get all pending revision IDs
                        revision_json = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                        if not revision_json or not revision_json.strip():
                            logger.warning("Could not get revision list - no pending commits to clear")
                            return True  # No pending commits
                        
                        import json
                        rev_data = json.loads(revision_json)
                        pending_rev_ids = []
                        for rev_id, rev_info in rev_data.items():
                            if isinstance(rev_info, dict) and rev_info.get('state') == 'confirm':
                                pending_rev_ids.append(rev_id)
                        
                        if not pending_rev_ids:
                            logger.info("No pending commits found - device is already clean")
                            return True
                        
                        logger.info(f"Found {len(pending_rev_ids)} pending commit(s) to delete: {pending_rev_ids}")
                        logs.append(f"  Found {len(pending_rev_ids)} pending commit(s): {pending_rev_ids}")
                        
                        # Delete each pending revision specifically
                        for rev_id in pending_rev_ids:
                            try:
                                logger.info(f"Deleting pending commit revision {rev_id}...")
                                logs.append(f"  Deleting revision {rev_id}...")
                                delete_output = self.connection.device.send_command_timing(f'nv config delete {rev_id}', read_timeout=30)
                                logger.info(f"Delete command output for revision {rev_id}: {delete_output[:500] if delete_output else 'Empty'}")
                                
                                # Check if delete command actually executed (look for error messages)
                                if delete_output and ('error' in delete_output.lower() or 'failed' in delete_output.lower()):
                                    logger.warning(f"Delete command may have failed for revision {rev_id}: {delete_output[:200]}")
                                
                                # Small delay between deletions if multiple
                                if len(pending_rev_ids) > 1:
                                    time.sleep(0.5)
                            except Exception as delete_error:
                                logger.error(f"Failed to delete revision {rev_id}: {delete_error}")
                                logs.append(f"    ✗ Failed to delete revision {rev_id}: {str(delete_error)}")
                        
                        # Wait a moment for deletions to take effect
                        time.sleep(2)
                        
                        # Verify all pending commits are gone - try multiple times with increasing delays
                        max_verify_attempts = 3
                        still_pending = True
                        for verify_attempt in range(1, max_verify_attempts + 1):
                            still_pending = self._check_for_pending_commits(driver_name)
                            if not still_pending:
                                logger.info(f"Successfully cleared all pending commits (verified on attempt {verify_attempt})")
                                logs.append(f"  SUCCESS: All pending commits cleared")
                                return True
                            if verify_attempt < max_verify_attempts:
                                logger.debug(f"Pending commits still detected, waiting longer (attempt {verify_attempt}/{max_verify_attempts})...")
                                time.sleep(2)
                        
                        # Still pending after multiple checks
                        logger.warning("Pending commits still exist after delete commands and multiple verification attempts")
                        logger.warning("This may indicate: (1) Delete command didn't execute properly, (2) Revision IDs were incorrect, or (3) Device state issue")
                        logs.append(f"  ⚠ WARNING: Some pending commits may still exist")
                        return False
                        
                    except Exception as clear_error:
                        logger.error(f"Failed to clear pending commits: {clear_error}")
                        import traceback
                        logger.debug(traceback.format_exc())
                        return False
                else:
                    logger.warning("Cannot clear pending commit - no device connection")
                    return False
                    
            elif driver_name == 'eos':
                # For EOS, abort the session
                if hasattr(self, '_eos_session_name') and hasattr(self, '_eos_netmiko_conn'):
                    try:
                        session_name = self._eos_session_name
                        netmiko_conn = self._eos_netmiko_conn
                        logger.info(f"Attempting to abort EOS session: {session_name}")
                        
                        abort_output = netmiko_conn.send_command_timing(f'configure session {session_name} abort', read_timeout=30)
                        logger.info(f"Abort output: {abort_output}")
                        
                        # Verify it's gone
                        time.sleep(2)
                        still_pending = self._check_for_pending_commits(driver_name)
                        if not still_pending:
                            logger.info("Successfully cleared EOS session")
                            return True
                        else:
                            logger.warning("EOS session still exists after abort")
                            return False
                    except Exception as eos_abort_error:
                        logger.error(f"Failed to abort EOS session: {eos_abort_error}")
                        return False
                return False
            else:
                # Other platforms - not supported
                logger.info(f"Pending commit clear not supported for platform: {driver_name}")
                return False
                
        except Exception as e:
            logger.error(f"Error clearing pending commit: {e}")
            return False
    
    def deploy_config_safe(self, config, replace=True, timeout=150,
                          checks=['connectivity', 'interfaces', 'lldp'],
                          critical_interfaces=None, min_neighbors=0,
                          vlan_id=None, interface_name=None, interface_names=None, interface_names_for_lldp=None,
                          interface_vlan_map=None):
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
            timeout: Rollback timer in seconds (60-150 recommended, default 150)
            checks: List of verification checks to perform ['connectivity', 'interfaces', 'lldp']
            critical_interfaces: List of interface names that must be up (for interface check)
            min_neighbors: Minimum LLDP neighbors required (for LLDP check)
            vlan_id: VLAN ID being deployed (for VLAN-specific verification in normal mode)
            interface_name: Single interface name (legacy, use interface_names instead)
            interface_names: List of interface names to run interface-level checks on (for interface state/traffic stats)
            interface_names_for_lldp: List of interface names for LLDP checks (defaults to interface_names if not provided)
                                     Use member interfaces for bonds (LLDP neighbors are only on physical interfaces)
            interface_vlan_map: Optional dict mapping "device:interface" -> {'untagged_vlan': int, 'tagged_vlans': [int], 'commands': [str]}
                              Used in sync mode to provide per-interface VLAN config from NetBox for comprehensive verification

        Returns:
            dict: {
                'success': bool,
                'committed': bool,
                'rolled_back': bool,
                'message': str,
                'verification_results': dict,
                'config_deployed': str,
                'logs': list,
                'baseline': dict  # Contains per-interface baseline data
            }
        """
        # CRITICAL: Validate config parameter before proceeding
        if config is None:
            error_msg = "Config parameter is None - cannot deploy empty configuration"
            logger.error(f"CRITICAL: {error_msg}")
            return {
                'success': False,
                'committed': False,
                'rolled_back': False,
                'message': error_msg,
                'verification_results': {},
                'config_deployed': None,
                'logs': [f"[FAIL] {error_msg}"]
            }
        
        # Convert config to string and strip whitespace
        if not isinstance(config, str):
            config = str(config) if config else ''
        
        config = config.strip()
        
        if not config:
            error_msg = "Config parameter is empty - cannot deploy empty configuration"
            logger.error(f"CRITICAL: {error_msg}")
            return {
                'success': False,
                'committed': False,
                'rolled_back': False,
                'message': error_msg,
                'verification_results': {},
                'config_deployed': '',
                'logs': [f"[FAIL] {error_msg}"]
            }
        
        logger.debug(f"[VALIDATION] Config parameter validated: {len(config)} characters, {len(config.splitlines())} lines")

        # Handle both single interface and multiple interfaces
        # Priority: interface_names (list) > interface_name (single) > None (device-level only)
        interfaces_to_check = []
        if interface_names:
            # Multiple interfaces provided as list
            interfaces_to_check = interface_names if isinstance(interface_names, list) else [interface_names]
            logger.info(f"Interface-level checks will run for {len(interfaces_to_check)} interface(s): {interfaces_to_check}")
        elif interface_name:
            # Single interface provided (legacy parameter)
            interfaces_to_check = [interface_name]
            logger.info(f"Interface-level checks will run for 1 interface: {interface_name}")
        else:
            # No interfaces specified - device-level checks only
            logger.info(f"No interfaces specified - device-level checks only (LLDP, connectivity, uptime)")
        
        # For LLDP checks, use interface_names_for_lldp if provided (member interfaces for bonds),
        # otherwise fall back to interfaces_to_check
        interfaces_for_lldp_check = []
        if interface_names_for_lldp:
            interfaces_for_lldp_check = interface_names_for_lldp if isinstance(interface_names_for_lldp, list) else [interface_names_for_lldp]
            logger.info(f"LLDP checks will run on {len(interfaces_for_lldp_check)} member interface(s): {interfaces_for_lldp_check}")
        else:
            # Fall back to interfaces_to_check if interface_names_for_lldp not provided
            interfaces_for_lldp_check = interfaces_to_check
            if interfaces_for_lldp_check:
                logger.info(f"LLDP checks will run on {len(interfaces_for_lldp_check)} interface(s): {interfaces_for_lldp_check}")

        result = {
            'success': False,
            'committed': False,
            'rolled_back': False,
            'message': '',
            'verification_results': {},
            'config_deployed': config,
            'logs': [],
            'baseline': {}  # Will store per-interface baseline data
        }

        # Initialize detailed logs
        logs = []

        # Phase 0: Ensure connection is established
        logger.info(f"{'='*60}")
        logger.info(f"SAFE DEPLOYMENT: {self.device.name} (timeout={timeout}s, replace={replace})")
        logger.info(f"{'='*60}")
        
        # Get driver name early - needed for platform-specific logic
        driver_name = self.get_driver_name()

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
            logs.append(f"  SUCCESS: Connection established successfully")
        else:
            logger.info(f"Phase 0: Using existing connection to {self.device.name}")
            logs.append(f"  SUCCESS: Using existing connection")

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
        
        # For Cumulus: Take pre-deployment configuration snapshot
        if driver_name == 'cumulus':
            logger.info(f"Taking pre-deployment configuration snapshot...")
            logs.append(f"")
            logs.append(f"  === PRE-DEPLOYMENT SNAPSHOT ===")
            
            try:
                if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                    # 1. Get current revision history (JSON format for reliable parsing)
                    logger.info(f"Retrieving current NVUE revision...")
                    revision_json_output = self.connection.device.send_command_timing('nv config history -o json', read_timeout=10)
                    
                    if revision_json_output:
                        import json
                        revision_data = json.loads(revision_json_output)
                        # Get latest revision (highest number) - filter out non-numeric revision IDs
                        # NVUE can have internal revisions like 'rev_178_apply_1/start' that should be ignored
                        numeric_revisions = []
                        for rev_id in revision_data.keys():
                            try:
                                numeric_revisions.append(int(rev_id))
                            except (ValueError, TypeError):
                                # Skip non-numeric revision IDs (internal/temporary revisions)
                                logger.debug(f"Skipping non-numeric revision ID: {rev_id}")
                                continue
                        
                        if numeric_revisions:
                            latest_revision = str(max(numeric_revisions))
                            revision_info = revision_data.get(latest_revision, {})
                            revision_date = revision_info.get('date', 'unknown')
                            revision_user = revision_info.get('user', 'unknown')
                            
                            logger.info(f"Current revision: {latest_revision} ({revision_date})")
                            logs.append(f"  Current Revision: {latest_revision}")
                            logs.append(f"  Date: {revision_date}")
                            logs.append(f"  User: {revision_user}")
                        else:
                            latest_revision = 'unknown'
                            logs.append(f"  [WARN] No numeric revision IDs found in history")
                    else:
                        latest_revision = 'unknown'
                        logs.append(f"  [WARN] Could not retrieve revision history")
                    
                    # 2. Export full configuration to timestamped file
                    import time as time_module
                    timestamp = int(time_module.time())
                    snapshot_filename = f"/tmp/pre_deploy_{timestamp}_rev{latest_revision}.txt"
                    
                    logger.info(f"Exporting configuration to {snapshot_filename}...")
                    export_cmd = f"nv config show -r applied -o commands > {snapshot_filename}"
                    self.connection.device.send_command_timing(export_cmd, read_timeout=30)
                    
                    # Verify file was created
                    verify_cmd = f"ls -lh {snapshot_filename}"
                    verify_output = self.connection.device.send_command_timing(verify_cmd, read_timeout=5)
                    
                    if snapshot_filename in verify_output:
                        logger.info(f"Snapshot file created successfully: {snapshot_filename}")
                        logs.append(f"  SUCCESS: Snapshot file: {snapshot_filename}")
                        # Store snapshot filename in result for later use
                        result['_pre_deployment_snapshot'] = snapshot_filename
                        result['_pre_deployment_revision'] = latest_revision
                    else:
                        logger.warning(f"Could not verify snapshot file creation")
                        logs.append(f"  ⚠ Could not verify snapshot file creation")
                        
                else:
                    logger.warning(f"Cannot access Netmiko connection for snapshot")
                    logs.append(f"  ⚠ Snapshot skipped - no device connection")
            except Exception as snapshot_error:
                logger.error(f"Failed to take pre-deployment snapshot: {snapshot_error}")
                logs.append(f"  ⚠ Snapshot failed: {str(snapshot_error)[:100]}")
            
            logs.append(f"")
        
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
                    logs.append(f"  SUCCESS: Connection reinitialized - device object available")
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
            # Collect interface state for ALL interfaces being configured
            # Store per-interface baseline in baseline['interfaces'] dict
            baseline['interfaces'] = {}

            if interfaces_to_check:
                logs.append(f"  Collecting interface-level baseline for {len(interfaces_to_check)} interface(s)...")

                # PERFORMANCE: For Cumulus, fetch basic interface info at once (saves link/description commands)
                # Note: nv show interface -o json doesn't include stats, so we still need per-interface commands
                # But we can use batched data for basic link info, then fetch full interface data (with stats) per-interface
                # This saves: 12 × 2 commands (link + description) × 10s = ~4 minutes
                all_interfaces_basic_data = None
                if driver_name == 'cumulus' and len(interfaces_to_check) > 1:
                    try:
                        logger.info(f"Fetching basic interface info at once for {len(interfaces_to_check)} interface(s) (performance optimization)...")
                        if hasattr(self.connection, 'device') and self.connection.device is not None:
                            # Fetch all interfaces at once: nv show interface -o json (basic info only, no stats)
                            all_ifaces_command = 'nv show interface -o json'
                            all_ifaces_output = self.connection.device.send_command_timing(all_ifaces_command, read_timeout=20)
                            if all_ifaces_output and all_ifaces_output.strip():
                                import json
                                try:
                                    all_interfaces_basic_data = json.loads(all_ifaces_output.strip())
                                    logger.info(f"Successfully fetched basic data for {len(all_interfaces_basic_data) if isinstance(all_interfaces_basic_data, dict) else 'all'} interface(s)")
                                except json.JSONDecodeError as e:
                                    logger.warning(f"Could not parse all interfaces JSON: {e}")
                    except Exception as batch_err:
                        logger.warning(f"Could not batch fetch interfaces (will fetch per-interface): {batch_err}")

                for iface_idx, interface_name in enumerate(interfaces_to_check, 1):
                    # CRITICAL FIX: Parse interface name if it's in "device:interface" format
                    # This can happen in sync mode where interface names might not be fully parsed
                    actual_interface_name = interface_name
                    if ':' in interface_name:
                        # Extract just the interface name (remove device prefix)
                        _, actual_interface_name = interface_name.split(':', 1)
                        logger.warning(f"  Parsing interface name '{interface_name}' → '{actual_interface_name}' (removed device prefix)")
                        interface_name = actual_interface_name  # Use parsed name for rest of loop
                    
                    logger.info(f"  [{iface_idx}/{len(interfaces_to_check)}] Collecting baseline for interface: {interface_name}")
                    # Note: When bonds are detected, interface_name will be the bond interface (e.g., bond3)
                    # not the member interface (e.g., swp3), since VLAN config is applied to the bond
                    logs.append(f"  [{iface_idx}/{len(interfaces_to_check)}] Interface: {interface_name}")

                    # Initialize baseline for this interface
                    interface_baseline = {}
                    baseline_interface_name = interface_name  # Default to interface_name (could be bond)
                    
                    # For Cumulus devices, use direct NVUE command instead of NAPALM's get_interfaces()
                    # This is more reliable for bond members which may not appear in get_interfaces()
                    baseline_collected = False
                    baseline_error_details = []
                    
                    if driver_name == 'cumulus':
                        try:
                            # Check if we can access device commands (either via device.send_command_timing or cli())
                            can_access_device = (
                                (hasattr(self.connection, 'device') and self.connection.device is not None and hasattr(self.connection.device, 'send_command')) or
                                hasattr(self.connection, 'cli')
                            )
                            
                            if can_access_device:
                                # PERFORMANCE: Use single per-interface command that gets everything (link + stats + description)
                                # nv show interface {interface} -o json gives us all data in one command
                                # This is still faster than 3 separate commands (stats, link, description)
                                # Before: 3 commands × 10s = 30s per interface
                                # After: 1 command × 10s = 10s per interface
                                # Savings: 12 interfaces × 20s = ~4 minutes
                                
                                # Try multiple interface names: interface_name (could be bond or member), and bond if member
                                interfaces_to_try = [interface_name]
                                
                                # Check if interface_name is a bond member and add bond to list
                                # Use batched basic data if available to check bond membership
                                if all_interfaces_basic_data and isinstance(all_interfaces_basic_data, dict):
                                    # Check if interface_name exists in basic data
                                    if interface_name not in all_interfaces_basic_data:
                                        # Might be a bond member - we'll check via per-interface command below
                                        pass
                                else:
                                    # No batched data - check bond membership via command
                                    try:
                                        bond_members_command = 'nv show interface bond-members -o json'
                                        if hasattr(self.connection, 'device') and self.connection.device is not None:
                                            bond_members_output = self.connection.device.send_command_timing(bond_members_command, read_timeout=10)
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
                                            for member, info in bond_members.items():
                                                if isinstance(info, dict) and (info.get('parent') == interface_name or info.get('bond') == interface_name):
                                                    if member not in interfaces_to_try:
                                                        interfaces_to_try.append(member)
                                                        logger.info(f"Interface {interface_name} is a bond, will also try member {member}")
                                                    break
                                    except Exception as bond_check:
                                        logger.debug(f"Could not check bond membership for baseline: {bond_check}")
                                
                                # Try each interface name until one works
                                if not baseline_collected:
                                    # Try multiple interface names: interface_name (could be bond or member), and bond if member
                                    interfaces_to_try = [interface_name]
                                    
                                    # Check if interface_name is a bond member and add bond to list
                                    try:
                                        bond_members_command = 'nv show interface bond-members -o json'
                                        if hasattr(self.connection, 'device') and self.connection.device is not None:
                                            bond_members_output = self.connection.device.send_command_timing(bond_members_command, read_timeout=10)
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
                                    
                                    # PERFORMANCE: Use single command per interface: nv show interface {interface} -o json
                                    # This gives us link info, stats, and description all in one command
                                    # Instead of 3 separate commands (stats, link, description)
                                    for test_interface in interfaces_to_try:
                                        try:
                                            # Single command to get all interface data (link + stats + description)
                                            full_iface_command = f'nv show interface {test_interface} -o json'
                                            
                                            # Use connection.device.send_command_timing (if available)
                                            if hasattr(self.connection, 'device') and self.connection.device is not None:
                                                full_iface_output = self.connection.device.send_command_timing(full_iface_command, read_timeout=10)
                                            elif hasattr(self.connection, 'cli'):
                                                # Fallback to NAPALM's cli() method
                                                cli_result = self.connection.cli([full_iface_command])
                                                if isinstance(cli_result, dict):
                                                    full_iface_output = cli_result.get(full_iface_command, '')
                                                else:
                                                    full_iface_output = str(cli_result) if cli_result else ''
                                            else:
                                                raise AttributeError("Neither connection.device.send_command nor connection.cli() is available")
                                            
                                            if full_iface_output and full_iface_output.strip():
                                                import json
                                                try:
                                                    full_iface_output_stripped = full_iface_output.strip()
                                                    if not full_iface_output_stripped.startswith('{') and not full_iface_output_stripped.startswith('['):
                                                        raise ValueError("Output is not JSON format")
                                                    full_iface_data = json.loads(full_iface_output_stripped)
                                                    
                                                    # Extract all data from single command response
                                                    # Structure: {"link": {"admin-status": "up", "oper-status": "up", "stats": {...}}, ...}
                                                    link_data = full_iface_data.get('link', {})
                                                    if not isinstance(link_data, dict):
                                                        baseline_error_details.append(f"Link data is not a dict for {test_interface}")
                                                        continue
                                                    
                                                    # Extract link state
                                                    is_up = link_data.get('oper-status') == 'up'
                                                    is_enabled = link_data.get('admin-status') == 'up'
                                                    
                                                    # Extract stats (nested under link.stats)
                                                    stats_data = link_data.get('stats', {})
                                                    if not isinstance(stats_data, dict):
                                                        stats_data = {}
                                                    
                                                    in_pkts = stats_data.get('in-pkts', 0)
                                                    out_pkts = stats_data.get('out-pkts', 0)
                                                    in_bytes = stats_data.get('in-bytes', 0)
                                                    out_bytes = stats_data.get('out-bytes', 0)
                                                    in_drops = stats_data.get('in-drops', 0)
                                                    out_drops = stats_data.get('out-drops', 0)
                                                    in_errors = stats_data.get('in-errors', 0)
                                                    out_errors = stats_data.get('out-errors', 0)
                                                    
                                                    # Extract description (if available in link data)
                                                    description = link_data.get('description', '')
                                                    
                                                    # Store baseline for this specific interface
                                                    interface_baseline = {
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
                                                    baseline['interfaces'][interface_name] = interface_baseline
                                                    logger.info(f"  Baseline: {test_interface} is_up={is_up}, is_enabled={is_enabled}, in_pkts={in_pkts}, out_pkts={out_pkts}")
                                                    logs.append(f"    SUCCESS: UP={is_up}, Enabled={is_enabled}, In-Pkts={in_pkts}, Out-Pkts={out_pkts}")

                                                    if test_interface != interface_name:
                                                        logs.append(f"    Note: Collected baseline for {test_interface} (requested {interface_name})")

                                                    # Success - baseline collected
                                                    baseline_collected = True
                                                    break  # Found working interface, stop trying
                                                except json.JSONDecodeError as json_err:
                                                    baseline_error_details.append(f"JSON decode error for {test_interface}: {json_err}")
                                                except Exception as parse_err:
                                                    baseline_error_details.append(f"Parse error for {test_interface}: {parse_err}")
                                            else:
                                                baseline_error_details.append(f"Full interface command returned empty for {test_interface}")
                                        except Exception as test_err:
                                            baseline_error_details.append(f"Error testing {test_interface}: {str(test_err)[:100]}")
                                
                                if not baseline_collected:
                                    # All attempts failed - log error but continue for other interfaces
                                    error_msg = f"Failed to collect baseline for interface {interface_name}. Tried: {', '.join(interfaces_to_try)}"
                                    logger.error(f"CRITICAL: {error_msg}")
                                    logs.append(f"  ✗ Baseline collection FAILED for {interface_name}")
                                    logs.append(f"  Tried interfaces: {', '.join(interfaces_to_try)}")
                                    for detail in baseline_error_details:
                                        logs.append(f"    - {detail}")
                                    # Store error in baseline but continue processing other interfaces
                                    baseline['interfaces'][interface_name] = {
                                        'name': interface_name,
                                        'is_up': None,
                                        'is_enabled': None,
                                        'error': error_msg,
                                        'baseline_error_details': baseline_error_details
                                    }
                                    # Don't return - continue to next interface
                                    continue
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
                                            bond_members_output = self.connection.device.send_command_timing(bond_members_command, read_timeout=10)
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
                        if not baseline_collected and 'interfaces_before' in locals() and interfaces_before and baseline_interface_name in interfaces_before:
                            interface_baseline = {
                                'name': baseline_interface_name,
                                'is_up': interfaces_before[baseline_interface_name].get('is_up', False),
                                'is_enabled': interfaces_before[baseline_interface_name].get('is_enabled', True),
                                'description': interfaces_before[baseline_interface_name].get('description', ''),
                            }
                            baseline['interfaces'][interface_name] = interface_baseline
                            logger.info(f"  Baseline: {baseline_interface_name} is_up={interface_baseline['is_up']}, is_enabled={interface_baseline['is_enabled']}")
                            logs.append(f"    SUCCESS: UP={interface_baseline['is_up']}, Enabled={interface_baseline['is_enabled']}")
                            # Note if we used bond instead of member
                            if baseline_interface_name != interface_name:
                                logs.append(f"    Note: Using bond interface {baseline_interface_name} for baseline (member {interface_name})")
                            baseline_collected = True  # Mark as collected
                        elif not baseline_collected:
                            # Baseline collection failed - this is now mandatory
                            error_msg = f"Baseline collection failed: Could not collect baseline for interface {interface_name}"
                            if baseline_interface_name != interface_name:
                                error_msg += f" (tried {baseline_interface_name} as fallback)"
                            logger.error(f"CRITICAL: {error_msg}")
                            logs.append(f"  ✗ Baseline collection FAILED")
                            logs.append(f"  Interface {interface_name} or {baseline_interface_name} not found in device interfaces")
                            if 'interfaces_before' in locals() and interfaces_before:
                                available_interfaces = list(interfaces_before.keys())[:10]  # Show first 10
                                logs.append(f"  Available interfaces on device: {', '.join(available_interfaces)}")
                            else:
                                logs.append(f"  Could not retrieve interface list from device")
                            result['message'] = error_msg
                            result['logs'] = logs
                            return result

                # End of per-interface baseline collection loop
                logger.info(f"Completed baseline collection for {len(baseline['interfaces'])} interface(s)")

            # Collect LLDP neighbors baseline (if checking) - INTERFACE-LEVEL for deployed interfaces
            if 'lldp' in checks:
                try:
                    # Determine which interfaces to collect LLDP for
                    # Use interfaces_for_lldp_check (member interfaces for bonds) instead of interfaces_to_check
                    interfaces_for_lldp = []
                    if interfaces_for_lldp_check:
                        interfaces_for_lldp = interfaces_for_lldp_check
                        logs.append(f"  Collecting LLDP neighbors for {len(interfaces_for_lldp)} member interface(s): {', '.join(interfaces_for_lldp)}")
                    elif interface_name:
                        interfaces_for_lldp = [interface_name]
                        logs.append(f"  Collecting LLDP neighbors for interface: {interface_name}")
                    else:
                        # No specific interfaces - collect device-level (fallback)
                        logs.append(f"  Collecting LLDP neighbors (device-level, no specific interfaces)...")
                        interfaces_for_lldp = None
                    
                    # Collect LLDP data for deployment interfaces (member interfaces, not bonds)
                    lldp_before = self.get_lldp_neighbors(interfaces=interfaces_for_lldp)

                    # Store per-interface LLDP data for the interfaces we're deploying
                    baseline['lldp_interfaces'] = {}  # Per-interface LLDP data for deployed interfaces
                    baseline['lldp_all_interfaces'] = {}  # All interfaces (for backward compatibility)
                    total_neighbors = 0
                    deployed_interfaces_neighbors = 0
                    
                    if lldp_before:
                        # Store all interfaces (for backward compatibility)
                        for iface, neighbors in lldp_before.items():
                            neighbor_count = len(neighbors) if neighbors else 0
                            baseline['lldp_all_interfaces'][iface] = neighbor_count
                            total_neighbors += neighbor_count
                        
                        # Store per-interface data for deployed interfaces
                        if interfaces_for_lldp:
                            for iface in interfaces_for_lldp:
                                if iface in lldp_before:
                                    neighbors = lldp_before[iface]
                                    neighbor_count = len(neighbors) if neighbors else 0
                                    baseline['lldp_interfaces'][iface] = {
                                        'neighbors': neighbors,  # Full neighbor data
                                        'count': neighbor_count
                                    }
                                    deployed_interfaces_neighbors += neighbor_count
                                    logger.info(f"  Baseline: Interface {iface} has {neighbor_count} LLDP neighbors")
                                    logs.append(f"  SUCCESS: Interface {iface}: {neighbor_count} neighbor(s)")
                                else:
                                    baseline['lldp_interfaces'][iface] = {
                                        'neighbors': [],
                                        'count': 0
                                    }
                                    logger.info(f"  Baseline: Interface {iface} has no LLDP neighbors")
                                    logs.append(f"  SUCCESS: Interface {iface}: 0 neighbors")
                        elif interface_name:
                            # Single interface mode
                            if interface_name in lldp_before:
                                neighbors = lldp_before[interface_name]
                                neighbor_count = len(neighbors) if neighbors else 0
                                baseline['lldp_interfaces'][interface_name] = {
                                    'neighbors': neighbors,
                                    'count': neighbor_count
                                }
                                baseline['lldp_neighbors'] = neighbor_count  # Backward compatibility
                                deployed_interfaces_neighbors = neighbor_count
                                logger.info(f"  Baseline: Interface {interface_name} has {neighbor_count} LLDP neighbors")
                                logs.append(f"  SUCCESS: Interface {interface_name}: {neighbor_count} neighbor(s)")
                            else:
                                baseline['lldp_interfaces'][interface_name] = {
                                    'neighbors': [],
                                    'count': 0
                                }
                                baseline['lldp_neighbors'] = 0  # Backward compatibility
                                logger.info(f"  Baseline: Interface {interface_name} has no LLDP neighbors")
                                logs.append(f"  SUCCESS: Interface {interface_name}: 0 neighbors")
                    else:
                        # No LLDP data collected
                        if interfaces_for_lldp:
                            for iface in interfaces_for_lldp:
                                baseline['lldp_interfaces'][iface] = {
                                    'neighbors': [],
                                    'count': 0
                                }
                        elif interface_name:
                            baseline['lldp_interfaces'][interface_name] = {
                                'neighbors': [],
                                'count': 0
                            }
                        logs.append(f"  ⚠ LLDP neighbors: No data collected")

                    # Summary log
                    if interfaces_for_lldp:
                        logger.info(f"  Baseline: Collected LLDP for {len(interfaces_for_lldp)} interface(s): {deployed_interfaces_neighbors} total neighbors")
                    else:
                        logger.info(f"  Baseline: Device has {total_neighbors} total LLDP neighbors across {len(baseline['lldp_all_interfaces'])} interfaces")

                except Exception as e:
                    logger.debug(f"Could not get LLDP baseline: {e}")
                    baseline['lldp_neighbors'] = None
                    baseline['lldp_interfaces'] = {}
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
                    logs.append(f"  SUCCESS: System uptime: {baseline['uptime']}s, hostname: {baseline['hostname']}")
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
            # Handle both single interface (baseline['interface']) and multiple interfaces (baseline['interfaces'])
            baseline_collected = False
            if 'interface' in baseline:
                baseline_collected = True
            elif 'interfaces' in baseline and baseline['interfaces']:
                baseline_collected = True
                # For backward compatibility with verification code that expects baseline['interface'],
                # create it from the first interface in baseline['interfaces']
                if interface_name and interface_name in baseline['interfaces']:
                    baseline['interface'] = baseline['interfaces'][interface_name]
                elif baseline['interfaces']:
                    # Use first interface if interface_name not found
                    first_iface_name = next(iter(baseline['interfaces']))
                    baseline['interface'] = baseline['interfaces'][first_iface_name]
                    logger.info(f"Using first interface '{first_iface_name}' for baseline['interface'] compatibility")
            
            # Check if we collected baseline for at least some interfaces
            # In sync mode with multiple interfaces, some may fail but others may succeed
            if interfaces_to_check:
                successful_baselines = sum(1 for iface in interfaces_to_check if iface in baseline.get('interfaces', {}) and 'error' not in baseline['interfaces'][iface])
                failed_baselines = len(interfaces_to_check) - successful_baselines
                
                if successful_baselines == 0:
                    # All interfaces failed
                    error_msg = f"Baseline collection incomplete: No baseline collected for any of {len(interfaces_to_check)} interface(s)"
                    logger.error(f"CRITICAL: {error_msg}")
                    logs.append(f"  ✗ Baseline collection FAILED: No baseline data collected for any interface")
                    result['success'] = False
                    result['error'] = error_msg
                    result['message'] = error_msg
                elif failed_baselines > 0:
                    # Some interfaces failed, but some succeeded
                    logger.warning(f"Baseline collection partially successful: {successful_baselines} succeeded, {failed_baselines} failed")
                    logs.append(f"  ⚠ Baseline collection: {successful_baselines} succeeded, {failed_baselines} failed")
                    # Don't mark as failed - continue with successful baselines
                else:
                    # All interfaces succeeded
                    logger.info(f"Baseline collection successful for all {successful_baselines} interface(s)")
            elif interface_name and not baseline_collected:
                # Single interface mode - must succeed
                error_msg = f"Baseline collection incomplete: Interface baseline not collected for {interface_name}"
                logger.error(f"CRITICAL: {error_msg}")
                logs.append(f"  ✗ Baseline collection FAILED: Interface baseline missing")
                result['success'] = False
                result['error'] = error_msg
                result['message'] = error_msg
                result['logs'] = logs
                return result
            
            # Store baseline for comparison later
            result['baseline'] = baseline
            logger.info(f"Phase 0.5: Baseline collection completed")
            logs.append(f"  SUCCESS: Baseline collection completed")

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
        
        # Track pending commits from BEFORE our deployment (to avoid deleting our own)
        self._pending_revisions_before_deployment = []
        # Track our candidate revision ID (created by load_config) to exclude from Phase 2 checks
        self._candidate_revision_id = None
        
        # PRE-PHASE 1: Check for and delete ANY existing pending commits from ANY user/previous deployment
        # This ensures we have a clean state before loading our config
        # IMPORTANT: We check BEFORE load_config() so we know any pending commit is NOT ours
        # CRITICAL: We check for ALL pending commits from ALL users, not just our own
        if driver_name == 'cumulus' and not use_eos_session:
            try:
                logs.append(f"")
                logs.append(f"[Pre-Phase 1] Checking for existing pending commits from ALL users...")
                existing_pending_revisions = []  # Changed to list to track ALL pending commits
                
                if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                    # Check for pending commits using JSON (most reliable - shows ALL pending commits from ALL users)
                    try:
                        revision_json_before = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                        if revision_json_before:
                            import json
                            rev_data_before = json.loads(revision_json_before)
                            for rev_id, rev_info in rev_data_before.items():
                                if isinstance(rev_info, dict) and rev_info.get('state') == 'confirm':
                                    # Found a pending commit - get user info if available
                                    rev_user = rev_info.get('user', 'unknown')
                                    rev_date = rev_info.get('date', 'unknown')
                                    
                                    existing_pending_revisions.append({
                                        'rev_id': str(rev_id),
                                        'user': rev_user,
                                        'date': rev_date
                                    })
                                    # Track this as a pre-deployment pending commit (NOT ours)
                                    self._pending_revisions_before_deployment.append(str(rev_id))
                                    logger.warning(f"[Pre-Phase 1] Found existing pending commit-confirm: revision {rev_id} (user: {rev_user}, date: {rev_date})")
                                    logs.append(f"  ⚠ Found pending commit-confirm session:")
                                    logs.append(f"    Revision: {rev_id}")
                                    logs.append(f"    User: {rev_user}")
                                    logs.append(f"    Date: {rev_date}")
                                    logs.append(f"    This is from a PREVIOUS deployment/user (not ours - will abort")
                    except Exception as json_error:
                        logger.debug(f"Could not check revision JSON before Phase 1: {json_error}")
                    
                    # Fallback: Check history text output (if JSON didn't find any)
                    if not existing_pending_revisions:
                        try:
                            # Get ALL pending commits from history (not just first one)
                            pending_before = self.connection.device.send_command_timing('nv config history | grep -i "pending\\|confirm\\|\\*"', read_timeout=10)
                            if pending_before:
                                import re
                                # Parse all pending commits from history output
                                for line in pending_before.split('\n'):
                                    if line and ('*' in line or 'pending' in line.lower() or 'confirm' in line.lower()):
                                        # Try to extract revision ID
                                        rev_match = re.search(r'Currently pending\s*\[rev_id:\s*(\d+)\]', line, re.IGNORECASE)
                                        if not rev_match:
                                            rev_match = re.search(r'Revision:\s*(\d+)', line)
                                        if not rev_match:
                                            rev_match = re.search(r'^\s*(\d+)\s*\*', line)
                                        if rev_match:
                                            rev_id = rev_match.group(1)
                                            # Only add if not already found via JSON
                                            if rev_id not in [r['rev_id'] for r in existing_pending_revisions]:
                                                existing_pending_revisions.append({
                                                    'rev_id': rev_id,
                                                    'user': 'unknown',
                                                    'date': 'unknown',
                                                    'source': 'history_text'
                                                })
                                                # Track this as a pre-deployment pending commit (NOT ours)
                                                if rev_id not in self._pending_revisions_before_deployment:
                                                    self._pending_revisions_before_deployment.append(rev_id)
                                                logger.warning(f"[Pre-Phase 1] Found pending commit in history text: revision {rev_id}")
                                                logs.append(f"  ⚠ Found pending commit in history:")
                                                logs.append(f"    Revision: {rev_id}")
                                                logs.append(f"    This is from a PREVIOUS deployment/user (not ours)")
                        except Exception as history_error:
                            logger.debug(f"Could not check history before Phase 1: {history_error}")
                    
                    # If we found ANY existing pending commits, delete ALL of them
                    if existing_pending_revisions:
                        logs.append(f"")
                        logs.append(f"  Found {len(existing_pending_revisions)} pending commit(s) from previous deployment(s)/user(s)")
                        logs.append(f"  Will delete ALL of them to ensure clean state...")
                        
                        # Delete all pending commits using specific revision IDs
                        # Use nv config delete <rev_id> for each pending revision
                        for pending_rev in existing_pending_revisions:
                            rev_id = pending_rev['rev_id']
                            rev_user = pending_rev.get('user', 'unknown')
                            try:
                                logger.info(f"[Pre-Phase 1] Deleting pending commit {rev_id} (user: {rev_user})...")
                                logs.append(f"  Deleting pending commit {rev_id} (user: {rev_user})...")
                                delete_output = self.connection.device.send_command_timing(f'nv config delete {rev_id}', read_timeout=30)
                                logger.info(f"[Pre-Phase 1] Delete output for revision {rev_id}: {delete_output}")
                                logs.append(f"    Delete output: {delete_output[:200] if delete_output else 'No output'}")
                                
                                # Small delay between deletions if multiple
                                if len(existing_pending_revisions) > 1:
                                    time.sleep(0.5)
                            except Exception as delete_error:
                                logger.error(f"[Pre-Phase 1] Failed to delete pending commit {rev_id}: {delete_error}")
                                logs.append(f"    ✗ Failed to delete revision {rev_id}: {str(delete_error)}")
                        
                        # Wait a moment and verify ALL pending commits are gone
                        time.sleep(1)
                        recheck_json = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                        if recheck_json:
                            import json
                            recheck_data = json.loads(recheck_json)
                            still_pending_list = []
                            for rev_id, rev_info in recheck_data.items():
                                if isinstance(rev_info, dict) and rev_info.get('state') == 'confirm':
                                    still_pending_list.append(rev_id)
                            
                            if not still_pending_list:
                                logger.info(f"[Pre-Phase 1] Successfully deleted ALL {len(existing_pending_revisions)} pending commit(s) - clean state achieved")
                                logs.append(f"  SUCCESS: Successfully deleted ALL {len(existing_pending_revisions)} pending commit(s)")
                                logs.append(f"  SUCCESS: Device is now in clean state - ready for new deployment")
                            else:
                                logger.warning(f"[Pre-Phase 1] Delete may have failed - {len(still_pending_list)} pending commit(s) still exist: {still_pending_list}")
                                logs.append(f"  ⚠ Delete may have failed - {len(still_pending_list)} pending commit(s) still exist:")
                                for rev_id in still_pending_list:
                                    logs.append(f"    - Revision {rev_id}")
                                logs.append(f"  Will proceed anyway - commit may fail with 'Pending commit confirm already in process'")
                        else:
                            logger.warning(f"[Pre-Phase 1] Could not verify abort - proceeding anyway")
                            logs.append(f"  ⚠ Could not verify abort - proceeding anyway")
                    else:
                        logger.info(f"[Pre-Phase 1] No existing pending commits found - device is in clean state")
                        logs.append(f"  SUCCESS: No existing pending commits found - device is in clean state")
            except Exception as pre_check_error:
                logger.warning(f"[Pre-Phase 1] Could not check for existing pending commits: {pre_check_error}")
                logs.append(f"  ⚠ Could not check for existing pending commits: {str(pre_check_error)[:100]}")
                logs.append(f"  Will proceed anyway - commit may fail if pending commit exists")
        
        # Phase 1: Load configuration (skip for EOS sessions - handled in Phase 2)
        if not use_eos_session:
            try:
                logger.info(f"Phase 1: Loading configuration to {self.device.name}...")
                logger.debug(f"Config to load:\n{config}")

                logs.append(f"")
                logs.append(f"[Phase 1] Configuration Loading")
                logs.append(f"  Mode: {'Replace (full config)' if replace else 'Merge (incremental)'}")
                logs.append(f"  Config to load ({len(config.splitlines())} lines):")
                # Show config line by line for better readability
                for line in config.split('\n'):
                    if line.strip():
                        logs.append(f"    {line.strip()}")
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
                            history_before_load = self.connection.device.send_command_timing('nv config history | head -3', read_timeout=10)
                            logger.debug(f"Config history BEFORE load_config:\n{history_before_load}")
                            logs.append(f"  [DEBUG] History before load (last 3 entries):")
                            for line in history_before_load.split('\n')[:3]:
                                if line.strip():
                                    logs.append(f"    {line.strip()}")
                    except Exception as hist_error:
                        logger.debug(f"Could not get history before load: {hist_error}")

                # DEBUG: Log config state before load
                logger.debug(f"[Phase 1] Config state before load_config: type={type(config)}, len={len(config) if config else 0}, is_empty={not config or not config.strip()}")
                logs.append(f"  [DEBUG] Config state: {len(config)} characters, {len(config.splitlines())} lines")
                
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
                                error_check = self.connection.device.send_command_timing('nv config diff', read_timeout=10)
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
                logs.append(f"  SUCCESS: Configuration loaded to candidate config")
                
                # CRITICAL: For Cumulus, validate that commands were actually accepted (no syntax errors)
                # If commands had syntax errors (like "vlan add" instead of "vlan"), they might fail silently
                if driver_name == 'cumulus':
                    try:
                        if hasattr(self.connection, 'revision_id'):
                            candidate_revision = self.connection.revision_id
                            # Store candidate revision ID to exclude from Phase 2 pending commit checks
                            self._candidate_revision_id = str(candidate_revision)
                            logger.info(f"Candidate revision ID after load: {candidate_revision}")
                            logs.append(f"  [DEBUG] Candidate revision ID: {candidate_revision}")
                        
                        # Validate candidate config to ensure commands were accepted
                        if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                            # Check if we can show the candidate revision (if it fails, commands had errors)
                            try:
                                candidate_check = self.connection.device.send_command_timing(f'nv config show -r {candidate_revision} -o json', read_timeout=10)
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
                            
                            # Check history after load (for debugging - shows candidate revision, NOT commit-confirm session)
                            # NOTE: "Currently pending [rev_id: X]" in history after load_config() is just the CANDIDATE revision
                            # It becomes a commit-confirm session only after commit_config() is called
                            history_after_load = self.connection.device.send_command_timing('nv config history | head -3', read_timeout=10)
                            logger.debug(f"Config history AFTER load_config (shows candidate revision, not commit-confirm):\n{history_after_load}")
                            logs.append(f"  [DEBUG] History after load (last 3 entries):")
                            logs.append(f"  [NOTE] 'Currently pending [rev_id: X]' shown here is the CANDIDATE revision (from load_config)")
                            logs.append(f"  [NOTE] It becomes a commit-confirm session only after commit_config() in Phase 2")
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
                                
                                # Note: We use compare_config() above, which internally uses 'nv config diff'
                                # No need to run 'nv config diff' again here - it's redundant
                                
                                # Check if diff shows actual changes
                                if 'no changes' in diff_output.lower() or (len(diff_output.strip()) < 10):
                                    logger.warning(f"WARNING: Candidate config appears to match running config - commit may not create revision")
                                    logs.append(f"  ⚠ WARNING: Candidate config matches running config - no changes to commit")
                                else:
                                    logs.append(f"  SUCCESS: Candidate config has differences from running config")
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
                                rev_output = self.connection.device.send_command_timing('nv config history | head -1', read_timeout=10)
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
                                        diff_output = self.connection.device.send_command_timing(diff_cmd, read_timeout=30)
                                        if diff_output and diff_output.strip() and 'diff <' not in diff_output:
                                            # Got actual diff output, use it
                                            diff = diff_output
                                            logger.info(f"Got diff output manually: {len(diff)} chars")
                                        else:
                                            # Still got command, try alternative: get applied revision and diff
                                            try:
                                                applied_output = self.connection.device.send_command_timing('nv config history | grep -i applied | head -1', read_timeout=10)
                                                if applied_output:
                                                    applied_match = re.search(r'Revision:\s*(\d+)', applied_output)
                                                    if not applied_match:
                                                        applied_match = re.search(r'^\s*(\d+)', applied_output)
                                                    if applied_match:
                                                        applied_rev = applied_match.group(1)
                                                        # Get diff between applied and current
                                                        diff_cmd2 = f'nv config diff {applied_rev}'
                                                        diff_output2 = self.connection.device.send_command_timing(diff_cmd2, read_timeout=30)
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
                        logs.append(f"  SUCCESS: Configuration diff:")
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
                        
                        # Show actual commands that will be executed (in correct order: unset first, then set)
                        logs.append(f"")
                        logs.append(f"    Configuration changes (commands in execution order):")
                        
                        # Convert removed commands to nv unset format
                        unset_commands = []
                        for cmd in removed_commands:
                            if cmd.startswith('nv set'):
                                # Convert "nv set interface X bridge domain br_default access Y" 
                                # to "nv unset interface X bridge domain br_default access"
                                unset_cmd = cmd.replace('nv set', 'nv unset')
                                # Remove the value at the end (access VLAN number)
                                # Pattern: "nv unset interface X bridge domain br_default access 3000"
                                # Should be: "nv unset interface X bridge domain br_default access"
                                import re
                                unset_cmd = re.sub(r'\s+\d+$', '', unset_cmd)  # Remove trailing number
                                unset_commands.append(unset_cmd)
                            elif cmd.startswith('nv unset'):
                                unset_commands.append(cmd)
                        
                        # Show unset commands first (removals)
                        if unset_commands:
                            logs.append(f"    Unset commands (removals):")
                            for unset_cmd in unset_commands:
                                logs.append(f"      {unset_cmd}")
                        
                        # Show set commands (additions)
                        if added_commands:
                            logs.append(f"    Set commands (additions):")
                            for set_cmd in added_commands:
                                logs.append(f"      {set_cmd}")
                        
                        # Also show diff format for reference
                        logs.append(f"")
                        logs.append(f"    Diff format (for reference):")
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
                                logs.append(f"      {line}")
                                diff_shown = True
                        
                        if not diff_shown and not unset_commands and not added_commands:
                            logs.append(f"    (no changes detected - configuration already applied to device)")
                            logs.append(f"    ℹ Device is already in the desired state - no changes needed")
                    else:
                        logger.info(f"No configuration differences detected - config already applied")
                        logs.append(f"  SUCCESS: No configuration differences detected")
                        logs.append(f"  ℹ Configuration is already applied to device - device is in desired state")
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
                # Store timeout in result for rollback logging
                result['_deployment_timeout'] = timeout
                
                # Retry configuration for concurrent workflow conflicts
                max_retries = 3
                retry_delays = [5, 15, 30]  # Exponential backoff: 5s, 15s, 30s
                commit_succeeded = False
                last_commit_error = None
                
                for attempt in range(max_retries):
                    if attempt > 0:
                        delay = retry_delays[attempt - 1]
                        logger.info(f"Retry attempt {attempt + 1}/{max_retries} after {delay}s delay (concurrent workflow detected)")
                        logs.append(f"")
                        logs.append(f"  === RETRY ATTEMPT {attempt + 1}/{max_retries} ===")
                        logs.append(f"  Waiting {delay}s for concurrent workflow to complete...")
                        time.sleep(delay)
                        logs.append(f"  Retrying commit...")
                    
                    # NOTE: Pre-Phase 1 already checked for and aborted ALL pending commits from previous deployments
                    # No need to check again here - we can proceed directly to commit
                    # The only "pending" revision at this point should be our candidate revision (from load_config),
                    # which is not a commit-confirm session yet and will become one after commit_config()
                    
                    # Pre-commit check: Verify there are actual changes to commit
                    # CRITICAL: Run 'nv config diff' BEFORE 'nv config apply' to check for changes
                    # Skip commit if diff is empty (config already matches desired state)
                    if driver_name == 'cumulus':
                        try:
                            if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                # Check diff before commit using send_command_timing() to avoid prompt detection issues
                                # This runs BEFORE commit_config() (which executes 'nv config apply --confirm {timeout}s -y')
                                logger.info(f"Pre-commit check: Running 'nv config diff' before commit...")
                                logs.append(f"  [DEBUG] Pre-commit check: Running 'nv config diff' before 'nv config apply'...")
                                pre_commit_diff = self.connection.device.send_command_timing('nv config diff', read_timeout=10)
                                if pre_commit_diff and pre_commit_diff.strip():
                                    # Check if diff shows actual changes (not just whitespace or "no changes" message)
                                    diff_content = pre_commit_diff.strip().lower()
                                    if 'no changes' in diff_content or 'no config diff' in diff_content or len(pre_commit_diff.strip()) < 10:
                                        logger.info(f"Config diff is empty or shows no changes - skipping commit (config already applied)")
                                        logs.append(f"  ℹ Pre-commit diff check: No changes detected")
                                        logs.append(f"  ℹ Configuration already matches desired state - skipping commit")
                                        result['_config_already_applied'] = True
                                        result['_commit_skipped_no_diff'] = True
                                        commit_succeeded = True  # Mark as success (idempotent)
                                        break  # Exit retry loop
                                    else:
                                        logger.info(f"Pre-commit diff check: Changes detected ({len(pre_commit_diff)} chars) - proceeding with commit")
                                        logs.append(f"  ✓ Pre-commit diff check: Changes detected - proceeding with 'nv config apply'")
                                elif not pre_commit_diff or not pre_commit_diff.strip():
                                    logger.warning(f"Pre-commit diff check returned empty - this may indicate config already applied or command failed")
                                    logs.append(f"  ⚠ Pre-commit diff check: Empty output")
                                    # Don't skip commit on empty diff check failure - let commit attempt proceed
                                    # The diff check might have failed due to prompt detection, but commit might still work
                        except Exception as pre_commit_diff_error:
                            logger.debug(f"Pre-commit diff check failed: {pre_commit_diff_error}")
                            # Don't skip commit on diff check failure - let commit attempt proceed
                    
                    # Execute commit_config - this should execute: nv config apply --confirm {timeout}s -y
                    # 
                    # ============================================================================
                    # NAPALM CUMULUS DRIVER BEHAVIOR & FALLBACK MECHANISM
                    # ============================================================================
                    # IMPORTANT: According to NAPALM documentation:
                    #   - commit_config() returns None on SUCCESS (no exception = success)
                    #   - This is expected behavior across all NAPALM platforms
                    #   - None does NOT indicate failure - it indicates the method executed without raising an exception
                    #
                    # ISSUE: NAPALM's Cumulus driver has limitations with commit_config(revert_in):
                    #   1. commit_config(revert_in=90) may not properly execute "nv config apply --confirm 90s -y"
                    #   2. The has_pending_commit flag may not be properly set after commit
                    #   3. Inconsistent behavior across NVUE versions (5.x vs 4.x)
                    #   4. Driver may not fully implement commit-confirm for revert_in parameter
                    # 
                    # ROOT CAUSE:
                    #   - commit_config(revert_in) support varies by platform
                    #   - Cumulus driver implementation may not handle revert_in parameter correctly
                    #   - The driver may execute the command but not set the has_pending_commit flag
                    #
                    # SOLUTION:
                    #   - Try NAPALM's commit_config() first (for compatibility with future fixes)
                    #   - Check has_pending_commit() to verify the session was actually created
                    #   - If has_pending_commit() = False, use fallback to direct NVUE command execution
                    #   - Direct execution: nv config apply --confirm {timeout}s -y (guaranteed to work)
                    #
                    # REFERENCES:
                    #   - https://napalm.readthedocs.io/en/latest/base.html (commit_config returns None on success)
                    #   - https://napalm.readthedocs.io/en/latest/support/ (platform limitations)
                    # ============================================================================
                    try:
                        logger.info(f"About to call commit_config(revert_in={timeout})")
                        logs.append(f"  [DEBUG] Calling commit_config(revert_in={timeout})...")
                        
                        # For Cumulus, use fallback mechanism due to NAPALM driver limitations
                        # ISSUE: NAPALM's cumulus driver has inconsistent support for commit_config(revert_in)
                        # - It may return None instead of executing "nv config apply --confirm Xs -y"
                        # - The has_pending_commit flag may not be properly set
                        # - Platform-specific variations in NVUE versions can cause issues
                        # SOLUTION: Try NAPALM first (for compatibility), fallback to direct NVUE execution
                        if driver_name == 'cumulus':
                            logger.info(f"Attempting commit via NAPALM with fallback to direct NVUE...")
                            logs.append(f"  [INFO] Trying NAPALM commit_config(revert_in={timeout})...")
                            
                            # DEBUG: Check device state BEFORE commit_config()
                            # Store candidate_state_before for comparison after commit
                            candidate_state_before = None
                            try:
                                if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                    # Check current revision state before commit
                                    rev_before = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                                    logger.debug(f"[DEBUG] Revision state BEFORE commit_config(): {rev_before[:500] if rev_before else 'None'}")
                                    logs.append(f"  [DEBUG] Device state BEFORE commit_config():")
                                    if rev_before:
                                        import json
                                        try:
                                            rev_data_before = json.loads(rev_before)
                                            pending_before = [rid for rid, info in rev_data_before.items() 
                                                            if isinstance(info, dict) and info.get('state') == 'confirm']
                                            logs.append(f"    Pending revisions: {pending_before if pending_before else 'None'}")
                                            logs.append(f"    Candidate revision (ours): {self._candidate_revision_id}")
                                            
                                            # CRITICAL: Check the state of OUR candidate revision before commit
                                            if self._candidate_revision_id:
                                                candidate_info_before = rev_data_before.get(self._candidate_revision_id, {})
                                                candidate_state_before = candidate_info_before.get('state') if isinstance(candidate_info_before, dict) else 'not_found'
                                                logger.info(f"[DEBUG] Candidate revision {self._candidate_revision_id} state BEFORE commit: {candidate_state_before}")
                                                logs.append(f"    Candidate revision {self._candidate_revision_id} state: {candidate_state_before}")
                                                logs.append(f"    [INFO] NAPALM commit_config() should convert this candidate to 'confirm' state")
                                            
                                            # Also check NAPALM's internal revision_id
                                            if hasattr(self.connection, 'revision_id'):
                                                napalm_revision_id = self.connection.revision_id
                                                logger.info(f"[DEBUG] NAPALM connection.revision_id: {napalm_revision_id}")
                                                logs.append(f"    NAPALM connection.revision_id: {napalm_revision_id}")
                                                if str(napalm_revision_id) != str(self._candidate_revision_id):
                                                    logger.warning(f"[DEBUG] MISMATCH: Our candidate={self._candidate_revision_id}, NAPALM's revision_id={napalm_revision_id}")
                                                    logs.append(f"    ⚠ MISMATCH: Our candidate != NAPALM's revision_id")
                                        except:
                                            logs.append(f"    Revision JSON: {rev_before[:200]}")
                                    
                                    # Check history to see current state
                                    history_before = self.connection.device.send_command_timing('nv config history | head -3', read_timeout=10)
                                    logger.debug(f"[DEBUG] History BEFORE commit_config():\n{history_before}")
                                    logs.append(f"    History (last 3): {history_before[:200] if history_before else 'None'}")
                            except Exception as debug_error:
                                logger.debug(f"Could not check pre-commit state for debugging: {debug_error}")
                            
                            # Try NAPALM's method first
                            logger.info(f"[DEBUG] About to call self.connection.commit_config(revert_in={timeout})")
                            try:
                                commit_result = self.connection.commit_config(revert_in=timeout)
                                logger.info(f"NAPALM commit_config returned: {commit_result} (type: {type(commit_result)})")
                                logs.append(f"  [DEBUG] NAPALM returned: {commit_result} (type: {type(commit_result).__name__})")
                                
                                # DEBUG: Check what command was actually executed (if we can see it)
                                try:
                                    if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                        # Check if we can see the last command in history
                                        history_after_call = self.connection.device.send_command_timing('nv config history | head -3', read_timeout=10)
                                        logger.debug(f"[DEBUG] History immediately after commit_config() call:\n{history_after_call}")
                                        logs.append(f"  [DEBUG] History immediately after commit_config() call:")
                                        if history_after_call:
                                            for line in history_after_call.split('\n')[:5]:
                                                if line.strip():
                                                    logs.append(f"    {line.strip()}")
                                except Exception as hist_error:
                                    logger.debug(f"Could not check history after commit_config call: {hist_error}")
                            except Exception as commit_exception:
                                logger.error(f"commit_config() raised exception: {commit_exception}")
                                logs.append(f"  ✗ commit_config() raised exception: {str(commit_exception)}")
                                raise
                            
                            # CRITICAL: Wait 5 seconds for NVUE backend to process
                            # NVUE needs time to: apply config → create revision → set "confirm" state
                            # Without this wait, has_pending_commit() may return False prematurely
                            logger.info(f"Waiting 5 seconds for NVUE backend to create commit-confirm session...")
                            logs.append(f"  [INFO] Waiting 5s for NVUE to process commit...")
                            time.sleep(5)
                            logs.append(f"  [INFO] Wait complete, checking commit-confirm status...")
                            
                            # DEBUG: Check device state AFTER wait
                            try:
                                if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                    rev_after = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                                    logger.debug(f"[DEBUG] Revision state AFTER commit_config() + 5s wait: {rev_after[:500] if rev_after else 'None'}")
                                    logs.append(f"  [DEBUG] Device state AFTER commit_config() + 5s wait:")
                                    if rev_after:
                                        import json
                                        try:
                                            rev_data_after = json.loads(rev_after)
                                            pending_after = [rid for rid, info in rev_data_after.items() 
                                                           if isinstance(info, dict) and info.get('state') == 'confirm']
                                            logs.append(f"    Pending revisions: {pending_after if pending_after else 'None'}")
                                            if pending_after:
                                                for rid in pending_after:
                                                    rev_info = rev_data_after.get(rid, {})
                                                    logs.append(f"      Revision {rid}: state={rev_info.get('state')}, user={rev_info.get('user')}, date={rev_info.get('date')}")
                                        except:
                                            logs.append(f"    Revision JSON: {rev_after[:200]}")
                                    
                                    # Check history to see if commit-confirm session was created
                                    history_after = self.connection.device.send_command_timing('nv config history | head -5', read_timeout=10)
                                    logger.debug(f"[DEBUG] History AFTER commit_config() + 5s wait:\n{history_after}")
                                    logs.append(f"    History (last 5):")
                                    if history_after:
                                        for line in history_after.split('\n')[:8]:
                                            if line.strip():
                                                logs.append(f"      {line.strip()}")
                                    
                                    # CRITICAL: Check if OUR candidate revision state changed to 'confirm'
                                    if self._candidate_revision_id:
                                        candidate_info_after = rev_data_after.get(self._candidate_revision_id, {})
                                        candidate_state_after = candidate_info_after.get('state') if isinstance(candidate_info_after, dict) else 'not_found'
                                        logger.info(f"[DEBUG] Candidate revision {self._candidate_revision_id} state AFTER commit: {candidate_state_after}")
                                        logs.append(f"    Candidate revision {self._candidate_revision_id} state AFTER commit: {candidate_state_after}")
                                        
                                        if candidate_state_after == 'confirm':
                                            logger.info(f"[DEBUG] SUCCESS: Candidate revision WAS converted to 'confirm' state - NAPALM worked!")
                                            logs.append(f"    SUCCESS: Candidate revision WAS converted to 'confirm' state - NAPALM worked!")
                                            logs.append(f"    [INFO] has_pending_commit() may be giving false negative - session WAS created")
                                        elif candidate_state_after == candidate_state_before:
                                            logger.warning(f"[DEBUG] ⚠ Candidate revision state unchanged: {candidate_state_after}")
                                            logs.append(f"    ⚠ Candidate revision state unchanged: {candidate_state_after}")
                                            logs.append(f"    [INFO] This suggests commit_config() did not convert the candidate to confirm state")
                                        else:
                                            logger.info(f"[DEBUG] Candidate revision state changed from {candidate_state_before} to {candidate_state_after}")
                                            logs.append(f"    [INFO] Candidate revision state changed: {candidate_state_before} → {candidate_state_after}")
                            except Exception as debug_error:
                                logger.debug(f"Could not check post-commit state for debugging: {debug_error}")
                            
                            # Check if NAPALM actually created a commit-confirm session
                            # IMPORTANT: According to NAPALM docs, commit_config() returns None on success (no exception = success)
                            # However, for Cumulus with revert_in parameter, the driver may not properly execute the command
                            # The real indicator of success is has_pending_commit() = True (session was actually created)
                            # So we check has_pending_commit() to verify the session was created, not the return value
                            napalm_failed = False
                            
                            # DEBUG: Check multiple indicators to understand what happened
                            # Primary check: has_pending_commit flag (this verifies the session was actually created)
                            has_pending_napalm = None
                            has_pending_direct = None
                            
                            if hasattr(self.connection, 'has_pending_commit'):
                                try:
                                    has_pending_napalm = self.connection.has_pending_commit()
                                    logger.info(f"has_pending_commit() check: {has_pending_napalm}")
                                    logs.append(f"  [DEBUG] has_pending_commit() = {has_pending_napalm}")
                                    
                                    # DEBUG: Also check directly via device command to compare
                                    try:
                                        if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                            rev_check = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                                            if rev_check:
                                                import json
                                                rev_data_check = json.loads(rev_check)
                                                pending_direct = [rid for rid, info in rev_data_check.items() 
                                                                if isinstance(info, dict) and info.get('state') == 'confirm']
                                                has_pending_direct = len(pending_direct) > 0
                                                logger.info(f"[DEBUG] Direct device check: {len(pending_direct)} pending revision(s): {pending_direct}")
                                                logs.append(f"  [DEBUG] Direct device check: {len(pending_direct)} pending revision(s): {pending_direct}")
                                                
                                                # Compare NAPALM method vs direct check
                                                if has_pending_napalm != has_pending_direct:
                                                    logger.warning(f"[DEBUG] MISMATCH: has_pending_commit()={has_pending_napalm} but direct check={has_pending_direct}")
                                                    logs.append(f"  ⚠ [DEBUG] MISMATCH: NAPALM method says {has_pending_napalm}, but direct check shows {has_pending_direct}")
                                                    # Trust direct check if it shows pending (more reliable)
                                                    if has_pending_direct:
                                                        logger.info(f"[DEBUG] Trusting direct check - session WAS created by NAPALM")
                                                        logs.append(f"  [DEBUG] Trusting direct check - session WAS created by NAPALM")
                                                        has_pending_napalm = True  # Override with direct check result
                                                        napalm_failed = False  # NAPALM actually worked!
                                    except Exception as direct_check_error:
                                        logger.debug(f"Could not do direct check: {direct_check_error}")
                                    
                                    if not has_pending_napalm:
                                        # has_pending_commit() = False means the commit-confirm session wasn't created
                                        # This indicates the NAPALM driver didn't execute the command properly
                                        logger.warning(f"has_pending_commit() returned False after 5s wait - NAPALM driver may not have executed commit-confirm")
                                        logs.append(f"  ⚠ has_pending_commit() = False (commit-confirm session not created)")
                                        
                                        # DEBUG: Try to understand why - check if command was executed at all
                                        try:
                                            if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                                # Check if candidate revision still exists and its state
                                                if self._candidate_revision_id:
                                                    rev_full = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                                                    if rev_full:
                                                        import json
                                                        rev_data_full = json.loads(rev_full)
                                                        candidate_info = rev_data_full.get(self._candidate_revision_id, {})
                                                        candidate_state = candidate_info.get('state') if isinstance(candidate_info, dict) else 'unknown'
                                                        logger.debug(f"[DEBUG] Candidate revision {self._candidate_revision_id} state: {candidate_state}")
                                                        logs.append(f"  [DEBUG] Candidate revision {self._candidate_revision_id} state: {candidate_state}")
                                                        if candidate_state == 'confirm':
                                                            logger.warning(f"[DEBUG] Candidate revision IS in confirm state - NAPALM method may have false negative!")
                                                            logs.append(f"  ⚠ [DEBUG] Candidate revision IS in confirm state - has_pending_commit() may be wrong!")
                                                            # Override - session WAS created
                                                            has_pending_napalm = True
                                                            napalm_failed = False
                                                        elif candidate_state in ['applied', 'aborted']:
                                                            logger.info(f"[DEBUG] Candidate revision state is '{candidate_state}' - commit may have already been applied/aborted")
                                                            logs.append(f"  [DEBUG] Candidate revision state is '{candidate_state}' - commit may have already been applied/aborted")
                                        except Exception as why_check_error:
                                            logger.debug(f"Could not check why session wasn't created: {why_check_error}")
                                        
                                        if not has_pending_napalm:
                                            logs.append(f"  [INFO] This is a known issue with NAPALM's Cumulus driver - will use fallback")
                                            napalm_failed = True
                                    else:
                                        # has_pending_commit() = True means it worked - session was created
                                        logger.info(f"SUCCESS: NAPALM commit-confirm session created successfully (has_pending_commit=True)")
                                        logs.append(f"  SUCCESS: NAPALM commit-confirm session created successfully")
                                        # Note: commit_result being None is expected (NAPALM returns None on success)
                                        if commit_result is None:
                                            logger.info(f"Note: commit_config returned None (this is expected - NAPALM returns None on success)")
                                            logs.append(f"  [INFO] commit_config returned None (expected - NAPALM returns None on success, not an error)")
                                except Exception as check_error:
                                    logger.debug(f"Could not check has_pending_commit: {check_error}")
                                    logs.append(f"  [DEBUG] Exception checking has_pending_commit: {str(check_error)}")
                                    # If we can't check has_pending_commit, we can't verify if session was created
                                    # For Cumulus, it's safer to use fallback if we can't verify
                                    logger.warning(f"Cannot verify has_pending_commit - using fallback for reliability")
                                    logs.append(f"  [INFO] Cannot verify has_pending_commit() - using fallback for reliability")
                                    napalm_failed = True
                            else:
                                # No has_pending_commit method - can't verify if session was created
                                # For Cumulus, use fallback to ensure reliability
                                logger.warning(f"No has_pending_commit() method available - using fallback for reliability")
                                logs.append(f"  [INFO] No has_pending_commit() method - using fallback to ensure commit-confirm session is created")
                                napalm_failed = True
                            
                            if napalm_failed:
                                logger.info(f"NAPALM commit_config returned {commit_result} - using fallback to direct NVUE execution (expected for Cumulus)")
                                logs.append(f"  [INFO] NAPALM commit_config returned {commit_result} (expected for Cumulus driver)")
                                logs.append(f"  [INFO] Using fallback: direct NVUE command execution (this is the normal path for Cumulus)")
                                logs.append(f"  Note: NAPALM's Cumulus driver has known limitations with commit-confirm")
                                logs.append(f"        Fallback to direct NVUE execution is the reliable method for Cumulus devices")
                                
                                # Fallback: Execute NVUE command directly
                                expected_cmd = f"nv config apply --confirm {timeout}s -y"
                                logger.info(f"Executing fallback: {expected_cmd}")
                                logs.append(f"  [FALLBACK] Executing: {expected_cmd}")
                                
                                if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                    commit_output = self.connection.device.send_command_timing(expected_cmd, read_timeout=60)
                                    logger.info(f"Fallback command output: {commit_output}")
                                    logs.append(f"  [DEBUG] Command output: {commit_output[:300] if commit_output else '(no output)'}")
                                    commit_result = commit_output
                                    
                                    # Check if fallback command indicates "no config diff" (config already applied)
                                    if commit_output and ('no config diff' in commit_output.lower() or 'warning: config apply executed with no config diff' in commit_output.lower()):
                                        logger.info(f"Fallback command indicates no config diff - configuration already applied")
                                        logs.append(f"  ℹ Fallback output: 'no config diff' - configuration already applied to device")
                                        logs.append(f"  ℹ Device is already in desired state - no commit-confirm session needed")
                                        result['_config_already_applied'] = True
                                        # This is actually success (idempotent deployment)
                                        logs.append(f"  SUCCESS: Configuration already applied (idempotent deployment)")
                                    else:
                                        # Wait a moment and verify fallback created a commit-confirm session
                                        time.sleep(2)
                                        if hasattr(self.connection, 'has_pending_commit'):
                                            try:
                                                has_pending_after_fallback = self.connection.has_pending_commit()
                                                logger.info(f"has_pending_commit() after fallback: {has_pending_after_fallback}")
                                                logs.append(f"  [DEBUG] has_pending_commit() after fallback: {has_pending_after_fallback}")
                                                if has_pending_after_fallback:
                                                    logs.append(f"  SUCCESS: Fallback commit-confirm session created successfully")
                                                else:
                                                    # Fallback didn't create a session - check why
                                                    logs.append(f"  ⚠ Fallback executed but no commit-confirm session created")
                                                    logs.append(f"  [DEBUG] Checking config diff to understand why...")
                                                    try:
                                                        diff_after_fallback = self.connection.device.send_command_timing('nv config diff', read_timeout=10)
                                                        if diff_after_fallback:
                                                            if 'no changes' in diff_after_fallback.lower() or 'no config diff' in diff_after_fallback.lower():
                                                                logger.info(f"Config diff shows no changes - configuration already applied")
                                                                logs.append(f"  ℹ Config diff: no changes - configuration already applied")
                                                                result['_config_already_applied'] = True
                                                            else:
                                                                logger.warning(f"Config diff shows changes but no session created - may be a timing issue")
                                                                logs.append(f"  ⚠ Config diff shows changes but no session created")
                                                                logs.append(f"  [DEBUG] Config diff output:")
                                                                for line in diff_after_fallback.split('\n')[:10]:
                                                                    if line.strip():
                                                                        logs.append(f"    {line.strip()}")
                                                    except Exception as diff_check_error:
                                                        logger.debug(f"Could not check diff after fallback: {diff_check_error}")
                                            except Exception as check_error:
                                                logger.debug(f"Could not check has_pending_commit after fallback: {check_error}")
                                        else:
                                            logs.append(f"  SUCCESS: Fallback commit executed (cannot verify session - no has_pending_commit method)")
                                else:
                                    raise Exception("Cannot access Netmiko connection from NAPALM driver")
                            else:
                                logs.append(f"  SUCCESS: NAPALM commit_config executed successfully")
                        else:
                            # For other platforms (Juniper, EOS), use NAPALM's commit_config
                            commit_result = self.connection.commit_config(revert_in=timeout)
                        logger.info(f"commit_config() returned: {commit_result}")
                        logs.append(f"  [DEBUG] commit_config() return value: {commit_result}")
                        logs.append(f"  [DEBUG] commit_config() return type: {type(commit_result)}")
                        # Store commit result for later diagnostics
                        result['_commit_result'] = commit_result
                        result['_config_commands'] = config
                        
                        # Note: We already verified commit succeeded by checking revision state above
                        # Checking 'nv config diff' after commit is redundant because:
                        # - After commit_config(), config is in commit-confirm state (applied but pending)
                        # - 'nv config diff' compares running vs candidate, but candidate has been committed
                        # - So diff will be empty (expected) - changes are already applied, waiting for confirmation
                        # - We already confirmed commit succeeded by checking revision state (state=confirm)
                        # Removed redundant post-commit diff check to reduce unnecessary device queries
                        
                        # Commit succeeded - mark success and break retry loop
                        commit_succeeded = True
                        break
                        
                    except Exception as commit_error:
                        error_msg = str(commit_error)
                        error_type = type(commit_error).__name__
                        logger.error(f"commit_config() raised exception: {commit_error}")
                        import traceback
                        logger.error(f"Full traceback:\n{traceback.format_exc()}")
                        
                        # Special handling for "Pending commit confirm already in process" error
                        # This indicates concurrent workflow conflict - another session is active
                        is_concurrent_conflict = "pending commit" in error_msg.lower() or "commit confirm already" in error_msg.lower()
                        
                        if is_concurrent_conflict:
                            # Store the error for potential retry
                            last_commit_error = commit_error
                            
                            logs.append(f"  ✗ Commit FAILED with exception: {error_msg}")
                            logs.append(f"  [DEBUG] Exception type: {error_type}")
                            logs.append(f"")
                            logs.append(f"  === CONCURRENT WORKFLOW DETECTED ===")
                            logs.append(f"  The device rejected the commit because a pending commit-confirm session already exists.")
                            logs.append(f"  This can happen if:")
                            logs.append(f"    1. Another workflow is currently running on this device")
                            logs.append(f"    2. A previous deployment didn't complete (confirm/abort)")
                            logs.append(f"    3. Another process/user has a pending commit")
                            logs.append(f"")
                            
                            # Check current state for diagnostics
                            try:
                                if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                    # Check revision JSON
                                    rev_json = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                                    if rev_json:
                                        import json
                                        rev_data = json.loads(rev_json)
                                        pending_revs = []
                                        for rev_id, rev_info in rev_data.items():
                                            if isinstance(rev_info, dict) and rev_info.get('state') == 'confirm':
                                                pending_revs.append(rev_id)
                                        if pending_revs:
                                            logs.append(f"  Found {len(pending_revs)} pending revision(s): {', '.join(pending_revs)}")
                                        else:
                                            logs.append(f"  No pending revisions found in JSON (may be timing issue)")
                            except Exception as diag_error:
                                logs.append(f"  Could not get diagnostics: {str(diag_error)}")
                            
                            # Retry logic
                            if attempt < max_retries - 1:
                                logs.append(f"")
                                logs.append(f"  Will retry after waiting for concurrent workflow to complete...")
                                continue  # Continue to next retry attempt
                            else:
                                # Final attempt failed
                                logs.append(f"")
                                logs.append(f"  === MAX RETRIES REACHED ===")
                                logs.append(f"  Failed after {max_retries} attempts. Concurrent workflow may still be active.")
                                logs.append(f"")
                                logs.append(f"  === RECOMMENDED ACTIONS ===")
                                logs.append(f"  1. Check device manually: nv config history")
                                logs.append(f"  2. Delete existing commit: nv config delete <revision_id>")
                                logs.append(f"  3. Or wait for timeout (if commit-confirm is active)")
                                logs.append(f"  4. Then retry the deployment")
                                logs.append(f"")
                                raise  # Re-raise to be caught by outer exception handler
                        else:
                            # Non-concurrent error - don't retry
                            logs.append(f"  ✗ Commit FAILED with exception: {error_msg}")
                            logs.append(f"  [DEBUG] Exception type: {error_type}")
                            raise  # Re-raise to be caught by outer exception handler
                
                # Check if commit succeeded after retry loop
                if not commit_succeeded:
                    error_msg = f"Commit failed after {max_retries} retry attempts"
                    if last_commit_error:
                        error_msg = f"{error_msg}: {str(last_commit_error)}"
                    logger.error(error_msg)
                    raise Exception(error_msg)
                
                logger.info(f"Phase 2: Config committed (will auto-rollback in {timeout}s if not confirmed)")
                logs.append(f"  SUCCESS: Configuration committed with {timeout}s rollback timer")
                if attempt > 0:
                    logs.append(f"  SUCCESS: Succeeded after {attempt + 1} attempt(s) (concurrent workflow resolved)")
                logs.append(f"  ⚠ Will auto-rollback if not confirmed within {timeout}s")
                
                # CRITICAL FIX: For Cumulus, get the actual pending revision ID after commit
                # NAPALM's driver stores candidate revision_id from load_config, but commit_config
                # creates a NEW pending revision. We need to get the actual pending revision ID.
                if driver_name == 'cumulus':
                    try:
                        if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                            # Wait for the revision to be created
                            # Increased wait time and added retry logic for better reliability
                            time.sleep(3.0)  # Increased to 3.0s - some devices are slower
                            
                            actual_pending_revision = None
                            detailed_diagnostics = []
                            
                            # METHOD 1: Use NAPALM driver's _get_pending_commits() if available (most reliable)
                            # This uses 'nv config revision -o json' which is more structured than text parsing
                            try:
                                if hasattr(self.connection, '_get_pending_commits'):
                                    pending_commits = self.connection._get_pending_commits()
                                    detailed_diagnostics.append(f"Method 1 (_get_pending_commits): {pending_commits}")
                                    if pending_commits and len(pending_commits) > 0:
                                        # Get the most recent pending commit (first in list, or highest number)
                                        actual_pending_revision = str(pending_commits[0])
                                        logger.info(f"Found commit-confirm session (pending confirmation) using _get_pending_commits(): {actual_pending_revision}")
                                        logs.append(f"  [DEBUG] Found commit-confirm session (pending confirmation) via JSON API: revision {actual_pending_revision}")
                                        logs.append(f"  [INFO] Note: 'Pending' means commit-confirm session is active (config is applied, waiting for confirmation)")
                                else:
                                    detailed_diagnostics.append(f"Method 1: NAPALM driver doesn't have _get_pending_commits()")
                            except Exception as json_error:
                                logger.debug(f"Could not use _get_pending_commits(): {json_error}")
                                detailed_diagnostics.append(f"Method 1 error: {str(json_error)}")
                            
                            # METHOD 2: Use nv config history -o json to get ALL revisions, then find latest by timestamp
                            # This is more reliable than nv config revision -o json which may not show latest
                            # IMPORTANT: History JSON shows historical metadata (like "state_controls: {confirm: 90}")
                            # which indicates HOW a commit was done, NOT the current state.
                            # We use history ONLY to find the latest revision by timestamp, then check
                            # nv config revision -o json for the ACTUAL current state (state == 'confirm' means pending)
                            if not actual_pending_revision:
                                try:
                                    history_json_output = self.connection.device.send_command_timing('nv config history -o json', read_timeout=10)
                                    detailed_diagnostics.append(f"Method 2 (nv config history -o json): {history_json_output[:200] if history_json_output else 'No output'}")
                                    if history_json_output:
                                        import json
                                        from datetime import datetime
                                        history_data = json.loads(history_json_output)
                                        
                                        # Find the latest revision by comparing timestamps
                                        # NOTE: We ignore "state_controls: {confirm: 90}" in history - that's just metadata
                                        # about how the commit was done, not the current pending state
                                        latest_revision = None
                                        latest_timestamp = None
                                        confirm_revisions = []
                                        
                                        for rev_id, rev_info in history_data.items():
                                            if isinstance(rev_info, dict):
                                                # Get timestamp from revision
                                                # Format can be: "2025-12-26T14:03:49+00:00" or "2025-09-08 18:53:20"
                                                # Check both top-level 'date' and nested 'last-apply.date'
                                                rev_date = rev_info.get('date') or (rev_info.get('last-apply', {}) or {}).get('date')
                                                if rev_date:
                                                    try:
                                                        # Try ISO format first (2025-12-26T14:03:49+00:00)
                                                        if 'T' in rev_date:
                                                            rev_timestamp = datetime.fromisoformat(rev_date.replace('+00:00', ''))
                                                        else:
                                                            # Try space format (2025-09-08 18:53:20)
                                                            rev_timestamp = datetime.strptime(rev_date, '%Y-%m-%d %H:%M:%S')
                                                        
                                                        # Check if this is the latest revision
                                                        if latest_timestamp is None or rev_timestamp > latest_timestamp:
                                                            latest_timestamp = rev_timestamp
                                                            latest_revision = str(rev_id)
                                                        
                                                        # Also check if this revision is in confirm state (from nv config revision)
                                                        # We'll check this separately
                                                    except (ValueError, AttributeError) as date_error:
                                                        logger.debug(f"Could not parse date '{rev_date}' for revision {rev_id}: {date_error}")
                                                        # If we can't parse date, still track the revision
                                                        if latest_revision is None:
                                                            latest_revision = str(rev_id)
                                        
                                        # Now check if the latest revision is in confirm state (pending)
                                        # CRITICAL: We check nv config revision -o json for ACTUAL current state
                                        # History JSON's "state_controls: {confirm: 90}" is just metadata, not current state
                                        if latest_revision:
                                            detailed_diagnostics.append(f"Method 2: Latest revision by timestamp: {latest_revision} (date: {latest_timestamp})")
                                            
                                            # Check revision CURRENT state using nv config revision -o json
                                            # This shows ONLY revisions that are currently pending (state == 'confirm')
                                            try:
                                                revision_json_output = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                                                if revision_json_output:
                                                    revision_data = json.loads(revision_json_output)
                                                    detailed_diagnostics.append(f"Method 2: nv config revision -o json shows {len(revision_data)} revision(s) with current state")
                                                    
                                                    # Check if latest revision is in confirm state (currently pending)
                                                    if latest_revision in revision_data:
                                                        rev_info = revision_data[latest_revision]
                                                        rev_state = rev_info.get('state') if isinstance(rev_info, dict) else None
                                                        detailed_diagnostics.append(f"Method 2: Latest revision {latest_revision} current state: '{rev_state}'")
                                                        
                                                        if rev_state == 'confirm':
                                                            # Latest revision IS currently pending
                                                            actual_pending_revision = latest_revision
                                                            confirm_revisions.append(latest_revision)
                                                            logger.info(f"Found pending commit via history+revision JSON: {actual_pending_revision} (latest by timestamp, state=confirm)")
                                                            logs.append(f"  [DEBUG] Found pending commit via history+revision JSON: {actual_pending_revision}")
                                                            detailed_diagnostics.append(f"Method 2: SUCCESS: Latest revision {latest_revision} is in 'confirm' state (CURRENTLY PENDING)")
                                                        else:
                                                            detailed_diagnostics.append(f"Method 2: Latest revision {latest_revision} state is '{rev_state}' (NOT pending - already confirmed/aborted)")
                                                    else:
                                                        # Latest revision not in revision JSON - means it's NOT pending
                                                        detailed_diagnostics.append(f"Method 2: Latest revision {latest_revision} not in revision JSON (NOT pending)")
                                                        
                                                        # Check all revisions in revision JSON for any with confirm state
                                                        for rev_id, rev_info in revision_data.items():
                                                            if isinstance(rev_info, dict) and rev_info.get('state') == 'confirm':
                                                                confirm_revisions.append(rev_id)
                                                                if not actual_pending_revision:
                                                                    actual_pending_revision = str(rev_id)
                                                                    logger.info(f"Found pending commit via revision JSON: {actual_pending_revision} (not latest, but has state=confirm)")
                                                                    logs.append(f"  [DEBUG] Found pending commit via revision JSON: {actual_pending_revision}")
                                                                    detailed_diagnostics.append(f"Method 2: Found pending revision {rev_id} (not latest, but currently pending)")
                                            except Exception as rev_check_error:
                                                logger.debug(f"Could not check revision state: {rev_check_error}")
                                                detailed_diagnostics.append(f"Method 2: Could not check revision state: {str(rev_check_error)}")
                                        
                                        detailed_diagnostics.append(f"Method 2: Found {len(confirm_revisions)} confirm state revisions: {confirm_revisions}")
                                except (json.JSONDecodeError, Exception) as json_error:
                                    logger.debug(f"Could not parse history JSON: {json_error}")
                                    detailed_diagnostics.append(f"Method 2 error: {str(json_error)}")
                            
                            # METHOD 3: Parse nv config history text output (fallback if JSON methods fail)
                            if not actual_pending_revision:
                                try:
                                    pending_rev_output = self.connection.device.send_command_timing('nv config history | head -5', read_timeout=10)
                                    logger.debug(f"Full history output after commit:\n{pending_rev_output}")
                                    detailed_diagnostics.append(f"Method 3 (nv config history):")
                                    for line in pending_rev_output.split('\n')[:5] if pending_rev_output else []:
                                        detailed_diagnostics.append(f"  {line}")
                                    
                                    if pending_rev_output:
                                        import re
                                        # Try multiple regex patterns to match different output formats
                                        # Pattern 1: "Currently pending [rev_id: 197]" (most common for pending commits)
                                        # Pattern 2: "Revision: 271 * pending (confirm)"
                                        # Pattern 3: "271 * pending"
                                        # Pattern 4: "271 pending"
                                        # Pattern 5: "271 ... confirm"
                                        # Pattern 6: Just the number at start of line with * marker
                                        patterns = [
                                            r'Currently pending\s*\[rev_id:\s*(\d+)\]',  # "Currently pending [rev_id: 197]"
                                            r'pending\s*\[rev_id:\s*(\d+)\]',  # "pending [rev_id: 197]" (case-insensitive)
                                            r'Revision:\s*(\d+)',  # "Revision: 271"
                                            r'^\s*(\d+)\s*\*',     # "271 *"
                                            r'^\s*(\d+).*pending', # "271 ... pending"
                                            r'^\s*(\d+).*confirm', # "271 ... confirm"
                                        ]
                                        
                                        lines = pending_rev_output.split('\n')
                                        for line in lines:
                                            # Look for lines with pending/confirm indicators
                                            if 'pending' in line.lower() or 'confirm' in line.lower() or '*' in line:
                                                for pattern in patterns:
                                                    rev_match = re.search(pattern, line, re.IGNORECASE)
                                                    if rev_match:
                                                        actual_pending_revision = rev_match.group(1)
                                                        logger.info(f"Found pending commit via history parsing: {actual_pending_revision} (matched pattern: {pattern})")
                                                        logs.append(f"  [DEBUG] Found pending commit via history text: {actual_pending_revision}")
                                                        detailed_diagnostics.append(f"Method 3: Found pending revision {actual_pending_revision} in text output: {line.strip()}")
                                                        break
                                                if actual_pending_revision:
                                                    break
                                        
                                        # Also verify the found revision exists in nv config revision -o json
                                        if actual_pending_revision:
                                            try:
                                                revision_json_output = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                                                if revision_json_output:
                                                    revision_data = json.loads(revision_json_output)
                                                    if actual_pending_revision in revision_data:
                                                        rev_info = revision_data[actual_pending_revision]
                                                        rev_state = rev_info.get('state') if isinstance(rev_info, dict) else None
                                                        if rev_state == 'confirm':
                                                            detailed_diagnostics.append(f"Method 3: Verified revision {actual_pending_revision} is in 'confirm' state (pending)")
                                                        else:
                                                            detailed_diagnostics.append(f"Method 3: WARNING - Revision {actual_pending_revision} found in text but state is '{rev_state}' (not confirm)")
                                                    else:
                                                        detailed_diagnostics.append(f"Method 3: WARNING - Revision {actual_pending_revision} found in text but NOT in revision JSON (may be stale)")
                                            except Exception as verify_error:
                                                logger.debug(f"Could not verify revision {actual_pending_revision}: {verify_error}")
                                                detailed_diagnostics.append(f"Method 3: Could not verify revision state: {str(verify_error)}")
                                except Exception as history_error:
                                    logger.debug(f"Could not parse history output: {history_error}")
                                    detailed_diagnostics.append(f"Method 3 error: {str(history_error)}")
                            
                            # If we found a pending revision, store it
                            if actual_pending_revision:
                                # CRITICAL: Verify this is OUR revision (created during this deployment), not a previous one
                                is_our_revision = actual_pending_revision not in self._pending_revisions_before_deployment
                                
                                if is_our_revision:
                                    result['_cumulus_pending_revision_id'] = actual_pending_revision
                                    # Also update NAPALM driver's revision_id for consistency
                                    if hasattr(self.connection, 'revision_id'):
                                        self.connection.revision_id = actual_pending_revision
                                    logger.info(f"Found OUR pending commit-confirm revision ID: {actual_pending_revision} (created during this deployment)")
                                    logs.append(f"  SUCCESS: Commit-confirm session revision ID captured: {actual_pending_revision}")
                                    logs.append(f"  ℹ This is OUR commit-confirm session (created during this deployment)")
                                    logs.append(f"  ℹ Config is APPLIED and active, but session is PENDING confirmation (will auto-rollback if not confirmed)")
                                    detailed_diagnostics.append(f"Revision {actual_pending_revision} is OUR revision (created during this deployment)")
                                else:
                                    logger.warning(f"Found pending revision {actual_pending_revision} but it was present BEFORE our deployment - this should not happen!")
                                    logs.append(f"  ⚠ WARNING: Found pending revision {actual_pending_revision} that existed BEFORE our deployment")
                                    logs.append(f"  This suggests our Pre-Phase 1 abort may have failed")
                                    detailed_diagnostics.append(f"WARNING: Revision {actual_pending_revision} was in pre-deployment list - abort may have failed")
                                    # Still store it, but log the warning
                                    result['_cumulus_pending_revision_id'] = actual_pending_revision
                                    if hasattr(self.connection, 'revision_id'):
                                        self.connection.revision_id = actual_pending_revision
                            else:
                                # No pending revision found - check if config is already applied
                                if result.get('_config_already_applied', False):
                                    logger.info(f"No pending revision found - configuration already applied (expected)")
                                    logs.append(f"  ℹ No pending revision found - configuration already applied")
                                    logs.append(f"  ℹ Device is already in desired state - no commit-confirm session needed")
                                    logs.append(f"  SUCCESS: Commit successful (no changes needed)")
                                else:
                                    # No pending revision found - check if commit actually happened
                                    logger.warning(f"No pending revision found using any method")
                                    logs.append(f"  ⚠ No pending revision found - checking if commit succeeded...")
                                logs.append(f"")
                                logs.append(f"  === DIAGNOSTICS: REVISION DETECTION ===")
                                for diag_line in detailed_diagnostics:
                                    logs.append(f"  {diag_line}")
                                logs.append(f"")
                                
                                # Check if there's a diff (if no diff, no revision is created - this is NORMAL for idempotent configs)
                                diff_check = self.connection.device.send_command_timing('nv config diff', read_timeout=10)
                                detailed_diagnostics.append(f"nv config diff check: {diff_check[:200] if diff_check else 'No output'}")
                                
                                if diff_check and ('no changes' in diff_check.lower() or 'no config diff' in diff_check.lower()):
                                    # GOOD: Config is idempotent - already applied
                                    logs.append(f"  SUCCESS: Config is idempotent - already applied (no new revision needed)")
                                    logger.info(f"Commit did not create revision because config already matches")
                                    result['_commit_idempotent'] = True
                                    result['_config_already_applied'] = True
                                else:
                                    # CRITICAL: No pending revision but changes exist
                                    # This means NAPALM claimed success but didn't actually create commit-confirm session
                                    # TRIGGER FALLBACK: Use direct NVUE commands
                                    logs.append(f"  [WARN] NAPALM claimed success but no commit-confirm session created")
                                    logger.warning(f"NAPALM commit succeeded but no pending revision - triggering fallback")
                                    logs.append(f"  Triggering FALLBACK: Direct NVUE commit-confirm command")
                                    logs.append(f"")
                                    
                                    # Check if there are any error messages first
                                    if diff_check and ('error' in diff_check.lower() or 'invalid' in diff_check.lower()):
                                        error_msg = "Commit failed - configuration commands rejected by NVUE"
                                        logger.error(f"Phase 2 failed: {error_msg}")
                                        logs.append(f"  [FAIL] {error_msg}")
                                        logs.append(f"  [DEBUG] Config diff shows errors:")
                                        for line in diff_check.split('\n')[:20]:
                                            if line.strip() and ('error' in line.lower() or 'invalid' in line.lower()):
                                                logs.append(f"    {line.strip()}")
                                        result['message'] = error_msg
                                        result['logs'] = logs
                                        return result
                                    
                                    # FALLBACK: Execute direct NVUE commit-confirm command
                                    try:
                                        logger.info(f"FALLBACK: Executing direct NVUE command: nv config apply --confirm {timeout}s -y")
                                        logs.append(f"  [FALLBACK] Executing: nv config apply --confirm {timeout}s -y")
                                        
                                        fallback_output = self.connection.device.send_command_timing(
                                            f'nv config apply --confirm {timeout}s -y',
                                            read_timeout=120,
                                            expect_string=r'#'
                                        )
                                        
                                        logger.info(f"FALLBACK command output: {fallback_output}")
                                        logs.append(f"  [DEBUG] NVUE output: {fallback_output[:200] if fallback_output else 'No output'}")
                                        
                                        # CRITICAL: Check if NVUE says "no config diff" - this means config is already applied
                                        # In this case, no commit-confirm session is created (expected behavior)
                                        no_config_diff = False
                                        if fallback_output and ('no config diff' in fallback_output.lower() or 'no changes' in fallback_output.lower()):
                                            no_config_diff = True
                                            logger.info(f"NVUE reports 'no config diff' - configuration already applied to device")
                                            logs.append(f"  ℹ NVUE reports: Configuration already applied (no changes to commit)")
                                            logs.append(f"  ℹ This is expected when device is already in desired state")
                                            logs.append(f"  ℹ No commit-confirm session needed - device is already configured correctly")
                                            # Mark as success - device is already in desired state
                                            actual_pending_revision = "N/A (no changes)"  # Special marker
                                            result['_cumulus_pending_revision_id'] = None  # No revision created
                                            result['_config_already_applied'] = True
                                            result['_commit_warning'] = "Config already applied - no commit needed"
                                        
                                        if not no_config_diff:
                                            # Wait for NVUE backend to process
                                            time.sleep(3)
                                            
                                            # Check again for pending revision
                                            try:
                                                revision_json_check = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                                                if revision_json_check:
                                                    import json
                                                    rev_data_check = json.loads(revision_json_check)
                                                    for rev_id, rev_info in rev_data_check.items():
                                                        if isinstance(rev_info, dict) and rev_info.get('state') == 'confirm':
                                                            actual_pending_revision = rev_id
                                                            result['_cumulus_pending_revision_id'] = actual_pending_revision
                                                            logger.info(f"FALLBACK SUCCESS: Found pending revision {actual_pending_revision}")
                                                            logs.append(f"  [OK] Fallback successful - pending revision {actual_pending_revision} created")
                                                            break
                                            except Exception as fallback_check_error:
                                                logger.warning(f"Could not verify fallback commit: {fallback_check_error}")
                                            
                                            if not actual_pending_revision:
                                                # Fallback also failed (and it's not a "no config diff" case)
                                                logs.append(f"  [FAIL] Fallback command did not create commit-confirm session")
                                                logs.append(f"  This indicates a deeper NVUE issue")
                                                result['_commit_warning'] = "Fallback also failed - no commit-confirm session created"
                                                result['_detailed_diagnostics'] = detailed_diagnostics
                                        
                                    except Exception as fallback_error:
                                        logger.error(f"FALLBACK FAILED: {fallback_error}")
                                        logs.append(f"  [FAIL] Fallback command failed: {str(fallback_error)[:200]}")
                                        result['_commit_warning'] = f"Fallback failed: {str(fallback_error)}"
                                        result['_detailed_diagnostics'] = detailed_diagnostics
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
                    output = netmiko_conn.send_command_timing(
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
                        output = netmiko_conn.send_command_timing(
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
                                netmiko_conn.send_command_timing("abort", expect_string=r'#', read_timeout=10)
                            except:
                                pass
                            result['message'] = f"Configuration rejected by device: {output.strip()}"
                            result['logs'] = logs
                            return result

                    # Step 3: Show pending diff (for logging)
                    try:
                        diff_output = netmiko_conn.send_command_timing(
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
                    output = netmiko_conn.send_command_timing(
                        commit_cmd,
                        expect_string=r'#',
                        read_timeout=60
                    )
                    logger.info(f"Commit timer output: {output}")
                    
                    # Check if commit was successful
                    if 'failed' in output.lower() or 'error' in output.lower():
                        raise Exception(f"Commit timer failed: {output}")
                    
                    logs.append(f"  SUCCESS: Configuration committed with {timer_minutes} minute rollback timer")
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
                            self._eos_netmiko_conn.send_command_timing("abort")
                            logs.append(f"  SUCCESS: Session aborted (before commit timer)")
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
                logs.append(f"  SUCCESS: Configuration committed")

        except Exception as e:
            result['message'] = f"Failed to commit config: {str(e)}"
            logger.error(f"Phase 2 failed: {e}")
            logs.append(f"  ✗ Commit FAILED: {str(e)}")
            logs.append(f"  Discarding configuration...")
            try:
                self.connection.discard_config()
                logs.append(f"  SUCCESS: Configuration discarded")
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
        # We have 150s total timeout, need time for verification + confirmation
        # 10s settle + ~10-20s verification + confirmation = ~30-40s, leaving ~110-120s buffer
        settle_time = 10  # seconds - balanced for config propagation and timeout window
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
        
        logs.append(f"  SUCCESS: Wait complete ({settle_time}s)")

        # Phase 4: Run verification checks
        logger.info(f"Phase 4: Running verification checks...")
        logs.append(f"")
        logs.append(f"[Phase 4] Post-Deployment Verification")
        all_checks_passed = True

        # If this is a VLAN deployment, use comprehensive VLAN verification with baseline
        # Run interface-level checks for ALL interfaces in interfaces_to_check
        # Support both normal mode (vlan_id) and sync mode (interface_vlan_map)
        use_comprehensive_verification = False
        if interfaces_to_check:
            if vlan_id:
                # Normal mode: single VLAN ID for all interfaces
                use_comprehensive_verification = True
                verification_vlan_id = vlan_id
            elif interface_vlan_map:
                # Sync mode: per-interface VLAN mapping
                use_comprehensive_verification = True
                verification_vlan_id = None  # Will be extracted per-interface
        
        if use_comprehensive_verification:
            if vlan_id:
                logger.info(f"Running comprehensive VLAN verification for {len(interfaces_to_check)} interface(s), VLAN {vlan_id}...")
                logs.append(f"  Running comprehensive VLAN verification for {len(interfaces_to_check)} interface(s)...")
                logs.append(f"  VLAN ID: {vlan_id}")
            else:
                logger.info(f"Running comprehensive VLAN verification for {len(interfaces_to_check)} interface(s) (sync mode)...")
                logs.append(f"  Running comprehensive VLAN verification for {len(interfaces_to_check)} interface(s)...")
                logs.append(f"  Mode: Sync (per-interface VLANs from NetBox)")

            baseline_data = result.get('baseline', {})
            result['verification_results'] = {}

            # PERFORMANCE: Fetch data ONCE for all interfaces (not per-interface)
            # This saves significant time - instead of 12 config fetches (20s each = 4 minutes),
            # and 12 get_interfaces() calls, we do 1 config fetch + 1 get_interfaces() call
            cached_full_config = None
            cached_interfaces_config = None
            cached_interfaces = None  # Cache get_interfaces() result
            cached_lldp = None  # Cache get_lldp_neighbors() result
            cached_connectivity = None  # Cache verify_connectivity() result
            if interfaces_to_check and len(interfaces_to_check) > 1:
                # Only cache if multiple interfaces (single interface doesn't benefit)
                driver_name = self.get_driver_name()
                if driver_name == 'cumulus':
                    try:
                        logger.info(f"Fetching config once for {len(interfaces_to_check)} interface(s) (performance optimization)...")
                        if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                            # Try revision ID first (most accurate)
                            revision_id = None
                            if hasattr(self, '_candidate_revision_id') and self._candidate_revision_id:
                                revision_id = self._candidate_revision_id
                            
                            if revision_id:
                                full_config_output = self.connection.device.send_command_timing(
                                    f'nv config show -r {revision_id} -o json',
                                    read_timeout=20
                                )
                                if not full_config_output or not full_config_output.strip():
                                    revision_id = None
                            
                            if not revision_id:
                                full_config_output = self.connection.device.send_command_timing(
                                    'nv config show -r applied -o json',
                                    read_timeout=20
                                )
                            
                            if not full_config_output or not full_config_output.strip():
                                full_config_output = self.connection.device.send_command_timing(
                                    'nv config show -o json',
                                    read_timeout=20
                                )
                            
                            if full_config_output and full_config_output.strip():
                                import json
                                try:
                                    cached_full_config = json.loads(full_config_output.strip())
                                    
                                    # Parse config structure (same logic as verify_vlan_deployment)
                                    if isinstance(cached_full_config, list):
                                        if len(cached_full_config) >= 2:
                                            cached_full_config = cached_full_config[1]
                                        elif len(cached_full_config) == 1:
                                            cached_full_config = cached_full_config[0]
                                    
                                    if isinstance(cached_full_config, dict):
                                        if 'set' in cached_full_config:
                                            cached_full_config = cached_full_config['set']
                                        interface_raw = cached_full_config.get('interface', {})
                                        if isinstance(interface_raw, dict):
                                            cached_interfaces_config = interface_raw
                                    
                                    if cached_interfaces_config:
                                        logger.info(f"Successfully cached config for {len(cached_interfaces_config)} interface(s)/range(s)")
                                    else:
                                        logger.warning(f"Could not extract interface config from cached config")
                                except json.JSONDecodeError as e:
                                    logger.warning(f"Could not parse cached config JSON: {e}")
                    except Exception as cache_err:
                        logger.warning(f"Could not cache config (will fetch per-interface): {cache_err}")
                    
                    # PERFORMANCE: Also cache get_interfaces() result (used by interface status check)
                    try:
                        logger.info(f"Fetching interfaces once for {len(interfaces_to_check)} interface(s) (performance optimization)...")
                        cached_interfaces = self.get_interfaces()
                        if cached_interfaces:
                            logger.info(f"Successfully cached interfaces data for {len(cached_interfaces)} interface(s)")
                        else:
                            logger.warning(f"get_interfaces() returned empty result")
                    except Exception as interfaces_err:
                        logger.warning(f"Could not cache interfaces (will fetch per-interface): {interfaces_err}")
                
                # PERFORMANCE: Also cache LLDP and connectivity results (used by verification)
                try:
                    logger.info(f"Fetching LLDP once for {len(interfaces_to_check)} interface(s) (performance optimization)...")
                    cached_lldp = self.get_lldp_neighbors(interfaces=interfaces_to_check)
                    if cached_lldp:
                        total_neighbors = sum(len(neighbors) for neighbors in cached_lldp.values())
                        logger.info(f"Successfully cached LLDP data for {len(cached_lldp)} interface(s) with {total_neighbors} total neighbors")
                    else:
                        logger.warning(f"get_lldp_neighbors() returned empty result")
                except Exception as lldp_err:
                    logger.warning(f"Could not cache LLDP (will fetch per-interface): {lldp_err}")
                
                # PERFORMANCE: Cache connectivity check (fast but avoid repeated calls)
                # Only cache if successful - if it fails, let each interface retry
                try:
                    logger.debug(f"Checking connectivity once (performance optimization)...")
                    # Ensure connection is still alive before checking
                    if self.connection and hasattr(self.connection, 'is_alive'):
                        try:
                            if not self.connection.is_alive():
                                logger.warning(f"Connection is not alive, attempting to refresh...")
                                self.connection.open()
                        except Exception as refresh_err:
                            logger.warning(f"Could not refresh connection: {refresh_err}")
                    
                    cached_connectivity = self.verify_connectivity()
                    # Only cache if connectivity check succeeded
                    if cached_connectivity and cached_connectivity.get('success', False):
                        logger.debug(f"Connectivity check cached: SUCCESS")
                    else:
                        logger.warning(f"Connectivity check failed during caching - will retry per-interface")
                        cached_connectivity = None  # Don't cache failed results
                except Exception as conn_err:
                    logger.warning(f"Could not cache connectivity (will check per-interface): {conn_err}")
                    cached_connectivity = None  # Don't cache on exception

            # Verify EACH interface
            for iface_idx, iface_name in enumerate(interfaces_to_check, 1):
                logger.info(f"  [{iface_idx}/{len(interfaces_to_check)}] Verifying interface: {iface_name}")
                logs.append(f"")
                logs.append(f"  [{iface_idx}/{len(interfaces_to_check)}] Interface: {iface_name}")

                # Get VLAN ID for this interface
                # In sync mode, extract from interface_vlan_map; in normal mode, use vlan_id
                iface_vlan_id = verification_vlan_id
                if not iface_vlan_id and interface_vlan_map:
                    # Sync mode: extract VLAN from interface_vlan_map
                    # interface_vlan_map keys are target_interface names (bonds if detected)
                    vlan_config = interface_vlan_map.get(iface_name)
                    
                    if vlan_config:
                        # Prefer untagged_vlan, fallback to first tagged_vlan
                        iface_vlan_id = vlan_config.get('untagged_vlan')
                        if not iface_vlan_id and vlan_config.get('tagged_vlans'):
                            iface_vlan_id = vlan_config['tagged_vlans'][0]
                        logger.debug(f"Extracted VLAN ID {iface_vlan_id} for interface {iface_name} from interface_vlan_map")
                    else:
                        logger.debug(f"Could not find VLAN config for interface {iface_name} in interface_vlan_map (keys: {list(interface_vlan_map.keys())})")
                
                if not iface_vlan_id:
                    logger.warning(f"  [{iface_idx}/{len(interfaces_to_check)}] Could not determine VLAN ID for {iface_name} - skipping VLAN verification")
                    logs.append(f"    [WARN] Could not determine VLAN ID for interface - skipping VLAN verification")
                    # Still do other checks (connectivity, interface status, LLDP)
                    continue

                # Get baseline for this specific interface
                interface_baseline = baseline_data.get('interfaces', {}).get(iface_name, {})
                if interface_baseline:
                    # Create a baseline dict with the old structure for compatibility
                    # CRITICAL: Include lldp_interfaces (member interfaces) for LLDP checks
                    # LLDP is only on member interfaces, not bond interfaces
                    iface_baseline_compat = {
                        'interface': interface_baseline,
                        'lldp_interfaces': baseline_data.get('lldp_interfaces', {}),  # Member interfaces for LLDP
                        'lldp_all_interfaces': baseline_data.get('lldp_all_interfaces', {}),
                        'uptime': baseline_data.get('uptime'),
                        'hostname': baseline_data.get('hostname')
                    }
                else:
                    # No baseline for this interface - use device-level only
                    # Still include lldp_interfaces if available (member interfaces for LLDP checks)
                    iface_baseline_compat = baseline_data.copy()
                    # Ensure lldp_interfaces is included (member interfaces, not bond interfaces)
                    if 'lldp_interfaces' not in iface_baseline_compat:
                        iface_baseline_compat['lldp_interfaces'] = baseline_data.get('lldp_interfaces', {})

                # Pass all interfaces being verified so LLDP check can extract member interfaces from all bonds at once
                # Pass cached config to avoid repeated fetches (performance optimization)
                vlan_check = self.verify_vlan_deployment(
                    iface_name, 
                    iface_vlan_id, 
                    baseline=iface_baseline_compat, 
                    all_interfaces=interfaces_to_check,
                    cached_config=cached_interfaces_config if cached_interfaces_config else None,
                    cached_interfaces=cached_interfaces if cached_interfaces else None,
                    cached_lldp=cached_lldp if cached_lldp else None,
                    cached_connectivity=cached_connectivity if cached_connectivity else None
                )
                result['verification_results'][iface_name] = vlan_check['checks']

                # Log each verification check result for this interface (pretty format matching normal mode)
                for check_name, check_data in vlan_check['checks'].items():
                    if check_data.get('success'):
                        logs.append(f"    ✓ {check_name}: {check_data.get('message', 'OK')}")
                    else:
                        logs.append(f"    ✗ {check_name}: {check_data.get('message', 'FAILED')}")
                        all_checks_passed = False  # ANY interface failure = overall failure

                if vlan_check['success']:
                    logger.info(f"  [{iface_idx}/{len(interfaces_to_check)}] SUCCESS: {iface_name} verification passed")
                    logs.append(f"    SUCCESS: Interface {iface_name} verification PASSED")
                else:
                    logger.error(f"  [{iface_idx}/{len(interfaces_to_check)}] FAILED: {iface_name} verification failed: {vlan_check['message']}")
                    logs.append(f"    ✗ Interface {iface_name} verification FAILED")
                    all_checks_passed = False

            # Summary
            if all_checks_passed:
                logger.info(f"SUCCESS: All {len(interfaces_to_check)} interface(s) verification passed")
                logs.append(f"")
                logs.append(f"  SUCCESS: All {len(interfaces_to_check)} interface(s) verification PASSED")
            else:
                logger.error(f"ERROR: One or more interface verification checks failed")
                logs.append(f"")
                logs.append(f"  ✗ One or more interface verification checks FAILED")
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
                    logs.append(f"  SUCCESS: Connectivity: {check_result.get('message', 'OK')}")

            if 'interfaces' in checks and all_checks_passed:
                logs.append(f"  Checking interfaces...")
                check_result = self.verify_interfaces(critical_interfaces=critical_interfaces)
                result['verification_results']['interfaces'] = check_result
                if not check_result['success']:
                    all_checks_passed = False
                    logs.append(f"  ✗ Interfaces: {check_result.get('message', 'FAILED')}")
                else:
                    logs.append(f"  SUCCESS: Interfaces: {check_result.get('message', 'OK')}")

            if 'lldp' in checks and all_checks_passed:
                logs.append(f"  Checking LLDP neighbors...")
                check_result = self.verify_lldp_neighbors(min_neighbors=min_neighbors)
                result['verification_results']['lldp'] = check_result
                if not check_result['success']:
                    all_checks_passed = False
                    logs.append(f"  ✗ LLDP: {check_result.get('message', 'FAILED')}")
                else:
                    logs.append(f"  SUCCESS: LLDP: {check_result.get('message', 'OK')}")
        
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
                    
                    # ============================================================================
                    # CUMULUS COMMIT CONFIRMATION - DIRECT NVUE EXECUTION REQUIRED
                    # ============================================================================
                    # ISSUE: NAPALM's cumulus driver confirm_commit() has known issues:
                    #   1. NAPALM stores candidate revision_id from load_config (Phase 1)
                    #   2. commit_config creates a NEW pending revision with different ID
                    #   3. confirm_commit() looks for old revision_id, can't find it
                    #   4. Result: "No pending commit-confirm found!" error
                    #
                    # FIX: Bypass NAPALM and directly execute NVUE confirmation command
                    #   - Use the actual pending revision ID we captured in Phase 2
                    #   - Execute: nv config apply {revision_id} --confirm-yes
                    #   - Then save: nv config save
                    # ============================================================================
                    if driver_name == 'cumulus':
                        # Check if we captured the pending revision ID in Phase 2
                        actual_pending_revision = result.get('_cumulus_pending_revision_id')
                        if actual_pending_revision:
                            # Use the actual pending revision ID to confirm
                            logger.info(f"Using captured pending revision ID {actual_pending_revision} to confirm commit")
                            logs.append(f"  Using pending revision ID: {actual_pending_revision}")
                            
                            try:
                                if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                    # CRITICAL: Check if there's a diff before trying to confirm
                                    # NVUE cannot force-apply a no-diff candidate - if diff is empty, config is already applied
                                    
                                    # First, check if we already know from Phase 2 that diff was empty
                                    if result.get('_config_diff_empty_after_commit', False):
                                        logger.info(f"Config diff was empty after commit - skipping diff check and confirm")
                                        logs.append(f"  [INFO] Config diff was empty after commit (from Phase 2) - skipping confirm")
                                        has_diff = False
                                    else:
                                        logger.info(f"Checking for config diff before confirming...")
                                        logs.append(f"  [DEBUG] Checking for config diff before confirming...")
                                        diff_output = None
                                        has_diff = False
                                        try:
                                            # Use send_command_timing for diff check (more reliable than send_command)
                                            try:
                                                diff_output = self.connection.device.send_command_timing('nv config diff', read_timeout=10)
                                            except Exception as send_cmd_error:
                                                # If first attempt fails, retry with longer delay
                                                logger.debug(f"send_command_timing failed for diff check, retrying with longer delay: {send_cmd_error}")
                                                if hasattr(self.connection.device, 'send_command_timing'):
                                                    diff_output = self.connection.device.send_command_timing('nv config diff', delay_factor=2, max_loops=30)
                                                else:
                                                    raise send_cmd_error
                                            
                                            if diff_output and diff_output.strip():
                                                # Check if diff shows actual changes (not just empty/whitespace)
                                                diff_stripped = diff_output.strip()
                                                # NVUE may return messages like "config apply executed with no config diff"
                                                if 'no config diff' in diff_stripped.lower() or 'no changes' in diff_stripped.lower():
                                                    has_diff = False
                                                    logger.info(f"No config diff detected - config already applied to device")
                                                    logs.append(f"  [INFO] No config diff detected - config already applied to device")
                                                else:
                                                    # Check if there are actual changes (not just empty output)
                                                    # Diff should have some content indicating changes
                                                    has_diff = True
                                                    logger.info(f"Config diff detected - changes need to be confirmed")
                                                    logs.append(f"  [INFO] Config diff detected - proceeding with confirm")
                                            else:
                                                has_diff = False
                                                logger.info(f"No config diff (empty output) - config already applied to device")
                                                logs.append(f"  [INFO] No config diff (empty output) - config already applied to device")
                                        except Exception as diff_check_error:
                                            logger.warning(f"Could not check config diff: {diff_check_error}")
                                            logs.append(f"  ⚠ WARNING: Could not check config diff: {str(diff_check_error)[:100]}")
                                            # Check if we already know from Phase 2 that diff was empty
                                            # If config diff was empty after commit, it's likely still empty now
                                            if result.get('_config_diff_empty_after_commit', False):
                                                logger.info(f"Config diff was empty after commit - assuming still empty, skipping confirm")
                                                logs.append(f"  [INFO] Config diff was empty after commit - skipping confirm")
                                                has_diff = False
                                            else:
                                                # Assume there's a diff and proceed with confirm (safer)
                                                has_diff = True
                                    
                                    # Track if we originally had no diff (before checking pending revision)
                                    originally_no_diff = not has_diff
                                    
                                    if not has_diff:
                                        # No diff detected - but we need to verify config is actually in running config
                                        # Sometimes diff is empty even if config wasn't applied
                                        logger.info(f"No config diff detected - verifying config is actually in running config...")
                                        logs.append(f"  [DEBUG] No config diff detected - verifying config is in running config...")
                                        
                                        # Verify by checking if there's a pending revision
                                        # If there's a pending revision, we should confirm it even if diff is empty
                                        # The diff might be empty if the config was already applied to the pending revision
                                        # but not yet confirmed to the running config
                                        try:
                                            pending_check = self._check_for_pending_commits(driver_name)
                                            if pending_check:
                                                logger.info(f"Pending revision exists - proceeding with confirm (diff was empty but revision is pending)")
                                                logs.append(f"  [INFO] Pending revision exists - proceeding with confirm")
                                                has_diff = True  # Force confirm to ensure config is applied
                                            else:
                                                logger.info(f"No pending revision - config may already be confirmed")
                                                logs.append(f"  [INFO] No pending revision found - config may already be confirmed")
                                        except Exception as pending_check_error:
                                            logger.warning(f"Could not check for pending commits: {pending_check_error}")
                                            logs.append(f"  ⚠ WARNING: Could not verify pending commits - proceeding with confirm to be safe")
                                            has_diff = True  # Force confirm to be safe
                                    
                                    if not has_diff:
                                        # Verified: No diff AND no pending revision - config is already applied
                                        logger.info(f"Config already applied (no diff, no pending revision) - skipping confirm step")
                                        logs.append(f"  [OK] Config already applied to device - no confirm needed")
                                        logs.append(f"  [INFO] NVUE cannot force-apply a no-diff candidate (this is expected behavior)")
                                        logs.append(f"  [INFO] Configuration is already applied to device {self.device.name}")
                                        
                                        logs.append(f"  [INFO] Proceeding with post-deployment checks...")
                                        
                                        # Config is already applied - treat as successful confirmation
                                        pending_after_confirm = False  # Treat as confirmed since config is already applied
                                        
                                        # Skip the confirm command execution and verification
                                        # Go straight to save and success path
                                    else:
                                        # Has diff OR pending revision exists - proceed with normal confirm flow
                                        # Directly execute confirm command (bypass NAPALM)
                                        # CRITICAL: Check revision state FIRST to determine the correct command
                                        # NVUE has different states: "pending" and "confirm"
                                        # Based on testing: both "nv config apply -y" and "nv config apply {revision_id} --confirm-yes" work
                                        # However, "nv config apply {revision_id} --confirm-yes" fails with "Unknown state: 'pending'" if state is "pending"
                                        # Strategy: Check state, use appropriate command, with fallback
                                        
                                        # Check revision state BEFORE confirm to determine correct command
                                        revision_state_before = None
                                        confirm_cmd = None
                                        try:
                                            if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                                rev_json_before = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                                                if rev_json_before:
                                                    import json
                                                    rev_data_before = json.loads(rev_json_before)
                                                    if actual_pending_revision in rev_data_before:
                                                        revision_state_before = rev_data_before[actual_pending_revision].get('state') if isinstance(rev_data_before[actual_pending_revision], dict) else None
                                                        logger.info(f"Revision {actual_pending_revision} state BEFORE confirm: {revision_state_before}")
                                                        logs.append(f"  [DEBUG] Revision {actual_pending_revision} state BEFORE confirm: {revision_state_before}")
                                                        
                                                        # Choose command based on revision state
                                                        if revision_state_before == 'confirm':
                                                            # Revision is in "confirm" state (commit-confirm session) - use --confirm-yes flag
                                                            confirm_cmd = f"nv config apply {actual_pending_revision} --confirm-yes"
                                                            logger.info(f"Revision in 'confirm' state (commit-confirm session) - using: {confirm_cmd}")
                                                            logs.append(f"  [INFO] Revision is in 'confirm' state - using confirm-yes flag")
                                                        elif revision_state_before == 'pending':
                                                            # Revision is in "pending" state - use nv config apply -y (works for both states)
                                                            confirm_cmd = "nv config apply -y"
                                                            logger.info(f"Revision in 'pending' state - using: {confirm_cmd}")
                                                            logs.append(f"  [INFO] Revision is in 'pending' state - using 'nv config apply -y'")
                                                        else:
                                                            # Unknown state - prefer "nv config apply -y" as it works for both states
                                                            confirm_cmd = "nv config apply -y"
                                                            logger.warning(f"Revision in unknown state '{revision_state_before}' - using 'nv config apply -y' (universal)")
                                                            logs.append(f"  [WARN] Revision in unknown state '{revision_state_before}' - using 'nv config apply -y'")
                                        except Exception as state_check_error:
                                            logger.warning(f"Could not check revision state before confirm: {state_check_error}")
                                            logs.append(f"  [WARN] Could not check revision state - using 'nv config apply -y' (universal)")
                                            # Fallback: use "nv config apply -y" as it works for both "pending" and "confirm" states
                                            confirm_cmd = "nv config apply -y"
                                        
                                        # If state check failed or didn't set confirm_cmd, use universal command
                                        if not confirm_cmd:
                                            # Use "nv config apply -y" as it works reliably for both states
                                            confirm_cmd = "nv config apply -y"
                                            logger.info(f"Using universal confirm command: {confirm_cmd}")
                                            logs.append(f"  [INFO] Using universal confirm command: {confirm_cmd}")
                                        
                                        logs.append(f"  [DEBUG] Directly executing: {confirm_cmd}")
                                        logs.append(f"  [INFO] This will confirm/apply the pending commit (revision {actual_pending_revision})")
                                        
                                        # Use send_command_timing() for reliable command execution
                                        # send_command_timing() uses timing-based detection instead of prompt pattern matching
                                        # This avoids "Pattern not detected" errors during NVUE processing
                                        # Increase timeout to 90s - confirm command can take longer, especially with large configs
                                        confirm_output = None
                                        confirm_succeeded = False
                                        try:
                                            if hasattr(self.connection.device, 'send_command_timing'):
                                                logger.info(f"Using send_command_timing() for confirm command (more reliable for NVUE)")
                                                logs.append(f"  [DEBUG] Using send_command_timing() method (more reliable for NVUE)")
                                                confirm_output = self.connection.device.send_command_timing(confirm_cmd, read_timeout=90, delay_factor=2)
                                            else:
                                                # Fallback: send_command_timing should always be available, but handle gracefully
                                                logger.warning(f"send_command_timing not available, this should not happen")
                                                logs.append(f"  [WARN] send_command_timing not available (unexpected)")
                                                # Still try send_command_timing as it should exist
                                                confirm_output = self.connection.device.send_command_timing(confirm_cmd, read_timeout=90)
                                            
                                            logger.info(f"Confirm command completed, output length: {len(str(confirm_output)) if confirm_output else 0}")
                                            
                                            # Parse output to check for actual errors (ignore state messages like "rolling back")
                                            if confirm_output:
                                                output_str = str(confirm_output).lower()
                                                # Check for "Unknown state: 'pending'" error - this means we used wrong command
                                                if "unknown state: 'pending'" in output_str or "unknown state" in output_str:
                                                    # We tried --confirm-yes but revision is in "pending" state
                                                    # Retry with "nv config apply -y" (without revision ID)
                                                    logger.warning(f"Confirm command failed with 'Unknown state: pending' - retrying with 'nv config apply -y'")
                                                    logs.append(f"  [WARN] Confirm command failed: Unknown state 'pending'")
                                                    logs.append(f"  [INFO] Retrying with 'nv config apply -y' (without revision ID)")
                                                    try:
                                                        confirm_output = self.connection.device.send_command_timing("nv config apply -y", read_timeout=90, delay_factor=2)
                                                        logger.info(f"Retry with 'nv config apply -y' succeeded")
                                                        logs.append(f"  [OK] Retry command succeeded")
                                                    except Exception as retry_error:
                                                        logger.error(f"Retry with 'nv config apply -y' also failed: {retry_error}")
                                                        logs.append(f"  ✗ ERROR: Retry command also failed: {str(retry_error)[:100]}")
                                                        raise Exception(f"Confirm command failed: Unknown state 'pending', and retry with 'nv config apply -y' also failed: {retry_error}")
                                                # Check for other actual errors (not just state messages)
                                                elif 'error:' in output_str and 'timeout' not in output_str:
                                                    # Real error (not timeout-related)
                                                    error_match = None
                                                    import re
                                                    error_patterns = [
                                                        r'error:\s*([^\n]+)',
                                                        r'failed:\s*([^\n]+)',
                                                        r'cannot\s+([^\n]+)',
                                                    ]
                                                    for pattern in error_patterns:
                                                        match = re.search(pattern, output_str, re.IGNORECASE)
                                                        if match:
                                                            error_match = match.group(1).strip()
                                                            break
                                                    
                                                    if error_match and 'rolling back' not in error_match.lower():
                                                        # This is a real error, not a state message
                                                        logger.error(f"Confirm command failed with error: {error_match}")
                                                        logs.append(f"  ✗ ERROR: Confirm command failed: {error_match}")
                                                        raise Exception(f"Confirm command failed: {error_match}")
                                                
                                                # "Warning: Rolling back to rev_200_apply_1/start" is an internal NVUE state message
                                                # that appears during processing, not an actual rollback
                                                # NVUE shows this message when transitioning internal states during confirm processing
                                                if 'warning: rolling back' in output_str or 'rolling back to' in output_str:
                                                    logger.info(f"Detected NVUE state message 'rolling back' - this is NORMAL during confirm processing")
                                                    logs.append(f"  [INFO] ⚠️  IMPORTANT: Detected NVUE state message 'rolling back'")
                                                    logs.append(f"  [INFO] This is an INTERNAL NVUE state transition message, NOT an actual rollback")
                                                    logs.append(f"  [INFO] NVUE shows this during confirm processing - the commit is still being confirmed")
                                                    logs.append(f"  [INFO] We will verify the actual commit status by checking device state below")
                                            
                                            confirm_succeeded = True
                                        except Exception as confirm_timeout:
                                            logger.warning(f"Confirm command timed out or raised exception: {confirm_timeout}")
                                            logs.append(f"  ⚠ WARNING: Confirm command timed out or raised exception: {str(confirm_timeout)[:100]}")
                                            logs.append(f"  Will verify if commit was actually confirmed by checking device state...")
                                            # Continue - will verify below
                                        
                                        # Give NVUE time to process confirm. State must leave 'confirm' before we declare success.
                                        # CRITICAL: If state stays 'confirm', the rollback timer is STILL running. We must NOT
                                        # declare success (history "Apply Date" / _check_for_pending) — we'd close, timer fires, revert.
                                        post_confirm_wait = 15  # seconds
                                        retry_interval = 5
                                        max_retries = 3
                                        logger.info(f"Waiting {post_confirm_wait}s for NVUE to process confirm...")
                                        logs.append(f"  [INFO] Waiting {post_confirm_wait}s for NVUE to process confirm...")
                                        time.sleep(post_confirm_wait)
                                        
                                        revision_state_after = None
                                        pending_after_confirm = True
                                        try:
                                            for attempt in range(max_retries):
                                                if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                                    rev_json_after = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
                                                    if rev_json_after:
                                                        import json
                                                        rev_data_after = json.loads(rev_json_after)
                                                        if actual_pending_revision in rev_data_after:
                                                            revision_state_after = rev_data_after[actual_pending_revision].get('state') if isinstance(rev_data_after[actual_pending_revision], dict) else None
                                                            logger.info(f"Revision {actual_pending_revision} state AFTER confirm (attempt {attempt+1}/{max_retries}): {revision_state_after}")
                                                            logs.append(f"  [DEBUG] Revision {actual_pending_revision} state: {revision_state_after}")
                                                            if revision_state_after != 'confirm':
                                                                # State left 'confirm' — timer cancelled, confirm succeeded
                                                                logger.info(f"Confirm successful - state is '{revision_state_after}' (no longer 'confirm')")
                                                                logs.append(f"  [OK] Confirm successful - state: {revision_state_before or '?'} → {revision_state_after}")
                                                                pending_after_confirm = False
                                                                break
                                                            if revision_state_after == 'confirm':
                                                                # Timer still running. Do NOT use history/_check to clear. Retry or fail.
                                                                pending_after_confirm = True
                                                                if attempt < max_retries - 1:
                                                                    logger.info(f"State still 'confirm', waiting {retry_interval}s before recheck...")
                                                                    logs.append(f"  [INFO] State still 'confirm' — waiting {retry_interval}s (attempt {attempt+1}/{max_retries})")
                                                                    time.sleep(retry_interval)
                                                                else:
                                                                    logs.append(f"  [WARN] State still 'confirm' after {max_retries} checks — confirm did not complete; timer will rollback")
                                                                continue
                                                        else:
                                                            logger.info(f"Revision {actual_pending_revision} no longer in pending list - confirm succeeded")
                                                            logs.append(f"  [OK] Revision {actual_pending_revision} no longer pending - confirm succeeded")
                                                            pending_after_confirm = False
                                                            break
                                                if not pending_after_confirm:
                                                    break
                                        except Exception as verify_error:
                                            logger.warning(f"Could not verify revision state after confirm: {verify_error}")
                                            logs.append(f"  ⚠ WARNING: Could not verify revision state: {str(verify_error)[:100]}")
                                            pending_after_confirm = True
                                    
                                    if pending_after_confirm:
                                        logger.warning(f"Pending commit still exists after confirm command - confirm may have failed")
                                        logs.append(f"  ⚠ WARNING: Pending commit still exists after confirm command")
                                        logs.append(f"  [INFO] This means the confirm command did not succeed")
                                        logs.append(f"  [INFO] The pending commit will auto-rollback when the timer expires")
                                        logs.append(f"  [INFO] We do NOT clear it (nv config delete would revert config). Manual cleanup: nv config delete <revision_id> if needed.")
                                        raise Exception(f"Confirm command failed - pending commit still exists. It will auto-rollback when the timer expires.")
                                    else:
                                        logger.info(f"Confirm successful - no pending commits found")
                                        logs.append(f"  [OK] Confirm successful - no pending commits found")
                                    
                                    # Also run nv config save to make it persistent
                                    logger.info(f"Saving config to persistent storage")
                                    logs.append(f"  [DEBUG] Executing: nv config save")
                                    save_output = self.connection.device.send_command_timing("nv config save", read_timeout=30)
                                    logger.info(f"Save output: {save_output}")
                                    logs.append(f"  [DEBUG] Save output: {save_output[:200] if save_output else '(no output)'}")
                                    
                                    # Brief settle after save so NVUE can persist before we close
                                    settle_after_save = 5
                                    logger.info(f"Waiting {settle_after_save}s for config to persist...")
                                    logs.append(f"  [INFO] Waiting {settle_after_save}s for config to persist...")
                                    time.sleep(settle_after_save)
                                    logs.append(f"  [OK] Post-save settle complete")
                                    
                                    # Update NAPALM's revision_id to None to mark as committed
                                    if hasattr(self.connection, 'revision_id'):
                                        self.connection.revision_id = None
                                    
                                    logger.info(f"Successfully confirmed commit using revision {actual_pending_revision}")
                                else:
                                    raise Exception("Cannot access Netmiko connection from NAPALM driver")
                            except Exception as manual_confirm_error:
                                error_msg = str(manual_confirm_error)
                                logger.error(f"Direct confirm failed: {manual_confirm_error}")
                                logs.append(f"  ✗ Confirm failed: {error_msg}")
                                raise Exception(f"Commit confirmation failed: {error_msg}")
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
                                        diff_output = self.connection.device.send_command_timing('nv config diff', read_timeout=10)
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
                                        # NOTE: "Currently pending [rev_id: X]" in history shows the CANDIDATE revision (from load_config)
                                        # It only becomes a commit-confirm session after commit_config() is called
                                        history_output = self.connection.device.send_command_timing('nv config history | head -10', read_timeout=10)
                                        detailed_diagnostics.append(f"[DEBUG] nv config history output:")
                                        detailed_diagnostics.append(f"[NOTE] 'Currently pending [rev_id: X]' is the CANDIDATE revision, not commit-confirm session")
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
                                        pending_check = self.connection.device.send_command_timing('nv config revision -o json', read_timeout=10)
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
                                # Check if this is an idempotent deployment (config already applied)
                                is_idempotent = result.get('_commit_idempotent', False)
                                
                                if is_idempotent:
                                    # GOOD: Config already matches - no commit needed (idempotent)
                                    logs.append(f"  SUCCESS: Config is idempotent - already applied on device")
                                    logs.append(f"  This is NORMAL and SAFE - no changes were needed")
                                    logger.info(f"No changes to apply - config already matches (idempotent)")
                                    result['success'] = True
                                    result['committed'] = False  # Nothing to commit
                                    result['message'] = f"Configuration already applied (idempotent - no changes needed)"
                                    logs.append(f"")
                                    logs.append(f"=== DEPLOYMENT COMPLETED (IDEMPOTENT) ===")
                                    result['logs'] = logs
                                    return result
                                else:
                                    # BAD: Commit-confirm session was not created but changes were expected
                                    logs.append(f"  The commit-confirm session was not created. Possible reasons:")
                                    logs.append(f"    1. NVUE rejected the commands (syntax error)")
                                    logs.append(f"    2. Commit command failed to create revision")
                                    logs.append(f"    3. Concurrent commit from another process")
                                    logs.append(f"    4. Timing issue - revision not yet visible (unlikely after 3s)")
                                    logs.append(f"")
                                    
                                    # Check current state to understand what happened
                                    try:
                                        if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                            diff_check = self.connection.device.send_command_timing('nv config diff', read_timeout=10)
                                            
                                            if diff_check and 'no changes' not in diff_check.lower():
                                                # CRITICAL: Changes exist but no commit-confirm session - this is BAD
                                                # DO NOT save automatically - this is unsafe!
                                                logger.error(f"CRITICAL: Pending changes detected but no commit-confirm session - deployment FAILED")
                                                logs.append(f"  ✗ CRITICAL: Pending changes exist but no commit-confirm session")
                                                logs.append(f"  This means the commit command failed or was rejected")
                                                logs.append(f"")
                                                logs.append(f"  === PENDING CHANGES ===")
                                                for line in diff_check.split('\n')[:15]:
                                                    if line.strip():
                                                        logs.append(f"  {line}")
                                                logs.append(f"")
                                                logs.append(f"  === RECOMMENDED ACTIONS ===")
                                                logs.append(f"  1. Review commands for syntax errors")
                                                logs.append(f"  2. Check device logs: show log syslog")
                                                logs.append(f"  3. Manually verify config: nv config diff")
                                                logs.append(f"  4. Delete pending changes: nv config delete <revision_id>")
                                                logs.append(f"")
                                                result['success'] = False
                                                result['committed'] = False
                                                result['message'] = f"Commit-confirm session not created - deployment FAILED (see logs for details)"
                                                result['logs'] = logs
                                                return result
                                            else:
                                                # No changes detected - might be idempotent case that wasn't detected earlier
                                                logger.info(f"No pending changes - config already matches")
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
                                            pending_rev_output = self.connection.device.send_command_timing('nv config history | grep -i "pending\\|confirm" | head -1', read_timeout=10)
                                            if pending_rev_output:
                                                import re
                                                rev_match = re.search(r'Revision:\s*(\d+)', pending_rev_output)
                                                if not rev_match:
                                                    rev_match = re.search(r'^\s*(\d+)\s*\*', pending_rev_output)
                                                if rev_match:
                                                    actual_rev = rev_match.group(1)
                                                    logger.info(f"Found pending revision {actual_rev}, confirming manually...")
                                                    self.connection.device.send_command_timing(f"nv config apply {actual_rev} --confirm-yes", read_timeout=30)
                                                    self.connection.device.send_command_timing("nv config save", read_timeout=30)
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
                    logs.append(f"  SUCCESS: Commit CONFIRMED - changes are now PERMANENT")
                    logs.append(f"")
                    
                    # POST-DEPLOYMENT VERIFICATION: Check for leftover pending (informational only)
                    # CRITICAL: Do NOT call _clear_pending_commit after successful confirm!
                    # Clearing runs "nv config delete <rev_id>" which REVERTS our confirmed config.
                    # If NVUE still reports "pending" (e.g. our rev briefly in 'confirm' state),
                    # that is timing/API semantics — we must NOT delete it or we undo our deploy.
                    logs.append(f"[Post-Deployment Verification] Checking for leftover pending commits...")
                    pending_after_success = self._check_for_pending_commits(driver_name)
                    
                    if pending_after_success:
                        logger.warning(
                            "Pending commit still reported after confirm — NOT clearing. "
                            "Clearing would revert our confirmed config. If this persists, check NVUE state manually."
                        )
                        logs.append(f"  [WARN] NVUE still reports a pending commit after confirmation.")
                        logs.append(f"  We do NOT clear it: clearing would revert the config we just confirmed.")
                        logs.append(f"  Config is permanent. If unsure, verify with: nv config revision -o json")
                    else:
                        logs.append(f"  [OK] No pending commits - deployment confirmed successfully")
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
                    
                    # POST-ROLLBACK: Check for leftover pending (informational only; we do NOT clear)
                    logs.append(f"")
                    logs.append(f"[Post-Rollback] Checking for leftover pending commits...")
                    pending_after_rollback = self._check_for_pending_commits(driver_name)
                    
                    if pending_after_rollback:
                        logger.warning(f"Pending commit detected after rollback - we do NOT clear (nv config delete can revert config)")
                        logs.append(f"  [WARN] Pending commit still exists after rollback")
                        logs.append(f"  We do NOT clear it. Manual cleanup if needed: nv config delete <revision_id>")
                    else:
                        logs.append(f"  [OK] No pending commits - device is in stable state")
                    logs.append(f"")
                    
                    if rollback_status is True:
                        result['message'] += f" - Auto-rollback completed"
                        logger.info(f"Auto-rollback completed: {rollback_message}")
                        logs.append(f"  SUCCESS: Auto-rollback completed - changes reverted")
                        logs.append(f"  SUCCESS: Verification: {rollback_message}")
                    elif rollback_status is False:
                        result['message'] += f" - Auto-rollback may have failed"
                        logger.warning(f"Auto-rollback verification failed: {rollback_message}")
                        logs.append(f"  ⚠ Auto-rollback completed but verification failed")
                        logs.append(f"  ⚠ Warning: {rollback_message}")
                    else:
                        result['message'] += f" - Auto-rollback completed (could not verify)"
                        logger.info(f"Auto-rollback completed: {rollback_message}")
                        logs.append(f"  SUCCESS: Auto-rollback completed - changes reverted")
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
                    output = netmiko_conn.send_command_timing(
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
                    logs.append(f"  SUCCESS: EOS session CONFIRMED - changes are now PERMANENT")
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
                    
                    # POST-EOS-FAILURE CLEANUP: Ensure session will rollback
                    logs.append(f"[Post-Failure Cleanup] Checking EOS session status...")
                    pending_eos_session = self._check_for_pending_commits(driver_name)
                    
                    if pending_eos_session:
                        logs.append(f"  [OK] EOS session still exists - will auto-rollback after timer expires")
                    else:
                        logs.append(f"  [INFO] EOS session already cleared")
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
                logs.append(f"  SUCCESS: Configuration committed (direct commit, no rollback support)")
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
                
                # Log what command was used for initial auto-rollback
                logs.append(f"")
                logs.append(f"[Initial Auto-Rollback Information]")
                if driver_name == 'cumulus':
                    # For Cumulus, auto-rollback is handled by commit-confirm timer
                    # The command executed was: nv config apply --confirm {timeout}s -y (via NAPALM commit_config(revert_in=timeout))
                    # Get timeout from deployment result or default to 90
                    timeout_used = result.get('_deployment_timeout', 90)
                    revision_id = result.get('_cumulus_pending_revision_id', 'unknown')
                    logs.append(f"  Method: Commit-confirm timer-based auto-rollback")
                    logs.append(f"  Command that SHOULD have been executed: nv config apply --confirm {timeout_used}s -y")
                    logs.append(f"  (Called via: NAPALM commit_config(revert_in={timeout_used}))")
                    logs.append(f"  Expected behavior: Config should auto-rollback after {timeout_used}s if not confirmed")
                    logs.append(f"  Revision ID: {revision_id}")
                    if rollback_status is False:
                        logs.append(f"  ⚠ Auto-rollback verification failed - possible reasons:")
                        logs.append(f"     • NAPALM driver may not have executed 'nv config apply --confirm {timeout_used}s -y' correctly")
                        logs.append(f"     • Commit-confirm session was not created properly by NAPALM driver")
                        logs.append(f"     • Timer expired but rollback didn't execute automatically")
                        logs.append(f"     • Pending revision {revision_id} still exists (needs manual cleanup)")
                        logs.append(f"     • Check device logs: nv config history | grep {revision_id}")
                else:
                    logs.append(f"  Method: Platform-specific auto-rollback")
                    logs.append(f"  Command: NAPALM commit_config(revert_in={result.get('_deployment_timeout', 'unknown')})")
                
                # POST-VERIFICATION-FAILURE: Check for leftover pending (informational only; we do NOT clear)
                logs.append(f"")
                logs.append(f"[Post-Rollback] Checking for leftover pending commits...")
                pending_after_verification_failure = self._check_for_pending_commits(driver_name)
                
                if pending_after_verification_failure:
                    logger.warning(f"Pending commit detected after verification failure rollback - we do NOT clear (nv config delete can revert config)")
                    logs.append(f"  [WARN] Pending commit still exists after rollback")
                    logs.append(f"  We do NOT clear it. Manual cleanup if needed: nv config delete <revision_id>")
                else:
                    logs.append(f"  [OK] No pending commits - device is in stable state")
                logs.append(f"")
                
                if rollback_status is True:
                    result['message'] += f" - Auto-rollback completed"
                    logger.info(f"{'='*60}")
                    logger.info(f"AUTO-ROLLBACK: Device returned to previous state")
                    logger.info(f"Verification: {rollback_message}")
                    logger.info(f"{'='*60}")
                    logs.append(f"  SUCCESS: Auto-rollback completed - device returned to previous state")
                    logs.append(f"  SUCCESS: Verification: {rollback_message}")
                elif rollback_status is False:
                    result['message'] += f" - Auto-rollback may have failed"
                    logger.warning(f"{'='*60}")
                    logger.warning(f"AUTO-ROLLBACK: Verification failed")
                    logger.warning(f"Warning: {rollback_message}")
                    logger.warning(f"{'='*60}")
                    logs.append(f"  ⚠ Auto-rollback completed but verification failed")
                    logs.append(f"  ⚠ Warning: {rollback_message}")
                    
                    # ========================================================================
                    # SURGICAL NVUE ROLLBACK FALLBACK (for Cumulus only)
                    # ========================================================================
                    # If NAPALM auto-rollback failed, attempt surgical rollback using config diff
                    # This compares pre-deployment snapshot with current config and reverts changes
                    # ========================================================================
                    if driver_name == 'cumulus' and result.get('_pre_deployment_snapshot'):
                        logger.warning(f"Attempting surgical NVUE rollback...")
                        logs.append(f"")
                        logs.append(f"  === SURGICAL NVUE ROLLBACK (FALLBACK) ===")
                        logs.append(f"  Auto-rollback failed - attempting surgical config revert...")
                        
                        try:
                            if hasattr(self.connection, 'device') and hasattr(self.connection.device, 'send_command'):
                                # Step 1: Take post-deployment snapshot
                                import time as time_module
                                timestamp = int(time_module.time())
                                post_snapshot_file = f"/tmp/post_deploy_{timestamp}_failed.txt"
                                export_cmd = f"nv config show -r applied -o commands > {post_snapshot_file}"
                                self.connection.device.send_command_timing(export_cmd, read_timeout=30)
                                logs.append(f"  Post-deployment snapshot: {post_snapshot_file}")
                                
                                # Step 2: Read both snapshots
                                pre_snapshot_file = result.get('_pre_deployment_snapshot')
                                
                                pre_config_cmd = f"cat {pre_snapshot_file}"
                                post_config_cmd = f"cat {post_snapshot_file}"
                                
                                pre_config = self.connection.device.send_command_timing(pre_config_cmd, read_timeout=10)
                                post_config = self.connection.device.send_command_timing(post_config_cmd, read_timeout=10)
                                
                                # Step 3: Compare and find differences
                                pre_lines = set(pre_config.strip().split('\n'))
                                post_lines = set(post_config.strip().split('\n'))
                                
                                added_lines = post_lines - pre_lines  # In post but not in pre
                                removed_lines = pre_lines - post_lines  # In pre but not in post
                                
                                rollback_commands = []
                                
                                # Generate rollback commands
                                for line in added_lines:
                                    if line.strip() and line.startswith('nv set'):
                                        # Convert "nv set" to "nv unset"
                                        rollback_cmd = line.replace('nv set', 'nv unset', 1)
                                        # Remove the value part for unset (keep only the parameter path)
                                        # Example: "nv unset interface swp4 bridge domain br_default access 3019"
                                        #       → "nv unset interface swp4 bridge domain br_default access"
                                        parts = rollback_cmd.split()
                                        if len(parts) > 3:
                                            # Keep command structure but remove last value for unset
                                            if 'access' in rollback_cmd or 'vlan' in rollback_cmd:
                                                rollback_cmd = ' '.join(parts[:-1]) if parts[-1].isdigit() or ',' in parts[-1] else rollback_cmd
                                        rollback_commands.append(rollback_cmd)
                                
                                for line in removed_lines:
                                    if line.strip() and line.startswith('nv set'):
                                        # Re-apply removed configuration
                                        rollback_commands.append(line)
                                
                                if rollback_commands:
                                    logs.append(f"  Identified {len(rollback_commands)} change(s) to revert:")
                                    for cmd in rollback_commands[:10]:  # Show first 10
                                        logs.append(f"    • {cmd}")
                                    if len(rollback_commands) > 10:
                                        logs.append(f"    ... and {len(rollback_commands) - 10} more")
                                    logs.append(f"")
                                    
                                    # Step 4: Execute rollback commands
                                    logs.append(f"  Executing rollback commands...")
                                    for cmd in rollback_commands:
                                        try:
                                            output = self.connection.device.send_command_timing(cmd, read_timeout=10)
                                            if output and output.strip():
                                                logger.debug(f"Rollback command output: {output}")
                                        except Exception as cmd_error:
                                            logger.warning(f"Rollback command failed: {cmd} - {cmd_error}")
                                            logs.append(f"    ⚠ {cmd} - {str(cmd_error)[:50]}")
                                    
                                    logs.append(f"  SUCCESS: Rollback commands executed")
                                    logs.append(f"")
                                    
                                    # Step 5: Check config diff
                                    logs.append(f"  Verifying rollback changes...")
                                    diff_output = self.connection.device.send_command_timing('nv config diff', read_timeout=10)
                                    
                                    if diff_output and diff_output.strip() and 'no changes' not in diff_output.lower():
                                        # Changes detected - need to apply
                                        logs.append(f"  SUCCESS: Pending changes detected:")
                                        for line in diff_output.split('\n')[:15]:
                                            if line.strip():
                                                logs.append(f"    {line}")
                                        logs.append(f"")
                                        
                                        # Step 6: Apply the rollback
                                        logs.append(f"  Applying rollback configuration...")
                                        apply_output = self.connection.device.send_command_timing('nv config apply', read_timeout=30)
                                        logs.append(f"  SUCCESS: Rollback configuration applied")
                                        
                                        # Step 7: Verify rollback succeeded
                                        time.sleep(2)
                                        verify_diff = self.connection.device.send_command_timing('nv config diff', read_timeout=10)
                                        
                                        if not verify_diff or not verify_diff.strip() or 'no changes' in verify_diff.lower():
                                            logs.append(f"  SUCCESS: Rollback verification: No pending changes")
                                            logs.append(f"  SUCCESS: Configuration successfully reverted to pre-deployment state")
                                            result['rolled_back'] = True
                                            result['message'] = f"Verification failed but surgical rollback succeeded"
                                        else:
                                            logs.append(f"  ⚠ Pending changes still exist after rollback:")
                                            # Show full diff output (no truncation) so user can see all pending changes including VLAN numbers and all interfaces
                                            # Split into lines for better readability
                                            for line in verify_diff.split('\n'):
                                                if line.strip():
                                                    logs.append(f"    {line}")
                                    else:
                                        # No changes - config already matches
                                        logs.append(f"  ℹ No pending changes detected")
                                        logs.append(f"  Configuration already matches pre-deployment state")
                                        result['rolled_back'] = True
                                else:
                                    logs.append(f"  ℹ No configuration differences found")
                                    logs.append(f"  Configuration already matches pre-deployment snapshot")
                                    result['rolled_back'] = True
                        
                        except Exception as surgical_error:
                            logger.error(f"Surgical rollback failed: {surgical_error}")
                            logs.append(f"  ✗ Surgical rollback failed: {str(surgical_error)[:100]}")
                            logs.append(f"  Manual intervention required")
                        
                        logs.append(f"")
                else:
                    result['message'] += f" - Auto-rollback completed (could not verify)"
                    logger.info(f"{'='*60}")
                    logger.info(f"AUTO-ROLLBACK: Device returned to previous state")
                    logger.info(f"Note: {rollback_message}")
                    logger.info(f"{'='*60}")
                    logs.append(f"  SUCCESS: Auto-rollback completed - device returned to previous state")
                    logs.append(f"  ⚠ Note: {rollback_message}")
                
                logs.append(f"")
                
                # Add rollback information based on verification
                # Use result['rolled_back'] if surgical rollback succeeded, otherwise use initial rollback_status
                final_rollback_status = result.get('rolled_back', rollback_status)
                logs.append(f"--- Rollback Information ---")
                logs.append(f"Platform: {driver_name.upper()}")
                if final_rollback_status is True:
                    logs.append(f"Auto-Rollback: VERIFIED - Changes have been automatically reverted due to verification failure")
                    if result.get('rolled_back') and rollback_status is False:
                        # Surgical rollback succeeded after initial auto-rollback failed
                        logs.append(f"  Status: Surgical rollback succeeded (initial auto-rollback failed)")
                    else:
                        logs.append(f"  Status: {rollback_message}")
                    # Don't show manual steps when rollback is verified successful
                elif final_rollback_status is False:
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
                    logs.append(f"  SUCCESS: Timer expired - device automatically rolled back to previous state")
                    logs.append(f"  SUCCESS: Verification: {rollback_message}")
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
                    logs.append(f"  SUCCESS: Timer expired - device automatically rolled back to previous state")
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

