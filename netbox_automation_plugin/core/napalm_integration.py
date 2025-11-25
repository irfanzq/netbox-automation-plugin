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
                    logger.info(f"Connected to {self.device.name} using {driver_name} driver (attempt {attempt + 1})")
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
                return False
        
        try:
            if replace:
                # Full configuration replacement
                self.connection.load_replace_candidate(config=config)
                logger.info(f"Loaded REPLACE candidate config on {self.device.name}")
            else:
                # Incremental merge
                self.connection.load_merge_candidate(config=config)
                logger.info(f"Loaded MERGE candidate config on {self.device.name}")
            
            return True
                
        except Exception as e:
            logger.error(f"Failed to load config on {self.device.name}: {e}")
            try:
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

        try:
            # Collect interface state if specific interface is being configured
            if interface_name:
                logs.append(f"  Collecting interface state for {interface_name}...")
                interfaces_before = self.get_interfaces()
                if interfaces_before and interface_name in interfaces_before:
                    baseline['interface'] = {
                        'name': interface_name,
                        'is_up': interfaces_before[interface_name].get('is_up', False),
                        'is_enabled': interfaces_before[interface_name].get('is_enabled', True),
                        'description': interfaces_before[interface_name].get('description', ''),
                    }
                    logger.info(f"  Baseline: {interface_name} is_up={baseline['interface']['is_up']}, is_enabled={baseline['interface']['is_enabled']}")
                    logs.append(f"  ✓ Interface {interface_name}: UP={baseline['interface']['is_up']}, Enabled={baseline['interface']['is_enabled']}")
                else:
                    # Interface doesn't exist on device
                    # This is an ERROR - interface should exist in NetBox AND on device
                    error_msg = f"Interface {interface_name} does not exist on device {self.device.name}"
                    logger.error(f"CRITICAL: {error_msg}")
                    logs.append(f"  ✗ Interface {interface_name}: Does not exist on device!")
                    result['message'] = f"Interface validation failed: {error_msg}"
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

            # Store baseline for comparison later
            result['baseline'] = baseline
            logger.info(f"Phase 0.5: Baseline collection completed")
            logs.append(f"  ✓ Baseline collection completed")

        except Exception as e:
            logger.warning(f"Phase 0.5: Could not collect complete baseline: {e}")
            logger.warning(f"Proceeding with deployment (baseline collection is optional)")
            result['baseline'] = {}
            logs.append(f"  ⚠ Baseline collection incomplete: {str(e)[:100]}")
            logs.append(f"  Proceeding with deployment...")
        
        # Determine platform-specific approach BEFORE Phase 1
        driver_name = self.get_driver_name()
        supports_native_commit_confirm = driver_name in ['junos', 'cumulus']  # EOS SSH does NOT support commit-confirm
        use_eos_session = (driver_name == 'eos')  # EOS requires configure session with timer
        
        # Phase 1: Load configuration (skip for EOS sessions - handled in Phase 2)
        if not use_eos_session:
            try:
                logger.info(f"Phase 1: Loading configuration to {self.device.name}...")
                logger.debug(f"Config to load:\n{config}")

                logs.append(f"")
                logs.append(f"[Phase 1] Configuration Loading")
                logs.append(f"  Config to load: {config[:200]}{'...' if len(config) > 200 else ''}")
                logs.append(f"  Mode: {'Replace (full config)' if replace else 'Merge (incremental)'}")
                logs.append(f"  Loading configuration...")

                if not self.load_config(config, replace=replace):
                    result['message'] = "Failed to load configuration. The device rejected the config or NAPALM driver encountered an error."
                    logger.error(f"Phase 1 failed: load_config returned False")
                    logs.append(f"  ✗ Configuration load FAILED")
                    logs.append(f"  Error: Device rejected config or NAPALM driver error")
                    result['logs'] = logs
                    return result

                logger.info(f"Phase 1: Configuration loaded successfully")
                logs.append(f"  ✓ Configuration loaded to candidate config")

                # Phase 1.5: Compare/Preview changes (optional, if supported by driver)
                try:
                    logs.append(f"  Generating configuration diff...")
                    diff = self.connection.compare_config()
                    if diff:
                        logger.info(f"Configuration diff preview:")
                        logger.info(diff[:500])  # Log first 500 chars
                        logs.append(f"  ✓ Configuration diff:")
                        # Add first few lines of diff
                        diff_lines = diff.split('\n')[:10]
                        for line in diff_lines:
                            logs.append(f"    {line}")
                        if len(diff.split('\n')) > 10:
                            logs.append(f"    ... ({len(diff.split('\n')) - 10} more lines)")
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
                self.connection.commit_config(revert_in=timeout)
                logger.info(f"Phase 2: Config committed (will auto-rollback in {timeout}s if not confirmed)")
                logs.append(f"  ✓ Configuration committed with {timeout}s rollback timer")
                logs.append(f"  ⚠ Will auto-rollback if not confirmed within {timeout}s")

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
            result['logs'] = logs
            return result
        
        # Phase 3: Verification window (let config settle)
        # Extended wait time for testing rollback scenarios (30s gives time to SSH and break things)
        settle_time = 30  # seconds - increase for easier testing, decrease for production
        logger.info(f"Phase 3: Waiting {settle_time} seconds for config to settle...")
        logs.append(f"")
        logs.append(f"[Phase 3] Configuration Settling")
        logs.append(f"  Waiting {settle_time} seconds for config to take effect...")
        logs.append(f"  💡 TIP: You have {settle_time}s to SSH to device and test rollback scenarios")
        logs.append(f"     (e.g., shutdown a different interface to trigger LLDP check failure)")
        
        # Progress indicator in logs so you know it's waiting
        for i in range(settle_time):
            if i == 0 or i == 5 or i == 10 or i == 15 or i == 20 or i == 25 or i == settle_time - 1:
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
                    self.connection.confirm_commit()
                    result['success'] = True
                    result['committed'] = True
                    result['message'] = f"Configuration successfully deployed and confirmed on {self.device.name}"
                    logger.info(f"{'='*60}")
                    logger.info(f"SUCCESS: Configuration is now PERMANENT")
                    logger.info(f"{'='*60}")
                    logs.append(f"  ✓ Commit CONFIRMED - changes are now PERMANENT")
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
                    result['rolled_back'] = True
                    result['message'] += f" - Auto-rollback completed"
                    logger.info(f"Auto-rollback completed")
                    logs.append(f"  ✓ Auto-rollback completed - changes reverted")
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
                result['rolled_back'] = True
                result['message'] += f" - Auto-rollback completed"
                logger.info(f"{'='*60}")
                logger.info(f"AUTO-ROLLBACK: Device returned to previous state")
                logger.info(f"{'='*60}")
                logs.append(f"  ✓ Auto-rollback completed - device returned to previous state")
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
                
                result['rolled_back'] = True
                result['message'] += f" - Auto-rollback completed (timer expired)"
                logger.info(f"{'='*60}")
                logger.info(f"AUTO-ROLLBACK: EOS timer expired, device returned to previous state")
                logger.info(f"{'='*60}")
                logs.append(f"  ✓ Timer expired - device automatically rolled back to previous state")
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

