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
            driver_name = self.get_driver_name()
            self.driver = napalm.get_network_driver(driver_name)
            
            # Get connection parameters
            optional_args = getattr(settings, 'NAPALM_OPTIONAL_ARGS', {})
            
            # Special handling for Cumulus devices
            if driver_name == 'cumulus':
                # Cumulus-specific optional args
                cumulus_args = optional_args.copy()
                # Add any Cumulus-specific settings here if needed
                # e.g., cumulus_args['use_keys'] = True
                optional_args = cumulus_args
            
            self.connection = self.driver(
                hostname=self.device.primary_ip4.address.split('/')[0] if self.device.primary_ip4 else None,
                username=getattr(settings, 'NAPALM_USERNAME', 'admin'),
                password=getattr(settings, 'NAPALM_PASSWORD', ''),
                timeout=getattr(settings, 'NAPALM_TIMEOUT', 60),
                optional_args=optional_args
            )
            
            self.connection.open()
            logger.info(f"Connected to {self.device.name} using {driver_name} driver")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to {self.device.name}: {e}")
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
    
    def deploy_config_safe(self, config, replace=True, timeout=60, 
                          checks=['connectivity', 'interfaces', 'lldp'],
                          critical_interfaces=None, min_neighbors=0):
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
                'config_deployed': str
            }
        """
        result = {
            'success': False,
            'committed': False,
            'rolled_back': False,
            'message': '',
            'verification_results': {},
            'config_deployed': config
        }
        
        # Phase 1: Load configuration
        logger.info(f"{'='*60}")
        logger.info(f"SAFE DEPLOYMENT: {self.device.name} (timeout={timeout}s, replace={replace})")
        logger.info(f"{'='*60}")
        
        try:
            if not self.load_config(config, replace=replace):
                result['message'] = "Failed to load configuration"
                return result
            
            logger.info(f"Phase 1: Configuration loaded successfully")
        
        except Exception as e:
            result['message'] = f"Exception during config load: {str(e)}"
            logger.error(f"Phase 1 failed: {e}")
            return result
        
        # Phase 2: Commit with rollback timer
        try:
            logger.info(f"Phase 2: Committing with {timeout}s rollback timer...")
            self.connection.commit_config(revert_in=timeout)
            logger.info(f"Phase 2: Config committed (will auto-rollback in {timeout}s if not confirmed)")
        
        except Exception as e:
            result['message'] = f"Failed to commit config: {str(e)}"
            logger.error(f"Phase 2 failed: {e}")
            try:
                self.connection.discard_config()
            except:
                pass
            return result
        
        # Phase 3: Verification window (let config settle)
        logger.info(f"Phase 3: Waiting 5 seconds for config to settle...")
        time.sleep(5)
        
        # Phase 4: Run verification checks
        logger.info(f"Phase 4: Running verification checks...")
        all_checks_passed = True
        
        if 'connectivity' in checks:
            check_result = self.verify_connectivity()
            result['verification_results']['connectivity'] = check_result
            if not check_result['success']:
                all_checks_passed = False
        
        if 'interfaces' in checks and all_checks_passed:
            check_result = self.verify_interfaces(critical_interfaces=critical_interfaces)
            result['verification_results']['interfaces'] = check_result
            if not check_result['success']:
                all_checks_passed = False
        
        if 'lldp' in checks and all_checks_passed:
            check_result = self.verify_lldp_neighbors(min_neighbors=min_neighbors)
            result['verification_results']['lldp'] = check_result
            if not check_result['success']:
                all_checks_passed = False
        
        # Phase 5: Confirm or let rollback
        if all_checks_passed:
            try:
                logger.info(f"Phase 5: All checks passed - confirming commit...")
                self.connection.confirm_commit()
                result['success'] = True
                result['committed'] = True
                result['message'] = f"Configuration successfully deployed and confirmed on {self.device.name}"
                logger.info(f"{'='*60}")
                logger.info(f"SUCCESS: Configuration is now PERMANENT")
                logger.info(f"{'='*60}")
                return result
            
            except Exception as e:
                result['message'] = f"Failed to confirm commit: {str(e)} - will auto-rollback"
                logger.error(f"Phase 5 failed: {e}")
                logger.warning(f"Waiting {timeout}s for automatic rollback...")
                time.sleep(timeout + 5)
                result['rolled_back'] = True
                result['message'] += f" - Auto-rollback completed"
                logger.info(f"Auto-rollback completed")
                return result
        
        else:
            # Verification failed - let auto-rollback happen
            failed_checks = [k for k, v in result['verification_results'].items() if not v['success']]
            result['message'] = f"Verification checks failed: {', '.join(failed_checks)} - waiting for auto-rollback"
            logger.warning(f"Verification failed: {', '.join(failed_checks)}")
            logger.warning(f"NOT calling confirm_commit() - waiting {timeout}s for automatic rollback...")
            time.sleep(timeout + 5)
            result['rolled_back'] = True
            result['message'] += f" - Auto-rollback completed"
            logger.info(f"{'='*60}")
            logger.info(f"AUTO-ROLLBACK: Device returned to previous state")
            logger.info(f"{'='*60}")
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

