"""
Nornir Integration for NetBox Automation Plugin

This module provides Nornir integration to connect to NetBox devices in parallel
using NAPALM drivers, including support for napalm-cumulus.

Uses proper NetBox plugin architecture with get_plugin_config().
Includes failsafe config deployment with Juniper-style commit-confirm workflow.
"""

from typing import Any, Dict, List, Optional, Callable, Tuple, TYPE_CHECKING
from nornir.core.inventory import Inventory, Host, Hosts, Groups, Defaults, ConnectionOptions
from nornir.core.task import Task, Result
from nornir_napalm.plugins.tasks import napalm_get
from nornir.core.plugins.connections import ConnectionPluginRegister
import logging
import time
import sys

if TYPE_CHECKING:
    from dcim.models import Device

logger = logging.getLogger(__name__)

# Production version - direct connections only (no SSH proxy support)

# Import Paramiko for custom SSH client
import paramiko
from paramiko import SSHClient, Transport


class KeyboardInteractiveSSHClient(SSHClient):
    """
    Custom SSH client that uses keyboard-interactive authentication for EOS/IOS devices.
    
    EOS devices only accept 'publickey' or 'keyboard-interactive' authentication,
    not password authentication. This class forces keyboard-interactive mode.
    
    Based on Palo Alto's SSHClient_interactive approach.
    """
    
    def __init__(self, password: str):
        """
        Initialize the custom SSH client.
        
        Args:
            password: Password to use for keyboard-interactive authentication
        """
        super().__init__()
        self.password = password
    
    def keyboard_interactive_handler(
        self, title: str, instructions: str, prompt_list: List[Tuple[str, bool]]
    ) -> List[str]:
        """
        Handler for keyboard-interactive authentication prompts.
        
        Args:
            title: Title of the authentication prompt
            instructions: Instructions from the server
            prompt_list: List of (prompt_text, echo) tuples
            
        Returns:
            List of responses to the prompts
        """
        import sys
        import logging
        logger = logging.getLogger(__name__)
        
        # Debug logging
        logger.error(f"KEYBOARD_INTERACTIVE: title={title}, instructions={instructions}")
        logger.error(f"KEYBOARD_INTERACTIVE: prompt_list={prompt_list}")
        print(f"KEYBOARD_INTERACTIVE DEBUG: title={title}", file=sys.stderr, flush=True)
        print(f"KEYBOARD_INTERACTIVE DEBUG: instructions={instructions}", file=sys.stderr, flush=True)
        print(f"KEYBOARD_INTERACTIVE DEBUG: prompt_list={prompt_list}", file=sys.stderr, flush=True)
        
        responses = []
        for prompt, echo in prompt_list:
            print(f"KEYBOARD_INTERACTIVE DEBUG: Processing prompt: '{prompt}' (echo={echo})", file=sys.stderr, flush=True)
            # Check if this is a password prompt
            if 'password' in prompt.lower() or 'passcode' in prompt.lower() or 'passphrase' in prompt.lower():
                print(f"KEYBOARD_INTERACTIVE DEBUG: Detected password prompt, responding with password", file=sys.stderr, flush=True)
                responses.append(self.password)
            elif 'username' in prompt.lower() or 'login' in prompt.lower():
                # Some devices might ask for username again
                # We'll return empty string and let Paramiko handle it
                print(f"KEYBOARD_INTERACTIVE DEBUG: Detected username prompt, responding with empty", file=sys.stderr, flush=True)
                responses.append('')
            else:
                # Unknown prompt - try password as fallback
                print(f"KEYBOARD_INTERACTIVE DEBUG: Unknown prompt, trying password as fallback", file=sys.stderr, flush=True)
                responses.append(self.password)
        
        print(f"KEYBOARD_INTERACTIVE DEBUG: Returning responses: {[len(r) for r in responses]}", file=sys.stderr, flush=True)
        return responses
    
    def _auth(self, username: str, password: str, *args: Any) -> None:
        """
        Override authentication to use keyboard-interactive instead of password.
        
        This method is called by Paramiko's connect() method.
        We intercept it and use auth_interactive() instead of auth_password().
        
        Args:
            username: Username for authentication
            password: Password (stored in self.password)
            *args: Additional arguments (ignored)
        """
        # Store password for the handler
        self.password = password
        
        # Get the transport and use keyboard-interactive authentication
        transport = self.get_transport()
        if transport is None:
            raise paramiko.ssh_exception.SSHException("Transport not available")
        
        # Use keyboard-interactive authentication
        transport.auth_interactive(username, handler=self.keyboard_interactive_handler)


def napalm_get_with_proxy(task: Task, getters: List[str] = None, retrieve: str = None, **kwargs) -> Result:
    """
    Custom task wrapper for napalm_get that uses direct NAPALM connection (production - direct connections only)

    Args:
        task: Nornir task object
        getters: List of NAPALM getters to execute
        retrieve: Parameter for get_config (e.g., 'running', 'startup', 'all')
        **kwargs: Additional arguments (ignored for compatibility)

    Returns:
        Result object with getter data
    """
    from napalm import get_network_driver

    # Handle getters list - don't overwrite if already provided
    if not getters:
        getters = []

    # Get connection parameters
    hostname = task.host.hostname
    username = task.host.username
    password = task.host.password
    platform = task.host.platform

    # Setup debug logging to multiple outputs
    import sys
    try:
        debug_file = open('/tmp/napalm_debug.log', 'a')
    except:
        debug_file = None
    
    def debug_log(msg):
        """Log to stderr, file, and logger"""
        try:
            print(f"NAPALM_DEBUG: {msg}", file=sys.stderr, flush=True)
        except:
            pass
        if debug_file:
            try:
                debug_file.write(f"{msg}\n")
                debug_file.flush()
            except:
                pass
        logger.error(msg)
    
    # Debug logging (production - direct connections only)

    debug_log(f"=== NAPALM_GET_WITH_PROXY START for {task.host.name} ({hostname}) ===")
    debug_log(f"=== Direct connection to {hostname} (production - no SSH proxy) ===")

    # Create NAPALM driver with detailed error handling and fallback
    logger.info(f"Attempting to get NAPALM driver for platform: '{platform}'")
    driver = None
    
    # Special handling for cumulus platform with fallback
    if platform.lower() == 'cumulus':
        logger.info(f"Platform is cumulus - will use fallback if NAPALM discovery fails")
    
    try:
        # Debug: Check Python path
        import sys
        import traceback
        logger.info(f"Python path: {sys.path[:3]}... (showing first 3)")
        
        # First, check if we can import napalm
        import napalm
        logger.info(f"napalm module imported: {napalm.__file__}")
        
        # Check if napalm_cumulus is available
        try:
            import napalm_cumulus
            logger.info(f"napalm_cumulus module available: {napalm_cumulus.__file__}")
            
            # Try to import the driver class directly
            try:
                from napalm_cumulus.cumulus import CumulusDriver
                logger.info(f"CumulusDriver class importable: {CumulusDriver}")
            except ImportError as driver_import_error:
                logger.warning(f"Cannot import CumulusDriver class: {driver_import_error}")
        except ImportError as e:
            logger.warning(f"napalm_cumulus module not importable: {e}")
            logger.warning(f"   Import error details: {type(e).__name__}: {e}")
        
        # Try to get the driver using NAPALM's standard method
        logger.info(f"Calling get_network_driver('{platform}')...")
        try:
            driver = get_network_driver(platform)
            logger.info(f"Successfully got driver via NAPALM: {driver} (module: {driver.__module__})")
        except Exception as napalm_error:
            logger.warning(f"NAPALM get_network_driver failed: {napalm_error}")
            logger.warning(f"   Error type: {type(napalm_error).__name__}")
            
            # FALLBACK: For cumulus, try direct import
            if platform.lower() == 'cumulus':
                logger.info(f"Attempting fallback: direct import of CumulusDriver...")
                try:
                    # Ensure /opt/napalm-cumulus is in Python path
                    napalm_cumulus_path = '/opt/napalm-cumulus'
                    if napalm_cumulus_path not in sys.path:
                        sys.path.insert(0, napalm_cumulus_path)
                        logger.info(f"Added {napalm_cumulus_path} to Python path")
                    
                    # Try importing - this should work since the module is installed
                    from napalm_cumulus.cumulus import CumulusDriver
                    driver = CumulusDriver
                    logger.info(f"Successfully imported CumulusDriver directly: {driver} (module: {driver.__module__})")
                    logger.info(f"Fallback succeeded - using CumulusDriver directly")
                except ImportError as direct_error:
                    logger.error(f"Direct import also failed: {direct_error}")
                    logger.error(f"   Python path: {sys.path[:5]}")
                    logger.error(f"   Checking if /opt/napalm-cumulus exists...")
                    import os
                    if os.path.exists('/opt/napalm-cumulus'):
                        logger.error(f"   /opt/napalm-cumulus exists")
                        if os.path.exists('/opt/napalm-cumulus/napalm_cumulus'):
                            logger.error(f"   /opt/napalm-cumulus/napalm_cumulus exists")
                        else:
                            logger.error(f"   /opt/napalm-cumulus/napalm_cumulus does NOT exist")
                    else:
                        logger.error(f"   /opt/napalm-cumulus does NOT exist")
                    raise napalm_error  # Re-raise original error
            else:
                raise napalm_error  # Re-raise for non-cumulus platforms
        
    except Exception as e:
        error_msg = f"Cannot import '{platform}'. Is the library installed?"
        logger.error(f"ERROR getting NAPALM driver for platform '{platform}': {e}")
        logger.error(f"   Error type: {type(e).__name__}")
        import traceback
        logger.error(f"   Full traceback:\n{traceback.format_exc()}")
        
        # Additional debugging: Check what drivers are available
        try:
            import importlib.metadata
            eps = importlib.metadata.entry_points(group='napalm.drivers')
            available_drivers = [ep.name for ep in eps]
            logger.error(f"   Available NAPALM drivers via entry points: {available_drivers}")
        except Exception as ep_error:
            logger.error(f"   Could not check entry points: {ep_error}")
        
        # Re-raise with more context
        from napalm.base.exceptions import ModuleImportError
        raise ModuleImportError(error_msg) from e
    
    if driver is None:
        error_msg = f"Failed to get driver for platform '{platform}'"
        logger.error(f"{error_msg}")
        from napalm.base.exceptions import ModuleImportError
        raise ModuleImportError(error_msg)

    # Build optional_args with proper timeout settings for Netmiko
    # These MUST be passed through to Netmiko's ConnectHandler
    optional_args = {
        # Netmiko timeout parameters
        'conn_timeout': 60,      # TCP connection timeout
        'auth_timeout': 60,      # Authentication timeout
        'banner_timeout': 30,    # SSH banner timeout
        'timeout': 100,          # Read timeout (Netmiko default, but explicit)
        # Disable host key checking to avoid interactive prompts
        'ssh_strict': False,     # Don't reject unknown SSH host keys
        'system_host_keys': False,  # Don't load system known_hosts
        'alt_host_keys': False,   # Don't use alternate host keys
        # Force password authentication, disable SSH key auth to target device
        'use_keys': False,       # Don't use SSH keys for device authentication
        'allow_agent': False,    # Don't use SSH agent
    }
    
    # CRITICAL: For EOS devices, force SSH transport (not eAPI/HTTP)
    if platform == 'eos':
        optional_args['transport'] = 'ssh'
        debug_log(f"=== EOS device: Forcing SSH transport (not eAPI) ===")

    # CRITICAL: For EOS/IOS devices, use keyboard-interactive authentication
    # EOS devices only accept 'publickey' or 'keyboard-interactive', not password
    use_keyboard_interactive = platform in ['ios', 'eos', 'nxos']
    
    # Initialize variables for keyboard-interactive patching
    original_build_ssh_client = None
    thread_local = None
    
    if use_keyboard_interactive:
        debug_log(f"=== EOS/IOS device detected: {platform} - Using keyboard-interactive authentication ===")
        
        # Monkey-patch Netmiko's _build_ssh_client method to use our custom client
        # We need to do this before NAPALM creates the Netmiko connection
        import netmiko.base_connection
        import threading
        
        # Store the original method and create a thread-local storage for password
        original_build_ssh_client = netmiko.base_connection.BaseConnection._build_ssh_client
        thread_local = threading.local()
        thread_local.keyboard_interactive_password = password
        
        def patched_build_ssh_client(self):
            """Patched version that returns our custom SSH client for EOS/IOS"""
            # Get password from thread-local storage
            auth_password = getattr(thread_local, 'keyboard_interactive_password', None)
            
            if auth_password:
                # Create our custom SSH client
                ssh_client = KeyboardInteractiveSSHClient(password=auth_password)
                
                # Configure it like Netmiko would
                if self.system_host_keys:
                    ssh_client.load_system_host_keys()
                if self.alt_host_keys and hasattr(self, 'alt_key_file'):
                    import os
                    if os.path.isfile(self.alt_key_file):
                        ssh_client.load_host_keys(self.alt_key_file)
                
                # Set missing host key policy
                ssh_client.set_missing_host_key_policy(self.key_policy)
                
                return ssh_client
            else:
                # Fallback to original if password not set
                return original_build_ssh_client(self)
        
        # Apply the patch
        netmiko.base_connection.BaseConnection._build_ssh_client = patched_build_ssh_client
        debug_log(f"DEBUG: Patched Netmiko's _build_ssh_client to use KeyboardInteractiveSSHClient")
    else:
        debug_log(f"=== Platform {platform} - Using standard password authentication ===")

    # Create NAPALM connection - EXACT same way as test script
    debug_log(f"=== Creating NAPALM device ===")
    debug_log(f"DEBUG: hostname={hostname}")
    debug_log(f"DEBUG: username={username}")
    debug_log(f"DEBUG: platform={platform}")
    debug_log(f"DEBUG: optional_args keys = {list(optional_args.keys())}")
    
    # Create NAPALM device (patch must be active during this)
    try:
        device = driver(
            hostname=hostname,
            username=username,
            password=password,
            timeout=120,  # Increased NAPALM timeout for slow connections
            optional_args=optional_args,
        )
    except Exception as e:
        # Log error before restoring
        debug_log(f"ERROR: Failed to create NAPALM device: {e}")
        # Restore patch even on error (though device.open() won't be called)
        if use_keyboard_interactive and original_build_ssh_client is not None:
            try:
                import netmiko.base_connection
                netmiko.base_connection.BaseConnection._build_ssh_client = original_build_ssh_client
                if thread_local is not None and hasattr(thread_local, 'keyboard_interactive_password'):
                    delattr(thread_local, 'keyboard_interactive_password')
                debug_log(f"DEBUG: Restored original Netmiko _build_ssh_client method (after device creation error)")
            except Exception as restore_error:
                debug_log(f"WARNING: Failed to restore original _build_ssh_client: {restore_error}")
        raise
    
    debug_log(f"=== NAPALM device created ===")
    
    # Open connection
    debug_log(f"=== About to call device.open() for {hostname} ===")
    debug_log(f"DEBUG: Direct connection (production - no proxy)")

    # CRITICAL: Log connection attempt - raise exception if this fails so we know
    import datetime
    import sys
    log_msg = f"\n{'='*80}\n"
    log_msg += f"[{datetime.datetime.now()}] Attempting connection to {hostname}\n"
    log_msg += f"Connection: Direct (production - no SSH proxy)\n"
    log_msg += f"use_keys: {optional_args.get('use_keys', 'NOT SET')}\n"
    log_msg += f"allow_agent: {optional_args.get('allow_agent', 'NOT SET')}\n"
    log_msg += f"About to call device.open()...\n"

    # ALWAYS print to stdout/stderr so it appears in Docker logs
    print(f"DEBUG: NAPALM CONNECTION DEBUG: {log_msg}", file=sys.stderr, flush=True)

    # Try multiple log locations
    for log_path in ['/opt/netbox/netbox/media/napalm_debug.txt', '/tmp/napalm_connection_attempt.log']:
        try:
            with open(log_path, 'a') as f:
                f.write(log_msg)
                f.flush()
            print(f"SUCCESS: Wrote debug log to {log_path}", file=sys.stderr, flush=True)
            break  # Success, stop trying
        except Exception as e:
            print(f"✗ Failed to write to {log_path}: {e}", file=sys.stderr, flush=True)
            continue  # Try next path

    # Close debug file
    if debug_file:
        try:
            debug_file.close()
        except:
            pass

    # CRITICAL: device.open() must happen while patch is active!
    # Retry connection with exponential backoff (handles transient network failures)
    max_retries = 3
    retry_delay = 2  # Initial delay in seconds
    connection_success = False
    conn_error = None
    
    try:
        for attempt in range(max_retries):
            try:
                device.open()
                connection_success = True
                # Log success
                for log_path in ['/opt/netbox/netbox/media/napalm_debug.txt', '/tmp/napalm_connection_attempt.log']:
                    try:
                        with open(log_path, 'a') as f:
                            f.write(f"SUCCESS: SUCCESS: Connected to {hostname} (attempt {attempt + 1})\n")
                            f.flush()
                        break
                    except:
                        continue
                debug_log(f"SUCCESS: Connected to {hostname} on attempt {attempt + 1}")
                break  # Success, exit retry loop
                
            except Exception as e:
                conn_error = e
                # Check if this is a retryable error (connection failure, not auth failure)
                is_retryable = (
                    'Connection' in str(type(e).__name__) or
                    'refused' in str(e).lower() or
                    'timeout' in str(e).lower() or
                    'socket' in str(e).lower()
                )
                
                if attempt < max_retries - 1 and is_retryable:
                    wait_time = retry_delay * (2 ** attempt)  # Exponential: 2s, 4s, 8s
                    debug_log(f"Connection attempt {attempt + 1}/{max_retries} failed: {e}. Retrying in {wait_time}s...")
                    
                    # Log retry attempt
                    for log_path in ['/opt/netbox/netbox/media/napalm_debug.txt', '/tmp/napalm_connection_attempt.log']:
                        try:
                            with open(log_path, 'a') as f:
                                f.write(f"⚠ RETRY {attempt + 1}/{max_retries}: {e}. Waiting {wait_time}s...\n")
                                f.flush()
                            break
                        except:
                            continue
                    
                    time.sleep(wait_time)
                    
                    # Recreate device for retry (old device may be in bad state)
                    try:
                        if device:
                            try:
                                device.close()
                            except:
                                pass
                    except:
                        pass
                    
                    # Recreate NAPALM device for retry
                    try:
                        device = driver(
                            hostname=hostname,
                            username=username,
                            password=password,
                            optional_args=optional_args
                        )
                    except Exception as recreate_error:
                        debug_log(f"Failed to recreate device for retry: {recreate_error}")
                        break  # Can't retry if we can't recreate device
                else:
                    # Final attempt failed or non-retryable error
                    debug_log(f"Connection failed (non-retryable or final attempt): {e}")
                    break
        
        if not connection_success:
            # Log final failure
            for log_path in ['/opt/netbox/netbox/media/napalm_debug.txt', '/tmp/napalm_connection_attempt.log']:
                try:
                    with open(log_path, 'a') as f:
                        f.write(f"✗ FAILED after {max_retries} attempts: {conn_error}\n")
                        f.write(f"Error type: {type(conn_error).__name__}\n")
                        f.flush()
                    break
                except:
                    continue
            raise conn_error
    finally:
        # CRITICAL: Restore original method AFTER device.open() completes (even on error)
        if use_keyboard_interactive and original_build_ssh_client is not None:
            try:
                import netmiko.base_connection
                netmiko.base_connection.BaseConnection._build_ssh_client = original_build_ssh_client
                # Clear thread-local password
                if thread_local is not None and hasattr(thread_local, 'keyboard_interactive_password'):
                    delattr(thread_local, 'keyboard_interactive_password')
                debug_log(f"DEBUG: Restored original Netmiko _build_ssh_client method (after device.open())")
            except Exception as restore_error:
                debug_log(f"WARNING: Failed to restore original _build_ssh_client: {restore_error}")

    # Execute getters
    result = {}
    try:
        for getter in getters:
            try:
                method = getattr(device, f"get_{getter}")
                # Special handling for get_config which needs retrieve parameter
                if getter == "config" and retrieve:
                    result[getter] = method(retrieve=retrieve)
                else:
                    result[getter] = method()
            except Exception as e:
                logger.error(f"Failed to execute getter '{getter}' on {task.host.name}: {e}")
                raise
    finally:
        # Always close the connection
        try:
            device.close()
        except:
            pass


    return Result(host=task.host, result=result)


class NetBoxORMInventory:
    """
    Custom Nornir inventory plugin that reads devices from NetBox using Django ORM
    and uses the correct NAPALM driver (including cumulus for Mellanox/Nvidia devices)
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
        Initialize NetBox ORM-based Nornir inventory (production - direct connections only)

        Args:
            devices: List of NetBox Device objects (optional)
            device_filter: Django ORM filter to select devices (optional)
            username: SSH username (optional, overrides plugin config)
            password: SSH password (optional, overrides plugin config)
        """
        from netbox.plugins import get_plugin_config

        # Read credentials from plugin config
        try:
            napalm_config = get_plugin_config('netbox_automation_plugin', 'napalm', {})
            default_username = napalm_config.get('username')
            default_password = napalm_config.get('password')
            # Support per-platform credentials
            self.platform_credentials = napalm_config.get('platform_credentials', {})
        except Exception as e:
            logger.warning(f"Could not load plugin config: {e}")
            default_username = None
            default_password = None
            self.platform_credentials = {}

        # Use provided credentials or fall back to plugin config
        self.username = username if username is not None else default_username
        self.password = password if password is not None else default_password
        self.device_filter = device_filter or {}
        self.devices = devices
        
    def load(self) -> Inventory:
        """Load inventory from NetBox using Django ORM"""

        # Import Django models here to avoid import-time issues
        from dcim.models import Device
        from netbox_automation_plugin.core.napalm_integration import NAPALMDeviceManager

        # Get devices from NetBox
        if self.devices is None:
            devices = Device.objects.filter(**self.device_filter).select_related(
                'device_type',
                'device_type__manufacturer',
                'site',
                'role',
                'primary_ip4',
                'primary_ip6'
            )
        else:
            devices = self.devices
        
        # Build Nornir hosts
        hosts = Hosts()
        
        for device in devices:
            # Skip devices without primary IP
            if not device.primary_ip4 and not device.primary_ip6:
                logger.warning(f"Device {device.name} has no primary IP, skipping")
                continue
            
            # Get primary IP
            primary_ip = None
            if device.primary_ip4:
                primary_ip = str(device.primary_ip4.address).split('/')[0]
            elif device.primary_ip6:
                primary_ip = str(device.primary_ip6.address).split('/')[0]
            
            # Get NAPALM driver using our integration
            napalm_manager = NAPALMDeviceManager(device)
            driver = napalm_manager.get_driver_name()

            # Get device metadata
            manufacturer = device.device_type.manufacturer.name if device.device_type and device.device_type.manufacturer else 'Unknown'
            model = device.device_type.model if device.device_type else 'Unknown'
            site = device.site.name if device.site else 'Unknown'
            role = device.role.name if device.role else 'Unknown'

            # NEW: Get platform-specific credentials if configured
            device_username = self.username
            device_password = self.password

            # Debug: Log available platform credentials and driver
            logger.error(f"DEBUG: Checking platform credentials for {device.name}")
            logger.error(f"DEBUG: driver = {driver}")
            logger.error(f"DEBUG: platform_credentials keys = {list(self.platform_credentials.keys())}")
            logger.error(f"DEBUG: default username = {self.username}")
            logger.error(f"DEBUG: default password = {self.password}")

            if driver in self.platform_credentials:
                platform_creds = self.platform_credentials[driver]
                device_username = platform_creds.get('username', self.username)
                device_password = platform_creds.get('password', self.password)
                logger.error(f"SUCCESS: Using platform-specific credentials for {device.name} (platform: {driver})")
                logger.error(f"  Username: {device_username}")
                logger.error(f"  Password: {'*' * len(device_password) if device_password else 'None'}")
            else:
                logger.error(f"✗ No platform-specific credentials found for {driver}, using defaults")
                logger.error(f"  Username: {device_username}")
                logger.error(f"  Password: {'*' * len(device_password) if device_password else 'None'}")

            # Production: Direct connections only (no SSH proxy)
            connection_options = {}

            host = Host(
                name=device.name,
                hostname=primary_ip,
                platform=driver,  # NAPALM driver name
                username=device_username,  # Use platform-specific username
                password=device_password,  # Use platform-specific password
                connection_options=connection_options if connection_options else {},
                data={
                    'netbox_id': device.id,
                    'manufacturer': manufacturer,
                    'model': model,
                    'site': site,
                    'role': role,
                    'napalm_driver': driver,
                }
            )
            logger.error(f"=== Created Nornir host {device.name} ===")
            logger.error(f"  hostname={primary_ip}")
            logger.error(f"  platform={driver}")

            hosts[device.name] = host
        
        # Create inventory
        return Inventory(
            hosts=hosts,
            groups=Groups(),
            defaults=Defaults()
        )


class NornirDeviceManager:
    """
    Manager class for running Nornir tasks against NetBox devices
    Uses proper plugin architecture with get_plugin_config()
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
        Initialize Nornir device manager using plugin configuration (production - direct connections only)

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
        self.username = username  # Store for passing to inventory
        self.password = password  # Store for passing to inventory
        self.num_workers = num_workers if num_workers is not None else default_num_workers
        self.nr = None
        
    def initialize(self):
        """Initialize Nornir with NetBox inventory using ThreadedRunner for parallel execution"""
        import logging
        logger = logging.getLogger('netbox_automation_plugin.nornir')

        # Build custom inventory from NetBox devices (production - direct connections only)
        logger.info(f"NornirDeviceManager.initialize: Creating inventory (direct connections)")
        inventory = NetBoxORMInventory(
            devices=self.devices,
            device_filter=self.device_filter,
            username=self.username,
            password=self.password
        ).load()
        logger.info(f"NornirDeviceManager.initialize: Inventory created with {len(inventory.hosts)} hosts")

        # Create Nornir with our inventory and threaded runner for parallel execution
        from nornir.core import Nornir
        from nornir.core.plugins.connections import ConnectionPluginRegister
        from nornir.plugins.runners import ThreadedRunner

        # Auto-register all available connection plugins (napalm, netmiko, etc.)
        ConnectionPluginRegister.auto_register()

        # Create Nornir instance with our custom inventory and threaded runner
        self.nr = Nornir(
            inventory=inventory,
            runner=ThreadedRunner(num_workers=self.num_workers)
        )

        logger.info(f"Nornir initialized with {len(self.nr.inventory.hosts)} hosts, {self.num_workers} workers (direct connections)")
        return self.nr
    
    def get_facts(self) -> Dict[str, Any]:
        """
        Get facts from all devices in parallel

        Returns:
            Dictionary mapping device names to their facts
        """
        if not self.nr:
            self.nr = self.initialize()

        # Run napalm_get task with proxy support
        result = self.nr.run(
            task=napalm_get_with_proxy,
            getters=["facts"]
        )
        
        # Process results
        facts = {}
        for host, task_result in result.items():
            try:
                if task_result.failed:
                    # Get the actual error message
                    error_msg = str(task_result.exception) if task_result.exception else "Unknown error"

                    # Log the full traceback for debugging
                    if task_result.exception:
                        logger.error(f"Task failed for {host}: {error_msg}")
                        import traceback
                        if hasattr(task_result.exception, '__traceback__'):
                            logger.error(''.join(traceback.format_exception(
                                type(task_result.exception),
                                task_result.exception,
                                task_result.exception.__traceback__
                            )))

                    facts[host] = {
                        'error': error_msg,
                        'failed': True
                    }
                else:
                    facts[host] = task_result.result.get('facts', {})
                    facts[host]['failed'] = False
            except Exception as e:
                logger.error(f"Error processing result for {host}: {e}")
                import traceback
                logger.error(traceback.format_exc())
                facts[host] = {
                    'error': f"Error processing result: {e}",
                    'failed': True
                }

        return facts
    
    def get_interfaces(self) -> Dict[str, Any]:
        """
        Get interfaces from all devices in parallel

        Returns:
            Dictionary mapping device names to their interfaces
        """
        if not self.nr:
            self.initialize()

        result = self.nr.run(
            task=napalm_get_with_proxy,
            getters=["interfaces"]
        )
        
        interfaces = {}
        for host, task_result in result.items():
            if task_result.failed:
                interfaces[host] = {
                    'error': str(task_result.exception),
                    'failed': True
                }
            else:
                interfaces[host] = task_result.result.get('interfaces', {})
                interfaces[host]['failed'] = False
        
        return interfaces
    
    def get_config(self, retrieve: str = "all") -> Dict[str, Any]:
        """
        Get configuration from all devices in parallel

        Args:
            retrieve: Type of config to retrieve ("all", "running", "startup", "candidate")

        Returns:
            Dictionary mapping device names to their configurations
        """
        if not self.nr:
            self.initialize()

        result = self.nr.run(
            task=napalm_get_with_proxy,
            getters=["config"],
            retrieve=retrieve
        )
        
        configs = {}
        for host, task_result in result.items():
            if task_result.failed:
                configs[host] = {
                    'error': str(task_result.exception),
                    'failed': True
                }
            else:
                configs[host] = task_result.result.get('config', {})
                configs[host]['failed'] = False
        
        return configs
    
    def get_lldp_neighbors(self) -> Dict[str, Any]:
        """
        Get LLDP neighbors from all devices in parallel

        Returns:
            Dictionary mapping device names to their LLDP neighbors
            Example: {'device1': {'Ethernet1': [{'hostname': 'switch1', 'port': 'Eth1/1'}]}}
        """
        if not self.nr:
            self.initialize()

        result = self.nr.run(
            task=napalm_get_with_proxy,
            getters=["lldp_neighbors"]
        )

        lldp_data = {}
        for host, task_result in result.items():
            if task_result.failed:
                lldp_data[host] = {
                    'error': str(task_result.exception),
                    'failed': True
                }
            else:
                lldp_data[host] = task_result.result.get('lldp_neighbors', {})
                lldp_data[host]['failed'] = False

        return lldp_data

    def get_lldp_neighbors_detail(self) -> Dict[str, Any]:
        """
        Get detailed LLDP neighbor information from all devices in parallel

        Returns:
            Dictionary mapping device names to their detailed LLDP neighbor information
        """

        if not self.nr:
            self.initialize()

        result = self.nr.run(
            task=napalm_get_with_proxy,
            getters=["lldp_neighbors_detail"]
        )

        lldp_detail = {}
        for host, task_result in result.items():
            if task_result.failed:
                # Get full error details including traceback
                import traceback
                error_msg = str(task_result.exception)
                if task_result.exception:
                    error_msg += f"\nTraceback: {''.join(traceback.format_exception(type(task_result.exception), task_result.exception, task_result.exception.__traceback__))}"

                lldp_detail[host] = {
                    'error': error_msg,
                    'failed': True
                }
            else:
                lldp_detail[host] = task_result.result.get('lldp_neighbors_detail', {})
                lldp_detail[host]['failed'] = False

        return lldp_detail

    def run_custom_task(self, task_func: Callable, **kwargs) -> Dict[str, Any]:
        """
        Run a custom Nornir task against all devices

        Args:
            task_func: Nornir task function
            **kwargs: Additional arguments to pass to the task

        Returns:
            Dictionary mapping device names to task results
        """
        if not self.nr:
            self.initialize()

        result = self.nr.run(task=task_func, **kwargs)

        results = {}
        for host, task_result in result.items():
            if task_result.failed:
                results[host] = {
                    'error': str(task_result.exception),
                    'failed': True
                }
            else:
                results[host] = {
                    'result': task_result.result,
                    'failed': False
                }

        return results
    
    def deploy_config_safe(self, config_template: str, replace: bool = True, 
                          timeout: int = 60, checks: Optional[List[str]] = None,
                          critical_interfaces: Optional[List[str]] = None,
                          min_neighbors: int = 0, job_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Deploy configuration to all devices in parallel with failsafe commit-confirm
        
        This method runs the failsafe deployment workflow on all devices simultaneously:
        - Each device loads config (replace or merge)
        - Each device commits with auto-rollback timer
        - Each device runs verification checks
        - Each device confirms if checks pass, or auto-rolls back
        
        Args:
            config_template: Configuration template string (use {{device_name}}, {{site}}, etc.)
            replace: If True, replace entire config. If False, merge incrementally
            timeout: Rollback timer per device in seconds (60-120 recommended)
            checks: List of verification checks to run (default: ['connectivity', 'interfaces', 'lldp'])
            critical_interfaces: List of interface names that must be up
            min_neighbors: Minimum LLDP neighbors required
            job_id: Optional AutomationJob ID for tracking
        
        Returns:
            Dictionary mapping device names to deployment results
        """
        if not self.nr:
            self.initialize()
        
        if checks is None:
            checks = ['connectivity', 'interfaces', 'lldp']
        
        # Define the Nornir task
        def deploy_task(task: Task, config_template: str, replace: bool, timeout: int,
                       checks: List[str], critical_interfaces: Optional[List[str]],
                       min_neighbors: int, job_id: Optional[int]) -> Result:
            """
            Nornir task to deploy config safely on a single device
            """
            from dcim.models import Device
            from netbox_automation_plugin.core.napalm_integration import NAPALMDeviceManager
            
            # Get the NetBox device object
            device_name = task.host.name
            netbox_device_id = task.host.data.get('netbox_id')
            
            try:
                device = Device.objects.get(id=netbox_device_id)
            except Device.DoesNotExist:
                return Result(
                    host=task.host,
                    failed=True,
                    result={
                        'success': False,
                        'committed': False,
                        'rolled_back': False,
                        'message': f'NetBox device with ID {netbox_device_id} not found',
                        'error': 'Device not found'
                    }
                )
            
            # Render template with device context
            rendered_config = _render_template(config_template, device)
            
            # Create NAPALM manager and deploy safely
            manager = NAPALMDeviceManager(device)
            
            try:
                manager.connect()
                
                deploy_result = manager.deploy_config_safe(
                    config=rendered_config,
                    replace=replace,
                    timeout=timeout,
                    checks=checks,
                    critical_interfaces=critical_interfaces,
                    min_neighbors=min_neighbors
                )
                
                # Track job if provided
                if job_id:
                    try:
                        from netbox_automation_plugin.models import AutomationJob
                        job = AutomationJob.objects.get(id=job_id)
                        job.result_data[device_name] = deploy_result
                        job.save()
                    except:
                        pass
                
                return Result(
                    host=task.host,
                    failed=not deploy_result['success'],
                    result=deploy_result
                )
                
            except Exception as e:
                error_result = {
                    'success': False,
                    'committed': False,
                    'rolled_back': False,
                    'message': f'Exception during deployment: {str(e)}',
                    'error': str(e)
                }
                
                # Track job if provided
                if job_id:
                    try:
                        from netbox_automation_plugin.models import AutomationJob
                        job = AutomationJob.objects.get(id=job_id)
                        job.result_data[device_name] = error_result
                        job.save()
                    except:
                        pass
                
                return Result(
                    host=task.host,
                    failed=True,
                    result=error_result
                )
                
            finally:
                manager.disconnect()
        
        # Run deployment in parallel across all devices
        logger.info(f"Starting parallel safe deployment to {len(self.nr.inventory.hosts)} devices")
        logger.info(f"Settings: replace={replace}, timeout={timeout}s, checks={checks}")
        
        result = self.nr.run(
            task=deploy_task,
            config_template=config_template,
            replace=replace,
            timeout=timeout,
            checks=checks,
            critical_interfaces=critical_interfaces,
            min_neighbors=min_neighbors,
            job_id=job_id
        )
        
        # Process results
        results = {}
        success_count = 0
        failed_count = 0
        rolled_back_count = 0
        
        for host, task_result in result.items():
            if task_result.failed:
                results[host] = task_result.result
                failed_count += 1
                if task_result.result.get('rolled_back', False):
                    rolled_back_count += 1
            else:
                results[host] = task_result.result
                if task_result.result.get('success', False):
                    success_count += 1
                else:
                    failed_count += 1
                    if task_result.result.get('rolled_back', False):
                        rolled_back_count += 1
        
        logger.info(f"Deployment complete: {success_count} succeeded, {failed_count} failed, {rolled_back_count} rolled back")
        
        return results

    def deploy_vlan(self, interface_list: List[str], vlan_id: int, platform: str, timeout: int = 150, bond_info_map: Optional[Dict[str, Dict[str, str]]] = None, bonds_to_create_on_device: Optional[Dict[str, Dict[str, Any]]] = None, dry_run: bool = False, preview_callback: Optional[Callable] = None, interface_vlan_map: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Deploy VLAN configuration to multiple interfaces across all devices in parallel.

        CRITICAL: Interfaces on the same device are processed SEQUENTIALLY to avoid:
        - Multiple commit-confirm sessions conflicting
        - Conflicting revision IDs
        - One commit overwriting another
        - Inconsistent device state

        Devices are processed in PARALLEL (up to num_workers, default 20).
        Interfaces per device are processed SEQUENTIALLY.

        Args:
            interface_list: List of interface names (e.g., ['swp7', 'swp8'] or ['device:swp7', 'device:swp8'] for sync mode)
            vlan_id: VLAN ID to configure (1-4094). Ignored if interface_vlan_map is provided (sync mode).
            platform: Platform type ('cumulus' or 'eos')
            timeout: Rollback timeout in seconds (default: 150)
            bond_info_map: Optional dict mapping device_name -> {interface_name: bond_name}
                          If provided, uses bond_name instead of interface_name for config generation
            bonds_to_create_on_device: Optional dict mapping device_name -> {bond_name: {'members': [...], 'bond_interface': obj}}
                                      Bonds that exist in NetBox but not on device - will be created on device
            dry_run: If True, preview changes without deploying (default: False)
            preview_callback: Optional callback function for dry run preview generation
                            Signature: callback(device, interface_list_for_device, platform, vlan_id) -> dict
            interface_vlan_map: Optional dict mapping "device:interface" -> {'untagged_vlan': int, 'tagged_vlans': [int], 'commands': [str]}
                              Used in sync mode to provide per-interface VLAN config from NetBox

        Returns:
            Dictionary mapping device names to deployment results per interface
            {
                'device1': {
                    'swp7': {'success': True, 'committed': True, ...},
                    'swp8': {'success': True, 'committed': True, ...}
                },
                'device2': {...}
            }
        """
        logger.info(f"[DEPLOY_VLAN ENTRY] Called with dry_run={dry_run}, preview_callback={'provided' if preview_callback else 'None'}, interface_list={interface_list[:3]}... ({len(interface_list)} total)")
        print(f"[DEPLOY_VLAN ENTRY] Called with dry_run={dry_run}, preview_callback={'provided' if preview_callback else 'None'}, interface_list={interface_list[:3]}... ({len(interface_list)} total)", file=sys.stderr, flush=True)
        logger.info(f"[DEPLOY_VLAN] Step 1: Checking Nornir initialization...")
        print(f"[DEPLOY_VLAN] Step 1: Checking Nornir initialization...", file=sys.stderr, flush=True)

        if not self.nr:
            logger.info(f"[DEPLOY_VLAN] Step 2: Nornir not initialized, calling initialize()...")
            print(f"[DEPLOY_VLAN] Step 2: Nornir not initialized, calling initialize()...", file=sys.stderr, flush=True)
            self.nr = self.initialize()
            logger.info(f"[DEPLOY_VLAN] Step 2: Nornir initialization complete")
            print(f"[DEPLOY_VLAN] Step 2: Nornir initialization complete", file=sys.stderr, flush=True)
        else:
            logger.info(f"[DEPLOY_VLAN] Step 2: Nornir already initialized, reusing existing instance")
            print(f"[DEPLOY_VLAN] Step 2: Nornir already initialized, reusing existing instance", file=sys.stderr, flush=True)

        num_devices = len(self.nr.inventory.hosts)
        num_interfaces = len(interface_list)
        total_tasks = num_devices * num_interfaces

        logger.info(f"[DEPLOY_VLAN] Step 3: Nornir inventory has {num_devices} devices: {list(self.nr.inventory.hosts.keys())}")
        print(f"[DEPLOY_VLAN] Step 3: Nornir inventory has {num_devices} devices: {list(self.nr.inventory.hosts.keys())}", file=sys.stderr, flush=True)

        mode_str = "DRY RUN preview" if dry_run else "deployment"
        logger.info(f"[DEPLOY_VLAN] Step 4: Starting VLAN {vlan_id} {mode_str} to {num_devices} devices, "
                   f"{num_interfaces} interfaces per device ({total_tasks} total tasks), "
                   f"platform: {platform}, max {self.num_workers} parallel workers")
        print(f"[DEPLOY_VLAN] Step 4: Starting VLAN {vlan_id} {mode_str} to {num_devices} devices, "
              f"{num_interfaces} interfaces per device ({total_tasks} total tasks), "
              f"platform: {platform}, max {self.num_workers} parallel workers", file=sys.stderr, flush=True)
        logger.info(f"[DEPLOY_VLAN] Strategy: Devices in PARALLEL (up to {self.num_workers}), interfaces per device BATCHED")
        logger.info(f"[DEPLOY_VLAN] Step 5: About to start ThreadPoolExecutor with {self.num_workers} workers...")
        print(f"[DEPLOY_VLAN] Step 5: About to start ThreadPoolExecutor with {self.num_workers} workers...", file=sys.stderr, flush=True)
        
        # Group by device: process interfaces sequentially per device, devices in parallel
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        
        all_results = {}
        results_lock = threading.Lock()
        
        def deploy_device_interfaces(device_name: str):
            """
            Deploy VLAN to all interfaces on a single device in ONE commit-confirm session.
            Batches all interface configs together for efficiency.

            In dry run mode, uses preview_callback to generate preview data.
            """
            device_results = {}

            try:
                mode_str = "preview" if dry_run else "deployment"
                logger.info(f"[DEPLOY_START] Device {device_name}: Starting batched {mode_str} of {num_interfaces} interfaces in single session...")
                print(f"[DEPLOY_START] Device {device_name}: Starting batched {mode_str} of {num_interfaces} interfaces in single session...", file=sys.stderr, flush=True)
                logger.info(f"[DEPLOY_START] Device {device_name}: dry_run={dry_run}, preview_callback={'provided' if preview_callback else 'None'}")
                print(f"[DEPLOY_START] Device {device_name}: dry_run={dry_run}, preview_callback={'provided' if preview_callback else 'None'}", file=sys.stderr, flush=True)

                # Build config for all interfaces on this device
                from netbox_automation_plugin.core.napalm_integration import NAPALMDeviceManager
                from dcim.models import Device

                device = Device.objects.get(name=device_name)

                # If dry run mode and callback provided, use callback for preview
                if dry_run and preview_callback:
                    # Build list of interfaces for this device
                    device_interfaces = []
                    logger.info(f"Device {device_name}: Parsing interface_list with {len(interface_list)} entries...")
                    for interface_name in interface_list:
                        # Parse "device:interface" format if present
                        if ':' in interface_name:
                            iface_device_name, actual_interface_name = interface_name.split(':', 1)
                            logger.debug(f"Device {device_name}: Parsed '{interface_name}' -> device='{iface_device_name}', interface='{actual_interface_name}'")
                            if iface_device_name != device_name:
                                logger.debug(f"Device {device_name}: Skipping interface '{interface_name}' (belongs to '{iface_device_name}')")
                                continue
                            device_interfaces.append(actual_interface_name)
                        else:
                            device_interfaces.append(interface_name)

                    logger.info(f"Device {device_name}: Found {len(device_interfaces)} interfaces for this device")

                    # PERFORMANCE FIX: Fetch device data ONCE in Nornir (not in preview_callback)
                    # This avoids multiple connections per device
                    logger.info(f"Device {device_name}: Fetching device data (LLDP + config) for {len(device_interfaces)} interfaces...")

                    # Initialize data structures
                    device_lldp_data = {}
                    device_config_data = {}
                    device_uptime = None
                    connection_error = None

                    # Connect to device ONCE and fetch all data
                    logger.info(f"Device {device_name}: Initializing NAPALMDeviceManager...")
                    print(f"Device {device_name}: Initializing NAPALMDeviceManager...", file=sys.stderr, flush=True)
                    napalm_mgr = NAPALMDeviceManager(device)
                    connection_success = False
                    try:
                        logger.info(f"Device {device_name}: Attempting connection (this may take up to 60s)...")
                        print(f"Device {device_name}: Attempting connection (this may take up to 60s)...", file=sys.stderr, flush=True)
                        connection_success = napalm_mgr.connect()
                        if connection_success:
                            logger.info(f"Device {device_name}: Connection successful!")
                            print(f"Device {device_name}: Connection successful!", file=sys.stderr, flush=True)
                        else:
                            logger.warning(f"Device {device_name}: Connection returned False (failed)")
                            print(f"Device {device_name}: Connection returned False (failed)", file=sys.stderr, flush=True)
                    except Exception as conn_err:
                        connection_error = str(conn_err)
                        logger.error(f"Device {device_name}: Connection exception: {connection_error}")
                        print(f"Device {device_name}: Connection exception: {connection_error}", file=sys.stderr, flush=True)
                        import traceback
                        logger.error(f"Device {device_name}: Connection traceback: {traceback.format_exc()}")
                        print(f"Device {device_name}: Connection traceback: {traceback.format_exc()}", file=sys.stderr, flush=True)

                    if connection_success:
                        try:
                            # 1. Collect LLDP neighbors (device-level, all interfaces)
                            logger.info(f"Device {device_name}: Collecting LLDP neighbors...")
                            print(f"Device {device_name}: Collecting LLDP neighbors...", file=sys.stderr, flush=True)
                            try:
                                device_lldp_data = napalm_mgr.get_lldp_neighbors()
                                if device_lldp_data:
                                    total_neighbors = sum(len(neighbors) for neighbors in device_lldp_data.values())
                                    logger.info(f"Device {device_name}: Collected LLDP data for {len(device_lldp_data)} interfaces with {total_neighbors} total neighbors")
                                    print(f"Device {device_name}: Collected LLDP data for {len(device_lldp_data)} interfaces with {total_neighbors} total neighbors", file=sys.stderr, flush=True)
                                else:
                                    logger.warning(f"Device {device_name}: No LLDP data collected")
                                    print(f"Device {device_name}: No LLDP data collected", file=sys.stderr, flush=True)
                            except Exception as e:
                                logger.error(f"Device {device_name}: Failed to collect LLDP data: {e}")
                                print(f"Device {device_name}: Failed to collect LLDP data: {e}", file=sys.stderr, flush=True)

                            # 2. Collect device config ONCE (for all interfaces)
                            logger.info(f"Device {device_name}: Collecting device configuration...")
                            print(f"Device {device_name}: Collecting device configuration...", file=sys.stderr, flush=True)
                            try:
                                connection = napalm_mgr.connection

                                # Get device uptime
                                try:
                                    if hasattr(connection, 'cli'):
                                        uptime_output = connection.cli(['uptime'])
                                        if uptime_output:
                                            if isinstance(uptime_output, dict):
                                                device_uptime = list(uptime_output.values())[0] if uptime_output else None
                                            else:
                                                device_uptime = str(uptime_output).strip() if uptime_output else None
                                except Exception as e_uptime:
                                    logger.debug(f"Device {device_name}: Could not get uptime: {e_uptime}")

                                # Get full device config (platform-specific)
                                # CRITICAL FIX: Detect platform internally (like LLDP does) to handle platform mismatches
                                detected_platform = napalm_mgr.get_driver_name()
                                logger.debug(f"Device {device_name}: Platform parameter='{platform}', detected='{detected_platform}'")
                                
                                # Use detected platform if parameter doesn't match, but log warning
                                config_platform = platform
                                if platform != detected_platform:
                                    logger.warning(f"Device {device_name}: Platform mismatch - parameter='{platform}', detected='{detected_platform}'. Using detected platform.")
                                    config_platform = detected_platform

                                if config_platform == 'cumulus':
                                    # Use nv config show -o json for Cumulus
                                    try:
                                        config_show_output = None
                                        debug_info = []  # Collect debugging info for UI display
                                        
                                        # Try connection.cli() first
                                        if hasattr(connection, 'cli'):
                                            try:
                                                logger.debug(f"Device {device_name}: Trying connection.cli(['nv config show -o json'])...")
                                                debug_info.append("Method 1: connection.cli(['nv config show -o json'])")
                                                cli_result = connection.cli(['nv config show -o json'])
                                                logger.debug(f"Device {device_name}: cli() returned type: {type(cli_result)}")
                                                
                                                # Extract output from dict if needed
                                                if isinstance(cli_result, dict):
                                                    config_show_output = cli_result.get('nv config show -o json') or list(cli_result.values())[0] if cli_result else None
                                                else:
                                                    config_show_output = cli_result
                                                
                                                if config_show_output:
                                                    logger.debug(f"Device {device_name}: cli() extracted output length: {len(str(config_show_output))}")
                                                    debug_info.append("  → SUCCESS: Got output")
                                                else:
                                                    logger.warning(f"Device {device_name}: cli() returned empty/None output")
                                                    debug_info.append("  → FAILED: Returned empty/None")
                                            except Exception as cli_error:
                                                logger.warning(f"Device {device_name}: connection.cli() failed: {cli_error}")
                                                debug_info.append(f"  → FAILED: {str(cli_error)[:100]}")
                                                config_show_output = None
                                        
                                        # If cli() returned None or failed, try send_command_timing() fallback
                                        if not config_show_output and hasattr(connection, 'device') and hasattr(connection.device, 'send_command_timing'):
                                            try:
                                                logger.info(f"Device {device_name}: Fetching config using send_command_timing('nv config show -o json') (timeout=20s)...")
                                                print(f"Device {device_name}: Fetching config using send_command_timing('nv config show -o json') (timeout=20s)...", file=sys.stderr, flush=True)
                                                debug_info.append("Method 2: send_command_timing('nv config show -o json')")
                                                timing_result = connection.device.send_command_timing('nv config show -o json', read_timeout=20, delay_factor=2)
                                                logger.info(f"Device {device_name}: Config fetch completed (output length: {len(str(timing_result)) if timing_result else 0})")
                                                print(f"Device {device_name}: Config fetch completed (output length: {len(str(timing_result)) if timing_result else 0})", file=sys.stderr, flush=True)
                                                logger.debug(f"Device {device_name}: send_command_timing() returned type: {type(timing_result)}, length: {len(str(timing_result)) if timing_result else 0}")
                                                
                                                if timing_result and str(timing_result).strip():
                                                    config_show_output = str(timing_result).strip()
                                                    logger.debug(f"Device {device_name}: send_command_timing() extracted output length: {len(config_show_output)}")
                                                    debug_info.append("  → SUCCESS: Got output")
                                                else:
                                                    logger.warning(f"Device {device_name}: send_command_timing() returned empty output")
                                                    debug_info.append("  → FAILED: Returned empty output")
                                            except Exception as timing_error:
                                                logger.warning(f"Device {device_name}: send_command_timing() failed: {timing_error}")
                                                debug_info.append(f"  → FAILED: {str(timing_error)[:100]}")
                                                config_show_output = None
                                        
                                        # If still no output, try with --applied flag (Cumulus driver format)
                                        if not config_show_output and hasattr(connection, 'device') and hasattr(connection.device, 'send_command_timing'):
                                            try:
                                                logger.info(f"Device {device_name}: Trying with --applied flag...")
                                                debug_info.append("Method 3: send_command_timing('nv config show --applied -o json')")
                                                applied_result = connection.device.send_command_timing('nv config show --applied -o json', read_timeout=20, delay_factor=2)
                                                logger.debug(f"Device {device_name}: --applied flag returned type: {type(applied_result)}, length: {len(str(applied_result)) if applied_result else 0}")
                                                
                                                if applied_result and str(applied_result).strip():
                                                    config_show_output = str(applied_result).strip()
                                                    logger.debug(f"Device {device_name}: --applied flag extracted output length: {len(config_show_output)}")
                                                    debug_info.append("  → SUCCESS: Got output")
                                                else:
                                                    logger.warning(f"Device {device_name}: --applied flag returned empty output")
                                                    debug_info.append("  → FAILED: Returned empty output")
                                            except Exception as applied_error:
                                                logger.warning(f"Device {device_name}: --applied flag failed: {applied_error}")
                                                debug_info.append(f"  → FAILED: {str(applied_error)[:100]}")
                                                config_show_output = None
                                        
                                        # Last resort: Try NAPALM's get_config() method
                                        if not config_show_output and hasattr(connection, 'get_config'):
                                            try:
                                                logger.info(f"Device {device_name}: Trying NAPALM get_config() method as fallback...")
                                                debug_info.append("Method 4: connection.get_config(retrieve='running', format='json')")
                                                napalm_config = connection.get_config(retrieve='running', format='json')
                                                if napalm_config and 'running' in napalm_config:
                                                    config_show_output = napalm_config['running']
                                                    logger.debug(f"Device {device_name}: get_config() returned length: {len(str(config_show_output)) if config_show_output else 0}")
                                                    debug_info.append("  → SUCCESS: Got output")
                                                else:
                                                    debug_info.append("  → FAILED: No 'running' key in result")
                                            except Exception as napalm_error:
                                                logger.warning(f"Device {device_name}: NAPALM get_config() failed: {napalm_error}")
                                                debug_info.append(f"  → FAILED: {str(napalm_error)[:100]}")
                                        
                                        if not config_show_output:
                                            error_msg = "Config command returned no output"
                                            debug_details = "\n".join(debug_info) if debug_info else "No methods attempted"
                                            full_error = f"{error_msg}\n\nDebug Info (methods attempted):\n{debug_details}"
                                            logger.error(f"Device {device_name}: All config retrieval methods failed or returned no output")
                                            logger.error(f"Device {device_name}: Debug info: {debug_details}")
                                            device_config_data = {'_config_error': full_error}

                                        if config_show_output:
                                            # Extract JSON string - handle different return types
                                            config_json_str = None
                                            
                                            if isinstance(config_show_output, dict):
                                                # Try multiple keys that might contain the output
                                                config_json_str = (
                                                    config_show_output.get('nv config show -o json') or
                                                    config_show_output.get('nv config show --applied -o json') or
                                                    list(config_show_output.values())[0] if config_show_output else None
                                                )
                                            elif isinstance(config_show_output, str):
                                                config_json_str = config_show_output.strip()
                                            else:
                                                config_json_str = str(config_show_output).strip() if config_show_output else None
                                            
                                            if config_json_str and config_json_str.strip():
                                                try:
                                                    import json
                                                    device_config_data = json.loads(config_json_str)
                                                    logger.info(f"Device {device_name}: Collected device config ({len(str(device_config_data))} bytes)")
                                                except json.JSONDecodeError as json_error:
                                                    error_msg = f"Failed to parse JSON config: {str(json_error)}"
                                                    logger.error(f"Device {device_name}: {error_msg}")
                                                    logger.debug(f"Device {device_name}: JSON parse error, first 200 chars: {config_json_str[:200]}")
                                                    device_config_data = {'_config_error': error_msg}
                                            else:
                                                # Empty JSON string
                                                error_msg = "Config command returned empty output"
                                                debug_details = "\n".join(debug_info) if debug_info else "No methods attempted"
                                                full_error = f"{error_msg}\n\nDebug Info (methods attempted):\n{debug_details}"
                                                logger.error(f"Device {device_name}: {error_msg}")
                                                logger.error(f"Device {device_name}: Debug info: {debug_details}")
                                                device_config_data = {'_config_error': full_error}
                                    except Exception as e_config:
                                        error_msg = f"Config collection failed: {str(e_config)}"
                                        debug_details = "\n".join(debug_info) if 'debug_info' in locals() and debug_info else "Exception occurred before methods were attempted"
                                        full_error = f"{error_msg}\n\nDebug Info (methods attempted):\n{debug_details}"
                                        logger.error(f"Device {device_name}: {error_msg}")
                                        logger.error(f"Device {device_name}: Debug info: {debug_details}")
                                        import traceback
                                        logger.error(f"Device {device_name}: Traceback: {traceback.format_exc()}")
                                        device_config_data = {'_config_error': full_error}

                                elif config_platform == 'eos':
                                    # Use show running-config for EOS
                                    try:
                                        if hasattr(connection, 'cli'):
                                            config_show_output = connection.cli(['show running-config'])
                                        elif hasattr(connection, 'device') and hasattr(connection.device, 'send_command'):
                                            # Use send_command_timing() for reliable command execution (avoids prompt detection issues)
                                            logger.info(f"Device {device_name}: Fetching config using send_command_timing()...")
                                            config_show_output = connection.device.send_command_timing('show running-config')
                                        else:
                                            config_show_output = None

                                        if config_show_output:
                                            # Extract config string from dict or use directly
                                            if isinstance(config_show_output, dict):
                                                config_str = list(config_show_output.values())[0] if config_show_output else ''
                                                # Ensure it's a string
                                                device_config_data = str(config_str).strip() if config_str else ''
                                            else:
                                                device_config_data = str(config_show_output).strip()
                                            
                                            if device_config_data:
                                                logger.info(f"Device {device_name}: Collected device config ({len(device_config_data)} bytes)")
                                            else:
                                                # Empty config output
                                                error_msg = "Config command returned empty output"
                                                logger.error(f"Device {device_name}: {error_msg}")
                                                device_config_data = {'_config_error': error_msg}
                                        else:
                                            # No config output
                                            error_msg = "Config command returned no output"
                                            logger.error(f"Device {device_name}: {error_msg}")
                                            device_config_data = {'_config_error': error_msg}
                                    except Exception as e_config:
                                        error_msg = f"Config collection failed: {str(e_config)}"
                                        logger.error(f"Device {device_name}: {error_msg}")
                                        device_config_data = {'_config_error': error_msg}
                                else:
                                    # Unsupported platform
                                    error_msg = f"Unsupported platform for config collection: '{config_platform}' (supported: cumulus, eos)"
                                    logger.error(f"Device {device_name}: {error_msg}")
                                    device_config_data = {'_config_error': error_msg}

                            except Exception as e:
                                error_msg = f"Device data collection failed: {str(e)}"
                                logger.error(f"Device {device_name}: {error_msg}")
                                device_config_data = {'_config_error': error_msg}

                        finally:
                            # Disconnect after collecting all data
                            napalm_mgr.disconnect()
                            logger.info(f"Device {device_name}: Disconnected after data collection")
                    else:
                        error_msg = f"Failed to connect for data collection"
                        if connection_error:
                            error_msg += f": {connection_error}"
                        logger.error(f"Device {device_name}: {error_msg}")
                        # Store connection error for display in UI
                        device_config_data = {'_connection_error': error_msg}

                    # Call preview callback with pre-fetched data
                    logger.info(f"Device {device_name}: Calling preview callback with pre-fetched data...")
                    preview_result = preview_callback(
                        device=device,
                        device_interfaces=device_interfaces,
                        platform=platform,
                        vlan_id=vlan_id,
                        bond_info_map=bond_info_map,
                        device_lldp_data=device_lldp_data,
                        device_config_data=device_config_data,
                        device_uptime=device_uptime
                    )

                    # Store preview results
                    with results_lock:
                        all_results[device_name] = preview_result

                    logger.info(f"Device {device_name}: Preview completed for {len(device_interfaces)} interfaces")
                    return device_name

                # Normal deployment mode - continue with existing logic
                napalm_mgr = NAPALMDeviceManager(device)

                # Check if bridge VLAN already exists (for Cumulus only)
                # PERFORMANCE: Keep connection open - deploy_config_safe() will reuse it
                # PERFORMANCE: Reduced timeout to 20s for faster execution
                bridge_vlans = []
                bridge_vlan_needed = True
                existing_vlan_ids = set()  # Store existing VLAN IDs for sync mode filtering
                if platform == 'cumulus':
                    try:
                        if napalm_mgr.connect():
                            connection = napalm_mgr.connection
                            try:
                                # Get bridge VLANs from device config
                                # PERFORMANCE: Use 20s timeout instead of 60s/90s
                                if hasattr(connection, 'cli'):
                                    config_show_output = connection.cli(['nv config show -o json'])
                                elif hasattr(connection, 'device') and hasattr(connection.device, 'send_command'):
                                    config_show_output = connection.device.send_command_timing('nv config show -o json', read_timeout=20)
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

                                        # Extract bridge VLANs from JSON (same logic as views.py)
                                        # config_data is a list of dicts, each with 'set' key
                                        bridge_vlans = []
                                        try:
                                            if isinstance(config_data, list):
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
                                                                            # The keys are the VLAN strings we need to parse
                                                                            for vlan_key in vlan_data.keys():
                                                                                if isinstance(vlan_key, str):
                                                                                    bridge_vlans.append(vlan_key)
                                        except Exception as e:
                                            logger.debug(f"Could not parse bridge VLANs from JSON: {e}")

                                        # Check if VLAN already exists using same logic as views.py
                                        bridge_vlan_needed = True
                                        if bridge_vlans:
                                            logger.debug(f"Device {device_name}: Found {len(bridge_vlans)} bridge VLAN entry/entries: {bridge_vlans}")
                                            # Parse all bridge VLANs into individual VLAN IDs
                                            existing_vlan_ids = set()  # Reset for this device
                                            for vlan_item in bridge_vlans:
                                                if isinstance(vlan_item, int):
                                                    existing_vlan_ids.add(vlan_item)
                                                elif isinstance(vlan_item, str):
                                                    # Parse ranges and comma-separated values
                                                    parts = vlan_item.replace(' ', '').split(',')
                                                    for part in parts:
                                                        if '-' in part:
                                                            try:
                                                                start, end = map(int, part.split('-'))
                                                                existing_vlan_ids.update(range(start, end + 1))
                                                            except:
                                                                pass
                                                        else:
                                                            try:
                                                                existing_vlan_ids.add(int(part))
                                                            except:
                                                                pass

                                            logger.debug(f"Device {device_name}: Parsed existing bridge VLAN IDs: {sorted(existing_vlan_ids)}")
                                            if vlan_id in existing_vlan_ids:
                                                bridge_vlan_needed = False
                                                logger.info(f"Device {device_name}: VLAN {vlan_id} already exists in bridge - will skip bridge VLAN command")
                                            else:
                                                logger.debug(f"Device {device_name}: VLAN {vlan_id} NOT found in existing bridge VLANs {sorted(existing_vlan_ids)} - will add bridge VLAN command")
                                        else:
                                            logger.debug(f"Device {device_name}: No bridge VLANs found in device config - will add bridge VLAN command")
                            except Exception as e:
                                logger.warning(f"Could not get bridge VLANs from {device_name}: {e}")
                                logger.warning(f"Will add bridge VLAN command anyway (idempotent - safe to add even if already exists)")
                                import traceback
                                logger.debug(f"Traceback: {traceback.format_exc()}")
                                # Continue - will add command anyway (idempotent)
                            # PERFORMANCE FIX: Don't disconnect here - keep connection open
                            # deploy_config_safe() will reuse the existing connection (line 1795 in napalm_integration.py)
                            logger.info(f"Device {device_name}: Keeping connection open for deployment (performance optimization)")
                    except Exception as e:
                        logger.warning(f"Could not connect to {device_name} to check bridge VLANs: {e}")
                        # Continue - will add command anyway (idempotent)
                
                # Build combined config for all interfaces
                all_config_lines = []
                interface_mapping = {}  # {original_interface: target_interface} for NetBox updates
                members_vlan_removed = set()  # Track member interfaces that already had VLAN removed (avoid duplicates)

                # STEP 1: Add bond creation commands FIRST (Case 2: bonds in NetBox but not on device)
                if bonds_to_create_on_device and device_name in bonds_to_create_on_device:
                    logger.info(f"Device {device_name}: Creating {len(bonds_to_create_on_device[device_name])} bond(s) on device (from NetBox)")
                    all_config_lines.append("# BOND CREATION - Bonds exist in NetBox but NOT on device")
                    all_config_lines.append("#" + "=" * 78)

                    for bond_name, bond_data in bonds_to_create_on_device[device_name].items():
                        members = bond_data['members']
                        bond_interface = bond_data['bond_interface']

                        all_config_lines.append(f"# Creating bond {bond_name} on device (from NetBox)")
                        all_config_lines.append(f"# Members: {', '.join(members)}")
                        all_config_lines.append(f"nv set interface {bond_name} type bond")

                        # Add all members
                        for member in members:
                            all_config_lines.append(f"nv set interface {bond_name} bond member {member}")

                        # LACP settings
                        all_config_lines.append(f"nv set interface {bond_name} bond lacp-rate fast")
                        all_config_lines.append(f"nv set interface {bond_name} bond lacp-bypass on")

                        # Add bond to bridge domain
                        all_config_lines.append(f"nv set interface {bond_name} bridge domain br_default")
                        all_config_lines.append("")

                    all_config_lines.append("#" + "=" * 78)
                    all_config_lines.append("")
                    logger.info(f"Device {device_name}: Added bond creation commands for {len(bonds_to_create_on_device[device_name])} bond(s)")

                # STEP 2: Add VLAN configuration commands
                for interface_name in interface_list:
                    # In sync mode, interface_name might be in "device:interface" format
                    # Parse it and skip if it doesn't belong to this device
                    actual_interface_name = interface_name
                    if ':' in interface_name:
                        # Extract device name and interface name from "device:interface" format
                        iface_device_name, actual_interface_name = interface_name.split(':', 1)
                        # Skip if this interface doesn't belong to current device
                        if iface_device_name != device_name:
                            logger.debug(f"[DEBUG] Device {device_name}: Skipping interface {interface_name} (belongs to {iface_device_name})")
                            continue
                        logger.debug(f"[DEBUG] Device {device_name}: Parsed {interface_name} → {actual_interface_name}")

                    # CRITICAL: Validate actual_interface_name - must be a single interface name, not comma-separated list
                    # This can happen if interface names are incorrectly parsed from the form
                    if ',' in actual_interface_name:
                        logger.error(f"[ERROR] Device {device_name}: Interface name contains comma-separated values: '{actual_interface_name}'")
                        logger.error(f"[ERROR] This is invalid - interface names cannot contain commas. Using first part only.")
                        actual_interface_name = actual_interface_name.split(',')[0].strip()
                        logger.error(f"[ERROR] Using sanitized interface name: '{actual_interface_name}'")
                    
                    # Get bond interface name if available (use actual_interface_name for bond lookup)
                    target_interface = actual_interface_name
                    if bond_info_map and device_name in bond_info_map:
                        device_bond_map = bond_info_map[device_name]
                        if actual_interface_name in device_bond_map:
                            # bond_info_map structure: {device_name: {interface_name: {'bond_name': str, 'bond_id': str, 'source': str}}}
                            bond_name = device_bond_map[actual_interface_name]['bond_name']
                            
                            # CRITICAL: Validate bond_name - must be a single interface name, not comma-separated list
                            if ',' in bond_name:
                                logger.error(f"[ERROR] Device {device_name}: Bond name contains comma-separated values: '{bond_name}'")
                                logger.error(f"[ERROR] This is invalid - bond names cannot contain commas. Using first part only.")
                                bond_name = bond_name.split(',')[0].strip()
                                logger.error(f"[ERROR] Using sanitized bond name: '{bond_name}'")
                            
                            target_interface = bond_name
                            logger.info(f"[DEBUG] SUCCESS: BOND REDIRECT: Device {device_name}: Interface {actual_interface_name} → Bond {target_interface}")
                        else:
                            logger.debug(f"[DEBUG] Device {device_name}: Interface {actual_interface_name} not in bond map - using directly")
                    else:
                        logger.debug(f"[DEBUG] Device {device_name}: No bond map available - using interface {actual_interface_name} directly")

                    interface_mapping[actual_interface_name] = target_interface
                    
                    # CRITICAL: If bond is detected, remove VLAN config from member interface FIRST
                    # VLANs should NOT be configured on both bond and member interfaces simultaneously
                    # PERFORMANCE: Skip pre-deployment checks - we'll verify post-deployment with batched config fetch
                    # The unset/removal commands are idempotent, so safe to add without checking first
                    if actual_interface_name != target_interface:
                        # Bond detected - need to remove VLAN config from member interface
                        # Only process each member interface once (avoid duplicates if multiple members map to same bond)
                        if actual_interface_name not in members_vlan_removed:
                            logger.info(f"Device {device_name}: Bond detected ({actual_interface_name} → {target_interface}) - will remove VLAN config from member interface")
                            
                            # PERFORMANCE: Always add removal commands (idempotent)
                            # Pre-deployment checks removed - we'll verify post-deployment with batched config fetch
                            if platform == 'cumulus':
                                unset_cmd = f"nv unset interface {actual_interface_name} bridge domain br_default access"
                                all_config_lines.append(f"# Remove VLAN config from member interface {actual_interface_name} (VLAN will be on bond {target_interface})")
                                all_config_lines.append(unset_cmd)
                                members_vlan_removed.add(actual_interface_name)
                                logger.debug(f"Device {device_name}: Added command to remove VLAN from member {actual_interface_name} (will verify post-deployment)")
                            elif platform == 'eos':
                                # For EOS, add removal commands (idempotent - safe even if VLAN doesn't exist)
                                all_config_lines.append(f"# Remove VLAN config from member interface {actual_interface_name} (VLAN will be on bond {target_interface})")
                                all_config_lines.append(f"interface {actual_interface_name}")
                                all_config_lines.append(f"   no switchport access vlan")
                                all_config_lines.append(f"   no switchport mode")
                                members_vlan_removed.add(actual_interface_name)
                                logger.debug(f"Device {device_name}: Added commands to remove VLAN from member {actual_interface_name} (will verify post-deployment)")
                    
                    # Generate config for this interface
                    # In sync mode, use per-interface VLAN config from interface_vlan_map
                    # In normal mode, use vlan_id parameter (or interface_vlan_map if provided)
                    # Check both "device:interface" format and just "interface" format for lookup
                    vlan_config = None
                    if interface_vlan_map:
                        # Try exact match first
                        if interface_name in interface_vlan_map:
                            vlan_config = interface_vlan_map[interface_name]
                        else:
                            # Try "device:interface" format
                            map_key = f"{device_name}:{actual_interface_name}"
                            if map_key in interface_vlan_map:
                                vlan_config = interface_vlan_map[map_key]
                    
                    if vlan_config:
                        # Use pre-generated commands from interface_vlan_map (sync mode or normal mode with tagged VLANs)
                        commands = vlan_config.get('commands', [])
                        tagged_vlans = vlan_config.get('tagged_vlans', [])
                        vlans_already_in_bridge = vlan_config.get('vlans_already_in_bridge', [])
                        
                        # Add informational message about tagged VLANs already present (Cumulus only)
                        if platform == 'cumulus' and tagged_vlans and vlans_already_in_bridge:
                            # Filter to only tagged VLANs that are already in bridge
                            tagged_already_present = [v for v in tagged_vlans if v in vlans_already_in_bridge]
                            if tagged_already_present:
                                vlan_list_str = ', '.join(map(str, sorted(tagged_already_present)))
                                all_config_lines.append(f"# Tagged VLANs already present on device: {vlan_list_str}")
                        
                        # Replace interface names in commands with target_interface (bond if detected)
                        # Commands are like "nv set interface swp3 bridge domain br_default access 3000"
                        # Need to replace "swp3" with "bond3" if bond detected
                        for cmd in commands:
                            # Skip bridge VLAN command if VLAN already exists in bridge
                            # Check if this is a bridge VLAN command
                            if 'nv set bridge domain br_default vlan' in cmd:
                                # Extract VLAN ID from command (e.g., "nv set bridge domain br_default vlan 3040")
                                import re
                                vlan_match = re.search(r'vlan\s+(\d+)', cmd)
                                if vlan_match:
                                    cmd_vlan_id = int(vlan_match.group(1))
                                    # Check if this VLAN already exists in bridge
                                    if existing_vlan_ids and cmd_vlan_id in existing_vlan_ids:
                                        logger.info(f"Device {device_name}: Skipping bridge VLAN command for VLAN {cmd_vlan_id} (already exists in bridge)")
                                        continue  # Skip this command
                            
                            if actual_interface_name != target_interface:
                                # Replace actual_interface_name with target_interface in command
                                # Handle both "nv set interface {name}" and "interface {name}" formats
                                if f"interface {actual_interface_name}" in cmd:
                                    cmd = cmd.replace(f"interface {actual_interface_name}", f"interface {target_interface}")
                                elif f"nv set interface {actual_interface_name}" in cmd:
                                    cmd = cmd.replace(f"nv set interface {actual_interface_name}", f"nv set interface {target_interface}")
                            all_config_lines.append(cmd)
                        
                        logger.debug(f"Device {device_name}: Using sync mode config for {interface_name} → {target_interface}: {len(commands)} commands")
                    else:
                        # Normal mode: Use vlan_id parameter
                        if platform == 'cumulus':
                            # Bridge VLAN command (only add once, and only if needed)
                            if bridge_vlan_needed:
                                if not any('nv set bridge domain br_default vlan' in line for line in all_config_lines):
                                    logger.debug(f"Device {device_name}: Adding bridge VLAN command for VLAN {vlan_id} (bridge_vlan_needed={bridge_vlan_needed})")
                                    all_config_lines.append(f"nv set bridge domain br_default vlan {vlan_id}")
                                else:
                                    logger.debug(f"Device {device_name}: Bridge VLAN command already in config list - skipping duplicate")
                            else:
                                logger.debug(f"Device {device_name}: Skipping bridge VLAN command for VLAN {vlan_id} (already exists in bridge)")
                            # Interface access command
                            all_config_lines.append(f"nv set interface {target_interface} bridge domain br_default access {vlan_id}")
                        elif platform == 'eos':
                            all_config_lines.append(f"interface {target_interface}")
                            all_config_lines.append(f"   switchport mode access")
                            all_config_lines.append(f"   switchport access vlan {vlan_id}")
                
                # Combine all configs into single string
                combined_config = '\n'.join(all_config_lines)
                logger.info(f"Device {device_name}: Combined config for {num_interfaces} interfaces ({len(all_config_lines)} commands)")
                
                # Deploy combined config in single session
                if not napalm_mgr.connect():
                    error_msg = f"Failed to connect to {device_name}"
                    logger.error(error_msg)
                    # Mark all interfaces as failed (only those belonging to this device)
                    for interface_name in interface_list:
                        # Parse interface name if in "device:interface" format
                        actual_interface_name = interface_name
                        if ':' in interface_name:
                            iface_device_name, actual_interface_name = interface_name.split(':', 1)
                            # Skip if this interface doesn't belong to current device
                            if iface_device_name != device_name:
                                continue

                        device_results[actual_interface_name] = {
                            'success': False,
                            'committed': False,
                            'rolled_back': False,
                            'error': error_msg,
                            'message': error_msg,
                            'logs': [f"✗ Connection failed: {error_msg}"]
                        }
                    return device_name
                
                try:
                    # Add header to logs showing all interfaces being deployed together
                    combined_logs = []
                    combined_logs.append("=" * 80)
                    combined_logs.append("DEPLOYMENT EXECUTION (ALL INTERFACES TOGETHER)")
                    combined_logs.append("=" * 80)
                    combined_logs.append("")
                    combined_logs.append("=" * 80)
                    combined_logs.append(f"[BATCHED DEPLOYMENT] Device: {device_name}")
                    combined_logs.append(f"[BATCHED DEPLOYMENT] Deploying {num_interfaces} interface(s) in SINGLE commit-confirm session")
                    combined_logs.append("=" * 80)
                    combined_logs.append("")
                    combined_logs.append("Interfaces being configured:")
                    for interface_name in interface_list:
                        # Parse interface name if in "device:interface" format
                        actual_interface_name = interface_name
                        if ':' in interface_name:
                            iface_device_name, actual_interface_name = interface_name.split(':', 1)
                            # Skip if this interface doesn't belong to current device
                            if iface_device_name != device_name:
                                continue

                        target_interface = interface_mapping[actual_interface_name]
                        if target_interface != actual_interface_name:
                            combined_logs.append(f"  - {actual_interface_name} → {target_interface} (bond detected)")
                        else:
                            combined_logs.append(f"  - {actual_interface_name}")
                    combined_logs.append("")
                    combined_logs.append(f"Combined configuration ({len(all_config_lines)} commands):")
                    for line in all_config_lines:
                        combined_logs.append(f"  {line}")
                    combined_logs.append("")
                    
                    # Build list of target interfaces for baseline collection
                    # IMPORTANT: For LLDP, use MEMBER interfaces (physical interfaces) because LLDP neighbors
                    # are only shown on physical interfaces, not on bond interfaces
                    # For interface state and traffic stats, use BOND interfaces if detected
                    target_interfaces_for_baseline = []  # For interface state/traffic stats (bonds if detected)
                    member_interfaces_for_lldp = []  # For LLDP checks (always member interfaces)
                    seen_targets = set()
                    seen_members = set()
                    
                    # Build interface_vlan_map for verification (maps target_interface -> vlan_config)
                    # This is used in sync mode for comprehensive per-interface verification
                    verification_vlan_map = {}  # Maps target_interface -> vlan_config
                    
                    for interface_name in interface_list:
                        # Parse interface name if in "device:interface" format
                        actual_interface_name = interface_name
                        if ':' in interface_name:
                            iface_device_name, actual_interface_name = interface_name.split(':', 1)
                            # Skip if this interface doesn't belong to current device
                            if iface_device_name != device_name:
                                continue
                        
                        # Get target interface (bond if detected, otherwise member interface)
                        target_interface = interface_mapping.get(actual_interface_name, actual_interface_name)
                        
                        # For interface state and traffic stats: use bond interfaces if detected
                        # Only add each target interface once (deduplicate bonds)
                        if target_interface not in seen_targets:
                            target_interfaces_for_baseline.append(target_interface)
                            seen_targets.add(target_interface)
                            if target_interface != actual_interface_name:
                                logger.info(f"Device {device_name}: Baseline will collect interface state/traffic for bond {target_interface} (not member {actual_interface_name})")
                            
                            # Build verification_vlan_map: map target_interface -> vlan_config
                            # In sync mode, get vlan_config from interface_vlan_map
                            if interface_vlan_map and interface_name in interface_vlan_map:
                                vlan_config = interface_vlan_map[interface_name]
                                # Only add once per target_interface (if multiple members map to same bond)
                                if target_interface not in verification_vlan_map:
                                    verification_vlan_map[target_interface] = vlan_config
                                    logger.debug(f"Device {device_name}: Added verification VLAN map for {target_interface}: untagged={vlan_config.get('untagged_vlan')}, tagged={vlan_config.get('tagged_vlans')}")
                        
                        # For LLDP: ALWAYS use member interfaces (physical interfaces) because LLDP neighbors
                        # are only shown on physical interfaces, not on bond interfaces
                        if actual_interface_name not in seen_members:
                            member_interfaces_for_lldp.append(actual_interface_name)
                            seen_members.add(actual_interface_name)
                            if target_interface != actual_interface_name:
                                logger.info(f"Device {device_name}: LLDP will be checked on member {actual_interface_name} (bond {target_interface} has no LLDP neighbors)")
                    
                    # Deploy all interfaces in one commit-confirm session
                    # Pass MEMBER interfaces for LLDP checks, TARGET interfaces (bonds) for other checks
                    # Pass verification_vlan_map for comprehensive per-interface verification in sync mode
                    deploy_result = napalm_mgr.deploy_config_safe(
                        config=combined_config,
                        timeout=timeout,
                        replace=False,
                        interface_names=target_interfaces_for_baseline,  # For interface state/traffic stats (bonds if detected)
                        interface_names_for_lldp=member_interfaces_for_lldp,  # For LLDP checks (always member interfaces)
                        vlan_id=vlan_id,
                        interface_vlan_map=verification_vlan_map if verification_vlan_map else None  # For comprehensive verification in sync mode
                    )
                    
                    # Prepend batched deployment header to logs
                    if deploy_result.get('logs'):
                        deploy_result['logs'] = combined_logs + deploy_result['logs']
                    
                    # Collect all interface mappings for the batched deployment message
                    interface_mappings = []  # List of (member_interface, bond_interface) tuples
                    for interface_name in interface_list:
                        # Parse interface name if in "device:interface" format
                        actual_interface_name = interface_name
                        if ':' in interface_name:
                            iface_device_name, actual_interface_name = interface_name.split(':', 1)
                            # Skip if this interface doesn't belong to current device
                            if iface_device_name != device_name:
                                continue
                        
                        # Look up target interface using actual_interface_name
                        target_interface = interface_mapping.get(actual_interface_name, actual_interface_name)
                        interface_mappings.append((actual_interface_name, target_interface))
                    
                    # Generate a single comprehensive batched deployment message
                    note_lines = []
                    note_lines.append("")
                    note_lines.append("--- Batched Deployment Information ---")
                    
                    # Group interfaces by type (bonds vs regular)
                    bond_interfaces = []  # (member, bond) tuples
                    regular_interfaces = []  # interface names
                    
                    for member_iface, target_iface in interface_mappings:
                        if target_iface != member_iface:
                            bond_interfaces.append((member_iface, target_iface))
                        else:
                            regular_interfaces.append(member_iface)
                    
                    # Build the message
                    if bond_interfaces:
                        # List all bond mappings
                        bond_lines = []
                        for member, bond in bond_interfaces:
                            bond_lines.append(f"'{member}' (member) → '{bond}' (bond)")
                        
                        note_lines.append(f"Interface(s) {', '.join(bond_lines)} were deployed as part of a batched session")
                        note_lines.append(f"with {num_interfaces} interface(s) on device {device_name} in a single commit-confirm session.")
                        
                        # List all unique bond interfaces
                        unique_bonds = sorted(set(bond for _, bond in bond_interfaces))
                        unique_members = sorted(set(member for member, _ in bond_interfaces))
                        note_lines.append(f"Configuration was applied to bond interface(s): {', '.join(unique_bonds)}")
                        note_lines.append(f"(not member interface(s): {', '.join(unique_members)}).")
                    elif regular_interfaces:
                        # Regular interfaces (no bonds)
                        if len(regular_interfaces) == 1:
                            note_lines.append(f"Interface '{regular_interfaces[0]}' was deployed as part of a batched session")
                        else:
                            interface_list_str = ', '.join(f"'{iface}'" for iface in sorted(regular_interfaces))
                            note_lines.append(f"Interface(s) {interface_list_str} were deployed as part of a batched session")
                        note_lines.append(f"with {num_interfaces} interface(s) on device {device_name} in a single commit-confirm session.")
                    else:
                        # Fallback (shouldn't happen)
                        note_lines.append(f"{num_interfaces} interface(s) were deployed as part of a batched session")
                        note_lines.append(f"on device {device_name} in a single commit-confirm session.")
                    
                    note_lines.append("")
                    
                    # Create result for each interface (all share same deployment result)
                    for interface_name in interface_list:
                        # Parse interface name if in "device:interface" format
                        actual_interface_name = interface_name
                        if ':' in interface_name:
                            iface_device_name, actual_interface_name = interface_name.split(':', 1)
                            # Skip if this interface doesn't belong to current device
                            if iface_device_name != device_name:
                                continue

                        # Look up target interface using actual_interface_name
                        target_interface = interface_mapping.get(actual_interface_name, actual_interface_name)
                        interface_result = deploy_result.copy()
                        interface_result['original_interface_name'] = actual_interface_name
                        interface_result['target_interface'] = target_interface
                        interface_result['logs'] = deploy_result.get('logs', []).copy()  # Copy to avoid modifying shared list

                        # Add the batched deployment note BEFORE the completion message
                        # Find where "=== Deployment Completed ===" appears and insert note before it
                        if interface_result['logs']:
                            completion_idx = None
                            for i, log_line in enumerate(interface_result['logs']):
                                if "=== Deployment Completed ===" in log_line:
                                    completion_idx = i
                                    break

                            # Insert note before completion message, or at the end if not found
                            if completion_idx is not None:
                                interface_result['logs'] = (
                                    interface_result['logs'][:completion_idx] +
                                    note_lines +
                                    interface_result['logs'][completion_idx:]
                                )
                            else:
                                # If no completion message found, append at the end
                                interface_result['logs'].extend(note_lines)

                        # Store result using actual_interface_name as key
                        device_results[actual_interface_name] = interface_result
                    
                    if deploy_result.get('success'):
                        logger.info(f"Device {device_name}: Successfully deployed VLAN {vlan_id} to {num_interfaces} interfaces in single session")
                        
                        # PERFORMANCE: Post-deployment verification - batch check all member interfaces at once
                        # Fetch config once and verify all member interfaces from single config fetch
                        if platform == 'cumulus' and members_vlan_removed:
                            try:
                                logger.info(f"Device {device_name}: Performing post-deployment verification for {len(members_vlan_removed)} member interface(s)...")
                                # Reconnect if needed (connection might be closed)
                                if not napalm_mgr.connection or not hasattr(napalm_mgr.connection, 'device'):
                                    if not napalm_mgr.connect():
                                        logger.warning(f"Device {device_name}: Could not reconnect for post-deployment verification")
                                    else:
                                        logger.debug(f"Device {device_name}: Reconnected for post-deployment verification")
                                
                                if napalm_mgr.connection and hasattr(napalm_mgr.connection, 'device'):
                                    # Fetch applied config once (post-deployment state)
                                    logger.info(f"Device {device_name}: Fetching post-deployment config (nv config show --applied -o json, timeout=20s)...")
                                    config_show_output = None
                                    if hasattr(napalm_mgr.connection, 'cli'):
                                        try:
                                            config_show_output = napalm_mgr.connection.cli(['nv config show --applied -o json'])
                                        except:
                                            pass
                                    
                                    if not config_show_output and hasattr(napalm_mgr.connection.device, 'send_command_timing'):
                                        config_show_output = napalm_mgr.connection.device.send_command_timing(
                                            'nv config show --applied -o json', 
                                            read_timeout=20
                                        )
                                    
                                    if config_show_output:
                                        # Parse JSON config
                                        import json
                                        config_json_str = None
                                        if isinstance(config_show_output, dict):
                                            config_json_str = config_show_output.get('nv config show --applied -o json') or list(config_show_output.values())[0] if config_show_output else None
                                        else:
                                            config_json_str = str(config_show_output).strip()
                                        
                                        if config_json_str:
                                            try:
                                                config_data = json.loads(config_json_str)
                                                # Cache config for potential reuse
                                                cached_config = config_data
                                                
                                                # Batch check all member interfaces at once
                                                member_verification_results = {}
                                                for member_iface in members_vlan_removed:
                                                    # Check if member interface still has VLAN config (should be removed)
                                                    member_has_vlan = False
                                                    try:
                                                        # Parse config to find interface VLAN config
                                                        if isinstance(config_data, list):
                                                            for item in config_data:
                                                                if isinstance(item, dict) and 'set' in item:
                                                                    set_data = item['set']
                                                                    if isinstance(set_data, dict) and 'interface' in set_data:
                                                                        iface_data = set_data['interface']
                                                                        if isinstance(iface_data, dict) and member_iface in iface_data:
                                                                            iface_config = iface_data[member_iface]
                                                                            if isinstance(iface_config, dict) and 'bridge' in iface_config:
                                                                                bridge_data = iface_config['bridge']
                                                                                if isinstance(bridge_data, dict) and 'domain' in bridge_data:
                                                                                    domain_data = bridge_data['domain']
                                                                                    if isinstance(domain_data, dict) and 'br_default' in domain_data:
                                                                                        br_default_data = domain_data['br_default']
                                                                                        if isinstance(br_default_data, dict) and 'access' in br_default_data:
                                                                                            member_has_vlan = True
                                                                                            break
                                                    except Exception as parse_err:
                                                        logger.debug(f"Device {device_name}: Could not parse member {member_iface} from config: {parse_err}")
                                                    
                                                    member_verification_results[member_iface] = {
                                                        'has_vlan': member_has_vlan,
                                                        'verified': True
                                                    }
                                                
                                                # Add verification results to logs
                                                verification_logs = []
                                                verification_logs.append("")
                                                verification_logs.append("--- Post-Deployment Member Interface Verification ---")
                                                for member_iface, result in member_verification_results.items():
                                                    if result['has_vlan']:
                                                        verification_logs.append(f"⚠ Member {member_iface}: Still has VLAN config (should be removed)")
                                                    else:
                                                        verification_logs.append(f"✓ Member {member_iface}: VLAN config successfully removed")
                                                verification_logs.append("")
                                                
                                                # Add verification logs to all interface results
                                                for interface_name in interface_list:
                                                    actual_interface_name = interface_name
                                                    if ':' in interface_name:
                                                        iface_device_name, actual_interface_name = interface_name.split(':', 1)
                                                        if iface_device_name != device_name:
                                                            continue
                                                    
                                                    if actual_interface_name in device_results:
                                                        if 'logs' not in device_results[actual_interface_name]:
                                                            device_results[actual_interface_name]['logs'] = []
                                                        device_results[actual_interface_name]['logs'].extend(verification_logs)
                                                
                                                logger.info(f"Device {device_name}: Post-deployment verification completed for {len(member_verification_results)} member interface(s)")
                                            except json.JSONDecodeError as json_err:
                                                logger.warning(f"Device {device_name}: Could not parse post-deployment config JSON: {json_err}")
                                            except Exception as verify_err:
                                                logger.warning(f"Device {device_name}: Post-deployment verification failed: {verify_err}")
                                        else:
                                            logger.warning(f"Device {device_name}: Post-deployment config fetch returned empty output")
                                    else:
                                        logger.warning(f"Device {device_name}: Could not fetch post-deployment config (connection unavailable)")
                            except Exception as verify_ex:
                                logger.warning(f"Device {device_name}: Post-deployment verification exception: {verify_ex}")
                                # Don't fail deployment if verification fails
                    else:
                        logger.warning(f"Device {device_name}: Deployment failed for {num_interfaces} interfaces: {deploy_result.get('error', 'Unknown error')}")
                
                finally:
                    napalm_mgr.disconnect()
                
                # Store results thread-safely
                with results_lock:
                    all_results[device_name] = device_results
                
                logger.info(f"Device {device_name}: Completed deployment of {len(device_results)} interfaces")
                return device_name
                
            except Exception as e:
                import traceback
                error_traceback = traceback.format_exc()
                logger.error(f"Device {device_name}: Critical error during deployment: {e}")
                logger.error(f"Device {device_name}: Full traceback:\n{error_traceback}")
                # Mark all interfaces as failed for this device (only those belonging to this device)
                device_interfaces = {}
                for iface in interface_list:
                    # Parse interface name if in "device:interface" format
                    actual_iface = iface
                    if ':' in iface:
                        iface_device_name, actual_iface = iface.split(':', 1)
                        # Skip if this interface doesn't belong to current device
                        if iface_device_name != device_name:
                            continue

                    device_interfaces[actual_iface] = {
                        'success': False,
                        'committed': False,
                        'rolled_back': False,
                        'error': str(e),
                        'message': f'Device deployment failed: {str(e)}',
                        'traceback': error_traceback
                    }

                with results_lock:
                    all_results[device_name] = device_interfaces
                return device_name
        
        # Execute device deployments in parallel (limited by num_workers)
        # Each device processes its interfaces sequentially
        device_names = list(self.nr.inventory.hosts.keys())
        logger.info(f"[DEPLOY_VLAN] Step 6: Starting ThreadPoolExecutor with {min(len(device_names), self.num_workers)} workers for {len(device_names)} devices...")
        print(f"[DEPLOY_VLAN] Step 6: Starting ThreadPoolExecutor with {min(len(device_names), self.num_workers)} workers for {len(device_names)} devices...", file=sys.stderr, flush=True)
        logger.info(f"[DEPLOY_VLAN] Device list: {device_names}")
        print(f"[DEPLOY_VLAN] Device list: {device_names}", file=sys.stderr, flush=True)
        
        with ThreadPoolExecutor(max_workers=min(len(device_names), self.num_workers)) as executor:
            logger.info(f"[DEPLOY_VLAN] Step 7: Submitting {len(device_names)} tasks to executor...")
            print(f"[DEPLOY_VLAN] Step 7: Submitting {len(device_names)} tasks to executor...", file=sys.stderr, flush=True)
            futures = {}
            for device in device_names:
                logger.info(f"[DEPLOY_VLAN] Submitting task for device: {device}")
                print(f"[DEPLOY_VLAN] Submitting task for device: {device}", file=sys.stderr, flush=True)
                future = executor.submit(deploy_device_interfaces, device)
                futures[future] = device
            
            logger.info(f"[DEPLOY_VLAN] Step 8: All tasks submitted, waiting for completion...")
            print(f"[DEPLOY_VLAN] Step 8: All tasks submitted, waiting for completion...", file=sys.stderr, flush=True)
            completed = 0
            for future in as_completed(futures):
                completed += 1
                device_name = futures[future]
                logger.info(f"[DEPLOY_VLAN] Device {device_name} task completed ({completed}/{num_devices}), getting result...")
                print(f"[DEPLOY_VLAN] Device {device_name} task completed ({completed}/{num_devices}), getting result...", file=sys.stderr, flush=True)
                try:
                    result = future.result()
                    logger.info(f"[DEPLOY_VLAN] Device {device_name} deployment completed successfully ({completed}/{num_devices})")
                    print(f"[DEPLOY_VLAN] Device {device_name} deployment completed successfully ({completed}/{num_devices})", file=sys.stderr, flush=True)
                except Exception as e:
                    logger.error(f"[DEPLOY_VLAN] Device {device_name} deployment raised exception: {e}")
                    print(f"[DEPLOY_VLAN] Device {device_name} deployment raised exception: {e}", file=sys.stderr, flush=True)
                    import traceback
                    logger.error(f"[DEPLOY_VLAN] Device {device_name} exception traceback: {traceback.format_exc()}")
                    print(f"[DEPLOY_VLAN] Device {device_name} exception traceback: {traceback.format_exc()}", file=sys.stderr, flush=True)
        
        logger.info(f"[DEPLOY_VLAN] Step 9: All tasks complete. VLAN deployment finished for {len(all_results)} devices, {num_interfaces} interfaces")
        print(f"[DEPLOY_VLAN] Step 9: All tasks complete. VLAN deployment finished for {len(all_results)} devices, {num_interfaces} interfaces", file=sys.stderr, flush=True)
        
        return all_results


def _render_template(template: str, device: "Device") -> str:
    """
    Render configuration template with device context
    
    Args:
        template: Configuration template string
        device: NetBox Device object
    
    Returns:
        Rendered configuration string
    """
    context = {
        'device_name': device.name,
        'device_type': device.device_type.model if device.device_type else '',
        'manufacturer': device.device_type.manufacturer.name if device.device_type and device.device_type.manufacturer else '',
        'site': device.site.name if device.site else '',
        'role': device.role.name if device.role else '',
        'primary_ip': device.primary_ip4.address.split('/')[0] if device.primary_ip4 else '',
    }
    
    rendered = template
    for key, value in context.items():
        rendered = rendered.replace(f'{{{{{key}}}}}', str(value))
    
    return rendered


def deploy_vlan_config(task, interface_name: str, vlan_id: int, platform: str, timeout: int = 90, original_interface_name: Optional[str] = None):
    """
    Nornir task: Deploy VLAN configuration to a device interface with safe deployment.
    Uses NAPALM's commit-confirm for Cumulus, configure session for EOS.
    
    CRITICAL: For Cumulus bonds, interface_name should be the bond interface (e.g., 'bond3'),
    not the member interface (e.g., 'swp3'). This ensures config is applied to the logical
    interface that actually carries traffic.
    
    Args:
        task: Nornir task object
        interface_name: Target interface name (bond interface if bond member, e.g., 'bond3', 'swp7')
        vlan_id: VLAN ID to configure
        platform: Platform type ('cumulus' or 'eos')
        timeout: Rollback timeout in seconds (default: 90)
        original_interface_name: Original interface name from form (member interface if bond, e.g., 'swp3')
                                 Used for NetBox updates. If None, uses interface_name.
    
    Returns:
        Nornir Result with deployment status
    """
    from netbox_automation_plugin.core.napalm_integration import NAPALMDeviceManager
    from dcim.models import Device
    import logging
    
    logger = logging.getLogger('netbox_automation_plugin')
    device_name = task.host.name
    
    # Use original_interface_name for NetBox lookups, interface_name for device config
    netbox_interface_name = original_interface_name if original_interface_name else interface_name
    
    try:
        # Get NetBox device object
        device = Device.objects.get(name=device_name)
        
        # CRITICAL: Validate interface exists in NetBox before deploying
        # Check original interface (member) in NetBox, but deploy to bond interface on device
        from dcim.models import Interface
        try:
            interface = Interface.objects.get(device=device, name=netbox_interface_name)
            logger.info(f"{device_name}: Interface {netbox_interface_name} validated in NetBox")
            if interface_name != netbox_interface_name:
                logger.info(f"{device_name}: Will deploy to bond interface {interface_name} (NetBox interface: {netbox_interface_name})")
        except Interface.DoesNotExist:
            # If bond interface doesn't exist in NetBox, that's OK - we'll create it
            # But if original interface doesn't exist, that's an error
            if interface_name == netbox_interface_name:
                error_msg = f"Interface {interface_name} does not exist on device {device_name} in NetBox"
                logger.error(error_msg)
                return {
                    "success": False,
                    "committed": False,
                    "rolled_back": False,
                    "error": error_msg,
                    "message": error_msg,
                    "logs": [f"✗ Pre-deployment validation failed: {error_msg}"]
                }
            else:
                logger.info(f"{device_name}: Bond interface {interface_name} not in NetBox (will be created), member {netbox_interface_name} exists")
        
        # Generate platform-specific config
        # IMPORTANT: For Cumulus, include bridge VLAN command + interface access command
        # Load all commands at once to create single revision ID
        if platform == 'cumulus':
            # Command 1: Add VLAN to bridge domain (must be first)
            bridge_vlan_cmd = f"nv set bridge domain br_default vlan {vlan_id}"
            # Command 2: Set interface access VLAN
            interface_access_cmd = f"nv set interface {interface_name} bridge domain br_default access {vlan_id}"
            # Combine both commands - load all at once
            config = f"{bridge_vlan_cmd}\n{interface_access_cmd}"
            
            # Debug logging
            if interface_name != netbox_interface_name:
                logger.info(f"[DEBUG] SUCCESS: CONFIG GENERATION: Device {device_name}: Using BOND interface '{interface_name}' (member: '{netbox_interface_name}')")
                logger.info(f"[DEBUG]   Generated commands:")
                logger.info(f"[DEBUG]     1. {bridge_vlan_cmd}")
                logger.info(f"[DEBUG]     2. {interface_access_cmd}")
            else:
                logger.info(f"[DEBUG] SUCCESS: CONFIG GENERATION: Device {device_name}: Using interface '{interface_name}' directly (not a bond member)")
                logger.info(f"[DEBUG]   Generated commands:")
                logger.info(f"[DEBUG]     1. {bridge_vlan_cmd}")
                logger.info(f"[DEBUG]     2. {interface_access_cmd}")
            logger.info(f"[DEBUG]   Total commands: 2 (bridge VLAN + interface access)")
            logger.info(f"[DEBUG]   Config will be loaded as single block to create one revision ID")
        elif platform == 'eos':
            config = f"interface {interface_name}\n   switchport mode access\n   switchport access vlan {vlan_id}"
        else:
            return {"success": False, "error": f"Unsupported platform: {platform}"}
        
        # Use NAPALMDeviceManager for safe deployment
        # Pass interface_name (bond) for device config
        # Note: original_interface_name is stored in the task context for NetBox updates later
        napalm_mgr = NAPALMDeviceManager(device)
        result = napalm_mgr.deploy_config_safe(
            config=config,
            timeout=timeout,
            replace=False,
            interface_name=interface_name,  # Use bond interface for device config
            vlan_id=vlan_id
        )
        
        # Store original_interface_name in result for NetBox updates
        if original_interface_name:
            result['original_interface_name'] = original_interface_name
        
        return result
        
    except Device.DoesNotExist:
        error_msg = f"Device {device_name} not found in NetBox"
        logger.error(error_msg)
        return {"success": False, "error": error_msg}
    except Exception as e:
        error_msg = f"Exception during VLAN deployment: {str(e)}"
        logger.error(f"{device_name}: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {"success": False, "error": error_msg}
