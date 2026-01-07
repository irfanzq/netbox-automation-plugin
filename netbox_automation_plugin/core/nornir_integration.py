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
    print(f"🔍 NAPALM CONNECTION DEBUG: {log_msg}", file=sys.stderr, flush=True)

    # Try multiple log locations
    for log_path in ['/opt/netbox/netbox/media/napalm_debug.txt', '/tmp/napalm_connection_attempt.log']:
        try:
            with open(log_path, 'a') as f:
                f.write(log_msg)
                f.flush()
            print(f"✓ Wrote debug log to {log_path}", file=sys.stderr, flush=True)
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
                            f.write(f"✓ SUCCESS: Connected to {hostname} (attempt {attempt + 1})\n")
                            f.flush()
                        break
                    except:
                        continue
                debug_log(f"✓ Connected to {hostname} on attempt {attempt + 1}")
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
                logger.error(f"✓ Using platform-specific credentials for {device.name} (platform: {driver})")
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

    def deploy_vlan(self, interface_list: List[str], vlan_id: int, platform: str, timeout: int = 90, bond_info_map: Optional[Dict[str, Dict[str, str]]] = None) -> Dict[str, Any]:
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
            interface_list: List of interface names (e.g., ['swp7', 'swp8'])
            vlan_id: VLAN ID to configure (1-4094)
            platform: Platform type ('cumulus' or 'eos')
            timeout: Rollback timeout in seconds (default: 90)
            bond_info_map: Optional dict mapping device_name -> {interface_name: bond_name}
                          If provided, uses bond_name instead of interface_name for config generation
        
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
        if not self.nr:
            self.nr = self.initialize()
        
        num_devices = len(self.nr.inventory.hosts)
        num_interfaces = len(interface_list)
        total_tasks = num_devices * num_interfaces
        
        logger.info(f"Starting VLAN {vlan_id} deployment to {num_devices} devices, "
                   f"{num_interfaces} interfaces per device ({total_tasks} total tasks), "
                   f"platform: {platform}, max {self.num_workers} parallel workers")
        logger.info(f"Strategy: Devices in PARALLEL (up to {self.num_workers}), interfaces per device SEQUENTIALLY")
        
        # Group by device: process interfaces sequentially per device, devices in parallel
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        
        all_results = {}
        results_lock = threading.Lock()
        
        def deploy_device_interfaces(device_name: str):
            """
            Deploy VLAN to all interfaces on a single device in ONE commit-confirm session.
            Batches all interface configs together for efficiency.
            """
            device_results = {}
            
            try:
                logger.info(f"Device {device_name}: Starting batched deployment of {num_interfaces} interfaces in single session...")
                
                # Build config for all interfaces on this device
                from netbox_automation_plugin.core.napalm_integration import NAPALMDeviceManager
                from dcim.models import Device
                
                device = Device.objects.get(name=device_name)
                napalm_mgr = NAPALMDeviceManager(device)
                
                # Check if bridge VLAN already exists (for Cumulus only)
                bridge_vlans = []
                bridge_vlan_needed = True
                if platform == 'cumulus':
                    try:
                        if napalm_mgr.connect():
                            connection = napalm_mgr.connection
                            try:
                                # Get bridge VLANs from device config
                                if hasattr(connection, 'cli'):
                                    config_show_output = connection.cli(['nv config show -o json'])
                                elif hasattr(connection, 'device') and hasattr(connection.device, 'send_command'):
                                    config_show_output = connection.device.send_command('nv config show -o json', read_timeout=60)
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
                                            # Parse all bridge VLANs into individual VLAN IDs
                                            existing_vlan_ids = set()
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
                                            
                                            if vlan_id in existing_vlan_ids:
                                                bridge_vlan_needed = False
                                                logger.info(f"Device {device_name}: VLAN {vlan_id} already exists in bridge - will skip bridge VLAN command")
                            except Exception as e:
                                logger.warning(f"Could not get bridge VLANs from {device_name}: {e}")
                                # Continue - will add command anyway (idempotent)
                            finally:
                                napalm_mgr.disconnect()
                    except Exception as e:
                        logger.warning(f"Could not connect to {device_name} to check bridge VLANs: {e}")
                        # Continue - will add command anyway (idempotent)
                
                # Build combined config for all interfaces
                all_config_lines = []
                interface_mapping = {}  # {original_interface: target_interface} for NetBox updates

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

                    # Get bond interface name if available (use actual_interface_name for bond lookup)
                    target_interface = actual_interface_name
                    if bond_info_map and device_name in bond_info_map:
                        device_bond_map = bond_info_map[device_name]
                        if actual_interface_name in device_bond_map:
                            target_interface = device_bond_map[actual_interface_name]
                            logger.info(f"[DEBUG] ✓ BOND REDIRECT: Device {device_name}: Interface {actual_interface_name} → Bond {target_interface}")
                        else:
                            logger.debug(f"[DEBUG] Device {device_name}: Interface {actual_interface_name} not in bond map - using directly")
                    else:
                        logger.debug(f"[DEBUG] Device {device_name}: No bond map available - using interface {actual_interface_name} directly")

                    interface_mapping[actual_interface_name] = target_interface
                    
                    # Generate config for this interface
                    if platform == 'cumulus':
                        # Bridge VLAN command (only add once, and only if needed)
                        if bridge_vlan_needed and not any('nv set bridge domain br_default vlan' in line for line in all_config_lines):
                            all_config_lines.append(f"nv set bridge domain br_default vlan {vlan_id}")
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
                        target_interface = interface_mapping[interface_name]
                        if target_interface != interface_name:
                            combined_logs.append(f"  - {interface_name} → {target_interface} (bond detected)")
                        else:
                            combined_logs.append(f"  - {interface_name}")
                    combined_logs.append("")
                    combined_logs.append(f"Combined configuration ({len(all_config_lines)} commands):")
                    for line in all_config_lines:
                        combined_logs.append(f"  {line}")
                    combined_logs.append("")
                    
                    # Deploy all interfaces in one commit-confirm session
                    deploy_result = napalm_mgr.deploy_config_safe(
                        config=combined_config,
                        timeout=timeout,
                        replace=False,
                        interface_name=None,  # Multiple interfaces, no single interface_name
                        vlan_id=vlan_id
                    )
                    
                    # Prepend batched deployment header to logs
                    if deploy_result.get('logs'):
                        deploy_result['logs'] = combined_logs + deploy_result['logs']
                    
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

                        # Add interface-specific note about batched deployment BEFORE the completion message
                        # Find where "=== Deployment Completed ===" appears and insert note before it
                        if interface_result['logs']:
                            completion_idx = None
                            for i, log_line in enumerate(interface_result['logs']):
                                if "=== Deployment Completed ===" in log_line:
                                    completion_idx = i
                                    break

                            # Prepare note lines
                            note_lines = []
                            note_lines.append("")
                            note_lines.append("--- Batched Deployment Information ---")
                            if target_interface != actual_interface_name:
                                # Bond detected - show both interfaces clearly
                                note_lines.append(f"Interface '{actual_interface_name}' (member) → '{target_interface}' (bond) was deployed as part of a batched session")
                                note_lines.append(f"with {num_interfaces} interface(s) on device {device_name} in a single commit-confirm session.")
                                note_lines.append(f"Configuration was applied to bond interface '{target_interface}' (not member interface '{actual_interface_name}').")
                            else:
                                # No bond - just show the interface
                                note_lines.append(f"Interface '{actual_interface_name}' was deployed as part of a batched session")
                                note_lines.append(f"with {num_interfaces} interface(s) on device {device_name} in a single commit-confirm session.")
                            note_lines.append("")

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
                logger.error(f"Device {device_name}: Critical error during deployment: {e}")
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
                        'message': f'Device deployment failed: {str(e)}'
                    }

                with results_lock:
                    all_results[device_name] = device_interfaces
                return device_name
        
        # Execute device deployments in parallel (limited by num_workers)
        # Each device processes its interfaces sequentially
        device_names = list(self.nr.inventory.hosts.keys())
        with ThreadPoolExecutor(max_workers=min(len(device_names), self.num_workers)) as executor:
            futures = {executor.submit(deploy_device_interfaces, device): device for device in device_names}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                device_name = futures[future]
                try:
                    future.result()
                    logger.debug(f"Device {device_name} deployment completed ({completed}/{num_devices})")
                except Exception as e:
                    logger.error(f"Device {device_name} deployment raised exception: {e}")
        
        logger.info(f"VLAN deployment complete for {len(all_results)} devices, {num_interfaces} interfaces")
        
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
                logger.info(f"[DEBUG] ✓ CONFIG GENERATION: Device {device_name}: Using BOND interface '{interface_name}' (member: '{netbox_interface_name}')")
                logger.info(f"[DEBUG]   Generated commands:")
                logger.info(f"[DEBUG]     1. {bridge_vlan_cmd}")
                logger.info(f"[DEBUG]     2. {interface_access_cmd}")
            else:
                logger.info(f"[DEBUG] ✓ CONFIG GENERATION: Device {device_name}: Using interface '{interface_name}' directly (not a bond member)")
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
