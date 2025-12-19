#!/usr/bin/env python3
"""
Test script to verify Cumulus interface config parsing logic using NAPALM.
Tests nv config show -o json parsing with the same parser used in the workflow.

Usage:
    python3 test_cumulus_parsing.py
"""

import re
import json
import sys
import time

try:
    from napalm import get_network_driver
except ImportError:
    print("ERROR: NAPALM not installed. Please install with:")
    print("  pip install napalm napalm-cumulus")
    sys.exit(1)

# Device credentials
DEVICE_CREDENTIALS = {
    'username': 'cumulus',
    'password': 'Admin@123',
    'optional_args': {
        'conn_timeout': 30,
        'timeout': 60,
        'auth_timeout': 30,
        'allow_agent': False,
        'look_for_keys': False,
        'use_keys': False,
    }
}

# Device to test
DEVICE_IP = '172.19.1.29'

# Interfaces to test
TEST_INTERFACES = ['swp4', 'swp5', 'swp6', 'eth0', 'swp1', 'swp18']

def _looks_like_value(key):
    """Check if a key looks like a value (IP address, number, etc.) rather than a config key."""
    import re
    # IP address pattern (IPv4 or IPv6 with CIDR)
    if re.match(r'^[0-9a-fA-F:.]+/\d+$', key):
        return True
    # Pure number
    if re.match(r'^\d+$', key):
        return True
    # IPv6 address without CIDR (less common but possible)
    if '::' in key and re.match(r'^[0-9a-fA-F:.]+$', key):
        return True
    return False

def _interface_matches_range(interface_name, range_key):
    """
    Check if an interface name matches a range pattern.
    Examples:
    - swp6 matches swp1-32 -> True
    - swp6 matches swp6 -> True
    - swp6 matches bond6 -> False
    - swp6 matches swp1-5 -> False
    """
    import re
    # Exact match
    if interface_name == range_key:
        return True
    
    # Range pattern: swp1-32, bond3-6, etc.
    range_match = re.match(r'^([a-zA-Z]+)(\d+)-(\d+)$', range_key)
    if range_match:
        prefix = range_match.group(1)
        start = int(range_match.group(2))
        end = int(range_match.group(3))
        
        # Check if interface matches the prefix and is in range
        interface_match = re.match(r'^([a-zA-Z]+)(\d+)$', interface_name)
        if interface_match:
            iface_prefix = interface_match.group(1)
            iface_num = int(interface_match.group(2))
            
            if iface_prefix == prefix and start <= iface_num <= end:
                return True
    
    # Comma-separated list: bond3,5-6
    if ',' in range_key:
        parts = range_key.split(',')
        for part in parts:
            if _interface_matches_range(interface_name, part.strip()):
                return True
    
    return False

def _find_interface_config_in_json(config_data, interface_name):
    """
    Find interface configuration in JSON, handling ranges and bond members.
    Extracts from the "interface" key in the JSON structure.
    """
    # Navigate to interface section - extract from "interface" key
    interfaces = None
    for item in config_data:
        if isinstance(item, dict) and 'set' in item:
            set_data = item['set']
            if isinstance(set_data, dict) and 'interface' in set_data:
                interfaces = set_data['interface']  # Extract from "interface" key
                break
    
    if not interfaces or not isinstance(interfaces, dict):
        return None
    
    # First, try exact match
    if interface_name in interfaces:
        return interfaces[interface_name]
    
    # Check if interface is in a range (e.g., swp6 in swp1-32)
    for range_key, range_config in interfaces.items():
        if _interface_matches_range(interface_name, range_key) and interface_name != range_key:
            # Interface is in a range - return the range config
            if isinstance(range_config, dict):
                range_config = range_config.copy()
                range_config['_inherited_from'] = range_key
            return range_config
    
    # Check if interface is a bond member
    for bond_name, bond_config in interfaces.items():
        if isinstance(bond_config, dict) and 'bond' in bond_config:
            bond_members = bond_config.get('bond', {}).get('member', {})
            if isinstance(bond_members, dict) and interface_name in bond_members:
                # Interface is a bond member - return bond config with note
                if isinstance(bond_config, dict):
                    bond_config = bond_config.copy()
                    bond_config['_bond_member_of'] = bond_name
                return bond_config
    
    return None

def _parse_json_to_nv_commands(config_dict, base_path, interface_name):
    """
    Recursively parse JSON structure from nv config show -o json and generate nv set commands.
    This is a fully generic parser with NO hardcoding - it parses and displays whatever is 
    present in the interface configuration.
    """
    commands = []
    
    if not isinstance(config_dict, dict):
        return commands
    
    for key, value in config_dict.items():
        # Build the path
        path = f"{base_path} {key}" if base_path else key
        
        # Check if value is a dict (nested structure)
        if isinstance(value, dict):
            # Check if dict is empty {} - this means the key itself might be a value or a boolean flag
            if not value:
                # Empty dict - could be:
                # 1. Key is a value (e.g., IP address as key: "172.19.1.29/23": {})
                # 2. Key is a boolean flag (e.g., "up": {}, "on": {}, "enable": {})
                if _looks_like_value(key):
                    # Key is the value - use it directly
                    if base_path:
                        # Filter out link-local IPv6
                        if 'address' in base_path.lower() and key.startswith('fe80::'):
                            pass  # Skip link-local
                        else:
                            commands.append(f"nv set interface {interface_name} {base_path} {key}")
                else:
                    # Empty dict with a key - this is a boolean flag or config option
                    # Show it regardless - no hardcoding, just show what's there
                    commands.append(f"nv set interface {interface_name} {path}")
            else:
                # Non-empty dict - recurse into nested structure
                nested_commands = _parse_json_to_nv_commands(value, path, interface_name)
                commands.extend(nested_commands)
        else:
            # Leaf value - generate command
            # Filter out link-local IPv6
            if 'address' in key.lower() and isinstance(value, str) and value.startswith('fe80::'):
                pass  # Skip link-local
            else:
                # Convert value to string
                value_str = str(value)
                commands.append(f"nv set interface {interface_name} {path} {value_str}")
    
    return commands

def test_interface_config(device_ip, interface_name):
    """Test getting and parsing config for a specific interface"""
    print(f"\n{'='*80}")
    print(f"Testing interface: {interface_name} on device: {device_ip}")
    print(f"{'='*80}")
    
    driver = get_network_driver('cumulus')
    
    try:
        device = driver(
            hostname=device_ip,
            username=DEVICE_CREDENTIALS['username'],
            password=DEVICE_CREDENTIALS['password'],
            optional_args=DEVICE_CREDENTIALS['optional_args']
        )
        
        print(f"\n[1] Connecting to device {device_ip}...")
        device.open()
        print(f"[OK] Connected successfully")
        
        # Get device uptime to verify connection (using NAPALM cli method)
        try:
            if hasattr(device, 'cli'):
                uptime_output = device.cli(['uptime'])
                if uptime_output:
                    if isinstance(uptime_output, dict):
                        uptime_output = list(uptime_output.values())[0] if uptime_output else None
                    else:
                        uptime_output = str(uptime_output).strip() if uptime_output else None
                    if uptime_output:
                        print(f"[OK] Device uptime: {uptime_output}")
        except Exception as e_uptime:
            print(f"[WARN] Could not get uptime: {e_uptime}")
        
        # Primary method: Use nv config show -o json
        print(f"\n[2] Running 'nv config show -o json'...")
        config_json_str = None
        max_retries = 3
        
        # Try device.cli() first (if available), otherwise use device.device.send_command()
        use_cli_method = hasattr(device, 'cli')
        use_netmiko = hasattr(device, 'device') and hasattr(device.device, 'send_command')
        
        print(f"[DEBUG] Has cli() method: {use_cli_method}")
        print(f"[DEBUG] Has device.send_command() method: {use_netmiko}")
        
        for attempt in range(max_retries):
            try:
                # Try cli() first, but fall back to Netmiko if it returns None
                if use_cli_method:
                    print(f"[DEBUG] Attempt {attempt + 1}: Trying device.cli(['nv config show -o json'])...")
                    config_show_output = device.cli(['nv config show -o json'])
                    
                    # If cli() returns None, fall back to Netmiko
                    if config_show_output is None and use_netmiko:
                        print(f"[DEBUG] cli() returned None, falling back to Netmiko send_command()...")
                        config_show_output = device.device.send_command('nv config show -o json', read_timeout=60)
                elif use_netmiko:
                    print(f"[DEBUG] Attempt {attempt + 1}: Using device.device.send_command('nv config show -o json')...")
                    # Use Netmiko directly - no expect_string needed, it will auto-detect prompt
                    config_show_output = device.device.send_command('nv config show -o json', read_timeout=60)
                else:
                    print(f"[FAIL] No supported method to send commands")
                    device.close()
                    return
                
                print(f"[DEBUG] Output type: {type(config_show_output)}")
                if config_show_output:
                    print(f"[DEBUG] Output length: {len(str(config_show_output))}")
                    print(f"[DEBUG] Output preview (first 200 chars): {str(config_show_output)[:200]}")
                else:
                    print(f"[DEBUG] Output is None or empty")
                
                if config_show_output:
                    # Extract output (might be keyed by command if using cli(), or direct string if using Netmiko)
                    if isinstance(config_show_output, dict):
                        print(f"[DEBUG] Output is dict, keys: {list(config_show_output.keys())}")
                        if 'nv config show -o json' in config_show_output:
                            config_json_str = config_show_output['nv config show -o json']
                        elif 'nv config show' in config_show_output:
                            config_json_str = config_show_output['nv config show']
                        else:
                            # Try to get first value
                            values = list(config_show_output.values())
                            if values:
                                config_json_str = values[0]
                                print(f"[DEBUG] Using first dict value, type: {type(config_json_str)}")
                            else:
                                config_json_str = None
                    else:
                        # Netmiko returns string directly
                        config_json_str = str(config_show_output).strip()
                        print(f"[DEBUG] Output is string (from Netmiko), length: {len(config_json_str)}")
                    
                    print(f"[DEBUG] Extracted config_json_str type: {type(config_json_str)}")
                    print(f"[DEBUG] Extracted config_json_str length: {len(config_json_str) if config_json_str else 0}")
                    
                    if config_json_str and config_json_str.strip():
                        print(f"[OK] Got JSON output (attempt {attempt + 1})")
                        print(f"[DEBUG] First 200 chars: {config_json_str[:200]}...")
                        break
                    else:
                        print(f"[DEBUG] config_json_str is empty or None")
                
                if attempt < max_retries - 1:
                    time.sleep(1)
                    print(f"[RETRY] Attempt {attempt + 1} failed, retrying...")
            except Exception as e_retry:
                import traceback
                print(f"[DEBUG] Exception details:")
                traceback.print_exc()
                if attempt < max_retries - 1:
                    time.sleep(1)
                    print(f"[RETRY] Attempt {attempt + 1} failed with error: {e_retry}, retrying...")
                else:
                    print(f"[FAIL] Failed after {max_retries} attempts: {e_retry}")
        
        if not config_json_str or not config_json_str.strip():
            print(f"[FAIL] No JSON output received")
            device.close()
            return
        
        # Parse JSON
        print(f"\n[3] Parsing JSON...")
        try:
            config_data = json.loads(config_json_str)
            print(f"[OK] JSON parsed successfully")
            print(f"[DEBUG] JSON structure type: {type(config_data)}")
            if isinstance(config_data, list):
                print(f"[DEBUG] JSON is a list with {len(config_data)} items")
                for i, item in enumerate(config_data):
                    if isinstance(item, dict):
                        print(f"[DEBUG] Item {i} keys: {list(item.keys())}")
        except json.JSONDecodeError as e:
            print(f"[FAIL] JSON decode error: {e}")
            print(f"[DEBUG] First 500 chars of output: {config_json_str[:500]}")
            device.close()
            return
        
        # Find interface config
        print(f"\n[4] Finding config for interface '{interface_name}'...")
        interface_config = _find_interface_config_in_json(config_data, interface_name)
        
        if interface_config:
            print(f"[OK] Found interface config")
            if isinstance(interface_config, dict):
                inherited_from = interface_config.pop('_inherited_from', None)
                bond_member_of = interface_config.pop('_bond_member_of', None)
                
                if inherited_from:
                    print(f"[INFO] Interface inherits from range: {inherited_from}")
                if bond_member_of:
                    print(f"[INFO] Interface is member of bond: {bond_member_of}")
                
                print(f"[DEBUG] Config keys: {list(interface_config.keys())}")
        else:
            print(f"[FAIL] Interface config not found")
            print(f"[DEBUG] Checking available interfaces in JSON...")
            # Try to list available interfaces
            for item in config_data:
                if isinstance(item, dict) and 'set' in item:
                    set_data = item['set']
                    if isinstance(set_data, dict) and 'interface' in set_data:
                        interfaces = set_data['interface']
                        if isinstance(interfaces, dict):
                            print(f"[DEBUG] Available interfaces: {list(interfaces.keys())[:20]}...")  # Show first 20
            device.close()
            return
        
        # Parse to nv commands
        print(f"\n[5] Converting to nv set commands...")
        if interface_config:
            parsed_commands = _parse_json_to_nv_commands(interface_config, "", interface_name)
            
            if parsed_commands:
                print(f"[OK] Generated {len(parsed_commands)} commands:")
                for cmd in parsed_commands:
                    print(f"  {cmd}")
            else:
                print(f"[WARN] No commands generated (interface may have minimal config)")
        
        device.close()
        print(f"\n[OK] Test completed for {interface_name}")
        
    except Exception as e:
        print(f"\n[FAIL] Error testing {interface_name}: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Main test function"""
    print("="*80)
    print("Cumulus Interface Config Parsing Test")
    print("="*80)
    print(f"Device: {DEVICE_IP}")
    print(f"Interfaces to test: {', '.join(TEST_INTERFACES)}")
    print("="*80)
    
    for interface in TEST_INTERFACES:
        test_interface_config(DEVICE_IP, interface)
        time.sleep(1)  # Small delay between tests
    
    print("\n" + "="*80)
    print("All tests completed")
    print("="*80)

if __name__ == '__main__':
    main()
