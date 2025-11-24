# Per-Platform Credentials Configuration

The NetBox Automation Plugin now supports **per-platform credentials**, allowing you to use different usernames and passwords for different device types (Cumulus, EOS, IOS, etc.).

## Configuration

Add the `platform_credentials` section to your NetBox configuration file.

### Local Dev Environment

Edit `configuration/plugins.py` or `configuration/extra.py`:

```python
PLUGINS_CONFIG = {
    'netbox_automation_plugin': {
        'napalm': {
            # Default credentials (fallback if platform not specified)
            'username': 'admin',
            'password': 'default_password',
            'timeout': 60,
            'optional_args': {
                'ssh_config_file': '/opt/unit/.ssh/config',
            },
            # Per-platform credentials
            'platform_credentials': {
                'cumulus': {
                    'username': 'cumulus',
                    'password': 'Admin@123',
                },
                'eos': {
                    'username': 'admin',
                    'password': 'admin@123',
                },
                # Add more platforms as needed:
                # 'ios': {
                #     'username': 'cisco',
                #     'password': 'cisco123',
                # },
                # 'nxos': {
                #     'username': 'admin',
                #     'password': 'nxos123',
                # },
            },
        },
        'nornir': {
            'runner': {
                'plugin': 'threaded',
                'options': {
                    'num_workers': 20,
                }
            }
        },
    }
}
```

## How It Works

1. **Platform Detection**: The plugin automatically detects the device platform using the manufacturer in NetBox:
   - Cumulus/Nvidia/Mellanox → `cumulus` driver
   - Arista → `eos` driver
   - Cisco IOS → `ios` driver
   - Cisco NX-OS → `nxos` driver

2. **Credential Selection**: When connecting to a device:
   - If the platform has specific credentials in `platform_credentials`, use those
   - Otherwise, fall back to the default `username` and `password`

3. **Logging**: The plugin logs when platform-specific credentials are used:
   ```
   Using platform-specific credentials for switch01 (platform: eos)
   ```

## Example Scenarios

### Scenario 1: All Cumulus Devices
```python
'napalm': {
    'username': 'cumulus',
    'password': 'Admin@123',
    # No platform_credentials needed - all devices use default
}
```

### Scenario 2: Mixed Cumulus and EOS
```python
'napalm': {
    'username': 'cumulus',      # Default for Cumulus devices
    'password': 'Admin@123',
    'platform_credentials': {
        'eos': {                # Override for EOS devices
            'username': 'admin',
            'password': 'admin@123',
        },
    },
}
```

### Scenario 3: Multiple Platforms
```python
'napalm': {
    'username': 'admin',        # Generic default
    'password': 'default123',
    'platform_credentials': {
        'cumulus': {
            'username': 'cumulus',
            'password': 'Admin@123',
        },
        'eos': {
            'username': 'admin',
            'password': 'admin@123',
        },
        'ios': {
            'username': 'cisco',
            'password': 'cisco123',
        },
    },
}
```

## Supported Platforms

The following platform names are supported (based on NAPALM drivers):

- `cumulus` - Cumulus Linux / Nvidia / Mellanox
- `eos` - Arista EOS
- `ios` - Cisco IOS
- `iosxr` - Cisco IOS-XR
- `nxos` - Cisco NX-OS
- `junos` - Juniper JunOS

## Testing

After updating your configuration:

1. **Restart NetBox**:
   ```bash
   docker-compose restart netbox
   ```

2. **Test with VLAN Deployment**:
   - Navigate to: Plugins → VLAN Deployment
   - Select a Cumulus device → Should use `cumulus/Admin@123`
   - Select an EOS device → Should use `admin/admin@123`
   - Enable "Dry Run" to test without making changes

3. **Check Logs**:
   ```bash
   docker-compose logs netbox | grep "platform-specific credentials"
   ```

## Production Deployment

When copying to production, update the production NetBox configuration with the same `platform_credentials` section. The core files remain unchanged - only the configuration differs between environments.

