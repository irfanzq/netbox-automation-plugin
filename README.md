# NetBox Automation Plugin

NetBox plugin with NAPALM and Nornir integration for parallel device operations.

## Features

- Parallel device connections using Nornir ThreadedRunner
- Support for multiple NAPALM drivers (Cumulus, EOS, IOS, NXOS, JunOS)
- Automatic platform detection based on manufacturer
- Configurable worker count for parallel execution

## Installation

Add to your plugin_requirements.txt:

netbox-automation-plugin @ git+ssh://git@gitlab.b52.whitefiber.internal:2424/operations/netbox-automation-plugin.git

## Configuration

Add to your NetBox configuration/plugins.py:

PLUGINS = [
    'netbox_automation_plugin',
]

PLUGINS_CONFIG = {
    'netbox_automation_plugin': {
        'nornir': {
            'runner': {
                'plugin': 'threaded',
                'options': {
                    'num_workers': 20
                }
            }
        },
        'napalm': {
            'username': 'your_username',
            'password': 'your_password',
            'timeout': 60,
            'optional_args': {}
        }
    },
}
