# NetBox Automation Plugin

NetBox plugin with NAPALM and Nornir integration for parallel device operations.

## Features

- Parallel device connections using Nornir ThreadedRunner
- Support for multiple NAPALM drivers (Cumulus, EOS, IOS, NXOS, JunOS)
- Automatic platform detection based on manufacturer
- Configurable worker count for parallel execution

## Installation

Add to your `plugin_requirements.txt` (or equivalent):

```
netbox-automation-plugin @ git+https://github.com/irfanzq/netbox-automation-plugin.git
```

(or your internal Git URL)

### Python 3.12+ / NetBox Docker (long-term)

NAPALM imports `pkg_resources`, which is provided by **setuptools**. NetBox’s Python 3.12 venv may not include setuptools by default.

This plugin declares **`setuptools>=65.0.0`** in `pyproject.toml`, so a normal `pip install` of the package pulls it in.

**If your image still fails with `No module named 'pkg_resources'`**, your build is likely skipping plugin dependencies. Fix it permanently in the Dockerfile **before** installing the plugin:

```dockerfile
# Ensure setuptools is in the same venv as NetBox (required for NAPALM on Python 3.12+)
RUN /opt/netbox/venv/bin/pip install --no-cache-dir 'setuptools>=65.0.0'
```

Do **not** use `pip install --no-deps` for this plugin unless setuptools is already installed.

Then install the plugin as usual (e.g. from `plugin_requirements.txt` or `pip install .`).

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
