# NetBox Automation Plugin

NetBox plugin with NAPALM and Nornir integration for parallel device operations.

## MAAS / OpenStack sync (drift audit)

Design and Phase 0 scope: [`netbox_automation_plugin/sync/DRIFT_DESIGN.md`](netbox_automation_plugin/sync/DRIFT_DESIGN.md).  
Config: [`netbox_automation_plugin/sync/CONFIG.md`](netbox_automation_plugin/sync/CONFIG.md).

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

This plugin pins **`setuptools>=65,<82`** because **setuptools 82+ removed `pkg_resources`**, which **NAPALM 5** still imports.

**If the build installs setuptools first then plugins and `import pkg_resources` still fails:** the second `uv pip install -r …` pass **drops setuptools** from the venv (it is not a dependency of NAPALM/plugins), so **`pkg_resources` disappears**. Install setuptools **after** plugin requirements (NetBox’s venv has no `pip`, so use `uv` with `--python`):

```dockerfile
RUN /usr/local/bin/uv pip install --python /opt/netbox/venv/bin/python --no-cache-dir -r /opt/netbox/plugin_requirements.txt \
    && /usr/local/bin/uv pip install --python /opt/netbox/venv/bin/python --no-cache-dir 'setuptools>=65,<82' \
    && /opt/netbox/venv/bin/python -c "import pkg_resources; print('ok')"
```

Verify inside a running container:

```bash
docker exec <netbox-container> /opt/netbox/venv/bin/python -c "import pkg_resources; print('ok')"
```

Do **not** use `pip install --no-deps` for this plugin unless setuptools is already in that venv.

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
