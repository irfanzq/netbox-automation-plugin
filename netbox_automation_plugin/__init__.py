"""
NetBox Automation Plugin

A comprehensive NetBox plugin that integrates with NAPALM and Nornir for:
- Device configuration management
- Live data collection and synchronization
- Automated compliance checking
- Network automation workflows
"""

from netbox.plugins import PluginConfig
from pathlib import Path

__version__ = '1.0.0'


class NetBoxAutomationPluginConfig(PluginConfig):
    name = 'netbox_automation_plugin'
    verbose_name = 'NetBox Automation'
    description = 'Network automation plugin with NAPALM and Nornir integration for parallel device operations'
    version = __version__
    author = 'Whitefiber Undercloud Engineering'
    author_email = 'irfan@whitefiber.com'
    base_url = 'automation'
    min_version = '4.0.0'
    max_version = '4.9.99'
    required_settings = []
    default_settings = {
        'napalm': {
            'username': 'admin',
            'password': '',
            'timeout': 60,
            'optional_args': {},
            # Per-platform credentials (optional)
            # If specified, these override the default username/password for specific platforms
            'platform_credentials': {
                # 'cumulus': {'username': 'cumulus', 'password': 'Admin@123'},
                # 'eos': {'username': 'admin', 'password': 'admin@123'},
                # 'ios': {'username': 'cisco', 'password': 'cisco123'},
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
        'automation': {
            'default_platform': 'cumulus',
            'backup_enabled': True,
            'backup_path': '/opt/netbox/backups/',
            'compliance_check_interval': 24,
        }
    }

    @property
    def template_dir(self):
        """Return the path to the plugin's templates directory."""
        return Path(__file__).parent / 'templates'


config = NetBoxAutomationPluginConfig
