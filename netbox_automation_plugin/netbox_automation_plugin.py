"""
NetBox Automation Plugin Configuration

Provides centralized configuration for NAPALM and Nornir integration.
All settings are read from Django settings with sensible defaults.
"""

from django.conf import settings

PLUGIN_NAME = 'netbox_automation_plugin'

PLUGIN_CONFIG = {
    'napalm': {
        'username': getattr(settings, 'NAPALM_USERNAME', 'admin'),
        'password': getattr(settings, 'NAPALM_PASSWORD', ''),
        'timeout': getattr(settings, 'NAPALM_TIMEOUT', 60),
        'optional_args': getattr(settings, 'NAPALM_OPTIONAL_ARGS', {}),
    },
    'nornir': {
        'runner': {
            'plugin': 'threaded',
            'options': {
                'num_workers': getattr(settings, 'NORNIR_NUM_WORKERS', 20),
            }
        }
    },
    'automation': {
        'default_platform': 'cumulus',
        'backup_enabled': True,
        'backup_path': getattr(settings, 'BACKUP_PATH', '/opt/netbox/backups/'),
        'compliance_check_interval': 24,  # hours
    }
}



