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
        },
        # MAAS / OpenStack Sync — URLs and mapping in config; keep secrets in env (MAAS_API_KEY, OPENSTACK_PASSWORD, etc.)
        'maas_openstack_sync': {
            'maas_url': '',
            'maas_api_key': '',
            'maas_insecure': True,
            'openstack_auth_url': '',
            'openstack_username': '',
            'openstack_password': '',
            'openstack_project_name': '',
            'openstack_region_name': 'birch',
            'site_mapping_fabric': {},  # e.g. {'birch-fabric': 'birch'}
            'site_mapping_pool': {},   # e.g. {'birch': 'birch'}
        }
    }

    @property
    def template_dir(self):
        """Return the path to the plugin's templates directory."""
        return Path(__file__).parent / 'templates'

    def ready(self):
        super().ready()
        import logging

        from django.conf import settings

        from netbox_automation_plugin.integrations.netbox_branching_router_patch import (
            apply_branch_router_objectchange_write_patch,
        )
        from netbox_automation_plugin.integrations.branching_diff_object_column_patch import (
            apply_branching_diff_object_column_patch,
        )

        apply_branch_router_objectchange_write_patch()
        apply_branching_diff_object_column_patch()

        # Reconciliation / branch routing diagnostics: DEBUG on submodule loggers when enabled.
        # Disable with RECONCILIATION_DIAGNOSTIC_LOGGERS_VERBOSE = False in NetBox configuration.
        if getattr(settings, "RECONCILIATION_DIAGNOSTIC_LOGGERS_VERBOSE", True):
            for _log_name in (
                "netbox_automation_plugin.sync.reconciliation",
                "netbox_automation_plugin.sync.reconciliation.apply_cells",
                "netbox_automation_plugin.sync.reconciliation.service",
                "netbox_automation_plugin.sync.reconciliation.views",
                "netbox_automation_plugin.sync.reconciliation.branch",
                "netbox_automation_plugin.sync.reconciliation.pg_branch_session",
            ):
                logging.getLogger(_log_name).setLevel(logging.DEBUG)


config = NetBoxAutomationPluginConfig
