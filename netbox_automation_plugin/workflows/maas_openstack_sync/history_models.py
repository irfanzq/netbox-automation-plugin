"""
Compatibility import for workflow modules.

Primary model declaration lives in netbox_automation_plugin.models to avoid app
registry issues during startup.
"""

from netbox_automation_plugin.models import MAASOpenStackDriftRun

__all__ = ["MAASOpenStackDriftRun"]
