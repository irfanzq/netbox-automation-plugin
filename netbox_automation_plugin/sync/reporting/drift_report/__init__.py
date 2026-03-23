"""
Human-readable drift audit report from MAAS, NetBox, and OpenStack data.

Distinguishes **host data NICs** (Ethernet MAC/IP/VLAN) from **BMC / OOB**
(IPMI, iDRAC, Redfish). NetBox models OOB as device OOB IP plus an optional
management-only port — not the same as in-band NICs.

Implementation is split under this package to keep modules small. Public API
matches the former single ``drift_report`` module.
"""

from netbox_automation_plugin.sync.reporting.drift_report.format_html import (
    format_drift_report,
)
from netbox_automation_plugin.sync.reporting.drift_report.placement import (
    _drift_for_user_reports,
)
from netbox_automation_plugin.sync.reporting.drift_report.xlsx_export import (
    build_drift_report_xlsx,
)

__all__ = [
    "build_drift_report_xlsx",
    "format_drift_report",
    "_drift_for_user_reports",
]
