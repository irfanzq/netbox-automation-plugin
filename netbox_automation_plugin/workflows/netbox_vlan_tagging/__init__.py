"""
NetBox VLAN Tagging Workflow

This workflow analyzes devices and interfaces based on defined criteria and applies NetBox tags accordingly.
It is a standalone analysis and tagging tool, completely independent of deployment workflows.

Features:
- Device-level analysis and tagging (automation-ready:vlan)
- Interface-level analysis and tagging (vlan-mode:access, vlan-mode:tagged, vlan-mode:uplink, vlan-mode:routed, vlan-mode:needs-review)
- Bulk analysis and tagging
- Auto-tagging based on NetBox data
"""

from .forms import VLANTaggingForm
from .views import VLANTaggingView
from .tables import VLANTaggingResultTable

__all__ = [
    'VLANTaggingForm',
    'VLANTaggingView',
    'VLANTaggingResultTable',
]

