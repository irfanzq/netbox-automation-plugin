"""
Workflow modules for NetBox Automation Plugin

This package contains UI workflows for network automation tasks.
"""

# Import LLDP Consistency workflow
from .lldp_consistency import (
    LLDPConsistencyCheckForm,
    LLDPConsistencyCheckView,
    LLDPConsistencyResultTable,
)

# Import VLAN Deployment workflow
from .vlan_deployment import (
    VLANDeploymentForm,
    VLANDeploymentView,
    VLANDeploymentResultTable,
)

# Import NetBox VLAN Tagging workflow
from .netbox_vlan_tagging import (
    VLANTaggingForm,
    VLANTaggingView,
    VLANTaggingResultTable,
)

__all__ = [
    # LLDP Consistency Workflow
    'LLDPConsistencyCheckForm',
    'LLDPConsistencyCheckView',
    'LLDPConsistencyResultTable',
    # VLAN Deployment Workflow
    'VLANDeploymentForm',
    'VLANDeploymentView',
    'VLANDeploymentResultTable',
    # NetBox VLAN Tagging Workflow
    'VLANTaggingForm',
    'VLANTaggingView',
    'VLANTaggingResultTable',
]
