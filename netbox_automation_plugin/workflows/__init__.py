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

__all__ = [
    # LLDP Consistency Workflow
    'LLDPConsistencyCheckForm',
    'LLDPConsistencyCheckView',
    'LLDPConsistencyResultTable',
    # VLAN Deployment Workflow
    'VLANDeploymentForm',
    'VLANDeploymentView',
    'VLANDeploymentResultTable',
]
