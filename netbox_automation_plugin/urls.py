from django.urls import path

from .workflows.lldp_consistency.views import LLDPConsistencyCheckView
from .workflows.vlan_deployment.views import VLANDeploymentView, GetCommonInterfacesView, GetVLANsBySiteView

app_name = "netbox_automation_plugin"

urlpatterns = [
    path(
        "lldp-consistency-check/",
        LLDPConsistencyCheckView.as_view(),
        name="lldp_consistency_check",
    ),
    path(
        "vlan-deployment/",
        VLANDeploymentView.as_view(),
        name="vlan_deployment",
    ),
    path(
        "vlan-deployment/get-interfaces/",
        GetCommonInterfacesView.as_view(),
        name="vlan_deployment_get_interfaces",
    ),
    path(
        "vlan-deployment/get-vlans/",
        GetVLANsBySiteView.as_view(),
        name="vlan_deployment_get_vlans",
    ),
]


