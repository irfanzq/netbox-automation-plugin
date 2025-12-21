from django.urls import path

from .workflows.lldp_consistency.views import LLDPConsistencyCheckView
from .workflows.vlan_deployment.views import VLANDeploymentView, GetCommonInterfacesView, GetVLANsBySiteView, GetInterfacesForSyncView
from .workflows.netbox_vlan_tagging.views import VLANTaggingView

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
        "vlan-deployment/get-interfaces-for-sync/",
        GetInterfacesForSyncView.as_view(),
        name="vlan_deployment_get_interfaces_for_sync",
    ),
    path(
        "vlan-deployment/get-vlans/",
        GetVLANsBySiteView.as_view(),
        name="vlan_deployment_get_vlans",
    ),
    path(
        "netbox-vlan-tagging/",
        VLANTaggingView.as_view(),
        name="netbox_vlan_tagging",
    ),
]


