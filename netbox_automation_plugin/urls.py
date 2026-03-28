from django.urls import path

from .workflows.lldp_consistency.views import LLDPConsistencyCheckView
from .workflows.vlan_deployment.views import VLANDeploymentView, GetCommonInterfacesView, GetVLANsBySiteView, GetInterfacesForSyncView, VLANDeploymentJobsView, VLANDeploymentJobDetailView
from .workflows.netbox_vlan_tagging.views import VLANTaggingView
from .workflows.maas_openstack_sync.views import (
    MAASOpenStackSyncView,
    DriftAuditDownloadXlsxView,
    DriftAuditDownloadXlsxModifiedView,
)
from .workflows.maas_openstack_sync.history_views import (
    MAASOpenStackSyncRunsView,
    MAASOpenStackSyncRunDetailView,
    MAASOpenStackSyncRunDownloadXlsxView,
    MAASOpenStackSyncRunSaveReviewView,
)

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
        "vlan-deployment/jobs/",
        VLANDeploymentJobsView.as_view(),
        name="vlan_deployment_jobs",
    ),
    path(
        "vlan-deployment/jobs/<int:job_id>/",
        VLANDeploymentJobDetailView.as_view(),
        name="vlan_deployment_job_detail",
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
    path(
        "maas-openstack-sync/",
        MAASOpenStackSyncView.as_view(),
        name="maas_openstack_sync",
    ),
    path(
        "maas-openstack-sync/download-xlsx/",
        DriftAuditDownloadXlsxView.as_view(),
        name="maas_openstack_sync_download_xlsx",
    ),
    path(
        "maas-openstack-sync/download-xlsx-modified/",
        DriftAuditDownloadXlsxModifiedView.as_view(),
        name="maas_openstack_sync_download_xlsx_modified",
    ),
    path(
        "maas-openstack-sync/runs/",
        MAASOpenStackSyncRunsView.as_view(),
        name="maas_openstack_sync_runs",
    ),
    path(
        "maas-openstack-sync/runs/<int:run_id>/",
        MAASOpenStackSyncRunDetailView.as_view(),
        name="maas_openstack_sync_run_detail",
    ),
    path(
        "maas-openstack-sync/runs/<int:run_id>/download-xlsx/",
        MAASOpenStackSyncRunDownloadXlsxView.as_view(),
        name="maas_openstack_sync_run_download_xlsx",
    ),
    path(
        "maas-openstack-sync/runs/<int:run_id>/save-review/",
        MAASOpenStackSyncRunSaveReviewView.as_view(),
        name="maas_openstack_sync_run_save_review",
    ),
]


