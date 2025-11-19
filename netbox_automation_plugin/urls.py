from django.urls import path

from .workflows.lldp_consistency.views import LLDPConsistencyCheckView

app_name = "netbox_automation_plugin"

urlpatterns = [
    path(
        "lldp-consistency-check/",
        LLDPConsistencyCheckView.as_view(),
        name="lldp_consistency_check",
    ),
]


