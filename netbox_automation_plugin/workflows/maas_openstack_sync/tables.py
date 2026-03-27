import django_tables2 as tables
from django.urls import reverse
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .history_models import MAASOpenStackDriftRun


class MAASOpenStackDriftRunTable(tables.Table):
    id = tables.Column(
        verbose_name=_("Run ID"),
        orderable=True,
    )
    status = tables.Column(verbose_name=_("Status"), orderable=True)
    created_by = tables.Column(verbose_name=_("User"), orderable=True)
    created = tables.DateTimeColumn(verbose_name=_("Created"), orderable=True)
    matched_hosts = tables.Column(verbose_name=_("Matched Hosts"), empty_values=(), orderable=False)
    maas_machines = tables.Column(verbose_name=_("MAAS Machines"), empty_values=(), orderable=False)
    netbox_devices = tables.Column(verbose_name=_("NetBox Devices"), empty_values=(), orderable=False)
    actions = tables.Column(verbose_name=_("Actions"), empty_values=(), orderable=False)

    class Meta:
        model = MAASOpenStackDriftRun
        fields = (
            "id",
            "status",
            "created_by",
            "created",
            "matched_hosts",
            "maas_machines",
            "netbox_devices",
            "actions",
        )
        attrs = {"class": "table table-hover table-headings"}

    def render_matched_hosts(self, record):
        return (record.audit_summary or {}).get("matched_hostnames", 0)

    def render_maas_machines(self, record):
        return (record.audit_summary or {}).get("maas_machines", 0)

    def render_netbox_devices(self, record):
        return (record.audit_summary or {}).get("netbox_devices", 0)

    def render_actions(self, record):
        view_url = reverse(
            "plugins:netbox_automation_plugin:maas_openstack_sync_run_detail",
            args=[record.id],
        )
        download_url = reverse(
            "plugins:netbox_automation_plugin:maas_openstack_sync_run_download_xlsx",
            args=[record.id],
        )
        return format_html(
            '<div class="d-flex gap-2 flex-wrap">'
            '<a href="{}" class="btn btn-outline-primary btn-sm py-0 px-2">View report</a>'
            '<a href="{}" class="btn btn-outline-success btn-sm py-0 px-2">Download Excel</a>'
            "</div>",
            view_url,
            download_url,
        )
