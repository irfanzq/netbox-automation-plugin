import django_tables2 as tables
from django.urls import reverse
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from netbox_automation_plugin.sync.reporting.drift_report.drift_overrides_apply import (
    normalize_drift_review_overrides,
)

from .history_models import MAASOpenStackDriftRun


class MAASOpenStackDriftRunTable(tables.Table):
    id = tables.Column(
        verbose_name=_("Run ID"),
        orderable=True,
    )
    status = tables.Column(verbose_name=_("Status"), orderable=True)
    created_by = tables.Column(verbose_name=_("User"), orderable=True)
    created = tables.DateTimeColumn(verbose_name=_("Created"), orderable=True)
    netbox_sites_locations = tables.Column(
        verbose_name=_("NetBox sites / locations"),
        empty_values=(),
        orderable=False,
    )
    matched_hosts = tables.Column(
        verbose_name=_("Hosts present in both MAAS and NetBox"),
        empty_values=(),
        orderable=False,
    )
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
            "netbox_sites_locations",
            "matched_hosts",
            "maas_machines",
            "netbox_devices",
            "actions",
        )
        attrs = {"class": "table table-hover table-headings"}

    def render_netbox_sites_locations(self, record):
        sf = record.scope_filters if isinstance(record.scope_filters, dict) else {}
        sites = sf.get("sites") or []
        locs = sf.get("locations") or []
        if not isinstance(sites, list):
            sites = []
        if not isinstance(locs, list):
            locs = []
        if not sites and not locs:
            return format_html(
                '<span class="text-muted">{}</span>',
                _("All (no site/location filter)"),
            )
        parts = []
        if sites:
            parts.append(format_html("<strong>{}</strong> {}", _("Sites"), ", ".join(str(s) for s in sites)))
        if locs:
            parts.append(
                format_html("<strong>{}</strong> {}", _("Locations"), ", ".join(str(x) for x in locs))
            )
        return format_html("{}<br/>{}", parts[0], parts[1]) if len(parts) == 2 else parts[0]

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
        download_mod_url = download_url + "?modified=1"
        has_review = bool((record.report_drift_modified_html or "").strip()) or bool(
            normalize_drift_review_overrides(record.drift_review_overrides)
        )
        badge_link = "badge text-decoration-none fw-normal py-2 px-2"
        if has_review:
            return format_html(
                '<div class="d-flex flex-column gap-2 align-items-start">'
                '<span class="badge text-bg-light text-dark border" title="{}">{}</span>'
                '<div class="d-flex flex-wrap gap-1 align-items-center">'
                '<a href="{}" class="{} text-bg-primary">{}</a>'
                '<a href="{}?view=modified" class="{} text-bg-info">{}</a>'
                '<a href="{}" class="{} text-bg-success js-drift-xlsx-get" data-download-name="drift-report-run-{}.xlsx">{}</a>'
                '<a href="{}" class="{} text-bg-secondary js-drift-xlsx-get" data-download-name="drift-report-run-{}-modified.xlsx">{}</a>'
                "</div>"
                "</div>",
                _("Saved NB proposed review edits for this run."),
                _("Edits saved"),
                view_url,
                badge_link,
                _("View report"),
                view_url,
                badge_link,
                _("View modified"),
                download_url,
                badge_link,
                record.id,
                _("Download Excel"),
                download_mod_url,
                badge_link,
                record.id,
                _("Download modified Excel"),
            )
        return format_html(
            '<div class="d-flex flex-wrap gap-2 align-items-center">'
            '<a href="{}" class="btn btn-outline-primary btn-sm py-0 px-2">{}</a>'
            '<a href="{}" class="btn btn-outline-success btn-sm py-0 px-2 js-drift-xlsx-get" data-download-name="drift-report-run-{}.xlsx">{}</a>'
            "</div>",
            view_url,
            _("View report"),
            download_url,
            record.id,
            _("Download Excel"),
        )
