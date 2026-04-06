import django_tables2 as tables
from django.urls import reverse
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from netbox_automation_plugin.sync.reporting.drift_report.drift_overrides_apply import (
    normalize_drift_review_overrides,
)

from .history_models import MAASOpenStackDriftRun


def _history_modified_view_query(record) -> str:
    ts = getattr(record, "drift_review_saved_at", None)
    if ts is None:
        return "view=modified"
    try:
        return f"view=modified&review_saved={int(ts.timestamp())}"
    except (OSError, OverflowError, TypeError, ValueError):
        return "view=modified"


def _history_modified_xlsx_query(record) -> str:
    ts = getattr(record, "drift_review_saved_at", None)
    if ts is None:
        return "modified=1"
    try:
        return f"modified=1&review_saved={int(ts.timestamp())}"
    except (OSError, OverflowError, TypeError, ValueError):
        return "modified=1"


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
        download_mod_url = download_url + "?" + _history_modified_xlsx_query(record)
        has_review = bool((record.report_drift_modified_html or "").strip()) or bool(
            normalize_drift_review_overrides(record.drift_review_overrides)
        )
        rpk = getattr(record, "latest_reconciliation_pk", None)
        if rpk:
            recon_url = reverse(
                "plugins:netbox_automation_plugin:maas_openstack_reconciliation_detail",
                args=[rpk],
            )
            saved_audit_url = f"{view_url}?audit=1"
            modified_view_url = f"{view_url}?audit=1&{_history_modified_view_query(record)}"
            primary_url = recon_url
            primary_label = _("Reconciliation")
            secondary_url = saved_audit_url
            secondary_label = _("Saved audit (HTML)")
        else:
            saved_audit_url = view_url
            modified_view_url = f"{view_url}?{_history_modified_view_query(record)}"
            primary_url = view_url
            primary_label = _("View report")
            secondary_url = modified_view_url
            secondary_label = _("View modified")
        badge_link = "badge text-decoration-none fw-normal py-2 px-2"
        if has_review:
            if rpk:
                return format_html(
                    '<div class="d-flex flex-column gap-2 align-items-start">'
                    '<span class="badge text-bg-light text-dark border" title="{}">{}</span>'
                    '<div class="d-flex flex-wrap gap-1 align-items-center">'
                    '<a href="{}" class="{} text-bg-primary js-drift-nav-loading">{}</a>'
                    '<a href="{}" class="{} text-bg-secondary js-drift-nav-loading">{}</a>'
                    '<a href="{}" class="{} text-bg-info js-drift-nav-loading">{}</a>'
                    '<a href="{}" class="{} text-bg-success js-drift-xlsx-get" data-download-name="drift-report-run-{}.xlsx">{}</a>'
                    '<a href="{}" class="{} text-bg-secondary js-drift-xlsx-get" data-download-name="drift-report-run-{}-modified.xlsx">{}</a>'
                    "</div>"
                    "</div>",
                    _("Saved NB proposed edits for this run."),
                    _("Edits saved"),
                    primary_url,
                    badge_link,
                    primary_label,
                    secondary_url,
                    badge_link,
                    secondary_label,
                    modified_view_url,
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
                '<div class="d-flex flex-column gap-2 align-items-start">'
                '<span class="badge text-bg-light text-dark border" title="{}">{}</span>'
                '<div class="d-flex flex-wrap gap-1 align-items-center">'
                '<a href="{}" class="{} text-bg-primary js-drift-nav-loading">{}</a>'
                '<a href="{}" class="{} text-bg-info js-drift-nav-loading">{}</a>'
                '<a href="{}" class="{} text-bg-success js-drift-xlsx-get" data-download-name="drift-report-run-{}.xlsx">{}</a>'
                '<a href="{}" class="{} text-bg-secondary js-drift-xlsx-get" data-download-name="drift-report-run-{}-modified.xlsx">{}</a>'
                "</div>"
                "</div>",
                _("Saved NB proposed edits for this run."),
                _("Edits saved"),
                primary_url,
                badge_link,
                primary_label,
                secondary_url,
                badge_link,
                secondary_label,
                download_url,
                badge_link,
                record.id,
                _("Download Excel"),
                download_mod_url,
                badge_link,
                record.id,
                _("Download modified Excel"),
            )
        if rpk:
            return format_html(
                '<div class="d-flex flex-wrap gap-2 align-items-center">'
                '<a href="{}" class="btn btn-outline-primary btn-sm py-0 px-2 js-drift-nav-loading">{}</a>'
                '<a href="{}" class="btn btn-outline-secondary btn-sm py-0 px-2 js-drift-nav-loading">{}</a>'
                '<a href="{}" class="btn btn-outline-success btn-sm py-0 px-2 js-drift-xlsx-get" data-download-name="drift-report-run-{}.xlsx">{}</a>'
                "</div>",
                primary_url,
                primary_label,
                saved_audit_url,
                _("Saved audit (HTML)"),
                download_url,
                record.id,
                _("Download Excel"),
            )
        return format_html(
            '<div class="d-flex flex-wrap gap-2 align-items-center">'
            '<a href="{}" class="btn btn-outline-primary btn-sm py-0 px-2 js-drift-nav-loading">{}</a>'
            '<a href="{}" class="btn btn-outline-success btn-sm py-0 px-2 js-drift-xlsx-get" data-download-name="drift-report-run-{}.xlsx">{}</a>'
            "</div>",
            primary_url,
            primary_label,
            download_url,
            record.id,
            _("Download Excel"),
        )
