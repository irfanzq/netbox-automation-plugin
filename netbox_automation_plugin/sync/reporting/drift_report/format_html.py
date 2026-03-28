"""Assemble the main drift audit HTML (or ASCII) report."""

from netbox_automation_plugin.sync.reporting.drift_report.format_html_drift import (
    emit_drift_counts_and_alignment,
)
from netbox_automation_plugin.sync.reporting.drift_report.format_html_inventory import (
    emit_inventory_scope,
)
from netbox_automation_plugin.sync.reporting.drift_report.format_html_proposed import (
    emit_proposed_change_tables,
)
from netbox_automation_plugin.sync.reporting.drift_report.fabric_alignment import (
    _alignment_review_rows,
)
from netbox_automation_plugin.sync.reporting.drift_report.drift_overrides_apply import (
    merge_drift_review_overrides,
    normalize_drift_review_overrides,
)
from netbox_automation_plugin.sync.reporting.drift_report.placement import _drift_for_user_reports
from netbox_automation_plugin.sync.reporting.drift_report.proposed_changes import (
    _proposed_changes_rows,
)
from netbox_automation_plugin.sync.reporting.drift_report.render_tables import _DriftReportEmitter


def format_drift_report(
    maas_data,
    netbox_data,
    openstack_data,
    drift,
    *,
    matched_rows=None,
    os_subnet_hints=None,
    os_subnet_gaps=None,
    os_floating_gaps=None,
    netbox_prefix_count=0,
    interface_audit=None,
    netbox_ifaces=None,
    use_html=True,
    drift_overrides=None,
):
    """
    Return {"drift": str, "reference": str, "drift_markup": "html"|"text"}.

    drift = Phase 0 + drift-only tables (MAAS-only, matched with drift, NIC drift, OS gaps).
    reference = full matched hosts, full per-device NIC audit, OpenStack ref (collapsible in UI).
    OpenStack data is already combined from all configured clouds before being passed here.

    When use_html is True (default), drift is a safe HTML fragment for |safe in templates.
    """
    orphaned_nb_count = len((drift or {}).get("in_netbox_not_maas") or [])
    drift = _drift_for_user_reports(drift)
    e = _DriftReportEmitter(use_html=use_html)
    ref_lines = []

    emit_inventory_scope(
        e, maas_data, netbox_data, openstack_data, drift, netbox_prefix_count
    )
    align_rows = _alignment_review_rows(matched_rows)
    prop = _proposed_changes_rows(
        maas_data,
        netbox_data,
        drift,
        interface_audit,
        matched_rows,
        os_subnet_gaps or [],
        os_floating_gaps or [],
        openstack_data=openstack_data,
        netbox_ifaces=netbox_ifaces,
    )
    norm = normalize_drift_review_overrides(drift_overrides) if drift_overrides else {}
    if norm:
        prop, align_rows = merge_drift_review_overrides(prop, align_rows, norm)
    emit_drift_counts_and_alignment(
        e,
        drift,
        maas_data,
        netbox_data,
        openstack_data,
        matched_rows,
        interface_audit,
        os_subnet_gaps,
        os_floating_gaps,
        orphaned_nb_count,
        alignment_rows_override=align_rows,
    )
    emit_proposed_change_tables(e, prop)

    e.spacer()
    e.banner("END OF DRIFT AUDIT", "=")

    return {
        "drift": e.render(),
        "reference": "\n".join(ref_lines),
        "drift_markup": "html" if use_html else "text",
    }
