"""Regenerate drift HTML / XLSX from a persisted snapshot_payload dict."""

from __future__ import annotations

from typing import Any

from netbox_automation_plugin.sync.reporting.drift_report import (
    build_drift_report_xlsx,
    format_drift_report,
)


def format_drift_report_from_snapshot_payload(
    payload: dict[str, Any] | None,
    *,
    drift_overrides: dict | None = None,
):
    p = payload or {}
    return format_drift_report(
        p.get("maas_data") or {},
        p.get("netbox_data") or {},
        p.get("openstack_data"),
        p.get("drift") or {},
        matched_rows=p.get("matched_rows"),
        os_subnet_hints=p.get("os_subnet_hints"),
        os_subnet_gaps=p.get("os_subnet_gaps"),
        os_floating_gaps=p.get("os_floating_gaps"),
        netbox_prefix_count=p.get("netbox_prefix_count", 0),
        interface_audit=p.get("interface_audit"),
        netbox_ifaces=p.get("netbox_ifaces"),
        drift_overrides=drift_overrides,
    )


def build_drift_report_xlsx_from_snapshot_payload(
    payload: dict[str, Any] | None,
    *,
    drift_overrides: dict | None = None,
) -> bytes:
    p = payload or {}
    return build_drift_report_xlsx(
        p.get("maas_data") or {},
        p.get("netbox_data") or {},
        p.get("openstack_data"),
        p.get("drift") or {},
        matched_rows=p.get("matched_rows"),
        os_subnet_hints=p.get("os_subnet_hints"),
        os_subnet_gaps=p.get("os_subnet_gaps"),
        os_floating_gaps=p.get("os_floating_gaps"),
        netbox_prefix_count=p.get("netbox_prefix_count", 0),
        interface_audit=p.get("interface_audit"),
        netbox_ifaces=p.get("netbox_ifaces"),
        drift_overrides=drift_overrides,
    )
