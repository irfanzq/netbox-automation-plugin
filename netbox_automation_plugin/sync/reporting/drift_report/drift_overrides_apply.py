"""Merge saved drift review overrides into proposed rows and alignment tables."""

from __future__ import annotations

import copy
import json
from typing import Any

from netbox_automation_plugin.sync.reporting.drift_report.drift_nb_picker_catalog import (
    coerce_nb_proposed_tenant_cell,
)
from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_derived import (
    NIC_DRIFT_AUTHORITY_COL_INDEX,
    NIC_NEW_AUTHORITY_COL_INDEX,
)

_NB_PROPOSED_TENANT_HEADER = "NB Proposed Tenant"

# selection_key (HTML data-selection-key) -> prop dict key
SELECTION_KEY_TO_PROP_LIST: dict[str, str] = {
    "detail_new_devices": "add_devices",
    "detail_review_only_devices": "add_devices_review_only",
    "detail_proposed_missing_vlans": "add_proposed_missing_vlans",
    "detail_new_prefixes": "add_prefixes",
    "detail_new_ip_ranges": "add_ip_ranges",
    "detail_new_fips": "add_fips",
    "detail_existing_prefixes": "update_prefixes",
    "detail_existing_fips": "update_fips",
    "detail_new_vms": "add_openstack_vms",
    "detail_existing_vms": "update_openstack_vms",
    "detail_new_nics": "add_nb_interfaces",
    "detail_new_nics_os": "add_nb_interfaces",
    "detail_new_nics_maas": "add_nb_interfaces",
    "detail_bmc_new_devices": "add_mgmt_iface_new_devices",
    "detail_bmc_existing": "add_mgmt_iface",
    "detail_serial_review": "review_serial",
}

HEADERS_DETAIL_NEW_DEVICES: list[str] = [
    "Hostname",
    "MAAS fabric",
    "MAAS status",
    "Serial Number",
    "OS region",
    "OS provision",
    "OS power",
    "OS maintenance",
    "NB proposed region",
    "NB proposed site",
    "NB proposed location",
    "NB proposed device type",
    "NB proposed role",
    "NB proposed device status",
    "NB proposed tag",
    "NB proposed platform",
    "Authority",
    "Proposed Action",
]

HEADERS_DETAIL_NEW_PREFIXES: list[str] = [
    "OS region",
    "CIDR",
    "OS Description",
    "Project",
    "NB Proposed Prefix description (editable)",
    "NB Proposed Tenant",
    "NB Proposed Scope",
    "NB Proposed VLAN",
    "NB proposed role",
    "NB proposed status",
    "NB proposed VRF",
    "Role reason",
    "Authority",
    "Proposed Action",
]

HEADERS_DETAIL_NEW_FIPS: list[str] = [
    "OS region",
    "Floating IP",
    "Name",
    "NAT inside IP (from OpenStack fixed IP)",
    "Project",
    "NB Proposed Tenant",
    "NB proposed status",
    "NB proposed role",
    "NB proposed VRF",
    "Proposed Action",
]

HEADERS_DETAIL_EXISTING_PREFIXES: list[str] = [
    "OS region",
    "CIDR",
    "OS Description",
    "Project",
    "NB current VRF",
    "NB current status",
    "NB current role",
    "NB current tenant",
    "NB current description",
    "NB Proposed Prefix description (editable)",
    "NB Proposed Tenant",
    "NB Proposed Scope",
    "NB Proposed VLAN",
    "NB proposed role",
    "NB proposed status",
    "NB proposed VRF",
    "Drift summary",
    "Role reason",
    "Authority",
    "Proposed Action",
]

HEADERS_DETAIL_EXISTING_FIPS: list[str] = [
    "NB current NAT inside",
    "OS region",
    "Floating IP",
    "Name",
    "NAT inside IP (from OpenStack fixed IP)",
    "Project",
    "NB Proposed Tenant",
    "NB proposed status",
    "NB proposed role",
    "NB proposed VRF",
    "Proposed Action",
]

# Column groups: Host | (MAAS — none for VMs) | OS | NB | Authority | Proposed Action
# Row builders: proposed_changes add_openstack_vms / update_openstack_vms append order must match.
HEADERS_DETAIL_NEW_VMS: list[str] = [
    "VM name",
    "OS region",
    "OS status",
    "Project",
    "Hypervisor hostname",
    "NB proposed primary IP",
    "NB proposed cluster",
    "NB proposed site",
    "NB Proposed Tenant",
    "NB proposed VM status",
    "NB proposed device (VM)",
    "Authority",
    "Proposed Action",
]

# Row builders: proposed_changes update_openstack_vms append order must match.
HEADERS_DETAIL_EXISTING_VMS: list[str] = [
    "VM name",
    "NetBox VM ID",
    "OS region",
    "OS status",
    "Project",
    "Hypervisor hostname",
    "NB current vCPUs",
    "NB current Memory MB",
    "NB current Disk GB",
    "NB current primary IP",
    "NB current cluster",
    "NB current device",
    "NB current VM status",
    "NB proposed primary IP",
    "NB proposed cluster",
    "NB proposed site",
    "NB Proposed Tenant",
    "NB proposed VM status",
    "NB proposed device (VM)",
    "Drift summary",
    "Authority",
    "Proposed Action",
]

HEADERS_DETAIL_NEW_IP_RANGES: list[str] = [
    "OS region",
    "CIDR",
    "Start address",
    "End address",
    "OS Pool Description",
    "NB Proposed Description",
    "Project",
    "NB proposed status",
    "NB proposed role",
    "NB proposed VRF",
    "Authority",
    "Proposed Action",
]

HEADERS_PLACEMENT_ALIGNMENT: list[str] = [
    "Host",
    "MAAS fabric",
    "MAAS state",
    "OS region",
    "OS provision",
    "OS power",
    "OS maintenance",
    "NetBox site",
    "NetBox location",
    "NB state (current)",
    "NB proposed device status",
    "Authority",
    "Proposed Action",
]

HEADERS_DETAIL_NEW_NICS: list[str] = [
    "Host",
    "MAAS intf",
    "MAAS fabric",
    "MAAS MAC",
    "MAAS IPs",
    "MAAS VLAN",
    "MAAS link speed",
    "MAAS NIC model",
    "MAAS LLDP switch",
    "OS LLDP switch",
    "OS region",
    "OS MAC",
    "OS runtime IP",
    "OS runtime VLAN",
    "NB site",
    "NB location",
    "NB Proposed intf Label",
    "NB Proposed intf Type",
    "Suggested NB name",
    "Proposed Action",
    "Authority",
    "Risk",
]

HEADERS_DETAIL_NIC_DRIFT: list[str] = [
    "Host",
    "MAAS intf",
    "MAAS fabric",
    "MAAS MAC",
    "MAAS IPs",
    "MAAS VLAN",
    "MAAS link speed",
    "MAAS NIC model",
    "MAAS LLDP switch",
    "OS LLDP switch",
    "OS region",
    "OS MAC",
    "OS runtime IP",
    "OS runtime VLAN",
    "NB intf",
    "NB MAC",
    "NB IPs",
    "NB VLAN",
    "NB Proposed intf Label",
    "NB Proposed intf Type",
    "Authority",
    "Proposed Action",
    "Risk",
]

# Same columns as MAAS-fallback NIC drift; selection_key differs only.
HEADERS_DETAIL_NIC_DRIFT_OS: list[str] = list(HEADERS_DETAIL_NIC_DRIFT)

HEADERS_BMC_NEW_DEVICES: list[str] = [
    "Host",
    "MAAS BMC IP",
    "MAAS power_type",
    "MAAS vendor",
    "MAAS product",
    "MAAS BMC MAC",
    "MAAS link speed",
    "MAAS LLDP switch",
    "OS BMC IP",
    "OS mgmt type",
    "OS vendor",
    "OS model",
    "OS LLDP switch",
    "NB Proposed intf Label",
    "NB Proposed intf Type",
    "Suggested NB mgmt iface",
    "NB mgmt iface IP",
    "Authority",
    "Proposed Action",
    "Risk",
]

HEADERS_BMC_EXISTING: list[str] = [
    "Host",
    "MAAS BMC IP",
    "MAAS power_type",
    "MAAS vendor",
    "MAAS product",
    "MAAS BMC MAC",
    "MAAS link speed",
    "MAAS LLDP switch",
    "OS BMC IP",
    "OS mgmt type",
    "OS vendor",
    "OS model",
    "OS LLDP switch",
    "NB Proposed intf Label",
    "NB Proposed intf Type",
    "Suggested NB OOB Port",
    "NetBox OOB",
    "NB IP coverage",
    "Actual NB Port Carrying BMC IP",
    "NB OOB MAC",
    "Authority",
    "Status",
    "Proposed Action",
    "Risk",
]

HEADERS_SERIAL_REVIEW: list[str] = [
    "Host",
    "MAAS Serial",
    "NetBox Serial",
    "Proposed Action",
    "Risk",
]

HEADERS_DETAIL_PROPOSED_MISSING_VLANS: list[str] = [
    "NB site",
    "NB location",
    "MAAS VLAN",
    "OS runtime VLAN",
    "VID source",
    "NB Proposed VLAN ID",
    "NB proposed VLAN group",
    "NB proposed VLAN name (editable)",
    "NB Proposed Tenant",
    "NB proposed status",
    "Proposed Action",
    "Risk",
]

SELECTION_KEY_TO_HEADERS: dict[str, list[str]] = {
    "detail_new_devices": HEADERS_DETAIL_NEW_DEVICES,
    "detail_review_only_devices": HEADERS_DETAIL_NEW_DEVICES,
    "detail_proposed_missing_vlans": HEADERS_DETAIL_PROPOSED_MISSING_VLANS,
    "detail_new_prefixes": HEADERS_DETAIL_NEW_PREFIXES,
    "detail_new_ip_ranges": HEADERS_DETAIL_NEW_IP_RANGES,
    "detail_new_fips": HEADERS_DETAIL_NEW_FIPS,
    "detail_existing_prefixes": HEADERS_DETAIL_EXISTING_PREFIXES,
    "detail_existing_fips": HEADERS_DETAIL_EXISTING_FIPS,
    "detail_new_vms": HEADERS_DETAIL_NEW_VMS,
    "detail_existing_vms": HEADERS_DETAIL_EXISTING_VMS,
    "detail_new_nics": HEADERS_DETAIL_NEW_NICS,
    "detail_new_nics_os": HEADERS_DETAIL_NEW_NICS,
    "detail_new_nics_maas": HEADERS_DETAIL_NEW_NICS,
    "detail_nic_drift_os": HEADERS_DETAIL_NIC_DRIFT_OS,
    "detail_nic_drift_maas": HEADERS_DETAIL_NIC_DRIFT,
    "detail_bmc_new_devices": HEADERS_BMC_NEW_DEVICES,
    "detail_bmc_existing": HEADERS_BMC_EXISTING,
    "detail_serial_review": HEADERS_SERIAL_REVIEW,
    "detail_placement_lifecycle_alignment": HEADERS_PLACEMENT_ALIGNMENT,
}


def normalize_drift_review_overrides(raw: Any) -> dict[str, dict[str, dict[str, str]]]:
    """
    Return { selection_key: { row_index_str: { column_header: value } } }.
    Ignores unknown keys and non-dict leaves.
    """
    if raw is None:
        return {}
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return {}
        try:
            raw = json.loads(s)
        except (json.JSONDecodeError, TypeError):
            return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, dict[str, str]]] = {}
    for sel_key, section in raw.items():
        sk = str(sel_key).strip()
        if not sk or not isinstance(section, dict):
            continue
        inner: dict[str, dict[str, str]] = {}
        for ridx, cmap in section.items():
            if not isinstance(cmap, dict):
                continue
            rk = str(ridx).strip()
            if not rk:
                continue
            colmap: dict[str, str] = {}
            for col, val in cmap.items():
                ck = str(col).strip()
                if not ck:
                    continue
                colmap[ck] = "" if val is None else str(val).strip()
            if colmap:
                inner[rk] = colmap
        if inner:
            out[sk] = inner
    _remap_legacy_truncated_nb_placement_headers(out)
    _remap_proposed_missing_vlan_editable_name_header(out)
    _sanitize_nb_proposed_tenant_overrides(out)
    return out


def _sanitize_nb_proposed_tenant_overrides(
    out: dict[str, dict[str, dict[str, str]]],
) -> None:
    """Drop tenant values that are not real NetBox picker labels (same rule as audit HTML)."""
    for sec in out.values():
        for cmap in sec.values():
            if _NB_PROPOSED_TENANT_HEADER not in cmap:
                continue
            coerced = coerce_nb_proposed_tenant_cell(
                cmap.get(_NB_PROPOSED_TENANT_HEADER)
            )
            if coerced:
                cmap[_NB_PROPOSED_TENANT_HEADER] = coerced
            else:
                cmap.pop(_NB_PROPOSED_TENANT_HEADER, None)


def _remap_proposed_missing_vlan_editable_name_header(
    out: dict[str, dict[str, dict[str, str]]],
) -> None:
    """Saved drift JSON may use the pre-editable-column label for VLAN display name."""
    sec = out.get("detail_proposed_missing_vlans")
    if not isinstance(sec, dict):
        return
    old, new = "NB proposed VLAN name", "NB proposed VLAN name (editable)"
    for cmap in sec.values():
        if not isinstance(cmap, dict):
            continue
        if old in cmap and new not in cmap:
            cmap[new] = cmap.pop(old)


def _remap_legacy_truncated_nb_placement_headers(
    out: dict[str, dict[str, dict[str, str]]],
) -> None:
    """
    Older drift HTML used unquoted data-drift-col-header attributes; browsers then
    truncated values at the first space (e.g. \"NB proposed device status\" -> \"NB\").
    Remap a sole \"NB\" key in the placement table to the real header so merge,
    saved modified HTML, history \"view modified\", and Excel stay consistent.
    """
    sec = out.get("detail_placement_lifecycle_alignment")
    if not isinstance(sec, dict):
        return
    target = "NB proposed device status"
    for cmap in sec.values():
        if not isinstance(cmap, dict):
            continue
        for legacy_key, cur in (
            ("Alignment issues", "Proposed Action"),
            ("NB Proposed Actions", "Proposed Action"),
        ):
            if legacy_key in cmap and cur not in cmap:
                cmap[cur] = cmap.pop(legacy_key)
        if len(cmap) != 1:
            continue
        if "NB" not in cmap or target in cmap:
            continue
        cmap[target] = cmap.pop("NB")


def _update_nic_row_is_os_authority(row) -> bool:
    """Matches format_html_proposed split for NIC drift (OS vs MAAS) tables."""
    i = NIC_DRIFT_AUTHORITY_COL_INDEX
    return len(row) > i and str(row[i]).strip() == "[OS]"


def _new_nic_row_is_os_authority(row) -> bool:
    """Matches format_html_proposed split for new NICs (OS vs MAAS) tables."""
    i = NIC_NEW_AUTHORITY_COL_INDEX
    return len(row) > i and str(row[i]).strip() == "[OS]"


def _apply_new_nics_subset(
    rows: list,
    headers: list[str],
    section: dict[str, dict[str, str]],
    *,
    os_authority: bool,
) -> None:
    """
    HTML uses two tables with row indices 0..n-1 per subset; underlying prop is one add_nb_interfaces list.
    Map subset index -> global index before applying cell overrides.
    """
    h2i = {h: i for i, h in enumerate(headers)}
    global_indices = [
        i
        for i, r in enumerate(rows)
        if isinstance(r, (list, tuple)) and (_new_nic_row_is_os_authority(r) == os_authority)
    ]
    for ridx_str, cmap in section.items():
        try:
            sub_idx = int(ridx_str)
        except (TypeError, ValueError):
            continue
        if sub_idx < 0 or sub_idx >= len(global_indices):
            continue
        gi = global_indices[sub_idx]
        row = list(rows[gi])
        for col_header, val in cmap.items():
            j = h2i.get(col_header)
            if j is None:
                continue
            while len(row) <= j:
                row.append("")
            row[j] = "" if val is None else str(val).strip()
        rows[gi] = row


def _apply_update_nic_subset(
    update_nic: list,
    headers: list[str],
    section: dict[str, dict[str, str]],
    *,
    os_authority: bool,
) -> None:
    """
    HTML uses two tables with row indices 0..n-1 per subset; underlying prop is one update_nic list.
    Map subset index -> global index before applying cell overrides.
    """
    h2i = {h: i for i, h in enumerate(headers)}
    global_indices = [
        i
        for i, r in enumerate(update_nic)
        if isinstance(r, (list, tuple)) and (_update_nic_row_is_os_authority(r) == os_authority)
    ]
    for ridx_str, cmap in section.items():
        try:
            sub_idx = int(ridx_str)
        except (TypeError, ValueError):
            continue
        if sub_idx < 0 or sub_idx >= len(global_indices):
            continue
        gi = global_indices[sub_idx]
        row = list(update_nic[gi])
        for col_header, val in cmap.items():
            j = h2i.get(col_header)
            if j is None:
                continue
            while len(row) <= j:
                row.append("")
            row[j] = "" if val is None else str(val).strip()
        update_nic[gi] = row


def _apply_section(headers: list[str], rows: list, section: dict[str, dict[str, str]]) -> None:
    h2i = {h: i for i, h in enumerate(headers)}
    for ridx_str, cmap in section.items():
        try:
            idx = int(ridx_str)
        except (TypeError, ValueError):
            continue
        if idx < 0 or idx >= len(rows):
            continue
        row = list(rows[idx])
        for col_header, val in cmap.items():
            j = h2i.get(col_header)
            if j is None:
                continue
            while len(row) <= j:
                row.append("")
            row[j] = "" if val is None else str(val).strip()
        rows[idx] = row


def merge_drift_review_overrides(
    prop: dict,
    align_rows: list[list],
    overrides: dict[str, dict[str, dict[str, str]]] | None,
) -> tuple[dict, list[list]]:
    """Deep-copy prop, copy align_rows lists, apply overrides in place on copies."""
    p = copy.deepcopy(prop)
    a = [list(r) for r in align_rows]
    if not overrides:
        return p, a
    for sel_key, section in overrides.items():
        if sel_key == "detail_placement_lifecycle_alignment":
            hdrs = SELECTION_KEY_TO_HEADERS.get(sel_key)
            if hdrs:
                _apply_section(hdrs, a, section)
            continue
        if sel_key == "detail_nic_drift_os":
            un = p.get("update_nic")
            if isinstance(un, list):
                _apply_update_nic_subset(
                    un, HEADERS_DETAIL_NIC_DRIFT_OS, section, os_authority=True
                )
            continue
        if sel_key == "detail_nic_drift_maas":
            un = p.get("update_nic")
            if isinstance(un, list):
                _apply_update_nic_subset(
                    un, HEADERS_DETAIL_NIC_DRIFT, section, os_authority=False
                )
            continue
        if sel_key == "detail_new_nics_os":
            rows = p.get("add_nb_interfaces")
            if isinstance(rows, list):
                _apply_new_nics_subset(
                    rows, HEADERS_DETAIL_NEW_NICS, section, os_authority=True
                )
            continue
        if sel_key == "detail_new_nics_maas":
            rows = p.get("add_nb_interfaces")
            if isinstance(rows, list):
                _apply_new_nics_subset(
                    rows, HEADERS_DETAIL_NEW_NICS, section, os_authority=False
                )
            continue
        pk = SELECTION_KEY_TO_PROP_LIST.get(sel_key)
        hdrs = SELECTION_KEY_TO_HEADERS.get(sel_key)
        if not pk or not hdrs:
            continue
        rows = p.get(pk)
        if not isinstance(rows, list):
            continue
        _apply_section(hdrs, rows, section)
    return p, a
