"""Single NetBox write projection for MAAS/OpenStack reconciliation.

MAAS VLAN columns use ``vlan.vid`` (0 = native/untagged; 1–4094 = tag). Never MAAS ``vlan.id``.

This module defines the only mapping from drift/recon ``cells`` to the NetBox-oriented
key/value dict shown on the reconciliation run page. ``apply_cells.netbox_write_preview_cells``
delegates here so column order and values stay stable.

Apply handlers should read typed writes from :func:`netbox_write_projection_for_op` / 
``netbox_write_projection_cells`` (same ``cells`` as ``apply_row_operation``) so the
reconciliation preview and NetBox mutations stay aligned.

**OpenStack VM rows** (``detail_new_vms`` / ``detail_existing_vms``): apply uses projection
keys ``name``, ``id`` (existing only), ``primary_ip4``, ``primary_ip6``, ``cluster``, ``site``,
``tenant``, ``status``, ``device``, and ``nova_compute_host`` (VM custom field when defined
in NetBox; see ``apply_cells._VM_PROJECTION_CF_KEYS``).

**Proposed missing VLANs** (``detail_proposed_missing_vlans``): projection keys ``vid``,
``vlan_group``, ``site``, ``location``, ``name``, ``tenant`` (optional when empty or ``—``),
``status`` — same cells contract as ``apply_create_vlan`` (``location`` is drift context only;
NetBox VLAN has no Location field; ``apply_create_vlan`` requires **NB site** and sets
``VLAN.site`` when the model has a ``site`` field).

**New / NIC drift interfaces**: projection uses ``untagged_vlan_vid`` (802.1Q tag parsed from
audit cells), not NetBox ``ipam.VLAN`` database ``id`` — avoids confusing VID with VLAN pk in
apply logs and preview tables.

Imports from ``apply_cells`` are deferred inside functions to avoid import cycles while
``apply_cells`` is still loading.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from netbox_automation_plugin.sync.reporting.drift_report.drift_nb_picker_catalog import (
    coerce_nb_proposed_tenant_cell,
)

# Full projection key order (includes optional ``tenant``) for recon tables when some rows omit tenant.
_NETBOX_PREVIEW_FULL_KEY_ORDER: dict[str, tuple[str, ...]] = {
    "detail_new_prefixes": (
        "prefix",
        "vrf",
        "status",
        "role",
        "tenant",
        "scope",
        "vlan",
        "vlan_group",
        "description",
    ),
    "detail_existing_prefixes": (
        "prefix",
        "vrf",
        "status",
        "role",
        "tenant",
        "scope",
        "vlan",
        "vlan_group",
        "description",
    ),
    "detail_new_fips": (
        "address",
        "status",
        "role",
        "vrf",
        "tenant",
        "nat_inside",
        "description",
    ),
    "detail_existing_fips": (
        "address",
        "status",
        "role",
        "vrf",
        "tenant",
        "nat_inside",
        "description",
    ),
    "detail_new_vms": (
        "name",
        "primary_ip4",
        "primary_ip6",
        "cluster",
        "site",
        "tenant",
        "status",
        "device",
        "nova_compute_host",
    ),
    "detail_existing_vms": (
        "id",
        "name",
        "primary_ip4",
        "primary_ip6",
        "cluster",
        "site",
        "tenant",
        "status",
        "device",
        "nova_compute_host",
    ),
    "detail_proposed_missing_vlans": (
        "vid",
        "vlan_group",
        "site",
        "location",
        "name",
        "tenant",
        "status",
    ),
}


def _drop_empty_tenant(d: dict[str, str]) -> dict[str, str]:
    """Omit ``tenant`` from preview/projection when unset so recon UI and payloads stay lean."""
    out = dict(d)
    if not (out.get("tenant") or "").strip():
        out.pop("tenant", None)
    return out


def netbox_write_preview_table_headers(
    selection_key: str, projections: list[dict[str, str]]
) -> tuple[str, ...]:
    """
    Headers for one reconciliation section table: stable order, ``tenant`` only if present on ≥1 row.
    """
    sk = str(selection_key or "").strip()
    if not projections:
        ac = _ac()
        return tuple(ac.netbox_write_preview_ordered_fieldnames(sk))
    union: set[str] = set()
    for p in projections:
        union |= set(p.keys())
    canon = _NETBOX_PREVIEW_FULL_KEY_ORDER.get(sk)
    if canon:
        return tuple(k for k in canon if k in union)
    ac = _ac()
    return tuple(k for k in ac.netbox_write_preview_ordered_fieldnames(sk) if k in union)


def _ac():
    from netbox_automation_plugin.sync.reconciliation import apply_cells as ac

    return ac


def _ci_key_map(cells: dict[str, str]) -> dict[str, str]:
    """Lowercase header → original key spelling in *cells*."""
    return {str(k).strip().lower(): str(k).strip() for k in cells if str(k).strip()}


def _scope_label_from_gfk_audit_cells(cells: dict[str, str]) -> str:
    """
    When ``NB Proposed Scope`` is empty, some exports store GenericFK components as
    ``scope_id`` + ``scope_type`` (ContentType pk). Resolve to the scoped object's label.
    """
    try:
        from django.contrib.contenttypes.models import ContentType
    except Exception:
        return ""
    km = _ci_key_map(cells)
    k_sid = km.get("scope_id")
    k_st = km.get("scope_type")
    if not k_sid or not k_st:
        return ""
    raw_sid = str(cells.get(k_sid) or "").strip()
    raw_st = str(cells.get(k_st) or "").strip()
    if not raw_sid.isdigit() or not raw_st.isdigit():
        return ""
    try:
        ct = ContentType.objects.filter(pk=int(raw_st)).first()
        if ct is None:
            return ""
        model = ct.model_class()
        if model is None:
            return f"{ct.app_label}.{ct.model} #{raw_sid}"
        obj = model.objects.filter(pk=int(raw_sid)).first()
        if obj is None:
            return f"{ct.app_label}.{ct.model} #{raw_sid}"
        name = str(getattr(obj, "name", None) or "").strip()
        if name:
            return name
        return str(obj).strip() or f"{ct.app_label}.{ct.model} #{raw_sid}"
    except Exception:
        return ""


def _prefix_scope_cell(cells: dict[str, str], _cell) -> str:
    direct = (_cell(cells, "NB Proposed Scope") or "").strip()
    if direct and direct not in ("—", "-"):
        return direct
    return _scope_label_from_gfk_audit_cells(cells)


def netbox_write_projection_cells(selection_key: str, cells: dict[str, str] | None) -> dict[str, str]:
    """
    NetBox-style attribute dict for one recon row (preview = apply contract for listed keys).

    Keys are NetBox-oriented (core field names and custom-field keys used on apply).
    Order is stable: new keys are appended so existing preview columns keep their positions.
    """
    ac = _ac()
    _cell = ac._cell
    NEW_NIC_SELECTION_KEYS = ac.NEW_NIC_SELECTION_KEYS

    sk = str(selection_key or "").strip()
    c = cells or {}

    def _device_netbox_write_preview(cc: dict[str, str]) -> dict[str, str]:
        serial = _cell(cc, "Serial Number", "MAAS Serial")
        platform_src = _cell(cc, "NB proposed platform", "OS provision", "OS release")
        return {
            "name": _cell(cc, "Hostname", "Host"),
            "site": _cell(cc, "NB proposed site", "NetBox site"),
            "site.region": _cell(cc, "NB proposed region"),
            "location": _cell(cc, "NB proposed location", "NetBox location"),
            "role": _cell(cc, "NB proposed role"),
            "device_type": _cell(cc, "NB proposed device type"),
            "status": _cell(cc, "NB proposed device status", "NB state (current)"),
            "serial": serial,
            "platform": platform_src,
            "tags": _cell(cc, "NB proposed tag", "Suggested NetBox tags", "NetBox tags"),
        }

    def _vm_primary_ip4_ip6_cells(cc: dict[str, str]) -> tuple[str, str]:
        pri = (_cell(cc, "NB proposed primary IP") or "").strip()
        if not pri or pri in ("—", "-"):
            return "", ""
        try:
            host = pri.split("/", 1)[0].strip()
            ver = ipaddress.ip_address(host).version
        except ValueError:
            return pri, ""
        if ver == 4:
            return pri, ""
        return "", pri

    def _netbox_write_ip_range_description(cc: dict[str, str]) -> str:
        nb = _cell(cc, "NB Proposed Description")
        if nb and nb not in ("—", "-"):
            return nb
        return _cell(cc, "OS Pool Description")

    def _netbox_write_new_nic_preview(cc: dict[str, str]) -> dict[str, str]:
        mac, vid, ips = ac._interface_mac_vlan_ip_from_cells(cc, include_nb_fallback=False)
        if_name = _cell(cc, "Suggested NB name", "MAAS intf")
        if_desc = _cell(
            cc,
            "Description",
            "NB proposed description",
            "NB intf description",
            "Interface description",
        )
        return {
            "device": _cell(cc, "Host"),
            "name": if_name,
            "type": _cell(cc, "NB Proposed intf Type"),
            "mac_address": mac or "—",
            "untagged_vlan_vid": str(vid) if vid else "—",
            "description": if_desc or "—",
            "tags": _cell(cc, "NB Proposed intf Label"),
            "device.site": _cell(cc, "NB site"),
            "device.location": _cell(cc, "NB location"),
            "IPAddress.address": ips or "—",
        }

    def _netbox_write_nic_drift_preview(cc: dict[str, str]) -> dict[str, str]:
        mac, vid, ip_blob = ac._interface_mac_vlan_ip_from_cells(cc, include_nb_fallback=True)
        if_desc = _cell(
            cc,
            "Description",
            "NB proposed description",
            "NB intf description",
            "Interface description",
        )
        return {
            "device": _cell(cc, "Host"),
            "name": _cell(cc, "NB intf"),
            "type": _cell(cc, "NB Proposed intf Type"),
            "mac_address": mac or "—",
            "untagged_vlan_vid": str(vid) if vid else "—",
            "description": if_desc or "—",
            "tags": _cell(cc, "NB Proposed intf Label"),
            "device.site": _cell(cc, "NB site", "NetBox site"),
            "device.location": _cell(cc, "NB location", "NetBox location"),
            "IPAddress.address": ip_blob or "—",
        }

    def _netbox_write_bmc_preview(cc: dict[str, str], *, existing_oob: bool) -> dict[str, str]:
        bmc_ip_maas = _cell(cc, "MAAS BMC IP")
        bmc_ip_os = _cell(cc, "OS BMC IP")
        bmc_ip_nb = _cell(cc, "NB mgmt iface IP")
        bmc_ip = bmc_ip_maas or bmc_ip_os or bmc_ip_nb
        mac = ac._normalize_mac(_cell(cc, "MAAS BMC MAC", "NB OOB MAC"))
        if_name = _cell(
            cc,
            "Suggested NB OOB Port" if existing_oob else "Suggested NB mgmt iface",
        )
        if existing_oob:
            return {
                "device": _cell(cc, "Host"),
                "name": if_name,
                "mac_address": mac or "—",
                "tags": _cell(cc, "NB Proposed intf Label"),
                "IPAddress.address": bmc_ip or "—",
                "description": _cell(cc, "NetBox OOB"),
            }
        return {
            "device": _cell(cc, "Host"),
            "name": if_name,
            "mac_address": mac or "—",
            "type": _cell(cc, "NB Proposed intf Type"),
            "tags": _cell(cc, "NB Proposed intf Label"),
            "IPAddress.address": bmc_ip or "—",
        }

    if sk == "detail_placement_lifecycle_alignment":
        return {
            "name": _cell(c, "Host", "Hostname"),
            "site": _cell(c, "NetBox site"),
            "location": _cell(c, "NetBox location"),
            "status": _cell(c, "NB proposed device status"),
        }
    if sk in ("detail_new_devices", "detail_review_only_devices"):
        return _device_netbox_write_preview(c)
    if sk == "detail_new_prefixes":
        pd = ac._prefix_description_max_len()
        return _drop_empty_tenant(
            {
                "prefix": _cell(c, "CIDR"),
                "vrf": _cell(c, "NB proposed VRF"),
                "status": _cell(c, "NB proposed status"),
                "role": _cell(c, "NB proposed role"),
                "tenant": coerce_nb_proposed_tenant_cell(_cell(c, "NB Proposed Tenant")),
                "scope": _prefix_scope_cell(c, _cell),
                "vlan": _cell(c, "NB Proposed VLAN"),
                "vlan_group": _cell(c, "NB proposed VLAN group"),
                "description": ac._prefix_description_from_cells(c, max_len=pd),
            }
        )
    if sk == "detail_existing_prefixes":
        pd = ac._prefix_description_max_len()
        return _drop_empty_tenant(
            {
                "prefix": _cell(c, "CIDR"),
                "vrf": _cell(c, "NB proposed VRF"),
                "status": _cell(c, "NB proposed status"),
                "role": _cell(c, "NB proposed role"),
                "tenant": coerce_nb_proposed_tenant_cell(_cell(c, "NB Proposed Tenant")),
                "scope": _prefix_scope_cell(c, _cell),
                "vlan": _cell(c, "NB Proposed VLAN"),
                "vlan_group": _cell(c, "NB proposed VLAN group"),
                "description": ac._prefix_description_from_cells(c, max_len=pd),
            }
        )
    if sk == "detail_new_ip_ranges":
        return {
            "start_address": _cell(c, "Start address"),
            "end_address": _cell(c, "End address"),
            "status": _cell(c, "NB proposed status"),
            "role": _cell(c, "NB proposed role"),
            "vrf": _cell(c, "NB proposed VRF"),
            "description": _netbox_write_ip_range_description(c),
        }
    if sk == "detail_new_fips":
        fd = ac._ip_address_description_max_len()
        return _drop_empty_tenant(
            {
                "address": _cell(c, "Floating IP"),
                "status": _cell(c, "NB proposed status"),
                "role": _cell(c, "NB proposed role"),
                "vrf": _cell(c, "NB proposed VRF"),
                "tenant": coerce_nb_proposed_tenant_cell(_cell(c, "NB Proposed Tenant")),
                "nat_inside": _cell(c, "NAT inside IP (from OpenStack fixed IP)"),
                "description": ac._fip_description_from_cells(c, max_len=fd),
            }
        )
    if sk == "detail_existing_fips":
        fd = ac._ip_address_description_max_len()
        return _drop_empty_tenant(
            {
                "address": _cell(c, "Floating IP"),
                "status": _cell(c, "NB proposed status"),
                "role": _cell(c, "NB proposed role"),
                "vrf": _cell(c, "NB proposed VRF"),
                "tenant": coerce_nb_proposed_tenant_cell(_cell(c, "NB Proposed Tenant")),
                "nat_inside": _cell(c, "NAT inside IP (from OpenStack fixed IP)"),
                "description": ac._fip_description_from_cells(c, max_len=fd),
            }
        )
    if sk == "detail_new_vms":
        p4, p6 = _vm_primary_ip4_ip6_cells(c)
        return _drop_empty_tenant(
            {
                "name": _cell(c, "VM name"),
                "primary_ip4": p4,
                "primary_ip6": p6,
                "cluster": _cell(c, "NB proposed cluster"),
                "site": _cell(c, "NB proposed site"),
                "tenant": coerce_nb_proposed_tenant_cell(_cell(c, "NB Proposed Tenant")),
                "status": _cell(c, "NB proposed VM status"),
                "device": _cell(
                    c, "NB proposed device (VM)", "NB proposed device (hypervisor)", "Hypervisor hostname"
                ),
                "nova_compute_host": _cell(c, "Hypervisor hostname"),
            }
        )
    if sk == "detail_existing_vms":
        p4, p6 = _vm_primary_ip4_ip6_cells(c)
        return _drop_empty_tenant(
            {
                "id": _cell(c, "NetBox VM ID"),
                "name": _cell(c, "VM name"),
                "primary_ip4": p4,
                "primary_ip6": p6,
                "cluster": _cell(c, "NB proposed cluster"),
                "site": _cell(c, "NB proposed site"),
                "tenant": coerce_nb_proposed_tenant_cell(_cell(c, "NB Proposed Tenant")),
                "status": _cell(c, "NB proposed VM status"),
                "device": _cell(
                    c, "NB proposed device (VM)", "NB proposed device (hypervisor)", "Hypervisor hostname"
                ),
                "nova_compute_host": _cell(c, "Hypervisor hostname"),
            }
        )
    if sk in NEW_NIC_SELECTION_KEYS:
        return _netbox_write_new_nic_preview(c)
    if sk in ("detail_nic_drift_os", "detail_nic_drift_maas"):
        return _netbox_write_nic_drift_preview(c)
    if sk == "detail_bmc_new_devices":
        return _netbox_write_bmc_preview(c, existing_oob=False)
    if sk == "detail_bmc_existing":
        return _netbox_write_bmc_preview(c, existing_oob=True)
    if sk == "detail_proposed_missing_vlans":
        return _drop_empty_tenant(
            {
                "vid": _cell(c, "NB Proposed VLAN ID", "Target VID"),
                "vlan_group": _cell(c, "NB proposed VLAN group"),
                "site": _cell(c, "NB site"),
                "location": _cell(c, "NB location"),
                "name": _cell(c, "NB proposed VLAN name (editable)", "NB proposed VLAN name"),
                "tenant": coerce_nb_proposed_tenant_cell(_cell(c, "NB Proposed Tenant")),
                "status": _cell(c, "NB proposed status"),
            }
        )
    if sk == "detail_serial_review":
        return {
            "name": _cell(c, "Host", "Hostname"),
            "serial": _cell(c, "MAAS Serial", "NetBox Serial", "Serial Number"),
        }
    out: dict[str, str] = {}
    for k, v in c.items():
        vv = "" if v is None else str(v).strip()
        if vv and vv not in ("—", "-"):
            out[str(k).strip()] = vv
    return out


def netbox_write_projection_for_op(op: dict[str, Any]) -> dict[str, str]:
    """Projection for a frozen reconciliation op (same ``cells`` as ``apply_row_operation``)."""
    sk = str(op.get("selection_key") or "").strip()
    cells = op.get("cells")
    if not isinstance(cells, dict):
        cells = {}
    return netbox_write_projection_cells(sk, cells)
