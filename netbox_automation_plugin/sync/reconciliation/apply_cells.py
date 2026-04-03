"""Apply frozen reconciliation rows using scoped audit cells.

NetBox-oriented fields shown on the recon page are defined in
:mod:`netbox_write_projection` (:func:`netbox_write_projection_cells`). Preview delegates
there; apply handlers should read those same projected strings where possible so UI and
writes stay aligned.

``apply_row_operation`` narrows each row to reconciliation-preview source columns (plus
workflow fields: Proposed Action, Status, Risk, Authority) and drops empty / em-dash
placeholders so handlers only see values that would appear on the recon page (Proposed
Action is not shown there but is kept when non-empty for skip policy and NIC parsing).

Execution order (e.g. create devices before create/update interfaces) is enforced in
``service.apply_reconciliation_run`` via ``AUDIT_REPORT_APPLY_ORDER`` and action phase.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from functools import lru_cache
from typing import Any

from django.utils.text import slugify

from netbox_automation_plugin.sync.reconciliation.netbox_write_projection import (
    netbox_write_projection_for_op,
)

logger = logging.getLogger(__name__)

_VID_FROM_PARENS_RE = re.compile(r"\((\d+)\)\s*$")

# Actions with real NetBox writers (extend as handlers are filled in).
SUPPORTED_APPLY_ACTIONS: frozenset[str] = frozenset(
    {
        "create_prefix",
        "create_ip_range",
        "create_floating_ip",
        "create_device",
        "review_device",
        "create_interface",
        "update_interface",
        "placement_alignment",
        "serial_review",
        "bmc_documentation",
        "bmc_alignment",
        "create_openstack_vm",
        "update_openstack_vm",
    }
)


def _cell(cells: dict[str, str], *names: str) -> str:
    for n in names:
        for k, v in cells.items():
            if str(k).strip().lower() == str(n).strip().lower():
                return "" if v is None else str(v).strip()
    for n in names:
        key_l = str(n).strip().lower()
        for k, v in cells.items():
            if str(k).strip().lower() == key_l:
                return "" if v is None else str(v).strip()
    return ""


_SKIP_WORDS = (
    "skip",
    "no action",
    "none",
    "informational",
    "review only",
    "do not",
    "not required",
    "n/a",
)


def skip_reason_from_row_guides(cells: dict[str, str]) -> str | None:
    """
    Honour Proposed Action / Status-style columns so we do not write when the audit row says not to.
    """
    for label in ("Proposed Action", "Proposed action", "proposed action"):
        val = _cell(cells, label).lower()
        if not val or val in ("—", "-"):
            continue
        for w in _SKIP_WORDS:
            if w in val:
                return "skipped_policy_proposed_action"
    st = _cell(cells, "Status").lower()
    if st and ("no drift" in st or "fully aligned" in st) and not _cell(
        cells, "Proposed Action", "Proposed action"
    ):
        return "skipped_policy_status_unchanged"
    return None


def _netbox_changelog_snapshot(instance: Any) -> None:
    """
    NetBox change-logging (and netbox-branching ChangeDiff field deltas) need a pre-save
    snapshot. The REST UI does this automatically; plugin ORM paths must call it before
    mutating an existing row or the branch Diff shows \"Updated\" with empty columns.
    Ref: https://github.com/netboxlabs/netbox-branching/discussions/51
    """
    fn = getattr(instance, "snapshot", None)
    if not callable(fn):
        return
    try:
        fn()
    except Exception:
        logger.debug(
            "snapshot() failed for %s pk=%s",
            type(instance).__name__,
            getattr(instance, "pk", None),
            exc_info=True,
        )


def _pick_choice_value(field, raw: str) -> Any:
    s = str(raw or "").strip()
    if not s:
        return None
    try:
        choices = list(getattr(field, "choices", []) or [])
    except Exception:
        return None
    sl = s.lower()
    for val, label in choices:
        if str(val).lower() == sl or str(label).strip().lower() == sl:
            return val
    return None


def _resolve_by_name(model, name: str):
    s = str(name or "").strip()
    if not s:
        return None
    for lookup in ("name", "slug", "model"):
        try:
            obj = model.objects.filter(**{lookup: s}).first()
        except Exception:
            obj = None
        if obj is not None:
            return obj
    for lookup in ("name__iexact", "slug__iexact", "model__iexact"):
        try:
            obj = model.objects.filter(**{lookup: s}).first()
        except Exception:
            obj = None
        if obj is not None:
            return obj
    return None


def _normalize_ip_for_netbox(raw_ip: str) -> str:
    s = str(raw_ip or "").strip()
    if not s:
        raise ValueError("empty address")
    if "/" in s:
        ipaddress.ip_interface(s)
        return s
    ip_obj = ipaddress.ip_address(s)
    return f"{s}/32" if ip_obj.version == 4 else f"{s}/128"


def _parse_vlan_vid(raw: str) -> int | None:
    s = str(raw or "").strip()
    if not s:
        return None
    m = re.search(r"\b(\d{1,4})\b", s)
    if not m:
        return None
    v = int(m.group(1))
    if 1 <= v <= 4094:
        return v
    return None


def _normalize_mac(raw: str) -> str | None:
    s = str(raw or "").strip().upper().replace("-", ":")
    if not s:
        return None
    parts = [p for p in s.split(":") if p]
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        try:
            int("".join(parts), 16)
        except ValueError:
            return None
        return ":".join(parts)
    return None


def _nic_proposed_property_segment_ok(val: str | None) -> bool:
    if val is None:
        return False
    t = str(val).strip()
    return bool(t) and t not in ("—", "-")


def _parse_set_netbox_interface_directives(raw: str) -> tuple[str | None, str | None, str | None]:
    """
    Workflow ``Proposed Action`` tokens: SET_NETBOX_MAC=…; SET_NETBOX_UNTAGGED_VLAN=…; SET_NETBOX_IP=…
    (semicolon-separated). Multiple IP directives are concatenated with comma+space.
    """
    s = (raw or "").strip()
    if not s:
        return None, None, None
    mac_val = vlan_val = None
    m = re.search(r"\bSET_NETBOX_MAC=([^;]+)", s, flags=re.IGNORECASE)
    if m:
        mac_val = m.group(1).strip()
    m = re.search(r"\bSET_NETBOX_UNTAGGED_VLAN=([^;]+)", s, flags=re.IGNORECASE)
    if m:
        vlan_val = m.group(1).strip()
    ip_chunks: list[str] = []
    for m in re.finditer(r"\bSET_NETBOX_IP=([^;]+)", s, flags=re.IGNORECASE):
        t = m.group(1).strip()
        if t:
            ip_chunks.append(t)
    ips_val = ", ".join(ip_chunks) if ip_chunks else None
    return mac_val, vlan_val, ips_val


def _parse_nic_proposed_properties_segments(raw: str) -> tuple[str | None, str | None, str | None]:
    """
    ``Proposed Action`` text with MAC / untagged VLAN / IPs clauses, e.g.
    ``MAC c4:cb:e1:e5:93:be; untagged VLAN 2148; IPs: 10.25.56.154``.
    Missing clauses or ``—`` segments are handled by the caller.
    """
    s = (raw or "").strip()
    if not s or s in ("—", "-"):
        return None, None, None
    mac_val = vlan_val = ips_val = None
    m = re.search(r"\bMAC\s+([^;]+)", s, flags=re.IGNORECASE)
    if m:
        mac_val = m.group(1).strip()
    m = re.search(r"\buntagged\s+VLAN\s+([^;]+)", s, flags=re.IGNORECASE)
    if m:
        vlan_val = m.group(1).strip()
    m = re.search(r"\bIPs:\s*(.+)", s, flags=re.IGNORECASE)
    if m:
        ips_val = m.group(1).strip()
    return mac_val, vlan_val, ips_val


def _cell_nic_proposed_body(cells: dict[str, str]) -> str:
    """Single column name in drift/recon UI; frozen rows may still use legacy headers."""
    return _cell(
        cells,
        "Proposed Action",
        "Proposed action",
        "Proposed properties",
        "Proposed properties (from MAAS)",
    )


def _text_has_derivable_nic_clauses(raw: str) -> bool:
    """True when Proposed Action carries human-readable or SET_NETBOX_* NIC intent."""
    mac, vlan, ips = _parse_nic_proposed_properties_segments(raw)
    if (
        _nic_proposed_property_segment_ok(mac)
        or _nic_proposed_property_segment_ok(vlan)
        or _nic_proposed_property_segment_ok(ips)
    ):
        return True
    sm, sv, si = _parse_set_netbox_interface_directives(raw)
    if _nic_proposed_property_segment_ok(sm):
        return True
    if sv and _parse_vlan_vid(sv) is not None:
        return True
    if _nic_proposed_property_segment_ok(si):
        return True
    return False


def _interface_mac_vlan_ip_from_cells(
    cells: dict[str, str], *, include_nb_fallback: bool
) -> tuple[str | None, int | None, str]:
    """
    Per field: human-readable ``MAC`` / ``untagged VLAN`` / ``IPs:`` clauses in Proposed Action,
    then ``SET_NETBOX_MAC`` / ``SET_NETBOX_UNTAGGED_VLAN`` / ``SET_NETBOX_IP`` directives,
    then MAAS/OS (and NetBox when ``include_nb_fallback`` for NIC drift).
    """
    body = _cell_nic_proposed_body(cells)
    p_mac, p_vlan, p_ips = _parse_nic_proposed_properties_segments(body)
    s_mac, s_vlan, s_ips = _parse_set_netbox_interface_directives(body)

    mac = _normalize_mac(p_mac) if _nic_proposed_property_segment_ok(p_mac) else None
    if mac is None and _nic_proposed_property_segment_ok(s_mac):
        mac = _normalize_mac(s_mac)
    if mac is None:
        if include_nb_fallback:
            mac = _normalize_mac(_cell(cells, "MAAS MAC", "OS MAC", "NB MAC"))
        else:
            mac = _normalize_mac(_cell(cells, "MAAS MAC", "OS MAC"))

    vid: int | None = None
    if _nic_proposed_property_segment_ok(p_vlan):
        vid = _parse_vlan_vid(p_vlan)
    if vid is None and s_vlan:
        vid = _parse_vlan_vid(s_vlan)
    if vid is None:
        if include_nb_fallback:
            vid = _parse_vlan_vid(_cell(cells, "MAAS VLAN", "OS runtime VLAN", "NB VLAN"))
        else:
            vid = _parse_vlan_vid(_cell(cells, "MAAS VLAN", "OS runtime VLAN"))

    ip_blob = ""
    if _nic_proposed_property_segment_ok(p_ips):
        ip_blob = str(p_ips).strip()
    if not ip_blob and _nic_proposed_property_segment_ok(s_ips):
        ip_blob = str(s_ips).strip()
    if not ip_blob:
        if include_nb_fallback:
            ip_blob = _cell(cells, "MAAS IPs", "OS runtime IP", "NB IPs")
        else:
            ip_blob = _cell(cells, "MAAS IPs", "OS runtime IP")

    ip_blob = str(ip_blob or "").strip()
    if ip_blob in ("—", "-"):
        ip_blob = ""

    return mac, vid, ip_blob


NEW_NIC_RECON_PAYLOAD_HEADERS: tuple[str, ...] = (
    "Host",
    "NB Proposed intf Label",
    "NB Proposed intf Type",
    "Suggested NB name",
    "Proposed Action",
    "Parsed MAC",
    "Parsed untagged VLAN",
    "Parsed IPs",
)

# Selection keys for proposed-change "new interface" tables (frozen ops use minimal cells).
NEW_NIC_SELECTION_KEYS: frozenset[str] = frozenset(
    {"detail_new_nics", "detail_new_nics_os", "detail_new_nics_maas"}
)


def new_nic_cells_for_reconciliation(full_cells: dict[str, str]) -> dict[str, str]:
    """
    Frozen reconciliation ops for new-NIC tables only carry these keys (plus parsed L2 fields).

    ``apply_create_interface`` reads MAC/VLAN/IPs from ``Proposed Action`` when clauses are present;
    ``Parsed *`` keys are for preview/diff and apply resolution (MAC/VLAN/IP).
    """
    out: dict[str, str] = {}
    for k in NEW_NIC_RECON_PAYLOAD_HEADERS[:5]:
        if k == "Proposed Action":
            v = (
                full_cells.get("Proposed Action")
                or full_cells.get("Proposed action")
                or full_cells.get("Proposed properties")
                or full_cells.get("Proposed properties (from MAAS)")
                or ""
            )
            out[k] = str(v).strip()
        else:
            out[k] = str(full_cells.get(k) or "").strip()
    props = out["Proposed Action"]
    p_mac, p_vlan, p_ips = _parse_nic_proposed_properties_segments(props)
    s_mac, s_vlan, s_ips = _parse_set_netbox_interface_directives(props)
    if not _nic_proposed_property_segment_ok(p_mac) and _nic_proposed_property_segment_ok(s_mac):
        p_mac = s_mac
    if not _nic_proposed_property_segment_ok(p_vlan) and s_vlan and _parse_vlan_vid(s_vlan) is not None:
        p_vlan = s_vlan
    if not _nic_proposed_property_segment_ok(p_ips) and _nic_proposed_property_segment_ok(s_ips):
        p_ips = s_ips
    out["Parsed MAC"] = (p_mac or "").strip() if _nic_proposed_property_segment_ok(p_mac) else ""
    out["Parsed untagged VLAN"] = (p_vlan or "").strip() if _nic_proposed_property_segment_ok(p_vlan) else ""
    out["Parsed IPs"] = (p_ips or "").strip() if _nic_proposed_property_segment_ok(p_ips) else ""
    return out


def _split_ip_candidates(blob: str) -> list[str]:
    out: list[str] = []
    for chunk in re.split(r"[,;\s]+", str(blob or "").strip()):
        t = chunk.strip()
        if not t or t in ("—", "-"):
            continue
        out.append(t)
    return out


_DRIFT_AUDIT_MARKER = "\n=== Drift reconciliation (full row) ===\n"
# Legacy prefix apply embedded a row snapshot after this marker in Prefix.description.
_LEGACY_PREFIX_DRIFT_ROW_MARKER = "--- Drift row (reconciliation) ---"


def strip_prefix_description_audit_suffix(raw: str | None) -> str:
    """Strip reconciliation audit tails from Prefix.description or editable drift cells."""
    t = (raw or "").strip()
    if not t:
        return ""
    if _LEGACY_PREFIX_DRIFT_ROW_MARKER in t:
        t = t.split(_LEGACY_PREFIX_DRIFT_ROW_MARKER)[0].rstrip()
    m = _DRIFT_AUDIT_MARKER.strip()
    if m in t:
        t = t.split(m)[0].rstrip()
    return t.strip()


def _norm_header(k: str) -> str:
    return str(k or "").strip().lower()


def netbox_write_preview_cells(selection_key: str, cells: dict[str, str]) -> dict[str, str]:
    """
    Reconciliation / branch preview: delegates to :mod:`netbox_write_projection` (single source
    of truth). Column keys and values are unchanged from the historical implementation.
    """
    from netbox_automation_plugin.sync.reconciliation.netbox_write_projection import (
        netbox_write_projection_cells,
    )

    return netbox_write_projection_cells(selection_key, cells)


def netbox_write_preview_ordered_fieldnames(selection_key: str) -> tuple[str, ...]:
    """Ordered NetBox-style preview column keys for a reconciliation section (stable table headers)."""
    sk = str(selection_key or "").strip()
    return tuple(netbox_write_preview_cells(sk, {}).keys())


def netbox_write_preview_fieldnames(selection_key: str) -> frozenset[str]:
    """Set of preview headers (same order as ``netbox_write_preview_ordered_fieldnames``)."""
    return frozenset(netbox_write_preview_ordered_fieldnames(selection_key))


def recon_operation_display_cells(selection_key: str, cells: dict[str, str]) -> dict[str, str]:
    """NetBox write-oriented columns for reconciliation staging, run detail, and diffs."""
    return netbox_write_preview_cells(selection_key, cells)


def _audit_residual_text(cells: dict[str, str], consumed_lower: set[str]) -> str:
    """Text block for every audit column not mapped to typed NetBox fields on this object."""
    lines: list[str] = []
    for k, v in sorted(cells.items(), key=lambda x: _norm_header(str(x[0]))):
        kn = _norm_header(str(k))
        if kn in consumed_lower:
            continue
        vv = "" if v is None else str(v).strip()
        if not vv or vv in ("—", "-"):
            continue
        lines.append(f"{k}: {vv}")
    if not lines:
        return ""
    return _DRIFT_AUDIT_MARKER.strip() + "\n" + "\n".join(lines)


def _strip_prior_drift_block(cur: str) -> str:
    s = (cur or "").strip()
    if _DRIFT_AUDIT_MARKER.strip() in s:
        s = s.split(_DRIFT_AUDIT_MARKER.strip())[0].rstrip()
    return s


def _interface_description_is_drift_audit_dump(s: str | None) -> bool:
    """True if description matches reconciliation audit text (never treat as operator intent)."""
    t = (s or "").strip()
    if not t:
        return False
    if _DRIFT_AUDIT_MARKER.strip() in t:
        return True
    # Legacy one-line / compact dumps from older apply paths
    if "NB Proposed intf Type:" in t and "Authority:" in t:
        return True
    if "Suggested NB name:" in t and "Risk:" in t and "Authority:" in t:
        return True
    return False


def _scrub_interface_drift_audit_description(iface: Any) -> bool:
    """Clear Interface.description when it holds drift audit junk. Returns True if the row was mutated."""
    if not hasattr(iface, "description"):
        return False
    if not _interface_description_is_drift_audit_dump(getattr(iface, "description", None)):
        return False
    iface.description = None
    return True


def _merge_audit_residual_onto_object(
    obj: Any,
    cells: dict[str, str],
    consumed_lower: set[str],
    *,
    attr_names: tuple[str, ...] = ("comments", "description"),
    max_len: int = 8000,
) -> bool:
    """Append audit columns not mapped to typed fields onto text attributes (prefix, IPAM, etc.).

    Not used for Device / Interface reconciliation rows: those belong in typed NetBox fields or
    custom fields, not in comments/description.
    """
    block = _audit_residual_text(cells, consumed_lower)
    if not block:
        return False
    for attr in attr_names:
        if not hasattr(obj, attr):
            continue
        cur = _strip_prior_drift_block(getattr(obj, attr) or "")
        new = (cur + "\n\n" + block).strip() if cur else block
        if len(new) > max_len:
            new = new[: max_len - 3] + "..."
        if (getattr(obj, attr) or "").strip() == new:
            continue
        setattr(obj, attr, new)
        return True
    return False


def _resolve_interface_type_slug(cell_val: str):
    """NetBox Interface.type choice value from drift cell (slug or human label)."""
    try:
        from dcim.models import Interface
    except Exception:
        return None
    s = str(cell_val or "").strip()
    if not s or s in ("—", "-"):
        return None
    field = Interface._meta.get_field("type")
    ch = getattr(field, "choices", None) or []
    slow = s.lower()
    for val, lab in ch:
        if val is None or val == "":
            continue
        if str(val).strip().lower() == slow:
            return val
    for val, lab in ch:
        if str(lab).strip().lower() == slow:
            return val
    return None


def _merge_interface_role_tag(iface, label_cell: str) -> bool:
    """Attach a Tag named like the drift role (Management, Data, …) when non-empty."""
    from django.utils.text import slugify
    from extras.models import Tag

    raw = str(label_cell or "").strip()
    if not raw or raw in ("—", "-"):
        return False
    if raw.upper() == "DATA":
        raw = "Data"
    slug_base = slugify(raw) or "tag"
    slug = slug_base[:50]
    tag, _ = Tag.objects.get_or_create(
        slug=slug, defaults={"name": raw[:100] if len(raw) <= 100 else raw[:97] + "..."}
    )
    if iface.tags.filter(pk=tag.pk).exists():
        return False
    iface.tags.add(tag)
    return True


def _merge_device_tags(device, tag_cell: str) -> bool:
    from extras.models import Tag

    tag_cell = str(tag_cell or "").strip()
    if not tag_cell:
        return False
    changed = False
    names = [x.strip() for x in re.split(r"[,;]", tag_cell) if x.strip()]
    for name in names:
        slug_base = slugify(name) or "tag"
        slug = slug_base[:50]
        tag, _ = Tag.objects.get_or_create(
            slug=slug, defaults={"name": name[:100] if len(name) <= 100 else name[:97] + "..."}
        )
        if not device.tags.filter(pk=tag.pk).exists():
            device.tags.add(tag)
            changed = True
    return changed


# Detail — new devices: MAAS / OS / audit columns -> NetBox Device custom field `key` (first existing wins).
# Add Custom Fields on Device with any of these keys (type text is enough) to populate from drift apply.
_NEW_DEVICE_DRIFT_TO_CF_KEYS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("OS region", ("os_region", "drift_os_region")),
    ("OS provision", ("os_provision", "drift_os_provision")),
    ("OS power", ("os_power", "drift_os_power")),
    ("OS maintenance", ("os_maintenance", "drift_os_maintenance")),
    ("MAAS fabric", ("maas_fabric", "drift_maas_fabric")),
    ("MAAS status", ("maas_status", "drift_maas_status")),
    ("Authority", ("drift_authority", "authority")),
)


def _custom_field_targets_model(cf: Any, model_cls: type) -> bool:
    from django.contrib.contenttypes.models import ContentType

    try:
        ct = ContentType.objects.get_for_model(model_cls, for_concrete_model=False)
    except Exception:
        return False
    try:
        rel = getattr(cf, "content_types", None)
        if rel is not None and hasattr(rel, "filter"):
            if rel.filter(pk=ct.pk).exists():
                return True
    except Exception:
        pass
    try:
        rel = getattr(cf, "object_types", None)
        if rel is not None and hasattr(rel, "filter"):
            app, name = model_cls._meta.app_label, model_cls._meta.model_name
            if rel.filter(app_label=app, model=name).exists():
                return True
    except Exception:
        pass
    return False


@lru_cache(maxsize=1)
def _device_custom_field_keys_cached() -> frozenset[str]:
    try:
        from dcim.models import Device
        from extras.models import CustomField
    except Exception:
        return frozenset()
    keys: set[str] = set()
    for cf in CustomField.objects.iterator():
        if not _custom_field_targets_model(cf, Device):
            continue
        k = getattr(cf, "key", None)
        if k:
            keys.add(str(k))
    return frozenset(keys)


def _merge_new_device_row_into_custom_fields(device: Any, cells: dict[str, str]) -> tuple[bool, set[str]]:
    """
    Write drift source columns into Device.custom_field_data when matching Custom Field keys exist.

    Returns (device_custom_field_data_changed, drift_headers_applied).
    """
    valid = _device_custom_field_keys_cached()
    if not valid or not hasattr(device, "custom_field_data"):
        return False, set()
    data = dict(device.custom_field_data or {})
    changed = False
    applied_headers: set[str] = set()
    for header, slug_opts in _NEW_DEVICE_DRIFT_TO_CF_KEYS:
        val = _cell(cells, header)
        if not val or val in ("—", "-"):
            continue
        for slug in slug_opts:
            if slug not in valid:
                continue
            if data.get(slug) != val:
                data[slug] = val
                changed = True
            applied_headers.add(header)
            break
    if changed:
        device.custom_field_data = data
    return changed, applied_headers


def _meaningful_cell_val(v: str | None) -> bool:
    vv = "" if v is None else str(v).strip()
    return bool(vv and vv not in ("—", "-"))


# Detail — new prefixes: ordered snapshot lines (must match drift table headers).
_NEW_PREFIX_DRIFT_SNAPSHOT_HEADERS: tuple[str, ...] = (
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
)

_NEW_PREFIX_DRIFT_TO_CF_KEYS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("OS region", ("openstack_region", "os_region", "region")),
    ("OS Description", ("openstack_description", "os_description", "os_subnet_description")),
    ("Project", ("openstack_project", "project")),
    ("Role reason", ("role_reason", "drift_role_reason")),
    ("Authority", ("drift_authority", "authority")),
)


@lru_cache(maxsize=1)
def _prefix_custom_field_keys_cached() -> frozenset[str]:
    try:
        from ipam.models import Prefix
        from extras.models import CustomField
    except Exception:
        return frozenset()
    keys: set[str] = set()
    for cf in CustomField.objects.iterator():
        if not _custom_field_targets_model(cf, Prefix):
            continue
        k = getattr(cf, "key", None)
        if k:
            keys.add(str(k))
    return frozenset(keys)


def _merge_prefix_row_into_custom_fields(prefix_obj: Any, cells: dict[str, str]) -> tuple[bool, set[str]]:
    """Map drift columns into Prefix.custom_field_data when matching Custom Field keys exist."""
    valid = _prefix_custom_field_keys_cached()
    if not valid or not hasattr(prefix_obj, "custom_field_data"):
        return False, set()
    data = dict(prefix_obj.custom_field_data or {})
    changed = False
    applied_headers: set[str] = set()
    for header, slug_opts in _NEW_PREFIX_DRIFT_TO_CF_KEYS:
        val = _cell(cells, header)
        if not _meaningful_cell_val(val):
            continue
        for slug in slug_opts:
            if slug not in valid:
                continue
            if data.get(slug) != val:
                data[slug] = val
                changed = True
            applied_headers.add(header)
            break
    if changed:
        prefix_obj.custom_field_data = data
    return changed, applied_headers


def _prefix_description_max_len() -> int:
    from ipam.models import Prefix

    f = Prefix._meta.get_field("description")
    ml = getattr(f, "max_length", None)
    return int(ml) if ml else 4000


def _prefix_description_from_cells(cells: dict[str, str], *, max_len: int) -> str:
    """NetBox Prefix.description: operator-editable column only (drift lives in typed fields / CF)."""
    editable = strip_prefix_description_audit_suffix(
        _cell(cells, "NB Proposed Prefix description (editable)")
    )
    if max_len and len(editable) > max_len:
        return editable[: max_len - 3] + "..."
    return editable


def apply_create_prefix(op: dict[str, Any]) -> tuple[str, str]:
    from ipam.models import Prefix, Role, VRF

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    cidr = (proj.get("prefix") or "").strip()
    vrf_name = (proj.get("vrf") or "").strip()
    status_name = (proj.get("status") or "").strip()
    role_name = (proj.get("role") or "").strip()
    tenant_name = (proj.get("tenant") or "").strip()
    scope_name = (proj.get("scope") or "").strip()
    vlan_name = (proj.get("vlan") or "").strip()
    full_descr = (proj.get("description") or "").strip()
    # Drift columns map to typed fields / CF; description is editable column only (no audit dump).
    if not cidr:
        return "skipped", "skipped_prerequisite_missing"
    vrf = _resolve_by_name(VRF, vrf_name) if vrf_name else None
    if vrf_name and vrf is None:
        return "skipped", "skipped_prerequisite_missing"
    role = _resolve_by_name(Role, role_name) if role_name else None
    if role_name and role is None:
        return "skipped", "skipped_prerequisite_missing"
    tenant = None
    if tenant_name and tenant_name not in {"—", "-"}:
        try:
            from tenancy.models import Tenant

            tenant = _resolve_by_name(Tenant, tenant_name)
        except Exception:
            tenant = None
        if tenant is None:
            return "skipped", "skipped_prerequisite_missing"
    scope_obj = None
    if scope_name and scope_name not in {"—", "-"}:
        try:
            from dcim.models import Location

            scope_obj = _resolve_by_name(Location, scope_name)
        except Exception:
            scope_obj = None
        if scope_obj is None:
            return "skipped", "skipped_prerequisite_missing"
    vlan_obj = None
    if vlan_name and vlan_name not in {"—", "-"}:
        try:
            vlan_obj = _resolve_vlan_for_prefix_scope(vlan_name, scope_obj)
        except Exception:
            vlan_obj = None
        if vlan_obj is None:
            return "skipped", "skipped_prerequisite_missing"
    prefix_pk_raw = _cell(cells, "NetBox prefix ID")
    existing = None
    if prefix_pk_raw and str(prefix_pk_raw).strip().isdigit():
        existing = Prefix.objects.filter(pk=int(str(prefix_pk_raw).strip())).first()
    if existing is None:
        existing = Prefix.objects.filter(prefix=cidr, vrf=vrf).first()
    if existing is not None:
        _netbox_changelog_snapshot(existing)
        changed = False
        if vrf is not None and getattr(existing, "vrf_id", None) != vrf.pk:
            existing.vrf = vrf
            changed = True
        if status_name:
            val = _pick_choice_value(existing._meta.get_field("status"), status_name)
            if val is not None and existing.status != val:
                existing.status = val
                changed = True
        if role is not None and getattr(existing, "role_id", None) != role.pk:
            existing.role = role
            changed = True
        if tenant is not None and hasattr(existing, "tenant_id") and existing.tenant_id != tenant.pk:
            existing.tenant = tenant
            changed = True
        if scope_obj is not None and hasattr(existing, "scope"):
            cur = getattr(existing, "scope", None)
            if cur is None or getattr(cur, "pk", None) != scope_obj.pk:
                existing.scope = scope_obj
                changed = True
        if vlan_obj is not None and hasattr(existing, "vlan_id") and existing.vlan_id != vlan_obj.pk:
            existing.vlan = vlan_obj
            changed = True
        if hasattr(existing, "description"):
            if (existing.description or "").strip() != full_descr.strip():
                existing.description = full_descr
                changed = True
        cf_ch, _ = _merge_prefix_row_into_custom_fields(existing, cells)
        if cf_ch:
            changed = True
        if changed:
            existing.save()
            return "updated", "ok_updated"
        return "skipped", "skipped_already_desired"
    obj = Prefix(prefix=cidr, vrf=vrf)
    if status_name:
        val = _pick_choice_value(obj._meta.get_field("status"), status_name)
        if val is not None:
            obj.status = val
    if role is not None:
        obj.role = role
    if tenant is not None and hasattr(obj, "tenant"):
        obj.tenant = tenant
    if scope_obj is not None and hasattr(obj, "scope"):
        obj.scope = scope_obj
    if vlan_obj is not None and hasattr(obj, "vlan"):
        obj.vlan = vlan_obj
    if hasattr(obj, "description"):
        obj.description = full_descr
    _merge_prefix_row_into_custom_fields(obj, cells)
    obj.save()
    return "created", "ok_created"


def apply_create_ip_range(op: dict[str, Any]) -> tuple[str, str]:
    from ipam.models import IPRange, Role, VRF

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    start_addr = (proj.get("start_address") or "").strip()
    end_addr = (proj.get("end_address") or "").strip()
    status_name = (proj.get("status") or "").strip()
    role_name = (proj.get("role") or "").strip()
    vrf_name = (proj.get("vrf") or "").strip()
    descr = (proj.get("description") or "").strip()
    if status_name in {"—", "-"}:
        status_name = ""
    if role_name in {"—", "-"}:
        role_name = ""
    if vrf_name in {"—", "-"}:
        vrf_name = ""
    consumed = {
        _norm_header("OS region"),
        _norm_header("CIDR"),
        _norm_header("Start address"),
        _norm_header("End address"),
        _norm_header("OS Pool Description"),
        _norm_header("NB Proposed Description"),
        _norm_header("Project"),
        _norm_header("NB proposed status"),
        _norm_header("NB proposed role"),
        _norm_header("NB proposed VRF"),
        _norm_header("Authority"),
        _norm_header("Proposed Action"),
    }
    if not start_addr or not end_addr:
        return "skipped", "skipped_prerequisite_missing"
    vrf = _resolve_by_name(VRF, vrf_name) if vrf_name else None
    if vrf_name and vrf is None:
        return "skipped", "skipped_prerequisite_missing"
    role = _resolve_by_name(Role, role_name) if role_name else None
    if role_name and role is None:
        return "skipped", "skipped_prerequisite_missing"
    existing = IPRange.objects.filter(
        start_address=start_addr,
        end_address=end_addr,
        vrf=vrf,
    ).first()
    if existing is not None:
        _netbox_changelog_snapshot(existing)
        changed = False
        if status_name:
            val = _pick_choice_value(existing._meta.get_field("status"), status_name)
            if val is not None and existing.status != val:
                existing.status = val
                changed = True
        if role is not None and getattr(existing, "role_id", None) != role.pk:
            existing.role = role
            changed = True
        if descr and hasattr(existing, "description"):
            if (existing.description or "") != descr[:2000]:
                existing.description = descr[:2000]
                changed = True
        merge_ch = _merge_audit_residual_onto_object(
            existing, cells, consumed, attr_names=("description",), max_len=4000
        )
        if changed or merge_ch:
            existing.save()
            return "updated", "ok_updated"
        return "skipped", "skipped_already_desired"
    obj = IPRange(start_address=start_addr, end_address=end_addr, vrf=vrf)
    if status_name:
        val = _pick_choice_value(obj._meta.get_field("status"), status_name)
        if val is not None:
            obj.status = val
    if role is not None and hasattr(obj, "role"):
        obj.role = role
    if descr and hasattr(obj, "description"):
        obj.description = descr[:2000]
    obj.save()
    if _merge_audit_residual_onto_object(obj, cells, consumed, attr_names=("description",), max_len=4000):
        obj.save()
    return "created", "ok_created"


# Detail — new floating IPs (headers must match format_html_proposed / xlsx_export).
_NEW_FIP_DRIFT_SNAPSHOT_HEADERS: tuple[str, ...] = (
    "OS region",
    "Floating IP",
    "Name",
    "NAT inside IP (from OpenStack fixed IP)",
    "Project",
    "NB Proposed Tenant",
    "NB proposed status",
    "NB proposed role",
    "NB proposed VRF",
)

_NEW_FIP_DRIFT_TO_CF_KEYS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("OS region", ("openstack_region", "os_region", "region")),
    ("Name", ("floating_ip_name", "fip_name")),
    ("Project", ("openstack_project", "project")),
    ("NAT inside IP (from OpenStack fixed IP)", ("nat_inside_hint", "fixed_ip", "openstack_fixed_ip")),
)


@lru_cache(maxsize=1)
def _ip_address_custom_field_keys_cached() -> frozenset[str]:
    try:
        from extras.models import CustomField
        from ipam.models import IPAddress
    except Exception:
        return frozenset()
    keys: set[str] = set()
    for cf in CustomField.objects.iterator():
        if not _custom_field_targets_model(cf, IPAddress):
            continue
        k = getattr(cf, "key", None)
        if k:
            keys.add(str(k))
    return frozenset(keys)


def _merge_ip_address_row_into_custom_fields(ip_obj: Any, cells: dict[str, str]) -> tuple[bool, set[str]]:
    valid = _ip_address_custom_field_keys_cached()
    if not valid or not hasattr(ip_obj, "custom_field_data"):
        return False, set()
    data = dict(ip_obj.custom_field_data or {})
    changed = False
    applied_headers: set[str] = set()
    for header, slug_opts in _NEW_FIP_DRIFT_TO_CF_KEYS:
        val = _cell(cells, header)
        if not _meaningful_cell_val(val):
            continue
        for slug in slug_opts:
            if slug not in valid:
                continue
            if data.get(slug) != val:
                data[slug] = val
                changed = True
            applied_headers.add(header)
            break
    if changed:
        ip_obj.custom_field_data = data
    return changed, applied_headers


def _ip_address_description_max_len() -> int:
    from ipam.models import IPAddress

    f = IPAddress._meta.get_field("description")
    ml = getattr(f, "max_length", None)
    return int(ml) if ml else 4000


def _fip_description_from_cells(cells: dict[str, str], *, max_len: int) -> str:
    """NetBox IPAddress.description: mirror the drift report Name column only (typed fields hold the rest)."""
    body = (_cell(cells, "Name") or "").strip()
    if max_len and len(body) > max_len:
        return body[: max_len - 3] + "..."
    return body


def _resolve_nat_inside_ipaddress(inside_raw: str, vrf_preferred: Any) -> Any:
    """
    NetBox: public / floating side stores NAT inside on IPAddress.nat_inside (inside address object).
    Prefer same VRF as the floating IP, then Global (null VRF), then any single match.
    """
    from ipam.models import IPAddress

    if not _meaningful_cell_val(inside_raw):
        return None
    try:
        inside_addr = _normalize_ip_for_netbox(inside_raw)
    except ValueError:
        return None
    qs = IPAddress.objects.filter(address=inside_addr)
    if vrf_preferred is not None:
        hit = qs.filter(vrf=vrf_preferred).first()
        if hit is not None:
            return hit
    hit = qs.filter(vrf__isnull=True).first()
    if hit is not None:
        return hit
    if qs.count() == 1:
        return qs.first()
    return None


def _apply_fip_nat_inside(ip_obj: Any, cells: dict[str, str], vrf: Any) -> bool:
    if not hasattr(ip_obj, "nat_inside_id"):
        return False
    inside_raw = _cell(
        cells,
        "NAT inside IP (from OpenStack fixed IP)",
        "NAT inside IP",
    )
    inner = _resolve_nat_inside_ipaddress(inside_raw, vrf)
    if inner is None:
        return False
    if getattr(ip_obj, "nat_inside_id", None) == inner.pk:
        return False
    ip_obj.nat_inside = inner
    return True


def apply_create_floating_ip(op: dict[str, Any]) -> tuple[str, str]:
    from ipam.models import IPAddress, VRF

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    raw_ip = (proj.get("address") or "").strip()
    status_name = (proj.get("status") or "").strip()
    vrf_name = (proj.get("vrf") or "").strip()
    role_name = (proj.get("role") or "").strip()
    tenant_name = (proj.get("tenant") or "").strip()
    full_descr = (proj.get("description") or "").strip()
    dmax = _ip_address_description_max_len()
    consumed = {
        _norm_header("NB current NAT inside"),
        _norm_header("OS region"),
        _norm_header("Floating IP"),
        _norm_header("Name"),
        _norm_header("NAT inside IP (from OpenStack fixed IP)"),
        _norm_header("Project"),
        _norm_header("NB Proposed Tenant"),
        _norm_header("NB proposed status"),
        _norm_header("NB proposed role"),
        _norm_header("NB proposed VRF"),
        # Proposed Action: workflow hint only; consume so it is not merged into description.
        _norm_header("Proposed Action"),
    }
    if not raw_ip:
        return "skipped", "skipped_prerequisite_missing"
    try:
        address = _normalize_ip_for_netbox(raw_ip)
    except ValueError:
        return "failed", "failed_validation_bad_ip"
    vrf = _resolve_by_name(VRF, vrf_name) if vrf_name else None
    if vrf_name and vrf is None:
        return "skipped", "skipped_prerequisite_missing"
    role_obj = None
    if role_name:
        try:
            from ipam.models import Role

            role_obj = _resolve_by_name(Role, role_name)
        except Exception:
            role_obj = None
        if role_obj is None:
            return "skipped", "skipped_prerequisite_missing"
    tenant_obj = None
    if tenant_name and tenant_name not in {"—", "-"}:
        try:
            from tenancy.models import Tenant

            tenant_obj = _resolve_by_name(Tenant, tenant_name)
        except Exception:
            tenant_obj = None
        if tenant_obj is None:
            return "skipped", "skipped_prerequisite_missing"
    existing = IPAddress.objects.filter(address=address, vrf=vrf).first()
    if existing is not None:
        _netbox_changelog_snapshot(existing)
        changed = False
        if status_name:
            val = _pick_choice_value(existing._meta.get_field("status"), status_name)
            if val is not None and existing.status != val:
                existing.status = val
                changed = True
        if role_obj is not None and hasattr(existing, "role_id") and existing.role_id != role_obj.pk:
            existing.role = role_obj
            changed = True
        if tenant_obj is not None and hasattr(existing, "tenant_id") and existing.tenant_id != tenant_obj.pk:
            existing.tenant = tenant_obj
            changed = True
        if hasattr(existing, "description"):
            if (existing.description or "").strip() != full_descr.strip():
                existing.description = full_descr
                changed = True
        if _apply_fip_nat_inside(existing, cells, vrf):
            changed = True
        cf_ch, _ = _merge_ip_address_row_into_custom_fields(existing, cells)
        if cf_ch:
            changed = True
        merge_ch = _merge_audit_residual_onto_object(
            existing, cells, consumed, attr_names=("description",), max_len=max(dmax, 8000)
        )
        if changed or merge_ch:
            existing.save()
            return "updated", "ok_updated"
        return "skipped", "skipped_already_desired"
    ip_obj = IPAddress(address=address, vrf=vrf)
    if status_name:
        val = _pick_choice_value(ip_obj._meta.get_field("status"), status_name)
        if val is not None:
            ip_obj.status = val
    if role_obj is not None and hasattr(ip_obj, "role"):
        ip_obj.role = role_obj
    if tenant_obj is not None and hasattr(ip_obj, "tenant"):
        ip_obj.tenant = tenant_obj
    if hasattr(ip_obj, "description"):
        ip_obj.description = full_descr
    _apply_fip_nat_inside(ip_obj, cells, vrf)
    _merge_ip_address_row_into_custom_fields(ip_obj, cells)
    ip_obj.save()
    if _merge_audit_residual_onto_object(
        ip_obj, cells, consumed, attr_names=("description",), max_len=max(dmax, 8000)
    ):
        ip_obj.save()
    return "created", "ok_created"


def _resolve_ipaddress_for_vm_primary(raw: str):
    """Match NetBox IPAddress rows from drift cell (full prefix or host-only from OpenStack)."""
    from ipam.models import IPAddress

    raw = (raw or "").strip()
    if not raw or raw in {"—", "-"}:
        return None
    o = IPAddress.objects.filter(address=raw).first()
    if o is not None:
        return o
    host = raw.split("/", 1)[0].strip()
    try:
        ver = ipaddress.ip_address(host).version
    except ValueError:
        return None
    suffix = "/32" if ver == 4 else "/128"
    o = IPAddress.objects.filter(address=host + suffix).first()
    if o is not None:
        return o
    try:
        return IPAddress.objects.filter(address__startswith=host + "/").order_by("pk").first()
    except Exception:
        return None


def _apply_vm_primary_ip_from_cell(vm, cells: dict[str, str]) -> bool:
    pri = _cell(cells, "NB proposed primary IP")
    ip_obj = _resolve_ipaddress_for_vm_primary(pri)
    if ip_obj is None:
        return False
    try:
        ver = int(ip_obj.address.version)
    except Exception:
        try:
            ver = ipaddress.ip_address(str(ip_obj.address).split("/", 1)[0]).version
        except Exception:
            return False
    changed = False
    if ver == 4 and hasattr(vm, "primary_ip4_id"):
        if getattr(vm, "primary_ip4_id", None) != ip_obj.pk:
            vm.primary_ip4 = ip_obj
            changed = True
    elif ver == 6 and hasattr(vm, "primary_ip6_id"):
        if getattr(vm, "primary_ip6_id", None) != ip_obj.pk:
            vm.primary_ip6 = ip_obj
            changed = True
    return changed


def apply_create_openstack_vm(op: dict[str, Any]) -> tuple[str, str]:
    try:
        from virtualization.models import VirtualMachine, Cluster
        from dcim.models import Device, Site
        from tenancy.models import Tenant
    except Exception:
        return "failed", "failed_virtualization_not_available"

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    name = (proj.get("name") or "").strip()
    cluster_name = (proj.get("cluster") or "").strip()
    if not name or not cluster_name or cluster_name in {"—", "-"}:
        return "skipped", "skipped_prerequisite_missing"
    cluster = Cluster.objects.filter(name=cluster_name).first()
    if cluster is None:
        return "skipped", "skipped_prerequisite_missing"
    if VirtualMachine.objects.filter(name=name).exists():
        return "skipped", "skipped_already_desired"

    consumed = {
        _norm_header("OS region"),
        _norm_header("VM name"),
        _norm_header("OS status"),
        _norm_header("Project"),
        _norm_header("Hypervisor hostname"),
        _norm_header("NB proposed primary IP"),
        _norm_header("NB proposed cluster"),
        _norm_header("NB proposed site"),
        _norm_header("NB Proposed Tenant"),
        _norm_header("NB proposed VM status"),
        _norm_header("NB proposed device (VM)"),
        _norm_header("NB proposed device (hypervisor)"),
        _norm_header("Authority"),
        _norm_header("Proposed Action"),
    }

    vm = VirtualMachine(name=name, cluster=cluster)
    site_name = (proj.get("site") or "").strip()
    if site_name and site_name not in {"—", "-"}:
        site = _resolve_by_name(Site, site_name)
        if site is not None and hasattr(vm, "site_id"):
            vm.site = site
    tenant_name = (proj.get("tenant") or "").strip()
    if tenant_name and tenant_name not in {"—", "-"}:
        tenant = _resolve_by_name(Tenant, tenant_name)
        if tenant is not None and hasattr(vm, "tenant_id"):
            vm.tenant = tenant
    status_name = (proj.get("status") or "").strip()
    if status_name and status_name not in {"—", "-"}:
        val = _pick_choice_value(vm._meta.get_field("status"), status_name)
        if val is not None:
            vm.status = val
    dev = None
    device_cell = (proj.get("device") or "").strip()
    if device_cell and device_cell not in {"—", "-"}:
        dev = Device.objects.filter(name=device_cell).first()
    if dev is not None and hasattr(vm, "device_id"):
        vm.device = dev

    vm.save()
    pri_ch = _apply_vm_primary_ip_from_cell(vm, cells)
    merge_ch = _merge_audit_residual_onto_object(
        vm, cells, consumed, attr_names=("comments", "description"), max_len=8000
    )
    if pri_ch or merge_ch:
        _netbox_changelog_snapshot(vm)
        vm.save()
    return "created", "ok_created"


def apply_update_openstack_vm(op: dict[str, Any]) -> tuple[str, str]:
    try:
        from virtualization.models import VirtualMachine, Cluster
        from dcim.models import Device, Site
        from tenancy.models import Tenant
    except Exception:
        return "failed", "failed_virtualization_not_available"

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    pk_raw = (proj.get("id") or "").strip()
    if not pk_raw or not str(pk_raw).strip().isdigit():
        return "skipped", "skipped_prerequisite_missing"
    vm = VirtualMachine.objects.filter(pk=int(str(pk_raw).strip())).select_related(
        "cluster", "device", "tenant", "primary_ip4", "primary_ip6"
    ).first()
    if vm is None:
        return "skipped", "skipped_prerequisite_missing"
    _netbox_changelog_snapshot(vm)

    consumed = {
        _norm_header("NetBox VM ID"),
        _norm_header("OS region"),
        _norm_header("VM name"),
        _norm_header("OS status"),
        _norm_header("Project"),
        _norm_header("Hypervisor hostname"),
        _norm_header("NB current vCPUs"),
        _norm_header("NB current Memory MB"),
        _norm_header("NB current Disk GB"),
        _norm_header("NB current primary IP"),
        _norm_header("NB current cluster"),
        _norm_header("NB current device"),
        _norm_header("NB current VM status"),
        _norm_header("Drift summary"),
        _norm_header("NB proposed primary IP"),
        _norm_header("NB proposed cluster"),
        _norm_header("NB proposed site"),
        _norm_header("NB Proposed Tenant"),
        _norm_header("NB proposed VM status"),
        _norm_header("NB proposed device (VM)"),
        _norm_header("NB proposed device (hypervisor)"),
        _norm_header("Authority"),
        _norm_header("Proposed Action"),
    }

    changed = False
    if _apply_vm_primary_ip_from_cell(vm, cells):
        changed = True
    cluster_name = (proj.get("cluster") or "").strip()
    if cluster_name and cluster_name not in {"—", "-"}:
        cl = Cluster.objects.filter(name=cluster_name).first()
        if cl is not None and vm.cluster_id != cl.pk:
            vm.cluster = cl
            changed = True
    site_name = (proj.get("site") or "").strip()
    if site_name and site_name not in {"—", "-"} and hasattr(vm, "site_id"):
        site = _resolve_by_name(Site, site_name)
        if site is not None and getattr(vm, "site_id", None) != site.pk:
            vm.site = site
            changed = True
    tenant_name = (proj.get("tenant") or "").strip()
    if tenant_name and tenant_name not in {"—", "-"}:
        tenant = _resolve_by_name(Tenant, tenant_name)
        if tenant is not None and getattr(vm, "tenant_id", None) != tenant.pk:
            vm.tenant = tenant
            changed = True
    status_name = (proj.get("status") or "").strip()
    if status_name and status_name not in {"—", "-"}:
        val = _pick_choice_value(vm._meta.get_field("status"), status_name)
        if val is not None and vm.status != val:
            vm.status = val
            changed = True
    dev = None
    device_cell = (proj.get("device") or "").strip()
    if device_cell and device_cell not in {"—", "-"}:
        dev = Device.objects.filter(name=device_cell).first()
    if dev is not None and hasattr(vm, "device_id"):
        if getattr(vm, "device_id", None) != dev.pk:
            vm.device = dev
            changed = True

    merge_ch = _merge_audit_residual_onto_object(
        vm, cells, consumed, attr_names=("comments", "description"), max_len=8000
    )
    if changed or merge_ch:
        vm.save()
        return "updated", "ok_updated"
    return "skipped", "skipped_already_desired"


def _apply_device_core(cells: dict[str, str], *, create_if_missing: bool) -> tuple[str, str]:
    from dcim.models import Device, DeviceRole, DeviceType, Location, Platform, Site

    hostname = _cell(cells, "Hostname", "Host")
    site_name = _cell(cells, "NB proposed site", "NetBox site")
    location_name = _cell(cells, "NB proposed location", "NetBox location")
    role_name = _cell(cells, "NB proposed role")
    dtype_name = _cell(cells, "NB proposed device type")
    status_name = _cell(cells, "NB proposed device status", "NB state (current)")
    serial = _cell(cells, "Serial Number", "MAAS Serial")
    tag_cell = _cell(cells, "NB proposed tag", "Suggested NetBox tags", "NetBox tags")
    region_name = _cell(cells, "NB proposed region")
    _pn_raw = _cell(
        cells, "NB proposed platform", "OS provision", "OS release", "MAAS OS", "OS"
    )
    _pn = str(_pn_raw or "").strip()
    if not _pn or _pn in ("—", "-") or _pn.lower() in ("(none)", "none", "n/a"):
        platform_name = ""
    else:
        platform_name = _pn
    platform_obj = _resolve_by_name(Platform, platform_name) if platform_name else None
    consumed_d = {
        _norm_header("Hostname"),
        _norm_header("Host"),
        _norm_header("NB proposed region"),
        _norm_header("NB proposed site"),
        _norm_header("NetBox site"),
        _norm_header("NB proposed location"),
        _norm_header("NetBox location"),
        _norm_header("NB proposed role"),
        _norm_header("NB proposed device type"),
        _norm_header("NB proposed device status"),
        _norm_header("NB state (current)"),
        _norm_header("Serial Number"),
        _norm_header("MAAS Serial"),
        _norm_header("NB proposed tag"),
        _norm_header("Suggested NetBox tags"),
        _norm_header("NetBox tags"),
        _norm_header("NB proposed platform"),
        _norm_header("OS provision"),
        _norm_header("OS release"),
        _norm_header("MAAS OS"),
        _norm_header("OS"),
        _norm_header("Proposed Action"),
    }
    if not hostname:
        return "skipped", "skipped_prerequisite_missing"
    site = _resolve_by_name(Site, site_name) if site_name else None
    role = _resolve_by_name(DeviceRole, role_name) if role_name else None
    dtype = _resolve_by_name(DeviceType, dtype_name) if dtype_name else None
    location = None
    if location_name:
        location = _resolve_by_name(Location, location_name)
        if location is None:
            return "skipped", "skipped_prerequisite_missing"
    existing = Device.objects.filter(name=hostname).first()
    if existing is None:
        if not create_if_missing:
            return "skipped", "skipped_prerequisite_missing"
        if not site_name or not role_name or not dtype_name:
            return "skipped", "skipped_prerequisite_missing"
        if site is None or role is None or dtype is None:
            return "skipped", "skipped_prerequisite_missing"
        dev = Device(name=hostname, site=site, location=location, role=role, device_type=dtype)
        if status_name:
            val = _pick_choice_value(dev._meta.get_field("status"), status_name)
            if val is not None:
                dev.status = val
        if serial and hasattr(dev, "serial"):
            dev.serial = serial[:50]
        if platform_obj is not None and hasattr(dev, "platform"):
            dev.platform = platform_obj
        dev.save()
        _sync_site_region(dev.site, region_name)
        tags_applied = False
        if tag_cell:
            tags_applied = _merge_device_tags(dev, tag_cell)
        cf_changed, _cf_hdrs = _merge_new_device_row_into_custom_fields(dev, cells)
        if tags_applied or cf_changed:
            _netbox_changelog_snapshot(dev)
            dev.save()
        return "created", "ok_created"
    _netbox_changelog_snapshot(existing)
    changed = False
    if site is not None and existing.site_id != site.pk:
        existing.site = site
        changed = True
    if location is not None and getattr(existing, "location_id", None) != location.pk:
        existing.location = location
        changed = True
    if role is not None and existing.role_id != role.pk:
        existing.role = role
        changed = True
    if dtype is not None and existing.device_type_id != dtype.pk:
        existing.device_type = dtype
        changed = True
    if status_name:
        val = _pick_choice_value(existing._meta.get_field("status"), status_name)
        if val is not None and existing.status != val:
            existing.status = val
            changed = True
    if serial and hasattr(existing, "serial") and (existing.serial or "") != serial[:50]:
        existing.serial = serial[:50]
        changed = True
    if platform_obj is not None and hasattr(existing, "platform_id"):
        if existing.platform_id != platform_obj.pk:
            existing.platform = platform_obj
            changed = True
    if tag_cell:
        if _merge_device_tags(existing, tag_cell):
            changed = True
    target_site = site if site is not None else existing.site
    _, site_saved = _sync_site_region(target_site, region_name)
    cf_changed, _cf_hdrs = _merge_new_device_row_into_custom_fields(existing, cells)
    if changed or cf_changed:
        existing.save()
    if changed or cf_changed or site_saved:
        return "updated", "ok_updated"
    return "skipped", "skipped_already_desired"


def apply_create_device(op: dict[str, Any]) -> tuple[str, str]:
    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    return _apply_device_core(cells, create_if_missing=True)


def apply_review_device(op: dict[str, Any]) -> tuple[str, str]:
    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    # Same creation path as new-device rows when the operator includes this row in apply:
    # review-only means the report flagged weak/unsafe MAAS state, not "never create in NB".
    return _apply_device_core(cells, create_if_missing=True)


def apply_placement_alignment(op: dict[str, Any]) -> tuple[str, str]:
    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    host = _cell(cells, "Host", "Hostname")
    if not host:
        return "skipped", "skipped_prerequisite_missing"
    role_h = _norm_header("NB proposed role")
    cells_no_role = {
        k: v
        for k, v in cells.items()
        if _norm_header(str(k)) != role_h
    }
    fake = {
        "Hostname": host,
        "NB proposed site": _cell(cells, "NetBox site"),
        "NB proposed location": _cell(cells, "NetBox location"),
        "NB proposed device status": _cell(cells, "NB proposed device status"),
    }
    return _apply_device_core(
        {**cells_no_role, **{k: v for k, v in fake.items() if v}},
        create_if_missing=False,
    )


def apply_serial_review(op: dict[str, Any]) -> tuple[str, str]:
    from dcim.models import Device

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    host = (proj.get("name") or "").strip()
    serial = (proj.get("serial") or "").strip()
    consumed_sr = {
        _norm_header("Hostname"),
        _norm_header("Host"),
        _norm_header("MAAS Serial"),
        _norm_header("NetBox Serial"),
        _norm_header("Serial Number"),
        _norm_header("Proposed Action"),
    }
    if not host:
        return "skipped", "skipped_prerequisite_missing"
    dev = Device.objects.filter(name=host).first()
    if not dev:
        return "skipped", "skipped_prerequisite_missing"
    if not serial:
        return "skipped", "skipped_prerequisite_missing"
    _netbox_changelog_snapshot(dev)
    changed = (dev.serial or "") != serial[:50]
    if changed:
        dev.serial = serial[:50]
    merge_ch = _merge_audit_residual_onto_object(
        dev, cells, consumed_sr, attr_names=("comments", "description"), max_len=8000
    )
    if changed or merge_ch:
        dev.save()
        return "updated", "ok_updated"
    return "skipped", "skipped_already_desired"


def _iface_type_default():
    try:
        from dcim.choices import InterfaceTypeChoices

        return InterfaceTypeChoices.TYPE_OTHER
    except Exception:
        return "other"


def _sync_site_region(site_obj, region_name: str) -> tuple[bool, bool]:
    """
    Apply NB proposed region onto the device's Site.

    Returns (omit_from_residual, site_row_was_saved).
    """
    rn = str(region_name or "").strip()
    if not rn or rn in ("—", "-"):
        return True, False
    if site_obj is None or not getattr(site_obj, "pk", None):
        return False, False
    try:
        from dcim.models import Region, Site
    except Exception:
        return False, False
    reg = _resolve_by_name(Region, rn)
    if reg is None:
        return False, False
    site_db = Site.objects.filter(pk=site_obj.pk).first()
    if site_db is None or not hasattr(site_db, "region_id"):
        return False, False
    if site_db.region_id == reg.pk:
        return True, False
    _netbox_changelog_snapshot(site_db)
    site_db.region = reg
    site_db.save()
    return True, True


def _resolve_vlan_for_device(device, vid: int):
    from ipam.models import VLAN

    if not device.site_id:
        return None
    return VLAN.objects.filter(site_id=device.site_id, vid=vid).first()


def _resolve_vlan_for_prefix_scope(vlan_name: str, scope_obj) -> Any | None:
    from ipam.models import VLAN

    raw = str(vlan_name or "").strip()
    if not raw or raw in {"—", "-"}:
        return None

    candidate_vid = None
    m = _VID_FROM_PARENS_RE.search(raw)
    if m:
        try:
            candidate_vid = int(m.group(1))
        except Exception:
            candidate_vid = None
    elif raw.isdigit():
        try:
            candidate_vid = int(raw)
        except Exception:
            candidate_vid = None

    q = VLAN.objects.all()
    if scope_obj is not None:
        try:
            from django.contrib.contenttypes.models import ContentType

            ct_loc = ContentType.objects.get_by_natural_key("dcim", "location")
            anc_ids = list(
                scope_obj.get_ancestors(include_self=True).values_list("id", flat=True)
            )
            q_loc = VLAN.objects.filter(
                group__scope_type=ct_loc,
                group__scope_id__in=anc_ids,
            )
            q_site = VLAN.objects.none()
            if getattr(scope_obj, "site_id", None):
                try:
                    q_site = VLAN.objects.get_for_site(scope_obj.site)
                except Exception:
                    q_site = VLAN.objects.none()
            q = (q_loc | q_site).distinct()
        except Exception:
            q = VLAN.objects.all()

    if candidate_vid is not None:
        by_vid = q.filter(vid=candidate_vid).first()
        if by_vid is not None:
            return by_vid
        by_vid_any = VLAN.objects.filter(vid=candidate_vid).first()
        if by_vid_any is not None:
            return by_vid_any

    by_name = _resolve_by_name(VLAN, raw)
    if by_name is not None:
        return by_name
    return q.filter(name=raw).first()


def _assign_ips_to_interface(iface, ip_blob: str, vrf) -> bool:
    from ipam.models import IPAddress

    changed = False
    for raw in _split_ip_candidates(ip_blob):
        try:
            addr = _normalize_ip_for_netbox(raw.split()[0])
        except Exception:
            continue
        existing = IPAddress.objects.filter(address=addr, vrf=vrf).first()
        if existing is None:
            ip_obj = IPAddress(address=addr, vrf=vrf)
            if hasattr(ip_obj, "assigned_object"):
                ip_obj.assigned_object = iface
            elif hasattr(ip_obj, "interface"):
                ip_obj.interface = iface
            ip_obj.save()
            changed = True
        else:
            same = False
            if hasattr(existing, "assigned_object_id") and existing.assigned_object_id == iface.pk:
                same = True
            if hasattr(existing, "interface_id") and getattr(existing, "interface_id", None) == iface.pk:
                same = True
            if not same:
                _netbox_changelog_snapshot(existing)
                if hasattr(existing, "assigned_object"):
                    existing.assigned_object = iface
                elif hasattr(existing, "interface"):
                    existing.interface = iface
                existing.save()
                changed = True
    return changed


def apply_create_interface(op: dict[str, Any]) -> tuple[str, str]:
    from dcim.models import Device, Interface, Location, Site

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    host = _cell(cells, "Host")
    if_name = _cell(cells, "Suggested NB name", "MAAS intf")
    mac, vid, ip_blob = _interface_mac_vlan_ip_from_cells(cells, include_nb_fallback=False)
    site_hint = _cell(cells, "NB site")
    loc_hint = _cell(cells, "NB location")
    type_slug = _resolve_interface_type_slug(_cell(cells, "NB Proposed intf Type"))
    role_label = _cell(cells, "NB Proposed intf Label")
    if not host or not if_name:
        return "skipped", "skipped_prerequisite_missing"
    dev = Device.objects.filter(name=host).first()
    if not dev:
        return "skipped", "skipped_prerequisite_missing"
    site_ch = loc_ch = False
    if site_hint:
        site_obj = _resolve_by_name(Site, site_hint)
        if site_obj and dev.site_id != site_obj.pk:
            dev.site = site_obj
            site_ch = True
    if loc_hint:
        loc_obj = _resolve_by_name(Location, loc_hint)
        if loc_obj and getattr(dev, "location_id", None) != loc_obj.pk:
            dev.location = loc_obj
            loc_ch = True
    if site_ch or loc_ch:
        _netbox_changelog_snapshot(dev)
        dev.save()
    iface = Interface.objects.filter(device=dev, name=if_name).first()
    untagged = _resolve_vlan_for_device(dev, vid) if vid else None
    if iface is None:
        iface = Interface(
            device=dev,
            name=if_name,
            type=type_slug if type_slug is not None else _iface_type_default(),
        )
        if mac:
            iface.mac_address = mac
        if untagged:
            iface.untagged_vlan = untagged
        iface.save()
        tag_ch = False
        if role_label and hasattr(iface, "tags"):
            tag_ch = _merge_interface_role_tag(iface, role_label)
        if tag_ch:
            iface.save()
        vrf = None
        if ip_blob:
            _assign_ips_to_interface(iface, ip_blob, vrf)
        return "created", "ok_created"
    _netbox_changelog_snapshot(iface)
    changed = False
    if _scrub_interface_drift_audit_description(iface):
        changed = True
    if mac and str(iface.mac_address or "").upper() != (mac or "").upper():
        iface.mac_address = mac
        changed = True
    if untagged and iface.untagged_vlan_id != untagged.pk:
        iface.untagged_vlan = untagged
        changed = True
    if type_slug is not None and getattr(iface, "type", None) != type_slug:
        iface.type = type_slug
        changed = True
    if changed:
        iface.save()
    tag_ch = False
    if role_label and hasattr(iface, "tags"):
        tag_ch = _merge_interface_role_tag(iface, role_label)
    if tag_ch:
        iface.save()
        changed = True
    vrf = None
    if ip_blob and _assign_ips_to_interface(iface, ip_blob, vrf):
        changed = True
    if changed:
        return "updated", "ok_updated"
    return "skipped", "skipped_already_desired"


def apply_update_interface(op: dict[str, Any]) -> tuple[str, str]:
    from dcim.models import Device, Interface

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    host = _cell(cells, "Host")
    nb_name = _cell(cells, "NB intf")
    ma_name = _cell(cells, "MAAS intf")
    mac, vid, ip_blob = _interface_mac_vlan_ip_from_cells(cells, include_nb_fallback=True)
    type_slug = _resolve_interface_type_slug(_cell(cells, "NB Proposed intf Type"))
    role_label = _cell(cells, "NB Proposed intf Label")
    if not host:
        return "skipped", "skipped_prerequisite_missing"
    dev = Device.objects.filter(name=host).first()
    if not dev:
        return "skipped", "skipped_prerequisite_missing"
    iface = None
    if nb_name:
        iface = Interface.objects.filter(device=dev, name=nb_name).first()
    if iface is None and ma_name:
        iface = Interface.objects.filter(device=dev, name=ma_name).first()
    if iface is None:
        return "skipped", "skipped_prerequisite_missing"
    _netbox_changelog_snapshot(iface)
    changed = False
    if _scrub_interface_drift_audit_description(iface):
        changed = True
    untagged = _resolve_vlan_for_device(dev, vid) if vid else None
    if mac and str(iface.mac_address or "").upper() != mac.upper():
        iface.mac_address = mac
        changed = True
    if untagged and iface.untagged_vlan_id != untagged.pk:
        iface.untagged_vlan = untagged
        changed = True
    if type_slug is not None and getattr(iface, "type", None) != type_slug:
        iface.type = type_slug
        changed = True
    if changed:
        iface.save()
    tag_ch = False
    if role_label and hasattr(iface, "tags"):
        tag_ch = _merge_interface_role_tag(iface, role_label)
    if tag_ch:
        iface.save()
        changed = True
    vrf = None
    if ip_blob and _assign_ips_to_interface(iface, ip_blob, vrf):
        changed = True
    if changed:
        return "updated", "ok_updated"
    return "skipped", "skipped_already_desired"


def _bmc_apply(op: dict[str, Any], *, existing_oob: bool) -> tuple[str, str]:
    from dcim.models import Device, Interface

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    host = _cell(cells, "Host")
    bmc_ip_maas = _cell(cells, "MAAS BMC IP")
    bmc_ip_os = _cell(cells, "OS BMC IP")
    bmc_ip_nb = _cell(cells, "NB mgmt iface IP")
    bmc_ip = bmc_ip_maas or bmc_ip_os or bmc_ip_nb
    bmc_mac = _normalize_mac(_cell(cells, "MAAS BMC MAC", "NB OOB MAC"))
    if_name = _cell(
        cells,
        "Suggested NB mgmt iface" if not existing_oob else "Suggested NB OOB Port",
    )
    type_slug = _resolve_interface_type_slug(_cell(cells, "NB Proposed intf Type"))
    role_label = _cell(cells, "NB Proposed intf Label")
    if not host or not if_name:
        return "skipped", "skipped_prerequisite_missing"
    if not bmc_ip:
        return "skipped", "skipped_prerequisite_missing"
    dev = Device.objects.filter(name=host).first()
    if not dev:
        return "skipped", "skipped_prerequisite_missing"
    iface = Interface.objects.filter(device=dev, name=if_name).first()
    if iface is None:
        iface = Interface(
            device=dev,
            name=if_name,
            type=type_slug if type_slug is not None else _iface_type_default(),
        )
        if bmc_mac:
            iface.mac_address = bmc_mac
        iface.save()
        created = True
    else:
        created = False
        _netbox_changelog_snapshot(iface)
        ch = False
        if bmc_mac and str(iface.mac_address or "").upper() != bmc_mac.upper():
            iface.mac_address = bmc_mac
            ch = True
        if type_slug is not None and getattr(iface, "type", None) != type_slug:
            iface.type = type_slug
            ch = True
        if ch:
            iface.save()
    vrf = None
    combined_blob = (
        " ".join(x for x in (bmc_ip_maas, bmc_ip_os, bmc_ip_nb) if (x or "").strip())
        or str(bmc_ip).strip()
    )
    try:
        for raw in _split_ip_candidates(combined_blob):
            _normalize_ip_for_netbox(raw.split()[0])
    except Exception:
        return "failed", "failed_validation_bad_ip"
    ip_changed = _assign_ips_to_interface(iface, combined_blob, vrf)
    desc_changed = False
    if not created and _scrub_interface_drift_audit_description(iface):
        desc_changed = True
    tag_ch = False
    if role_label and hasattr(iface, "tags"):
        tag_ch = _merge_interface_role_tag(iface, role_label)
    if tag_ch:
        iface.save()
    if desc_changed:
        iface.save()
    if ip_changed or desc_changed or created or tag_ch:
        return ("created", "ok_created") if created else ("updated", "ok_updated")
    return "skipped", "skipped_already_desired"


def apply_bmc_documentation(op: dict[str, Any]) -> tuple[str, str]:
    return _bmc_apply(op, existing_oob=False)


def apply_bmc_alignment(op: dict[str, Any]) -> tuple[str, str]:
    return _bmc_apply(op, existing_oob=True)


_APPLY_FUNCS: dict[str, Any] = {
    "create_prefix": apply_create_prefix,
    "create_ip_range": apply_create_ip_range,
    "create_floating_ip": apply_create_floating_ip,
    "create_device": apply_create_device,
    "review_device": apply_review_device,
    "create_interface": apply_create_interface,
    "update_interface": apply_update_interface,
    "placement_alignment": apply_placement_alignment,
    "serial_review": apply_serial_review,
    "bmc_documentation": apply_bmc_documentation,
    "bmc_alignment": apply_bmc_alignment,
    "create_openstack_vm": apply_create_openstack_vm,
    "update_openstack_vm": apply_update_openstack_vm,
}

_APPLY_WORKFLOW_HEADER_NORMS: frozenset[str] = frozenset(
    _norm_header(x)
    for x in (
        "Proposed Action",
        "Proposed action",
        "Proposed properties",
        "Proposed properties (from MAAS)",
        "Status",
        "Risk",
        "Authority",
    )
)


def _header_norms(*names: str) -> frozenset[str]:
    return frozenset(_norm_header(n) for n in names if str(n).strip())


def _netbox_preview_source_header_norms(selection_key: str) -> frozenset[str] | None:
    """
    Normalized audit headers that may feed apply for this section: recon preview sources,
    plus structural columns (description/CF snapshots) used by the same apply handlers.
    None = only strip placeholders; do not drop keys by name.
    """
    sk = str(selection_key or "").strip()
    if sk == "detail_placement_lifecycle_alignment":
        return _header_norms(
            "Host",
            "NetBox site",
            "NetBox location",
            "NB state (current)",
            "NB proposed device status",
        )
    if sk in ("detail_new_devices", "detail_review_only_devices"):
        return (
            _header_norms(
                "Hostname",
                "Host",
                "NB proposed region",
                "NB proposed site",
                "NB proposed location",
                "NB proposed role",
                "NB proposed device type",
                "NB proposed device status",
                "NB state (current)",
                "Serial Number",
                "MAAS Serial",
                "NB proposed tag",
                "Suggested NetBox tags",
                "NetBox tags",
                "NB proposed platform",
                "OS provision",
                "OS release",
                "MAAS OS",
                "OS",
                "NetBox site",
                "NetBox location",
            )
            | _header_norms(*(h for h, _ in _NEW_DEVICE_DRIFT_TO_CF_KEYS))
        )
    if sk == "detail_new_prefixes":
        return _header_norms(
            "NetBox prefix ID",
            "CIDR",
            "NB proposed VRF",
            "NB proposed status",
            "NB proposed role",
            "NB Proposed Tenant",
            "NB Proposed Scope",
            "NB Proposed VLAN",
            "NB Proposed Prefix description (editable)",
        ) | _header_norms(*_NEW_PREFIX_DRIFT_SNAPSHOT_HEADERS)
    if sk == "detail_existing_prefixes":
        # No NetBox prefix ID in drift rows; match apply path uses CIDR + VRF only.
        return _header_norms(
            "CIDR",
            "NB proposed VRF",
            "NB proposed status",
            "NB proposed role",
            "NB Proposed Tenant",
            "NB Proposed Scope",
            "NB Proposed VLAN",
            "NB Proposed Prefix description (editable)",
        ) | _header_norms(*_NEW_PREFIX_DRIFT_SNAPSHOT_HEADERS)
    if sk == "detail_new_ip_ranges":
        return _header_norms(
            "Start address",
            "End address",
            "NB proposed status",
            "NB proposed role",
            "NB proposed VRF",
            "NB Proposed Description",
            "OS Pool Description",
        )
    if sk in ("detail_new_fips", "detail_existing_fips"):
        return _header_norms(
            "Floating IP",
            "NB proposed status",
            "NB proposed role",
            "NB proposed VRF",
            "NB Proposed Tenant",
            "Name",
            "NAT inside IP (from OpenStack fixed IP)",
            "NAT inside IP",
            "NB current NAT inside",
        ) | _header_norms(*_NEW_FIP_DRIFT_SNAPSHOT_HEADERS) | _header_norms(
            *(h for h, _ in _NEW_FIP_DRIFT_TO_CF_KEYS)
        )
    if sk == "detail_new_vms":
        return _header_norms(
            "VM name",
            "NB proposed primary IP",
            "NB proposed cluster",
            "NB proposed site",
            "NB Proposed Tenant",
            "NB proposed VM status",
            "NB proposed device (VM)",
            "NB proposed device (hypervisor)",
            "Hypervisor hostname",
            "OS region",
            "OS status",
            "Project",
        )
    if sk == "detail_existing_vms":
        return _header_norms(
            "NetBox VM ID",
            "VM name",
            "NB proposed primary IP",
            "NB proposed cluster",
            "NB proposed site",
            "NB Proposed Tenant",
            "NB proposed VM status",
            "NB proposed device (VM)",
            "NB proposed device (hypervisor)",
            "Hypervisor hostname",
            "OS region",
            "OS status",
            "Project",
            "NB current vCPUs",
            "NB current Memory MB",
            "NB current Disk GB",
            "NB current primary IP",
            "NB current cluster",
            "NB current device",
            "NB current VM status",
            "Drift summary",
        )
    if sk in NEW_NIC_SELECTION_KEYS:
        return _header_norms(
            "Host",
            "Suggested NB name",
            "MAAS intf",
            "NB site",
            "NB location",
            "NB Proposed intf Label",
            "NB Proposed intf Type",
            "Parsed MAC",
            "Parsed untagged VLAN",
            "Parsed IPs",
            "MAAS MAC",
            "OS MAC",
            "MAAS VLAN",
            "OS runtime VLAN",
            "MAAS IPs",
            "OS runtime IP",
        )
    if sk in ("detail_nic_drift_os", "detail_nic_drift_maas"):
        return _header_norms(
            "Host",
            "NB intf",
            "MAAS intf",
            "NB Proposed intf Label",
            "NB Proposed intf Type",
            "MAAS MAC",
            "OS MAC",
            "NB MAC",
            "MAAS VLAN",
            "OS runtime VLAN",
            "NB VLAN",
            "MAAS IPs",
            "OS runtime IP",
            "NB IPs",
        )
    if sk == "detail_bmc_new_devices":
        return _header_norms(
            "Host",
            "MAAS BMC IP",
            "OS BMC IP",
            "NB mgmt iface IP",
            "MAAS BMC MAC",
            "NB OOB MAC",
            "Suggested NB mgmt iface",
            "NB Proposed intf Label",
            "NB Proposed intf Type",
        )
    if sk == "detail_bmc_existing":
        return _header_norms(
            "Host",
            "MAAS BMC IP",
            "OS BMC IP",
            "NB mgmt iface IP",
            "MAAS BMC MAC",
            "NB OOB MAC",
            "Suggested NB OOB Port",
            "NB Proposed intf Label",
            "NB Proposed intf Type",
            "NetBox OOB",
        )
    if sk == "detail_serial_review":
        return _header_norms("Host", "Hostname", "MAAS Serial", "NetBox Serial", "Serial Number")
    return None


def reconciliation_apply_snapshot_cells(selection_key: str, cells: Any) -> dict[str, str]:
    """
    Column/value dict passed into apply handlers (same path as ``apply_row_operation``):
    recon-preview allowlist, workflow fields when set, empty and ``—`` placeholders removed.
    """
    return _cells_scoped_for_apply(selection_key, cells)


def _cells_scoped_for_apply(selection_key: str, cells: Any) -> dict[str, str]:
    sk = str(selection_key or "").strip()
    if not isinstance(cells, dict):
        return {}
    base: dict[str, str] = {}
    for k, v in cells.items():
        ks = str(k).strip()
        if not ks:
            continue
        base[ks] = "" if v is None else str(v).strip()
    if sk in NEW_NIC_SELECTION_KEYS:
        base = new_nic_cells_for_reconciliation(base)
    allowed = _netbox_preview_source_header_norms(sk)
    wf = _APPLY_WORKFLOW_HEADER_NORMS
    out: dict[str, str] = {}
    for k, v in base.items():
        kn = _norm_header(k)
        if allowed is not None and kn not in allowed and kn not in wf:
            continue
        if kn in wf:
            if v.strip():
                out[k] = v
            continue
        if _meaningful_cell_val(v):
            out[k] = v
    return out


def apply_row_operation(op: dict[str, Any]) -> tuple[str, str]:
    action = str(op.get("action") or "").strip()
    fn = _APPLY_FUNCS.get(action)
    if not fn:
        return "failed", "failed_not_implemented"
    sk = str(op.get("selection_key") or "").strip()
    op_use = dict(op)
    op_use["cells"] = _cells_scoped_for_apply(sk, op.get("cells"))
    return fn(op_use)
