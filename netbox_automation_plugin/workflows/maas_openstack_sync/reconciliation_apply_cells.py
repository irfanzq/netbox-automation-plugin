"""Apply frozen reconciliation rows using full audit table cells (all columns).

Each op[\"cells\"] mirrors the drift HTML/XLSX row: NB proposed *, MAAS/OS fields,
Status, Proposed Action, Risk, notes, etc. Handlers map every applicable field to NetBox.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

from django.utils.text import slugify

logger = logging.getLogger(__name__)

# Actions with real NetBox writers (extend as handlers are filled in).
SUPPORTED_APPLY_ACTIONS: frozenset[str] = frozenset(
    {
        "create_prefix",
        "create_floating_ip",
        "create_device",
        "review_device",
        "create_interface",
        "update_interface",
        "placement_alignment",
        "serial_review",
        "bmc_documentation",
        "bmc_alignment",
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


def _split_ip_candidates(blob: str) -> list[str]:
    out: list[str] = []
    for chunk in re.split(r"[,;\s]+", str(blob or "").strip()):
        t = chunk.strip()
        if not t or t in ("—", "-"):
            continue
        out.append(t)
    return out


_DRIFT_AUDIT_MARKER = "\n=== Drift reconciliation (full row) ===\n"


def _norm_header(k: str) -> str:
    return str(k or "").strip().lower()


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


def _merge_audit_residual_onto_object(
    obj: Any,
    cells: dict[str, str],
    consumed_lower: set[str],
    *,
    attr_names: tuple[str, ...] = ("comments", "description"),
    max_len: int = 8000,
) -> bool:
    """Append full-row audit residue so suggested/proposed/OS/MAAS columns are not dropped."""
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


def _interface_audit_description(cells: dict[str, str], consumed_lower: set[str]) -> str:
    """Single description: headline NB/MAAS/proposed columns + full residual (no audit column omitted)."""
    # Each tuple: display label first, then synonym header names to match in cells.
    headline_specs: tuple[tuple[str, ...], ...] = (
        ("Proposed properties (from MAAS)",),
        ("Suggested NB name", "MAAS intf"),
        ("Risk",),
        ("Authority",),
        ("Status",),
        ("Proposed Action", "Proposed action"),
        ("Suggested NB vrf", "NB proposed VRF", "NB VRF"),
        ("NetBox site", "NB site"),
        ("NB proposed tag", "NetBox tags", "Suggested NetBox tags"),
        ("NetBox actions", "Suggested NetBox actions", "NB proposed actions"),
    )
    consumed2 = set(consumed_lower)
    headline: list[str] = []
    for spec in headline_specs:
        display = spec[0]
        for n in spec:
            consumed2.add(_norm_header(n))
        v = _cell(cells, *spec)
        if v:
            headline.append(f"{display}: {v}")
    residual = _audit_residual_text(cells, consumed2)
    parts = [p for p in ("\n".join(headline), residual) if p]
    out = "\n\n".join(parts).strip()
    return out[:4096] if len(out) > 4096 else out


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


def apply_create_prefix(op: dict[str, Any]) -> tuple[str, str]:
    from ipam.models import Prefix, Role, VRF

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    cidr = _cell(cells, "CIDR")
    vrf_name = _cell(cells, "NB proposed VRF")
    status_name = _cell(cells, "NB proposed status")
    role_name = _cell(cells, "NB proposed role")
    descr = _cell(cells, "Role reason", "Authority")
    consumed = {
        _norm_header("CIDR"),
        _norm_header("NB proposed VRF"),
        _norm_header("NB proposed status"),
        _norm_header("NB proposed role"),
        _norm_header("Role reason"),
        _norm_header("Authority"),
    }
    if not cidr:
        return "skipped", "skipped_prerequisite_missing"
    vrf = _resolve_by_name(VRF, vrf_name) if vrf_name else None
    if vrf_name and vrf is None:
        return "skipped", "skipped_prerequisite_missing"
    role = _resolve_by_name(Role, role_name) if role_name else None
    if role_name and role is None:
        return "skipped", "skipped_prerequisite_missing"
    existing = Prefix.objects.filter(prefix=cidr, vrf=vrf).first()
    if existing is not None:
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
    obj = Prefix(prefix=cidr, vrf=vrf)
    if status_name:
        val = _pick_choice_value(obj._meta.get_field("status"), status_name)
        if val is not None:
            obj.status = val
    if role is not None:
        obj.role = role
    if descr and hasattr(obj, "description"):
        obj.description = descr[:2000]
    obj.save()
    if _merge_audit_residual_onto_object(obj, cells, consumed, attr_names=("description",), max_len=4000):
        obj.save()
    return "created", "ok_created"


def apply_create_floating_ip(op: dict[str, Any]) -> tuple[str, str]:
    from ipam.models import IPAddress, VRF

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    raw_ip = _cell(cells, "Floating IP")
    status_name = _cell(cells, "NB proposed status")
    vrf_name = _cell(cells, "NB proposed VRF")
    role_name = _cell(cells, "NB proposed role")
    consumed = {
        _norm_header("Floating IP"),
        _norm_header("NB proposed status"),
        _norm_header("NB proposed VRF"),
        _norm_header("NB proposed role"),
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
    existing = IPAddress.objects.filter(address=address, vrf=vrf).first()
    if existing is not None:
        changed = False
        if status_name:
            val = _pick_choice_value(existing._meta.get_field("status"), status_name)
            if val is not None and existing.status != val:
                existing.status = val
                changed = True
        if role_obj is not None and hasattr(existing, "role_id") and existing.role_id != role_obj.pk:
            existing.role = role_obj
            changed = True
        merge_ch = _merge_audit_residual_onto_object(
            existing, cells, consumed, attr_names=("description",), max_len=4000
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
    ip_obj.save()
    if _merge_audit_residual_onto_object(ip_obj, cells, consumed, attr_names=("description",), max_len=4000):
        ip_obj.save()
    return "created", "ok_created"


def _apply_device_core(cells: dict[str, str], *, create_if_missing: bool) -> tuple[str, str]:
    from dcim.models import Device, DeviceRole, DeviceType, Location, Site

    hostname = _cell(cells, "Hostname", "Host")
    site_name = _cell(cells, "NB proposed site", "NetBox site")
    location_name = _cell(cells, "NB proposed location", "NetBox location")
    role_name = _cell(cells, "NB proposed role")
    dtype_name = _cell(cells, "NB proposed device type")
    status_name = _cell(cells, "NB proposed device status", "NB state (current)")
    serial = _cell(cells, "Serial Number", "MAAS Serial")
    tag_cell = _cell(cells, "NB proposed tag")
    consumed_d = {
        _norm_header("Hostname"),
        _norm_header("Host"),
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
        dev.save()
        if tag_cell:
            _merge_device_tags(dev, tag_cell)
        if _merge_audit_residual_onto_object(
            dev, cells, consumed_d, attr_names=("comments", "description"), max_len=8000
        ):
            dev.save()
        return "created", "ok_created"
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
    if tag_cell:
        if _merge_device_tags(existing, tag_cell):
            changed = True
    merge_ch = _merge_audit_residual_onto_object(
        existing, cells, consumed_d, attr_names=("comments", "description"), max_len=8000
    )
    if changed or merge_ch:
        existing.save()
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
    return _apply_device_core(cells, create_if_missing=False)


def apply_placement_alignment(op: dict[str, Any]) -> tuple[str, str]:
    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    host = _cell(cells, "Host", "Hostname")
    if not host:
        return "skipped", "skipped_prerequisite_missing"
    fake = {
        "Hostname": host,
        "NB proposed site": _cell(cells, "NetBox site"),
        "NB proposed location": _cell(cells, "NetBox location"),
        "NB proposed device status": _cell(cells, "NB proposed device status"),
        "NB proposed role": _cell(cells, "NB proposed role"),
    }
    return _apply_device_core(
        {**cells, **{k: v for k, v in fake.items() if v}}, create_if_missing=False
    )


def apply_serial_review(op: dict[str, Any]) -> tuple[str, str]:
    from dcim.models import Device

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    host = _cell(cells, "Hostname", "Host")
    serial = _cell(cells, "MAAS Serial") or _cell(cells, "NetBox Serial")
    consumed_sr = {
        _norm_header("Hostname"),
        _norm_header("Host"),
        _norm_header("MAAS Serial"),
        _norm_header("NetBox Serial"),
        _norm_header("Serial Number"),
    }
    if not host:
        return "skipped", "skipped_prerequisite_missing"
    dev = Device.objects.filter(name=host).first()
    if not dev:
        return "skipped", "skipped_prerequisite_missing"
    if not serial:
        return "skipped", "skipped_prerequisite_missing"
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


def _resolve_vlan_for_device(device, vid: int):
    from ipam.models import VLAN

    if not device.site_id:
        return None
    return VLAN.objects.filter(site_id=device.site_id, vid=vid).first()


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
    mac = _normalize_mac(_cell(cells, "MAAS MAC", "OS MAC"))
    vid = _parse_vlan_vid(_cell(cells, "MAAS VLAN", "OS runtime VLAN"))
    ip_blob = _cell(cells, "MAAS IPs", "OS runtime IP")
    site_hint = _cell(cells, "NB site")
    loc_hint = _cell(cells, "NB location")
    consumed_i = {
        _norm_header("Host"),
        _norm_header("NB site"),
        _norm_header("NB location"),
        _norm_header("MAAS intf"),
        _norm_header("Suggested NB name"),
        _norm_header("MAAS MAC"),
        _norm_header("OS MAC"),
        _norm_header("MAAS VLAN"),
        _norm_header("OS runtime VLAN"),
        _norm_header("MAAS IPs"),
        _norm_header("OS runtime IP"),
    }
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
        dev.save()
    iface = Interface.objects.filter(device=dev, name=if_name).first()
    untagged = _resolve_vlan_for_device(dev, vid) if vid else None
    full_desc = _interface_audit_description(cells, consumed_i)
    if iface is None:
        iface = Interface(device=dev, name=if_name, type=_iface_type_default())
        if mac:
            iface.mac_address = mac
        if untagged:
            iface.untagged_vlan = untagged
        if full_desc and hasattr(iface, "description"):
            iface.description = full_desc
        iface.save()
        vrf = None
        if ip_blob:
            _assign_ips_to_interface(iface, ip_blob, vrf)
        return "created", "ok_created"
    changed = False
    if mac and str(iface.mac_address or "").upper() != (mac or "").upper():
        iface.mac_address = mac
        changed = True
    if untagged and iface.untagged_vlan_id != untagged.pk:
        iface.untagged_vlan = untagged
        changed = True
    if full_desc and hasattr(iface, "description") and (iface.description or "").strip() != full_desc:
        iface.description = full_desc
        changed = True
    if changed:
        iface.save()
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
    mac = _normalize_mac(_cell(cells, "MAAS MAC", "OS MAC", "NB MAC"))
    vid = _parse_vlan_vid(_cell(cells, "MAAS VLAN", "OS runtime VLAN", "NB VLAN"))
    ip_blob = _cell(cells, "MAAS IPs", "OS runtime IP", "NB IPs")
    consumed_i = {
        _norm_header("Host"),
        _norm_header("NB intf"),
        _norm_header("MAAS intf"),
        _norm_header("MAAS MAC"),
        _norm_header("OS MAC"),
        _norm_header("NB MAC"),
        _norm_header("MAAS VLAN"),
        _norm_header("OS runtime VLAN"),
        _norm_header("NB VLAN"),
        _norm_header("MAAS IPs"),
        _norm_header("OS runtime IP"),
        _norm_header("NB IPs"),
    }
    full_desc = _interface_audit_description(cells, consumed_i)
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
    changed = False
    untagged = _resolve_vlan_for_device(dev, vid) if vid else None
    if mac and str(iface.mac_address or "").upper() != mac.upper():
        iface.mac_address = mac
        changed = True
    if untagged and iface.untagged_vlan_id != untagged.pk:
        iface.untagged_vlan = untagged
        changed = True
    if full_desc and hasattr(iface, "description") and (iface.description or "").strip() != full_desc:
        iface.description = full_desc
        changed = True
    if changed:
        iface.save()
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
    consumed_b = {
        _norm_header("Host"),
        _norm_header("MAAS BMC IP"),
        _norm_header("OS BMC IP"),
        _norm_header("NB mgmt iface IP"),
        _norm_header("MAAS BMC MAC"),
        _norm_header("NB OOB MAC"),
        _norm_header("Suggested NB mgmt iface"),
        _norm_header("Suggested NB OOB Port"),
        _norm_header("OS mgmt type"),
        _norm_header("MAAS power_type"),
    }
    if existing_oob:
        consumed_b.update(
            {
                _norm_header("NetBox OOB"),
                _norm_header("NB IP coverage"),
                _norm_header("Actual NB Port Carrying BMC IP"),
            }
        )
    if not host or not if_name:
        return "skipped", "skipped_prerequisite_missing"
    if not bmc_ip:
        return "skipped", "skipped_prerequisite_missing"
    dev = Device.objects.filter(name=host).first()
    if not dev:
        return "skipped", "skipped_prerequisite_missing"
    iface = Interface.objects.filter(device=dev, name=if_name).first()
    if iface is None:
        iface = Interface(device=dev, name=if_name, type=_iface_type_default())
        if bmc_mac:
            iface.mac_address = bmc_mac
        iface.save()
        created = True
    else:
        created = False
        ch = False
        if bmc_mac and str(iface.mac_address or "").upper() != bmc_mac.upper():
            iface.mac_address = bmc_mac
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
    full_desc = _interface_audit_description(cells, consumed_b)
    desc_changed = False
    if full_desc and hasattr(iface, "description") and (iface.description or "").strip() != full_desc:
        iface.description = full_desc
        desc_changed = True
    if desc_changed:
        iface.save()
    if ip_changed or desc_changed or created:
        return ("created", "ok_created") if created else ("updated", "ok_updated")
    return "skipped", "skipped_already_desired"


def apply_bmc_documentation(op: dict[str, Any]) -> tuple[str, str]:
    return _bmc_apply(op, existing_oob=False)


def apply_bmc_alignment(op: dict[str, Any]) -> tuple[str, str]:
    return _bmc_apply(op, existing_oob=True)


_APPLY_FUNCS: dict[str, Any] = {
    "create_prefix": apply_create_prefix,
    "create_floating_ip": apply_create_floating_ip,
    "create_device": apply_create_device,
    "review_device": apply_review_device,
    "create_interface": apply_create_interface,
    "update_interface": apply_update_interface,
    "placement_alignment": apply_placement_alignment,
    "serial_review": apply_serial_review,
    "bmc_documentation": apply_bmc_documentation,
    "bmc_alignment": apply_bmc_alignment,
}


def apply_row_operation(op: dict[str, Any]) -> tuple[str, str]:
    action = str(op.get("action") or "").strip()
    fn = _APPLY_FUNCS.get(action)
    if not fn:
        return "failed", "failed_not_implemented"
    return fn(op)
