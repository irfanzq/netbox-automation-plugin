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
from netbox_automation_plugin.sync.tenancy_netbox_compat import tenant_hierarchy_fk

logger = logging.getLogger(__name__)

_VID_FROM_PARENS_RE = re.compile(r"\((\d+)\)\s*$")
# Log once per model if snapshot() is missing (branch Diff will lack field deltas).
_SNAPSHOT_MISSING_LOGGED: set[str] = set()

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
        "create_vlan",
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


def _skip_missing_prereq(detail: str) -> tuple[str, str, str]:
    """Stable reason code + human detail for troubleshooting (stored as apply row ``reason_detail``)."""
    d = (detail or "").strip() or "No further detail."
    if len(d) > 2000:
        d = d[:1997] + "..."
    return "skipped", "skipped_prerequisite_missing", d


def _netbox_changelog_snapshot(instance: Any) -> None:
    """
    NetBox change-logging (and netbox-branching ChangeDiff field deltas) need a pre-save
    snapshot. The REST UI does this automatically; plugin ORM paths must call it before
    mutating an existing row or the branch Diff shows \"Updated\" with empty columns.

    Call again before *each* additional ``save()`` on the same instance in one request
    (e.g. field update then tag merge): otherwise only the first mutation gets a delta and
    MAC/VLAN/IP-style fields look missing while tags still appear.

    For **creates**, a single ``save()`` with every field often yields a branch row with an
    empty Difference column; prefer a minimal first ``save()``, then follow-up updates.

    Interface **scalar** fields (MAC, untagged VLAN, type, description) are applied in **one**
    ``snapshot()`` + ``save()`` per reconciliation row so branch Diff shows every changed
    field in one delta; multiple Interface saves in the same DB transaction are often
    collapsed in the Diff UI to a single sparse row (e.g. tags only).

    Ref: https://github.com/netboxlabs/netbox-branching/discussions/51
    """
    fn = getattr(instance, "snapshot", None)
    if not callable(fn):
        key = type(instance).__name__
        if key not in _SNAPSHOT_MISSING_LOGGED:
            _SNAPSHOT_MISSING_LOGGED.add(key)
            logger.warning(
                "NetBox change logging: %s has no snapshot(); branch Diff may omit field deltas for plugin ORM writes.",
                key,
            )
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


def _resolve_device_type(raw: str | None) -> Any:
    """
    Resolve ``DeviceType`` from drift / recon cells.

    The audit UI often shows ``"{manufacturer} {model}"`` (e.g. "Dell PowerEdge R660") while
    NetBox stores ``model`` (e.g. "PowerEdge R660") on ``DeviceType`` with a separate
    ``manufacturer`` FK—plain ``model__iexact`` on the full string therefore misses.
    """
    from dcim.models import DeviceType, Manufacturer

    s = str(raw or "").strip()
    if not s or s in ("—", "-"):
        return None
    dt = _resolve_by_name(DeviceType, s)
    if dt is not None:
        return dt
    qmod = DeviceType.objects.filter(model__iexact=s)
    n = qmod.count()
    if n == 1:
        return qmod.first()
    parts = s.split()
    if len(parts) >= 2:
        mfr_key, rest = parts[0], " ".join(parts[1:])
        hit = DeviceType.objects.filter(
            manufacturer__name__iexact=mfr_key,
            model__iexact=rest,
        ).first()
        if hit is not None:
            return hit
        mfr = Manufacturer.objects.filter(name__iexact=mfr_key).first()
        if mfr is None:
            mslug = slugify(mfr_key)[:50]
            mfr = Manufacturer.objects.filter(slug__iexact=mslug).first() if mslug else None
        if mfr is not None:
            hit = DeviceType.objects.filter(manufacturer=mfr, model__iexact=rest).first()
            if hit is not None:
                return hit
    s_low = s.lower()
    tail_guesses: list[str] = []
    if len(parts) >= 2:
        tail_guesses.append(parts[-1])
    tail_guesses.append(s)
    seen: set[str] = set()
    for tail in tail_guesses:
        t = tail.strip()
        if len(t) < 2 or t.lower() in seen:
            continue
        seen.add(t.lower())
        qs = DeviceType.objects.select_related("manufacturer").filter(model__iexact=t)
        if qs.count() > 40:
            qs = DeviceType.objects.select_related("manufacturer").filter(model__istartswith=t)[:50]
        for cand in qs:
            if f"{cand.manufacturer.name} {cand.model}".strip().lower() == s_low:
                return cand
    return None


def _resolve_tenant(raw: str | None) -> Any:
    """
    Resolve ``Tenant`` from drift / recon cells.

    Audit columns may use hyphenated or project-specific labels (e.g. ``whitefiber-internal``)
    while NetBox stores a shorter ``name`` (e.g. ``whitefiber``). Try slug and a unique
    prefix before the first hyphen when the full string does not match. Hierarchical picker
    labels ``Parent / Child`` (or ``Group / Tenant`` on NetBox 4.x) match hierarchy names.
    """
    from tenancy.models import Tenant

    s = str(raw or "").strip()
    if not s or s in ("—", "-"):
        return None
    if " / " in s:
        parent_part, child_part = s.split(" / ", 1)
        parent_part = (parent_part or "").strip()
        child_part = (child_part or "").strip()
        if parent_part and child_part:
            rel = tenant_hierarchy_fk()
            if rel == "parent":
                try:
                    for cand in Tenant.objects.filter(name__iexact=child_part).select_related(
                        "parent"
                    ).iterator():
                        par = getattr(cand, "parent", None)
                        pn = (par.name or "").strip() if par else ""
                        if pn.lower() == parent_part.lower():
                            return cand
                except Exception:
                    pass
            elif rel == "group":
                try:
                    hit = Tenant.objects.filter(
                        name__iexact=child_part,
                        group__name__iexact=parent_part,
                    ).first()
                    if hit is not None:
                        return hit
                except Exception:
                    pass
    t = _resolve_by_name(Tenant, s)
    if t is not None:
        return t
    slug = slugify(s)
    if slug:
        t = Tenant.objects.filter(slug__iexact=slug).first()
        if t is not None:
            return t
    if "-" in s:
        head = s.split("-", 1)[0].strip()
        if head and head.lower() != s.lower():
            q = Tenant.objects.filter(name__iexact=head)
            if q.count() == 1:
                return q.first()
            hs = slugify(head)
            if hs:
                q2 = Tenant.objects.filter(slug__iexact=hs)
                if q2.count() == 1:
                    return q2.first()
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


# NetBox ``VLAN.vid`` / ``Interface.untagged_vlan``: IEEE 802.1Q 1–4094. MAAS NIC rows must
# carry ``vlan.vid`` only, never ``vlan.id`` (see ``maas_client`` MAAS→NetBox VLAN mapping).
_NETBOX_IEEE_VLAN_VID_MAX = 4094


def _parse_vlan_vid(raw: str) -> int | None:
    """
    Parse a VLAN tag for NetBox apply: **1–4094** only.

    MAAS: ``vlan.vid == 0`` is untagged/native → returns ``None``. ``vlan.id`` must not appear
    in these strings (collection strips it). Values outside 1–4094 return ``None``.
    """
    s = str(raw or "").strip()
    if not s:
        return None
    m = re.search(r"\b(\d{1,4})\b", s)
    if not m:
        return None
    v = int(m.group(1))
    if 1 <= v <= _NETBOX_IEEE_VLAN_VID_MAX:
        return v
    return None


def _vlan_vid_over_ieee_max_from_proposed_body(body: str) -> int | None:
    """
    If Proposed Action names a VLAN integer above IEEE 802.1Q max, return that int.
    Used to fail loudly instead of ``ok_updated`` with no VLAN change (``_parse_vlan_vid`` drops it).
    """
    b = (body or "").strip()
    if not b:
        return None
    for pat in (
        r"\bSET_NETBOX_UNTAGGED_VLAN\s*=\s*(\d+)",
        r"\buntagged\s+VLAN\s+(\d+)",
    ):
        m = re.search(pat, b, flags=re.IGNORECASE)
        if not m:
            continue
        try:
            v = int(m.group(1))
        except ValueError:
            continue
        if v > _NETBOX_IEEE_VLAN_VID_MAX:
            return v
    return None


def _normalize_mac(raw: str) -> str | None:
    s = str(raw or "").strip().upper()
    if not s or s in ("—", "-"):
        return None
    s = s.replace("-", ":")
    parts = [p for p in s.split(":") if p]
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        try:
            int("".join(parts), 16)
        except ValueError:
            return None
        return ":".join(parts)
    # Cisco-style aabb.cc00.dd11 or bare 12 hex nibbles (MAAS / switch exports).
    dotless = s.replace(".", "").replace(":", "")
    if len(dotless) == 12:
        try:
            int(dotless, 16)
        except ValueError:
            return None
        return ":".join(dotless[i : i + 2] for i in range(0, 12, 2))
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


def _set_netbox_mac_directive_present(body: str) -> bool:
    return bool(re.search(r"\bSET_NETBOX_MAC\s*=", body or "", flags=re.IGNORECASE))


def _set_netbox_vlan_directive_present(body: str) -> bool:
    return bool(re.search(r"\bSET_NETBOX_UNTAGGED_VLAN\s*=", body or "", flags=re.IGNORECASE))


def _set_netbox_ip_directive_present(body: str) -> bool:
    return bool(re.search(r"\bSET_NETBOX_IP\s*=", body or "", flags=re.IGNORECASE))


def _nic_use_inventory_column_fallbacks(
    body: str,
    p_mac: str | None,
    p_vlan: str | None,
    p_ips: str | None,
    s_mac: str | None,
    s_vlan: str | None,
    s_ips: str | None,
) -> tuple[bool, bool, bool]:
    """
    Whether MAAS/OS/NB (and Parsed *) columns may supply MAC / VLAN / IP for apply.

    **SET_NETBOX_ mode:** A field uses inventory columns only if that keyword appears
    (``SET_NETBOX_MAC``, ``SET_NETBOX_UNTAGGED_VLAN``, ``SET_NETBOX_IP``)—exactly the
    knobs listed in Proposed Action. Human ``MAC`` / ``untagged VLAN`` / ``IPs:`` text
    does not enable column fallback in that mode.

    **Human-clause-only mode:** Column fallback is limited to columns matching clauses
    present in the text. Empty or non-clause Proposed Action keeps legacy behavior
    (all column fallbacks).
    """
    b = (body or "").strip()
    set_nb = bool(re.search(r"\bSET_NETBOX_", b, re.IGNORECASE))
    if set_nb:
        return (
            _set_netbox_mac_directive_present(b),
            _set_netbox_vlan_directive_present(b),
            _set_netbox_ip_directive_present(b),
        )

    any_human = (
        _nic_proposed_property_segment_ok(p_mac)
        or _nic_proposed_property_segment_ok(p_vlan)
        or _nic_proposed_property_segment_ok(p_ips)
    )
    if b and any_human:
        return (
            _nic_proposed_property_segment_ok(p_mac),
            _nic_proposed_property_segment_ok(p_vlan),
            _nic_proposed_property_segment_ok(p_ips),
        )
    return True, True, True


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
    Resolve MAC, untagged VLAN id, and IP blob for interface apply.

    * **Any** ``SET_NETBOX_`` in Proposed Action → **strict directive mode**: values come
      only from ``SET_NETBOX_MAC`` / ``SET_NETBOX_UNTAGGED_VLAN`` / ``SET_NETBOX_IP``
      (human ``MAC …`` / ``untagged VLAN …`` / ``IPs:`` clauses are ignored). Inventory
      columns fill a field only when that field’s ``SET_NETBOX_*`` keyword is present
      (e.g. ``SET_NETBOX_UNTAGGED_VLAN=1; SET_NETBOX_IP=172.17.0.6`` → VLAN + IP only).
    * Otherwise → human clauses first, then optional ``SET_NETBOX_*``, then columns as
      documented in ``_nic_use_inventory_column_fallbacks``.
    """
    body = _cell_nic_proposed_body(cells)
    p_mac, p_vlan, p_ips = _parse_nic_proposed_properties_segments(body)
    s_mac, s_vlan, s_ips = _parse_set_netbox_interface_directives(body)
    use_mac_cols, use_vlan_cols, use_ip_cols = _nic_use_inventory_column_fallbacks(
        body, p_mac, p_vlan, p_ips, s_mac, s_vlan, s_ips
    )
    set_nb = bool(re.search(r"\bSET_NETBOX_", body, re.IGNORECASE))

    if set_nb:
        mac = _normalize_mac(s_mac) if _nic_proposed_property_segment_ok(s_mac) else None
        if mac is None and use_mac_cols:
            if include_nb_fallback:
                mac = _normalize_mac(
                    _cell(cells, "MAAS MAC", "OS MAC", "NB MAC", "Parsed MAC")
                )
            else:
                mac = _normalize_mac(_cell(cells, "MAAS MAC", "OS MAC", "Parsed MAC"))

        vid: int | None = None
        if s_vlan:
            vid = _parse_vlan_vid(s_vlan)
        if vid is None and use_vlan_cols:
            if include_nb_fallback:
                vid = _parse_vlan_vid(
                    _cell(cells, "MAAS VLAN", "OS runtime VLAN", "NB VLAN", "Parsed untagged VLAN")
                )
            else:
                vid = _parse_vlan_vid(
                    _cell(cells, "MAAS VLAN", "OS runtime VLAN", "Parsed untagged VLAN")
                )

        ip_blob = ""
        if _nic_proposed_property_segment_ok(s_ips):
            ip_blob = str(s_ips).strip()
        if not ip_blob and use_ip_cols:
            if include_nb_fallback:
                ip_blob = _cell(cells, "MAAS IPs", "OS runtime IP", "NB IPs", "Parsed IPs")
            else:
                ip_blob = _cell(cells, "MAAS IPs", "OS runtime IP", "Parsed IPs")
    else:
        mac = _normalize_mac(p_mac) if _nic_proposed_property_segment_ok(p_mac) else None
        if mac is None and _nic_proposed_property_segment_ok(s_mac):
            mac = _normalize_mac(s_mac)
        if mac is None and use_mac_cols:
            if include_nb_fallback:
                mac = _normalize_mac(
                    _cell(cells, "MAAS MAC", "OS MAC", "NB MAC", "Parsed MAC")
                )
            else:
                mac = _normalize_mac(_cell(cells, "MAAS MAC", "OS MAC", "Parsed MAC"))

        vid = None
        if _nic_proposed_property_segment_ok(p_vlan):
            vid = _parse_vlan_vid(p_vlan)
        if vid is None and s_vlan:
            vid = _parse_vlan_vid(s_vlan)
        if vid is None and use_vlan_cols:
            if include_nb_fallback:
                vid = _parse_vlan_vid(
                    _cell(cells, "MAAS VLAN", "OS runtime VLAN", "NB VLAN", "Parsed untagged VLAN")
                )
            else:
                vid = _parse_vlan_vid(
                    _cell(cells, "MAAS VLAN", "OS runtime VLAN", "Parsed untagged VLAN")
                )

        ip_blob = ""
        if _nic_proposed_property_segment_ok(p_ips):
            ip_blob = str(p_ips).strip()
        if not ip_blob and _nic_proposed_property_segment_ok(s_ips):
            ip_blob = str(s_ips).strip()
        if not ip_blob and use_ip_cols:
            if include_nb_fallback:
                ip_blob = _cell(cells, "MAAS IPs", "OS runtime IP", "NB IPs", "Parsed IPs")
            else:
                ip_blob = _cell(cells, "MAAS IPs", "OS runtime IP", "Parsed IPs")

    ip_blob = str(ip_blob or "").strip()
    if ip_blob in ("—", "-"):
        ip_blob = ""

    return mac, vid, ip_blob


def _nic_mac_intent_raw(cells: dict[str, str], *, include_nb_fallback: bool) -> str | None:
    """
    Raw MAC string the row is asking to apply (before normalization).

    Used to avoid ``skipped_already_desired`` when the operator clearly set a MAC in
    Proposed Action or MAAS/OS/NB columns but the value is not a valid Ethernet MAC.
    """
    body = _cell_nic_proposed_body(cells)
    p_mac, p_vlan, p_ips = _parse_nic_proposed_properties_segments(body)
    s_mac, s_vlan, s_ips = _parse_set_netbox_interface_directives(body)
    use_mac_cols, _, _ = _nic_use_inventory_column_fallbacks(
        body, p_mac, p_vlan, p_ips, s_mac, s_vlan, s_ips
    )
    set_nb = bool(re.search(r"\bSET_NETBOX_", body, re.IGNORECASE))
    if set_nb:
        if _nic_proposed_property_segment_ok(s_mac):
            return str(s_mac).strip()
        if not use_mac_cols:
            return None
    else:
        if _nic_proposed_property_segment_ok(p_mac):
            return str(p_mac).strip()
        if _nic_proposed_property_segment_ok(s_mac):
            return str(s_mac).strip()
        if not use_mac_cols:
            return None
    cols = (
        _cell(cells, "MAAS MAC", "OS MAC", "NB MAC", "Parsed MAC")
        if include_nb_fallback
        else _cell(cells, "MAAS MAC", "OS MAC", "Parsed MAC")
    )
    return str(cols).strip() if _nic_proposed_property_segment_ok(cols) else None


def _nic_ip_blob_parse_stats(ip_blob: str) -> tuple[bool, bool]:
    """
    Whether the blob had IP tokens and whether at least one token is a valid NetBox address.

    No database access (safe before creating an interface row).
    """
    tokens = _split_ip_candidates(ip_blob)
    if not tokens:
        return False, False
    ok = False
    for raw in tokens:
        try:
            _normalize_ip_for_netbox(raw.split()[0])
            ok = True
        except Exception:
            continue
    return True, ok


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


def _interface_scrub_audit_description_stepwise(iface: Any) -> bool:
    """Like _scrub_interface_drift_audit_description but snapshot/save so branching shows description delta."""
    if not hasattr(iface, "description"):
        return False
    if not _interface_description_is_drift_audit_dump(getattr(iface, "description", None)):
        return False
    _netbox_changelog_snapshot(iface)
    iface.description = None
    iface.save()
    return True


def _interface_description_max_len() -> int:
    try:
        from dcim.models import Interface

        f = Interface._meta.get_field("description")
        ml = getattr(f, "max_length", None)
        return int(ml) if ml else 200
    except Exception:
        return 200


def _interface_description_from_cells(cells: dict[str, str]) -> str:
    return (
        _cell(
            cells,
            "Description",
            "NB proposed description",
            "NB intf description",
            "Interface description",
        )
        or ""
    ).strip()


def _interface_refresh_safe(iface: Any) -> None:
    try:
        iface.refresh_from_db()
    except Exception:
        logger.debug(
            "interface refresh_from_db failed (pk=%s)",
            getattr(iface, "pk", None),
            exc_info=True,
        )


def _interface_apply_physical_fields_batched(
    iface: Any,
    *,
    mac: str,
    untagged: Any,
    type_slug: Any,
    description: str = "",
) -> bool:
    """
    One ``snapshot()`` + one ``save()`` for MAC, untagged VLAN, type, and description.

    Several netbox-branching Diff UIs collapse multiple Interface saves that occur in the
    same database transaction into a single row, often showing only the last mutation (e.g.
    tags). Batching scalar fields yields one ObjectChange that includes every changed core
    field, aligned with recon apply lines (MAC / VLAN / type / description).
    """
    _interface_refresh_safe(iface)
    _netbox_changelog_snapshot(iface)
    changed = False
    if mac and str(iface.mac_address or "").upper() != mac.upper():
        iface.mac_address = mac
        changed = True
    if untagged is not None and iface.untagged_vlan_id != untagged.pk:
        iface.untagged_vlan = untagged
        changed = True
    if type_slug is not None and getattr(iface, "type", None) != type_slug:
        iface.type = type_slug
        changed = True
    ds = (description or "").strip()
    if ds and hasattr(iface, "description"):
        ml = _interface_description_max_len()
        if len(ds) > ml:
            ds = ds[: max(ml - 3, 0)] + "..."
        cur = (getattr(iface, "description", None) or "").strip()
        if cur != ds:
            iface.description = ds
            changed = True
    if changed:
        iface.save()
    return changed


def _interface_apply_physical_fields_stepwise(
    iface: Any,
    *,
    mac: str,
    untagged: Any,
    type_slug: Any,
    description: str = "",
) -> bool:
    """
    One ``snapshot()`` + ``save()`` per changed attribute (MAC, untagged VLAN, type,
    description). netbox-branching Diff / ObjectChange views often collapse or under-report
    when several mutations hit the same object in one transaction; stepwise updates match
    :func:`_device_apply_row_stepwise_changelog` so interface **updates** appear alongside
    device creates in the branch UI.
    """
    _interface_refresh_safe(iface)
    any_save = False
    m = (mac or "").strip()
    if m and str(iface.mac_address or "").upper() != m.upper():
        _netbox_changelog_snapshot(iface)
        iface.mac_address = mac
        iface.save()
        any_save = True
        _interface_refresh_safe(iface)
    if untagged is not None and iface.untagged_vlan_id != untagged.pk:
        _netbox_changelog_snapshot(iface)
        iface.untagged_vlan = untagged
        iface.save()
        any_save = True
        _interface_refresh_safe(iface)
    if type_slug is not None and getattr(iface, "type", None) != type_slug:
        _netbox_changelog_snapshot(iface)
        iface.type = type_slug
        iface.save()
        any_save = True
        _interface_refresh_safe(iface)
    ds = (description or "").strip()
    if ds and hasattr(iface, "description"):
        ml = _interface_description_max_len()
        if len(ds) > ml:
            ds = ds[: max(ml - 3, 0)] + "..."
        cur = (getattr(iface, "description", None) or "").strip()
        if cur != ds:
            _netbox_changelog_snapshot(iface)
            iface.description = ds
            iface.save()
            any_save = True
    return any_save


def _interface_apply_role_tag_changelog(iface: Any, role_label: str | None) -> bool:
    """``snapshot()`` before M2M tag add, then ``save()`` so branch Diff records tag deltas."""
    rl = str(role_label or "").strip()
    if not rl or not hasattr(iface, "tags"):
        return False
    _interface_refresh_safe(iface)
    _netbox_changelog_snapshot(iface)
    if not _merge_interface_role_tag(iface, rl):
        return False
    iface.save()
    return True


def _merge_audit_residual_onto_object(
    obj: Any,
    cells: dict[str, str],
    consumed_lower: set[str],
    *,
    attr_names: tuple[str, ...] = ("description",),
    max_len: int = 8000,
) -> bool:
    """Intentionally disabled: reconciliation does not append free-text drift row dumps to NetBox."""
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


def _prefix_apply_row_stepwise_changelog(
    prefix_obj: Any,
    *,
    vrf: Any,
    status_name: str,
    role: Any,
    tenant: Any,
    scope_obj: Any,
    vlan_obj: Any,
    full_descr: str,
    cells: dict[str, str],
) -> bool:
    """
    Apply prefix row fields with one save per changed attribute so netbox-branching diffs
    list vrf/status/role/tenant/scope/vlan/description (not only the first delta).
    """
    from ipam.models import Prefix

    if not isinstance(prefix_obj, Prefix):
        return False
    any_save = False
    if vrf is not None and getattr(prefix_obj, "vrf_id", None) != vrf.pk:
        _netbox_changelog_snapshot(prefix_obj)
        prefix_obj.vrf = vrf
        prefix_obj.save()
        any_save = True
    if status_name:
        val = _pick_choice_value(prefix_obj._meta.get_field("status"), status_name)
        if val is not None and prefix_obj.status != val:
            _netbox_changelog_snapshot(prefix_obj)
            prefix_obj.status = val
            prefix_obj.save()
            any_save = True
    if role is not None and getattr(prefix_obj, "role_id", None) != role.pk:
        _netbox_changelog_snapshot(prefix_obj)
        prefix_obj.role = role
        prefix_obj.save()
        any_save = True
    if tenant is not None and hasattr(prefix_obj, "tenant_id"):
        if prefix_obj.tenant_id != tenant.pk:
            _netbox_changelog_snapshot(prefix_obj)
            prefix_obj.tenant = tenant
            prefix_obj.save()
            any_save = True
    if scope_obj is not None and hasattr(prefix_obj, "scope"):
        cur = getattr(prefix_obj, "scope", None)
        if cur is None or getattr(cur, "pk", None) != scope_obj.pk:
            _netbox_changelog_snapshot(prefix_obj)
            prefix_obj.scope = scope_obj
            prefix_obj.save()
            any_save = True
    if vlan_obj is not None and hasattr(prefix_obj, "vlan_id"):
        if prefix_obj.vlan_id != vlan_obj.pk:
            _netbox_changelog_snapshot(prefix_obj)
            prefix_obj.vlan = vlan_obj
            prefix_obj.save()
            any_save = True
    if hasattr(prefix_obj, "description"):
        want = (full_descr or "").strip()
        if (prefix_obj.description or "").strip() != want:
            _netbox_changelog_snapshot(prefix_obj)
            prefix_obj.description = full_descr
            prefix_obj.save()
            any_save = True
    cf_ch, _ = _merge_prefix_row_into_custom_fields(prefix_obj, cells)
    if cf_ch:
        _netbox_changelog_snapshot(prefix_obj)
        prefix_obj.save()
        any_save = True
    return any_save


def _device_apply_row_stepwise_changelog(
    dev: Any,
    *,
    site: Any,
    location: Any,
    role: Any,
    dtype: Any,
    status_name: str,
    serial: str,
    platform_obj: Any,
    tag_cell: str,
    cells: dict[str, str],
    placement: bool,
) -> bool:
    """
    One netbox-branching save per changed device attribute (placement FKs, status, serial,
    platform, tags, custom fields) so the branch diff lists each column, not only the first.
    """
    from dcim.models import Device

    if not isinstance(dev, Device):
        return False
    any_save = False
    if placement:
        if site is not None and dev.site_id != site.pk:
            _netbox_changelog_snapshot(dev)
            dev.site = site
            dev.save()
            any_save = True
        if location is not None and getattr(dev, "location_id", None) != location.pk:
            _netbox_changelog_snapshot(dev)
            dev.location = location
            dev.save()
            any_save = True
        if role is not None and dev.role_id != role.pk:
            _netbox_changelog_snapshot(dev)
            dev.role = role
            dev.save()
            any_save = True
        if dtype is not None and dev.device_type_id != dtype.pk:
            _netbox_changelog_snapshot(dev)
            dev.device_type = dtype
            dev.save()
            any_save = True
    if status_name:
        val = _pick_choice_value(dev._meta.get_field("status"), status_name)
        if val is not None and dev.status != val:
            _netbox_changelog_snapshot(dev)
            dev.status = val
            dev.save()
            any_save = True
    sn = (serial or "").strip()
    if sn and hasattr(dev, "serial") and (dev.serial or "") != sn[:50]:
        _netbox_changelog_snapshot(dev)
        dev.serial = sn[:50]
        dev.save()
        any_save = True
    if platform_obj is not None and hasattr(dev, "platform_id"):
        if getattr(dev, "platform_id", None) != platform_obj.pk:
            _netbox_changelog_snapshot(dev)
            dev.platform = platform_obj
            dev.save()
            any_save = True
    if tag_cell and _merge_device_tags(dev, tag_cell):
        _netbox_changelog_snapshot(dev)
        dev.save()
        any_save = True
    cf_changed, _ = _merge_new_device_row_into_custom_fields(dev, cells)
    if cf_changed:
        _netbox_changelog_snapshot(dev)
        dev.save()
        any_save = True
    return any_save


def apply_create_vlan(op: dict[str, Any]) -> tuple[str, str]:
    from ipam.models import VLAN, VLANGroup

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason

    group_name = _cell(cells, "NB proposed VLAN group").strip()
    vid_raw = _cell(cells, "NB Proposed VLAN ID", "Target VID").strip()
    if not vid_raw.isdigit():
        return _skip_missing_prereq("NB Proposed VLAN ID missing or not an integer (1–4094).")
    vid_i = int(vid_raw)
    if vid_i < 1 or vid_i > _NETBOX_IEEE_VLAN_VID_MAX:
        return _skip_missing_prereq(
            f"NB Proposed VLAN ID {vid_i} is outside IEEE 802.1Q 1–{_NETBOX_IEEE_VLAN_VID_MAX}."
        )
    if not group_name or group_name in {"—", "-"}:
        return _skip_missing_prereq(
            "NB proposed VLAN group is empty — pick a VLAN group scoped to the site/location for this VID."
        )

    grp = VLANGroup.objects.filter(name__iexact=group_name).first()
    if grp is None:
        return _skip_missing_prereq(f'VLAN group "{group_name}" not found in NetBox.')

    gfk = "group" if any(f.name == "group" for f in VLAN._meta.fields) else "vlan_group"
    existing = VLAN.objects.filter(**{gfk: grp, "vid": vid_i}).first()
    if existing is not None:
        return "skipped", "skipped_already_desired"

    name = _cell(
        cells, "NB proposed VLAN name (editable)", "NB proposed VLAN name"
    ).strip()
    if not name or name in {"—", "-"}:
        name = f"VLAN-{vid_i}"

    tenant_name = _cell(cells, "NB Proposed Tenant")
    status_name = (_cell(cells, "NB proposed status") or "").strip() or "active"

    tenant = None
    if tenant_name and tenant_name not in {"—", "-"}:
        tenant = _resolve_tenant(tenant_name)
        if tenant is None:
            return _skip_missing_prereq(
                f'Tenant "{tenant_name}" not resolved — fix NB Proposed Tenant or create the tenant.'
            )

    vlan = VLAN(vid=vid_i, name=name)
    setattr(vlan, gfk, grp)
    st_f = vlan._meta.get_field("status")
    st_val = _pick_choice_value(st_f, status_name)
    if st_val is not None:
        vlan.status = st_val
    if tenant is not None and hasattr(vlan, "tenant_id"):
        vlan.tenant = tenant

    try:
        vlan.save()
    except Exception:
        logger.debug("apply_create_vlan: save failed (vid=%s group=%s)", vid_i, group_name, exc_info=True)
        return "failed", "failed_validation_save"
    return "created", "ok_created"


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
        return _skip_missing_prereq("Prefix/CIDR empty in row projection (expected from drift NB/OS prefix columns).")
    vrf = _resolve_by_name(VRF, vrf_name) if vrf_name else None
    if vrf_name and vrf is None:
        return _skip_missing_prereq(f'VRF "{vrf_name}" not found in NetBox (create it or fix NB proposed VRF).')
    role = _resolve_by_name(Role, role_name) if role_name else None
    if role_name and role is None:
        return _skip_missing_prereq(f'IPAM role "{role_name}" not found in NetBox (create it or fix NB proposed role).')
    tenant = None
    if tenant_name and tenant_name not in {"—", "-"}:
        try:
            from tenancy.models import Tenant

            tenant = _resolve_tenant(tenant_name)
        except Exception:
            tenant = None
        if tenant is None:
            return _skip_missing_prereq(f'Tenant "{tenant_name}" not found in NetBox (create it or fix NB Proposed Tenant).')
    scope_obj = None
    if scope_name and scope_name not in {"—", "-"}:
        try:
            from dcim.models import Location

            scope_obj = _resolve_by_name(Location, scope_name)
        except Exception:
            scope_obj = None
        if scope_obj is None:
            return _skip_missing_prereq(
                f'Prefix scope location "{scope_name}" not found in NetBox (Location for prefix scope).'
            )
    vlan_obj = None
    if vlan_name and vlan_name not in {"—", "-"}:
        try:
            vlan_obj = _resolve_vlan_for_prefix_scope(vlan_name, scope_obj)
        except Exception:
            vlan_obj = None
        if vlan_obj is None:
            return _skip_missing_prereq(
                f'VLAN "{vlan_name}" not resolved for this prefix scope '
                f'(create/link VLAN under site/location or fix name/VID in drift).'
            )
    prefix_pk_raw = _cell(cells, "NetBox prefix ID")
    existing = None
    if prefix_pk_raw and str(prefix_pk_raw).strip().isdigit():
        existing = Prefix.objects.filter(pk=int(str(prefix_pk_raw).strip())).first()
    if existing is None:
        existing = Prefix.objects.filter(prefix=cidr, vrf=vrf).first()
    if existing is not None:
        if _prefix_apply_row_stepwise_changelog(
            existing,
            vrf=vrf,
            status_name=status_name,
            role=role,
            tenant=tenant,
            scope_obj=scope_obj,
            vlan_obj=vlan_obj,
            full_descr=full_descr,
            cells=cells,
        ):
            return "updated", "ok_updated"
        return "skipped", "skipped_already_desired"
    obj = Prefix(prefix=cidr, vrf=vrf)
    try:
        obj.save()
    except Exception:
        logger.debug(
            "Prefix two-phase create: initial minimal save failed; retry minimal then stepwise or single save (prefix=%s)",
            cidr,
            exc_info=True,
        )
        pfx = Prefix(prefix=cidr, vrf=vrf)
        try:
            pfx.save()
        except Exception:
            logger.debug(
                "Prefix minimal save failed again; single create with all fields (prefix=%s)",
                cidr,
                exc_info=True,
            )
            pfx = Prefix(prefix=cidr, vrf=vrf)
            if status_name:
                val = _pick_choice_value(pfx._meta.get_field("status"), status_name)
                if val is not None:
                    pfx.status = val
            if role is not None:
                pfx.role = role
            if tenant is not None and hasattr(pfx, "tenant"):
                pfx.tenant = tenant
            if scope_obj is not None and hasattr(pfx, "scope"):
                pfx.scope = scope_obj
            if vlan_obj is not None and hasattr(pfx, "vlan"):
                pfx.vlan = vlan_obj
            if hasattr(pfx, "description"):
                pfx.description = full_descr
            _merge_prefix_row_into_custom_fields(pfx, cells)
            pfx.save()
            return "created", "ok_created"
        _prefix_apply_row_stepwise_changelog(
            pfx,
            vrf=None,
            status_name=status_name,
            role=role,
            tenant=tenant,
            scope_obj=scope_obj,
            vlan_obj=vlan_obj,
            full_descr=full_descr,
            cells=cells,
        )
        return "created", "ok_created"

    _prefix_apply_row_stepwise_changelog(
        obj,
        vrf=None,
        status_name=status_name,
        role=role,
        tenant=tenant,
        scope_obj=scope_obj,
        vlan_obj=vlan_obj,
        full_descr=full_descr,
        cells=cells,
    )
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
        return _skip_missing_prereq("IP range start/end address empty in row projection.")
    vrf = _resolve_by_name(VRF, vrf_name) if vrf_name else None
    if vrf_name and vrf is None:
        return _skip_missing_prereq(f'VRF "{vrf_name}" not found in NetBox (NB proposed VRF).')
    role = _resolve_by_name(Role, role_name) if role_name else None
    if role_name and role is None:
        return _skip_missing_prereq(f'IPAM role "{role_name}" not found in NetBox (NB proposed role).')
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
    try:
        obj.save()
    except Exception:
        logger.debug(
            "IPRange two-phase create: initial minimal save failed; retry minimal then field saves or single save (%s–%s)",
            start_addr,
            end_addr,
            exc_info=True,
        )
        rng = IPRange(start_address=start_addr, end_address=end_addr, vrf=vrf)
        try:
            rng.save()
        except Exception:
            logger.debug(
                "IPRange minimal save failed again; single create with all fields (%s–%s)",
                start_addr,
                end_addr,
                exc_info=True,
            )
            rng = IPRange(start_address=start_addr, end_address=end_addr, vrf=vrf)
            if status_name:
                val = _pick_choice_value(rng._meta.get_field("status"), status_name)
                if val is not None:
                    rng.status = val
            if role is not None and hasattr(rng, "role"):
                rng.role = role
            if descr and hasattr(rng, "description"):
                rng.description = descr[:2000]
            rng.save()
            return "created", "ok_created"
        _netbox_changelog_snapshot(rng)
        phase2_fb = False
        if status_name:
            val = _pick_choice_value(rng._meta.get_field("status"), status_name)
            if val is not None:
                rng.status = val
                phase2_fb = True
        if role is not None and hasattr(rng, "role"):
            rng.role = role
            phase2_fb = True
        if descr and hasattr(rng, "description"):
            rng.description = descr[:2000]
            phase2_fb = True
        if _merge_audit_residual_onto_object(rng, cells, consumed, attr_names=("description",), max_len=4000):
            phase2_fb = True
        if phase2_fb:
            rng.save()
        return "created", "ok_created"

    _netbox_changelog_snapshot(obj)
    phase2 = False
    if status_name:
        val = _pick_choice_value(obj._meta.get_field("status"), status_name)
        if val is not None:
            obj.status = val
            phase2 = True
    if role is not None and hasattr(obj, "role"):
        obj.role = role
        phase2 = True
    if descr and hasattr(obj, "description"):
        obj.description = descr[:2000]
        phase2 = True
    if _merge_audit_residual_onto_object(obj, cells, consumed, attr_names=("description",), max_len=4000):
        phase2 = True
    if phase2:
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

# VM custom fields: projection key -> NetBox custom_field keys (single source with preview + apply).
_VM_PROJECTION_CF_KEYS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "nova_compute_host",
        (
            "nova_compute_host",
            "openstack_hypervisor_hostname",
            "hypervisor_hostname",
            "os_hypervisor_host",
        ),
    ),
)
# When projection omits a value, fall back to this drift header (same cells as op).
_VM_CF_DRIFT_FALLBACK: dict[str, str] = {
    "nova_compute_host": "Hypervisor hostname",
}


@lru_cache(maxsize=1)
def _vm_custom_field_keys_cached() -> frozenset[str]:
    try:
        from extras.models import CustomField
        from virtualization.models import VirtualMachine
    except Exception:
        return frozenset()
    keys: set[str] = set()
    for cf in CustomField.objects.iterator():
        if not _custom_field_targets_model(cf, VirtualMachine):
            continue
        k = getattr(cf, "key", None)
        if k:
            keys.add(str(k))
    return frozenset(keys)


def _merge_vm_row_into_custom_fields(
    vm: Any, cells: dict[str, str], proj: dict[str, str]
) -> tuple[bool, set[str]]:
    """Write VM custom fields from ``proj`` (preferred) with drift fallback; keys from ``_VM_PROJECTION_CF_KEYS``."""
    valid = _vm_custom_field_keys_cached()
    if not valid or not hasattr(vm, "custom_field_data"):
        return False, set()
    data = dict(vm.custom_field_data or {})
    changed = False
    applied_proj_keys: set[str] = set()
    for proj_key, slug_opts in _VM_PROJECTION_CF_KEYS:
        val = (proj.get(proj_key) or "").strip()
        if not _meaningful_cell_val(val):
            fb = _VM_CF_DRIFT_FALLBACK.get(proj_key)
            if fb:
                val = _cell(cells, fb)
        if not _meaningful_cell_val(val):
            continue
        for slug in slug_opts:
            if slug not in valid:
                continue
            if data.get(slug) != val:
                data[slug] = val
                changed = True
            applied_proj_keys.add(proj_key)
            break
    if changed:
        vm.custom_field_data = data
    return changed, applied_proj_keys


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


def _floating_ip_apply_row_stepwise(
    ip_obj: Any,
    *,
    status_name: str,
    role_obj: Any,
    tenant_obj: Any,
    full_descr: str,
    cells: dict[str, str],
    vrf: Any,
) -> bool:
    """One branching save per changed IPAddress field (status, role, tenant, description, NAT, CF)."""
    any_save = False
    if status_name:
        val = _pick_choice_value(ip_obj._meta.get_field("status"), status_name)
        if val is not None and ip_obj.status != val:
            _netbox_changelog_snapshot(ip_obj)
            ip_obj.status = val
            ip_obj.save()
            any_save = True
    if role_obj is not None and hasattr(ip_obj, "role_id") and ip_obj.role_id != role_obj.pk:
        _netbox_changelog_snapshot(ip_obj)
        ip_obj.role = role_obj
        ip_obj.save()
        any_save = True
    if tenant_obj is not None and hasattr(ip_obj, "tenant_id") and ip_obj.tenant_id != tenant_obj.pk:
        _netbox_changelog_snapshot(ip_obj)
        ip_obj.tenant = tenant_obj
        ip_obj.save()
        any_save = True
    if hasattr(ip_obj, "description"):
        cur = (ip_obj.description or "").strip()
        if cur != full_descr.strip():
            _netbox_changelog_snapshot(ip_obj)
            ip_obj.description = full_descr
            ip_obj.save()
            any_save = True
    inside_raw = _cell(
        cells,
        "NAT inside IP (from OpenStack fixed IP)",
        "NAT inside IP",
    )
    inner = _resolve_nat_inside_ipaddress(inside_raw, vrf)
    if inner is not None and getattr(ip_obj, "nat_inside_id", None) != inner.pk:
        _netbox_changelog_snapshot(ip_obj)
        ip_obj.nat_inside = inner
        ip_obj.save()
        any_save = True
    _netbox_changelog_snapshot(ip_obj)
    cf_ch, _ = _merge_ip_address_row_into_custom_fields(ip_obj, cells)
    if cf_ch:
        ip_obj.save()
        any_save = True
    return any_save


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
        return _skip_missing_prereq("Floating IP address empty in row (Floating IP column / projection).")
    try:
        address = _normalize_ip_for_netbox(raw_ip)
    except ValueError:
        return "failed", "failed_validation_bad_ip"
    vrf = _resolve_by_name(VRF, vrf_name) if vrf_name else None
    if vrf_name and vrf is None:
        return _skip_missing_prereq(f'VRF "{vrf_name}" not found in NetBox (NB proposed VRF for floating IP).')
    role_obj = None
    if role_name:
        try:
            from ipam.models import Role

            role_obj = _resolve_by_name(Role, role_name)
        except Exception:
            role_obj = None
        if role_obj is None:
            return _skip_missing_prereq(f'IPAM role "{role_name}" not found in NetBox (NB proposed role).')
    tenant_obj = None
    if tenant_name and tenant_name not in {"—", "-"}:
        try:
            from tenancy.models import Tenant

            tenant_obj = _resolve_tenant(tenant_name)
        except Exception:
            tenant_obj = None
        if tenant_obj is None:
            return _skip_missing_prereq(f'Tenant "{tenant_name}" not found in NetBox (NB Proposed Tenant).')
    existing = IPAddress.objects.filter(address=address, vrf=vrf).first()
    if existing is not None:
        merge_ch = _merge_audit_residual_onto_object(
            existing, cells, consumed, attr_names=("description",), max_len=max(dmax, 8000)
        )
        any_save = _floating_ip_apply_row_stepwise(
            existing,
            status_name=status_name,
            role_obj=role_obj,
            tenant_obj=tenant_obj,
            full_descr=full_descr,
            cells=cells,
            vrf=vrf,
        )
        if any_save or merge_ch:
            return "updated", "ok_updated"
        return "skipped", "skipped_already_desired"
    ip_obj = IPAddress(address=address, vrf=vrf)
    try:
        ip_obj.save()
    except Exception:
        logger.debug(
            "Floating IP two-phase create: initial minimal save failed; retry minimal then stepwise or single save (address=%s)",
            address,
            exc_info=True,
        )
        ip_fb = IPAddress(address=address, vrf=vrf)
        try:
            ip_fb.save()
        except Exception:
            logger.debug(
                "Floating IP minimal save failed again; single create with all fields (address=%s)",
                address,
                exc_info=True,
            )
            ip_fb = IPAddress(address=address, vrf=vrf)
            if status_name:
                val = _pick_choice_value(ip_fb._meta.get_field("status"), status_name)
                if val is not None:
                    ip_fb.status = val
            if role_obj is not None and hasattr(ip_fb, "role"):
                ip_fb.role = role_obj
            if tenant_obj is not None and hasattr(ip_fb, "tenant"):
                ip_fb.tenant = tenant_obj
            if hasattr(ip_fb, "description"):
                ip_fb.description = full_descr
            _apply_fip_nat_inside(ip_fb, cells, vrf)
            _merge_ip_address_row_into_custom_fields(ip_fb, cells)
            ip_fb.save()
            if _merge_audit_residual_onto_object(
                ip_fb, cells, consumed, attr_names=("description",), max_len=max(dmax, 8000)
            ):
                ip_fb.save()
            return "created", "ok_created"
        _floating_ip_apply_row_stepwise(
            ip_fb,
            status_name=status_name,
            role_obj=role_obj,
            tenant_obj=tenant_obj,
            full_descr=full_descr,
            cells=cells,
            vrf=vrf,
        )
        _merge_audit_residual_onto_object(
            ip_fb, cells, consumed, attr_names=("description",), max_len=max(dmax, 8000)
        )
        return "created", "ok_created"

    _floating_ip_apply_row_stepwise(
        ip_obj,
        status_name=status_name,
        role_obj=role_obj,
        tenant_obj=tenant_obj,
        full_descr=full_descr,
        cells=cells,
        vrf=vrf,
    )
    _merge_audit_residual_onto_object(
        ip_obj, cells, consumed, attr_names=("description",), max_len=max(dmax, 8000)
    )
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


def _apply_vm_primary_ip_link(vm, raw: str) -> bool:
    ip_obj = _resolve_ipaddress_for_vm_primary(raw)
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


def _apply_vm_primary_ip_from_cell(vm, cells: dict[str, str]) -> bool:
    pri = _cell(cells, "NB proposed primary IP")
    return _apply_vm_primary_ip_link(vm, pri)


def _apply_vm_primary_ip_from_projection(
    vm, proj: dict[str, str], cells: dict[str, str]
) -> bool:
    """Set primary_ip4/6 from projection; if both empty, fall back to NB proposed primary IP cell."""
    changed = False
    for k in ("primary_ip4", "primary_ip6"):
        raw = (proj.get(k) or "").strip()
        if _meaningful_cell_val(raw) and _apply_vm_primary_ip_link(vm, raw):
            changed = True
    if not any(
        _meaningful_cell_val((proj.get(x) or "").strip()) for x in ("primary_ip4", "primary_ip6")
    ):
        return _apply_vm_primary_ip_from_cell(vm, cells)
    return changed


def _openstack_vm_apply_site_tenant_status_device_stepwise(vm: Any, proj: dict[str, str]) -> None:
    """After VM structural save, apply site/tenant/status/device with one branching delta each."""
    from dcim.models import Device, Site
    from tenancy.models import Tenant

    site_name = (proj.get("site") or "").strip()
    if site_name and site_name not in {"—", "-"}:
        site = _resolve_by_name(Site, site_name)
        if site is not None and hasattr(vm, "site_id") and getattr(vm, "site_id", None) != site.pk:
            _netbox_changelog_snapshot(vm)
            vm.site = site
            vm.save()
    tenant_name = (proj.get("tenant") or "").strip()
    if tenant_name and tenant_name not in {"—", "-"}:
        tenant = _resolve_tenant(tenant_name)
        if tenant is not None and hasattr(vm, "tenant_id") and getattr(vm, "tenant_id", None) != tenant.pk:
            _netbox_changelog_snapshot(vm)
            vm.tenant = tenant
            vm.save()
    status_name = (proj.get("status") or "").strip()
    if status_name and status_name not in {"—", "-"}:
        val = _pick_choice_value(vm._meta.get_field("status"), status_name)
        if val is not None and vm.status != val:
            _netbox_changelog_snapshot(vm)
            vm.status = val
            vm.save()
    device_cell = (proj.get("device") or "").strip()
    if device_cell and device_cell not in {"—", "-"}:
        dev = Device.objects.filter(name=device_cell).first()
        if dev is not None and hasattr(vm, "device_id") and getattr(vm, "device_id", None) != dev.pk:
            _netbox_changelog_snapshot(vm)
            vm.device = dev
            vm.save()


def apply_create_openstack_vm(op: dict[str, Any]) -> tuple[str, str]:
    try:
        from virtualization.models import VirtualMachine, Cluster
    except Exception:
        return "failed", "failed_virtualization_not_available"

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    proj = netbox_write_projection_for_op(op)
    name = (proj.get("name") or "").strip()
    cluster_name = (proj.get("cluster") or "").strip()
    if not name:
        return _skip_missing_prereq("VM name empty in row projection (OS VM name / drift columns).")
    if not cluster_name or cluster_name in {"—", "-"}:
        return _skip_missing_prereq(
            "NB proposed cluster empty in row; OpenStack VM apply requires a NetBox cluster name."
        )
    cluster = Cluster.objects.filter(name=cluster_name).first()
    if cluster is None:
        return _skip_missing_prereq(
            f'Cluster "{cluster_name}" not found in NetBox (Virtualization → Clusters). '
            f"Create the cluster or align NB proposed cluster in drift."
        )
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
    vm.save()
    _openstack_vm_apply_site_tenant_status_device_stepwise(vm, proj)
    _netbox_changelog_snapshot(vm)
    pri_ch = _apply_vm_primary_ip_from_projection(vm, proj, cells)
    if pri_ch:
        vm.save()
    _netbox_changelog_snapshot(vm)
    vm_cf_ch, _ = _merge_vm_row_into_custom_fields(vm, cells, proj)
    if vm_cf_ch:
        vm.save()
    _merge_audit_residual_onto_object(
        vm, cells, consumed, attr_names=("description",), max_len=8000
    )
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
        return _skip_missing_prereq(
            "NetBox VM ID missing or not numeric in row (NetBox VM ID / projection id)."
        )
    vm = VirtualMachine.objects.filter(pk=int(str(pk_raw).strip())).select_related(
        "cluster", "device", "tenant", "primary_ip4", "primary_ip6"
    ).first()
    if vm is None:
        return _skip_missing_prereq(
            f"VirtualMachine id={pk_raw} not found in NetBox (wrong branch, deleted, or stale drift ID)."
        )

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
    try:
        name_f = VirtualMachine._meta.get_field("name")
        nmax = int(getattr(name_f, "max_length", None) or 64)
    except Exception:
        nmax = 64
    name_new = (proj.get("name") or "").strip()
    if name_new and name_new not in {"—", "-"}:
        name_new = name_new[:nmax] if nmax > 0 else name_new
        if vm.name != name_new:
            _netbox_changelog_snapshot(vm)
            vm.name = name_new
            vm.save()
            changed = True
    _netbox_changelog_snapshot(vm)
    if _apply_vm_primary_ip_from_projection(vm, proj, cells):
        vm.save()
        changed = True
    cluster_name = (proj.get("cluster") or "").strip()
    if cluster_name and cluster_name not in {"—", "-"}:
        cl = Cluster.objects.filter(name=cluster_name).first()
        if cl is not None and vm.cluster_id != cl.pk:
            _netbox_changelog_snapshot(vm)
            vm.cluster = cl
            vm.save()
            changed = True
    site_name = (proj.get("site") or "").strip()
    if site_name and site_name not in {"—", "-"} and hasattr(vm, "site_id"):
        site = _resolve_by_name(Site, site_name)
        if site is not None and getattr(vm, "site_id", None) != site.pk:
            _netbox_changelog_snapshot(vm)
            vm.site = site
            vm.save()
            changed = True
    tenant_name = (proj.get("tenant") or "").strip()
    if tenant_name and tenant_name not in {"—", "-"}:
        tenant = _resolve_tenant(tenant_name)
        if tenant is not None and getattr(vm, "tenant_id", None) != tenant.pk:
            _netbox_changelog_snapshot(vm)
            vm.tenant = tenant
            vm.save()
            changed = True
    status_name = (proj.get("status") or "").strip()
    if status_name and status_name not in {"—", "-"}:
        val = _pick_choice_value(vm._meta.get_field("status"), status_name)
        if val is not None and vm.status != val:
            _netbox_changelog_snapshot(vm)
            vm.status = val
            vm.save()
            changed = True
    dev = None
    device_cell = (proj.get("device") or "").strip()
    if device_cell and device_cell not in {"—", "-"}:
        dev = Device.objects.filter(name=device_cell).first()
    if dev is not None and hasattr(vm, "device_id"):
        if getattr(vm, "device_id", None) != dev.pk:
            _netbox_changelog_snapshot(vm)
            vm.device = dev
            vm.save()
            changed = True

    _netbox_changelog_snapshot(vm)
    vm_cf_ch, _ = _merge_vm_row_into_custom_fields(vm, cells, proj)
    if vm_cf_ch:
        vm.save()
        changed = True
    merge_ch = _merge_audit_residual_onto_object(
        vm, cells, consumed, attr_names=("description",), max_len=8000
    )
    if changed or merge_ch:
        return "updated", "ok_updated"
    return "skipped", "skipped_already_desired"


def _cell_is_placeholder(val: str | None) -> bool:
    t = (val or "").strip()
    return not t or t in ("—", "-")


def _cells_indicate_vyos(hostname: str, cells: dict[str, str]) -> bool:
    """True when hostname or common MAAS/OS columns suggest VyOS (router role must be chosen manually)."""
    hn = (hostname or "").strip().lower()
    if "vyos" in hn:
        return True
    blob = " ".join(
        _cell(cells, h)
        for h in (
            "NB proposed platform",
            "OS provision",
            "OS release",
            "MAAS OS",
            "OS",
            "MAAS status",
        )
    ).lower()
    return "vyos" in blob


def _fallback_device_role_for_create(hostname: str, cells: dict[str, str]):
    """
    When ``NB proposed role`` is empty, pick a safe default — except VyOS (operator must set role).
    """
    from dcim.models import DeviceRole

    if _cells_indicate_vyos(hostname, cells):
        return None

    for slug in ("server", "compute", "network-device", "idc", "leaf", "spine"):
        r = DeviceRole.objects.filter(slug=slug).first()
        if r is not None:
            return r
    for nm in ("Server", "Compute", "Network Device"):
        r = DeviceRole.objects.filter(name__iexact=nm).first()
        if r is not None:
            return r
    return DeviceRole.objects.order_by("pk").first()


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
        return _skip_missing_prereq("Device hostname empty (Hostname / Host after scoping).")
    site = _resolve_by_name(Site, site_name) if site_name else None
    role = _resolve_by_name(DeviceRole, role_name) if role_name else None
    dtype = _resolve_device_type(dtype_name) if dtype_name else None
    location = None
    if location_name:
        location = _resolve_by_name(Location, location_name)
        if location is None:
            return _skip_missing_prereq(
                f'Location "{location_name}" not found in NetBox (NB proposed location / NetBox location).'
            )
    existing = Device.objects.filter(name=hostname).first()
    if existing is None:
        if not create_if_missing:
            return _skip_missing_prereq(
                f'Device "{hostname}" does not exist in NetBox. '
                f"Placement-only rows do not create devices; create the device first or include a new-device row."
            )
        role_raw = (role_name or "").strip()
        if _cells_indicate_vyos(hostname, cells):
            if _cell_is_placeholder(role_raw) or "ambiguous" in role_raw.lower():
                return _skip_missing_prereq(
                    "VyOS (vyos in hostname or OS columns): choose a specific NetBox device role "
                    "in NB proposed role on the drift audit (e.g. Edge Router, Cluster Edge Router, "
                    "Router Gateway — whichever your design uses). Save the drift review, "
                    "re-open reconciliation preview so the frozen ops pick it up, then apply again."
                )
        if _cell_is_placeholder(role_name):
            role_fb = _fallback_device_role_for_create(hostname, cells)
            if role_fb is not None:
                role = role_fb
                role_name = (getattr(role_fb, "name", None) or "").strip()
        if not site_name or _cell_is_placeholder(role_name) or _cell_is_placeholder(dtype_name):
            missing_bits = []
            if not site_name or _cell_is_placeholder(site_name):
                missing_bits.append("NB proposed site / NetBox site")
            if _cell_is_placeholder(role_name):
                missing_bits.append("NB proposed role")
            if _cell_is_placeholder(dtype_name):
                missing_bits.append("NB proposed device type")
            return _skip_missing_prereq(
                "Cannot create device; required fields empty in row: " + "; ".join(missing_bits) + "."
            )
        if site is None or role is None or dtype is None:
            bits = []
            if site is None and site_name:
                bits.append(f'site "{site_name}" not in NetBox')
            elif site is None:
                bits.append("site unresolved")
            if role is None and role_name:
                bits.append(f'role "{role_name}" not in NetBox')
            elif role is None:
                bits.append("role unresolved")
            if dtype is None and dtype_name:
                bits.append(f'device type "{dtype_name}" not in NetBox')
            elif dtype is None:
                bits.append("device type unresolved")
            return _skip_missing_prereq(
                f'Cannot create device "{hostname}"; ' + "; ".join(bits) + "."
            )
        # Structural create first, then one save per metadata field so netbox-branching lists each.
        dev = Device(name=hostname, site=site, location=location, role=role, device_type=dtype)
        dev.save()
        _sync_site_region(dev.site, region_name)
        _device_apply_row_stepwise_changelog(
            dev,
            site=None,
            location=None,
            role=None,
            dtype=None,
            status_name=status_name,
            serial=serial or "",
            platform_obj=platform_obj,
            tag_cell=tag_cell or "",
            cells=cells,
            placement=False,
        )
        return "created", "ok_created"
    # Device exists in NetBox but has no role: fill from audit, or non-VyOS fallback; VyOS needs explicit pick.
    if getattr(existing, "role_id", None) in (None, 0):
        rr = (role_name or "").strip()
        if _cells_indicate_vyos(hostname, cells) and (
            _cell_is_placeholder(rr) or "ambiguous" in rr.lower()
        ):
            return _skip_missing_prereq(
                "Device exists in NetBox without a device role; for VyOS pick NB proposed role "
                "on the drift audit (e.g. Edge Router), save review, re-run reconciliation, then apply."
            )
        if role is None:
            role_fb = _fallback_device_role_for_create(hostname, cells)
            if role_fb is not None:
                role = role_fb
    any_dev = _device_apply_row_stepwise_changelog(
        existing,
        site=site,
        location=location,
        role=role,
        dtype=dtype,
        status_name=status_name,
        serial=serial or "",
        platform_obj=platform_obj,
        tag_cell=tag_cell or "",
        cells=cells,
        placement=True,
    )
    target_site = site if site is not None else existing.site
    _, site_saved = _sync_site_region(target_site, region_name)
    if any_dev or site_saved:
        return "updated", "ok_updated"
    return "skipped", "skipped_already_desired"


# Reconciliation preview must not proceed until these NetBox write-projection keys are filled
# (aligned with apply prerequisites / NetBox required semantics for each section).
_MANDATORY_NETBOX_PREVIEW_FIELDS: dict[str, tuple[str, ...]] = {
    "detail_placement_lifecycle_alignment": ("name", "site", "status"),
    "detail_new_devices": ("name", "site", "role", "device_type"),
    "detail_review_only_devices": ("name", "site", "role", "device_type"),
    "detail_proposed_missing_vlans": ("vid", "vlan_group"),
    "detail_new_prefixes": ("prefix", "status"),
    "detail_existing_prefixes": ("prefix", "status"),
    "detail_new_ip_ranges": ("start_address", "end_address", "status"),
    "detail_new_fips": ("address", "status"),
    "detail_existing_fips": ("address", "status"),
    "detail_new_vms": ("name", "cluster"),
    "detail_existing_vms": ("id", "name"),
    "detail_nic_drift_os": ("device", "name"),
    "detail_nic_drift_maas": ("device", "name"),
    "detail_bmc_new_devices": ("device", "name", "IPAddress.address"),
    "detail_bmc_existing": ("device", "name", "IPAddress.address"),
    "detail_serial_review": ("name", "serial"),
}

_PREVIEW_FIELD_LABELS: dict[str, str] = {
    "name": "Name",
    "id": "NetBox VM ID",
    "site": "Site",
    "site.region": "Site region",
    "location": "Location",
    "role": "Role (NB proposed role)",
    "device_type": "Device type",
    "status": "Status",
    "serial": "Serial number",
    "prefix": "Prefix (CIDR)",
    "vrf": "VRF",
    "tenant": "Tenant",
    "cluster": "Cluster",
    "device": "Device (host)",
    "type": "Interface type",
    "mac_address": "MAC address",
    "untagged_vlan": "Untagged VLAN",
    "description": "Description",
    "tags": "Tags / labels",
    "IPAddress.address": "IP address",
    "start_address": "Start address",
    "end_address": "End address",
    "address": "Address",
    "vid": "VLAN ID",
    "vlan_group": "VLAN group",
    "nat_inside": "NAT inside IP",
}


def _mandatory_netbox_projection_keys(selection_key: str) -> tuple[str, ...]:
    sk = str(selection_key or "").strip()
    if sk in NEW_NIC_SELECTION_KEYS:
        return ("device", "name")
    return _MANDATORY_NETBOX_PREVIEW_FIELDS.get(sk, ())


def _preview_scalar_invalid(field_key: str, raw: str | None) -> bool:
    s = "" if raw is None else str(raw).strip()
    if _cell_is_placeholder(s):
        return True
    lk = str(field_key or "").lower()
    if lk == "role" and "ambiguous" in s.lower():
        return True
    if field_key == "vid":
        if not s.isdigit():
            return True
        v = int(s)
        return v < 1 or v > _NETBOX_IEEE_VLAN_VID_MAX
    if field_key == "id":
        return not s.isdigit()
    return False


def _nic_drift_interface_name_ok(cells: dict[str, str], proj: dict[str, str]) -> bool:
    pn = (proj.get("name") or "").strip()
    if not _cell_is_placeholder(pn):
        return True
    return not _cell_is_placeholder(_cell(cells, "MAAS intf"))


def _compact_preview_row_hint(summary: str) -> str:
    """Short label for grouping errors (strip common drift summary prefixes)."""
    s = (summary or "").strip()
    if not s:
        return "—"
    low = s.lower()
    for prefix in ("device row:", "device:", "vm row:", "row:"):
        if low.startswith(prefix):
            rest = s.split(":", 1)[1].strip()
            return rest or "—"
    return s


def validate_preview_mandatory_audit_fields(frozen: list[dict[str, Any]]) -> None:
    """
    Block reconciliation preview until NetBox-oriented audit columns required for apply
    are filled (empty, em-dash, or invalid VID / ambiguous role count as missing).

    Raises ValueError: short copy, grouped by table then field, rows listed once per group.
    """
    from collections import defaultdict

    from netbox_automation_plugin.sync.reconciliation.service import RECON_SECTION_TITLES

    # table -> field label -> row hints (order preserved, deduped when formatting)
    by_table_field: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    nic_name_fields: set[tuple[str, str]] = set()

    for op in frozen:
        if not isinstance(op, dict):
            continue
        sk = str(op.get("selection_key") or "").strip()
        keys = _mandatory_netbox_projection_keys(sk)
        if not keys:
            continue
        raw_cells = op.get("cells")
        if not isinstance(raw_cells, dict):
            raw_cells = {}
        cells: dict[str, str] = {
            str(k): "" if v is None else str(v) for k, v in raw_cells.items()
        }
        proj = netbox_write_projection_for_op(op)
        table_title = RECON_SECTION_TITLES.get(sk, sk)
        row_hint = _compact_preview_row_hint(str(op.get("summary") or ""))
        for field_key in keys:
            if field_key == "name" and sk in ("detail_nic_drift_os", "detail_nic_drift_maas"):
                if _nic_drift_interface_name_ok(cells, proj):
                    continue
                label = _PREVIEW_FIELD_LABELS.get("name", "Name")
                by_table_field[table_title][label].append(row_hint)
                nic_name_fields.add((table_title, label))
                continue
            val = proj.get(field_key)
            if not _preview_scalar_invalid(field_key, val if val is None else str(val)):
                continue
            label = _PREVIEW_FIELD_LABELS.get(
                field_key, str(field_key).replace("_", " ").title()
            )
            by_table_field[table_title][label].append(row_hint)

    if not by_table_field:
        return

    lines: list[str] = [
        "Fill the missing audit fields, save the review, then continue.",
        "",
    ]
    for table in sorted(by_table_field.keys(), key=lambda t: t.lower()):
        lines.append(table)
        field_map = by_table_field[table]
        for field_label in sorted(field_map.keys(), key=lambda f: f.lower()):
            uniq = list(dict.fromkeys(field_map[field_label]))
            lines.append(f"  • {field_label}: {', '.join(uniq)}")
        lines.append("")

    while lines and lines[-1] == "":
        lines.pop()

    if nic_name_fields:
        lines.extend(["", "NIC drift: set NB intf or MAAS intf where name is missing."])

    raise ValueError("\n".join(lines))


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
        return _skip_missing_prereq("Placement row missing Host / Hostname.")
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
        return _skip_missing_prereq("Serial review row missing device name (Host / Hostname / projection).")
    dev = Device.objects.filter(name=host).first()
    if not dev:
        return _skip_missing_prereq(f'Device "{host}" not found in NetBox.')
    if not serial:
        return _skip_missing_prereq(
            f'Proposed serial empty for device "{host}" (MAAS Serial / NetBox Serial / Serial Number).'
        )
    _netbox_changelog_snapshot(dev)
    changed = (dev.serial or "") != serial[:50]
    if changed:
        dev.serial = serial[:50]
    merge_ch = _merge_audit_residual_onto_object(
        dev, cells, consumed_sr, attr_names=("description",), max_len=8000
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
    """
    Resolve a VLAN instance for ``device`` + numeric VID.

    NetBox often scopes VLANs via VLAN groups (location/site/region) without setting
    ``VLAN.site``. Matching only ``site_id`` + ``vid`` misses those rows, so apply would
    skip the untagged VLAN while still reporting ``skipped_already_desired``.
    """
    from django.contrib.contenttypes.models import ContentType
    from ipam.models import VLAN

    if device is None or vid is None:
        return None
    try:
        vid_i = int(vid)
    except (TypeError, ValueError):
        return None

    if device.site_id:
        hit = VLAN.objects.filter(site_id=device.site_id, vid=vid_i).first()
        if hit is not None:
            return hit
        site = getattr(device, "site", None)
        if site is not None:
            try:
                site_qs = VLAN.objects.get_for_site(site)
                hit = site_qs.filter(vid=vid_i).first()
                if hit is not None:
                    return hit
            except Exception:
                pass

    loc = getattr(device, "location", None)
    if loc is not None:
        try:
            ct_loc = ContentType.objects.get_by_natural_key("dcim", "location")
            anc_ids = list(loc.get_ancestors(include_self=True).values_list("id", flat=True))
            hit = VLAN.objects.filter(
                group__scope_type=ct_loc,
                group__scope_id__in=anc_ids,
                vid=vid_i,
            ).first()
            if hit is not None:
                return hit
        except Exception:
            pass
        if getattr(loc, "site_id", None):
            hit = VLAN.objects.filter(site_id=loc.site_id, vid=vid_i).first()
            if hit is not None:
                return hit
            try:
                from dcim.models import Site

                s = Site.objects.filter(pk=loc.site_id).first()
                if s is not None:
                    site_qs = VLAN.objects.get_for_site(s)
                    hit = site_qs.filter(vid=vid_i).first()
                    if hit is not None:
                        return hit
            except Exception:
                pass

    dup = list(VLAN.objects.filter(vid=vid_i)[:2])
    if len(dup) == 1:
        return dup[0]
    if len(dup) > 1 and device.site_id:
        hit = VLAN.objects.filter(vid=vid_i, site_id=device.site_id).first()
        if hit is not None:
            return hit
    return None


def _reuse_iface_untagged_vlan_if_vid_matches(iface: Any, vid: int) -> Any | None:
    """When resolution fails, still accept the interface's current untagged VLAN if its VID matches."""
    from ipam.models import VLAN

    uid = getattr(iface, "untagged_vlan_id", None)
    if not uid:
        return None
    cur = VLAN.objects.filter(pk=uid).first()
    if cur is None or getattr(cur, "vid", None) != vid:
        return None
    return cur


def _resolve_untagged_vlan_for_apply(device: Any, iface: Any | None, vid: int | None) -> Any | None:
    """
    Resolve VLAN for interface apply. Returns None when no VID requested (including MAAS
    native where ``vlan.vid`` is 0—handled upstream by :func:`_parse_vlan_vid`).
    Raises skip tuple via caller when VID requested but cannot be applied.
    """
    if vid is None:
        return None
    try:
        vid_i = int(vid)
    except (TypeError, ValueError):
        return None
    u = _resolve_vlan_for_device(device, vid_i)
    if u is None and iface is not None:
        u = _reuse_iface_untagged_vlan_if_vid_matches(iface, vid_i)
    return u


def _skip_untagged_vlan_unresolved(
    host: str, vid: int, *, iface_name: str = ""
) -> tuple[str, str, str]:
    """
    Apply sets ``Interface.untagged_vlan`` (native/access VLAN on the port), not a field on
    Device. Resolution walks the device's site/location to pick a unique ``ipam.VLAN`` row.
    """
    ifn = (iface_name or "").strip()
    loc = f'interface "{ifn}" on device "{host}"' if ifn else f'device "{host}" (interface)'
    return _skip_missing_prereq(
        f"Cannot apply untagged VLAN VID {vid} to {loc}: no IPAM VLAN matches this "
        f"device's site or location (VLAN groups / get_for_site), or VID {vid} is ambiguous. "
        f"NetBox stores native VLAN on the interface; the VLAN object must exist in IPAM and "
        f"be in scope for the device. Create or scope VLAN {vid}, then re-run apply."
    )


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


def _vrf_for_ip_from_row_cells(cells: dict[str, str] | None) -> Any:
    """Resolve optional VRF for IPAddress create/assign from NIC/BMC drift columns."""
    from ipam.models import VRF

    if not cells:
        return None
    raw = str(
        _cell(cells, "NB proposed VRF", "NB proposed vrf", "VRF", "NetBox VRF") or ""
    ).strip()
    if not raw or raw in ("—", "-"):
        return None
    return _resolve_by_name(VRF, raw)


def _assign_ips_to_interface(iface, ip_blob: str, vrf) -> tuple[bool, bool, bool]:
    """
    Apply IP blob to interface.

    Returns ``(changed, row_had_ip_tokens, any_address_parse_ok)``. When the row lists IP
    text but nothing parses, callers must not report ``skipped_already_desired``.
    """
    from ipam.models import IPAddress

    tokens = _split_ip_candidates(ip_blob)
    row_had_ip_tokens = len(tokens) > 0
    changed = False
    any_parse_ok = False
    for raw in tokens:
        try:
            addr = _normalize_ip_for_netbox(raw.split()[0])
        except Exception:
            continue
        any_parse_ok = True
        existing = IPAddress.objects.filter(address=addr, vrf=vrf).first()
        if existing is None:
            # Two-phase: create address+VRF first, then snapshot + assign to interface so branch
            # changelog shows assignment (and VRF on the create row stays visible as its own delta).
            ip_obj = IPAddress(address=addr, vrf=vrf)
            try:
                ip_obj.save()
            except Exception:
                logger.debug(
                    "IPAddress two-phase create: initial minimal save failed; retry minimal then assign or single save (address=%s)",
                    addr,
                    exc_info=True,
                )
                ip_fb = IPAddress(address=addr, vrf=vrf)
                try:
                    ip_fb.save()
                except Exception:
                    logger.debug(
                        "IPAddress minimal save failed again; single create+assign (address=%s)",
                        addr,
                        exc_info=True,
                    )
                    ip_fb2 = IPAddress(address=addr, vrf=vrf)
                    if hasattr(ip_fb2, "assigned_object"):
                        ip_fb2.assigned_object = iface
                    elif hasattr(ip_fb2, "interface"):
                        ip_fb2.interface = iface
                    ip_fb2.save()
                    changed = True
                    continue
                _netbox_changelog_snapshot(ip_fb)
                if hasattr(ip_fb, "assigned_object"):
                    ip_fb.assigned_object = iface
                elif hasattr(ip_fb, "interface"):
                    ip_fb.interface = iface
                ip_fb.save()
                changed = True
                continue
            _netbox_changelog_snapshot(ip_obj)
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
    return changed, row_had_ip_tokens, any_parse_ok


def apply_create_interface(op: dict[str, Any]) -> tuple[str, str]:
    from dcim.models import Device, Interface, Location, Site

    cells = op.get("cells") or {}
    if (reason := skip_reason_from_row_guides(cells)) is not None:
        return "skipped", reason
    host = _cell(cells, "Host")
    if_name = _cell(cells, "Suggested NB name", "MAAS intf")
    mac, vid, ip_blob = _interface_mac_vlan_ip_from_cells(cells, include_nb_fallback=False)
    proposed_body = _cell_nic_proposed_body(cells)
    if (bad_vid := _vlan_vid_over_ieee_max_from_proposed_body(proposed_body)) is not None:
        return _skip_missing_prereq(
            f"VLAN VID {bad_vid} in Proposed Action exceeds NetBox IEEE 802.1Q maximum "
            f"({_NETBOX_IEEE_VLAN_VID_MAX}); it cannot be set as Interface.untagged_vlan. "
            f"Values above {_NETBOX_IEEE_VLAN_VID_MAX} are often VXLAN VNIs or fabric ids—use a "
            f"1–{_NETBOX_IEEE_VLAN_VID_MAX} VLAN in NetBox or adjust the drift source."
        )
    site_hint = _cell(cells, "NB site")
    loc_hint = _cell(cells, "NB location")
    type_slug = _resolve_interface_type_slug(_cell(cells, "NB Proposed intf Type"))
    role_label = _cell(cells, "NB Proposed intf Label")
    if not host or not if_name:
        return _skip_missing_prereq(
            "Missing Host or interface name (Suggested NB name / MAAS intf) for create_interface."
        )
    mac_intent = _nic_mac_intent_raw(cells, include_nb_fallback=False)
    if mac_intent and not mac:
        mac_tail = "…" if len(mac_intent) > 80 else ""
        return _skip_missing_prereq(
            f'Cannot apply MAC for device "{host}" interface "{if_name}": '
            f"value is not a valid Ethernet MAC ({mac_intent[:80]!r}{mac_tail})."
        )
    dev = Device.objects.filter(name=host).first()
    if not dev:
        return _skip_missing_prereq(
            f'Device "{host}" not found in NetBox; create the device before adding interfaces.'
        )
    if site_hint:
        site_obj = _resolve_by_name(Site, site_hint)
        if site_obj and dev.site_id != site_obj.pk:
            _netbox_changelog_snapshot(dev)
            dev.site = site_obj
            dev.save()
    if loc_hint:
        loc_obj = _resolve_by_name(Location, loc_hint)
        if loc_obj and getattr(dev, "location_id", None) != loc_obj.pk:
            _netbox_changelog_snapshot(dev)
            dev.location = loc_obj
            dev.save()
    iface = Interface.objects.filter(device=dev, name=if_name).first()
    untagged = _resolve_untagged_vlan_for_apply(dev, iface, vid)
    if vid is not None and untagged is None:
        try:
            vnum = int(vid)
        except (TypeError, ValueError):
            return _skip_missing_prereq(f"Invalid VLAN id in row for device {host!r}.")
        return _skip_untagged_vlan_unresolved(host, vnum, iface_name=if_name)
    if_desc = _interface_description_from_cells(cells)
    if iface is None and ip_blob:
        ip_tok, ip_parse = _nic_ip_blob_parse_stats(ip_blob)
        if ip_tok and not ip_parse:
            return _skip_missing_prereq(
                f'Cannot apply IP address(es) for device "{host}" interface "{if_name}": '
                f"no valid IP parsed from row (MAAS IPs / OS runtime IP / Proposed Action)."
            )
    if iface is None:
        # Minimal create row, then one batched save for type/MAC/VLAN/description so branch
        # Diff shows all scalar deltas together (multiple saves in one tx often collapse in UI).
        iface = Interface(device=dev, name=if_name, type=_iface_type_default())
        iface.save()
        _interface_apply_physical_fields_batched(
            iface,
            mac=mac or "",
            untagged=untagged,
            type_slug=type_slug,
            description=if_desc,
        )
        _interface_apply_role_tag_changelog(iface, role_label)
        ip_vrf = _vrf_for_ip_from_row_cells(cells)
        if ip_blob:
            _assign_ips_to_interface(iface, ip_blob, ip_vrf)
        return "created", "ok_created"
    changed = _interface_scrub_audit_description_stepwise(iface)
    changed |= _interface_apply_physical_fields_stepwise(
        iface,
        mac=mac or "",
        untagged=untagged,
        type_slug=type_slug,
        description=if_desc,
    )
    if _interface_apply_role_tag_changelog(iface, role_label):
        changed = True
    ip_vrf = _vrf_for_ip_from_row_cells(cells)
    if ip_blob:
        ip_ch, ip_tok, ip_parse = _assign_ips_to_interface(iface, ip_blob, ip_vrf)
        if ip_tok and not ip_parse:
            return _skip_missing_prereq(
                f'Cannot apply IP address(es) for device "{host}" interface "{if_name}": '
                f"no valid IP parsed from row (MAAS IPs / OS runtime IP / Proposed Action)."
            )
        if ip_ch:
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
        return _skip_missing_prereq("NIC drift row missing Host.")
    mac_intent = _nic_mac_intent_raw(cells, include_nb_fallback=True)
    if mac_intent and not mac:
        mac_tail = "…" if len(mac_intent) > 80 else ""
        return _skip_missing_prereq(
            f'Cannot apply MAC for NIC drift row (device "{host}"): '
            f"value is not a valid Ethernet MAC ({mac_intent[:80]!r}{mac_tail})."
        )
    dev = Device.objects.filter(name=host).first()
    if not dev:
        return _skip_missing_prereq(f'Device "{host}" not found in NetBox.')
    iface = None
    if nb_name:
        iface = Interface.objects.filter(device=dev, name=nb_name).first()
    if iface is None and ma_name:
        iface = Interface.objects.filter(device=dev, name=ma_name).first()
    if iface is None:
        return _skip_missing_prereq(
            f'No interface on device "{host}" matching NB intf "{nb_name}" or MAAS intf "{ma_name}".'
        )
    untagged = _resolve_untagged_vlan_for_apply(dev, iface, vid)
    if vid is not None and untagged is None:
        try:
            vnum = int(vid)
        except (TypeError, ValueError):
            return _skip_missing_prereq(f"Invalid VLAN id in row for device {host!r}.")
        return _skip_untagged_vlan_unresolved(host, vnum, iface_name=iface.name or nb_name or ma_name)
    if_desc = _interface_description_from_cells(cells)
    changed = _interface_scrub_audit_description_stepwise(iface)
    changed |= _interface_apply_physical_fields_stepwise(
        iface,
        mac=mac or "",
        untagged=untagged,
        type_slug=type_slug,
        description=if_desc,
    )
    if _interface_apply_role_tag_changelog(iface, role_label):
        changed = True
    ip_vrf = _vrf_for_ip_from_row_cells(cells)
    ip_ch, ip_tok, ip_parse = _assign_ips_to_interface(iface, ip_blob or "", ip_vrf)
    if ip_tok and not ip_parse:
        return _skip_missing_prereq(
            f'Cannot apply IP address(es) for device "{host}" (NIC drift): '
            f"no valid IP parsed from row (MAAS IPs / OS runtime IP / NB IPs / Proposed Action)."
        )
    if ip_ch:
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
        return _skip_missing_prereq(
            "BMC row missing Host or management interface name "
            "(Suggested NB mgmt iface / Suggested NB OOB Port)."
        )
    if not bmc_ip:
        return _skip_missing_prereq(
            "BMC IP empty (MAAS BMC IP / OS BMC IP / NB mgmt iface IP); need an address to assign."
        )
    dev = Device.objects.filter(name=host).first()
    if not dev:
        return _skip_missing_prereq(f'Device "{host}" not found in NetBox.')
    iface = Interface.objects.filter(device=dev, name=if_name).first()
    if iface is None:
        iface = Interface(device=dev, name=if_name, type=_iface_type_default())
        iface.save()
        _interface_apply_physical_fields_batched(
            iface,
            mac=bmc_mac or "",
            untagged=None,
            type_slug=type_slug,
            description="",
        )
        created = True
    else:
        created = False
        _interface_apply_physical_fields_batched(
            iface,
            mac=bmc_mac or "",
            untagged=None,
            type_slug=type_slug,
            description="",
        )
    ip_vrf = _vrf_for_ip_from_row_cells(cells)
    combined_blob = (
        " ".join(x for x in (bmc_ip_maas, bmc_ip_os, bmc_ip_nb) if (x or "").strip())
        or str(bmc_ip).strip()
    )
    try:
        for raw in _split_ip_candidates(combined_blob):
            _normalize_ip_for_netbox(raw.split()[0])
    except Exception:
        return "failed", "failed_validation_bad_ip"
    ip_changed, _, _ = _assign_ips_to_interface(iface, combined_blob, ip_vrf)
    desc_changed = False
    if not created and _scrub_interface_drift_audit_description(iface):
        desc_changed = True
    tag_ch = _interface_apply_role_tag_changelog(iface, role_label)
    if desc_changed:
        _netbox_changelog_snapshot(iface)
        iface.save()
    if ip_changed or desc_changed or created or tag_ch:
        return ("created", "ok_created") if created else ("updated", "ok_updated")
    return "skipped", "skipped_already_desired"


def apply_bmc_documentation(op: dict[str, Any]) -> tuple[str, str]:
    return _bmc_apply(op, existing_oob=False)


def apply_bmc_alignment(op: dict[str, Any]) -> tuple[str, str]:
    return _bmc_apply(op, existing_oob=True)


_APPLY_FUNCS: dict[str, Any] = {
    "create_vlan": apply_create_vlan,
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
            "Parsed MAC",
            "Parsed untagged VLAN",
            "Parsed IPs",
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
    if sk == "detail_proposed_missing_vlans":
        return _header_norms(
            "NB site",
            "NB location",
            "NB Proposed VLAN ID",
            "NB proposed VLAN group",
            "NB proposed VLAN name (editable)",
            "NB Proposed Tenant",
            "NB proposed status",
        )
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


def apply_row_operation(op: dict[str, Any]) -> tuple[str, str, str | None]:
    """
    Returns ``(status, reason, reason_detail)``. Handlers may return a 2-tuple; optional third
    element is human text for skips/failures (e.g. which prerequisite was missing).
    """
    action = str(op.get("action") or "").strip()
    fn = _APPLY_FUNCS.get(action)
    if not fn:
        return "failed", "failed_not_implemented", None
    sk = str(op.get("selection_key") or "").strip()
    op_use = dict(op)
    op_use["cells"] = _cells_scoped_for_apply(sk, op.get("cells"))
    raw = fn(op_use)
    if not isinstance(raw, tuple):
        return "failed", "failed_bad_apply_return", None
    if len(raw) == 2:
        return str(raw[0]), str(raw[1]), None
    if len(raw) == 3:
        det = raw[2]
        if det is None:
            return str(raw[0]), str(raw[1]), None
        ds = str(det).strip()
        return str(raw[0]), str(raw[1]), ds or None
    return "failed", "failed_bad_apply_return", None
