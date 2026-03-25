"""Placement/lifecycle hint parsing and MAAS fabric selection for alignment rows."""

import re

from netbox_automation_plugin.sync.reporting.drift_report.misc_utils import _dedupe_note_parts

# Substrings of hints from sync/reconciliation/audit_detail.py (placement / lifecycle only).
_ALIGNMENT_HINT_SUBSTRINGS = (
    "MAAS fabric vs NB location",
    "NB location empty — MAAS has fabric",
    "MAAS deployed / NB staged",
    "OS maintenance / NB not maintenance",
    "OS active+instance / NB staged",
    "OS available / NB active",
    "OS clean failed / NB active",
)


def _hint_is_placement_alignment(h: str) -> bool:
    t = (h or "").strip()
    return any(marker in t for marker in _ALIGNMENT_HINT_SUBSTRINGS)


def _is_generic_maas_fabric_name(name: str) -> bool:
    return re.fullmatch(r"(?i)fabric-\d+", (name or "").strip()) is not None


def _split_maas_fabrics(raw) -> list[str]:
    # MAAS fabric values may be a single name or a delimited list.
    txt = str(raw or "").strip()
    if not txt or txt == "—":
        return []
    parts = [p.strip() for p in re.split(r"[;,]", txt) if p.strip()]
    out = []
    seen = set()
    for p in parts:
        k = p.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(p)
    return out


def _select_alignment_fabric(maas_fabric_raw, nb_location_raw) -> str:
    """
    Prefer location-related MAAS fabric names (e.g. spruce-staging) and ignore
    generic fabric-#### labels when meaningful names exist.
    """
    fabrics = _split_maas_fabrics(maas_fabric_raw)
    if not fabrics:
        return "—"
    non_generic = [f for f in fabrics if not _is_generic_maas_fabric_name(f)]
    candidates = non_generic or fabrics
    nb_loc = (nb_location_raw or "").strip().lower()
    if nb_loc:
        for f in candidates:
            fl = f.lower()
            if nb_loc in fl or fl in nb_loc:
                return f
            tokens = [t for t in re.split(r"[-_\s/]+", fl) if t]
            if nb_loc in tokens:
                return f
    return candidates[0]


def _alignment_review_rows(matched_rows):
    """
    Matched hosts with placement/lifecycle hints only (not serial, NIC, or BMC/OOB —
    those have dedicated report tables).
    """
    out = []
    for r in matched_rows or []:
        hints = r.get("hints") or []
        align = [h for h in hints if _hint_is_placement_alignment(h)]
        if not align:
            continue
        joined = _dedupe_note_parts("; ".join(align))
        out.append(
            [
                r.get("hostname") or "",
                _select_alignment_fabric(r.get("maas_fabric"), r.get("netbox_location")),
                r.get("netbox_site") or "—",
                r.get("netbox_location") or "—",
                str(r.get("os_region") or "").strip() or "—",
                "[OS]" if str(r.get("os_authority") or "") == "openstack_runtime" else "[MAAS]",
                r.get("os_provision_state") or "—",
                r.get("os_power_state") or "—",
                r.get("os_maintenance") or "—",
                r.get("maas_status") or "-",
                r.get("netbox_status") or "-",
                joined or "—",
            ]
        )
    return sorted(out, key=lambda row: (row[0] or "").lower())
