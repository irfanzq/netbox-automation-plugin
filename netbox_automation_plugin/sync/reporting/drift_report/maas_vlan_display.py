"""MAAS VLAN column display for HTML / XLSX / audit (match NetBox ``—`` empty style)."""

from __future__ import annotations

from typing import Any

# Same placeholder as NB VLAN / drift tables (not hyphen-minus).
_DASH = "—"
_PLACE = frozenset({"", "—", "-", "None", "none", "NONE"})


def format_maas_vlan_vid_for_reports(raw: Any) -> str:
    """
    Human MAAS VLAN cell: show a real 802.1Q tag (1–4094) or ``—``.

    * ``vlan.vid`` **0** (MAAS native / untagged) → ``—`` (same idea as “no NB untagged VID”).
    * Empty / placeholders → ``—``.
    * Integer **> 4094** → ``—`` (legacy MAAS ``vlan.id`` or other non-tag).
    * **1–4094** → decimal string (trimmed, no leading zeros normalized by ``int``).
    * Non-numeric text (rare) → stripped string, or ``—`` if placeholder.
    """
    t = str(raw or "").strip()
    if not t or t in _PLACE:
        return _DASH
    try:
        n = int(t, 10)
    except ValueError:
        return t if t not in _PLACE else _DASH
    if n == 0:
        return _DASH
    if n < 1 or n > 4094:
        return _DASH
    return str(n)
