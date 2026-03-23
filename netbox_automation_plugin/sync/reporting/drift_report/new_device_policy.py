"""New-device candidate policy, fabric column display, proposed NetBox device.status."""

import re

from netbox_automation_plugin.sync.reporting.drift_report.fabric_alignment import (
    _is_generic_maas_fabric_name,
    _split_maas_fabrics,
)

def _new_device_fabric_display(maas_fabric_raw, nb_location_raw) -> str:
    """
    For new-device table, only show human fabric names that match NB location.
    Generic fabric-#### values are suppressed.
    """
    loc = (nb_location_raw or "").strip()
    if not loc or loc == "—":
        return "—"
    fabrics = _split_maas_fabrics(maas_fabric_raw)
    if not fabrics:
        return "—"
    non_generic = [f for f in fabrics if not _is_generic_maas_fabric_name(f)]
    if not non_generic:
        return "—"
    loc_l = loc.lower()
    for f in non_generic:
        fl = f.lower()
        if loc_l in fl or fl in loc_l:
            return f
        ftoks = {t for t in re.split(r"[^a-z0-9]+", fl) if t}
        ltoks = {t for t in re.split(r"[^a-z0-9]+", loc_l) if t}
        if any(len(t) >= 4 and t in ftoks for t in ltoks):
            return f
    return "—"


_MAAS_NEW_DEVICE_UNSAFE_STATUSES = {
    "FAILED_COMMISSIONING",
    "COMMISSIONING",
    "TESTING",
    "RESCUE_MODE",
    "EXITING_RESCUE_MODE",
    "RELEASING",
    "DEPLOYING",
    "FAILED",
    "BROKEN",
}


def _norm_maas_status(raw: str) -> str:
    return re.sub(r"[\s\-]+", "_", str(raw or "").strip()).upper()


def _has_usable_maas_fabric(machine: dict) -> bool:
    fab = str(machine.get("fabric_name") or "").strip().lower()
    return bool(fab and fab not in {"-", "unknown", "n/a", "none", "null"})


def _new_device_candidate_policy(
    machine: dict,
    nic_count: int,
    *,
    vendor: str = "",
    product: str = "",
) -> tuple[bool, str, int]:
    """
    Candidate policy for "A) Add to NetBox / Detail — new devices".

    Returns:
      (is_candidate, note, sort_rank)
    Lower sort_rank comes first.
    """
    st = _norm_maas_status(machine.get("status_name") or machine.get("status"))
    has_fabric = _has_usable_maas_fabric(machine)
    has_identity = bool((vendor or "").strip() and (product or "").strip())

    weak_flags = []
    if nic_count == 0:
        weak_flags.append("0 NICs")
    if not has_fabric:
        weak_flags.append("no MAAS fabric")
    if not has_identity:
        weak_flags.append("incomplete identity")
    weak_note = ", ".join(weak_flags)

    if st in _MAAS_NEW_DEVICE_UNSAFE_STATUSES:
        return False, f"MAAS status {st} is transient/unsafe for inventory create", 90
    if st == "DEFAULT" and weak_flags:
        return False, f"MAAS status DEFAULT with weak data ({weak_note})", 91
    if weak_flags:
        return False, f"Weak discovery data ({weak_note})", 92

    rank = {
        "DEPLOYED": 0,
        "ACTIVE": 1,
        "READY": 2,
        "ALLOCATED": 3,
    }.get(st, 10)
    return True, "Candidate", rank


# NetBox DCIM Device.status slugs (same set as dcim.choices.DeviceStatusChoices).
_NETBOX_DEVICE_STATUS_SLUGS = frozenset({
    "offline",
    "active",
    "planned",
    "staged",
    "failed",
    "inventory",
    "decommissioning",
})


def _proposed_netbox_status_for_new_maas_device(machine: dict) -> str:
    """
    Suggested NetBox device.status when creating a record for a MAAS-only host.

    Maps MAAS lifecycle states we treat as safe for add proposals (see
    _new_device_candidate_policy / rank keys) to valid NetBox slugs.
    Deployed and Ready → staged (aligns with “MAAS deployed / NB staged” review pattern).
    """
    st = _norm_maas_status(machine.get("status_name") or machine.get("status"))
    if not st:
        return "—"
    if st in _MAAS_NEW_DEVICE_UNSAFE_STATUSES:
        return "—"
    # Explicit MAAS → NetBox mappings for common candidate statuses.
    proposed = {
        "DEPLOYED": "staged",
        "READY": "staged",
        "ACTIVE": "active",
        "ALLOCATED": "planned",
        "DEFAULT": "inventory",
        "NEW": "inventory",
    }.get(st)
    if proposed is None:
        proposed = "staged"
    if proposed not in _NETBOX_DEVICE_STATUS_SLUGS:
        return "—"
    return proposed
