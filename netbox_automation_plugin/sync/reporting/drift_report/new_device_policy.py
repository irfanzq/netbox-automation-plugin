"""New-device candidate policy, fabric column display, proposed NetBox device.status."""

from __future__ import annotations

import re
from typing import Optional

from netbox_automation_plugin.sync.reporting.drift_report.fabric_alignment import (
    _is_generic_maas_fabric_name,
    _split_maas_fabrics,
)
from netbox_automation_plugin.sync.reporting.drift_report.maas_netbox_status import (
    normalize_maas_status,
    proposed_netbox_status_slug_from_maas,
    proposed_netbox_status_slug_from_openstack_runtime,
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
    st = normalize_maas_status(machine.get("status_name") or machine.get("status"))
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


def _proposed_netbox_status_for_new_maas_device(machine: dict) -> str:
    """
    Suggested NetBox device.status when creating a record for a MAAS-only host.

    Uses the same MAAS → NetBox slug map as placement/lifecycle (see
    maas_netbox_status). For transient/unsafe MAAS states we do not propose a status.
    """
    st = normalize_maas_status(machine.get("status_name") or machine.get("status"))
    if not st:
        return "—"
    if st in _MAAS_NEW_DEVICE_UNSAFE_STATUSES:
        return "—"
    return proposed_netbox_status_slug_from_maas(machine.get("status_name") or machine.get("status"))


def proposed_netbox_status_for_new_maas_machine(
    machine: dict, ironic_bmc_row: Optional[dict]
) -> str:
    """
    NetBox device.status for a MAAS-only (new device) row: OpenStack Ironic first when a
    BMC/runtime row exists, else MAAS-only policy (including unsafe-state guard).
    """
    if ironic_bmc_row:
        os_prop = proposed_netbox_status_slug_from_openstack_runtime(
            str(ironic_bmc_row.get("provision_state") or ""),
            ironic_bmc_row.get("maintenance"),
        )
        if os_prop != "—":
            return os_prop
    return _proposed_netbox_status_for_new_maas_device(machine)
