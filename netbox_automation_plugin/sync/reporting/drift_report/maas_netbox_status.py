"""
Map MAAS and OpenStack (Ironic) lifecycle signals to NetBox dcim.Device.status slugs.

Used for drift report proposals (placement/lifecycle, new devices). Slugs match
NetBox DeviceStatusChoices (e.g. active, offline, planned).

Alignment rows: OpenStack runtime is preferred when ``os_authority`` is
``openstack_runtime``; otherwise MAAS-only mapping is used
(see ``proposed_netbox_status_for_matched_row``).
"""

from __future__ import annotations

import re

# NetBox 4.x DCIM device.status values (slug form).
_NETBOX_DEVICE_STATUS_SLUGS = frozenset({
    "offline",
    "active",
    "planned",
    "staged",
    "failed",
    "inventory",
    "decommissioning",
})

# MAAS lifecycle → NetBox slug (MAAS side normalized with normalize_maas_status).
_MAAS_TO_NETBOX: dict[str, str] = {
    # Placeholder / unset lifecycle in some MAAS views — treat as “in CMDB but not lifecycle-classified”.
    "DEFAULT": "inventory",
    "DEPLOYED": "active",
    "ACTIVE": "active",
    "READY": "offline",
    "ALLOCATED": "staged",
    "NEW": "planned",
    "COMMISSIONING": "staged",
    "TESTING": "staged",
    "DEPLOYING": "staged",
    "RELEASING": "staged",
    "DISK_ERASING": "staged",
    "REBOOTING": "staged",
    "ALLOCATING": "staged",
    "BROKEN": "failed",
    "FAILED": "failed",
    "FAILED_COMMISSIONING": "failed",
    "FAILED_DEPLOYMENT": "failed",
    "FAILED_DISK_ERASING": "failed",
    "RESCUE_MODE": "staged",
    "ENTERING_RESCUE_MODE": "staged",
    "EXITING_RESCUE_MODE": "staged",
    "MISSING": "offline",
    "RETIRED": "decommissioning",
    "RELEASED": "offline",
}


def normalize_maas_status(raw: str) -> str:
    """MAAS status string → UPPER_WITH_UNDERSCORES for lookup."""
    return re.sub(r"[\s\-]+", "_", str(raw or "").strip()).upper()


def proposed_netbox_status_slug_from_maas(maas_status_display: str) -> str:
    """
    Suggested NetBox device.status slug from MAAS status_name (or equivalent).

    Returns a lowercase slug valid for NetBox, or "—" if unknown / not mappable.
    """
    st = normalize_maas_status(maas_status_display)
    if not st or st in {"-", "—", "UNKNOWN", "NONE", "NULL"}:
        return "—"

    proposed = _MAAS_TO_NETBOX.get(st)
    if proposed is None:
        if st.startswith("FAILED"):
            proposed = "failed"
        elif "RESCUE" in st:
            proposed = "staged"
        else:
            return "—"

    if proposed not in _NETBOX_DEVICE_STATUS_SLUGS:
        return "—"
    return proposed


def normalize_os_provision_state(raw: str) -> str:
    """Ironic/OpenStack provision_state string → lowercase_with_underscores for lookup."""
    return re.sub(r"[\s\-]+", "_", str(raw or "").strip()).lower()


def _os_maintenance_is_true(raw) -> bool:
    return str(raw or "").strip().lower() in ("true", "1", "yes")


# Ironic provision_state (normalized) → NetBox slug.
_OS_PROVISION_TO_NETBOX: dict[str, str] = {
    "active": "active",
    "available": "offline",
    "manageable": "offline",
    "enroll": "planned",
    "enrolling": "staged",
    "adopting": "staged",
    "cleaning": "staged",
    "clean_wait": "staged",
    "deploying": "staged",
    "deploy_wait": "staged",
    "inspecting": "staged",
    "inspect_wait": "staged",
    "decommissioning": "decommissioning",
    "rescuing": "staged",
    "unrescuing": "staged",
    "service": "staged",
    "error": "failed",
    "deploy_failed": "failed",
    "clean_failed": "failed",
}


def proposed_netbox_status_slug_from_openstack_runtime(
    provision_state_display: str,
    maintenance_raw,
) -> str:
    """
    Suggested NetBox device.status from OpenStack runtime BMC / Ironic fields.

    Maintenance forces ``staged`` (node sidelined in Ironic). Unknown provision
    returns ``—`` so callers can fall back to MAAS.
    """
    if _os_maintenance_is_true(maintenance_raw):
        return "staged"

    key = normalize_os_provision_state(provision_state_display)
    if not key or key in ("—", "-", "unknown", "none", "null"):
        return "—"

    proposed = _OS_PROVISION_TO_NETBOX.get(key)
    if proposed is None:
        if "fail" in key:
            proposed = "failed"
        elif key.endswith("_wait") or key.endswith("ing"):
            proposed = "staged"
        else:
            return "—"

    if proposed not in _NETBOX_DEVICE_STATUS_SLUGS:
        return "—"
    return proposed


def proposed_netbox_status_for_matched_row(row: dict) -> str:
    """
    Proposed NetBox device.status for a ``build_maas_netbox_matched_rows`` row.

    When ``os_authority`` is ``openstack_runtime``, use Ironic/runtime mapping first;
    if that yields ``—``, fall back to MAAS. Otherwise MAAS only.
    """
    maas_prop = proposed_netbox_status_slug_from_maas(row.get("maas_status") or "")

    if str(row.get("os_authority") or "").strip() != "openstack_runtime":
        return maas_prop

    os_prop = proposed_netbox_status_slug_from_openstack_runtime(
        str(row.get("os_provision_state") or ""),
        row.get("os_maintenance"),
    )
    if os_prop != "—":
        return os_prop
    return maas_prop


def maas_to_netbox_mapping_reference_rows() -> list[list[str]]:
    """
    Rows for drift report reference table: explicit MAAS → NetBox slugs plus rule summaries.
    Used when OpenStack runtime is absent (MAAS-only fallback).
    """
    rows: list[list[str]] = []
    for maas_key in sorted(_MAAS_TO_NETBOX.keys()):
        label = maas_key.replace("_", " ").title()
        rows.append([label, _MAAS_TO_NETBOX[maas_key]])
    rows.append(["Other FAILED*", "failed"])
    rows.append(["Other (contains RESCUE)", "staged"])
    rows.append(["Unlisted / unknown MAAS state", "—"])
    return rows
