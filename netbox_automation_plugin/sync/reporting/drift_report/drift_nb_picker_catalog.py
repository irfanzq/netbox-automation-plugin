"""
NetBox choice lists for drift-report HTML pickers (in-browser overrides for NB proposed columns).

Loaded once per page via json_script; keys match data-nb-pick-kind on picker cells.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("netbox_automation_plugin")


def build_drift_nb_picker_catalog() -> dict[str, list[str]]:
    """
    Return serializable dict: kind -> sorted unique display strings.
    Safe to call outside NetBox (returns empty lists).
    """
    out: dict[str, list[str]] = {
        "vrf": [],
        "region": [],
        "site": [],
        "location": [],
        "device_type": [],
        "device_role": [],
        "device_status": [],
        "prefix_status": [],
        "prefix_role": [],
        "ip_status": [],
        "ip_role": [],
    }
    try:
        from ipam.models import VRF

        out["vrf"] = sorted({(x.name or "").strip() for x in VRF.objects.only("name").iterator()} - {""})
    except Exception as e:
        logger.debug("drift picker vrf: %s", e)

    try:
        from dcim.models import Region

        out["region"] = sorted({(x.name or "").strip() for x in Region.objects.only("name").iterator()} - {""})
    except Exception as e:
        logger.debug("drift picker region: %s", e)

    try:
        from dcim.models import Site

        out["site"] = sorted({(x.name or "").strip() for x in Site.objects.only("name").iterator()} - {""})
    except Exception as e:
        logger.debug("drift picker site: %s", e)

    try:
        from dcim.models import Location

        for loc in Location.objects.select_related("site").only("name", "site__name", "site__slug").iterator():
            site_name = (getattr(loc.site, "name", None) or getattr(loc.site, "slug", "") or "").strip()
            loc_name = (loc.name or "").strip()
            if not loc_name:
                continue
            label = f"{site_name} / {loc_name}" if site_name else loc_name
            out["location"].append(label)
        out["location"] = sorted(set(out["location"]))
    except Exception as e:
        logger.debug("drift picker location: %s", e)

    try:
        from dcim.models import DeviceType

        for dt in DeviceType.objects.select_related("manufacturer").only(
            "model", "manufacturer__name"
        ).iterator():
            m = (getattr(dt.manufacturer, "name", None) or "").strip()
            mo = (dt.model or "").strip()
            disp = f"{m} {mo}".strip() if m else mo
            if disp:
                out["device_type"].append(disp)
        out["device_type"] = sorted(set(out["device_type"]))
    except Exception as e:
        logger.debug("drift picker device_type: %s", e)

    try:
        from dcim.models import DeviceRole

        out["device_role"] = sorted(
            {(x.name or "").strip() for x in DeviceRole.objects.only("name").iterator()} - {""}
        )
    except Exception as e:
        logger.debug("drift picker device_role: %s", e)

    try:
        from dcim.models import Device

        field = Device._meta.get_field("status")
        ch = getattr(field, "choices", None) or []
        slugs = []
        for val, _lab in ch:
            if val is None or val == "":
                continue
            slugs.append(str(val).strip())
        out["device_status"] = sorted(set(slugs) - {""})
    except Exception as e:
        logger.debug("drift picker device_status: %s", e)

    try:
        from ipam.models import Prefix

        field = Prefix._meta.get_field("status")
        ch = getattr(field, "choices", None) or []
        slugs = []
        for val, _lab in ch:
            if val is None or val == "":
                continue
            slugs.append(str(val).strip())
        out["prefix_status"] = sorted(set(slugs) - {""})
    except Exception as e:
        logger.debug("drift picker prefix_status: %s", e)

    try:
        from ipam.models import Role as PrefixRole  # NetBox 4.x

        out["prefix_role"] = sorted(
            {(x.name or "").strip() for x in PrefixRole.objects.only("name").iterator()} - {""}
        )
    except Exception:
        try:
            from extras.models import Role as PrefixRole

            out["prefix_role"] = sorted(
                {(x.name or "").strip() for x in PrefixRole.objects.only("name").iterator()} - {""}
            )
        except Exception as e:
            logger.debug("drift picker prefix_role: %s", e)

    try:
        from ipam.models import IPAddress

        field = IPAddress._meta.get_field("status")
        ch = getattr(field, "choices", None) or []
        slugs = []
        for val, _lab in ch:
            if val is None or val == "":
                continue
            slugs.append(str(val).strip())
        out["ip_status"] = sorted(set(slugs) - {""})
    except Exception as e:
        logger.debug("drift picker ip_status: %s", e)

    try:
        from ipam.models import IPAddress

        role_field = IPAddress._meta.get_field("role")
        remote = getattr(role_field, "remote_field", None)
        if remote and getattr(remote, "model", None):
            RoleModel = remote.model
            out["ip_role"] = sorted(
                {(x.name or "").strip() for x in RoleModel.objects.only("name").iterator()} - {""}
            )
        else:
            ch = getattr(role_field, "choices", None) or []
            out["ip_role"] = sorted(
                {str(lab).strip() for _v, lab in ch if lab} - {""}
            )
    except Exception as e:
        logger.debug("drift picker ip_role: %s", e)

    if not out["ip_role"] and out["prefix_role"]:
        out["ip_role"] = list(out["prefix_role"])

    if not out["device_status"]:
        out["device_status"] = sorted(
            {
                "offline",
                "active",
                "planned",
                "staged",
                "failed",
                "inventory",
                "decommissioning",
            }
        )
    if not out["prefix_status"]:
        out["prefix_status"] = ["active", "reserved"]
    if not out["ip_status"]:
        out["ip_status"] = list(out["prefix_status"])

    return out
