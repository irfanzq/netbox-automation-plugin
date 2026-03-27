"""
NetBox Site / Location choice lists shared by drift audit form and run history filters.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("netbox_automation_plugin")


def list_site_location_choices():
    """Return (site_choices, location_choices, location_meta_by_key, site_meta_by_slug)."""
    site_choices = []
    location_choices = []
    location_meta = {}
    site_meta = {}
    try:
        from dcim.models import Site, Location

        for s in (
            Site.objects.select_related("region")
            .only("slug", "name", "region__name", "region__slug")
            .order_by("name")
        ):
            slug = (s.slug or "").strip()
            if slug:
                site_choices.append((slug, s.name or slug))
                reg = getattr(s, "region", None)
                site_meta[slug] = {
                    "region_name": ((getattr(reg, "name", None) or "").strip()),
                    "region_slug": ((getattr(reg, "slug", None) or "").strip()),
                }
        for loc in (
            Location.objects.select_related("site", "site__region")
            .only(
                "name",
                "slug",
                "site__slug",
                "site__name",
                "site__region__name",
                "site__region__slug",
            )
            .order_by("site__name", "name")
        ):
            site_slug = (getattr(loc.site, "slug", "") or "").strip()
            loc_name = (loc.name or "").strip()
            if not site_slug or not loc_name:
                continue
            key = f"{site_slug}::{loc_name}"
            label = f"{getattr(loc.site, 'name', site_slug) or site_slug} / {loc_name}"
            location_choices.append((key, label))
            reg = getattr(loc.site, "region", None)
            location_meta[key] = {
                "site_slug": site_slug,
                "location_name": loc_name,
                "region_name": ((getattr(reg, "name", None) or "").strip()),
                "region_slug": ((getattr(reg, "slug", None) or "").strip()),
            }
    except Exception as e:
        logger.warning("Could not build site/location filter choices: %s", e)
    return site_choices, location_choices, location_meta, site_meta
