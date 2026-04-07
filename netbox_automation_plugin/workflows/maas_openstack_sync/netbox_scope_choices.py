"""
NetBox Site / Location choice lists shared by drift audit form and run history filters.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("netbox_automation_plugin")

# Case-insensitive substrings: never offer these in MAAS/OpenStack sync scope pickers
# (SUW / Redwood sites and locations stay out of the plugin UI).
_MAAS_SYNC_HIDDEN_SCOPE_SUBSTRINGS = ("suw", "redwood")


def _maas_sync_scope_text_hidden(*parts: str) -> bool:
    blob = " ".join(str(p or "").casefold() for p in parts)
    return any(sub in blob for sub in _MAAS_SYNC_HIDDEN_SCOPE_SUBSTRINGS)


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
            if not slug:
                continue
            reg = getattr(s, "region", None)
            reg_name = ((getattr(reg, "name", None) or "").strip())
            reg_slug = ((getattr(reg, "slug", None) or "").strip())
            if _maas_sync_scope_text_hidden(slug, s.name or "", reg_name, reg_slug):
                continue
            site_choices.append((slug, s.name or slug))
            site_meta[slug] = {
                "region_name": reg_name,
                "region_slug": reg_slug,
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
            site_name = (getattr(loc.site, "name", "") or "").strip()
            loc_name = (loc.name or "").strip()
            if not site_slug or not loc_name:
                continue
            reg = getattr(loc.site, "region", None)
            reg_name = ((getattr(reg, "name", None) or "").strip())
            reg_slug = ((getattr(reg, "slug", None) or "").strip())
            if _maas_sync_scope_text_hidden(
                site_slug, site_name, loc_name, reg_name, reg_slug
            ):
                continue
            key = f"{site_slug}::{loc_name}"
            label = f"{site_name or site_slug} / {loc_name}"
            location_choices.append((key, label))
            location_meta[key] = {
                "site_slug": site_slug,
                "location_name": loc_name,
                "region_name": reg_name,
                "region_slug": reg_slug,
            }
    except Exception as e:
        logger.warning("Could not build site/location filter choices: %s", e)
    return site_choices, location_choices, location_meta, site_meta
