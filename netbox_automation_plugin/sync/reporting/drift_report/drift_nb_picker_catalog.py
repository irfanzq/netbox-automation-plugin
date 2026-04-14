"""
NetBox choice lists for drift-report HTML pickers (in-browser overrides for NB proposed columns).

Loaded once per page via json_script; keys match data-nb-pick-kind on picker cells.
"""

from __future__ import annotations

import logging
from functools import lru_cache

logger = logging.getLogger("netbox_automation_plugin")

# Single placeholder for drift **NB Proposed Tenant** until the operator picks a label from the picker
# (values come from :func:`build_drift_nb_picker_catalog`; do not copy NetBox/OS fields here).
DRIFT_NB_PROPOSED_TENANT_DEFAULT = "—"

_PLACEHOLDER_TENANT = frozenset(("", "—", "-"))


@lru_cache(maxsize=1)
def drift_picker_tenant_label_allowlist() -> frozenset[str]:
    """Display strings that match the drift HTML tenant picker (hierarchy labels included)."""
    return frozenset(build_drift_nb_picker_catalog(user=None).get("tenant") or [])


def coerce_nb_proposed_tenant_cell(raw: str | None) -> str:
    """
    Return a tenant label safe for NetBox apply/preview: empty unless ``raw`` is empty/placeholder
    or exactly matches a value from :func:`build_drift_nb_picker_catalog` (tenant key).
    """
    s = (raw or "").strip()
    if not s or s in _PLACEHOLDER_TENANT:
        return ""
    if s in drift_picker_tenant_label_allowlist():
        return s
    return ""


def coerce_nb_proposed_tenant_cell_with_openstack_project(
    nb_proposed_tenant_cell: str | None,
    openstack_project_cell: str | None,
) -> str:
    """
    Prefer validated **NB Proposed Tenant**; else use **Project** (OpenStack) when it matches a
    NetBox tenant label from the drift picker catalog.

    When the OS project name is not in the catalog, apply may still resolve it via
    :func:`netbox_automation_plugin.sync.reconciliation.apply_cells._resolve_tenant`.
    """
    t = coerce_nb_proposed_tenant_cell(nb_proposed_tenant_cell)
    if t:
        return t
    p = (openstack_project_cell or "").strip()
    if not p or p in _PLACEHOLDER_TENANT:
        return ""
    if p in drift_picker_tenant_label_allowlist():
        return p
    return ""


def _picker_field_values_main_branch(
    model_cls, field_name: str, user, *, restrict_view: bool = True
) -> list[str]:
    """
    Distinct non-empty values for ``field_name``, ordered for display.

    When netbox-branching is active, ORM queries run in the branch schema by default; VM cluster
    pickers need every cluster name from the main dataset. We query inside ``deactivate_branch()``
    when that API exists, then fall back to the active connection on failure.

    When ``restrict_view`` is True and ``user`` is authenticated, applies NetBox
    ``restrict(..., "view")``. Cluster pickers pass ``restrict_view=False`` so the menu lists
    **all** clusters: object-level view rules are often scoped by site/tenant and would hide valid
    targets for ``NB proposed cluster`` even though reconciliation still resolves by name.
    """

    def _fetch() -> list[str]:
        qs = model_cls.objects.order_by(field_name)
        if (
            restrict_view
            and user is not None
            and getattr(user, "is_authenticated", False)
        ):
            qs = qs.restrict(user, "view")
        names: list[str] = []
        for val in qs.values_list(field_name, flat=True).iterator(chunk_size=4096):
            s = (val or "").strip()
            if s:
                names.append(s)
        return sorted(set(names))

    try:
        from netbox_branching.utilities import deactivate_branch
    except ImportError:
        return _fetch()
    try:
        with deactivate_branch():
            return _fetch()
    except Exception as e:
        logger.debug("drift picker main-branch %s: %s", getattr(model_cls, "__name__", "?"), e)
        return _fetch()


def build_drift_nb_picker_catalog(*, user=None) -> dict[str, list[str]]:
    """
    Return serializable dict: kind -> sorted unique display strings.
    Safe to call outside NetBox (returns empty lists).

    Pass ``user`` (typically ``request.user``) for pickers that use view restriction; VM cluster
    names are listed in full (no ``restrict``) so site-scoped permissions do not trim the dropdown.
    """
    out: dict[str, list[str]] = {
        "vrf": [],
        "region": [],
        "site": [],
        "location": [],
        "scope_location": [],
        "tenant": [],
        "vlan": [],
        "device_type": [],
        "platform": [],
        "device_role": [],
        "device_status": [],
        "prefix_status": [],
        "prefix_role": [],
        "ip_status": [],
        "ip_role": [],
        "intf_role": [],
        "interface_type": [],
        "vm_cluster": [],
        "vm_cluster_type": [],
        "vm_primary_ip": [],
        "vm_status": [],
        "vlan_group": [],
        "vlan_status": [],
    }
    out["_vlan_by_scope_location"] = {}
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
        from dcim.models import Location

        out["scope_location"] = sorted(
            {(x.name or "").strip() for x in Location.objects.only("name").iterator()} - {""}
        )
    except Exception as e:
        logger.debug("drift picker scope_location: %s", e)

    try:
        from tenancy.models import Tenant

        def _tenant_labels_fetch() -> list[str]:
            from netbox_automation_plugin.sync.tenancy_netbox_compat import tenant_hierarchy_fk

            rel = tenant_hierarchy_fk()
            if rel:
                qs = (
                    Tenant.objects.select_related(rel)
                    .only("name", f"{rel}__name")
                    .order_by("name")
                )
            else:
                qs = Tenant.objects.only("name").order_by("name")
            lab: set[str] = set()
            for t in qs.iterator(chunk_size=4096):
                child = (t.name or "").strip()
                if not child:
                    continue
                lab.add(child)
                if rel:
                    par = getattr(t, rel, None)
                    if par is not None and (par.name or "").strip():
                        lab.add(f"{(par.name or '').strip()} / {child}")
            return sorted(lab - {""})

        try:
            from netbox_branching.utilities import deactivate_branch
        except ImportError:
            out["tenant"] = _tenant_labels_fetch()
        else:
            try:
                with deactivate_branch():
                    out["tenant"] = _tenant_labels_fetch()
            except Exception as e:
                logger.debug("drift picker tenant main-branch: %s", e)
                out["tenant"] = _tenant_labels_fetch()
    except Exception as e:
        logger.debug("drift picker tenant: %s", e)

    try:
        from ipam.models import VLANGroup

        out["vlan_group"] = _picker_field_values_main_branch(
            VLANGroup, "name", user, restrict_view=False
        )
    except Exception as e:
        logger.debug("drift picker vlan_group: %s", e)

    try:
        from ipam.models import VLAN

        st_field = VLAN._meta.get_field("status")
        ch = getattr(st_field, "choices", None) or []
        vstat: list[str] = []
        for val, _lab in ch:
            if val is None or val == "":
                continue
            vstat.append(str(val).strip())
        out["vlan_status"] = sorted(set(vstat) - {""})
    except Exception as e:
        logger.debug("drift picker vlan_status: %s", e)

    try:
        from ipam.models import VLAN

        vals = []
        for v in VLAN.objects.only("name", "vid").iterator():
            vid = getattr(v, "vid", None)
            if vid is None:
                continue
            nm = (getattr(v, "name", None) or "").strip()
            vals.append(f"{nm} ({vid})" if nm else str(vid))
        out["vlan"] = sorted(set(vals))
    except Exception as e:
        logger.debug("drift picker vlan: %s", e)

    # Per-location VLAN choices for Prefix scope "DCIM > Location" behavior.
    try:
        from django.contrib.contenttypes.models import ContentType
        from dcim.models import Location
        from ipam.models import VLAN

        ct_loc = ContentType.objects.get_by_natural_key("dcim", "location")
        by_loc: dict[str, list[str]] = {}
        for loc in Location.objects.select_related("site").iterator():
            lname = (loc.name or "").strip()
            if not lname:
                continue
            labels = []
            # VLAN groups scoped to this location or any ancestor location.
            anc_ids = list(
                loc.get_ancestors(include_self=True).values_list("id", flat=True)
            )
            q_loc = VLAN.objects.filter(
                group__scope_type=ct_loc,
                group__scope_id__in=anc_ids,
            ).distinct()
            # NetBox site fallback behavior.
            q_site = VLAN.objects.none()
            if getattr(loc, "site_id", None):
                try:
                    q_site = VLAN.objects.get_for_site(loc.site)
                except Exception:
                    q_site = VLAN.objects.none()
            for v in (q_loc | q_site).distinct():
                vid = getattr(v, "vid", None)
                if vid is None:
                    continue
                nm = (getattr(v, "name", None) or "").strip()
                labels.append(f"{nm} ({vid})" if nm else str(vid))
            by_loc[lname] = sorted(set(labels))
        out["_vlan_by_scope_location"] = by_loc
    except Exception as e:
        logger.debug("drift picker vlan_by_scope_location: %s", e)

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
        from dcim.models import Platform

        out["platform"] = _picker_field_values_main_branch(Platform, "name", user, restrict_view=True)
    except Exception as e:
        logger.debug("drift picker platform: %s", e)

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

    try:
        from netbox_automation_plugin.sync.reporting.drift_report.proposed_nic_derived import (
            intf_role_catalog_values,
        )

        out["intf_role"] = intf_role_catalog_values()
    except Exception as e:
        logger.debug("drift picker intf_role: %s", e)

    try:
        from netbox_automation_plugin.sync.reconciliation.netbox_interface_types import (
            all_netbox_interface_type_slugs_sorted,
        )

        out["interface_type"] = all_netbox_interface_type_slugs_sorted()
    except Exception as e:
        logger.debug("drift picker interface_type: %s", e)

    try:
        from virtualization.models import Cluster

        out["vm_cluster"] = _picker_field_values_main_branch(
            Cluster, "name", user, restrict_view=False
        )
    except Exception as e:
        logger.debug("drift picker vm_cluster: %s", e)

    try:
        from virtualization.models import ClusterType

        out["vm_cluster_type"] = _picker_field_values_main_branch(
            ClusterType, "name", user, restrict_view=False
        )
    except Exception as e:
        logger.debug("drift picker vm_cluster_type: %s", e)

    try:
        from virtualization.models import VirtualMachine

        field = VirtualMachine._meta.get_field("status")
        ch = getattr(field, "choices", None) or []
        slugs = []
        for val, _lab in ch:
            if val is None or val == "":
                continue
            slugs.append(str(val).strip())
        out["vm_status"] = sorted(set(slugs) - {""})
    except Exception as e:
        logger.debug("drift picker vm_status: %s", e)

    # Host-only strings are not valid NetBox IPAddress.address values; picker lists DB prefixes.
    _VM_PRIMARY_CAP = 12000
    try:
        from ipam.models import IPAddress

        vals: list[str] = []
        for a in IPAddress.objects.only("address").iterator():
            try:
                s = str(getattr(a, "address", "") or "").strip()
            except Exception:
                continue
            if s:
                vals.append(s)
            if len(vals) >= _VM_PRIMARY_CAP:
                break
        out["vm_primary_ip"] = sorted(set(vals))
    except Exception as e:
        logger.debug("drift picker vm_primary_ip: %s", e)

    return out
