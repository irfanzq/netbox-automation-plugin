"""
NetBox data for sync / drift audit.

- **Local (ORM)** only: Same process as NetBox — no HTTP, no NETBOX_URL/DNS/token.
"""

import logging

logger = logging.getLogger("netbox_automation_plugin.sync")


def fetch_netbox_data_local():
    """
    Read sites and devices from this NetBox via Django ORM (like vlan_deployment).

    Returns: devices [{name, id, site_slug}], sites [{name, slug, region_name, region_slug}],
    locations [{site_slug, name}], device_types [...], device_roles [...], error.
    """
    result = {
        "devices": [],
        "sites": [],
        "locations": [],
        "vlans": [],
        "device_types": [],
        "device_roles": [],
        "prefix_roles": [],
        "vrfs": [],
        "error": None,
    }
    try:
        from dcim.models import Device, DeviceRole, DeviceType, Site

        for s in Site.objects.select_related("region").only(
            "name", "slug", "region_id", "region__name", "region__slug"
        ).iterator():
            reg_name = ""
            reg_slug = ""
            try:
                if getattr(s, "region_id", None) and s.region:
                    reg_name = (s.region.name or "").strip()
                    reg_slug = (getattr(s.region, "slug", None) or "").strip()
            except Exception:
                pass
            result["sites"].append({
                "name": s.name or "",
                "slug": s.slug or "",
                "region_name": reg_name,
                "region_slug": reg_slug,
            })
        try:
            from dcim.models import Location

            result["locations_count"] = Location.objects.count()
            result["location_lines"] = []
            for i, loc in enumerate(
                Location.objects.select_related("site")
                .only("name", "site__slug", "site__name")
                .order_by("site__slug", "name")
                .iterator()
            ):
                ss = (loc.site.slug or loc.site.name or "") if loc.site_id else ""
                ln = (loc.name or "").strip()
                if i < 60:
                    result["location_lines"].append(f"{ss}/{ln or '-'}")
                if ss and ln:
                    result["locations"].append({"site_slug": ss, "name": ln})
        except Exception:
            result["locations_count"] = 0
            result["location_lines"] = []
            result["locations"] = []
        for dt in DeviceType.objects.select_related("manufacturer").iterator():
            man = ""
            try:
                if dt.manufacturer_id and dt.manufacturer:
                    man = (dt.manufacturer.name or "").strip()
            except Exception:
                pass
            model = (getattr(dt, "model", None) or "").strip()
            slug = (getattr(dt, "slug", None) or "").strip()
            disp = f"{man} {model}".strip() if man else model
            result["device_types"].append({
                "slug": slug,
                "model": model,
                "manufacturer": man,
                "display": disp or model or slug,
            })
        for role in DeviceRole.objects.only("name", "slug").iterator():
            result["device_roles"].append({
                "slug": (getattr(role, "slug", None) or "").strip(),
                "name": (getattr(role, "name", None) or "").strip(),
            })
        # Prefix roles differ by NetBox version/model location.
        prefix_roles = []
        try:
            from ipam.models import Role as PrefixRole  # NetBox 4.x style

            prefix_roles = PrefixRole.objects.only("name", "slug").iterator()
        except Exception:
            try:
                from extras.models import Role as PrefixRole  # Fallback

                prefix_roles = (
                    PrefixRole.objects.filter(
                        content_types__app_label="ipam",
                        content_types__model__in=("prefix", "iprange"),
                    )
                    .only("name", "slug")
                    .iterator()
                )
            except Exception:
                prefix_roles = []
        for role in prefix_roles:
            result["prefix_roles"].append({
                "slug": (getattr(role, "slug", None) or "").strip(),
                "name": (getattr(role, "name", None) or "").strip(),
            })
        try:
            from ipam.models import VRF

            for vrf in VRF.objects.only("name", "rd").iterator():
                result["vrfs"].append({
                    "name": (getattr(vrf, "name", None) or "").strip(),
                    "rd": (getattr(vrf, "rd", None) or "").strip(),
                })
        except Exception:
            result["vrfs"] = []
        try:
            from ipam.models import VLAN

            for v in VLAN.objects.only("name", "vid").iterator():
                vname = (getattr(v, "name", None) or "").strip()
                vvid = getattr(v, "vid", None)
                if vvid is None:
                    continue
                display = f"{vname} ({vvid})" if vname else str(vvid)
                result["vlans"].append({"name": vname, "vid": int(vvid), "display": display})
        except Exception:
            result["vlans"] = []
        for d in Device.objects.select_related("site", "site__region", "location").only(
            "name",
            "id",
            "site_id",
            "site__slug",
            "site__name",
            "site__region_id",
            "site__region__name",
            "location_id",
            "location__name",
        ).iterator():
            site_slug = ""
            site_name = ""
            if d.site_id and d.site:
                site_slug = (d.site.slug or d.site.name or "")
                site_name = (d.site.name or site_slug or "").strip()
            region_name = ""
            try:
                if d.site_id and d.site and getattr(d.site, "region_id", None) and d.site.region:
                    region_name = (d.site.region.name or "").strip()
            except Exception:
                pass
            location_name = ""
            try:
                if getattr(d, "location_id", None) and d.location:
                    location_name = (d.location.name or "").strip()
            except Exception:
                pass
            result["devices"].append({
                "name": d.name or "",
                "id": d.pk,
                "site_slug": site_slug,
                "site_name": site_name or site_slug,
                "region_name": region_name,
                "location_name": location_name,
            })
    except Exception as e:
        logger.exception("NetBox local ORM fetch failed")
        result["error"] = str(e)
    return result


def fetch_netbox_audit_detail_for_names(names: set):
    """
    Per-device fields for MAAS-matched hostnames only (avoids scanning all devices).
    names: set of device names (short hostnames).
    """
    out = {}
    if not names:
        return out
    try:
        from dcim.models import Device, Interface

        from django.db.models import Prefetch

        from ipam.models import IPAddress

        names_list = list(names)[:8000]
        iface_qs = (
            Interface.objects.select_related("untagged_vlan")
            .prefetch_related(
                Prefetch(
                    "ip_addresses",
                    queryset=IPAddress.objects.select_related("vrf"),
                )
            )
        )
        select_rel = ["site", "location", "primary_ip4", "primary_ip4__vrf"]
        try:
            Device._meta.get_field("oob_ip")
            select_rel.append("oob_ip")
        except Exception:
            pass
        devices = (
            Device.objects.filter(name__in=names_list)
            .select_related(*select_rel)
            .prefetch_related(Prefetch("interfaces", queryset=iface_qs))
        )
        for d in devices:
            site_slug = ""
            site_name = ""
            if d.site_id and d.site:
                site_slug = d.site.slug or d.site.name or ""
                site_name = d.site.name or site_slug
            loc_name = ""
            loc_slug = ""
            if getattr(d, "location_id", None) and d.location:
                loc_name = d.location.name or ""
                loc_slug = getattr(d.location, "slug", None) or loc_name
            try:
                status_val = d.get_status_display()
            except Exception:
                status_val = str(getattr(d, "status", "") or "")
            serial = (getattr(d, "serial", None) or "").strip()
            primary_mac = ""
            try:
                ifaces = [
                    i
                    for i in d.interfaces.all()
                    if i.mac_address
                ]
                mgmt = [i for i in ifaces if getattr(i, "mgmt_only", False)]
                pick = mgmt[0] if mgmt else (ifaces[0] if ifaces else None)
                if pick:
                    primary_mac = str(pick.mac_address).lower()
            except Exception:
                pass
            primary_ip4_host = ""
            vrf_name = "Global"
            try:
                if getattr(d, "primary_ip4_id", None) and d.primary_ip4:
                    pip = d.primary_ip4
                    primary_ip4_host = str(pip.address).split("/", 1)[0].strip()
                    if getattr(pip, "vrf_id", None) and pip.vrf:
                        vrf_name = (pip.vrf.name or pip.vrf.slug or str(pip.vrf_id))[:32]
            except Exception:
                pass
            oob_ip_host = ""
            try:
                oob = getattr(d, "oob_ip", None)
                if oob is not None:
                    oob_ip_host = str(oob.address).split("/", 1)[0].strip()
            except Exception:
                pass
            device_ips = set()
            vlan_vids = set()
            try:
                for iface in d.interfaces.all():
                    uv = getattr(iface, "untagged_vlan", None)
                    if uv is not None and getattr(uv, "vid", None) is not None:
                        vlan_vids.add(str(uv.vid))
                    for ip in iface.ip_addresses.all():
                        device_ips.add(
                            str(ip.address).split("/", 1)[0].strip().lower()
                        )
            except Exception:
                pass
            try:
                vlan_summary = ",".join(
                    sorted(vlan_vids, key=lambda x: (int(x) if x.isdigit() else 9999, x))
                )
            except Exception:
                vlan_summary = ",".join(sorted(vlan_vids))
            if len(vlan_summary) > 28:
                vlan_summary = vlan_summary[:26] + ".."
            out[d.name] = {
                "site_slug": site_slug,
                "site_name": site_name,
                "location_name": loc_name,
                "location_slug": loc_slug,
                "status": status_val,
                "serial": serial,
                "primary_mac": primary_mac,
                "primary_ip4_host": primary_ip4_host,
                "vrf_name": vrf_name,
                "vlan_vids_summary": vlan_summary or "—",
                "device_ips": sorted(device_ips),
                "oob_ip_host": oob_ip_host,
            }
    except Exception:
        logger.exception("NetBox audit detail for names failed")
    return out


def _interface_peer_summary(iface) -> str:
    """
    Best-effort description of what this interface is cabled to (NetBox versions differ).
    """
    parts: list[str] = []

    def _add_remote(remote) -> None:
        if remote is None:
            return
        dev = getattr(remote, "device", None)
        dn = (getattr(dev, "name", None) or "").strip() if dev is not None else ""
        inm = (getattr(remote, "name", None) or "").strip()
        if dn or inm:
            parts.append(f"{dn}:{inm}".strip(":"))

    try:
        eps = getattr(iface, "connected_endpoints", None)
        if callable(eps):
            eps = eps()
        if eps is None:
            eps = []
        if eps and not isinstance(eps, (list, tuple)):
            eps = [eps]
        for ep in eps:
            _add_remote(ep)
    except Exception:
        pass

    if not parts:
        try:
            lps = getattr(iface, "link_peers", None)
            if lps:
                if not isinstance(lps, (list, tuple)):
                    lps = [lps]
                for lp in lps:
                    parent = getattr(lp, "parent_object", None)
                    dn = (getattr(parent, "name", None) or "").strip() if parent is not None else ""
                    inm = (getattr(lp, "name", None) or "").strip()
                    if dn or inm:
                        parts.append(f"{dn}:{inm}".strip(":"))
        except Exception:
            pass

    if parts:
        return " | ".join(dict.fromkeys(parts))

    try:
        cab = getattr(iface, "cable", None)
        if cab is not None:
            cid = getattr(cab, "pk", None) or getattr(cab, "id", None)
            if cid:
                return f"cable #{cid}"
            return "cabled"
    except Exception:
        pass
    return ""


def fetch_netbox_interfaces_for_names(names: set):
    """
    Per-device interfaces for MAAS-matched hostnames.
    Returns: device_name -> [{
      name, mac, ips, mgmt_only, untagged_vlan_vid, ip_vrfs,
      lag_name, peer_summary, nb_site, nb_location
    }]
    """
    out = {}
    if not names:
        return out
    try:
        from django.db.models import Prefetch

        from dcim.models import Device, Interface
        from ipam.models import IPAddress

        names_list = list(names)[:2000]
        iface_qs = Interface.objects.select_related(
            "untagged_vlan",
            "cable",
        ).prefetch_related(
            Prefetch(
                "ip_addresses",
                queryset=IPAddress.objects.select_related("vrf"),
            )
        )
        select_device = ["site"]
        try:
            Device._meta.get_field("location")
            select_device.append("location")
        except Exception:
            pass
        devices = (
            Device.objects.filter(name__in=names_list)
            .select_related(*select_device)
            .prefetch_related(Prefetch("interfaces", queryset=iface_qs))
        )
        for d in devices:
            site_nm = ""
            if d.site_id and d.site:
                site_nm = (d.site.name or d.site.slug or "").strip()
            loc_nm = ""
            try:
                if getattr(d, "location_id", None) and d.location:
                    loc_nm = (d.location.name or "").strip()
            except Exception:
                pass
            lst = []
            for iface in d.interfaces.all():
                mac = ""
                if iface.mac_address:
                    mac = str(iface.mac_address).lower().replace("-", ":")
                ips = []
                ip_vrfs = []
                for ip in iface.ip_addresses.all():
                    host = str(ip.address).split("/", 1)[0].strip().lower()
                    ips.append(host)
                    v = ""
                    if getattr(ip, "vrf_id", None) and ip.vrf:
                        v = (ip.vrf.name or ip.vrf.slug or "")[:12]
                    ip_vrfs.append(v or "Global")
                uv = getattr(iface, "untagged_vlan", None)
                vid = str(uv.vid) if uv and getattr(uv, "vid", None) is not None else ""
                lag_name = ""
                try:
                    lag_obj = getattr(iface, "lag", None)
                    lag_name = (getattr(lag_obj, "name", None) or "").strip()
                except Exception:
                    lag_name = ""
                peer_summary = _interface_peer_summary(iface)
                lst.append({
                    "name": iface.name or "",
                    "mac": mac,
                    "ips": ips,
                    "mgmt_only": bool(getattr(iface, "mgmt_only", False)),
                    "untagged_vlan_vid": vid,
                    "ip_vrfs": ip_vrfs,
                    "lag_name": lag_name,
                    "peer_summary": peer_summary,
                    "nb_site": site_nm,
                    "nb_location": loc_nm,
                })
            out[d.name or ""] = lst
    except Exception:
        logger.exception("NetBox interfaces for names failed")
    return out


def fetch_netbox_prefix_cidrs():
    """Set of prefix strings (CIDR) for coarse OpenStack subnet cross-check."""
    try:
        from ipam.models import Prefix

        return {str(p) for p in Prefix.objects.values_list("prefix", flat=True)}
    except Exception:
        logger.exception("NetBox prefix list failed")
        return set()


def fetch_netbox_ipam_inventory_counts():
    """
    Whole-database counts for drift report inventory (NetBox this instance).

    VIP role matches OpenStack floating-IP proposals in this plugin; NAT outside
    counts IPAddress rows with ``nat_inside`` set (public/outside side of a pair).
    """
    out = {
        "virtual_machines": 0,
        "ip_addresses_total": 0,
        "ip_addresses_vip_role": 0,
        "ip_addresses_nat_outside": 0,
    }
    try:
        from virtualization.models import VirtualMachine

        out["virtual_machines"] = VirtualMachine.objects.count()
    except Exception:
        logger.debug("NetBox virtual machine count skipped", exc_info=True)

    try:
        from ipam.models import IPAddress, Role

        out["ip_addresses_total"] = IPAddress.objects.count()
        vip_pk = None
        try:
            vip = Role.objects.filter(slug__iexact="vip").first()
            if vip is None:
                vip = Role.objects.filter(name__iexact="vip").first()
            if vip is not None:
                vip_pk = vip.pk
        except Exception:
            vip_pk = None
        if vip_pk is not None:
            out["ip_addresses_vip_role"] = IPAddress.objects.filter(role_id=vip_pk).count()
        if hasattr(IPAddress, "nat_inside_id"):
            out["ip_addresses_nat_outside"] = IPAddress.objects.exclude(nat_inside_id__isnull=True).count()
    except Exception:
        logger.exception("NetBox IP address inventory counts failed")
        out["ip_addresses_total"] = 0
        out["ip_addresses_vip_role"] = 0
        out["ip_addresses_nat_outside"] = 0

    return out


