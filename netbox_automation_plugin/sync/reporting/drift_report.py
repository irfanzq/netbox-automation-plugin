"""
Generate human-readable drift audit report from MAAS, NetBox, and OpenStack data.
"""


def format_drift_report(maas_data, netbox_data, openstack_data, drift):
    """
    Build a text report for the Drift Audit UI.

    maas_data, netbox_data, openstack_data: raw fetch results (may have .error).
    drift: result of compute_maas_netbox_drift().
    """
    lines = []

    # MAAS section
    lines.append("=== MAAS ===")
    if maas_data.get("error"):
        lines.append(f"  Error: {maas_data['error']}")
    else:
        lines.append(f"  Zones: {len(maas_data.get('zones') or [])}")
        lines.append(f"  Pools: {len(maas_data.get('pools') or [])}")
        lines.append(f"  Machines: {len(maas_data.get('machines') or [])}")

    # NetBox section
    lines.append("")
    lines.append("=== NetBox ===")
    if netbox_data.get("error"):
        lines.append(f"  Error: {netbox_data['error']}")
    else:
        lines.append(f"  Sites: {len(netbox_data.get('sites') or [])}")
        lines.append(f"  Devices: {len(netbox_data.get('devices') or [])}")

    # MAAS vs NetBox drift
    lines.append("")
    lines.append("=== MAAS vs NetBox ===")
    lines.append(f"  Matched (in both): {drift.get('matched_count', 0)}")
    lines.append(f"  In MAAS only (missing in NetBox): {len(drift.get('in_maas_not_netbox') or [])}")
    if drift.get("in_maas_not_netbox"):
        for h in (drift["in_maas_not_netbox"] or [])[:20]:
            lines.append(f"    - {h}")
        if len(drift.get("in_maas_not_netbox") or []) > 20:
            lines.append(f"    ... and {len(drift['in_maas_not_netbox']) - 20} more")
    lines.append(f"  In NetBox only (orphan candidates): {len(drift.get('in_netbox_not_maas') or [])}")
    if drift.get("in_netbox_not_maas"):
        for h in (drift["in_netbox_not_maas"] or [])[:20]:
            lines.append(f"    - {h}")
        if len(drift.get("in_netbox_not_maas") or []) > 20:
            lines.append(f"    ... and {len(drift['in_netbox_not_maas']) - 20} more")

    # OpenStack section (optional)
    if openstack_data:
        lines.append("")
        lines.append("=== OpenStack ===")
        if openstack_data.get("error"):
            lines.append(f"  Error: {openstack_data['error']}")
        else:
            lines.append(f"  Networks: {len(openstack_data.get('networks') or [])}")
            lines.append(f"  Subnets: {len(openstack_data.get('subnets') or [])}")
            lines.append(f"  Floating IPs: {len(openstack_data.get('floating_ips') or [])}")

    lines.append("")
    lines.append("--- End of Drift Audit ---")
    return "\n".join(lines)
