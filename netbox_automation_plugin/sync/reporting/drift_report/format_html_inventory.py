"""INVENTORY + SCOPE sections of the drift HTML/ASCII report."""

from netbox_automation_plugin.sync.reporting.drift_report.metrics import _run_metadata_rows


def emit_inventory_scope(e, maas_data, netbox_data, openstack_data, drift, netbox_prefix_count):
    e.banner("INVENTORY")
    e.spacer()
    e.subtitle("Run metadata")
    e.spacer()
    e.table(
        ["Property", "Value"],
        _run_metadata_rows(maas_data, netbox_data, openstack_data),
        dynamic_columns=True,
    )
    e.spacer()
    e.subtitle("MAAS")
    e.spacer()
    if maas_data.get("error"):
        e.error(f"Error: {maas_data['error']}")
    else:
        e.table(
            ["Metric", "Count"],
            [
                ["Zones", str(len(maas_data.get("zones") or []))],
                ["Resource pools", str(len(maas_data.get("pools") or []))],
                ["Machines", str(len(maas_data.get("machines") or []))],
            ],
        )

    e.spacer()
    e.subtitle("NetBox (this instance)")
    e.spacer()
    if netbox_data.get("error"):
        e.error(f"Error: {netbox_data['error']}")
    else:
        inv_rows = [
            ["Sites", str(len(netbox_data.get("sites") or []))],
            ["Devices", str(len(netbox_data.get("devices") or []))],
        ]
        if netbox_prefix_count:
            inv_rows.append(["IPAM Prefix objects", str(netbox_prefix_count)])
        e.table(["Metric", "Count"], inv_rows)

    scope_meta = (drift or {}).get("scope_meta") or {}
    if scope_meta:
        e.spacer()
        e.banner("SCOPE", "-")
        e.spacer()
        sel_sites = ", ".join(scope_meta.get("selected_sites") or []) or "(all)"
        sel_locs = ", ".join(scope_meta.get("selected_locations") or []) or "(all)"
        e.table(
            ["Check", "Value"],
            [
                ["Coverage status", str(scope_meta.get("coverage_status") or "PARTIAL")],
                ["Selected sites", sel_sites],
                ["Selected locations", sel_locs],
                [
                    "MAAS machines included / fetched",
                    f"{scope_meta.get('maas_machines_after', 0)} / {scope_meta.get('maas_machines_before', 0)}",
                ],
                [
                    "NetBox devices included / fetched",
                    f"{scope_meta.get('netbox_devices_after', 0)} / {scope_meta.get('netbox_devices_before', 0)}",
                ],
                [
                    "OpenStack nets included / fetched",
                    f"{scope_meta.get('openstack_networks_after', 0)} / {scope_meta.get('openstack_networks_before', 0)}",
                ],
                [
                    "OpenStack subnets included / fetched",
                    f"{scope_meta.get('openstack_subnets_after', 0)} / {scope_meta.get('openstack_subnets_before', 0)}",
                ],
                [
                    "OpenStack FIPs included / fetched",
                    f"{scope_meta.get('openstack_fips_after', 0)} / {scope_meta.get('openstack_fips_before', 0)}",
                ],
                [
                    "OpenStack runtime NIC rows",
                    str(len((openstack_data or {}).get("runtime_nics") or [])),
                ],
                [
                    "OpenStack runtime BMC rows",
                    str(len((openstack_data or {}).get("runtime_bmc") or [])),
                ],
            ],
            dynamic_columns=True,
        )
