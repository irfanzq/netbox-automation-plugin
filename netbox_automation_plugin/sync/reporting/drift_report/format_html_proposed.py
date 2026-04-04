"""PROPOSED CHANGES and summary tables for the drift HTML/ASCII report."""

from netbox_automation_plugin.sync.reporting.drift_report.drift_overrides_apply import (
    HEADERS_BMC_EXISTING,
    HEADERS_BMC_NEW_DEVICES,
    HEADERS_DETAIL_EXISTING_FIPS,
    HEADERS_DETAIL_EXISTING_PREFIXES,
    HEADERS_DETAIL_EXISTING_VMS,
    HEADERS_DETAIL_NEW_DEVICES,
    HEADERS_DETAIL_NEW_FIPS,
    HEADERS_DETAIL_NEW_IP_RANGES,
    HEADERS_DETAIL_NEW_NICS,
    HEADERS_DETAIL_NEW_PREFIXES,
    HEADERS_DETAIL_NEW_VMS,
    HEADERS_DETAIL_NIC_DRIFT,
    HEADERS_SERIAL_REVIEW,
    _new_nic_row_is_os_authority,
    _update_nic_row_is_os_authority,
)
from netbox_automation_plugin.sync.reporting.drift_report.maas_netbox_status import (
    maas_to_netbox_mapping_reference_rows,
)

# Header label → catalog key for drift_nb_picker_catalog (NB proposed tag excluded).
_PROPOSED_NB_PICK_DEVICE = {
    "NB proposed region": "region",
    "NB proposed site": "site",
    "NB proposed location": "location",
    "NB proposed device type": "device_type",
    "NB proposed role": "device_role",
    "NB proposed device status": "device_status",
    "NB proposed platform": "platform",
}
_PROPOSED_NB_PICK_PREFIX = {
    "NB Proposed Tenant": "tenant",
    "NB Proposed Scope": "scope_location",
    "NB Proposed VLAN": "vlan",
    "NB proposed role": "prefix_role",
    "NB proposed status": "prefix_status",
    "NB proposed VRF": "vrf",
}
_PROPOSED_NB_PICK_FIP = {
    "NB Proposed Tenant": "tenant",
    "NB proposed status": "ip_status",
    "NB proposed role": "ip_role",
    "NB proposed VRF": "vrf",
}
_PROPOSED_NB_PICK_VM = {
    "NB proposed primary IP": "vm_primary_ip",
    "NB proposed cluster": "vm_cluster",
    "NB proposed site": "site",
    "NB Proposed Tenant": "tenant",
    "NB proposed VM status": "vm_status",
}
_PROPOSED_NB_PICK_NIC = {
    "NB Proposed intf Label": "intf_role",
    "NB Proposed intf Type": "interface_type",
}


def emit_proposed_change_tables(e, prop):
    e.spacer()
    e.banner("PROPOSED CHANGES", "-")
    e.paragraph(
        "Read-only. Possible NetBox updates from OpenStack runtime (authoritative when present) with MAAS fallback where OpenStack data is missing."
    )
    e.spacer()

    e.subtitle("A) Add to NetBox")
    e.spacer()
    e.table(
        ["What", "Count", "Note"],
        [
            ["New devices (MAAS fallback)", str(len(prop["add_devices"])), "Safe create candidates when not present in NetBox"],
            [
                "Review-only MAAS-only hosts",
                str(len(prop.get("add_devices_review_only", []))),
                "Not safe to auto-propose (status/data quality policy)",
            ],
            ["New prefixes (OpenStack authority)", str(len(prop["add_prefixes"])), "Subnet not in IPAM"],
            [
                "Existing prefixes (OpenStack drift)",
                str(len(prop.get("update_prefixes", []))),
                "Prefix exists; VRF/status/role/tenant/description differ from OpenStack-derived proposal",
            ],
            ["New floating IPs (OpenStack authority)", str(len(prop["add_fips"])), "FIP not in IPAM"],
            [
                "Existing floating IPs (NAT drift)",
                str(len(prop.get("update_fips", []))),
                "FIP in IPAM; OpenStack fixed IP ≠ NetBox nat_inside",
            ],
            ["New VMs (OpenStack Nova)", str(len(prop.get("add_openstack_vms", []))), "Instance not modeled as NetBox Virtual Machine"],
            [
                "Existing VMs (OpenStack drift)",
                str(len(prop.get("update_openstack_vms", []))),
                "Virtual Machine exists; vCPU/memory/disk/status/device/cluster differ",
            ],
        ],
    )
    e.spacer()
    e.subtitle("Reference — MAAS → NetBox device.status (fallback when no OS runtime)")
    e.paragraph(
        "Placement and new-device rows prefer OpenStack Ironic when a BMC row exists; "
        "this table is the MAAS-only mapping used when OS data is missing or does not map."
    )
    e.spacer()
    e.table(
        ["MAAS state (normalized)", "NetBox status slug"],
        maas_to_netbox_mapping_reference_rows(),
        dynamic_columns=True,
        wrap_max_width=None,
        selectable=False,
    )
    if prop["add_prefixes"]:
        e.spacer()
        e.subtitle("Detail — new prefixes")
        e.paragraph(
            "Use each row as NetBox Prefix create input (CIDR + OpenStack network/project context). "
            "NB proposed status: reserved when no Neutron ports were counted on that subnet in this scan; "
            "active when at least one port was seen (role certainty is only in Role reason). "
            "NB proposed VRF is inferred from OpenStack naming signals (network/project/region text). "
            "Columns marked '(editable)' can be clicked and edited directly."
        )
        e.spacer()
        e.table(
            list(HEADERS_DETAIL_NEW_PREFIXES),
            prop["add_prefixes"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_new_prefixes",
            proposed_pick_columns=_PROPOSED_NB_PICK_PREFIX,
            editable_columns=["NB Proposed Prefix description (editable)"],
        )
    if prop.get("update_prefixes"):
        e.spacer()
        e.subtitle("Detail — existing prefixes")
        e.paragraph(
            "Subnet already has an exact matching NetBox Prefix, but OpenStack-derived VRF, status, role, "
            "tenant, or description does not match. Apply matches the Prefix by CIDR and NB proposed VRF "
            "(same handler as new prefixes)."
        )
        e.spacer()
        e.table(
            list(HEADERS_DETAIL_EXISTING_PREFIXES),
            prop["update_prefixes"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_existing_prefixes",
            proposed_pick_columns=_PROPOSED_NB_PICK_PREFIX,
            editable_columns=["NB Proposed Prefix description (editable)"],
        )
    if prop.get("add_ip_ranges"):
        e.spacer()
        e.subtitle("Detail — new IP ranges (allocation pools)")
        e.paragraph(
            "OpenStack subnet allocation pools proposed as NetBox IPRanges. "
            "These rows represent assignable host windows inside the subnet CIDR."
        )
        e.spacer()
        e.table(
            list(HEADERS_DETAIL_NEW_IP_RANGES),
            prop["add_ip_ranges"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_new_ip_ranges",
            proposed_pick_columns=_PROPOSED_NB_PICK_PREFIX,
            editable_columns=["NB Proposed Description"],
        )
    if prop["add_fips"]:
        e.spacer()
        e.subtitle("Detail — new floating IPs")
        e.spacer()
        e.table(
            list(HEADERS_DETAIL_NEW_FIPS),
            prop["add_fips"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_new_fips",
            proposed_pick_columns=_PROPOSED_NB_PICK_FIP,
        )
    if prop.get("update_fips"):
        e.spacer()
        e.subtitle("Detail — existing floating IPs")
        e.paragraph(
            "Floating IP exists in NetBox IPAM but NAT inside does not match OpenStack fixed IP "
            "(reassignment or first link). Same apply handler as new FIPs."
        )
        e.spacer()
        e.table(
            list(HEADERS_DETAIL_EXISTING_FIPS),
            prop["update_fips"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_existing_fips",
            proposed_pick_columns=_PROPOSED_NB_PICK_FIP,
        )
    if prop.get("add_openstack_vms"):
        e.spacer()
        e.subtitle("Detail — new VMs")
        e.paragraph(
            "OpenStack Nova instances (VMs and Ironic bare metal) with no NetBox Virtual Machine of the same name. "
            "Requires an existing Cluster (NB proposed cluster). NB proposed device (VM) is always the "
            "Nova instance name (same as VM name). Hypervisor hostname shows Nova's compute host for "
            "reference. Apply links a NetBox Device by that VM name first, then by hypervisor hostname "
            "if no Device matches the VM name. "
            "If the VM has a custom field whose key is one of "
            "<code>nova_compute_host</code>, <code>openstack_hypervisor_hostname</code>, "
            "<code>hypervisor_hostname</code>, or <code>os_hypervisor_host</code>, apply copies "
            "<strong>Hypervisor hostname</strong> there so the compute host stays visible even when "
            "the linked Device is the instance name."
        )
        e.spacer()
        e.table(
            list(HEADERS_DETAIL_NEW_VMS),
            prop["add_openstack_vms"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_new_vms",
            proposed_pick_columns=_PROPOSED_NB_PICK_VM,
        )
    if prop.get("update_openstack_vms"):
        e.spacer()
        e.subtitle("Detail — existing VMs")
        e.paragraph(
            "Virtual Machine name matches OpenStack; NetBox fields below differ from Nova where noted in Drift summary. "
            "Optional VM custom fields "
            "<code>nova_compute_host</code>, <code>openstack_hypervisor_hostname</code>, "
            "<code>hypervisor_hostname</code>, or <code>os_hypervisor_host</code> receive "
            "<strong>Hypervisor hostname</strong> on apply."
        )
        e.spacer()
        e.table(
            list(HEADERS_DETAIL_EXISTING_VMS),
            prop["update_openstack_vms"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_existing_vms",
            proposed_pick_columns=_PROPOSED_NB_PICK_VM,
        )

    if prop["add_devices"]:
        e.spacer()
        e.subtitle("Detail — new devices")
        e.spacer()
        e.table(
            list(HEADERS_DETAIL_NEW_DEVICES),
            prop["add_devices"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_new_devices",
            proposed_pick_columns=_PROPOSED_NB_PICK_DEVICE,
        )
    if prop.get("add_devices_review_only"):
        e.spacer()
        e.subtitle("Detail — MAAS-only hosts (manual review required)")
        e.spacer()
        e.table(
            list(HEADERS_DETAIL_NEW_DEVICES),
            prop["add_devices_review_only"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_review_only_devices",
            proposed_pick_columns=_PROPOSED_NB_PICK_DEVICE,
        )

    e.spacer()
    e.subtitle("B) NICs and BMC / OOB")
    e.spacer()
    e.table(
        ["What", "Count", "Note"],
        [
            ["New NICs in NetBox", str(len(prop["add_nb_interfaces"])), "Runtime/MAAS fallback interface not modeled in NetBox"],
            ["NIC drift", str(len(prop["update_nic"])), "Runtime authority (OS first, MAAS fallback) differs from NetBox"],
            [
                "BMC / OOB",
                str(len(prop["add_mgmt_iface"]) + len(prop.get("add_mgmt_iface_new_devices", []))),
                "BMC runtime authority (OS first, MAAS fallback) vs NetBox",
            ],
        ],
    )
    if prop["add_nb_interfaces"]:
        e.spacer()
        e.subtitle("Detail — new NICs")
        e.spacer()
        headers = list(HEADERS_DETAIL_NEW_NICS)
        os_rows = [r for r in prop["add_nb_interfaces"] if _new_nic_row_is_os_authority(r)]
        maas_rows = [r for r in prop["add_nb_interfaces"] if not _new_nic_row_is_os_authority(r)]
        e.paragraph(
            f"Authority split: OS runtime={len(os_rows)} row(s), MAAS fallback={len(maas_rows)} row(s)."
        )
        if os_rows:
            e.spacer()
            e.subtitle("Detail — new NICs (OS authority)")
            e.spacer()
            e.table(
                headers,
                os_rows,
                dynamic_columns=True,
                wrap_max_width=None,
                selectable=True,
                selection_key="detail_new_nics_os",
                proposed_pick_columns=_PROPOSED_NB_PICK_NIC,
            )
        if maas_rows:
            e.spacer()
            e.subtitle("Detail — new NICs (MAAS authority)")
            e.spacer()
            e.table(
                headers,
                maas_rows,
                dynamic_columns=True,
                wrap_max_width=None,
                selectable=True,
                selection_key="detail_new_nics_maas",
                proposed_pick_columns=_PROPOSED_NB_PICK_NIC,
            )
    if prop["update_nic"]:
        e.spacer()
        e.subtitle("Detail — NIC drift")
        e.spacer()
        headers = list(HEADERS_DETAIL_NIC_DRIFT)
        os_rows = [r for r in prop["update_nic"] if _update_nic_row_is_os_authority(r)]
        maas_rows = [r for r in prop["update_nic"] if not _update_nic_row_is_os_authority(r)]
        e.paragraph(
            f"Authority split: OS runtime={len(os_rows)} row(s), MAAS fallback={len(maas_rows)} row(s)."
        )
        if os_rows:
            e.spacer()
            e.subtitle("Detail — NIC drift (OS runtime authority)")
            e.spacer()
            e.table(
                headers,
                os_rows,
                dynamic_columns=True,
                wrap_max_width=None,
                selectable=True,
                selection_key="detail_nic_drift_os",
                proposed_pick_columns=_PROPOSED_NB_PICK_NIC,
            )
        if maas_rows:
            e.spacer()
            e.subtitle("Detail — NIC drift (MAAS fallback authority)")
            e.spacer()
            e.table(
                headers,
                maas_rows,
                dynamic_columns=True,
                wrap_max_width=None,
                selectable=True,
                selection_key="detail_nic_drift_maas",
                proposed_pick_columns=_PROPOSED_NB_PICK_NIC,
            )

    if prop.get("add_mgmt_iface_new_devices"):
        e.spacer()
        e.subtitle("Detail — new BMC / OOB interfaces")
        e.spacer()
        e.table(
            list(HEADERS_BMC_NEW_DEVICES),
            prop["add_mgmt_iface_new_devices"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_bmc_new_devices",
            proposed_pick_columns=_PROPOSED_NB_PICK_NIC,
        )

    if prop["add_mgmt_iface"]:
        e.spacer()
        e.subtitle("Detail — existing BMC / OOB")
        e.spacer()
        e.table(
            list(HEADERS_BMC_EXISTING),
            prop["add_mgmt_iface"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_bmc_existing",
            proposed_pick_columns=_PROPOSED_NB_PICK_NIC,
        )

    e.spacer()
    e.subtitle("C) Review")
    e.spacer()
    e.table(
        ["What", "Count", "Note"],
        [
            ["Serial check", str(len(prop["review_serial"])), "NetBox serial empty"],
        ],
    )
    if prop["review_serial"]:
        e.spacer()
        e.subtitle("Detail — serials")
        e.spacer()
        e.table(
            list(HEADERS_SERIAL_REVIEW),
            prop["review_serial"],
            dynamic_columns=True,
            wrap_max_width=None,
            selectable=True,
            selection_key="detail_serial_review",
        )
    e.spacer()
    e.subtitle("Summary")
    e.spacer()
    total_props = (
        len(prop["add_devices"]) + len(prop["add_prefixes"]) + len(prop.get("update_prefixes", [])) +
        len(prop["add_fips"]) + len(prop.get("update_fips", [])) +
        len(prop.get("add_openstack_vms", [])) + len(prop.get("update_openstack_vms", [])) +
        len(prop["update_nic"]) + len(prop["add_nb_interfaces"]) +
        len(prop["add_mgmt_iface"]) + len(prop.get("add_mgmt_iface_new_devices", [])) +
        len(prop["review_serial"])
    )
    e.table(
        ["Bucket", "Count"],
        [
            ["New devices", str(len(prop["add_devices"]))],
            ["New prefixes", str(len(prop["add_prefixes"]))],
            ["Existing prefixes (drift)", str(len(prop.get("update_prefixes", [])))],
            ["New floating IPs", str(len(prop["add_fips"]))],
            ["Existing floating IPs (NAT drift)", str(len(prop.get("update_fips", [])))],
            ["New VMs (OpenStack)", str(len(prop.get("add_openstack_vms", [])))],
            ["Existing VMs (drift)", str(len(prop.get("update_openstack_vms", [])))],
            ["New NICs", str(len(prop["add_nb_interfaces"]))],
            ["NIC drift", str(len(prop["update_nic"]))],
            ["BMC / OOB", str(len(prop["add_mgmt_iface"]) + len(prop.get("add_mgmt_iface_new_devices", [])))],
            ["Serials (review)", str(len(prop["review_serial"]))],
            ["Total", str(total_props)],
        ],
    )
