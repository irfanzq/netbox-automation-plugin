from netbox.plugins import PluginMenuItem

menu_items = (
    PluginMenuItem(
        link="plugins:netbox_automation_plugin:lldp_consistency_check",
        link_text="LLDP Consistency Check",
        permissions=["dcim.view_device"],
    ),
    PluginMenuItem(
        link="plugins:netbox_automation_plugin:vlan_deployment",
        link_text="VLAN Deployment",
        permissions=["dcim.change_device", "dcim.change_interface"],
    ),
    PluginMenuItem(
        link="plugins:netbox_automation_plugin:netbox_vlan_tagging",
        link_text="NetBox VLAN Tagging",
        permissions=["dcim.view_device", "dcim.view_interface", "extras.change_tag"],
    ),
)


