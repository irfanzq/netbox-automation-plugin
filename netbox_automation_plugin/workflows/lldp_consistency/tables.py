import django_tables2 as tables
from django.utils.translation import gettext_lazy as _

from dcim.models import Device, Interface
from netbox.tables import NetBoxTable, columns


class LLDPConsistencyResultTable(NetBoxTable):
    """
    Per-interface LLDP consistency results comparing Config, NetBox, and device LLDP data.
    """

    device = tables.Column(
        accessor="device",
        verbose_name=_("Device"),
        linkify=True,
    )
    interface = tables.Column(
        accessor="interface",
        verbose_name=_("Interface"),
    )
    lldp_neighbor = tables.Column(
        accessor="lldp_neighbor",
        verbose_name=_("LLDP Neighbor Device"),
    )
    lldp_port = tables.Column(
        accessor="lldp_port",
        verbose_name=_("LLDP Neighbor Port"),
    )
    netbox_peer = tables.Column(
        accessor="netbox_peer",
        verbose_name=_("NetBox Peer"),
    )
    config_description = tables.Column(
        accessor="config_description",
        verbose_name=_("Config Description"),
    )
    netbox_description = tables.Column(
        accessor="netbox_description",
        verbose_name=_("NetBox Description"),
    )
    status = tables.Column(
        accessor="status",
        verbose_name=_("Status"),
    )
    mismatch_type = tables.Column(
        accessor="mismatch_type",
        verbose_name=_("Mismatch Type"),
    )
    notes = tables.Column(
        accessor="notes",
        verbose_name=_("Notes"),
    )

    class Meta(NetBoxTable.Meta):
        model = Interface
        # We're using a dict-based row structure; the model is only for link resolution.
        fields = (
            "device",
            "interface",
            "lldp_neighbor",
            "lldp_port",
            "netbox_peer",
            "config_description",
            "netbox_description",
            "status",
            "mismatch_type",
            "notes",
        )
        default_columns = (
            "device",
            "interface",
            "lldp_neighbor",
            "lldp_port",
            "status",
            "mismatch_type",
        )


