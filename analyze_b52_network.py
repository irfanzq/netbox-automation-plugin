#!/usr/bin/env python3
"""
NetBox B52 Network Analysis Script

Analyzes network switches in B52 location to understand:
- Port configuration patterns (tagged vs access)
- Port naming sequences (swp, Ethernet, etc.)
- Leaf-to-spine connections
- Storage leaf connections and uplinks
- CLOS network topology

Usage:
    python manage.py shell < analyze_b52_network.py
    OR
    python analyze_b52_network.py (if run from NetBox environment)
"""

import os
import sys
import django
from collections import defaultdict, Counter
import re

# Setup Django environment
if 'DJANGO_SETTINGS_MODULE' not in os.environ:
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netbox.settings')
    django.setup()

from dcim.models import Device, Interface, Cable, CablePath
from ipam.models import IPAddress
from extras.models import Tag


def extract_port_number(interface_name):
    """Extract port number from interface name"""
    patterns = [
        (r'swp(\d+)', 'swp'),           # swp1, swp32
        (r'swp(\d+)s(\d+)', 'swp'),     # swp1s1, swp1s2
        (r'ethernet(\d+)', 'ethernet'),  # Ethernet1, Ethernet7
        (r'et(\d+)', 'ethernet'),        # Et1, Et7
        (r'gi(\d+)/\d+/(\d+)', 'gigabit'),  # GigabitEthernet1/0/1
        (r'port-channel(\d+)', 'port-channel'),  # Port-Channel7
        (r'po(\d+)', 'port-channel'),    # Po7
    ]
    
    for pattern, iface_type in patterns:
        match = re.match(pattern, interface_name.lower())
        if match:
            if iface_type == 'gigabit':
                return int(match.group(2)), iface_type  # Return sub-interface number
            return int(match.group(1)), iface_type
    return None, None


def analyze_device_interfaces(device):
    """Analyze all interfaces on a device"""
    interfaces = Interface.objects.filter(device=device).select_related(
        'untagged_vlan', 'tagged_vlans', 'lag', 'cable'
    ).prefetch_related('ip_addresses', 'tagged_vlans', 'tags')
    
    results = {
        'device': device.name,
        'role': device.role.name if device.role else 'Unknown',
        'model': device.device_type.model if device.device_type else 'Unknown',
        'manufacturer': device.device_type.manufacturer.name if device.device_type and device.device_type.manufacturer else 'Unknown',
        'total_interfaces': interfaces.count(),
        'interfaces': [],
        'port_patterns': defaultdict(int),
        'config_summary': {
            'access': 0,
            'tagged': 0,
            'routed': 0,
            'lag_member': 0,
            'lag_parent': 0,
            'no_config': 0,
            'has_cable': 0,
        }
    }
    
    for iface in interfaces:
        port_num, port_type = extract_port_number(iface.name)
        
        iface_data = {
            'name': iface.name,
            'type': iface.type,
            'port_number': port_num,
            'port_type': port_type,
            'mode': iface.mode,
            'untagged_vlan': iface.untagged_vlan.vid if iface.untagged_vlan else None,
            'tagged_vlans': [v.vid for v in iface.tagged_vlans.all()] if hasattr(iface, 'tagged_vlans') else [],
            'has_ip': iface.ip_addresses.exists(),
            'ip_addresses': [str(ip.address) for ip in iface.ip_addresses.all()],
            'is_lag_member': iface.lag is not None,
            'lag_parent': iface.lag.name if iface.lag else None,
            'is_lag_parent': Interface.objects.filter(lag=iface).exists(),
            'has_cable': iface.cable is not None,
            'description': iface.description or '',
            'tags': [tag.name for tag in iface.tags.all()],
        }
        
        # Determine configuration type
        if iface_data['has_ip']:
            config_type = 'routed'
        elif iface_data['mode'] == 'tagged' or iface_data['tagged_vlans']:
            config_type = 'tagged'
        elif iface_data['mode'] == 'access' and iface_data['untagged_vlan']:
            config_type = 'access'
        elif iface_data['is_lag_member']:
            config_type = 'lag_member'
        elif iface_data['is_lag_parent']:
            config_type = 'lag_parent'
        else:
            config_type = 'no_config'
        
        iface_data['config_type'] = config_type
        results['config_summary'][config_type] += 1
        
        if iface_data['has_cable']:
            results['config_summary']['has_cable'] += 1
        
        # Get cable peer information
        if iface.cable:
            try:
                peer_interface = iface.cable.get_peer_interface()
                if peer_interface:
                    peer_device = peer_interface.device
                    iface_data['peer_device'] = peer_device.name
                    iface_data['peer_interface'] = peer_interface.name
                    iface_data['peer_role'] = peer_device.role.name if peer_device.role else 'Unknown'
                    iface_data['peer_model'] = peer_device.device_type.model if peer_device.device_type else 'Unknown'
            except Exception as e:
                iface_data['peer_error'] = str(e)
        
        results['interfaces'].append(iface_data)
        
        # Track port patterns
        if port_type:
            results['port_patterns'][port_type] += 1
    
    return results


def analyze_leaf_spine_connections(devices):
    """Analyze how leafs connect to spines"""
    leafs = [d for d in devices if d.role and 'leaf' in d.role.name.lower()]
    spines = [d for d in devices if d.role and 'spine' in d.role.name.lower()]
    
    connections = []
    
    for leaf in leafs:
        leaf_interfaces = Interface.objects.filter(device=leaf, cable__isnull=False).select_related('cable')
        
        for iface in leaf_interfaces:
            try:
                peer = iface.cable.get_peer_interface()
                if peer and peer.device in spines:
                    connections.append({
                        'leaf': leaf.name,
                        'leaf_interface': iface.name,
                        'leaf_role': leaf.role.name if leaf.role else 'Unknown',
                        'spine': peer.device.name,
                        'spine_interface': peer.name,
                        'spine_role': peer.device.role.name if peer.device.role else 'Unknown',
                        'interface_mode': iface.mode,
                        'tagged_vlans': [v.vid for v in iface.tagged_vlans.all()] if hasattr(iface, 'tagged_vlans') else [],
                    })
            except:
                pass
    
    return connections


def analyze_storage_connections(devices):
    """Analyze storage leaf connections"""
    storage_leaves = [d for d in devices if d.role and 'storage' in d.role.name.lower()]
    
    storage_connections = []
    
    for storage_leaf in storage_leaves:
        interfaces = Interface.objects.filter(device=storage_leaf, cable__isnull=False).select_related('cable')
        
        for iface in interfaces:
            try:
                peer = iface.cable.get_peer_interface()
                if peer:
                    storage_connections.append({
                        'storage_leaf': storage_leaf.name,
                        'storage_interface': iface.name,
                        'peer_device': peer.device.name,
                        'peer_interface': peer.name,
                        'peer_role': peer.device.role.name if peer.device.role else 'Unknown',
                        'interface_mode': iface.mode,
                        'tagged_vlans': [v.vid for v in iface.tagged_vlans.all()] if hasattr(iface, 'tagged_vlans') else [],
                        'untagged_vlan': iface.untagged_vlan.vid if iface.untagged_vlan else None,
                    })
            except:
                pass
    
    return storage_connections


def main():
    """Main analysis function"""
    print("=" * 80)
    print("B52 Network Analysis - Port Configuration Patterns")
    print("=" * 80)
    print()
    
    # Get B52 site
    try:
        from dcim.models import Site
        b52_site = Site.objects.get(name='B52')
    except Site.DoesNotExist:
        print("ERROR: Site 'B52' not found in NetBox")
        print("Available sites:", [s.name for s in Site.objects.all()[:10]])
        return
    
    # Get active network switches in B52
    devices = Device.objects.filter(
        site=b52_site,
        status='active',
        device_type__manufacturer__name__in=['Arista', 'Mellanox', 'Nvidia', 'Cumulus']
    ).select_related('device_type', 'device_type__manufacturer', 'role', 'site').order_by('name')
    
    print(f"Found {devices.count()} active network switches in B52")
    print()
    
    # Analyze each device
    device_analyses = []
    for device in devices:
        print(f"Analyzing {device.name} ({device.role.name if device.role else 'Unknown'})...")
        analysis = analyze_device_interfaces(device)
        device_analyses.append(analysis)
    
    print()
    print("=" * 80)
    print("DEVICE SUMMARY")
    print("=" * 80)
    print()
    
    for analysis in device_analyses:
        print(f"\nDevice: {analysis['device']}")
        print(f"  Role: {analysis['role']}")
        print(f"  Model: {analysis['model']} ({analysis['manufacturer']})")
        print(f"  Total Interfaces: {analysis['total_interfaces']}")
        print(f"  Port Patterns: {dict(analysis['port_patterns'])}")
        print(f"  Config Summary:")
        print(f"    - Access ports: {analysis['config_summary']['access']}")
        print(f"    - Tagged ports: {analysis['config_summary']['tagged']}")
        print(f"    - Routed ports: {analysis['config_summary']['routed']}")
        print(f"    - LAG members: {analysis['config_summary']['lag_member']}")
        print(f"    - LAG parents: {analysis['config_summary']['lag_parent']}")
        print(f"    - No config: {analysis['config_summary']['no_config']}")
        print(f"    - Has cable: {analysis['config_summary']['has_cable']}")
    
    print()
    print("=" * 80)
    print("PORT NUMBERING PATTERNS")
    print("=" * 80)
    print()
    
    # Analyze port numbering patterns
    port_ranges = defaultdict(list)
    for analysis in device_analyses:
        for iface in analysis['interfaces']:
            if iface['port_number']:
                port_ranges[analysis['model']].append({
                    'name': iface['name'],
                    'number': iface['port_number'],
                    'type': iface['port_type'],
                    'config': iface['config_type'],
                })
    
    for model, ports in port_ranges.items():
        if ports:
            ports.sort(key=lambda x: x['number'])
            print(f"\n{model}:")
            print(f"  Port range: {ports[0]['number']} to {ports[-1]['number']}")
            print(f"  Port type: {ports[0]['type']}")
            print(f"  Sample ports: {', '.join([p['name'] for p in ports[:10]])}")
    
    print()
    print("=" * 80)
    print("LEAF-TO-SPINE CONNECTIONS")
    print("=" * 80)
    print()
    
    leaf_spine_conns = analyze_leaf_spine_connections(devices)
    print(f"Found {len(leaf_spine_conns)} leaf-to-spine connections")
    
    for conn in leaf_spine_conns[:20]:  # Show first 20
        print(f"\n{conn['leaf']} ({conn['leaf_interface']}) -> {conn['spine']} ({conn['spine_interface']})")
        print(f"  Mode: {conn['interface_mode']}")
        if conn['tagged_vlans']:
            print(f"  Tagged VLANs: {conn['tagged_vlans']}")
    
    print()
    print("=" * 80)
    print("STORAGE LEAF CONNECTIONS")
    print("=" * 80)
    print()
    
    storage_conns = analyze_storage_connections(devices)
    print(f"Found {len(storage_conns)} storage leaf connections")
    
    for conn in storage_conns[:20]:  # Show first 20
        print(f"\n{conn['storage_leaf']} ({conn['storage_interface']}) -> {conn['peer_device']} ({conn['peer_interface']})")
        print(f"  Peer role: {conn['peer_role']}")
        print(f"  Mode: {conn['interface_mode']}")
        if conn['tagged_vlans']:
            print(f"  Tagged VLANs: {conn['tagged_vlans']}")
        if conn['untagged_vlan']:
            print(f"  Untagged VLAN: {conn['untagged_vlan']}")
    
    print()
    print("=" * 80)
    print("DETAILED INTERFACE ANALYSIS")
    print("=" * 80)
    print()
    
    # Show detailed analysis for specific devices
    target_devices = ['se-h1-roce-leaf-3', 'se-h1-storage-leaf-2']
    
    for device_name in target_devices:
        analysis = next((a for a in device_analyses if a['device'] == device_name), None)
        if analysis:
            print(f"\n{'=' * 80}")
            print(f"Device: {device_name}")
            print(f"{'=' * 80}")
            print(f"Role: {analysis['role']}")
            print(f"Model: {analysis['model']}")
            print(f"\nInterfaces:")
            
            # Group by config type
            by_config = defaultdict(list)
            for iface in analysis['interfaces']:
                by_config[iface['config_type']].append(iface)
            
            for config_type, ifaces in sorted(by_config.items()):
                print(f"\n  {config_type.upper()} ({len(ifaces)} ports):")
                for iface in sorted(ifaces, key=lambda x: (x['port_number'] or 999, x['name'])):
                    print(f"    {iface['name']:20} | Port #{iface['port_number'] or 'N/A':>5} | Mode: {iface['mode'] or 'N/A':10} | ", end='')
                    if iface['untagged_vlan']:
                        print(f"Untagged: {iface['untagged_vlan']}", end='')
                    if iface['tagged_vlans']:
                        print(f"Tagged: {iface['tagged_vlans']}", end='')
                    if iface['has_ip']:
                        print(f"IP: {iface['ip_addresses']}", end='')
                    if iface['peer_device']:
                        print(f" -> {iface['peer_device']}/{iface['peer_interface']} ({iface['peer_role']})", end='')
                    print()
    
    print()
    print("=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)


if __name__ == '__main__':
    main()


