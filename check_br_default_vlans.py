#!/usr/bin/env python3
"""
Check br_default VLAN list from NetBox and Device

Compares NetBox data with actual device configuration.
Uses SSH proxy from dev environment configuration.

Usage:
    Run from NetBox Docker container
"""

import os
import sys
import django

# Setup Django environment
if 'DJANGO_SETTINGS_MODULE' not in os.environ:
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netbox.settings')
    django.setup()

from dcim.models import Device, Interface
from ipam.models import VLAN, IPAddress
from netbox.plugins import get_plugin_config


def find_device_by_ip(ip_address):
    """Find device by IP address"""
    try:
        ip_obj = IPAddress.objects.get(address__startswith=ip_address)
        if ip_obj.assigned_object and hasattr(ip_obj.assigned_object, 'device'):
            return ip_obj.assigned_object.device
    except IPAddress.DoesNotExist:
        pass
    
    devices = Device.objects.filter(
        primary_ip4__address__startswith=ip_address
    ) | Device.objects.filter(
        primary_ip6__address__startswith=ip_address
    )
    
    if devices.exists():
        return devices.first()
    
    return None


def get_br_default_from_device(device):
    """Query device via NAPALM to get br_default VLAN list"""
    print("\n" + "=" * 80)
    print("QUERYING DEVICE VIA NAPALM")
    print("=" * 80)
    print()
    
    try:
        # Import NAPALMDeviceManager from dev repo path
        # The dev repo should be mounted or accessible
        import sys
        import os
        
        # Try multiple possible paths
        possible_paths = [
            '/Users/irfanzq/netbox-datasource-dev',
            '/opt/netbox/netbox-datasource-dev',
            '/app/netbox-datasource-dev',
        ]
        
        dev_repo_path = None
        for path in possible_paths:
            if os.path.exists(path):
                dev_repo_path = path
                break
        
        if not dev_repo_path:
            # Try to find it relative to current location
            current_dir = os.path.dirname(os.path.abspath(__file__))
            # Go up from netbox-automation-plugin to find netbox-datasource-dev
            parent_dir = os.path.dirname(os.path.dirname(current_dir))
            potential_path = os.path.join(parent_dir, 'netbox-datasource-dev')
            if os.path.exists(potential_path):
                dev_repo_path = potential_path
        
        if dev_repo_path and dev_repo_path not in sys.path:
            sys.path.insert(0, dev_repo_path)
            print(f"Added dev repo to path: {dev_repo_path}")
        
        from netbox_automation_plugin.core.napalm_integration import NAPALMDeviceManager
        
        napalm_mgr = NAPALMDeviceManager(device)
        
        print(f"Connecting to {device.name} ({device.primary_ip4 or device.primary_ip6})...")
        print("(Using SSH proxy from plugin config if configured)")
        
        if not napalm_mgr.connect():
            print("❌ Failed to connect to device")
            return None, None
        
        print("✓ Connected successfully")
        print()
        
        # Use netmiko (raw CLI) to query NVUE
        try:
            netmiko_conn = napalm_mgr.connection.device
            
            # Query br_default VLAN list
            print("Querying bridge domain br_default VLAN list...")
            br_output = netmiko_conn.send_command("nv show bridge domain br_default vlan", use_textfsm=False)
            print(f"Raw output:\n{br_output}")
            print()
            
            # Also get full bridge domain config
            print("Getting full bridge domain configuration...")
            br_full = netmiko_conn.send_command("nv show bridge domain br_default", use_textfsm=False)
            print(f"Full bridge config:\n{br_full[:1000]}...")  # First 1000 chars
            print()
            
            # Parse VLAN list from output
            br_default_vlans = []
            import re
            
            # Parse from "nv show bridge domain br_default" output
            # Format shows:
            # Bridge Vlan Info :
            # untagged      tagged                                            
            # ------------- ---------------------------------------------------
            # 1             3019-3099
            lines = br_full.split('\n')
            in_bridge_vlan_section = False
            seen_separator = False
            
            for i, line in enumerate(lines):
                # Look for "Bridge Vlan Info" section
                if 'Bridge Vlan Info' in line:
                    in_bridge_vlan_section = True
                    continue
                
                if in_bridge_vlan_section:
                    # Skip header line
                    if 'untagged' in line.lower() and 'tagged' in line.lower():
                        continue
                    
                    # Skip separator line (all dashes)
                    if line.strip() and all(c in '- ' for c in line.strip()):
                        seen_separator = True
                        continue
                    
                    # After separator, parse data line
                    if seen_separator and line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            # First column is untagged
                            try:
                                untagged = int(parts[0])
                                if untagged not in br_default_vlans:
                                    br_default_vlans.append(untagged)
                            except ValueError:
                                pass
                            
                            # Second column is tagged (can be range like "3019-3099")
                            tagged_str = parts[1] if len(parts) > 1 else ''
                            if tagged_str:
                                # Parse ranges like "3019-3099"
                                if '-' in tagged_str:
                                    try:
                                        start, end = map(int, tagged_str.split('-'))
                                        br_default_vlans.extend(range(start, end + 1))
                                    except ValueError:
                                        pass
                                else:
                                    # Single VLAN or comma-separated
                                    for part in re.split(r'[,\s]+', tagged_str):
                                        part = part.strip()
                                        if part:
                                            try:
                                                vlan_id = int(part)
                                                if vlan_id not in br_default_vlans:
                                                    br_default_vlans.append(vlan_id)
                                            except ValueError:
                                                pass
                        # Stop after first data line
                        break
                    
                    # Check if we've moved past the VLAN info section
                    if 'Bridge Port Info' in line or ('Port' in line and 'State' in line):
                        break
            
            # Also parse from VLAN table output (shows individual VLANs)
            # Format: "3019       off        0.0.0.0    auto"
            # or "3019-3099                        auto"
            for line in br_output.split('\n'):
                line = line.strip()
                if not line or line.startswith('Vlan') or line.startswith('----'):
                    continue
                
                # Extract VLAN ID from first column
                parts = line.split()
                if parts:
                    vlan_str = parts[0]
                    if '-' in vlan_str:
                        # Range like "3019-3099"
                        try:
                            start, end = map(int, vlan_str.split('-'))
                            br_default_vlans.extend(range(start, end + 1))
                        except ValueError:
                            pass
                    else:
                        # Single VLAN
                        try:
                            vlan_id = int(vlan_str)
                            if vlan_id not in br_default_vlans:
                                br_default_vlans.append(vlan_id)
                        except ValueError:
                            pass
            
            # Remove duplicates and sort
            br_default_vlans = sorted(list(set(br_default_vlans)))
            
            # Get interface bridge domain assignments
            print("\nGetting interface bridge domain assignments...")
            interface_bridge_info = {}
            
            # Query all bond interfaces
            print("Querying bond interfaces...")
            try:
                bond_list_output = netmiko_conn.send_command("nv show interface bond", use_textfsm=False, read_timeout=10)
                print(f"Bond list:\n{bond_list_output[:500]}...")
                
                # Extract bond interface names
                bond_names = re.findall(r'bond_swp\d+', bond_list_output)
                print(f"Found bond interfaces: {bond_names[:10]}...")
                
                # Query each bond interface for bridge domain info
                for bond_name in bond_names[:32]:  # Limit to first 32
                    try:
                        bond_cmd = f"nv show interface {bond_name} bridge domain"
                        bond_info = netmiko_conn.send_command(bond_cmd, use_textfsm=False, read_timeout=5)
                        if bond_info and ('access' in bond_info or 'vlan' in bond_info.lower()):
                            # Parse access VLAN
                            access_match = re.search(r'access\s+(\d+)', bond_info)
                            access_vlan = int(access_match.group(1)) if access_match else None
                            
                            interface_bridge_info[bond_name] = {
                                'access': access_vlan,
                                'raw': bond_info[:200]  # First 200 chars
                            }
                            print(f"  {bond_name}: access={access_vlan}")
                    except Exception as e:
                        # Interface might not exist or have no config
                        pass
            except Exception as e:
                print(f"Could not query bond interfaces: {e}")
            
            # Also check swp interfaces directly
            print("\nChecking swp interfaces...")
            for i in range(1, 33):  # Check swp1-32
                try:
                    swp_cmd = f"nv show interface swp{i} bridge domain"
                    swp_info = netmiko_conn.send_command(swp_cmd, use_textfsm=False, read_timeout=3)
                    if swp_info and 'access' in swp_info:
                        access_match = re.search(r'access\s+(\d+)', swp_info)
                        if access_match:
                            interface_bridge_info[f'swp{i}'] = {
                                'access': int(access_match.group(1)),
                                'raw': swp_info[:200]
                            }
                            print(f"  swp{i}: access={access_match.group(1)}")
                except:
                    pass
            
            napalm_mgr.disconnect()
            
            return br_default_vlans, interface_bridge_info
            
        except Exception as e:
            print(f"❌ Error querying device: {e}")
            import traceback
            traceback.print_exc()
            if napalm_mgr.connection:
                napalm_mgr.disconnect()
            return None, None
            
    except ImportError as e:
        print(f"❌ Could not import NAPALMDeviceManager: {e}")
        print("Make sure netbox-datasource-dev is accessible")
        print(f"Tried path: /Users/irfanzq/netbox-datasource-dev")
        import traceback
        traceback.print_exc()
        return None, None
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def analyze_netbox_data(device):
    """Analyze NetBox interface data"""
    print("=" * 80)
    print("NETBOX DATA ANALYSIS")
    print("=" * 80)
    print()
    
    interfaces = Interface.objects.filter(device=device).select_related(
        'untagged_vlan'
    ).prefetch_related('tagged_vlans', 'ip_addresses').order_by('name')
    
    print(f"Device: {device.name}")
    print(f"IP: {device.primary_ip4 or device.primary_ip6}")
    print(f"Role: {device.role.name if device.role else 'Unknown'}")
    print(f"Total interfaces: {interfaces.count()}")
    print()
    
    # Collect VLANs
    all_tagged_vlans = set()
    all_untagged_vlans = set()
    interface_details = []
    
    print("Interfaces with VLAN assignments:")
    print("-" * 80)
    
    for iface in interfaces:
        tagged_vlans = list(iface.tagged_vlans.all())
        untagged_vlan = iface.untagged_vlan
        
        if tagged_vlans or untagged_vlan:
            all_tagged_vlans.update([v.vid for v in tagged_vlans])
            if untagged_vlan:
                all_untagged_vlans.add(untagged_vlan.vid)
            
            interface_details.append({
                'name': iface.name,
                'mode': iface.mode,
                'untagged': untagged_vlan.vid if untagged_vlan else None,
                'tagged': [v.vid for v in tagged_vlans],
            })
            
            print(f"{iface.name:20} | Mode: {iface.mode or 'None':10} | ", end='')
            if untagged_vlan:
                print(f"Untagged: {untagged_vlan.vid:5} | ", end='')
            if tagged_vlans:
                print(f"Tagged: {sorted([v.vid for v in tagged_vlans])[:10]}", end='')
                if len(tagged_vlans) > 10:
                    print(f" (+{len(tagged_vlans)-10} more)", end='')
            print()
    
    print()
    print(f"Summary:")
    print(f"  Interfaces with VLANs: {len(interface_details)}")
    print(f"  All untagged VLANs: {sorted(all_untagged_vlans)}")
    print(f"  All tagged VLANs: {sorted(all_tagged_vlans)}")
    print()
    
    return interface_details, sorted(all_tagged_vlans), sorted(all_untagged_vlans)


def main():
    device_ip = "172.19.1.26"
    
    print("=" * 80)
    print(f"BR_DEFAULT VLAN LIST ANALYSIS")
    print(f"Device IP: {device_ip}")
    print("=" * 80)
    print()
    
    # Find device
    device = find_device_by_ip(device_ip)
    if not device:
        print(f"❌ Device with IP {device_ip} not found in NetBox")
        return
    
    # Step 1: Analyze NetBox data
    netbox_interfaces, netbox_tagged, netbox_untagged = analyze_netbox_data(device)
    
    # Step 2: Query device
    device_br_default, device_interfaces = get_br_default_from_device(device)
    
    # Step 3: Compare
    print()
    print("=" * 80)
    print("COMPARISON: NETBOX vs DEVICE")
    print("=" * 80)
    print()
    
    if device_br_default:
        print(f"✅ Device br_default VLAN list: {device_br_default}")
        print(f"   Total VLANs: {len(device_br_default)}")
        print()
        
        if netbox_tagged:
            print(f"NetBox tagged VLANs: {netbox_tagged}")
            missing_in_netbox = set(device_br_default) - set(netbox_tagged)
            if missing_in_netbox:
                print(f"⚠️  VLANs in device but NOT in NetBox: {sorted(missing_in_netbox)}")
            else:
                print("✅ NetBox has all VLANs from device")
        else:
            print("❌ NetBox has NO tagged VLANs (empty)")
            print(f"   Device has {len(device_br_default)} VLANs in br_default")
    else:
        print("❌ Could not get br_default VLAN list from device")
    
    print()
    if device_interfaces:
        print("Device Interface Bridge Info:")
        for iface_name, info in device_interfaces.items():
            print(f"  {iface_name}: access={info.get('access')}")
    
    print()
    print("=" * 80)
    print("RECOMMENDATION")
    print("=" * 80)
    print()
    
    if device_br_default:
        print("✅ Device has br_default VLAN list")
        print("   Your workflow should:")
        print("   1. Deploy: nv set interface bond_swpX bridge domain br_default access <vlan>")
        print("   2. Use this VLAN list for NetBox update:")
        print(f"      - Mode: Tagged")
        print(f"      - Untagged VLAN: <user_selected_vlan>")
        print(f"      - Tagged VLANs: {device_br_default}")
        print("   3. Remove untagged VLAN from tagged list before updating NetBox")
    else:
        print("❌ Could not query device")
        print("   Check SSH proxy configuration and device connectivity")


if __name__ == '__main__':
    main()
