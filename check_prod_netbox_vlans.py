#!/usr/bin/env python3
"""
Check NetBox Production API for VLAN assignments

Uses NetBox REST API to query device and interface VLAN information.
"""

import json
import urllib.request
import urllib.parse
import ssl

# NetBox API Configuration
NETBOX_URL = "https://netbox.b52.whitefiber.internal"
API_TOKEN = "a1e5df5b9292d011baf724f08badf5518058c6cf"

# Device to check
DEVICE_IP = "172.19.1.26"
INTERFACE_NAME = "swp32"

# SSL context (disable verification for self-signed certs)
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# API Headers
headers = {
    "Authorization": f"Token {API_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

def api_request(url, params=None):
    """Make API request to NetBox"""
    if params:
        url += "?" + urllib.parse.urlencode(params)
    
    req = urllib.request.Request(url, headers=headers)
    response = urllib.request.urlopen(req, context=ssl_context)
    return json.loads(response.read().decode())


def get_device_by_ip(ip_address):
    """Find device by IP address"""
    print(f"Searching for device with IP {ip_address}...")
    
    # Try to find device by primary IP
    url = f"{NETBOX_URL}/api/dcim/devices/"
    params = {"primary_ip4": ip_address}
    
    try:
        data = api_request(url, params)
        if data.get("results"):
            return data["results"][0]
    except:
        pass
    
    # Try searching by IP address
    url = f"{NETBOX_URL}/api/ipam/ip-addresses/"
    params = {"address": ip_address}
    
    try:
        data = api_request(url, params)
        if data.get("results"):
            ip_obj = data["results"][0]
            if ip_obj.get("assigned_object_type") == "dcim.interface":
                interface_url = ip_obj["assigned_object"]["url"]
                interface_data = api_request(interface_url)
                device_url = interface_data["device"]["url"]
                return api_request(device_url)
    except:
        pass
    
    return None


def get_interface_vlans(device, interface_name):
    """Get VLAN assignments for an interface"""
    print(f"\nGetting VLAN info for interface {interface_name}...")
    
    url = f"{NETBOX_URL}/api/dcim/interfaces/"
    params = {
        "device_id": device["id"],
        "name": interface_name,
    }
    
    try:
        data = api_request(url, params)
        if data.get("results"):
            interface = data["results"][0]
            # Get full details
            detail_url = interface["url"]
            return api_request(detail_url)
    except Exception as e:
        print(f"Error: {e}")
    
    return None


def main():
    print("=" * 80)
    print("NETBOX PRODUCTION API - VLAN CHECK")
    print("=" * 80)
    print(f"NetBox URL: {NETBOX_URL}")
    print(f"Device IP: {DEVICE_IP}")
    print(f"Interface: {INTERFACE_NAME}")
    print()
    
    # Step 1: Find device
    device = get_device_by_ip(DEVICE_IP)
    if not device:
        print(f"❌ Device with IP {DEVICE_IP} not found")
        return
    
    print(f"✅ Found device: {device['name']}")
    print(f"   ID: {device['id']}")
    print(f"   Role: {device.get('device_role', {}).get('name', 'Unknown')}")
    print(f"   Platform: {device.get('platform', {}).get('name', 'Unknown')}")
    print()
    
    # Step 2: Get interface VLAN info
    interface = get_interface_vlans(device, INTERFACE_NAME)
    if not interface:
        print(f"❌ Interface {INTERFACE_NAME} not found on device {device.name}")
        return
    
    print(f"✅ Found interface: {interface['name']}")
    print(f"   ID: {interface['id']}")
    print(f"   Type: {interface.get('type', {}).get('label', 'Unknown')}")
    print(f"   Mode: {interface.get('mode', {}).get('label', 'None')}")
    print()
    
    # Step 3: Get VLAN assignments
    print("=" * 80)
    print("VLAN ASSIGNMENTS")
    print("=" * 80)
    
    untagged_vlan_obj = interface.get("untagged_vlan")
    tagged_vlan_objs = interface.get("tagged_vlans", [])
    
    if untagged_vlan_obj:
        # untagged_vlan_obj can be a dict with 'id' or just an int
        if isinstance(untagged_vlan_obj, dict):
            untagged_vlan_id = untagged_vlan_obj.get('id')
            untagged_vlan = untagged_vlan_obj  # Already have full object
        else:
            untagged_vlan_id = untagged_vlan_obj
            untagged_vlan = api_request(f"{NETBOX_URL}/api/ipam/vlans/{untagged_vlan_id}/")
        print(f"Untagged VLAN:")
        print(f"  ID: {untagged_vlan['id']}")
        print(f"  VID: {untagged_vlan['vid']}")
        print(f"  Name: {untagged_vlan.get('name', 'N/A')}")
    else:
        print("Untagged VLAN: None")
        untagged_vlan = None
    
    print()
    
    if tagged_vlan_objs:
        print(f"Tagged VLANs: {len(tagged_vlan_objs)} VLANs")
        tagged_vlans = []
        for vlan_obj in tagged_vlan_objs:
            # vlan_obj can be a dict with 'id' or just an int
            if isinstance(vlan_obj, dict):
                vlan = vlan_obj  # Already have full object
            else:
                vlan = api_request(f"{NETBOX_URL}/api/ipam/vlans/{vlan_obj}/")
            tagged_vlans.append(vlan)
            print(f"  - VID {vlan['vid']}: {vlan.get('name', 'N/A')}")
    else:
        print("Tagged VLANs: None")
        tagged_vlans = []
    
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Interface: {interface['name']}")
    print(f"Mode: {interface.get('mode', {}).get('label', 'None')}")
    print(f"Untagged VLAN: {untagged_vlan['vid'] if untagged_vlan else 'None'}")
    print(f"Tagged VLANs: {len(tagged_vlans)} VLANs")
    
    if tagged_vlans:
        vlan_vids = sorted([v['vid'] for v in tagged_vlans])
        print(f"Tagged VLAN IDs: {vlan_vids}")
        if len(vlan_vids) <= 10:
            print(f"All tagged VLANs: {vlan_vids}")
        else:
            print(f"First 10: {vlan_vids[:10]}...")
            print(f"Last 10: ...{vlan_vids[-10:]}")
    
    print()
    print("=" * 80)
    print("COMPARISON WITH DEVICE")
    print("=" * 80)
    print("From device query (earlier):")
    print("  - br_default VLANs: 1 (untagged) + 3019-3099 (tagged) = 82 VLANs")
    print("  - swp32 access VLAN: 3019")
    print()
    print("From NetBox API (production):")
    print(f"  - Untagged VLAN: {untagged_vlan['vid'] if untagged_vlan else 'None'}")
    print(f"  - Tagged VLANs: {len(tagged_vlans)} VLANs")
    
    if len(tagged_vlans) < 81:
        print()
        print("⚠️  WARNING: NetBox is missing tagged VLANs!")
        print(f"   Expected: 81 tagged VLANs (3019-3099)")
        print(f"   Found: {len(tagged_vlans)} tagged VLANs")
        print()
        print("   This confirms that NetBox does NOT store the full br_default VLAN list.")
        print("   Your workflow must query the device to get the complete list.")


if __name__ == '__main__':
    main()

