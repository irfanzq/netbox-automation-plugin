# Check br_default VLAN List in NetBox

## How to Run

### Option 1: From NetBox Docker Container

```bash
cd /Users/irfanzq/infra-stacks/netbox
docker compose cp ../netbox-automation-plugin/check_br_default_vlans.py netbox:/tmp/
docker compose exec netbox python /tmp/check_br_default_vlans.py
```

### Option 2: From NetBox Shell

```bash
cd /Users/irfanzq/infra-stacks/netbox
docker compose exec netbox python manage.py shell < /path/to/check_br_default_vlans.py
```

## What It Checks

1. **Finds device by IP**: 172.19.1.26
2. **Analyzes all interfaces**:
   - Bond interfaces (bond_swp*)
   - SWP interfaces
   - Tagged VLANs on each interface
   - Untagged VLANs on each interface

3. **Infers br_default VLAN list**:
   - Method 1: Union of all tagged VLANs from bond interfaces
   - Method 2: Common VLANs across interfaces with mode='tagged'
   - Method 3: All VLANs found on any interface

4. **Provides recommendation**:
   - ✅ If NetBox has br_default VLAN list → use it
   - ❌ If not → need to query device via NAPALM

## Expected Output

The script will show:
- Device information
- All interfaces with their VLAN assignments
- Inferred br_default VLAN list
- Whether NetBox already has this data or needs to query device


