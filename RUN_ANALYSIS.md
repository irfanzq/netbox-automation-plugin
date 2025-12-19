# How to Run B52 Network Analysis

## Option 1: Run from NetBox Docker Container (Recommended)

```bash
# Copy script to NetBox container
cd /Users/irfanzq/infra-stacks/netbox
docker compose cp ../netbox-automation-plugin/analyze_b52_network.py netbox:/tmp/

# Run analysis
docker compose exec netbox python /tmp/analyze_b52_network.py
```

## Option 2: Run as Django Management Command

```bash
# From NetBox environment
cd /path/to/netbox
python manage.py shell < /path/to/analyze_b52_network.py
```

## Option 3: Run from NetBox Shell

```bash
# Enter NetBox shell
cd /Users/irfanzq/infra-stacks/netbox
docker compose exec netbox python manage.py shell

# Then paste the script content or import it
```

## What the Script Analyzes

1. **All active network switches in B52 location**
   - Device name, role, model, manufacturer
   - Total interfaces count

2. **Port Configuration Patterns**
   - Access ports (mode=access, has untagged_vlan)
   - Tagged ports (mode=tagged, has tagged_vlans)
   - Routed ports (has IP addresses)
   - LAG members (has lag parent)
   - LAG parents (has lag children)
   - No config ports (none of the above)

3. **Port Numbering Sequences**
   - Extracts port numbers from interface names (swp1, Ethernet7, etc.)
   - Identifies port type patterns (swp, ethernet, etc.)
   - Shows port ranges per device model

4. **Leaf-to-Spine Connections**
   - Which leaf interfaces connect to which spine interfaces
   - Interface modes and tagged VLANs on uplinks

5. **Storage Leaf Connections**
   - Storage leaf interfaces and their connections
   - Peer devices and roles
   - Interface configurations

6. **Detailed Analysis for Specific Devices**
   - se-h1-roce-leaf-3
   - se-h1-storage-leaf-2
   - Shows all interfaces with their configurations

## Output Format

The script will print:
- Device summaries with port counts
- Port numbering patterns by model
- Leaf-spine connection map
- Storage leaf connection details
- Detailed interface breakdown for target devices

## Next Steps

After running the analysis, you'll have data to:
1. Define port number ranges for access vs routed (e.g., swp1-32 = access, swp33+ = routed)
2. Understand how tagged ports are configured
3. See CLOS network topology (leaf-spine connections)
4. Make informed decisions about VLAN tagging criteria


