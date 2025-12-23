# Baseline Collection Commands and Parsing

## Overview
Baseline collection gathers interface state information before deployment to detect traffic, verify connectivity, and compare pre/post deployment states.

## For Cumulus Devices (Primary Method - Direct NVUE)

### Commands Executed

1. **Bond Membership Check**
   ```bash
   nv show interface bond-members -o json
   ```
   - **Purpose**: Determine if the interface is a bond member or bond interface
   - **Parsing**: 
     - Parse JSON response
     - Check if `interface_name` is a key in the response
     - Extract bond name from `parent` or `bond` field
     - Also performs reverse lookup to find bond members if interface is a bond

2. **Interface Statistics**
   ```bash
   nv show interface {interface_name} link stats -o json
   ```
   - **Purpose**: Get packet counters and verify interface exists
   - **Parsing**:
     ```python
     stats_data = json.loads(stats_output)
     in_pkts = stats_data.get('in-pkts', 0)
     out_pkts = stats_data.get('out-pkts', 0)
     in_bytes = stats_data.get('in-bytes', 0)
     out_bytes = stats_data.get('out-bytes', 0)
     in_drops = stats_data.get('in-drops', 0)
     out_drops = stats_data.get('out-drops', 0)
     in_errors = stats_data.get('in-errors', 0)
     out_errors = stats_data.get('out-errors', 0)
     ```

3. **Interface Link State**
   ```bash
   nv show interface {interface_name} link -o json
   ```
   - **Purpose**: Get operational and administrative status
   - **Parsing**:
     ```python
     link_data = json.loads(link_output)
     link_info = link_data.get('link', {})
     is_up = link_info.get('oper-status') == 'up'
     is_enabled = link_info.get('admin-status') == 'up'
     ```

4. **Interface Description (Optional)**
   ```bash
   nv show interface {interface_name} description -o json
   ```
   - **Purpose**: Get interface description
   - **Parsing**:
     ```python
     desc_data = json.loads(desc_output)
     description = desc_data.get('link', {}).get('description', '')
     ```

### Parsing Flow for Cumulus

```python
# Step 1: Try multiple interface names (member interface, bond interface)
interfaces_to_try = [interface_name]

# Step 2: Check bond membership
bond_members_output = device.send_command('nv show interface bond-members -o json')
bond_members = json.loads(bond_members_output)

# Step 3: For each interface to try:
for test_interface in interfaces_to_try:
    # Get stats (verifies interface exists)
    stats_output = device.send_command(f'nv show interface {test_interface} link stats -o json')
    stats_data = json.loads(stats_output)
    
    # Get link state
    link_output = device.send_command(f'nv show interface {test_interface} link -o json')
    link_data = json.loads(link_output)
    link_info = link_data.get('link', {})
    
    # Extract data
    baseline['interface'] = {
        'name': test_interface,
        'is_up': link_info.get('oper-status') == 'up',
        'is_enabled': link_info.get('admin-status') == 'up',
        'in_pkts': stats_data.get('in-pkts', 0),
        'out_pkts': stats_data.get('out-pkts', 0),
        # ... other fields
    }
```

## For Non-Cumulus Devices (Fallback Method - NAPALM)

### Method Called

```python
interfaces_before = self.get_interfaces()
```

This calls NAPALM's `get_interfaces()` method, which is platform-specific:

### For Cumulus (when direct NVUE fails)

NAPALM's Cumulus driver uses:
1. **Interface MAC Information**
   ```bash
   nv show interface mac -o json
   ```
   - **Parsing**: Extracts `link.admin-status`, `link.oper-status`, `link.speed`, `link.mac-address`, `link.mtu`

2. **Interface Description**
   ```bash
   nv show interface description -o json
   ```
   - **Parsing**: Extracts `link.description`

### For Other Platforms

NAPALM uses platform-specific methods:
- **Juniper**: Uses NETCONF/RPC calls
- **Arista EOS**: Uses `show interfaces` commands
- **Cisco**: Uses `show interfaces` commands

## Complete Baseline Collection Process

### Phase 0.5: Baseline Collection

1. **Interface State Collection** (Mandatory)
   - For Cumulus: Direct NVUE commands (as shown above)
   - For others: NAPALM `get_interfaces()`
   - **Result**: `baseline['interface']` dictionary

2. **LLDP Neighbors Collection** (Optional, if `'lldp' in checks`)
   ```python
   lldp_before = self.get_lldp_neighbors()
   ```
   - **Method**: NAPALM's `get_lldp_neighbors()`
   - **Parsing**: Counts neighbors per interface
   - **Result**: `baseline['lldp_neighbors']` and `baseline['lldp_all_interfaces']`

3. **System Facts Collection** (Optional)
   ```python
   facts_before = self.get_facts()
   ```
   - **Method**: NAPALM's `get_facts()`
   - **Parsing**: Extracts `uptime` and `hostname`
   - **Result**: `baseline['uptime']` and `baseline['hostname']`

## JSON Response Examples

### Bond Members Response
```json
{
  "swp3": {
    "link": {
      "admin-status": "up",
      "mtu": 9000,
      "oper-status": "up",
      "speed": "100G"
    },
    "parent": "bond3"
  },
  "swp4": {
    "link": {
      "admin-status": "up",
      "mtu": 9000,
      "oper-status": "down"
    },
    "parent": "bond4"
  }
}
```

**Parsing Logic:**
```python
bond_members = json.loads(bond_members_output)
if interface_name in bond_members:
    member_info = bond_members[interface_name]  # Gets {"link": {...}, "parent": "bond3"}
    bond_name = member_info.get('parent')  # Extracts "bond3"
```

### Interface Stats Response
```json
{
  "carrier-down-count": 5,
  "carrier-transitions": 11,
  "carrier-up-count": 6,
  "in-bytes": 10393902452,
  "in-drops": 35992,
  "in-errors": 0,
  "in-pkts": 23730476,
  "out-bytes": 31354616949,
  "out-drops": 59141989,
  "out-errors": 0,
  "out-pkts": 134593634
}
```

**Parsing Logic:**
```python
stats_data = json.loads(stats_output)  # Stats are at top level
in_pkts = stats_data.get('in-pkts', 0)  # Direct access: 23730476
out_pkts = stats_data.get('out-pkts', 0)  # Direct access: 134593634
# ... other fields accessed directly
```

### Interface Link Response
**Actual structure** (verified):
```json
{
  "admin-status": "up",
  "auto-negotiate": "off",
  "duplex": "full",
  "flag": {
    "broadcast": {},
    "lower-up": {},
    "master": {},
    "multicast": {},
    "up": {}
  },
  "mac-address": "9c:05:91:42:38:68",
  "mtu": 9000,
  "oper-status": "up",
  "oper-status-last-change": "2025/11/10 17:07:52.187",
  "protodown": "disabled",
  "speed": "100G",
  "state": {
    "up": {}
  },
  "stats": {
    "carrier-down-count": 5,
    "carrier-transitions": 11,
    "carrier-up-count": 6,
    "in-bytes": 10394264353,
    "in-drops": 35994,
    "in-errors": 0,
    "in-pkts": 23731388,
    "out-bytes": 31355951324,
    "out-drops": 59144287,
    "out-errors": 0,
    "out-pkts": 134598643
  }
}
```

**Parsing Logic:**
```python
link_data = json.loads(link_output)
# Fields are at TOP LEVEL, not nested under "link" key
is_up = link_data.get('oper-status') == 'up'  # Direct access: "up"
is_enabled = link_data.get('admin-status') == 'up'  # Direct access: "up"
```

**Important Notes:**
- Fields like `oper-status`, `admin-status`, `speed`, `mtu`, `mac-address` are at the **top level**
- Stats are nested under `"stats"` key in this output, but we use a separate `link stats` command which returns stats at top level
- The `nv show interface {interface} link -o json` command returns all link info including stats nested
- The `nv show interface {interface} link stats -o json` command returns only stats at top level

## Error Handling

All commands use:
- `read_timeout=10` seconds
- JSON parsing with error handling
- Multiple interface name attempts (member → bond, bond → member)
- Detailed error messages showing what was tried

## Key Code Locations

- **Cumulus Direct NVUE**: `napalm_integration.py` lines 1097-1239
- **NAPALM Fallback**: `napalm_integration.py` lines 1244-1419
- **LLDP Collection**: `napalm_integration.py` lines 1421-1454
- **Facts Collection**: `napalm_integration.py` lines 1456-1473
- **NAPALM get_interfaces()**: Calls `self.connection.get_interfaces()` which uses platform-specific driver
- **Cumulus NAPALM Driver**: `napalm-cumulus/napalm_cumulus/cumulus.py` lines 424-456

