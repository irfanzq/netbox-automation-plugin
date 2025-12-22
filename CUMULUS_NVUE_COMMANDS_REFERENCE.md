# Cumulus NVUE Commands Used in VLAN Deployment Workflow

This document lists all Cumulus Linux NVUE (`nv`) commands used in the VLAN deployment workflow, organized by purpose.

---

## 1. Configuration Reading Commands

### `nv config show -o json`
**Purpose:** Get complete device configuration in JSON format  
**Used in:**
- `_get_current_device_config()` - Primary method to read device config
- `_get_bond_interface_for_member()` - Check bond membership from device config
- `_deploy_config_to_device()` - Verify config after deployment
- `_check_interface_traffic_stats()` - Get interface stats (indirectly)

**Location:** `views.py` lines 861, 4409, 4830, 4832

**Example:**
```bash
nv config show -o json
```

### `nv config show`
**Purpose:** Get device configuration in YAML format (fallback method)  
**Used in:**
- `_get_current_device_config()` - Fallback when JSON parsing fails
- Used with grep for interface-specific config: `nv config show | grep -A15 -B15 {interface_name}`

**Location:** `views.py` lines 877, 963

**Example:**
```bash
nv config show
nv config show | grep -A15 -B15 swp1
```

### `nv show interface {interface} link stats -o json`
**Purpose:** Get interface traffic statistics (packet counters) in JSON format  
**Used in:**
- `_check_interface_traffic_stats()` - Pre-deployment and post-deployment traffic checks
- Runs 3 times with 1-second intervals to detect active traffic flow

**Location:** `views.py` line 4573

**Example:**
```bash
nv show interface swp1 link stats -o json
nv show interface bond3 link stats -o json
```

---

## 2. VLAN Configuration Commands

### `nv set bridge domain br_default vlan add {vlan_id}`
**Purpose:** Add VLAN to bridge domain (additive, safe - won't remove existing VLANs)  
**Used in:**
- `_generate_config_from_netbox()` - Add tagged VLANs to bridge
- `_generate_vlan_config()` - Add VLAN to bridge before setting interface access
- Normal mode and sync mode VLAN deployment

**Location:** `views.py` lines 2392, 4719

**Example:**
```bash
nv set bridge domain br_default vlan add 3010
nv set bridge domain br_default vlan add 3020
```

**Note:** This is **additive** - it adds the VLAN to the existing list without removing others.

### `nv set interface {interface} bridge domain br_default access {vlan_id}`
**Purpose:** Set untagged (access) VLAN on an interface  
**Used in:**
- `_generate_config_from_netbox()` - Set access VLAN from NetBox config
- `_generate_vlan_config()` - Set access VLAN for normal deployment
- All deployment modes (normal, sync, dry run display)

**Location:** `views.py` lines 2398, 4722, 1278, 1283, 1371, 1382, 1440

**Example:**
```bash
nv set interface swp1 bridge domain br_default access 3010
nv set interface bond3 bridge domain br_default access 3060
```

**Note:** For bond members, this is applied to the bond interface, not the physical member.

---

## 3. Bond Interface Configuration Commands

### `nv set interface {bond_name} type bond`
**Purpose:** Create or configure a bond interface  
**Used in:**
- `_generate_vlan_config()` - When bond migration is needed (NetBox has `bond_swp3` but device has `bond3`)

**Location:** `views.py` line 4708

**Example:**
```bash
nv set interface bond_swp3 type bond
nv set interface bond3 type bond
```

### `nv set interface {bond_name} bond member {member_interface}`
**Purpose:** Add a physical interface as a member of a bond  
**Used in:**
- `_generate_vlan_config()` - When migrating bond members from old bond to new bond name

**Location:** `views.py` line 4712

**Example:**
```bash
nv set interface bond_swp3 bond member swp1
nv set interface bond_swp3 bond member swp2
nv set interface bond_swp3 bond member swp3
```

### `nv set interface {bond_name} bridge domain br_default`
**Purpose:** Add bond interface to bridge domain  
**Used in:**
- `_generate_vlan_config()` - When creating new bond during migration

**Location:** `views.py` line 4715

**Example:**
```bash
nv set interface bond_swp3 bridge domain br_default
```

---

## 4. Configuration Application Commands

### `nv config apply --confirm {timeout}s`
**Purpose:** Apply pending configuration with auto-rollback timer  
**Used in:**
- `_deploy_config_to_device()` - Safe deployment with commit-confirm workflow
- Default timeout: 90 seconds
- If not confirmed within timeout, automatically rolls back

**Location:** `views.py` line 4750, `napalm_integration.py` (handled by NAPALM)

**Example:**
```bash
nv config apply --confirm 90s
```

**Note:** This is handled automatically by NAPALM's `commit_config()` method.

### `nv config confirm`
**Purpose:** Confirm the applied configuration (prevents auto-rollback)  
**Used in:**
- `_deploy_config_to_device()` - After successful verification
- Called automatically after baseline verification passes

**Location:** `napalm_integration.py` (handled by NAPALM)

**Example:**
```bash
nv config confirm
```

### `nv config abort`
**Purpose:** Abort pending configuration (manual rollback)  
**Used in:**
- `_generate_rollback_info()` - Documented in rollback instructions
- Manual rollback option if auto-rollback doesn't trigger

**Location:** `views.py` line 1941

**Example:**
```bash
nv config abort
```

---

## 5. Configuration Status and History Commands

### `nv config pending`
**Purpose:** Check if there are pending configuration changes  
**Used in:**
- `napalm_integration.py` - Verify rollback was successful
- Checks if rollback removed all pending changes

**Location:** `napalm_integration.py` line 838

**Example:**
```bash
nv config pending
```

### `nv config history`
**Purpose:** View configuration revision history  
**Used in:**
- `_generate_rollback_info()` - Show rollback instructions
- `napalm_integration.py` - Get revision number for diff

**Location:** `views.py` lines 1963, `napalm_integration.py` lines 1098, 1117, 1405, 1592, 1605, 1769, 1782, 1900

**Example:**
```bash
nv config history
nv config history | head -1
nv config history | grep -i applied | head -1
```

### `nv config diff {revision_id}`
**Purpose:** Show differences between current config and a previous revision  
**Used in:**
- `_generate_rollback_info()` - Show how to view config diff
- `napalm_integration.py` - Get actual diff output for rollback verification

**Location:** `views.py` lines 1966, `napalm_integration.py` lines 1108, 1125

**Example:**
```bash
nv config diff 270
```

### `nv config apply {revision_id}`
**Purpose:** Apply a previous configuration revision (rollback)  
**Used in:**
- `_generate_rollback_info()` - Manual rollback instructions
- `napalm_integration.py` - Rollback to previous revision

**Location:** `views.py` line 1969, `napalm_integration.py` (referenced in rollback logic)

**Example:**
```bash
nv config apply 270
```

---

## 6. Configuration Removal Commands

### `nv unset interface {interface} bridge domain br_default access`
**Purpose:** Remove access VLAN configuration from an interface  
**Used in:**
- `_generate_rollback_info()` - Manual rollback instructions
- Remove VLAN configuration if needed

**Location:** `views.py` lines 1954, 1958

**Example:**
```bash
nv unset interface swp1 bridge domain br_default access
```

---

## Command Usage Summary by Workflow Stage

### **Dry Run Mode:**
1. `nv config show -o json` - Read current config
2. `nv show interface {interface} link stats -o json` - Check traffic (3x with 1s intervals)
3. Display proposed commands (not executed):
   - `nv set bridge domain br_default vlan add {vlan}`
   - `nv set interface {interface} bridge domain br_default access {vlan}`

### **Normal Deployment Mode:**
1. `nv config show -o json` - Read current config (baseline)
2. `nv show interface {interface} link stats -o json` - Pre-deployment traffic check
3. Execute VLAN config:
   - `nv set bridge domain br_default vlan add {vlan}`
   - `nv set interface {interface} bridge domain br_default access {vlan}`
4. `nv config apply --confirm 90s` - Apply with auto-rollback
5. `nv show interface {interface} link stats -o json` - Post-deployment traffic check
6. `nv config confirm` - Confirm if verification passes
7. `nv config abort` - Auto-rollback if verification fails

### **Sync Mode Deployment:**
1. `nv config show -o json` - Read current config
2. `nv show interface {interface} link stats -o json` - Pre-deployment traffic check
3. Execute bond migration (if needed):
   - `nv set interface {bond_name} type bond`
   - `nv set interface {bond_name} bond member {member}` (for each member)
   - `nv set interface {bond_name} bridge domain br_default`
4. Execute VLAN config:
   - `nv set bridge domain br_default vlan add {vlan}`
   - `nv set interface {interface} bridge domain br_default access {vlan}`
5. `nv config apply --confirm 90s` - Apply with auto-rollback
6. `nv show interface {interface} link stats -o json` - Post-deployment traffic check
7. `nv config confirm` - Confirm if verification passes

### **Rollback/Recovery:**
1. `nv config abort` - Immediate abort
2. `nv config history` - View revision history
3. `nv config diff {rev_id}` - View differences
4. `nv config apply {rev_id}` - Apply previous revision
5. `nv config pending` - Verify no pending changes

---

## Important Notes

1. **Additive VLAN Commands:** Always use `vlan add` instead of `vlan` to avoid overwriting the entire VLAN list
2. **Bond Handling:** For bond members, VLAN config is applied to the bond interface, not the physical member
3. **JSON Output:** Always use `-o json` flag for reliable parsing of command output
4. **Traffic Checks:** Run `nv show interface link stats` 3 times with 1-second intervals to detect active traffic
5. **Commit-Confirm:** Always use `--confirm {timeout}s` for safe deployment with auto-rollback
6. **Bridge Domain:** All VLANs are added to `br_default` bridge domain (Cumulus default)

---

## Command Categories

| Category | Commands | Count |
|----------|----------|-------|
| **Configuration Reading** | `nv config show`, `nv show interface link stats` | 2 |
| **VLAN Configuration** | `nv set bridge domain vlan add`, `nv set interface bridge domain access` | 2 |
| **Bond Configuration** | `nv set interface type bond`, `nv set interface bond member`, `nv set interface bridge domain` | 3 |
| **Config Application** | `nv config apply --confirm`, `nv config confirm`, `nv config abort` | 3 |
| **Status/History** | `nv config pending`, `nv config history`, `nv config diff`, `nv config apply {rev}` | 4 |
| **Removal** | `nv unset interface bridge domain access` | 1 |
| **TOTAL** | | **15 unique commands** |

---

*Last Updated: Based on codebase analysis of VLAN Deployment Workflow*

