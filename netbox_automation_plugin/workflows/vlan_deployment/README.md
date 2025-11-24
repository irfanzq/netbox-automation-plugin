# VLAN Deployment Workflow

## Overview
This workflow deploys VLAN configurations to network devices and updates NetBox interface assignments.

**Supported Platforms:**
- **Cumulus Linux** (NVUE) - Nvidia/Mellanox switches
- **Arista EOS** - Arista switches

**Phase 1 Features:**
- Single VLAN assignment (access mode/untagged only)
- Deploy to single device or device group (by site + role)
- Multi-platform support (auto-detects Cumulus vs EOS)
- Dry run mode for previewing changes
- Automatic NetBox interface VLAN assignment updates
- CSV export of deployment results

## Files Created
All files are **environment-agnostic** and can be copied directly to production:

```
workflows/vlan_deployment/
├── __init__.py          # Workflow package exports
├── forms.py             # Django form for UI (device/VLAN selection)
├── views.py             # Main workflow logic
├── tables.py            # Results table definition
└── README.md            # This file
```

## Integration Points

### 1. Uses Core Modules
The workflow uses `NAPALMDeviceManager` from `core/napalm_integration.py` for device connections and configuration deployment. All connection logic is handled in the core module, keeping workflow files environment-agnostic.

### 2. Platform-Specific Commands

**Cumulus Linux (NVUE):**
```bash
nv set interface <interface> bridge domain br_default access <vlan_id>
nv config apply
```

**Arista EOS:**
```
interface <interface>
switchport mode access
switchport access vlan <vlan_id>
```

The workflow automatically detects the device platform using NetBox device type/manufacturer information and generates the appropriate commands.

### 3. NetBox Updates
After successful deployment, updates NetBox interface:
- Sets `mode = 'access'`
- Sets `untagged_vlan = <selected_vlan>`

## TODO: Implementation Required

### In `views.py` - `_deploy_config_to_device()` method (lines 213-268)

You need to implement the actual config deployment using your `NornirDeviceManager` capabilities.

**Current implementation:**
The method already handles platform-specific command generation:
- **Cumulus**: Generates NVUE commands + `nv config apply`
- **EOS**: Generates interface config commands

**What needs implementation:**
The actual command execution is currently a placeholder. You need to add the command execution logic based on your `NornirDeviceManager` capabilities.

**Suggested implementation:**

```python
# In _deploy_config_to_device method, replace the TODO section with:

# Execute commands using Nornir
# Option 1: If you have a send_commands method
result = manager.send_commands(device_name=device_name, commands=commands)

if result.get(device_name, {}).get("failed"):
    return {
        "success": False,
        "error": result[device_name].get("error", "Command execution failed")
    }

return {"success": True, "error": None}
```

**Alternative using NAPALM config methods:**
```python
# If using NAPALM's load_merge_candidate
config_text = "\n".join(commands)
result = manager.load_config(
    device_name=device_name,
    config=config_text,
    replace=False
)

if not result.get(device_name, {}).get("failed"):
    commit_result = manager.commit_config(device_name=device_name)
    if commit_result.get(device_name, {}).get("failed"):
        return {"success": False, "error": "Commit failed"}
    return {"success": True, "error": None}
else:
    return {"success": False, "error": result[device_name].get("error")}
```

## Usage

### UI Access
After NetBox restart, the workflow will appear in the Plugins menu:
- **Plugins → VLAN Deployment**

### Workflow Steps
1. Select deployment scope (single device or group)
2. Choose VLAN from NetBox VLANs
3. Enter interface names (comma-separated, e.g., `bond1,bond2,bond3`)
4. Enable/disable dry run mode
5. Enable/disable NetBox updates
6. Click "Deploy VLAN" or "Deploy & Download CSV"

### Example Use Cases

**Single Cumulus Device:**
- Scope: Single Device
- Device: spruce-leaf-01 (Cumulus/Nvidia)
- VLAN: VLAN 100 (Tenant Network)
- Interfaces: bond1,bond2,bond3
- Dry Run: Yes (preview first)
- Result: Generates `nv set interface bond1 bridge domain br_default access 100`

**Single EOS Device:**
- Scope: Single Device
- Device: core-switch-01 (Arista EOS)
- VLAN: VLAN 200 (Management)
- Interfaces: Ethernet1,Ethernet2
- Dry Run: Yes
- Result: Generates EOS switchport commands

**Device Group (Mixed Platforms):**
- Scope: Device Group
- Site: Spruce
- Role: Network Leaf
- VLAN: VLAN 100
- Interfaces: bond1,bond2
- Dry Run: No
- Update NetBox: Yes
- Result: Automatically applies correct commands based on each device's platform

## Future Enhancements (Phase 2+)
- Trunk mode support (tagged VLANs)
- Multiple VLAN assignment
- VLAN range support
- Configuration templates
- Rollback capability
- Scheduled deployments

