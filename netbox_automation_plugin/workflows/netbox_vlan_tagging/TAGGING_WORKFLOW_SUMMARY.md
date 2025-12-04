# VLAN Automation Guardrails - Tagging Workflow Summary

## Workflow Name Recommendations

**Recommended Names:**
1. **"Automation Guardrails"** (Most descriptive, matches purpose)
2. **"VLAN Readiness Tagger"** (Clear and specific)
3. **"Interface Classifier"** (Simple and direct)
4. **"AutoGuard"** (Short and catchy)
5. **"Network Safety Tagger"** (Emphasizes safety aspect)

**Suggested URL Path:** `/plugins/automation-plugin/guardrails/` or `/plugins/automation-plugin/tagging/`

---

## Overview

The **Tagging Workflow** is a **standalone** NetBox automation plugin feature that analyzes devices and interfaces based on defined criteria and applies NetBox tags accordingly. It is **completely independent** of any deployment workflows.

**Important Scope Clarification:**

This tagging workflow applies **only** to devices and interfaces that are **connected to hosts** (CPU, GPU, storage servers, and similar endpoint systems).

It does **not** perform tagging for the entire network fabric, spine switches, routers, or infrastructure-wide tagging.

A separate workflow will be designed in the future for full-network tagging across all device roles.

### Purpose
- **Port Classification**: Analyze ports based on NetBox data and device configuration
- **Automatic Tagging**: Classify and tag interfaces as access-ready, uplink, routed, or needs-review
- **Device Tagging**: Tag devices as automation-ready based on eligibility criteria
- **Bulk Analysis**: Analyze multiple devices and interfaces at once
- **Auto-Tagging**: Automatically tag most interfaces based on NetBox data (minimal human intervention)
- **Documentation**: Provide clear classification and reasoning for each tag

### Key Principle
**Tagging Workflow = Standalone Analysis & Tagging Tool**  
**No connection to deployment workflows** - purely for analyzing and tagging devices/interfaces

### Template-Based Criteria
**CRITICAL: All interface criteria are derived based on the Jinja template logic (`cumulus-4600-leaf.jinja`):**

- **Primary Check**: `interface.cable` must exist (if no cable, cannot determine purpose)
- **If cable exists**: Use `interface.connected_endpoints[0]` to get neighbor information
- **Access-ready criteria**: Matches template line 22 (cable + Host Device + active status)
- **Uplink criteria**: Matches template line 55 (cable + Spine/same role)
- **Down interfaces**: Matches template line 59 (no cable OR offline/decommissioning)

**Why this matters:**
- Ensures consistency between template generation and tagging workflow
- Uses proven logic that already works in production
- Reduces risk of misclassification
- If template considers an interface eligible, tagging workflow will tag it accordingly

---

## Main Features

### 1. Device-Level Analysis & Tagging

**Scope Reminder:**

Device-level eligibility applies **only to leaf-type devices that have host-facing connections**.

Spine switches, routers, and aggregation layers are **not** part of this workflow.

#### Tag: `automation-ready:vlan`
**Purpose**: Mark devices that are safe for VLAN automation

**Criteria for "Green" Device:**
- Device status is `active` or `staged`
- Device has primary IP configured (reachable)
- Device manufacturer/platform is supported (Mellanox/Cumulus or Arista EOS)
- Device is not in maintenance mode or decommissioning
- Device has valid credentials configured in NetBox
- **Device role check** (see below)

**Device Role Determination:**

**Primary Method (Existing Devices): Check interface connections**
- Has interfaces connected to Host Devices (GPU hosts, CPU hosts, Storage hosts) → **Automation-ready** (leaf switch)
- Only has interfaces connected to Network Spine or same role device → **NOT automation-ready** (spine switch)
- Leaf switches typically have BOTH host-facing AND uplink connections (this is normal - e.g., se-c1-intranet-leaf-1)

**Fallback Method (New Devices): Check device role name**
- **Appropriate roles**: Network Leaf, IB Leaf, Storage IB Leaf, Management Leaf
- **Inappropriate roles**: Network Spine, IB Spine, Edge Router, Cluster Edge Router
- **Generic roles**: Network Switch, Management Switch → Needs connection check

**Decision Logic:**
- **Automation-ready**: Has host-facing connections (even if also has uplinks) OR appropriate role name
- **NOT automation-ready**: ONLY has uplink connections (no host-facing) OR inappropriate role name
- **Needs review**: No connections AND generic role name

---

### 2. Interface-Level Analysis & Tagging

**Scope Reminder:**

Only **host-facing interfaces** on leaf-type switches are processed by this workflow.

Interfaces connecting to spines, routers, IB fabrics, or internal infrastructure are **not part of this tagging pipeline**.

**CRITICAL: All interface criteria START with checking if cable is present in NetBox**

**Primary Check:**
- **`interface.cable` must exist** - If no cable, cannot determine interface purpose (skip tagging or mark as needs-review)

**If `interface.cable` exists**, then `interface.connected_endpoints[0]` is available with full neighbor information:
- Connected device: `interface.connected_endpoints[0].device`
- Device role: `interface.connected_endpoints[0].device.role`
- Role parent: `interface.connected_endpoints[0].device.role.parent.name`
- Device status: `interface.connected_endpoints[0].device.status`

---

#### Tag: `vlan-mode:access` (Access Port - Single Untagged VLAN)
**Purpose**: Mark interfaces that are safe to configure as access ports with a single untagged VLAN

**Criteria (from Jinja template line 22):**
- **`interface.cable` exists** (PRIMARY CHECK - must be first)
- **`interface.connected_endpoints[0].device.role.parent.name == "Host Device"`**
  - Connected device's role parent is "Host Device" (GPU hosts, CPU hosts, Storage hosts)
- **`interface.connected_endpoints[0].device.status in ["active", "staged", "failed", "planned"]`**
  - Connected device must be in one of these statuses
- No conflicting configuration (from device config check):
  - **Arista EOS**: Not a port-channel member (interface with `channel-group` command - VLAN config must be on port-channel interface, not member interface)
  - **Arista EOS**: Not a trunk port (interface with `switchport mode trunk` command)
  - **All platforms**: Not a routed port (interface with `no switchport` on EOS, or IP address/VRF on Cumulus/Mellanox)
  
  **Note**: In Cumulus/Mellanox, bond member interfaces (like `swp1` that is part of `bond_swp1`) CAN have individual VLAN configuration - this is normal and valid, not a conflict.
- Not a management interface (not `eth0`, `mgmt0`, etc.)
- **Note**: Existing `switchport access vlan` is OK - VLAN changes are allowed on access-ready interfaces

**Platform-Specific Behavior:**
- **Cumulus/Mellanox**: Interface has **only untagged VLAN** (no tagged VLANs)
  - Untagged VLAN = per-port access VLAN (what host uses)
  - Port may be part of `br_default` bridge domain (this is normal)
  - Ports in `br_default` can have untagged VLAN configured or empty configs
  - **Tag as `vlan-mode:access`** if other criteria met (cabled + Host Device + active status)
  - Example: `mode='access'` with `untagged_vlan=3019` and no tagged VLANs → **Access-ready**

- **Arista EOS**: Access ports have only one untagged VLAN
  - **Tag as `vlan-mode:access`** (single untagged VLAN only)
  - Having both access and trunk config would be a conflict → `vlan-mode:needs-review`

**Template Reference:**
```jinja
{%- if interface.cable and interface.connected_endpoints[0].device.role.parent.name == "Host Device" and interface.connected_endpoints[0].device.status in ["active", "staged", "failed", "planned"] %}
```

**What this means:**
- Interface is classified as access port (host-facing port with single untagged VLAN)
- This is the PRIMARY tag for host-facing ports with single VLAN
- Tag indicates interface is suitable for access port configuration

---

#### Tag: `vlan-mode:tagged` (Tagged Port - Both Tagged and Untagged VLANs)
**Purpose**: Mark interfaces that have both tagged and untagged VLANs configured (Cumulus/Mellanox VLAN-aware bridge behavior)

**Criteria:**
- **`interface.cable` exists** (PRIMARY CHECK - must be first)
- **`interface.connected_endpoints[0].device.role.parent.name == "Host Device"`**
  - Connected device's role parent is "Host Device" (GPU hosts, CPU hosts, Storage hosts)
- **`interface.connected_endpoints[0].device.status in ["active", "staged", "failed", "planned"]`**
  - Connected device must be in one of these statuses
- **NetBox interface `mode='tagged'`** (802.1Q Mode = Tagged)
- **Interface has BOTH `untagged_vlan` AND `tagged_vlans`** configured in NetBox
- No conflicting configuration (from device config check):
  - **All platforms**: Not a routed port (interface with `no switchport` on EOS, or IP address/VRF on Cumulus/Mellanox)
  
  **Note**: In Cumulus/Mellanox, bond member interfaces (like `swp1` that is part of `bond_swp1`) CAN have individual VLAN configuration - this is normal and valid, not a conflict.
- Not a management interface (not `eth0`, `mgmt0`, etc.)

**Platform-Specific Behavior:**
- **Cumulus/Mellanox ONLY**: Having both tagged and untagged VLANs is **NORMAL** (VLAN-aware bridge architecture)
  - Untagged VLAN = per-port access VLAN (what host uses)
  - Tagged VLANs = part of `br_default` bridge domain (inherited by all ports)
  - **This is NOT a conflict** - tag as `vlan-mode:tagged`
  - Example: `mode='tagged'` with `untagged_vlan=3019` and `tagged_vlans=[3000,3020]` → **Tagged-ready**
  - Port being part of `br_default` bridge domain is **NORMAL** and expected
  - This matches the Jinja template behavior (line 22-43 handles both tagged and untagged)

- **Arista EOS**: **NOT applicable** - Arista access ports only support single untagged VLAN
  - Arista ports with both access and trunk config would be a conflict → `vlan-mode:needs-review`

**Template Reference:**
```jinja
{%- if interface.cable and interface.connected_endpoints[0].device.role.parent.name == "Host Device" and interface.connected_endpoints[0].device.status in ["active", "staged", "failed", "planned"] %}
```

**What this means:**
- Interface is classified as tagged port (host-facing port with both tagged and untagged VLANs)
- This is specific to Cumulus/Mellanox VLAN-aware bridge architecture
- Tag indicates interface has both untagged (access) and tagged (bridge domain) VLANs
- Used for documentation and classification purposes

---

#### Tag: `vlan-mode:uplink` (Uplink/Trunk Interface)
**Purpose**: Mark interfaces that are uplinks or trunks

**Criteria (from Jinja template line 55):**
- **`interface.cable` exists** (PRIMARY CHECK - must be first)
- **`interface.connected_endpoints[0].device.role == device.role`** OR **`interface.connected_endpoints[0].device.role.name == "Network Spine"`**
  - Connected device has same role as current device (peer switch) OR is Network Spine
- Interface is configured as trunk (tagged VLANs) - optional check from device config
- Interface is part of underlay network (BGP neighbors, EVPN uplinks) - optional check

**Template Reference:**
```jinja
{%- elif interface.cable and (interface.connected_endpoints[0].device.role == device.role or interface.connected_endpoints[0].device.role.name == "Network Spine") %}
```

**What this means:**
- Interface is classified as uplink/trunk
- Tag indicates interface is critical for network connectivity
- Used for documentation and classification purposes

---

#### Tag: `vlan-mode:routed` (Routed Interface)
**Purpose**: Mark interfaces that are routed ports

**Criteria:**
- Interface has IP address configured (routed port)
- Interface has `no switchport` configured (EOS) or is in VRF (Cumulus)
- Interface is not part of `br_default` bridge domain (Cumulus/Mellanox)
- Interface is connected to router or L3 device

**What this means:**
- Interface is classified as routed port (L3)
- Tag indicates interface is used for routing
- Used for documentation and classification purposes

---

#### Tag: `vlan-mode:needs-review` (Needs Human Review)
**Purpose**: Mark interfaces that need manual review before automation

**Criteria (ONLY these cases need human review):**

1. **Conflicting or unclear configuration (Platform-Specific)**
   - **Arista EOS**: Has both access and trunk config (conflict - access ports can't be trunks)
   - **Any platform**: Configuration state is ambiguous or unclear
   
   **Note**: In Cumulus/Mellanox, bond member interfaces CAN have individual VLAN configuration - this is normal and valid, NOT a conflict.

2. **Unknown connection type**
   - Port is empty + Cabled + NOT connected to Host Device + Cannot determine if uplink/routed/other from NetBox data

**IMPORTANT - Platform-Specific Exceptions:**
- **Cumulus/Mellanox**: Having both tagged and untagged VLANs is **NOT a conflict**
  - This is normal VLAN-aware bridge behavior
  - Interface with `mode='tagged'`, `untagged_vlan=3019`, and `tagged_vlans=[3000,3020]` → **Tag as `vlan-mode:tagged`** (NOT needs-review)
  - The untagged VLAN is the access VLAN, tagged VLANs are from the bridge domain
  - This matches the Jinja template behavior (line 22-43 handles both tagged and untagged)

**What this means:**
- Interface needs human decision to resolve conflict or determine purpose
- Tag indicates interface requires manual review
- User should review and manually tag the interface appropriately

---

### 3. Auto-Tagging Logic (Minimal Human Intervention)

**CRITICAL: All auto-tagging logic starts with checking if `interface.cable` exists**

**Most interfaces are auto-tagged automatically** - no human review needed:

#### Auto-tag as `vlan-mode:access`:
**Criteria (from Jinja template line 22):**
- **`interface.cable` exists** (PRIMARY CHECK)
- **`interface.connected_endpoints[0].device.role.parent.name == "Host Device"`**
- **`interface.connected_endpoints[0].device.status in ["active", "staged", "failed", "planned"]`**
- **Interface has ONLY untagged VLAN** (no tagged VLANs) OR **no VLAN configured**
  - **Cumulus/Mellanox**: `mode='access'` or `untagged_vlan` exists but no `tagged_vlans`
  - **Arista EOS**: `switchport mode access` with single untagged VLAN
- Port may be empty (no VLAN config) - this is OK for new ports
- **This is the PRIMARY use case** - new ports waiting for VLAN assignment
- Most ports will be like this - auto-tag as access-ready

**Template Logic:**
```jinja
{%- if interface.cable and interface.connected_endpoints[0].device.role.parent.name == "Host Device" and interface.connected_endpoints[0].device.status in ["active", "staged", "failed", "planned"] %}
```

#### Auto-tag as `vlan-mode:tagged`:
**Criteria (Cumulus/Mellanox only):**
- **`interface.cable` exists** (PRIMARY CHECK)
- **`interface.connected_endpoints[0].device.role.parent.name == "Host Device"`**
- **`interface.connected_endpoints[0].device.status in ["active", "staged", "failed", "planned"]`**
- **NetBox interface `mode='tagged'`** (802.1Q Mode = Tagged)
- **Interface has BOTH `untagged_vlan` AND `tagged_vlans`** configured in NetBox
- This is normal VLAN-aware bridge behavior → Auto-tag as `vlan-mode:tagged`

**Template Logic:**
```jinja
{%- if interface.cable and interface.connected_endpoints[0].device.role.parent.name == "Host Device" and interface.connected_endpoints[0].device.status in ["active", "staged", "failed", "planned"] %}
```

#### Auto-tag as `vlan-mode:uplink`:
**Criteria (from Jinja template line 55):**
- **`interface.cable` exists** (PRIMARY CHECK)
- **`interface.connected_endpoints[0].device.role == device.role`** OR **`interface.connected_endpoints[0].device.role.name == "Network Spine"`**
- This is an uplink → Auto-tag as `vlan-mode:uplink`

**Template Logic:**
```jinja
{%- elif interface.cable and (interface.connected_endpoints[0].device.role == device.role or interface.connected_endpoints[0].device.role.name == "Network Spine") %}
```

#### Auto-tag as `vlan-mode:routed`:
**Criteria (from device config check):**
- **`interface.cable` exists** (PRIMARY CHECK)
- Interface has IP address configured (routed port)
- Interface has `no switchport` configured (EOS) or is in VRF (Cumulus)
- Connected to router or L3 device (from `connected_endpoints[0].device.role`)
- This is a routed connection → Auto-tag as `vlan-mode:routed`

#### No tag (cannot determine - from Jinja template line 59):
**Criteria (from Jinja template line 59):**
- **`interface.cable` does NOT exist** (cannot determine purpose without cable)
  - Cannot auto-tag - requires cable information in NetBox first
  - User should add cable information, then re-run analysis
- **`interface.cable` exists BUT `interface.connected_endpoints[0].device.status in ["decommissioning", "offline"]`**
  - Cannot auto-tag - connected device is not active
  - User should update device status or wait for device to come online

**Template Logic:**
```jinja
{%- elif (('swp' in interface.name) and (not interface.cable or (interface.cable and interface.connected_endpoints[0].device.status in ["decommissioning", "offline"]))) %}
```

**Summary:**
- **Auto-tagged**: Most empty ports based on what they connect to (access, tagged, uplink, routed)
- **Needs review**: Only conflicting configs (platform-specific) or unknown connection types
  - **Cumulus/Mellanox**: Both tagged and untagged VLANs = Normal (`vlan-mode:tagged`), NOT needs-review
  - **Arista EOS**: Both access and trunk config = Conflict (needs-review)
- **No tag**: Not cabled or offline/decommissioning devices (cannot determine purpose)

---

## Detection Methods

### Method 1: NetBox Data Analysis (Primary - Based on Jinja Template)
**Use NetBox data to infer interface type (matches Jinja template logic):**

**CRITICAL: Start with cable check - this is the PRIMARY check from the template**

1. **First Check: `interface.cable` exists**
   - If `interface.cable` exists → `interface.connected_endpoints[0]` is available
   - Can get: connected device, device role, role parent, device status
   - **This is the foundation for all other checks**

2. **If cable exists, check connected device:**
   - **For access-ready**: `interface.connected_endpoints[0].device.role.parent.name == "Host Device"` AND `interface.connected_endpoints[0].device.status in ["active", "staged", "failed", "planned"]`
   - **For uplink**: `interface.connected_endpoints[0].device.role == device.role` OR `interface.connected_endpoints[0].device.role.name == "Network Spine"`

3. **Additional checks (optional, from NetBox data):**
   - Check interface `mode` field (`access`, `tagged`, `tagged-all`)
   - Check interface `untagged_vlan` and `tagged_vlans`
   - Check interface `ip_addresses` (routed ports have IPs)

**Key Point**: If a port is cabled in NetBox (`interface.cable` exists), we have ALL neighbor information via `connected_endpoints` - no need for LLDP or device queries. This matches exactly how the Jinja template determines interface eligibility.

**Advantages:**
- Fast (no device connection needed)
- Can analyze all interfaces at once
- Works for bulk tagging
- Complete neighbor info if cabled
- **NetBox is the source of truth** - devices should comply with NetBox data

**Key Behavior:**
- **"No config" ports are NOT missed** - if `interface.cable` exists + no VLAN config + remote is Host Device → Tag as `vlan-mode:access` (new port ready for VLAN assignment)
- **NetBox data is sufficient** - we don't need device-side config checks for conflict detection
- NetBox data determines the tag - devices should comply with NetBox, not the other way around

---

### Method 2: Device Configuration Check (Optional - Safety Warning)
**Note**: This method is optional but recommended for safety warnings. NetBox is the source of truth, but we should warn users if there's a mismatch.

**Purpose**: Warn users if NetBox indicates port is access-ready, but actual device configuration shows it's routed/uplink/trunk/port-channel.

**Validation Process:**
1. **NetBox analysis determines tag** (Method 1) - NetBox is source of truth
2. **Optional NAPALM query** to check actual device configuration
3. **If mismatch detected, show warning** (but still apply tag based on NetBox):
   - NetBox says: `vlan-mode:access` (cabled + Host Device + active)
   - Device config shows: Routed port (`no switchport` or IP address)
   - **Warning**: "NetBox indicates access-ready, but device shows routed port - verify NetBox data"
   - NetBox says: `vlan-mode:access` (cabled + Host Device + active)
   - Device config shows: Trunk port (`switchport mode trunk`)
   - **Warning**: "NetBox indicates access-ready, but device shows trunk port - verify NetBox data"
   - NetBox says: `vlan-mode:access` (cabled + Host Device + active)
   - Device config shows: Port-channel member (`channel-group` on Arista) or bond member interface (on Cumulus/Mellanox)
   - **Warning**: "NetBox indicates access-ready, but device shows port-channel/bond member interface - verify NetBox data"

**What to check in device config:**
- **Arista EOS**: 
  - `channel-group` → Port-channel member
  - `switchport mode trunk` → Trunk port
  - `no switchport` → Routed port
  - IP address on interface → Routed port
- **Cumulus/Mellanox**: 
  - Bond member interface (physical interface like `swp1` that is part of a bond interface like `bond_swp1`) - **Note**: Bond interfaces themselves (like `bond_swp1`) can be access-ready
  - Part of `br_default` bridge domain → **This is NORMAL** (not a conflict, counts as access-ready)
  - IP address on interface → Routed port
  - In VRF → Routed port

**Important**: 
- **NetBox is the source of truth** - tags are applied based on NetBox data
- Device config check is for **safety warnings only** - alerts user to potential NetBox data issues
- User can proceed with tagging based on NetBox, but should verify NetBox data if warnings appear
- **For Cumulus/Mellanox**: Port being part of `br_default` is normal and expected - not a conflict

---

## UI Workflow Features

### Phase 1: Analysis Mode
**Purpose**: Analyze devices and interfaces, show classification results

**Features:**
- **Device Selection**: Single device or group by Site/Location/Role/Manufacturer
- **Run Analysis**: Analyze selected devices and all their interfaces
- **Results Display**:
  - Device-level summary: Ready/Not Ready count
  - Interface-level summary: Access-ready / Tagged / Uplink / Routed / Needs Review count
  - Per-device breakdown with device status
  - Per-interface breakdown with classification and reasons
  - Visual indicators (Green, Yellow, Red)
- **Recommendations**: Suggestions for tagging based on analysis

**Output:**
- Summary report (counts, percentages)
- Per-device breakdown (device name, status, tag recommendation)
- Per-interface classification (interface name, current tag, recommended tag, criteria met/missed, reason)
- Export option (CSV/JSON) for reporting

---

### Phase 2: Tagging Mode
**Purpose**: Apply tags to devices and interfaces based on analysis

**Features:**
- **Review Analysis Results**: Display analysis from Phase 1
- **Bulk Tagging Options**:
  - Tag all devices as `automation-ready:vlan` (if criteria met)
  - Tag all interfaces as `vlan-mode:access` (if criteria met)
  - Tag all interfaces as `vlan-mode:tagged` (if criteria met - Cumulus/Mellanox only)
  - Tag all interfaces as `vlan-mode:uplink` (if criteria met)
  - Tag all interfaces as `vlan-mode:routed` (if criteria met)
  - Tag all interfaces as `vlan-mode:needs-review` (if criteria met)
- **Selective Tagging**:
  - Checkbox selection for individual devices/interfaces
  - Tag selected items only
- **Manual Override**: User can manually tag individual interfaces (override analysis)
- **Validation**: Warn if tagging conflicts with analysis (e.g., tagging uplink as access)
- **Confirmation**: Show preview of tags to be applied before committing

**Output:**
- Tags applied to NetBox (device and interface tags)
- Summary of tags applied (counts)
- List of interfaces that still need review (if any)
- Success/error messages for each tag operation

---

### Phase 3: Re-Analysis (Optional - Future)
**Purpose**: Re-analyze devices/interfaces after changes (cables added, configs updated)

**Features:**
- Re-run analysis on previously tagged devices
- Detect changes (new cables, config updates)
- Update tags automatically if criteria changed
- Show diff of tag changes

---

## Workflow Summary

### Step-by-Step Process

1. **User selects devices** (single or group by filters)
2. **Run analysis** (Phase 1)
   - Analyze device eligibility (status, IP, platform, credentials, role)
   - Analyze interface eligibility (cabled, connected device, config conflicts)
   - Classify each interface (access, tagged, uplink, routed, needs-review)
   - Generate report with recommendations
3. **Review results** (Phase 1 output)
   - Check device-level recommendations
   - Check interface-level classifications
   - Review any "needs-review" cases
4. **Apply tags** (Phase 2)
   - Bulk tag devices as `automation-ready:vlan`
   - Bulk tag interfaces as `vlan-mode:access`, `vlan-mode:tagged`, `vlan-mode:uplink`, `vlan-mode:routed`, or `vlan-mode:needs-review`
   - Manual override if needed
   - Confirm and apply tags to NetBox
5. **Tags are now in NetBox** - available for any workflow or process that needs to reference them

---

## Key Benefits

1. **Classification**: Clear classification of ports based on criteria
2. **Automation**: Most interfaces are auto-tagged (minimal human intervention)
3. **Transparency**: Clear classification with reasons for each tag
4. **Scalability**: Bulk analysis and tagging for multiple devices
5. **Documentation**: Tags serve as documentation of port purpose and status
6. **Educational**: Users learn which ports are access-ready, uplinks, routed, etc.
7. **Flexibility**: Manual override for experienced users
8. **Standalone**: Independent workflow - no dependencies on other workflows

---

## Implementation Checklist

### Core Features
- [ ] Device selection (single or group by filters)
- [ ] Device-level analysis (status, IP, platform, credentials, role)
- [ ] Interface-level analysis (cabled, connected device, config conflicts)
- [ ] Auto-tagging logic (access, tagged, uplink, routed based on connections)
- [ ] Manual tagging override
- [ ] Bulk tagging operations
- [ ] Analysis report generation
- [ ] Tag application to NetBox

### UI Components
- [ ] Analysis mode form (device selection, filters)
- [ ] Results display (summary, per-device, per-interface)
- [ ] Tagging mode form (review results, select tags to apply)
- [ ] Confirmation dialog (preview tags before applying)
- [ ] Success/error messages
- [ ] Export functionality (CSV/JSON)

### Standalone Features
- [ ] No dependencies on other workflows
- [ ] Self-contained analysis and tagging
- [ ] Export tags for use by other systems/workflows

---

## Technical Notes

### NetBox Tags Used
- **Device tag**: `automation-ready:vlan`
- **Interface tags**: `vlan-mode:access`, `vlan-mode:tagged`, `vlan-mode:uplink`, `vlan-mode:routed`, `vlan-mode:needs-review`

### Data Sources
- **Primary**: NetBox ORM (Device, Interface, Cable, VLAN models)
- **Secondary**: NAPALM (optional, for device config checks)

### Performance Considerations
- NetBox data analysis is fast (no device connections needed)
- Bulk operations should use Django ORM efficiently
- Consider pagination for large device groups
- Background jobs for very large analyses (future enhancement)

---

## Next Steps

1. **Design UI mockups** for Analysis and Tagging modes
2. **Implement Phase 1** (Analysis mode) - device and interface analysis
3. **Implement Phase 2** (Tagging mode) - tag application to NetBox
4. **Add export functionality** - CSV/JSON reports
5. **Add re-analysis feature** (optional) - detect changes and update tags
6. **Ensure independence** - no dependencies on other workflows

---

## Questions to Resolve

1. **Analysis Frequency**: Should analysis be automatic (background job) or manual (user-triggered)?
2. **Re-tagging**: How do we handle interfaces that change over time (cables added, configs updated)?
3. **Device Config Checks**: Should we use NAPALM for conflict detection, or rely on NetBox data only?
4. **Bulk Operations**: Should we support tagging entire sites/locations at once?
5. **Tag Removal**: Should we support removing tags (e.g., if device becomes unavailable)?
