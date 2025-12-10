# Sample Dry Run Output

## Example: Interface with IP Address (BLOCKED Deployment)

```
================================================================================
DRY RUN MODE - PREVIEW ONLY
================================================================================

--- Device & Platform Information ---
Device: stg1-leaf-03 (Network Leaf)
Site: B52 / Location: Staging
IP Address: 172.19.1.29
Platform: CUMULUS

--- Interface Details ---
Interface: eth0
Type: 1000base-t
Description: Management interface
Cable Status: [OK] Cabled
Connected To: stg1-mgmt-01 (Ethernet7)
Port-Channel Member: No

Validation Breakdown:
Check | Status | Details
--------------------------------------------------------------------------------
Device: automation-ready:vlan | [PASS] PASS | Device tagged as 'automation-ready:vlan' - would pass
Interface: tag check | [BLOCK] BLOCK | Interface has IP address configured (routed port) - would block deployment

Risk Assessment:
Risk Level: [HIGH] HIGH
Risk Factors:
• Interface validation failed (would block deployment)

--- Device Config Source ---
[OK] Connected to device successfully
Config fetched at: 2025-12-10 15:30:15 UTC

--- Current Device Configuration (Real from Device) ---
nv set interface eth0 ip vrf mgmt
nv set interface eth0 ip address 172.19.1.29/23
nv set interface eth0 ip address fe80::966d:aeff:fe4b:adf6/64
nv set interface eth0 ip gateway 172.19.1.254

--- Current NetBox Configuration (Source of Truth) ---
802.1Q Mode: None
Untagged VLAN: None
Tagged VLANs: []
IP Addresses: 172.19.1.29/23
VRF: mgmt
Cable Status: Connected
Connected To: stg1-mgmt-01 (Ethernet7)
Enabled: True
Port-Channel Member: False

--- Configuration Conflict Detection ---
[OK] Device config matches NetBox - no conflicts detected

Device Currently Has (from device):
nv set interface eth0 ip vrf mgmt
nv set interface eth0 ip address 172.19.1.29/23
nv set interface eth0 ip address fe80::966d:aeff:fe4b:adf6/64
nv set interface eth0 ip gateway 172.19.1.254

Device Should Have (According to NetBox):
  ip address: 172.19.1.29/23
  vrf: mgmt
  No VLAN configuration

Note: Device config matches NetBox. Both show IP address and VRF configured (routed interface).

--- Deployment Status ---
[BLOCKED] Deployment will not proceed due to validation failures above.

Current configurations are shown for reference above.
Fix blocking conditions and re-run to preview deployment changes.

Proposed configuration, diffs, and rollback information are hidden
because deployment is blocked. These will be shown once validation passes.

--- Summary Statistics ---
Total Devices: 1
Total Interfaces: 1
Would Pass: 0
Would Warn: 0
Would Block: 1

--- Next Steps ---
1. Fix interface issues (cable, tags, etc.)
2. Re-run this dry run to verify validation passes

================================================================================
Final Status: Would BLOCK deployment
================================================================================
```

## Example: Actual Conflict Between Device and NetBox (PASS - Would Deploy but with Conflict Warning)

```
================================================================================
DRY RUN MODE - PREVIEW ONLY
================================================================================

--- Device & Platform Information ---
Device: stg1-leaf-03 (Network Leaf)
Site: B52 / Location: Staging
IP Address: 172.19.1.29
Platform: CUMULUS

--- Interface Details ---
Interface: swp10
Type: 10gbase-t
Description: Server connection
Cable Status: [OK] Cabled
Connected To: server-03 (eth0)
Port-Channel Member: No

Validation Breakdown:
Check | Status | Details
--------------------------------------------------------------------------------
Device: automation-ready:vlan | [PASS] PASS | Device tagged as 'automation-ready:vlan' - would pass
Interface: tag check | [PASS] PASS | Interface tagged as 'vlan-mode:access' - would pass

--- Device Config Source ---
[OK] Connected to device successfully
Config fetched at: 2025-12-10 15:30:15 UTC

--- Current Device Configuration (Real from Device) ---
nv set interface swp10 bridge domain br_default access 3010

--- Current NetBox Configuration (Source of Truth) ---
802.1Q Mode: tagged
Untagged VLAN: 3020
Tagged VLANs: []
IP Addresses: None
VRF: None
Cable Status: Connected
Connected To: server-03 (eth0)
Enabled: True
Port-Channel Member: False

--- Configuration Conflict Detection ---
[WARN] Device config differs from NetBox config

Device Currently Has (from device):
nv set interface swp10 bridge domain br_default access 3010

Device Should Have (According to NetBox):
  bridge domain br_default access: 3020
  No IP or VRF configuration

Note: NetBox is the source of truth. Device has VLAN 3010 but NetBox shows VLAN 3020.
      Device will be updated to match NetBox + new VLAN assignment during deployment.

--- Deployment Status ---
[Would PASS validation] Deployment would proceed. Changes shown below.

--- Proposed Configuration (VLAN Deployment) ---

Device Config:
nv set interface swp10 bridge domain br_default access 3020

NetBox Config:
  802.1Q Mode: tagged → tagged
  Untagged VLAN: 3020 → 3020

--- Configuration Comparison ---

Current Configuration:
nv set interface swp10 bridge domain br_default access 3010

Proposed Configuration:
nv set interface swp10 bridge domain br_default access 3020

--- Config Diff ---
--- Current Configuration
+++ Proposed Configuration

Removed/Replaced:
  - nv set interface swp10 bridge domain br_default access 3010

Added:
  + nv set interface swp10 bridge domain br_default access 3020

--- NetBox Configuration Changes ---
--- Current NetBox State
+++ Proposed NetBox State
  802.1Q Mode: tagged → tagged (no change)
  Untagged VLAN: 3020 → 3020 (no change)
  Tagged VLANs: [] → [] (no change)
  IP Addresses: None → None (no change)
  VRF: None → None (no change)
  Cable Status: Connected → Connected (no change)
  Connected To: server-03 (eth0) → server-03 (eth0) (no change)
  Enabled: True → True (no change)
  Port-Channel Member: False → False (no change)

Rollback Plan:
Platform: Cumulus Linux (NVUE)
Auto-Rollback:
[OK] Supported: Yes (native commit-confirm)
• Method: nv config apply --confirm 90s
• Timer: 90 seconds
• Behavior: Automatically rolls back if not confirmed within 90s

Manual Rollback (if needed):
nv unset interface swp10 bridge domain br_default access
nv set interface swp10 bridge domain br_default access 3010
nv config apply

To Confirm (prevent rollback):
nv config confirm

--- Summary Statistics ---
Total Devices: 1
Total Interfaces: 1
Would Pass: 1
Would Warn: 0
Would Block: 0

--- Next Steps ---
1. Review all changes above
2. If changes look correct, proceed with actual deployment

================================================================================
Final Status: Would PASS validation
================================================================================
```

## Example: Interface Ready for Deployment (PASS - Would Deploy)

```
================================================================================
DRY RUN MODE - PREVIEW ONLY
================================================================================

--- Device & Platform Information ---
Device: stg1-leaf-03 (Network Leaf)
Site: B52 / Location: Staging
IP Address: 172.19.1.29
Platform: CUMULUS

--- Interface Details ---
Interface: swp7
Type: 10gbase-t
Description: Server connection
Cable Status: [OK] Cabled
Connected To: server-01 (eth0)
Port-Channel Member: No

Validation Breakdown:
Check | Status | Details
--------------------------------------------------------------------------------
Device: automation-ready:vlan | [PASS] PASS | Device tagged as 'automation-ready:vlan' - would pass
Interface: tag check | [PASS] PASS | Interface tagged as 'vlan-mode:access' - would pass

Risk Assessment:
Risk Level: [LOW] LOW
Risk Factors:
• All validations passed

--- Device Config Source ---
[OK] Connected to device successfully
Config fetched at: 2025-12-10 15:30:15 UTC

--- Current Device Configuration (Real from Device) ---
nv set interface swp7 bridge domain br_default access 3010

--- Current NetBox Configuration (Source of Truth) ---
802.1Q Mode: tagged
Untagged VLAN: 3010
Tagged VLANs: []
IP Addresses: None
VRF: None
Cable Status: Connected
Connected To: server-01 (eth0)
Enabled: True
Port-Channel Member: False

--- Configuration Conflict Detection ---
[OK] Device config matches NetBox - no conflicts detected

--- Deployment Status ---
[Would PASS validation] Deployment would proceed. Changes shown below.

--- Proposed Configuration (VLAN Deployment) ---

Device Config:
nv set interface swp7 bridge domain br_default access 3020

NetBox Config:
  802.1Q Mode: tagged → tagged
  Untagged VLAN: 3010 → 3020

--- Configuration Comparison ---

Current Configuration:
nv set interface swp7 bridge domain br_default access 3010

Proposed Configuration:
nv set interface swp7 bridge domain br_default access 3020

--- Config Diff ---
--- Current Configuration
+++ Proposed Configuration

Removed/Replaced:
  - nv set interface swp7 bridge domain br_default access 3010

Added:
  + nv set interface swp7 bridge domain br_default access 3020

--- NetBox Configuration Changes ---
--- Current NetBox State
+++ Proposed NetBox State
  802.1Q Mode: tagged → tagged (no change)
  Untagged VLAN: 3010 → 3020
  Tagged VLANs: [] → [] (no change)
  IP Addresses: None → None (no change)
  VRF: None → None (no change)
  Cable Status: Connected → Connected (no change)
  Connected To: server-01 (eth0) → server-01 (eth0) (no change)
  Enabled: True → True (no change)
  Port-Channel Member: False → False (no change)

Rollback Plan:
Platform: Cumulus Linux (NVUE)
Auto-Rollback:
[OK] Supported: Yes (native commit-confirm)
• Method: nv config apply --confirm 90s
• Timer: 90 seconds
• Behavior: Automatically rolls back if not confirmed within 90s

Manual Rollback (if needed):
nv unset interface swp7 bridge domain br_default access
nv config apply

To Confirm (prevent rollback):
nv config confirm

--- Summary Statistics ---
Total Devices: 1
Total Interfaces: 1
Would Pass: 1
Would Warn: 0
Would Block: 0

--- Next Steps ---
1. Review all changes above
2. If changes look correct, proceed with actual deployment

================================================================================
Final Status: Would PASS validation
================================================================================
```

## Example: Interface Changing from Routed to Bridged (PASS - Would Deploy)

```
================================================================================
DRY RUN MODE - PREVIEW ONLY
================================================================================

--- Device & Platform Information ---
Device: stg1-leaf-03 (Network Leaf)
Site: B52 / Location: Staging
IP Address: 172.19.1.29
Platform: CUMULUS

--- Interface Details ---
Interface: eth1
Type: 1000base-t
Description: Server connection
Cable Status: [OK] Cabled
Connected To: server-02 (eth0)
Port-Channel Member: No

Validation Breakdown:
Check | Status | Details
--------------------------------------------------------------------------------
Device: automation-ready:vlan | [PASS] PASS | Device tagged as 'automation-ready:vlan' - would pass
Interface: tag check | [PASS] PASS | Interface tagged as 'vlan-mode:access' - would pass

--- Device Config Source ---
[OK] Connected to device successfully
Config fetched at: 2025-12-10 15:30:15 UTC

--- Current Device Configuration (Real from Device) ---
nv set interface eth1 ip vrf mgmt
nv set interface eth1 ip address 192.168.1.10/24
nv set interface eth1 ip gateway 192.168.1.1

--- Current NetBox Configuration (Source of Truth) ---
802.1Q Mode: None
Untagged VLAN: None
Tagged VLANs: []
IP Addresses: 192.168.1.10/24
VRF: mgmt
Cable Status: Connected
Connected To: server-02 (eth0)
Enabled: True
Port-Channel Member: False

--- Configuration Conflict Detection ---
[OK] Device config matches NetBox - no conflicts detected

--- Deployment Status ---
[Would PASS validation] Deployment would proceed. Changes shown below.

--- Proposed Configuration (VLAN Deployment) ---

Device Config:
nv set interface eth1 bridge domain br_default access 3020

NetBox Config:
  802.1Q Mode: None → tagged
  Untagged VLAN: None → 3020

--- Configuration Comparison ---

Current Configuration:
nv set interface eth1 ip vrf mgmt
nv set interface eth1 ip address 192.168.1.10/24
nv set interface eth1 ip gateway 192.168.1.1

Proposed Configuration:
nv set interface eth1 bridge domain br_default access 3020

--- Config Diff ---
--- Current Configuration
+++ Proposed Configuration

Removed/Replaced:
  - nv set interface eth1 ip vrf mgmt
  - nv set interface eth1 ip address 192.168.1.10/24
  - nv set interface eth1 ip gateway 192.168.1.1

Added:
  + nv set interface eth1 bridge domain br_default access 3020

--- NetBox Configuration Changes ---
--- Current NetBox State
+++ Proposed NetBox State
  802.1Q Mode: None → tagged
  Untagged VLAN: None → 3020
  Tagged VLANs: [] → [] (no change)
  IP Addresses: 192.168.1.10/24 → None (removed - interface changing from routed to bridged)
  VRF: mgmt → None (removed - interface changing from routed to bridged)
  Cable Status: Connected → Connected (no change)
  Connected To: server-02 (eth0) → server-02 (eth0) (no change)
  Enabled: True → True (no change)
  Port-Channel Member: False → False (no change)

[WARN] IP addresses will be removed from NetBox interface (routed → bridged)
[WARN] VRF will be removed from NetBox interface (routed → bridged)

Rollback Plan:
Platform: Cumulus Linux (NVUE)
Auto-Rollback:
[OK] Supported: Yes (native commit-confirm)
• Method: nv config apply --confirm 90s
• Timer: 90 seconds
• Behavior: Automatically rolls back if not confirmed within 90s

Manual Rollback (if needed):
nv unset interface eth1 bridge domain br_default access
nv set interface eth1 ip vrf mgmt
nv set interface eth1 ip address 192.168.1.10/24
nv set interface eth1 ip gateway 192.168.1.1
nv config apply

To Confirm (prevent rollback):
nv config confirm

--- Summary Statistics ---
Total Devices: 1
Total Interfaces: 1
Would Pass: 1
Would Warn: 0
Would Block: 0

--- Next Steps ---
1. Review all changes above
2. If changes look correct, proceed with actual deployment

================================================================================
Final Status: Would PASS validation
================================================================================
```

