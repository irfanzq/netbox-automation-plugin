# Test Checklist: VLAN Deployment Fixes Verification

## Overview
This checklist verifies that all fixes for normal mode VLAN deployment are working correctly, especially for bond interface scenarios.

---

## Pre-Test Setup

### Test Scenario
- **Device**: Cumulus Linux switch with bond interface
- **Interface**: `swp3` (member of `bond3`)
- **VLAN**: 3010
- **NetBox State**: 
  - Interface `swp3` exists in NetBox
  - Bond `bond3` may or may not exist in NetBox (test both cases)

### Test Data
- Device name: `stg1-leaf-04` (or your test device)
- Member interface: `swp3`
- Bond interface: `bond3`
- VLAN ID: `3010`

---

## Test Checklist

### ✅ Issue 1 & 4: Bond Interface Name Usage

**Test**: Verify that when bond is detected, all commands use `bond3` instead of `swp3`

#### Checkpoints:

1. **Bond Detection Logs**
   - [ ] Look for: `[DEBUG] ✓ BOND DETECTED: Device X: Interface swp3 is member of bond bond3`
   - [ ] Look for: `[DEBUG] Will use bond interface 'bond3' for device config (instead of 'swp3')`
   - [ ] Verify bond_info_map is built: `[DEBUG] Bond info map created: {'device_name': {'swp3': 'bond3'}}`

2. **Config Generation Logs**
   - [ ] Look for: `[DEBUG] ✓ CONFIG GENERATION: Device X: Using BOND interface 'bond3' (member: 'swp3')`
   - [ ] Verify generated commands show `bond3`:
     ```
     [DEBUG]   1. nv set bridge domain br_default vlan 3010
     [DEBUG]   2. nv set interface bond3 bridge domain br_default access 3010
     ```

3. **Phase 1: Configuration Loading**
   - [ ] Check log: `[Phase 1] Configuration Loading`
   - [ ] Verify `Config to load:` shows BOTH commands:
     ```
     nv set bridge domain br_default vlan 3010
     nv set interface bond3 bridge domain br_default access 3010
     ```
   - [ ] **NOT** just: `nv set interface swp3 bridge domain br_default access 3010`

4. **Commands to be executed**
   - [ ] Check log: `Commands to be executed:`
   - [ ] Verify shows:
     ```
     + nv set bridge domain br_default vlan 3010
     + nv set interface bond3 bridge domain br_default access 3010
     ```
   - [ ] **NOT**: `+ nv set interface swp3 bridge domain br_default access 3010`

5. **Config Diff**
   - [ ] Check log: `Configuration changes:`
   - [ ] Verify shows `bond3`, not `swp3`

---

### ✅ Issue 5: Config Loading All Commands at Once

**Test**: Verify that both commands are loaded together, creating a single revision ID

#### Checkpoints:

1. **Config Generation**
   - [ ] Look for: `[DEBUG] Total commands: 2 (bridge VLAN + interface access)`
   - [ ] Look for: `[DEBUG] Config will be loaded as single block to create one revision ID`

2. **Phase 1: Configuration Loading**
   - [ ] Verify `Config to load:` shows **TWO** commands (not one)
   - [ ] Both commands should be in the same config block

3. **Revision ID**
   - [ ] Check log: `[DEBUG] Candidate revision ID: XXX`
   - [ ] Verify only **ONE** revision ID is created
   - [ ] The revision should contain BOTH commands

4. **Config Diff**
   - [ ] Check log: `Configuration changes:`
   - [ ] Should show BOTH commands:
     ```
     +nv set bridge domain br_default vlan 3010
     +nv set interface bond3 bridge domain br_default access 3010
     ```

---

### ✅ Issue 6: Commit-Confirm Detection and Error Messages

**Test**: Verify improved error messages and commit-confirm detection

#### Checkpoints:

1. **Error Messages (if config load fails)**
   - [ ] Look for: `[DEBUG] Actual error from device:`
   - [ ] Should show **actual error** from device, not generic example
   - [ ] Should **NOT** show: `Example: 'nv set bridge domain br_default vlan add 3000' should be...`

2. **Pending Commit Detection**
   - [ ] Check log: `[DEBUG] has_pending_commit() before commit: False` (this is OK - we check before commit)
   - [ ] After commit, look for: `[DEBUG] Found pending commit via JSON API: XXX` or similar
   - [ ] Should find pending revision using one of the methods

3. **Commit Result**
   - [ ] Check log: `[DEBUG] commit_config() return value: None` (this is OK - NAPALM returns None on success)
   - [ ] Look for: `✓ Pending changes detected` (after commit)
   - [ ] Should find pending revision ID

4. **If No Pending Revision Found**
   - [ ] Check log: `Error: <actual error from device>`
   - [ ] Should show actual error, not generic example
   - [ ] Look for: `Possible causes:` with specific reasons

---

### ✅ Issue 7: NetBox Update and Bond Creation (Option A)

**Test**: Verify bond is created in NetBox BEFORE VLAN update

#### Checkpoints:

1. **Bond Detection Before NetBox Update**
   - [ ] Look for: `[Step 4] Updating NetBox interface assignment...`
   - [ ] Look for: `[INFO] Device has bond 'bond3' but NetBox doesn't - creating bond first...`

2. **Bond Creation**
   - [ ] Look for: `[OK] Created bond 'bond3' in NetBox`
   - [ ] Look for: `[OK] Added X interface(s) to bond 'bond3' in NetBox`
   - [ ] Bond should be created **BEFORE** VLAN update

3. **VLAN Update on Bond Interface**
   - [ ] Look for: `[INFO] Updating NetBox interface 'bond3' with VLAN 3010...`
   - [ ] Look for: `[OK] NetBox interface 'bond3' (bond) updated successfully (member: swp3)`
   - [ ] Should show **bond3**, not **swp3**

4. **NetBox Verification**
   - [ ] Look for: `[Step 5] Verifying NetBox update...`
   - [ ] Look for: `Interface: bond3 (bond, member: swp3)` or `Interface: bond3`
   - [ ] Should verify **bond3**, not **swp3**

5. **If Bond Already Exists in NetBox**
   - [ ] Should skip bond creation
   - [ ] Should directly update VLAN on existing bond interface

---

## Test Scenarios

### Scenario 1: Bond NOT in NetBox (Most Common)
**Setup**: 
- Device has `bond3` with member `swp3`
- NetBox has `swp3` but NOT `bond3`

**Expected Flow**:
1. Bond detected from device config
2. Config generated for `bond3`
3. Device deployment to `bond3` succeeds
4. NetBox: Create `bond3` first
5. NetBox: Update VLAN on `bond3`
6. NetBox: Verify `bond3` has VLAN 3010

**Verification**:
- [ ] All logs show `bond3`, not `swp3`
- [ ] Bond created in NetBox before VLAN update
- [ ] NetBox verification shows `bond3`

---

### Scenario 2: Bond Already in NetBox
**Setup**:
- Device has `bond3` with member `swp3`
- NetBox has both `swp3` and `bond3` (bond already exists)

**Expected Flow**:
1. Bond detected from device config
2. Config generated for `bond3`
3. Device deployment to `bond3` succeeds
4. NetBox: Skip bond creation (already exists)
5. NetBox: Update VLAN on `bond3`
6. NetBox: Verify `bond3` has VLAN 3010

**Verification**:
- [ ] All logs show `bond3`, not `swp3`
- [ ] Bond creation skipped (already exists)
- [ ] NetBox verification shows `bond3`

---

### Scenario 3: No Bond (Regular Interface)
**Setup**:
- Device has `swp7` (NOT a bond member)
- NetBox has `swp7`

**Expected Flow**:
1. No bond detected
2. Config generated for `swp7`
3. Device deployment to `swp7` succeeds
4. NetBox: Update VLAN on `swp7`
5. NetBox: Verify `swp7` has VLAN 3010

**Verification**:
- [ ] All logs show `swp7` (no bond)
- [ ] No bond creation attempted
- [ ] NetBox verification shows `swp7`

---

## Debug Log Search Patterns

### To Find Bond Detection:
```bash
grep -i "BOND DETECTED\|bond_info_map\|bond member" deployment_logs.txt
```

### To Find Config Generation:
```bash
grep -i "CONFIG GENERATION\|Generated commands\|Total commands" deployment_logs.txt
```

### To Find NetBox Updates:
```bash
grep -i "Updating NetBox\|Created bond\|bond.*updated successfully" deployment_logs.txt
```

### To Find Errors:
```bash
grep -i "Actual error\|Error Type\|FAILED" deployment_logs.txt
```

---

## Common Issues to Watch For

### ❌ Still Showing `swp3` Instead of `bond3`
**Symptoms**:
- Logs show `swp3` in commands
- Config diff shows `swp3`

**Possible Causes**:
- Bond detection not working
- `bond_info_map` not being built correctly
- Config generation not using bond interface

**Debug Steps**:
1. Check: `[DEBUG] Building bond_info_map...`
2. Check: `[DEBUG] ✓ BOND DETECTED...`
3. Check: `[DEBUG] ✓ CONFIG GENERATION...`

---

### ❌ Only One Command Loaded
**Symptoms**:
- `Config to load:` shows only interface access command
- Missing bridge VLAN command

**Possible Causes**:
- Config generation not including bridge VLAN
- Bridge VLAN command filtered out as duplicate

**Debug Steps**:
1. Check: `[DEBUG] Total commands: 2`
2. Check: `[DEBUG] Generated commands:` (should show 2)
3. Check: `Config to load:` (should show 2 commands)

---

### ❌ NetBox Update on Wrong Interface
**Symptoms**:
- NetBox updated on `swp3` instead of `bond3`
- Bond not created before VLAN update

**Possible Causes**:
- Bond detection not working in NetBox update section
- Option A not implemented correctly

**Debug Steps**:
1. Check: `[INFO] Device has bond 'bond3' but NetBox doesn't...`
2. Check: `[OK] Created bond 'bond3' in NetBox`
3. Check: `[INFO] Updating NetBox interface 'bond3'...`

---

## Success Criteria

✅ **All tests pass if**:
1. Bond detected → Commands use `bond3` (not `swp3`)
2. Both commands loaded together → Single revision ID
3. Error messages show actual errors (not examples)
4. NetBox bond created before VLAN update (Option A)
5. NetBox verification shows correct interface (`bond3`)

---

## Post-Test Verification

After deployment, verify in NetBox UI:
- [ ] Bond interface `bond3` exists
- [ ] `swp3` is member of `bond3`
- [ ] `bond3` has VLAN 3010 configured (untagged)
- [ ] `swp3` does NOT have VLAN 3010 (bond has it)

Verify on device:
```bash
nv show interface bond3 bridge domain br_default
nv show bridge domain br_default vlan
```

Should show:
- `bond3` has access VLAN 3010
- Bridge has VLAN 3010

---

## Notes

- All debug logs are prefixed with `[DEBUG]` for easy filtering
- Bond detection happens in normal mode before Nornir call
- Config generation happens in `deploy_vlan_config()` task
- NetBox updates happen after successful device deployment
- Option A ensures bond exists before VLAN update

