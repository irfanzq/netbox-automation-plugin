# Deployment Failure Analysis

## Summary

The deployment failed due to multiple bugs in the code that prevented proper commit-confirm handling for Cumulus NVUE devices. The configuration was loaded and committed, but the commit-confirm confirmation step failed because the pending revision ID was not properly captured.

## Root Causes

### 1. **Variable Scope Bug: `interfaces_before` Not Initialized**

**Location:** `napalm_integration.py` lines 1203-1357

**Problem:**
- When using Cumulus direct NVUE path for baseline collection, `interfaces_before` is never initialized
- The code path: Direct NVUE succeeds → `baseline_collected = True` → skips the `get_interfaces()` fallback
- Later code (lines 1234, 1241, 1292, 1357) tries to use `interfaces_before` which was never set
- This causes: `cannot access local variable 'interfaces_before' where it is not associated with a value`

**Error Location:**
```
⚠ Baseline collection incomplete: cannot access local variable 'interfaces_before' where it is not associated with a value
```

**Fix Required:**
- Initialize `interfaces_before = None` or `interfaces_before = {}` before the Cumulus direct NVUE path
- Or ensure `interfaces_before` is always set, even when using direct NVUE

### 2. **Variable Scope Bug: `time` Module Not Imported in Exception Handler**

**Location:** `napalm_integration.py` line 1859

**Problem:**
- Line 1859 calls `time.sleep(0.5)` inside a try block
- `time` is imported at module level (line 13), BUT the exception handler at line 1877 tries to reference `time` in a context where it might not be in scope
- Actually, looking closer: `time` IS imported at module level, so this shouldn't be an issue unless there's a local variable shadowing it
- Wait - line 1902 has `import time` inside the try block, which creates a local `time` variable
- If an exception occurs before line 1902, the exception handler can't access the local `time` that was never created

**Error Location:**
```
⚠ Exception checking diff: cannot access local variable 'time' where it is not associated with a value
```

**Fix Required:**
- Remove the redundant `import time` at line 1902 (time is already imported at module level)
- Or ensure `time` is always available in the exception handler scope

### 3. **Commit-Confirm Revision ID Not Captured**

**Location:** `napalm_integration.py` lines 1895-1949

**Problem:**
- After `commit_config(revert_in=90)` is called, the code tries to find the pending revision ID
- The parsing logic looks for pending revisions in `nv config history` output
- However, the commit may not have created a pending revision if:
  - The configuration was already applied (no diff)
  - The commit command failed silently
  - The revision parsing regex doesn't match the actual output format

**Error Location:**
```
✗ WARNING: Commit may have failed - no pending revision created but changes exist
⚠ No pending revision found - checking if commit succeeded...
```

**Evidence from Logs:**
- Config diff shows changes exist: `nv config diff` shows pending changes
- But `nv config history` doesn't show a pending revision
- This suggests the commit command executed but didn't create a pending commit-confirm session

**Possible Causes:**
1. **NVUE Behavior:** `nv config apply --confirm 90s -y` might not create a pending revision if there's already a pending commit
2. **Timing Issue:** The revision might not appear immediately after commit
3. **Output Format:** The regex pattern might not match the actual `nv config history` output format

### 4. **Confirm Commit Failed - No Pending Revision Found**

**Location:** `napalm_integration.py` lines 2219-2299

**Problem:**
- Phase 5 tries to confirm the commit using the captured revision ID
- Since no revision ID was captured in Phase 2, it falls back to NAPALM's `confirm_commit()`
- NAPALM's `confirm_commit()` looks for `self.connection.revision_id` which was set during `load_config()` (Phase 1)
- But `commit_config()` creates a NEW pending revision with a different ID
- So `confirm_commit()` can't find the pending commit → "No pending commit-confirm found!"

**Error Location:**
```
✗ Commit-confirm not found: No pending commit-confirm found!
✗ Recovery attempt also failed: No pending commits found - may have timed out
```

**Root Cause:**
- The commit-confirm workflow requires:
  1. `load_config()` → creates candidate revision (e.g., revision 170)
  2. `commit_config(revert_in=90)` → applies revision 170 with commit-confirm, creates NEW pending revision
  3. `confirm_commit()` → needs to find the NEW pending revision, not the old candidate revision
- The code tries to capture the new pending revision in Phase 2, but fails to find it

### 5. **Rollback Failed - Pending Changes Still Exist**

**Location:** After Phase 5 failure

**Problem:**
- After commit-confirm confirmation fails, the code waits for auto-rollback
- However, the rollback doesn't complete properly
- `nv config diff` still shows pending changes after the 90s timeout
- This suggests the commit-confirm session is stuck or wasn't properly created

**Error Location:**
```
⚠ Warning: Rollback may have failed: Pending changes still exist
```

## Technical Details

### NVUE Commit-Confirm Workflow

The expected workflow for Cumulus NVUE commit-confirm:

1. **Load candidate config:**
   ```bash
   nv set interface swp3 bridge domain br_default access 3070
   ```
   → Creates candidate revision (e.g., 170)

2. **Apply with commit-confirm:**
   ```bash
   nv config apply --confirm 90s -y
   ```
   → Should create a pending commit-confirm session

3. **Check pending status:**
   ```bash
   nv config history
   ```
   → Should show pending revision with "*" marker

4. **Confirm (if verification passes):**
   ```bash
   nv config apply <revision_id> --confirm-yes
   nv config save
   ```

5. **Or auto-rollback (if timeout):**
   → Automatically reverts after 90s if not confirmed

### What Actually Happened

Based on the logs:

1. ✅ Phase 1: Config loaded successfully (revision 170 created)
2. ✅ Phase 2: `commit_config(revert_in=90)` called
3. ❌ Phase 2: No pending revision found after commit
4. ✅ Phase 4: Verification passed (config was actually applied)
5. ❌ Phase 5: Confirm failed - no pending revision to confirm
6. ❌ Rollback: Failed - pending changes still exist

**Key Insight:** The config WAS applied (verification passed), but the commit-confirm session wasn't properly created or tracked. This means:
- The changes are active on the device
- But they're not in a commit-confirm session
- So they can't be confirmed or rolled back via the commit-confirm mechanism
- They're in a "limbo" state

## Recommended Fixes

### Fix 1: Initialize `interfaces_before` Variable

```python
# Around line 1095, before baseline collection
interfaces_before = None  # Initialize early

# Then in the Cumulus direct NVUE path, ensure it's set:
if driver_name == 'cumulus' and interface_name:
    # ... direct NVUE code ...
    if baseline_collected:
        # If we used direct NVUE, we still need interfaces_before for later checks
        try:
            interfaces_before = self.get_interfaces() or {}
        except:
            interfaces_before = {}
```

### Fix 2: Remove Redundant `import time`

```python
# Line 1902: Remove this line
# import time  # <-- DELETE THIS, time is already imported at module level
```

### Fix 3: Improve Pending Revision Detection

```python
# After commit_config(), try multiple methods to find pending revision:
# 1. Check nv config history with better parsing
# 2. Check nv config diff to see if changes are pending
# 3. Check nv config pending (if available)
# 4. Use nv config revision -o json to get structured data
```

### Fix 4: Handle Case Where Commit Doesn't Create Pending Revision

```python
# If no pending revision found but diff shows changes:
# - The commit may have applied directly (no commit-confirm session)
# - In this case, we should just save the config instead of trying to confirm
if no_pending_revision and changes_exist:
    # Config was applied but not in commit-confirm mode
    # Just save it to make it persistent
    self.connection.device.send_command("nv config save", read_timeout=30)
```

### Fix 5: Better Error Handling for Stuck Commits

```python
# If rollback fails, provide manual recovery steps:
# - Check nv config history
# - Manually abort: nv config abort
# - Or manually apply previous revision
```

## Immediate Action Required

The device is currently in an inconsistent state:
- Configuration changes are applied
- But not in a commit-confirm session
- And not permanently saved

**Manual Recovery Steps:**
1. SSH to device: `stg1-leaf-04` (172.19.1.30)
2. Check current state: `nv config diff`
3. If changes look correct: `nv config save` (make permanent)
4. If changes are wrong: `nv config apply <previous_revision>` (rollback)

## Testing Recommendations

After fixes are applied, test with:
1. Fresh deployment (no existing pending commits)
2. Deployment with existing pending commit (should detect and handle)
3. Deployment where config already matches (should handle gracefully)
4. Deployment that times out (should rollback properly)

