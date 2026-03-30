# MAAS / OpenStack Sync - Branch Reconciliation UI Flow

## Purpose

Define the end-to-end UX flow after Drift Audit so selected report rows become safe, reviewable NetBox branch changes before merge to `main`.

This flow follows the core design principles in `Netbox-MAAS-OS-SYNC-Design.md`:

- NetBox is authoritative for design intent
- Drift is visible before changes
- Changes are reviewable in branch
- No direct write to main dataset
- Runs are idempotent and fail-safe

---

## Phase model and pages

### Phase 0 - Drift Audit (existing page)

Page:

- `MAASOpenStackSyncView` (`maas_openstack_sync_form.html`)

Current role:

- Run read-only drift
- Show detail tables with Include selection and row keys
- NetBox picker columns (▾) for proposed values
- **`Save edits`** persists user choices to `MAASOpenStackDriftRun` (see **Drift run persistence** below)
- Export Excel (baseline and modified with merged overrides)

New role (action handoff):

- Convert **reviewed** proposed rows (after optional selection / preview) into a staged reconciliation run request
- Handoff must use the **same merged data** as modified HTML/Excel, not the original report only

Buttons on this page:

- `Run drift audit` (existing)
- `Download as Excel` (existing, cache-backed)
- `Save edits` (existing — **recommended before branch creation** so NetBox-bound values match what reviewers saw)
- **`Preview selected changes`** (new, required before branch creation)
- **`Create NetBox Branch from Selected`** (new primary action after audit)

Redirect after successful click:

- Redirect to **Sync Run Detail** page for the created **reconciliation** run (not back to drift report).  
- The drift audit is already tied to **`MAASOpenStackDriftRun`** (`audit_run_id` / history run id); branch creation should reference that id as immutable input.

Why:

- Drift page stays focused on review/selection
- Branch/apply/merge actions live in run lifecycle pages

---

### Phase 1 - Run creation + branch creation

Backend action from drift page button:

1. Validate selected keys from detail tables
2. Resolve selected keys into concrete operations (deterministic mapping)
3. Run pre-apply validation on resolved operations (create-time gate)
4. Create `SyncRun` record with immutable snapshot metadata + frozen operations
5. Create NetBox branch
6. Store branch identity on run
7. Set run status to `branch_created`

Validation timing policy (implementation):

- create-time pre-apply validation: structural/identity checks required to create a valid frozen operation set
- apply-time pre-apply validation: re-run critical safety checks that may change over time (permissions, branch existence, lock state, and key prerequisites)
- post-apply validation remains a separate lifecycle step before merge

Strict backend state progression (enforced in code):

- `draft` -> `branch_creating` -> `branch_created` or `branch_create_failed`
- `branch_created` -> `apply_in_progress`
- `apply_in_progress` -> `applied` or `apply_failed_partial` or `apply_failed`
- `applied` -> `validation_in_progress`
- `validation_in_progress` -> `validated` or `validation_failed`
- `validated` -> `merge_in_progress`
- `merge_in_progress` -> `merged` or `merge_failed`
- `draft|branch_create_failed|branch_created|applied|validation_failed|merge_failed|apply_failed_partial|apply_failed` -> `discarded`
- `apply_failed_partial|apply_failed` -> `apply_in_progress` (via `retry_failed`)
- `validation_failed` -> `validation_in_progress` (re-validation after fixes)

Terminal states:

- `merged`
- `discarded`

Hard transition rules:

- only `branch_created` can enter apply
- `validation_in_progress` can be entered from `applied` (initial validation) and from `validation_failed` (re-validation after fixes)
- only `validated` can enter merge
- no transitions out of terminal states
- `branch_create_failed` cannot enter apply/validate/merge
- `retry_failed` is a first-class lifecycle action (audited), implemented as re-entry to `apply_in_progress`

User-facing message on success:

- Branch name/id
- Selected counts by table
- CTA to apply selected changes

Redirect target:

- `Sync Run Detail` page for that run

---

### Phase 2 - Apply selected changes to branch

Page:

- **Sync Run Detail** (new)

Purpose:

- Show selected payload summary
- Execute controlled apply to NetBox branch objects
- Show per-table and per-row results
- Enforce explicit partial-failure semantics

**Branch write contract (`netbox_branching`):** In Apply mode, the workflow activates the selected branch using `netbox_branching.utilities.activate_branch(branch)` and runs ORM writes inside the branch-aware transaction/connection context used by the installed plugin — specifically the same pairing the plugin uses internally (`activate_branch` plus `transaction.atomic(using=branch.connection_name)`, matching `Branch.sync` in `models/branches.py`). If branch activation or branch-scoped transaction setup fails, the run must fail clearly and must not write branch-affected models to main.

Buttons on Run Detail:

- **`Apply selected changes to branch`** (primary when `branch_created`)
- `Re-apply failed items` (only if partial failures)
- `Refresh status`

After apply:

- Show result cards:
  - created/updated/skipped/failed counts
  - failures with reason
- Keep run immutable input (selected keys + snapshot id)
- Keep frozen operation set immutable (no re-resolution from fresh drift)

Stay on same page after apply:

- Update status and results in place
- Optional auto-refresh polling while `apply_in_progress`

---

### Phase 3 - Validate branch

Page:

- Same **Sync Run Detail** page

Validation has two layers:

1. **Pre-apply validation** (before writing to branch; part of create/apply gate)
   - operation legality and completeness
   - required field presence
   - identity/mapping validity
   - conflict pre-checks where possible

2. **Post-apply branch validation** (after apply)
   - branch consistency and clean end-state
   - object-level reconciliation checks
   - policy checks before merge

Post-apply validation examples:

- identity collisions
- required NetBox fields populated
- role/device-type mapping sanity
- prefix/IP conflicts
- guarded checks for non-destructive policy

Buttons:

- **`Run validation checks`**
- `View validation report`

Result:

- status `validated` or `validation_failed`

---

### Phase 4 - Review and merge

Page:

- Same **Sync Run Detail** page, with branch links

Buttons:

- **`Open NetBox Branch Diff`** (link/button)
- **`Merge branch to main`** (enabled only when `validated`)
- `Discard branch` (safe cancel path)

After merge:

- status `merged`
- show merge metadata (who/when/branch)
- optional button: `Start new drift audit`

After discard:

- status `discarded`
- keep run history for audit
- semantics: discard means abandon the run and branch; it does not reverse already-applied branch operations row-by-row

---

## Navigation map

1. User opens Drift Audit page  
2. Runs drift and selects rows  
3. Clicks `Create NetBox Branch from Selected`  
4. System creates run + branch  
5. Redirect to `Sync Run Detail`  
6. User clicks `Apply selected changes to branch`  
7. User clicks `Run validation checks`  
8. User reviews branch diff  
9. User clicks `Merge branch to main` or `Discard branch`

---

## Where each button should live

### Drift report page (`maas_openstack_sync_form.html`)

Show after `audit_done`:

- `Preview selected changes` -> required action before branch creation
- `Create NetBox Branch from Selected` -> POST to run-create endpoint
- Keep existing `Download as Excel`

Do not place merge/apply buttons here.

### New page: `Sync Run Detail`

Show lifecycle actions here:

- `Apply selected changes to branch`
- `Run validation checks`
- `Open branch diff`
- `Merge branch to main`
- `Discard branch`

### New page: `Sync Runs` (list/history)

Show discoverability and operations:

- run id, status, user, time, branch
- link to run detail
- filter by status

---

## Drift run persistence (implemented) — what feeds the branch workflow

Each drift audit creates a **`MAASOpenStackDriftRun`** row (history). After **Save edits**, the following fields matter for any downstream NetBox branch / apply step:

| Field | Role |
|--------|------|
| **`snapshot_payload`** | Frozen audit inputs: `maas_data`, `netbox_data`, `openstack_data`, `drift`, `matched_rows`, `interface_audit`, `netbox_ifaces`, gaps, etc. This is the **original** run snapshot; it is **not** rewritten when the user changes pickers. |
| **`drift_review_overrides`** | Structured JSON: `{ selection_key: { row_index_str: { column_header: value } } }` — the **reviewed** cell values (same shape as the drift Excel/HTML merge). Normalized via **`normalize_drift_review_overrides()`** (includes legacy fixes such as placement `NB` → `NB proposed device status`). |
| **`report_drift`** | Original drift HTML/text at audit time (**pre-review**). |
| **`report_drift_modified_html`** | Drift HTML regenerated with overrides merged (human-readable; optional display). |
| **`drift_review_modified_xlsx`** | Same merge as Excel export (optional attachment). |
| **`drift_review_saved_at` / `drift_review_saved_by`** | Whether review was saved and by whom. |

### Source of truth for “what we apply to NetBox”

1. **Authoritative inputs for merged proposed rows**  
   - **`snapshot_payload`** + **`normalize_drift_review_overrides(run.drift_review_overrides)`**  
   - Then the **same pipeline** as modified HTML/Excel: build proposed rows + alignment rows from the snapshot, then **`merge_drift_review_overrides(prop, align_rows, norm)`**.  
   - Resulting **`prop`** (add_devices, add_prefixes, update_nic, …) and **alignment rows** are the **structured** values to map to NetBox branch operations (device status, site, prefix, NIC, etc.).

2. **Do not use as sole input for apply**  
   - **`report_drift`** alone — **pre-review**, can disagree with pickers.  
   - **Session drift cache** without tying to **`MAASOpenStackDriftRun.id`** — can be stale vs DB.  
   - Parsing **`report_drift_modified_html`** for apply logic — fragile; prefer structured merge above.

3. **Handoff to “Create NetBox Branch” UI**  
   - Pass **`drift_run_id`** (`MAASOpenStackDriftRun.pk`, same as live page `audit_run_id` / history run id).  
   - Server loads the run from DB (`refresh_from_db` on relevant fields), re-runs **snapshot + normalize(overrides) + merge**, then resolves **included** row keys (if selection is still keyed by stable row keys) into frozen operations.  
   - If the user has **not** saved edits, **`drift_review_overrides`** may be empty — merged output equals **auto-generated** proposed rows only (expected).

4. **Alignment with modified Excel**  
   - **`build_drift_report_xlsx_from_snapshot_payload(snapshot_payload, drift_overrides=norm)`** uses the same merge — branch preview/apply should match that file when fed the same run.

### Optional shared helper (future code)

Add a single function used by save, history, Excel, and branch preview, e.g.:

- Input: `MAASOpenStackDriftRun` or `(snapshot_payload, drift_review_overrides)`  
- Output: merged `prop` dict + `align_rows` (and optionally digest for preview token)

So the branch workflow never duplicates merge rules.

---

## Data contract between report and branch workflow

From drift / run handoff (recommended):

- **`drift_run_id`** — `MAASOpenStackDriftRun` primary key (persisted audit + optional review overrides)
- **`audit_snapshot_id`** / `source_cache_key` — optional correlation; **do not** rely on cache alone for merge data
- **selected keys** grouped by section (stable row keys from drift tables, where Include/selection is enforced)
- metadata: selected/unselected counts
- preview acknowledgement token (server-generated from frozen operation digest)

The server **loads** `MAASOpenStackDriftRun`, applies **`normalize_drift_review_overrides` + merge** to `snapshot_payload`, then resolves keys → operations. Frozen operations are stored on the **Sync** run (reconciliation run), not mutated by later drift audits.

Example shape (client → create-run endpoint):

```json
{
  "drift_run_id": 27,
  "selection_mode": "selected_keys",
  "selected": {
    "detail_new_devices": ["a1b2...", "c3d4..."],
    "detail_new_prefixes": ["e5f6..."],
    "detail_nic_drift_os": ["9abc..."]
  }
}
```

Legacy / alternate shape (cache-only — **discouraged** for apply):

```json
{
  "snapshot_id": "drift:2026-03-27T09:10:12Z:usr42",
  "selection_mode": "selected_keys",
  "selected": { }
}
```

Mapping rule:

- backend loads **`MAASOpenStackDriftRun`** by `drift_run_id`, merges **`drift_review_overrides`** into proposed rows from **`snapshot_payload`**
- backend resolves each **selected** key (and/or policy for “all included rows”) to a deterministic proposed operation
- operation contains target model, action, field map, and stable operation id
- operation set is frozen on **Sync** run and never re-derived from later drift data
- apply engine executes frozen operations table-by-table, row-by-row
- all action attempts are recorded with actor + timestamp + outcome

No direct writes to main dataset.

---

## Recommended endpoint set

Suggested URLs (plugin namespace style):

- `POST /plugins/netbox-automation-plugin/maas-openstack-sync/runs/create/`
- `POST /plugins/netbox-automation-plugin/maas-openstack-sync/runs/preview/`
- `GET /plugins/netbox-automation-plugin/maas-openstack-sync/runs/`
- `GET /plugins/netbox-automation-plugin/maas-openstack-sync/runs/<run_id>/`
- `POST /plugins/netbox-automation-plugin/maas-openstack-sync/runs/<run_id>/apply/`
- `POST /plugins/netbox-automation-plugin/maas-openstack-sync/runs/<run_id>/retry-failed/` (recommended), or reuse apply endpoint with `mode=retry_failed`
- `POST /plugins/netbox-automation-plugin/maas-openstack-sync/runs/<run_id>/validate/`
- `POST /plugins/netbox-automation-plugin/maas-openstack-sync/runs/<run_id>/merge/`
- `POST /plugins/netbox-automation-plugin/maas-openstack-sync/runs/<run_id>/discard/`

---

## Guardrails

- Reject apply/merge if run has no branch
- Reject merge unless run status is `validated`
- Keep idempotency key per operation
- Never auto-delete in initial rollout
- Preserve full run audit trail
- Enforce backend state machine on every lifecycle endpoint
- Fail branch creation cleanly on naming collision or plugin errors (do not advance state)
- Enforce per-run action lock: only one lifecycle mutation (`apply|validate|merge|discard|retry_failed`) can run at a time
- Reject concurrent action requests with conflict response and current in-progress action metadata
- (Future) support optional scope-level lock to prevent overlapping runs writing same inventory scope concurrently
- Merge preflight must verify: run status is `validated`, branch still exists, and no in-progress lock is held

---

## Permission boundaries (v1)

Minimum role boundaries:

- `create_run` / `preview`: users with workflow run permission
- `apply` / `retry_failed`: users with sync-apply permission
- `validate`: users with sync-validate permission
- `merge`: users with elevated merge permission (separate from apply)
- `discard`: users with sync-discard permission

Rules:

- backend enforces permissions for every lifecycle endpoint (not UI-only controls)
- merge requires both `validated` status and merge permission
- each lifecycle action records actor identity in audit trail

---

## Branch naming and collision policy

Branch naming rule (v1):

- `sync-<YYYYMMDD>-<HHMMSS>-<username>-<shortid>`

Examples:

- `sync-20260327-154210-irfanzq-a1b2c3`

Collision handling:

- if generated name exists, regenerate with new shortid up to N retries
- if still failing, mark run `branch_create_failed` and return error
- do not allow transition to `branch_created` on failure

---

## Partial failure semantics (v1)

v1 policy is explicit:

- **Best effort per row** with full failure recording
- `apply_failed_partial` cannot enter validation directly; operator must retry failed rows (or discard run) first

Meaning of `applied`:

- all rows processed, no failed rows

Meaning of `apply_failed_partial`:

- run completed processing, but one or more rows failed

Behavior:

- successful rows are kept in branch
- failed rows can be retried via `Re-apply failed items`
- every row has explicit result (`created|updated|skipped|failed`) and reason
- `retry_failed` only re-attempts rows with latest status `failed`; previously successful rows are not re-run by default

Required `skipped` reason taxonomy:

- `skipped_already_desired` (healthy: object already in desired state)
- `skipped_policy_blocked` (guardrail/policy blocked write)
- `skipped_identity_ambiguous` (unsafe identity match, manual review required)
- `skipped_prerequisite_missing` (dependency absent, e.g., required object not found)

---

## Mandatory operation preview

Preview is first-class and required (not optional).

Minimum preview output before branch creation:

- `Create Device <name>`
- `Update Interface <device>/<ifname> MAC`
- `Create Prefix <cidr> in VRF <vrf>`
- `Create IP <ip> (floating)`
- `Skip <reason>`

Preview page/action must show:

- grouped operations by section
- total counts by action type
- warnings/high-risk operations
- digest/hash of frozen operation set

User confirmation should bind to that digest so creation/apply uses the exact reviewed set.

---

## Audit trail fields (required)

For run and lifecycle actions, store:

- actor user id/name
- action (`create_run`, `create_branch`, `apply`, `validate`, `merge`, `discard`, `retry_failed`)
- timestamp (UTC)
- previous status -> new status
- branch id/name
- operation digest/version
- request id / correlation id
- result summary and error details

---

## Implementation invariants (must enforce in code)

- **Preview acknowledgement is mandatory for branch creation**
  - `Create NetBox Branch from Selected` must hard-fail unless a valid preview acknowledgement token is supplied.
  - Token must be bound to the frozen operation digest and run context.
  - Do not rely on UI button order for correctness.

- **Discard never performs reverse mutations**
  - If a branch exists, discard should abandon/delete branch when possible.
  - Always preserve full run + action audit history.
  - Discard must never attempt row-by-row rollback/reverse apply logic.

- **`retry_failed` is failed-rows-only**
  - Retry endpoint and service layer must both enforce retry scope to rows currently marked `failed`.
  - Previously successful rows must not be replayed by retry path.
  - Any request violating this invariant must fail validation.

---

## Implementation order (practical)

1. Add shared **`merged_proposed_from_drift_run(run)`** (or equivalent) — snapshot + `normalize_drift_review_overrides` + `merge_drift_review_overrides`; use from branch preview/create and keep parity with modified Excel.
2. Add `Create NetBox Branch from Selected` on drift page — POST **`drift_run_id`** (+ selected keys / preview token).
3. Create `SyncRun` model + run detail page
4. Implement branch creation and run status transitions
5. Implement apply engine: frozen operations derived from merged `prop` / alignment rows + selection, not from `report_drift` alone
6. Add validation step
7. Add merge/discard actions
8. Add sync runs list/history page (distinct from **Drift run** history, unless unified intentionally)

This sequence gives working value early while staying aligned with branch-first safety and **reviewed** proposed values.
