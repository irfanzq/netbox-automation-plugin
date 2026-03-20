# Goal

Keep NetBox accurate and up to date for all infrastructure (bare-metal and cloud) through controlled reconciliation with runtime systems.

NetBox remains the **trusted source of truth for infrastructure inventory and IPAM**, while runtime systems provide operational state.

Reconciliation will be executed through a **NetBox UI workflow** and applied safely using **NetBox Branching**.

---

# Problem statement

NetBox must remain the **authoritative source of truth for infrastructure inventory and IPAM**.

Infrastructure drift occurs when runtime systems change faster than NetBox is updated.

Examples include:

- MAAS machines added or removed
- OpenStack IP allocations and floating IP changes
- VLAN or prefix inconsistencies across environments
- Cabling updates not reflected in NetBox

Without reconciliation, NetBox gradually diverges from operational reality.

Automated reconciliation improves:

- Infrastructure accuracy
- Troubleshooting reliability
- Operational visibility
- Alignment between runtime systems and NetBox design intent

---

# High-level approach

A **NetBox-based reconciliation system** will compare infrastructure state across systems and safely update NetBox.

Core model:

- **MAAS + OpenStack → NetBox reconciliation**
- NetBox remains authoritative for **design intent and IPAM**
- Runtime systems provide **operational state**

Reconciliation follows a controlled staged workflow:

1. Run **read-only drift audit**
2. Generate reconciliation report
3. Apply proposed changes inside a **NetBox Branch**
4. Engineers review branch changes
5. Approved changes are merged into the NetBox  `main` dataset 

**Principle**

Start with **read-only audit**, then move to **branch-based reconciliation** once validation logic is trusted.

No external system is allowed to overwrite NetBox design intent without review.

---

# Design principles

The reconciliation system follows a set of principles to ensure automation remains safe, predictable, and aligned with NetBox as the authoritative infrastructure system.

**NetBox remains the authoritative design source**

NetBox defines the intended infrastructure model, including device inventory, IPAM structure, VLAN design, and topology relationships. External systems provide operational data but do not automatically overwrite NetBox design intent.

**Runtime systems provide operational state**

MAAS and OpenStack represent the operational state of infrastructure. Their data is used to detect drift and reconcile NetBox where appropriate.

**Drift must be visible before changes occur**

All reconciliation begins with a read-only drift audit so engineers can review detected differences before any changes are applied.

**All changes must be reviewable**

Updates are applied to a NetBox branch rather than directly to the main dataset, allowing engineers to review differences before merging.

**Automation must be safe to repeat**

Reconciliation logic is idempotent. Running the workflow multiple times produces the same result without duplicate or conflicting updates.

**Automation must fail safely**

If external systems are unreachable or validation fails, reconciliation aborts without modifying NetBox data.

---

# Reconciliation flow

The reconciliation process ensures visibility and safety before any production data is modified.

```
External Systems (Reality)
   ├─ MAAS (hardware inventory)
   ├─ OpenStack (runtime networks/IPs)
   └─ LLDP (physical connectivity)

            ↓

Phase 0 — Cross-System Audit (Read-Only)
   • Detect drift across systems
   • Produce structured reconciliation report
   • No NetBox changes

            ↓

Branch-Based Reconciliation
   • Create NetBox reconciliation branch
   • Apply proposed changes to branch only

            ↓

Engineering Review
   • Review branch diff
   • Review reconciliation report

            ↓

Merge or Reject
   • Merge branch → main
   • Or discard branch if issues are found
```

---

# Source-of-truth boundaries

Clear ownership rules prevent conflicting updates between systems. Each system contributes a specific type of operational or discovery data while **NetBox remains the authoritative design system**.

## LLDP owns (physical connectivity truth)

- Switchport ↔ NIC neighbor relationships
- Physical link observation
- Used to validate NetBox cabling data
- Host-side LLDP observations may also be collected when available

LLDP is used for **validation of physical connectivity**, not automatic topology modification.

## MAAS owns (bare-metal truth)

MAAS represents the **operational lifecycle state of bare-metal machines** within the provisioning environment.

MAAS provides:

- Machine lifecycle state
- Commissioning / deployment status
- Observed machine presence
- Observed NIC and MAC address data

MAAS does **not own design fields** in NetBox.

MAAS must **not overwrite**:

- Hostnames
- Site or rack placement
- Device roles
- VLAN design
- IPAM architecture

MAAS data is used for **reconciliation and validation**, not direct design authority.

## OpenStack owns (runtime allocation truth)

OpenStack represents **runtime networking state inside the cloud environment**.

OpenStack provides:

- Networks and subnets
- Floating IP allocations
- Tenant networking
- Provider VLAN runtime usage

OpenStack does not control NetBox IPAM design or VLAN definitions.

OpenStack data is used for **runtime visibility and drift detection**.

## NetBox owns (enterprise design truth)

NetBox remains the **authoritative source of infrastructure design intent**.

NetBox defines:

- Hostnames
- Device inventory model
- Sites and racks
- Device roles
- VLAN Groups
- Approved VLAN definitions
- IPAM architecture
- Prefix allocations
- Interface design intent

External systems provide operational data but **do not automatically overwrite NetBox design intent**.

---

# Data precedence

When systems disagree, the following precedence applies.

| Domain | Authoritative System |
| --- | --- |
| Physical cabling | LLDP |
| Hardware presence / MACs | MAAS |
| Runtime IP allocation | OpenStack |
| Design intent and IP planning | NetBox |

---

# Object identity and matching rules

To safely reconcile data across multiple systems, the automation must determine when objects represent the same real-world resource.

Different systems may represent the same infrastructure objects with different identifiers or metadata. Deterministic identity rules ensure the reconciliation process consistently identifies the correct objects across systems.

These rules prevent:

- duplicate object creation
- unintended overwrites
- incorrect updates when systems disagree

The reconciliation logic therefore relies on well-defined identity keys for each object type.

| Object | Identity Key |
| --- | --- |
| Device | hostname (validated by serial when available) |
| Interface | device + interface name (validated by MAC) |
| VLAN | VLAN Group + VID |
| Prefix | prefix + VRF |
| IP address | IP + VRF |
| Floating IP | IP + tenant/project |

All reconciliation runs must be **idempotent**, meaning repeated runs produce the same result without creating duplicate objects or conflicting updates.

---

# Automation scope

The reconciliation system focuses on synchronizing infrastructure data from runtime systems into NetBox while preserving NetBox as the authoritative design source.

During the initial rollout, the scope of automation is intentionally limited to a small set of well-understood objects. This reduces operational risk while allowing the team to validate reconciliation logic and reporting before expanding automation coverage.

## MAAS → NetBox (primary reconciliation)

**Sync items**

- Create or update NetBox devices from MAAS machines
- Create or update interfaces from MAAS NICs
- Ensure MAC addresses match
- Tag devices `source:maas`
- Mark NetBox-only devices as `orphaned` and classify MAAS-only machines as `maas-discovered`

**Outcome**

NetBox accurately reflects bare-metal inventory and NIC/MAC data.

## MAAS inventory drift categories

MAAS reconciliation must classify unmatched inventory in both directions. A device recorded in NetBox but not present in MAAS is not the same condition as a machine present in MAAS but missing from NetBox. These cases must be tracked separately because they represent different operational risks and require different handling.

### Orphan (NetBox-side)

A device that exists in NetBox but has no matching machine in MAAS is considered an orphan. This usually indicates stale inventory, decommissioned hardware, hostname drift, identity mismatch, or incomplete provisioning state. Orphaned objects must be included in the reconciliation report, tagged as `orphaned`, and held for review. They must not be automatically deleted from NetBox.

Definition: Documented device exists in NetBox, but no matching MAAS machine is found.

Tag: `orphaned`

### MAAS-only (runtime-discovered)

A machine that exists in MAAS but has no matching device in NetBox is considered MAAS-only or runtime-discovered. This means the runtime system sees an active machine, but there is no approved design record for it in NetBox. This condition must not be labeled as orphaned. Instead, it should be treated as a runtime-discovered asset that requires review before it becomes part of approved NetBox inventory.

Definition: Machine exists in MAAS, but no matching NetBox device is found.

Tag: `maas-discovered`

### Handling rules

Orphaned NetBox devices and MAAS-only machines must both appear in the reconciliation report, but they must be handled differently. Orphaned devices indicate NetBox-side stale or missing runtime alignment. MAAS-only machines indicate runtime-discovered assets that are not yet represented in approved NetBox design. Neither case should be automatically deleted or silently accepted into Main.

In audit mode, both conditions are reported only. In branch-based reconciliation mode, orphaned devices remain tagged for review, while MAAS-only machines may be proposed for staged creation inside a NetBox branch with the tag `maas-discovered`. Any such creation must remain subject to review and approval before merge into Main.

---

## OpenStack → NetBox (controlled visibility)

**Sync items**

- Networks and subnets → NetBox prefixes
- Floating IPs → NetBox IP objects
- Tag objects `source:openstack`

Optional future scope:

- Port IP reconciliation
- Project / tenant mapping

**Outcome**

OpenStack IP usage becomes visible in NetBox and conflicts can be detected early.

---

# VLAN reconciliation

## Purpose

Ensure VLAN definitions and interface VLAN assignments in NetBox match operational state across systems.

This prevents:

- L2 drift
- incorrect VLAN placement
- mismatched prefix assignments

---

# VLAN inventory reconciliation

### MAAS → NetBox

- Map MAAS Fabric → NetBox VLAN Group
- Map MAAS VLAN → NetBox VLAN
- Create missing VLANs in branch
- Flag mismatched metadata

No destructive VLAN deletion occurs in the initial rollout.

---

### OpenStack → NetBox

- Ensure provider VLAN exists in NetBox
- Map OpenStack physnet → VLAN Group
- Validate subnet prefix alignment
- Detect VLAN conflicts

Important rule:

A VLAN ID must be **unique within its VLAN Group**.

---

# Interface VLAN reconciliation

## Physical interfaces (MAAS)

If MAAS exposes VLAN information:

- Sync untagged VLAN
- Sync tagged VLANs when clearly defined
- Validate prefix alignment
- Tag mismatches `vlan-drift`

## Virtual networks (OpenStack)

- Reconcile provider VLAN definitions
- Associate prefixes with VLAN objects

OpenStack **does not control physical NIC VLAN state**.

---

# VLAN rollout model

Initial rollout will be conservative.

Phase 1 includes:

- single untagged VLAN per physical interface
- tagged VLANs only when clearly exposed
- no trunk or LAG modeling changes

Advanced VLAN modeling may be introduced later.

---

# VLAN reconciliation guardrails

To protect infrastructure integrity:

- No automatic VLAN deletion
- No VLAN group reassignment
- No trunk modeling changes
- No overwrite of NetBox design intent
- Large VLAN updates must run in scoped mode

---

# Execution model (implementation v1)

Reconciliation runs **inside NetBox** using the existing automation plugin.

Repository:

```
netbox-automation-plugin
```

Automation is triggered through a NetBox workflow.

```
Automation → MAAS / OpenStack Sync
```

Engineers run reconciliation manually through the NetBox UI.

---

# Workflow modes

The NetBox workflow supports two operating modes.

## Drift Audit

Read-only reconciliation.

Functions:

- Detect drift across systems
- Compare MAAS, OpenStack, LLDP, and NetBox data
- Generate reconciliation report summarizing differences

No NetBox data is modified.

The audit workflow produces a **structured reconciliation report** summarizing all detected differences across systems. This report provides a **human-readable summary of proposed changes**, allowing engineers to review drift without relying solely on the NetBox branch diff view.

This is important because the NetBox branch diff UI may become difficult to interpret when large numbers of objects change. The reconciliation report highlights:

- object counts
- categorized drift types
- high-risk differences
- summary statistics

Engineers review this report before any reconciliation changes are applied.

---

## Full Sync

Applies staged reconciliation:

1. MAAS reconciliation
2. OpenStack reconciliation
3. VLAN reconciliation (optional and disabled by default)

All changes are written to a **NetBox Branch** rather than directly to production.

---

# Branch-based reconciliation workflow

Reconciliation changes follow a controlled branch workflow.

1. Create reconciliation branch
2. Apply proposed changes to branch
3. Generate reconciliation report summarizing all proposed changes
4. Engineers review branch diff
5. Merge branch → main or discard

Branching provides:

- staging environment for changes
- safe review before production updates
- rollback capability
- shared review surface for engineers

---

# Drift handling

Reconciliation is designed to be **safe by default**.

If NetBox contains objects not present in MAAS or OpenStack:

- Tag as `orphaned`
- Include in reconciliation reports
- Do not delete automatically

If MAAS contains machines not present in NetBox:

- Classify as MAAS-only
- Tag proposed staged objects as `maas-discovered`
- Include in reconciliation reports
- Do not merge into `main` without review

Large reconciliation runs produce:

- structured reconciliation summary
- categorized drift output
- NetBox branch diff for review

Scoped execution may limit reconciliation to:

- site
- rack
- device

---

# Operational safety

The reconciliation system enforces safety guarantees.

- No writes occur if MAAS or OpenStack APIs are unreachable
- Partial data retrieval aborts reconciliation
- Runs are idempotent
- No destructive changes occur without review
- Errors are surfaced through reconciliation reports
- No silent failures occur

Automation is designed to **fail safely**.

---

# Phase implementation plan

## Phase 0 — Cross-system audit

Read-only comparison across systems.

Comparisons include:

- **MAAS vs NetBox inventory**
- **OpenStack vs NetBox IP allocations**
- **LLDP vs NetBox cabling topology**

LLDP data is collected from the network infrastructure (switch neighbor tables) and compared against the physical cabling model stored in NetBox.

The goal of this phase is to identify differences between:

- **system data**
- **NetBox design**
- **physical network reality**

Output of this phase includes:

- structured reconciliation report
- categorized differences
- summary statistics of detected drift

No changes are written to NetBox during this phase.

---

## Phase 1 — MAAS reconciliation

Implement MAAS → NetBox synchronization.

Features include:

- device synchronization
- interface synchronization
- orphan detection
- reconciliation reporting

---

## Phase 2 — OpenStack visibility

Import runtime networking state into NetBox:

- networks
- subnets
- floating IPs

Add conflict detection against NetBox IPAM.

---

## Phase 3 — reporting and hardening

Improve operational visibility.

Capabilities include:

- reconciliation summary reports
- improved drift classification
- guardrails for safe reconciliation
- optional approval-based cleanup workflows

---

# Success metrics

The system is considered successful when:

| Metric | Target |
| --- | --- |
| MAAS coverage in NetBox | 100% |
| MAC mismatch rate | ~0 |
| Orphan count | decreasing |
| Prefix conflicts | detected early |
| Duplicate VLANs | none |
| Prefix/VLAN alignment | 100% |
| Interface VLAN consistency | validated |

---

# Deliverables

The team will receive:

- NetBox workflow **MAAS / OpenStack Sync**
- Integrated reconciliation module inside **netbox-automation-plugin**
- Branch-based reconciliation workflow
- Drift audit reporting
- Structured reconciliation reports
- Operational runbooks and walkthrough documentation

Supporting scripts used for API testing remain in the repository but are not part of production automation.
