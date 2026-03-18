# NetBox syncing with OpenStack and MAAS — Design (authoritative copy)

**Status:** In progress · **Goal:** Keep NetBox accurate via controlled reconciliation with MAAS and OpenStack.

## Goal

- **NetBox** = trusted **design source of truth** for inventory and IPAM.
- **MAAS / OpenStack** = **operational runtime state** (detect drift; reconcile only via reviewed branches).
- Reconciliation runs as a **NetBox UI workflow**, applied with **NetBox Branching** after review.

## Problem

Drift when runtime changes outpace NetBox: MAAS add/remove machines, OpenStack IP/FIP changes, VLAN/prefix/cabling gaps. Without reconciliation, NetBox diverges from reality.

## High-level approach

1. **Read-only drift audit** → structured report  
2. **Reconciliation branch** → proposed changes  
3. **Engineer review** → merge or discard  

**Principle:** No external system overwrites NetBox design intent without review.

## Design principles

| Principle | Meaning |
|-----------|---------|
| NetBox authoritative for design | Inventory, IPAM, VLAN design, topology intent |
| Runtime = operational state | MAAS / OpenStack for drift detection |
| Drift visible first | Always audit before writes |
| Changes reviewable | Branch, not direct main |
| Idempotent | Repeatable runs, no dupes |
| Fail safe | Unreachable APIs → abort, no silent failures |

## Reconciliation flow

```
MAAS (bare metal) ─┐
OpenStack (cloud) ─┼→ Phase 0: Cross-system audit (read-only) → report
LLDP (cabling)    ─┘         ↓
                    Branch reconciliation → review → merge/reject
```

## Source-of-truth boundaries

| Domain | Authoritative |
|--------|----------------|
| Physical cabling | **LLDP** (validate NetBox cabling; not auto-rewire in v1) |
| Hardware presence / MACs | **MAAS** |
| Runtime IP allocation (cloud) | **OpenStack** |
| Design intent & IP planning | **NetBox** |

**MAAS must not overwrite NetBox design:** hostnames, site/rack, roles, VLAN design, and **populated chassis serial / manufacturer / model** when those reflect **netbox-agent** or manual design (MAAS reconciles/validates; see serial rules below).

**OpenStack** does not own NetBox IPAM design; used for **runtime visibility and drift**.

## Identity keys (reconciliation matching)

| Object | Identity key |
|--------|----------------|
| **Device** | **hostname** (match); **serial** validates identity when present — see **Serial & hardware identity** below |
| **Interface** | device + interface name (**validated by MAC**) |
| **VLAN** | VLAN Group + VID |
| **Prefix** | prefix + VRF |
| **IP address** | IP + VRF |
| **Floating IP** | **IP + tenant/project** |

## Serial number & hardware identity (drift / sync logic)

**Context:** MAAS reports serial from commissioning/DMI; **netbox-agent** typically reads **live** chassis serial into NetBox. In practice **NetBox serial is often more reliable** once agent has run; MAAS serial remains useful for cross-check and for machines **not yet** enrolled with agent.

### Source-of-truth for chassis serial

| Situation | Rule |
|-----------|------|
| NetBox serial **already populated** (e.g. by agent) | **Do not overwrite** with MAAS on reconciliation. If MAAS serial **differs**, treat as **drift** — report/flag for review, not auto-sync. |
| NetBox device **missing**; create from MAAS (future branch sync) | May **seed** serial from MAAS **only while** NetBox serial is empty; expect **agent to become authoritative** when the host runs agent. |
| Serial missing everywhere | Match on **hostname** (and MAC/`system_id` for idempotency); fill serial when agent or trusted source appears. |

### Matching policy (device exists or not)

Recommended order for **“is this the same physical machine?”**:

1. **Serial** — when both sides expose a trusted serial, use for **validation** (and strongest dedupe when hostname changed).
2. **Hostname** (short name ↔ NetBox device name) — **primary join in Phase 0 drift today**; serial is often sparse, so hostname is the usual key.
3. **MAC / interface correlation** — fallback at **interface** level; weak alone for whole-device identity.
4. **MAAS `system_id`** — durable **MAAS-side** id for idempotent ETL / traceability (store in custom field if desired).

### MAAS → NetBox scope for hardware fields

- **MAAS owns:** machine presence, lifecycle, hostname (as observed), interfaces, MACs, fabric/VLAN context, **BMC endpoint** (power parameters — surfaced in drift as **MAAS BMC** vs NetBox **OOB IP**).
- **NetBox-agent / design owns:** chassis serial, manufacturer, model where org policy says agent is truth — **v1 sync does not stomp those from MAAS** once set.

## Automation scope (rollout)

### MAAS → NetBox (primary)

- Create/update devices from MAAS machines (respect **serial/hardware** rules above)  
- Create/update interfaces from MAAS NICs  
- MAC alignment  
- Tag `source:maas`  
- NetBox-only devices → **orphan** candidates (report; no auto-delete)  

### OpenStack → NetBox (visibility)

- Networks/subnets → NetBox **prefixes**  
- Floating IPs → NetBox **IP objects**  
- Tag `source:openstack`  
- Future: port IPs, tenant mapping  

## Interface VLAN reconciliation

### Physical interfaces (MAAS)

If MAAS exposes VLAN information:

- Sync **untagged** VLAN  
- Sync **tagged** VLANs when clearly defined  
- Validate **prefix** alignment  
- Tag mismatches **`vlan-drift`**

### Virtual networks (OpenStack)

- Reconcile **provider VLAN** definitions  
- Associate **prefixes** with VLAN objects  

OpenStack **does not control physical NIC VLAN state**.

## VLAN rollout model

Initial rollout will be **conservative**.

**Phase 1** includes:

- Single **untagged** VLAN per physical interface  
- Tagged VLANs only when **clearly exposed** (API/UI)  
- No trunk or LAG modeling changes  

Advanced VLAN modeling may be introduced later.

## VLAN reconciliation guardrails

To protect infrastructure integrity:

- No automatic VLAN **deletion**  
- No **VLAN group** reassignment  
- No **trunk** modeling changes  
- No overwrite of **NetBox design intent**  
- Large VLAN updates must run in **scoped** mode  

*Mapping reminder:* MAAS **fabric** ↔ NetBox **VLAN group** (convention per site); MAAS **VLAN** ↔ NetBox **VLAN** by **VID** where API exposes it (summary UI may show names only).

### Phase 0 audit scope (this plugin, read-only)

| Comparison | In drift report today |
|------------|------------------------|
| MAAS ↔ NetBox inventory | Yes (hostname, zone/pool/fabric, status, system_id vs serial) |
| MAAS ↔ NetBox interfaces | Yes (MAC + name + IP per NIC) |
| MAAS ↔ NetBox **untagged VID** (physical NIC) | Yes when MAAS API exposes `vid`: **VLAN_DRIFT** / **VLAN_DRIFT+IP_GAP** per row; Phase 0 counts **vlan-drift** + **VLAN unverified** (NB VID set, MAAS silent). Tagged/trunk/OpenStack provider VLAN not in this audit yet. |
| OpenStack ↔ NetBox IPAM | Yes (subnet CIDR vs Prefix; FIP vs IPAddress + project) |
| LLDP ↔ NetBox cabling | **Not yet** (planned) |
| VLAN **branch** reconciliation (writes) | **Not yet** (Phase 1+; guardrails above) |

## Workflow modes

- **Drift audit:** read-only; categorized report; **no NetBox writes**.  
- **Full sync:** MAAS + OpenStack + optional VLAN → **branch only** (future).

## Success metrics (targets)

| Metric | Target |
|--------|--------|
| MAAS coverage in NetBox | 100% |
| MAC mismatch rate | ~0 |
| Orphan count | decreasing |
| Prefix conflicts | detected early |
| Prefix/VLAN alignment | validated over time |

## Deliverables

- NetBox workflow **MAAS / OpenStack Sync**  
- Module in **netbox-automation-plugin**  
- Drift audit reporting (this document + `CONFIG.md`)  
- Branch reconciliation (future)  

---

*Derived from project design doc. Implementation details: `CONFIG.md`, `clients/maas_client.py`, `openstack_client.py`, `reporting/drift_report.py`.*
