"""Limits and Phase 0 field-ownership copy for drift reporting."""

_MAX_MAAS_MISSING_ROWS = 500
_MAX_OS_NETWORKS = 40
_MAX_OS_SUBNET_HINTS = 60
_MAX_COL = 10000
_MAX_MATCHED_COL = 18
_MAX_NOTES_COL = 42
_NOTES_COL_MAX_WIDTH = 8000
_DYNAMIC_COL_CAP = 10000
_ASCII_COL_WRAP_DEFAULT = 96
_ASCII_NOTES_COL_WRAP = 200

_DT_MATCH_MIN_SCORE = 220.0
_DT_MATCH_TIE_EPSILON = 24.0
_DT_MATCH_NARROW_MIN = 20

_PHASE0_FIELD_OWNERSHIP_TITLE = "Field ownership — Phase 0 drift audit"
_PHASE0_FIELD_OWNERSHIP_LEAD = (
    "NetBox is the canonical inventory model in this workflow. "
    "Where OpenStack runtime exists for a host, it is the primary source for live NIC signals (MAC, IP, VLAN) and supported lifecycle context; "
    "MAAS covers commissioning, OOB/power, host/NIC correlation, and fallback when OpenStack is absent or not authoritative. "
    "Proposed actions are review-gated and do not run automatically."
)
_PHASE0_FIELD_OWNERSHIP_BULLETS = (
    "Discovery scope in Phase 0: detect new device candidates and drift; do not auto-apply changes.",
    "OpenStack is not only subnet/Floating IP inventory: enrolled runtime is primary for per-host NIC drift (MAC, IP, VLAN) and supported device lifecycle signals in this audit when available.",
    "MAAS is used for commissioning inventory, BMC/OOB power documentation, matching, drift visibility, and MAAS-fallback authority when OpenStack runtime is absent or non-authoritative for a host.",
    "OpenStack subnet and floating IP state additionally supports NetBox/IPAM gap detection beyond per-host runtime.",
    "Explicit non-goals for this phase: no blind hostname renames and no deletes from this screen.",
    "Conflict handling: operational evidence is compared to model intent; NetBox remains authoritative after approved updates.",
)
