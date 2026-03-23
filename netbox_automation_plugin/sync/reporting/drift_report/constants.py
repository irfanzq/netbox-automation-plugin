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
    "MAAS and OpenStack supply runtime signals for comparison and gap detection; "
    "proposed actions are review-gated suggestions to align NetBox and do not run automatically."
)
_PHASE0_FIELD_OWNERSHIP_BULLETS = (
    "Discovery scope in Phase 0: detect new device candidates and drift; do not auto-apply changes.",
    "MAAS data is used for host/NIC matching and drift visibility (MAC, IP, VLAN observations).",
    "OOB/BMC values from MAAS power data inform NetBox management documentation alignment.",
    "OpenStack subnet and floating IP state is used to detect NetBox/IPAM gaps.",
    "Explicit non-goals for this phase: no blind hostname renames and no deletes from this screen.",
    "Conflict handling: operational evidence is compared to model intent; NetBox remains authoritative after approved updates.",
)
