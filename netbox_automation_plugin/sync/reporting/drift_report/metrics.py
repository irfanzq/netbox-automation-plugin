"""Phase 0 counts, run metadata, severity triage."""

def _phase0_category_counts(
    drift,
    matched_rows,
    interface_audit,
    os_subnet_gaps,
    os_floating_gaps,
):
    maas_only = len(drift.get("in_maas_not_netbox") or [])
    check_hosts = sum(1 for r in (matched_rows or []) if r.get("place_match") == "CHECK")
    iface_not_ok = 0
    maas_nic_missing_nb = 0
    vlan_drift_nic = 0
    vlan_unverified_nic = 0
    for b in (interface_audit or {}).get("hosts") or []:
        for row in b.get("rows") or []:
            st = row.get("status") or ""
            if st not in {"OK", "OK_NAME_DIFF", "NAME_DIFF_ONLY"}:
                iface_not_ok += 1
            if st == "NOT_IN_NETBOX":
                maas_nic_missing_nb += 1
            if st.startswith("VLAN_DRIFT") or st.startswith("OS_RUNTIME_VLAN_DRIFT"):
                vlan_drift_nic += 1
            notes = row.get("notes") or ""
            if "VLAN unverified:" in notes:
                vlan_unverified_nic += 1
    if os_subnet_gaps is None:
        sub_gaps = None
    else:
        sub_gaps = len(os_subnet_gaps or [])
    fip_gaps = len(os_floating_gaps or [])
    return {
        "maas_only": maas_only,
        "check_hosts": check_hosts,
        "iface_not_ok": iface_not_ok,
        "maas_nic_missing_nb": maas_nic_missing_nb,
        "sub_gaps": sub_gaps,
        "fip_gaps": fip_gaps,
        "vlan_drift_nic": vlan_drift_nic,
        "vlan_unverified_nic": vlan_unverified_nic,
    }


def _align_phase0_counts_with_rendered_details(
    pc: dict,
    *,
    update_nic_rows=None,
    add_nb_interface_rows=None,
    alignment_rows=None,
    add_device_rows=None,
    add_device_review_rows=None,
):
    """
    Normalize headline counts to the same rendered/filtered rows used by detail tables.
    This avoids confusion when raw audit rows are later merged/deferred/hidden.
    """
    out = dict(pc or {})
    if alignment_rows is not None:
        out["check_hosts"] = len(alignment_rows or [])
    if add_device_rows is not None or add_device_review_rows is not None:
        out["maas_only"] = len(add_device_rows or []) + len(add_device_review_rows or [])
    if update_nic_rows is not None or add_nb_interface_rows is not None:
        upd = list(update_nic_rows or [])
        addi = list(add_nb_interface_rows or [])
        out["iface_not_ok"] = len(upd) + len(addi)
        out["maas_nic_missing_nb"] = len(addi)
        out["vlan_drift_nic"] = sum(
            1
            for r in upd
            if isinstance(r, (list, tuple))
            and len(r) >= 2
            and "SET_NETBOX_UNTAGGED_VLAN=" in str(r[-2] or "")
        )
    return out


def _matched_hosts_with_drift(matched_rows):
    """Rows that have review hints (place_match CHECK) so we show drifting hosts only."""
    if not matched_rows:
        return []
    return [
        r for r in matched_rows
        if r.get("place_match") == "CHECK" or (r.get("hints") or [])
    ]


def _count_hints(matched_rows, needle: str) -> int:
    c = 0
    for r in (matched_rows or []):
        for h in (r.get("hints") or []):
            if needle in (h or ""):
                c += 1
                break
    return c


def _truncate_run_meta(text: str, max_len: int = 240) -> str:
    s = (text or "").strip()
    if not s:
        return ""
    if len(s) <= max_len:
        return s
    return s[: max_len - 1].rstrip() + "…"


def _run_metadata_rows(maas_data, netbox_data, openstack_data):
    """
    Trust/context lines for reviewers: source reachability, match policy, scope, action mode.
    Returns rows for Property / Value tables.
    """
    maas_data = maas_data or {}
    netbox_data = netbox_data or {}

    def _maas_line():
        err = maas_data.get("error")
        if err:
            return f"Failed — {_truncate_run_meta(str(err))}"
        return "Reachable / success"

    def _netbox_line():
        err = netbox_data.get("error")
        if err:
            return f"Failed — {_truncate_run_meta(str(err))}"
        return "Reachable / success"

    def _openstack_line():
        if openstack_data is None:
            return "Skipped — OpenStack not fetched for this run"
        osd = openstack_data or {}
        if osd.get("openstack_cred_missing"):
            return "Not configured — OpenStack credentials missing"
        err = osd.get("error")
        if err:
            return f"Failed — {_truncate_run_meta(str(err))}"
        return "Reachable / success"

    return [
        ["MAAS source", _maas_line()],
        ["OpenStack source", _openstack_line()],
        ["NetBox source", _netbox_line()],
        [
            "Authority policy",
            "OpenStack runtime wins when present (NIC/BMC/lifecycle); MAAS fallback when OS data is missing.",
        ],
        ["Match logic", "Hostname + NIC MAC (plus Ironic runtime mapping where available)"],
        ["Scope", "Phase 0 audit only (discovery + drift + proposed actions)"],
        [
            "Action mode",
            "Read-only from this screen: no NetBox write. Branch apply/merge is handled in a separate NetBox branch workflow.",
        ],
    ]


def _severity_triage_rows(
    pc,
    *,
    serial_validation_needed: int,
    bmc_oob_mismatch: int,
    netbox_outside_scope: int = 0,
):
    """
    Severity policy for Phase 0 review.
    Returns rows: [severity, category, count, why].
    """
    sub_count = pc["sub_gaps"] if pc["sub_gaps"] is not None else "N/A"
    return [
        [
            "High",
            "OpenStack FIP → no IP record",
            str(pc["fip_gaps"]),
            "Routable addresses may exist without NetBox/IPAM tracking.",
        ],
        [
            "High",
            "OpenStack subnet → no Prefix",
            str(sub_count),
            "Subnet usage exists but design intent is missing from IPAM.",
        ],
        [
            "High",
            "VLAN mismatch (runtime authority vs NetBox)",
            str(pc["vlan_drift_nic"]),
            "Authoritative runtime VLAN (OpenStack when present, else MAAS) differs from NetBox intent.",
        ],
        [
            "High",
            "BMC vs NetBox OOB differs (OS/MAAS fallback)",
            str(bmc_oob_mismatch),
            "Out-of-band access may target the wrong management endpoint.",
        ],
        [
            "Medium",
            "NIC rows not OK",
            str(pc["iface_not_ok"]),
            "Interface-level deltas need review (IP/MAC/VLAN alignment).",
        ],
        [
            "Medium",
            "MAAS NIC missing in NetBox",
            str(pc["maas_nic_missing_nb"]),
            "Operational interfaces are present but not yet modeled.",
        ],
        [
            "Low",
            "Matched — review hints",
            str(pc["check_hosts"]),
            "Review host alignment/lifecycle hints (fabric vs location, lifecycle state mismatches). NIC and OOB drift are covered in dedicated detail tables.",
        ],
        [
            "Low",
            "NetBox serial missing",
            str(serial_validation_needed),
            "Asset metadata quality gap; usually non-blocking for connectivity.",
        ],
        [
            "Info",
            "VLAN unverified from MAAS fallback",
            str(pc["vlan_unverified_nic"]),
            "Observation is incomplete; confirm before applying intent changes.",
        ],
        [
            "Info",
            "In MAAS only (not in NetBox)",
            str(pc["maas_only"]),
            "Discovery candidate count for onboarding review.",
        ],
        [
            "Info",
            "MAAS in scope, NetBox device under other site/location",
            str(netbox_outside_scope),
            "Not missing from NetBox; expand site/location filters to include NIC drift for these hosts.",
        ],
    ]
