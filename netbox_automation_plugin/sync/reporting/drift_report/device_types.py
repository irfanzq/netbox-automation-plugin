"""MAAS hardware → NetBox device type and role inference."""

import difflib
import json
import re
from collections import defaultdict

from netbox_automation_plugin.sync.reporting.drift_report.constants import (
    _DT_MATCH_MIN_SCORE,
    _DT_MATCH_NARROW_MIN,
    _DT_MATCH_TIE_EPSILON,
)

def _maas_vendor_product(machine: dict) -> tuple[str, str]:
    hi = machine.get("hardware_info")
    if isinstance(hi, str) and hi.strip().startswith("{"):
        try:
            hi = json.loads(hi)
        except Exception:
            hi = None
    if not isinstance(hi, dict):
        hi = {}
    vendor = (
        str(machine.get("hardware_vendor") or hi.get("system_vendor") or hi.get("vendor") or "")
    ).strip()
    product = (
        str(
            hi.get("system_product")
            or machine.get("hardware_product")
            or machine.get("product_name")
            or hi.get("product_name")
            or hi.get("mainboard_product")
            or ""
        )
    ).strip()
    if vendor.lower() in ("unknown", "none", "n/a", ""):
        vendor = ""
    if product.lower() in ("unknown", "none", "n/a", ""):
        product = ""
    return vendor, product


def _maas_product_sku_tokens(product: str) -> list[str]:
    """
    Pull hardware SKU-like tokens from a MAAS product string so we can match NetBox
    models that only store the short code (e.g. ``R660`` from ``PowerEdge R660``).
    """
    p = (product or "").strip()
    if not p:
        return []
    found: set[str] = set()
    # Dell PowerEdge rack / common patterns
    for m in re.finditer(r"\bR\d{3,4}[A-Z]{0,4}\b", p, re.I):
        found.add(m.group(0))
    for m in re.finditer(r"\bC\d{3,4}[A-Z]{0,4}\b", p, re.I):
        found.add(m.group(0))
    for m in re.finditer(r"\bDL\d{3,4}[A-Z]?\b", p, re.I):
        found.add(m.group(0))
    for m in re.finditer(r"\bXR\d{3,4}\w*\b", p, re.I):
        found.add(m.group(0))
    # Broader alnum product codes (e.g. other vendors)
    for m in re.finditer(r"\b[A-Z]{1,4}\d{3,5}[A-Z0-9\-]{0,6}\b", p, re.I):
        found.add(m.group(0))
    return sorted(found, key=lambda t: (-len(t), t.lower()))


def _device_type_contains_sku_token(dt: dict, token: str) -> bool:
    """True if token appears as its own token in model, slug, or display (not R660 inside R660xs)."""
    if not token:
        return False
    pat = re.compile(
        rf"(?<![A-Za-z0-9]){re.escape(token)}(?![A-Za-z0-9])",
        re.I,
    )
    for key in ("model", "slug", "display"):
        s = (dt.get(key) or "").strip()
        if s and pat.search(s):
            return True
    return False


def _fold_device_type_text(s: str) -> str:
    """Lowercase, alnum tokens, single spaces — for similarity and containment."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", (s or "").lower())).strip()


def _norm_vendor_dtype(v: str) -> str:
    """Normalize manufacturer string for bucketing (must match MAAS vendor normalization)."""
    s = re.sub(r"[^a-z0-9]+", " ", str(v or "").lower()).strip()
    toks = [t for t in s.split() if t]
    while toks and toks[-1] in {
        "inc",
        "incorporated",
        "corp",
        "corporation",
        "ltd",
        "llc",
        "co",
        "company",
    }:
        toks.pop()
    return " ".join(toks)


def _build_device_type_match_index(types_list: list) -> dict[str, list[dict]]:
    """
    One-time index: normalized manufacturer -> pre-folded NetBox device type rows.
    Speeds up per-host matching (no repeated string folding; smaller candidate sets).
    """
    buckets: dict[str, list[dict]] = defaultdict(list)
    for dt in types_list or []:
        if not isinstance(dt, dict):
            continue
        man_raw = (dt.get("manufacturer") or "").strip()
        man_norm = _norm_vendor_dtype(man_raw)
        model_raw = (dt.get("model") or "").strip()
        fold_m = _fold_device_type_text(model_raw)
        fold_d = _fold_device_type_text(dt.get("display") or "")
        fold_s = _fold_device_type_text((dt.get("slug") or "").replace("-", " "))
        fold_c = _fold_device_type_text(f"{man_raw} {model_raw}")
        tok_m = frozenset(fold_m.split()) if fold_m else frozenset()
        tok_d = frozenset(fold_d.split()) if fold_d else frozenset()
        tok_c = frozenset(fold_c.split()) if fold_c else frozenset()
        blob = f"{fold_m}{fold_s}{fold_d}".replace(" ", "").replace("-", "")
        buckets[man_norm].append(
            {
                "dt": dt,
                "model_lower": model_raw.lower(),
                "fold_m": fold_m,
                "fold_d": fold_d,
                "fold_s": fold_s,
                "fold_c": fold_c,
                "tok_m": tok_m,
                "tok_d": tok_d,
                "tok_c": tok_c,
                "blob": blob,
            }
        )
    return dict(buckets)


def _narrow_dtype_entries(
    entries: list[dict],
    prod_fold: str,
    prod_nums: list[str],
    sku_tokens: list[str],
) -> list[dict]:
    """Cheap filter before SequenceMatcher when a vendor has many device types."""
    if len(entries) <= _DT_MATCH_NARROW_MIN:
        return entries
    if not prod_fold:
        return entries
    prod_word_toks = frozenset(prod_fold.split())
    narrowed: list[dict] = []
    sku_slice = sku_tokens[:8]
    for e in entries:
        fm = e["fold_m"]
        if prod_fold == fm or prod_fold in fm or (fm and fm in prod_fold):
            narrowed.append(e)
            continue
        if prod_word_toks & e["tok_m"] or prod_word_toks & e["tok_d"] or prod_word_toks & e["tok_c"]:
            narrowed.append(e)
            continue
        if prod_nums and any(n in e["blob"] for n in prod_nums):
            narrowed.append(e)
            continue
        dt = e["dt"]
        for t in sku_slice:
            if _device_type_contains_sku_token(dt, t):
                narrowed.append(e)
                break
    return narrowed if narrowed else entries


def _seq_ratio_scaled(prod_fold: str, cand: str, scale: float) -> float:
    if len(cand) < 1:
        return 0.0
    return difflib.SequenceMatcher(None, prod_fold, cand).ratio() * scale


def _score_maas_product_vs_dtype_entry(
    prod_fold: str,
    product_n: str,
    sku_tokens: list[str],
    e: dict,
) -> float:
    """Same scoring ideas as before, using pre-folded index entry (faster per host)."""
    if not prod_fold:
        return 0.0
    model = e["fold_m"]
    disp = e["fold_d"]
    slug = e["fold_s"]
    combined = e["fold_c"]
    dt = e["dt"]

    parts: list[float] = []

    if model == prod_fold:
        parts.append(1000.0)
    if model:
        if prod_fold in model:
            parts.append(520.0 + min(len(prod_fold), 96) * 1.5)
        elif model in prod_fold and len(model) >= 3:
            parts.append(480.0 + min(len(model), 96) * 1.5)

    seen: set[str] = set()
    for cand in (model, disp, slug, combined):
        if not cand or cand in seen:
            continue
        seen.add(cand)
        parts.append(_seq_ratio_scaled(prod_fold, cand, 520.0))

    pt = set(prod_fold.split())
    seen_tok_cands: set[str] = set()
    for cand in (model, disp, combined):
        if not cand or cand in seen_tok_cands:
            continue
        seen_tok_cands.add(cand)
        ct = set(cand.split())
        if not pt or not ct:
            continue
        j = len(pt & ct) / len(pt | ct)
        parts.append(j * 420.0)

    nums = [n for n in re.findall(r"\d{3,5}", product_n) if len(n) >= 3]
    if nums:
        blob = e["blob"]
        matched = sum(1 for n in nums if n in blob)
        if matched:
            parts.append(95.0 * matched / len(nums))
        elif model:
            parts.append(-75.0)

    for tok in sku_tokens[:6]:
        if _device_type_contains_sku_token(dt, tok):
            parts.append(210.0)
            break

    return max(parts) if parts else 0.0


def _resolve_device_type_display(
    vendor_raw: str,
    product_n: str,
    dtype_index: dict[str, list[dict]],
) -> str:
    """
    Pick NetBox device type display for MAAS vendor/product using a pre-built index.
    Logic: exact model+vendor, else scored match among (narrowed) vendor bucket.
    """
    vendor_raw = (vendor_raw or "").strip()
    product_n = (product_n or "").strip()
    if not vendor_raw or not product_n:
        return "—"
    vendor_l = _norm_vendor_dtype(vendor_raw)
    entries = dtype_index.get(vendor_l) or []
    if not entries:
        return "—"

    exact_dt = [e["dt"] for e in entries if e["model_lower"] == product_n.lower()]
    if len(exact_dt) == 1:
        return (exact_dt[0].get("display") or "").strip() or "—"
    if len(exact_dt) > 1:
        return (exact_dt[0].get("display") or "").strip() + f" (ambiguous ×{len(exact_dt)})"

    prod_fold = _fold_device_type_text(product_n)
    prod_nums = [n for n in re.findall(r"\d{3,5}", product_n) if len(n) >= 3]
    sku_tokens = _maas_product_sku_tokens(product_n)
    candidates = _narrow_dtype_entries(entries, prod_fold, prod_nums, sku_tokens)

    scored = [
        (e["dt"], _score_maas_product_vs_dtype_entry(prod_fold, product_n, sku_tokens, e))
        for e in candidates
    ]
    scored.sort(
        key=lambda x: (
            -x[1],
            -len((x[0].get("model") or "")),
            (x[0].get("display") or "").lower(),
        )
    )
    best_dt, best_s = scored[0]
    if best_s < _DT_MATCH_MIN_SCORE:
        return "—"
    close = [
        dt
        for dt, s in scored
        if s >= best_s - _DT_MATCH_TIE_EPSILON and s >= _DT_MATCH_MIN_SCORE
    ]
    if len(close) > 1:
        return (close[0].get("display") or "").strip() + f" (ambiguous ×{len(close)})"
    return (best_dt.get("display") or "").strip() or "—"


def _is_storage_host_role(slug: str, name: str) -> bool:
    s = (slug or "").strip().lower()
    n = (name or "").strip().lower()
    if s == "storage-host" or n == "storage host":
        return True
    if "storage" in s and "host" in s and s != "storage":
        return True
    if "storage" in n and "host" in n and n.replace(" ", "") != "storage":
        return True
    return False


def _match_netbox_role_from_hostname(hostname: str, netbox_data: dict) -> str:
    hn = (hostname or "").strip().lower()
    if not hn:
        return "—"
    roles = netbox_data.get("device_roles") or []
    if not roles:
        return "—"
    tokens = {t for t in re.split(r"[^a-z0-9]+", hn) if t}

    def role_display(r: dict) -> str:
        name = (r.get("name") or "").strip()
        slug = (r.get("slug") or "").strip()
        return name or slug or "—"

    def pick_cpu_host() -> str:
        exact_name = [r for r in roles if (r.get("name") or "").strip().lower() == "cpu host"]
        if exact_name:
            return role_display(exact_name[0])
        exact_slug = [r for r in roles if (r.get("slug") or "").strip().lower() == "cpu-host"]
        if exact_slug:
            return role_display(exact_slug[0])
        for r in roles:
            s = (r.get("slug") or "").strip().lower()
            n = (r.get("name") or "").strip().lower()
            if "cpu" in s and "host" in s:
                return role_display(r)
            if "cpu" in n and "host" in n:
                return role_display(r)
        return "—"

    if "gpu" in tokens:
        for r in roles:
            s = (r.get("slug") or "").strip().lower()
            n = (r.get("name") or "").strip().lower()
            if "gpu" in s and "host" in s:
                return role_display(r)
            if "gpu" in n and "host" in n:
                return role_display(r)
        return "—"

    # Storage: token "stor" (org naming) OR token "weka" (explicit request), and hostname contains "se-s".
    if ("stor" in tokens or "weka" in tokens) and "se-s" in hn:
        candidates = []
        for r in roles:
            s = (r.get("slug") or "").strip().lower()
            n = (r.get("name") or "").strip().lower()
            if "weka" in tokens:
                if _is_storage_host_role(s, n):
                    candidates.append(r)
                    continue
            if _is_storage_host_role(s, n):
                continue
            if s == "storage" or n == "storage":
                candidates.append(r)
            elif "storage" in s and "host" not in s:
                candidates.append(r)
            elif "storage" in n and "host" not in n:
                candidates.append(r)
        if len(candidates) == 1:
            return role_display(candidates[0])
        if len(candidates) > 1:
            return role_display(candidates[0]) + f" (ambiguous ×{len(candidates)})"
        return "—"

    # VyOS (hostname / MAAS): do not auto-pick among router roles — orgs define several (edge vs
    # cluster vs gateway). Leave ``—`` so the operator chooses NB proposed role on the audit.
    if "vyos" in tokens or "vyos" in hn:
        return "—"

    if "cpu" in tokens or "osctrl" in tokens:
        return pick_cpu_host()

    return "—"
