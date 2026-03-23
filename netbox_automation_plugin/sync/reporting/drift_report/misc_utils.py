"""Small string/device helpers shared by drift report modules."""

def _device_by_name(netbox_data):
    out = {}
    for d in (netbox_data or {}).get("devices") or []:
        n = (d.get("name") or "").strip()
        if n:
            out[n] = d
    return out


def _dedupe_note_parts(text: str) -> str:
    if not text:
        return ""
    parts = [p.strip() for p in str(text).replace("\n", " ").split(";")]
    seen = set()
    ordered = []
    for p in parts:
        if not p:
            continue
        k = p.lower()
        if k in seen:
            continue
        seen.add(k)
        ordered.append(p)
    return "; ".join(ordered)


def _ip_address_host(ip_str: str) -> str:
    """Host portion of an IP or CIDR string, lowercased."""
    if not ip_str or ip_str == "—":
        return ""
    return str(ip_str).split("/", 1)[0].strip().lower()
