#!/usr/bin/env python3
"""
Probe common management APIs on a node to see where interface / IP / (maybe) VRF data exists.

Reality check
-------------
- **BMC HTTPS + Redfish** (see ``test_gpu_http.py``): great for BMC and sometimes host NIC
  inventory; **VRF is rarely modeled**, and **host L3** is often incomplete.
- **NETCONF (TCP 830)** on a random GPU/Linux box is **unusual** — typical on routers/switches
  (Cisco, Juniper, some NOS). This script only checks reachability / optional client connect.
- **SNMP**: can list interfaces + IPv4 **if** ``snmpd`` (or a BMC SNMP agent) answers on the
  IP you target. **Linux VRF** is **not** in standard IF-MIB / IP-MIB; you still need the OS
  for ``ip vrf``.
- **SSH** (not implemented here — use your normal access): best on Linux for
  ``ip -br addr``, ``ip vrf show``, routes.

What to give this script
------------------------
- **Host**: IP (or DNS) that actually reaches the service:
  - BMC IP → Redfish + sometimes BMC SNMP.
  - Linux mgmt/data IP → host ``snmpd`` / SSH.
- **SNMPv2 community** (lab only — SNMPv2c is cleartext) via ``--snmp-community`` or env
  ``SNMP_COMMUNITY``.
- Optional **SNMPv3** via ``--snmp-v3`` plus user/auth/priv (if you use it).

Dependencies
------------
- Port checks: stdlib only.
- SNMP: ``snmpwalk`` in ``PATH`` (e.g. ``brew install net-snmp`` on macOS).
- NETCONF: optional ``pip install ncclient`` (this script only notes if import works; creds are
  still required for a real session).

Examples
--------
  python scripts/probe_host_network_apis.py 172.17.114.101
  python scripts/probe_host_network_apis.py 172.17.114.101 --snmp-community public
  SNMP_COMMUNITY=private python scripts/probe_host_network_apis.py 172.17.114.101
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_ports(host: str, timeout: float) -> None:
    print(f"\n=== TCP connect ({host}) ===")
    checks = [
        (22, "ssh"),
        (443, "https"),
        (830, "netconf (often SSH-based; open port != full NETCONF)"),
    ]
    for port, label in checks:
        ok = _tcp_open(host, port, timeout)
        print(f"  {port}/tcp  {label}: {'open' if ok else 'closed/filtered'}")


def _run_snmpwalk_cmd(
    host: str,
    community: str,
    oid: str,
    timeout_s: int,
) -> tuple[int, str]:
    exe = shutil.which("snmpwalk")
    if not exe:
        return 127, "snmpwalk not in PATH"
    cmd = [
        exe,
        "-v2c",
        "-c",
        community,
        "-t",
        str(timeout_s),
        "-r",
        "1",
        host,
        oid,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 5)
    except subprocess.TimeoutExpired:
        return 124, "snmpwalk timed out"
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode, out.strip()


def probe_snmp_v2c(host: str, community: str, timeout: float) -> None:
    print(f"\n=== SNMPv2c ({host}, community from args/env) ===")
    t = max(1, int(timeout))

    # ipAddrTable — IPv4 addresses (1.3.6.1.2.1.4.20)
    oid_ip = "1.3.6.1.2.1.4.20.1.1"
    if not shutil.which("snmpwalk"):
        print(
            "  snmpwalk not in PATH — install net-snmp (e.g. brew install net-snmp) "
            "or use your OS package manager, then re-run with --snmp-community."
        )
        return

    code, out = _run_snmpwalk_cmd(host, community, oid_ip, t)
    label = "snmpwalk ipAddrTable (sample)"
    if code == 0:
        sample = "\n".join(out.splitlines()[:40])
        print(f"  {label}:\n{sample}")
        n = len(out.splitlines())
        if n > 40:
            print(f"  ... ({n} lines total)")
    else:
        print(f"  {label}: exit {code}\n{out[:800]}")

    oid_if = "IF-MIB::ifDescr"
    code2, out2 = _run_snmpwalk_cmd(host, community, oid_if, t)
    if code2 == 0:
        lines2 = out2.splitlines()
        print(f"\n  snmpwalk ifDescr (first 25 of {len(lines2)}):")
        print("\n".join(lines2[:25]))
    else:
        print(f"\n  ifDescr: exit {code2}\n{out2[:600]}")

    print(
        "\n  Note: standard SNMP MIBs do not map Linux **VRF** names. "
        "Use ``ip vrf`` on the host or your CMDB."
    )


def probe_netconf_stub(host: str, timeout: float) -> None:
    print(f"\n=== NETCONF ({host}) ===")
    print("  Most GPU/Linux hosts do not expose NETCONF. Switches/NOS often use SSH (not raw 830).")
    open830 = _tcp_open(host, 830, timeout)
    print(f"  830/tcp open: {open830}")
    try:
        import ncclient  # noqa: F401
    except ImportError:
        print(
            "  ncclient not installed — skipping client attempt. "
            "`pip install ncclient` if you truly have a NETCONF endpoint + creds."
        )
        return
    print(
        "  ncclient is present but this script does not guess credentials. "
        "Use your vendor's tooling or interactive SSH-NETCONF once you have user/key."
    )


def main() -> int:
    p = argparse.ArgumentParser(description="Probe SSH/HTTPS/NETCONF ports and optional SNMP on a host.")
    p.add_argument("host", help="Target IP or hostname (BMC IP vs Linux IP matters for SNMP).")
    p.add_argument("--timeout", type=float, default=3.0, help="TCP / SNMP timeout (seconds)")
    p.add_argument(
        "--snmp-community",
        default=os.environ.get("SNMP_COMMUNITY", ""),
        help="SNMPv2c community (or set SNMP_COMMUNITY). If empty, SNMP section is skipped.",
    )
    args = p.parse_args()

    host = args.host.strip()
    if not host:
        print("host required", file=sys.stderr)
        return 2

    probe_ports(host, args.timeout)
    probe_netconf_stub(host, args.timeout)

    if args.snmp_community:
        probe_snmp_v2c(host, args.snmp_community, args.timeout)
    else:
        print("\n=== SNMP ===")
        print("  Skipped (no --snmp-community / SNMP_COMMUNITY).")
        print("  Example:  --snmp-community public")

    print("\n=== What I need from you for richer results ===")
    print("  1. Which IP is which: BMC vs Linux host mgmt?")
    print("  2. SNMP: community (lab) or v3 user + auth/priv parameters.")
    print("  3. For definitive IP + VRF on Linux: SSH and ``ip -br addr`` / ``ip vrf show``.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
