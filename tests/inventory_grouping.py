#!/usr/bin/env python3
"""Validate Blastwall current/stale policy marker grouping semantics."""

from pathlib import Path
import json
import sys


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "inventory-policy-markers.json"

ACCEPTED_POLICY_RPMS = [
    "blastwall_policy_rpm=blastwall-selinux-0.5.0-1",
    "blastwall_policy_rpm=blastwall-selinux-0.5.1-1",
]

REQUIRED_MARKERS = [
    "blastwall_policy_state=active",
    "blastwall_policy_alg_socket=denied",
    "blastwall_policy_bpf=denied",
    "blastwall_policy_selfprotect=denied",
    "blastwall_policy_packet_socket=denied",
    "blastwall_policy_userns=denied",
    "blastwall_policy_io_uring=denied",
]


def is_current(description: str) -> bool:
    return (
        bool(description)
        and any(marker in description for marker in ACCEPTED_POLICY_RPMS)
        and all(marker in description for marker in REQUIRED_MARKERS)
    )


fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
actual = {
    "blastwall_policy_current": [],
    "blastwall_policy_stale": [],
}

for host in fixture["hosts"]:
    group = "blastwall_policy_current" if is_current(host.get("description", "")) else "blastwall_policy_stale"
    actual[group].append(host["name"])

if actual != fixture["expected"]:
    print("FAIL: inventory policy marker grouping mismatch", file=sys.stderr)
    print(json.dumps({"actual": actual, "expected": fixture["expected"]}, indent=2), file=sys.stderr)
    raise SystemExit(1)

print("PASS: inventory marker grouping selects current and stale hosts")
