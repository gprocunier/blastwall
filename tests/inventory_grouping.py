#!/usr/bin/env python3
"""Validate Blastwall current/stale policy marker grouping semantics."""

from pathlib import Path
import json
import sys


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "inventory-policy-markers.json"

ACCEPTED_POLICY_RPMS = [
    "bw_rpm=blastwall-selinux-0.5.2-1",
]

REQUIRED_MARKERS = [
    "bw_state=active",
    "bw_alg=deny",
    "bw_bpf=deny",
    "bw_self=deny",
    "bw_pkt=deny",
    "bw_userns=deny",
    "bw_iou=deny",
    "bw_xfrm=deny",
    "bw_rxrpc=deny",
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
