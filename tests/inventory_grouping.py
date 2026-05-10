#!/usr/bin/env python3
"""Validate Blastwall current/stale policy marker grouping semantics."""

from pathlib import Path
import json
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "inventory-policy-markers.json"

ACCEPTED_POLICY_RPMS = [
    "blastwall-selinux-0.5.2-1",
]

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_MARKERS = {
    "state": "active",
    "alg": "deny",
    "bpf": "deny",
    "self": "deny",
    "pkt": "deny",
    "userns": "deny",
    "iou": "deny",
    "xfrm": "deny",
    "rxrpc": "deny",
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_marker(marker):
    if not marker.startswith("blastwall:"):
        return {}

    return {
        key: value
        for key, value in (
            token.split("=", 1)
            for token in marker.removeprefix("blastwall:").split(";")
            if "=" in token
        )
    }


def is_current(userclass) -> bool:
    if isinstance(userclass, str):
        userclass = [userclass]

    if not isinstance(userclass, list):
        return False

    for marker in userclass:
        parsed = parse_marker(marker)
        if not parsed:
            continue

        if parsed.get("rpm") not in ACCEPTED_POLICY_RPMS:
            continue

        if not SHA256_RE.match(parsed.get("rpm_sha256", "")):
            continue

        if all(parsed.get(marker_name) == value for marker_name, value in REQUIRED_MARKERS.items()):
            return True

    return False


fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
actual = {
    "blastwall_policy_current": [],
    "blastwall_policy_stale": [],
}

for host in fixture["hosts"]:
    if "description" in host:
        fail("fixture host entries should use idm_userclass, not description")
    group = "blastwall_policy_current" if is_current(host.get("idm_userclass", [])) else "blastwall_policy_stale"
    actual[group].append(host["name"])

if actual != fixture["expected"]:
    print("FAIL: inventory policy marker grouping mismatch", file=sys.stderr)
    print(json.dumps({"actual": actual, "expected": fixture["expected"]}, indent=2), file=sys.stderr)
    raise SystemExit(1)

print("PASS: inventory marker grouping selects current and stale hosts")
