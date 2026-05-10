#!/usr/bin/env python3
"""Static checks for Blastwall policy scope wiring."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policy"


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


makefile = (POLICY / "Makefile").read_text(encoding="utf-8")
match = re.search(r"^DENY_POLICIES\s*:=\s*(.+)$", makefile, re.MULTILINE)
if not match:
    fail("policy/Makefile does not define DENY_POLICIES")

deny_policies = match.group(1).split()
if not deny_policies:
    fail("DENY_POLICIES is empty")

for policy in deny_policies:
    cil_path = POLICY / f"{policy}.cil"
    if not cil_path.exists():
        fail(f"{cil_path.relative_to(ROOT)} is listed but missing")

    cil = cil_path.read_text(encoding="utf-8")
    if "(deny " not in cil:
        fail(f"{cil_path.relative_to(ROOT)} does not contain a deny rule")
    if "(neverallow " not in cil:
        fail(f"{cil_path.relative_to(ROOT)} does not contain a neverallow rule")

print(f"PASS: validated {len(deny_policies)} deny policy scopes")
