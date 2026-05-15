# Phase 08 Remediation Checkpoint

Date: 2026-05-15

Branch: `blastwall-v2-phase-08-rc1k`

Start commit: `6ec0f9e5759a8c83f75f6c38cb1ec7257b382334`

Scope assertion: no new SELinux deny scopes, socket classes, KVM/seccomp/BPF
LSM enforcement, production `strange-socket-v1` promotion, or new marker
profile names were introduced.

## Phase Status

| Phase | Status | Owner | Evidence |
|---|---|---|---|
| 00 baseline and scope freeze | COMPLETE locally | main thread | this file, `future-scope-triage.md` |
| 01 marker pre-validation and hash contract | COMPLETE locally | main thread | `tools/blastwall_policy_hash.py`, marker tests |
| 02 preflight safety and targeting | COMPLETE locally | main thread | `playbooks/preflight.yml`, static tests |
| 03 inventory resilience and monitoring | COMPLETE locally | main thread | `tools/audit_blastwall_inventory.py`, audit playbook |
| 04 rollback recoverability | COMPLETE locally | main thread | deploy rescue verification and marker states |
| 05 base automation corpus replay | ARTIFACT READY, LIVE HOLD | main thread | `base-corpus-replay-report.md` |
| 06 OpenShift/SPO compatibility | COMPLETE locally, LIVE HOLD | main thread | `spo-compatibility-matrix.md` |
| 07 operator docs and governance | COMPLETE locally | main thread | one-page summary, runbook, decision tree, governance docs |
| 08 Calabi gate and release decision | HOLD | main thread | `phase-08-calabi-final-checkpoint.md` |

## Implemented Remediation

- Marker publication in deploy/promote now validates the emitted marker before
  IdM writes with expected registry hash, installed policy hash, RPM, target,
  required profile set, and explicit dry-run allowance.
- `policy_sha256` now means installed policy payload hash. RPM artifact identity
  remains in evidence as `artifact_sha256` or `policy_rpm_sha256`.
- Preflight splits no-eligible-host tolerance from marker validation. Marker
  validation remains enabled unless the dangerous bypass flag and reason are
  both explicit.
- Inventory grouping is generated from `tools/render_inventory_profile_groups.py`
  and exposes schema and parser anomaly groups.
- `tools/audit_blastwall_inventory.py` and
  `playbooks/audit-inventory-membership.yml` provide group movement evidence and
  current-to-stale detection.
- Deploy rollback verifies post-rescue module and login-context state and then
  publishes `failed`, `rollback-active`, or `rollback-failed` marker evidence.
- The base automation corpus playbook exists and records the required SELinux
  context before running ordinary automation tasks.
- OpenShift/SPO validation now fails closed on unknown `status.usage` shapes and
  records validation class evidence.
- Operator docs now cover the summary, troubleshooting path, inventory decision
  tree, ownership, scope triage, positioning, stable/reference decision, and
  second-maintainer tabletop.

## Validation Log

Local validation completed in this remediation pass. Live Calabi gates are
tracked separately in `phase-08-calabi-final-checkpoint.md`.

```bash
python3 tests/policy_static.py
# PASS

python3 tests/inventory_grouping.py
# PASS

python3 -m pytest -q tests/test_blastwall_marker.py tests/test_blastwall_policy_hash.py tests/test_check_blastwall_drift.py tests/test_audit_blastwall_inventory.py
# 49 passed

python3 -m pytest -q tests
# 65 passed

python3 tools/validate_blastwall_profiles.py --registry policy/profiles.yml
# PASS

python3 tools/check_blastwall_drift.py --registry policy/profiles.yml
# PASS

ansible-playbook --syntax-check -i localhost, playbooks/preflight.yml playbooks/deploy-policy.yml playbooks/promote-policy-rpm.yml playbooks/install-policy-rpm.yml playbooks/audit-inventory-membership.yml
# PASS

ansible-playbook --syntax-check -i localhost, tests/corpus/base_automation_corpus.yml
# PASS

npm run test:policy
# PASS

npm run test:openshift
# PASS

make test-fast
# PASS

npm run test:docs
# 108 passed

git diff --check
# PASS
```

## PM Sign-Off

Phase 00: remediation-only scope is frozen.

Phase 01: no host marker can become source of truth without local validation.

Phase 02: preflight cannot silently become a pass-through.

Phase 03: the control plane cannot lose track of hosts without an observable signal.

Phase 04: a failed deploy creates an incident signal, not ambiguity.

Phase 05: base corpus is defined, but live operability remains a Calabi gate.

Phase 06: OpenShift evidence is bounded to the exact proven cluster/SPO behavior.

Phase 07: project operation no longer depends only on maintainer memory.

Phase 08: HOLD until live Calabi gates are rerun on this branch after remediation.
