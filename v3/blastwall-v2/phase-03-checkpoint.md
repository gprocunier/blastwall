# Blastwall v2 Phase 03 Checkpoint

## Summary

- Phase: 03 - static validation and drift checks
- Branch: `blastwall-v2-phase-03-drift-checks`
- Commit: this phase commit
- Date: 2026-05-10T16:55:22-04:00
- Operator: release automation

Phase 03 adds a registry-driven drift checker for the current Blastwall base
posture. It validates that active profiles and variants stay in sync with
registry scopes, RHEL CIL artifacts, OpenShift/SPO RawSelinuxProfile artifacts,
required safe probes or evidence sources, and public docs. It does not add
SELinux enforcement, enable planned scopes, alter marker behavior, or change
OpenShift admission behavior.

## Repository Changes

- Added `tools/check_blastwall_drift.py` as the Phase 03 static drift checker.
- Added `tests/test_check_blastwall_drift.py` with negative fixtures for active
  profile drift, missing deny/neverallow coverage, missing probes, invalid
  variant removals, optional class handling, missing documentation, and
  OpenShift `status.usage` contract drift.
- Updated `package.json` so `npm run test:policy` runs the drift checker and
  its unit tests before the existing marker, inventory, policy, and OpenShift
  manifest checks.

## Validation

- PASS: `python3 tools/validate_blastwall_profiles.py --registry policy/profiles.yml`
- PASS: `python3 tools/check_blastwall_drift.py --registry policy/profiles.yml`
- PASS: `python3 tests/test_check_blastwall_drift.py`
- PASS: `npm run test:policy`
- PASS: `python3 -m pytest -q tests` (`30 passed`)
- PASS: `git diff --check`

## Acceptance Criteria

- PASS: active profile and active variant scopes must resolve to active registry
  scopes.
- PASS: active profiles cannot silently inherit planned scopes such as
  `xdp_socket`.
- PASS: RHEL CIL target artifacts must exist and carry deny plus neverallow
  posture for registry-backed scopes.
- PASS: OpenShift/SPO target artifacts must exist and carry deny plus neverallow
  posture for registry-backed scopes.
- PASS: required release safe probes or required evidence sources must exist.
- PASS: optional class scopes, currently `io_uring`, are checked for optional
  wrapper coverage without turning class absence into a hard failure.
- PASS: `base-nested` is variant-aware and intentionally removes `userns`.
- PASS: `capability2_bpf` remains static-validation-only and is not forced to
  grow a runtime probe in this phase.
- PASS: `selfprotect` remains RHEL-only and is not treated as an OpenShift/SPO
  drift failure.
- PASS: OpenShift targets must declare `usage_source: status.usage` in the
  registry, and docs must mention the `status.usage` discovery path.
- DEFERRED: SCCs, test jobs, and probe defaults still carry compatibility
  hardcoded process types. The checker reports this as a Phase 04 deferred item
  rather than blocking Phase 03.

## Calabi Gate

Status: PASS.

Execution boundary:

- Workstation staged the Phase 03 branch to
  `/opt/openshift/aws-metal-openshift-demo/blastwall-phase03-gate` on
  `bastion-01.workshop.lan` through `virt-01`.
- Live validation ran from `bastion-01.workshop.lan`.
- No enforcement installation, marker mutation, or OpenShift policy application
  was performed during this phase.

Evidence:

- PASS: `python3 tools/validate_blastwall_profiles.py --registry policy/profiles.yml`
- PASS: `python3 tools/check_blastwall_drift.py --registry policy/profiles.yml`
- PASS: `python3 tests/test_validate_blastwall_profiles.py`
- PASS: `python3 tests/test_check_blastwall_drift.py`
- PASS: `python3 tests/test_blastwall_marker.py`
- PASS: `python3 tests/policy_static.py`
- PASS: `python3 tests/inventory_grouping.py`
- PASS: `python3 -m pytest -q tests` (`30 passed`)
- PASS: `python3 tests/openshift/validate_spo_manifests.py`

Captured log paths on `bastion-01.workshop.lan`:

- `/tmp/blastwall-phase03-drift-check.log` records the first live run, including
  the expected bastion-local `No module named pytest` environment gap.
- `/tmp/blastwall-phase03-drift-check-pass.log` records the passing live gate
  with direct Python test scripts.
- `/tmp/blastwall-phase03-pytest-after-install.log` records the pytest-only pass
  after installing pytest into the `cloud-user` user site.
- `/tmp/blastwall-phase03-full-gate-after-pytest-install.log` records the
  complete live Phase 03 static gate after pytest installation.

## Risks and Follow-Up

- Phase 03 intentionally surfaces, but does not fix, hardcoded OpenShift
  process-type defaults in SCC and test harness assets. Phase 04 remains the
  correct place to move runtime binding paths to `.status.usage` where the live
  cluster can provide it.
- Phase 03 only validated that registry permissions were present in artifacts.
  This was superseded by the RC drift checker, which now requires exact
  permission-set matches and fails on extra permissions as well as missing
  permissions.
- Planned strange-socket scopes remain planned-only. Phase 03 did not generate
  or install additional denials.

## Rollback

Revert this phase commit to remove the drift checker, its tests, the policy
test wiring, and this checkpoint. No host state, IdM marker state, OpenShift
objects, or SELinux policy state need cleanup.

## Go / No-Go

Recommendation: GO for Phase 04. Repository-side validation and the live Calabi
Phase 03 static gate are complete.
