# Blastwall v2 Phase 04 Checkpoint

## Summary

- Phase: 04 - OpenShift/SPO compatibility and validation harness
- Branch: `blastwall-v2-phase-04-spo-compat`
- Commit: this phase commit
- Date: 2026-05-10T18:49:11-04:00
- Operator: release automation

Phase 04 makes the OpenShift/SPO harness profile-aware and version-resilient.
Executable harness paths no longer hardcode the legacy generated process-type
strings. They read `RawSelinuxProfile.status.usage`, derive the SCC-compatible
SELinux type for the validated SPO/OCP behavior, and validate standard and
nested paths separately. No new SELinux deny scope was added.

## Repository Changes

- Added `docs/blastwall-v2/spo-compatibility.md` to record the OpenShift/SPO
  usage-to-runtime-type contract and version notes.
- Replaced executable SCC and validation-job process-type literals with
  `__BLASTWALL_SPO_*_SELINUX_TYPE__` placeholders.
- Updated `openshift/spo/scripts/validate-blastwall-spo-nodes.sh` to query
  `.status.usage`, derive the SCC-compatible SELinux type, patch SCCs, and run
  separate standard and nested safe probes.
- Updated `playbooks/apply-validate-spo-policy-crs.yml` to apply prerequisites,
  wait for RawSelinuxProfile readiness, read `status.usage`, hydrate SCCs/jobs,
  and validate standard/nested jobs separately.
- Updated the probe script and ConfigMap copy to require
  `BLASTWALL_EXPECTED_SELINUX_TYPE` instead of falling back to a guessed type,
  and to emit `standard_profile: passed` / `nested_profile: passed` summaries.
- Updated the static OpenShift manifest validator and drift checker to fail on
  legacy hardcoded process-type strings in executable harness paths.
- Updated `openshift/spo/README.md` to document the placeholder and runtime
  hydration path.

## Validation

- PASS: `python3 tools/validate_blastwall_profiles.py --registry policy/profiles.yml`
- PASS: `python3 tools/check_blastwall_drift.py --registry policy/profiles.yml`
- PASS: `python3 tests/test_check_blastwall_drift.py`
- PASS: `python3 tests/openshift/validate_spo_manifests.py`
- PASS: `npm run test:policy`
- PASS: `python3 -m pytest -q tests` (`30 passed`)
- PASS: `ansible-playbook --syntax-check playbooks/render-spo-policy-crs.yml`
- BLOCKED locally: `ansible-playbook --syntax-check playbooks/apply-validate-spo-policy-crs.yml`
  on the workstation because `kubernetes.core` is not installed there.
- PASS on bastion: `ansible-playbook --syntax-check playbooks/apply-validate-spo-policy-crs.yml playbooks/render-spo-policy-crs.yml`
- PASS: `git diff --check`

## Acceptance Criteria

- PASS: harness uses `RawSelinuxProfile.status.usage` as the source for
  OpenShift/SPO runtime binding.
- PASS: OCP 4.20/SPO 0.10 compatibility is handled by deriving
  `blastwall_.process` / `blastwallnested_.process` from status usage
  `blastwall.process` / `blastwallnested.process`; the literals are not
  executable defaults.
- PASS: standard and nested paths are validated separately.
- PASS: compatibility matrix exists.
- PASS: drift checker covers OpenShift executable artifacts and fails on legacy
  hardcoded process-type defaults.
- PASS: no strange-socket or other new enforcement scope was added.

## Calabi Gate

Status: PASS.

Execution boundary:

- Workstation staged the Phase 04 branch to
  `/opt/openshift/aws-metal-openshift-demo/blastwall-phase04-gate` on
  `bastion-01.workshop.lan` through `virt-01`.
- Live validation ran from `bastion-01.workshop.lan`.
- The bastion now has pytest available from the earlier Phase 03 follow-up, and
  Phase 04 also installed `kubernetes.core` plus the Python `kubernetes` client
  into `cloud-user`'s user environment to exercise the Ansible apply path.

Cluster evidence:

- OCP: `4.20.15`
- Kubernetes: `v1.33.6`
- RHCOS workers: `9.6.20260217-1 (Plow)`
- SPO CSV: `security-profiles-operator.v0.10.0`, `Succeeded`
- `RawSelinuxProfile/blastwall`: `Installed`, usage `blastwall.process`
- `RawSelinuxProfile/blastwallnested`: `Installed`, usage `blastwallnested.process`
- `SecurityContextConstraints/blastwall-confined`: type `blastwall_.process`
- `SecurityContextConstraints/blastwall-nested`: type `blastwallnested_.process`,
  `userNamespaceLevel=RequirePodLevel`

Live test evidence:

- PASS: bastion static gate:
  `python3 tools/validate_blastwall_profiles.py --registry policy/profiles.yml`
- PASS: bastion drift gate:
  `python3 tools/check_blastwall_drift.py --registry policy/profiles.yml`
- PASS: bastion pytest:
  `python3 -m pytest -q tests` (`30 passed`)
- PASS: bastion OpenShift static validator:
  `python3 tests/openshift/validate_spo_manifests.py`
- PASS: worker-node standard probes on `ocp-worker-01`, `ocp-worker-02`, and
  `ocp-worker-03`.
- PASS: worker-node nested probes on `ocp-worker-01`, `ocp-worker-02`, and
  `ocp-worker-03`.
- PASS: Ansible render/apply/validate path reported
  `spo_policy_apply_validate: passed`.

Captured log paths on `bastion-01.workshop.lan`:

- `/tmp/blastwall-phase04-static-pytest-final.log`
- `/tmp/blastwall-phase04-spo-worker-validation-final.log`
- `/tmp/blastwall-phase04-render-spo-final2.log`
- `/tmp/blastwall-phase04-apply-validate-spo-pass.log`
- `/tmp/blastwall-phase04-cluster-evidence.log`

Failed discovery evidence retained:

- `/tmp/blastwall-phase04-spo-worker-validation.log` and
  `/tmp/blastwall-phase04-standard-worker01-keep-fail.log` captured the raw
  `status.usage` SCC failure: kubelet rejected `blastwall.process` with
  `write to /proc/self/attr/keycreate: Invalid argument`.
- `/tmp/blastwall-phase04-apply-validate-spo-final.log` and
  `/tmp/blastwall-phase04-apply-validate-spo-final2.log` captured intermediate
  Ansible environment and transform failures before the final pass.

## Risks and Follow-Up

- OCP 4.20/SPO 0.10 exposes `status.usage` values that are not directly accepted
  by SCC `seLinuxOptions.type`. The harness now derives the accepted SELinux
  type from the reported usage. This should be rechecked against other SPO
  versions before claiming universal behavior.
- Phase 04 installed test dependencies on the bastion user environment:
  `pytest`, `kubernetes.core`, and Python `kubernetes`. This is lab tooling, not
  a Blastwall runtime dependency.
- Documentation pages still contain historical process-type strings as evidence
  and examples. Static checks only forbid those strings in executable harness
  paths.

## Rollback

Revert this phase commit to restore the previous hardcoded OpenShift/SPO test
harness. If live lab cleanup is desired, delete the validation jobs:

```bash
oc -n blastwall-workloads delete job blastwall-spo-validation blastwall-nested-spo-validation --ignore-not-found
```

No RHEL login policy, IdM marker, or strange-socket state was changed.

## Go / No-Go

Recommendation: GO for Phase 05. Repository validation, bastion pytest, worker
node SPO probes, and Ansible apply/validate workflow all pass.
