# Phase 06 Checkpoint - strange-socket-v1 Dry Run

Date: 2026-05-11
Branch: `blastwall-v2-phase-06-strange-socket-dry-run`
Commit: this commit (`feat: add strange socket dry-run profile`)

## Objective

Phase 06 implements the first SELinux-only `strange-socket-v1` expansion as a
lab-only dry run. The base profile stays unchanged. The new first-wave socket
families are represented in the registry, backed by optional CIL deny blocks,
validated by a safe socket-creation probe, and installable only when the lab
dry-run flag is explicitly enabled.

## Repository State

Changed areas:

- Registry and drift validation: `policy/profiles.yml`,
  `tools/validate_blastwall_profiles.py`, `tools/check_blastwall_drift.py`
- RHEL dry-run policy: `policy/blastwall-strange-socket-v1-deny.cil`,
  `policy/Makefile`
- Pipeline/playbooks: dry-run RPM payload support, opt-in activation, runtime
  probe execution, and profile-aware preflight overrides
- Tests: registry, drift, marker, inventory, static policy, and probe coverage
- Docs: profile model updated to describe `strange-socket-v1` as lab-only

## Local Validation

- PASS: `git diff --check`
- PASS: YAML parse for `policy/profiles.yml` and changed playbooks
- PASS: `npm run test:policy`
- BLOCKED on workstation: `make -C policy check` because
  `/usr/share/selinux/devel/Makefile` is absent locally. The policy check ran
  during the Calabi RPM build.

## Calabi Lab Validation

Target: `mirror-registry.workshop.lan`

- PASS: staged full source tree to bastion path
  `/opt/openshift/aws-metal-openshift-demo/blastwall`
- PASS: bastion Python policy/static/inventory/SPO validation
- PASS: bastion syntax checks for build, install, verify, preflight, and promote
  playbooks
- PASS: built `blastwall-selinux-0.6.1-0.rc1.noarch`
- PASS: RPM payload includes dry-run module
  `blastwall-strange-socket-v1-deny`
- PASS: installed and activated dry-run module with
  `BLASTWALL_STRANGE_SOCKET_V1_DRY_RUN=true`
- PASS: confined runtime verification as `svc-ansible-runner` in
  `blastwall_u:blastwall_r:blastwall_t:s0`
- PASS: base probes still pass
- PASS: strange-socket-v1 probe returned `BLOCKED` for all seven first-wave
  socket families: AF_XDP, AF_TIPC, AF_CAN, AF_BLUETOOTH, AF_NFC, AF_KCM, AF_RDS
- PASS: promoted lab marker with profiles `base,strange-socket-v1`
- PASS: marker parser accepts the lab marker when `0.6.1-0.rc1` and both
  profiles are required
- PASS: preflight accepts `BLASTWALL_REQUIRED_POLICY_PROFILES=base,strange-socket-v1`
- PASS: negative preflight with stale required RPM fails closed before selecting
  a current host

Local evidence archive:

```text
blastwall-phase06-evidence.tgz
```

Remote source:

```text
bastion-01:/tmp/blastwall-phase06-evidence.tgz
```

## Acceptance Criteria

- PASS: first-wave scopes are represented in the registry as dry-run scopes.
- PASS: RHEL CIL fragment exists, uses optional wrappers, and includes deny plus
  neverallow rules.
- PASS: safe probe exists and emits `BLOCKED`, `SKIP_ABSENT`, or `FAIL_ALLOWED`.
- PASS: drift checker covers dry-run scopes and profiles.
- PASS: base profile and default install path are unchanged.
- PASS: lab evidence supports activation only on the Calabi target.
- DEFERRED: OpenShift/SPO strange-socket support. Phase 06 records RHEL-login
  support only; the SPO path was not extended.

## Security Posture Impact

- Enforcement changed by default: no
- New lab-only denials added: yes, only when dry-run activation is enabled
- Existing denials weakened: no
- Marker behavior changed: yes, preflight can now require `base,strange-socket-v1`
- OpenShift behavior changed: no

## Risks And Unknowns

- The dry-run module is now active on `mirror-registry.workshop.lan` and the IdM
  marker claims `base,strange-socket-v1` for that designated Calabi lab target.
- The marker promotion collection path failed under no-log output and fell back
  to the FreeIPA CLI path, matching the existing fallback boundary.
- Direct `semodule` from the confined Blastwall runtime remains blocked by
  design; install/activation used the unconfined bootstrap channel.

## Rollback Plan

To restore the Phase 05 lab marker and active module set on the Calabi target:

```bash
ssh cloud-user@mirror-registry.workshop.lan 'sudo semodule -r blastwall-strange-socket-v1-deny'
```

Then re-promote the Phase 05 base marker or rerun the Phase 05 `0.6.0-0.rc1`
promotion flow.

## Recommendation

Phase 06 is complete. The implementation is safe to keep on the feature branch
as a lab-only dry-run expansion. Do not promote `strange-socket-v1` to production
or OpenShift paths without a separate human approval.
