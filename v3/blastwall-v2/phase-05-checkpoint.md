# Phase 05 Checkpoint — Calabi v0.6.0 Control-Plane Gate

Date: 2026-05-11
Branch: `blastwall-v2-phase-05-calabi-v060-gate`
Base commit: `4284f13 feat: derive openshift spo usage dynamically`

## Result

Functional gate: **GO** for the v0.6.0 control-plane candidate.

Release-publication gate: **conditional GO**. Two follow-ups should be resolved
before presenting the AAP policy pipeline as a fully self-contained upgrade path:

- The confined Blastwall runtime identity cannot activate SELinux policy with
  `semodule`, by design. Phase 05 used the unconfined Calabi bootstrap channel
  for candidate install/activation, then validated runtime and preflight through
  the confined identity.
- AVC excerpts were not emitted on the RHEL target even after temporarily
  disabling dontaudit with `semodule -DB`. Probe stdout proves enforcement, but
  audit observability needs a separate fix or documentation note.

No strange-socket scope was added. The base profile deny posture was unchanged.

## Repository Changes

- `inventory/blastwall-idm.yml` and
  `poc-calabi/aap/inventory/blastwall-idm.yml` now keep the checked-in `0.5.2`
  marker default while accepting release-candidate grouping overrides through:
  - `BLASTWALL_REQUIRED_POLICY_MARKER`
  - `BLASTWALL_PROFILE_REGISTRY_SHA256`
- `tests/policy_static.py` now asserts those inventory override knobs exist.

This avoids one-off edited inventories during the `0.6.0-rc1` Calabi gate.

## Local Validation

- PASS: `git diff --check`
- PASS: `python3 tools/validate_blastwall_profiles.py --registry policy/profiles.yml`
- PASS: `python3 tools/check_blastwall_drift.py --registry policy/profiles.yml`
- PASS: `python3 -m pytest -q tests` (`30 passed`)
- PASS: `npm run test:policy`
- PASS: syntax check for build, install, promote, preflight, render-SPO, and
  verify-managed-host playbooks
- N/A: top-level `make test` and `make rpm` do not exist
- N/A on workstation: `make -C policy check` requires
  `/usr/share/selinux/devel/Makefile`; the policy build ran in Calabi instead

## Calabi RHEL Evidence

Target: `mirror-registry.workshop.lan`

- OS: Red Hat Enterprise Linux 10.1 (Coughlan)
- Kernel: `6.12.0-124.52.1.el10_1.x86_64`
- SELinux: enabled, targeted, enforcing
- Installed RPM: `blastwall-selinux-0.6.0-0.rc1.noarch`
- Registry SHA256:
  `9c11a7409662c3584175284c2f2b5e72c1fd69aec855c81e9083ae05e94ff854`
- Policy/RPM SHA256:
  `651039f9f69c712e0a462c1e4891ec94474e4340d921b3ccb34894029c4c7f28`
- Installed modules include:
  `blastwall`, `blastwall-role`, `blastwall-sshd-login`,
  `blastwall-alg-socket-deny`, `blastwall-bpf-deny`,
  `blastwall-policy-selfprotect`, `blastwall-packet-socket-deny`,
  `blastwall-userns-deny`, `blastwall-io-uring-deny`,
  `blastwall-xfrm-deny`, `blastwall-rxrpc-deny`

Probe results under `svc-ansible-runner` in
`blastwall_u:blastwall_r:blastwall_t:s0`:

- PASS: sudo reaches UID 0 and stays in Blastwall SELinux context
- PASS: BPF map/prog load blocked
- PASS: AF_PACKET socket creation blocked
- PASS: user namespace creation blocked
- PASS: `io_uring_setup` blocked
- PASS: NETLINK_XFRM and AF_RXRPC blocked
- PASS: AF_ALG probe returned an expected blocked/skip result

## Marker And Preflight

Published Calabi lab marker:

```text
blastwall:v=2;state=active;target=rhel-login;rpm=blastwall-selinux-0.6.0-0.rc1;registry_sha256=9c11a7409662c3584175284c2f2b5e72c1fd69aec855c81e9083ae05e94ff854;policy_sha256=651039f9f69c712e0a462c1e4891ec94474e4340d921b3ccb34894029c4c7f28;profiles=base;scopes=alg_socket,bpf,capability2_bpf,packet_socket,userns,io_uring,xfrm,rxrpc,selfprotect
```

Inventory after promotion:

- `blastwall_policy_current`: `mirror-registry.workshop.lan`
- `blastwall_profile_base`: `mirror-registry.workshop.lan`
- `blastwall_policy_stale`: `stale-blastwall-01.workshop.lan`

AAP preflight:

- PASS: positive preflight selected `mirror-registry.workshop.lan`
- PASS: stale expected marker failed closed
- PASS: missing marker failed closed
- PASS: malformed marker failed closed
- PASS: marker restored after negative tests

## OpenShift/SPO Evidence

Cluster:

- OpenShift: `4.20.15`
- Kubernetes: `v1.33.6`
- SPO CSV: `security-profiles-operator.v0.10.0`
- Workers: RHCOS 9.6, kernel `5.14.0-570.92.1.el9_6.x86_64`

Rendered SPO bundle:

- Path: `/var/tmp/blastwall-policy-pipeline/artifacts/openshift-spo/blastwall-spo-crs.yaml`
- SHA256: `fd728168f7c3447912178ae0d83da19eb856c8a717f5cb9039b65decd4ba90bb`

Validation:

- PASS: RawSelinuxProfile `blastwall` ready
- PASS: RawSelinuxProfile `blastwallnested` ready
- PASS: standard `status.usage`: `blastwall.process`
- PASS: nested `status.usage`: `blastwallnested.process`
- PASS: standard SCC type hydrated to `blastwall_.process`
- PASS: nested SCC type hydrated to `blastwallnested_.process`
- PASS: standard validation job summary: `standard_profile: passed`
- PASS: nested validation job summary: `nested_profile: passed`

## Evidence Bundle

Local evidence archive:

```text
blastwall-phase05-evidence.tgz
```

Remote source:

```text
bastion-01:/tmp/blastwall-phase05-evidence.tgz
```

The bundle contains build, install, RHEL facts, probe, marker, inventory,
preflight, negative marker, SPO render, and SPO apply/validate logs.

## Follow-Up Before Phase 06

1. Decide whether the AAP policy pipeline should advertise install/activation as
   a bootstrap-channel step, or add a separate unconfined policy-maintenance
   credential/path.
2. Add or document an audit-evidence mechanism for RHEL deny probes when AVCs
   are not emitted under the current policy/audit posture.
3. Keep Phase 06 blocked until explicit human approval to start
   `strange-socket-v1`.
