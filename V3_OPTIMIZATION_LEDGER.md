# Blastwall v3 Eigenstate 1.18.1 Optimization Ledger

## Phase 00 - Baseline and Branch Control

```text
phase: 00 baseline and branch control
commit: 3a284e181ec8e5d9ebe7152cf104d313e6df0059
files changed: V3_OPTIMIZATION_LEDGER.md
tests run:
  PASS python3 tests/policy_static.py
  PASS python3 tools/validate_blastwall_profiles.py --registry policy/profiles.yml
  PASS python3 tools/check_blastwall_drift.py --registry policy/profiles.yml
  PASS python3 -m pytest -q tests
  PASS make test-fast
  PASS ansible-playbook --syntax-check playbooks/preflight.yml
  PASS ansible-playbook --syntax-check playbooks/sign-attestation.yml
  PASS ansible-playbook --syntax-check playbooks/promote-policy-rpm.yml
  PASS ansible-playbook --syntax-check playbooks/attestation-vault-health.yml
  PASS ansible-playbook --syntax-check aap/configure-controller.yml
  PASS ansible-galaxy collection list eigenstate.ipa
  PASS ansible-doc -t inventory eigenstate.ipa.idm
  PASS ansible-doc -t module eigenstate.ipa.vault_health
  PASS ansible-doc -t module eigenstate.ipa.vault_artifact
  PASS ansible-doc -t module eigenstate.ipa.access_path
  PASS ansible-doc -t filter eigenstate.ipa.sudo_risk
evidence captured:
  branch: blastwall-v3-signed-attestation
  upstream: origin/blastwall-v3-signed-attestation
  eigenstate.ipa local collection version: 1.18.1
  requirements.yml: eigenstate.ipa 1.18.1
  execution-environment/requirements.yml: eigenstate.ipa 1.18.1
  poc-calabi/requirements.yml: eigenstate.ipa 1.18.1
  pytest result: 162 passed in 23.89s
  make test-fast result: PASS
  dirty state understood:
    WORK_LEDGER.md is untracked local evidence from earlier work and is not
    part of the published branch.
    tests/test_traffic_control_userns_precondition_probe.py and
    tests/trigger-traffic-control-userns-precondition.py are untracked local
    safe precondition probe artifacts from the Fragnesia/traffic-control work.
security invariants checked:
  marker remains a locator or selector hint, not proof.
  stable-v3 requires signed envelope and latest index artifact retrieval.
  signer, verifier, and marker publication credentials remain separated.
  no new SELinux scopes, cryptographic formats, KVM, seccomp, BPF LSM, or PSS
  migration were introduced in the baseline step.
open issues:
  Required optimization docs were absent at baseline:
    docs/blastwall-v3/eigenstate-1.18.1-integration.md
    docs/blastwall-v3/calabi-negative-evidence.md
    docs/blastwall-v3/multi-host-continuous-verification-plan.md
  Live destructive negative Calabi evidence is not recorded in-repo yet.
next phase handoff:
  Audit existing implementation against phases 01-08, patch only confirmed
  gaps, add required docs, then run the local/static gate again before any
  live Calabi work or publication.
```

## Phase 01 - Dependency and EE Alignment

```text
phase: 01 dependency and execution environment alignment
commit: working tree after 3a284e181ec8e5d9ebe7152cf104d313e6df0059
files changed:
  docs/blastwall-v3/eigenstate-1.18.1-integration.md
tests run:
  PASS ansible-galaxy collection list eigenstate.ipa
  PASS ansible-doc -t inventory eigenstate.ipa.idm
  PASS ansible-doc -t module eigenstate.ipa.vault_health
  PASS ansible-doc -t module eigenstate.ipa.vault_artifact
  PASS ansible-doc -t module eigenstate.ipa.access_path
  PASS ansible-doc -t filter eigenstate.ipa.sudo_risk
  PASS python3 tests/policy_static.py
evidence captured:
  local collection version: eigenstate.ipa 1.18.1
  all three requirements files pin eigenstate.ipa 1.18.1
security invariants checked:
  eigenstate.ipa remains the generic IdM/KRA/access fact provider.
  Blastwall-specific policy, marker, attestation, and verification decisions
  remain in this repository.
open issues:
  AAP EE load proof must be rechecked in live Controller if the EE image is
  rebuilt after this patch.
next phase handoff:
  Use collection-backed surfaces in preflight and health gates.
```

## Phases 02-08 - Collection-First Control Path and Static Contracts

```text
phase: 02 vault_artifact preflight retrieval
commit: working tree after 3a284e181ec8e5d9ebe7152cf104d313e6df0059
files changed:
  playbooks/preflight.yml
  tests/policy_static.py
tests run:
  PASS python3 tests/policy_static.py
  PASS ansible-playbook --syntax-check playbooks/preflight.yml
evidence captured:
  stable-v3 preflight resolves marker locations with resolve-existing.
  stable-v3 preflight reads envelope and latest index through
  eigenstate.ipa.vault_artifact and materializes local files before verifier
  execution.
security invariants checked:
  preflight does not use retrieve-existing/raw Blastwall vault helper in the
  stable-v3 default path.
open issues:
  Live missing-artifact and missing-index destructive cases remain pending.
next phase handoff:
  Keep vault helper compatibility code out of the stable-v3 default path.

phase: 03 real KRA health gate
commit: working tree after 3a284e181ec8e5d9ebe7152cf104d313e6df0059
files changed:
  playbooks/attestation-vault-health.yml
  tests/policy_static.py
tests run:
  PASS python3 tests/policy_static.py
  PASS ansible-playbook --syntax-check playbooks/attestation-vault-health.yml
evidence captured:
  attestation-vault-health.yml now calls eigenstate.ipa.vault_health with
  require_direct_kra=true and reports PASS/FAIL plus failure_state fields.
security invariants checked:
  health check distinguishes KRA/auth/timeout/canary classes from host drift.
open issues:
  Live canary stale/missing evidence remains pending.
next phase handoff:
  Use this playbook for live KRA health and canary negative cases.

phase: 04 stable-v3 preflight simplification
commit: working tree after 3a284e181ec8e5d9ebe7152cf104d313e6df0059
files changed:
  playbooks/preflight.yml
  tests/policy_static.py
tests run:
  PASS python3 tests/policy_static.py
  PASS ansible-playbook --syntax-check playbooks/preflight.yml
evidence captured:
  default preflight uses access_path, sudo_risk, vault_health, marker locator
  resolution, vault_artifact reads, and attestation verification.
  isolated HBAC operation test is diagnostic-only behind
  BLASTWALL_RUN_HBAC_OPERATION_TEST=true.
security invariants checked:
  stable-v3 still fails closed on high/unknown sudo risk unless an explicit
  dangerous override and reason are supplied.
open issues:
  Diagnostic HBAC test can still be run for Calabi proof, but is not part of
  the default stable-v3 launch path.
next phase handoff:
  Do not reintroduce nested ansible-playbook execution into default preflight.

phase: 05 marker publication fallback hardening
commit: working tree after 3a284e181ec8e5d9ebe7152cf104d313e6df0059
files changed:
  playbooks/promote-policy-rpm.yml
  playbooks/deploy-policy.yml
  tests/policy_static.py
tests run:
  PASS python3 tests/policy_static.py
  PASS ansible-playbook --syntax-check playbooks/promote-policy-rpm.yml
  PASS ansible-playbook --syntax-check playbooks/deploy-policy.yml
evidence captured:
  raw ipa host-mod fallback now requires BLASTWALL_ALLOW_IPA_CLI_FALLBACK=true
  and a non-empty BLASTWALL_ALLOW_IPA_CLI_FALLBACK_REASON.
security invariants checked:
  collection-backed FreeIPA marker writes remain primary.
  stable-v3 marker publication still verifies the signed envelope/index before
  writing the marker.
open issues:
  Direct collection-backed readback of userClass is limited by available module
  surfaces; post-promotion inventory sync and preflight remain the normal
  read-side proof path.
next phase handoff:
  If raw fallback is used live, capture the explicit reason and post-write
  marker evidence.

phase: 06 post-promotion targeting semantics
commit: working tree after 3a284e181ec8e5d9ebe7152cf104d313e6df0059
files changed:
  aap/vars/blastwall-controller.yml
  poc-calabi/aap/20-configure-controller.yml
  tests/policy_static.py
tests run:
  PASS python3 tests/policy_static.py
  PASS ansible-playbook --syntax-check aap/configure-controller.yml
  PASS ansible-playbook --syntax-check poc-calabi/aap/20-configure-controller.yml
evidence captured:
  post-promotion preflight now defaults to
  blastwall_aap_profile_post_promotion_preflight_group, which defaults to
  blastwall_profile_base, instead of the stale/candidate group.
  The Calabi Controller wrapper now feeds the same profile-derived default into
  Controller configuration instead of reintroducing the candidate group at lab
  runtime.
security invariants checked:
  a successfully promoted host should not disappear from the default
  post-promotion preflight target group.
open issues:
  Operators can still override BLASTWALL_POST_PROMOTION_PREFLIGHT_TARGET_GROUP
  for a persistent cohort.
next phase handoff:
  Live AAP configuration should be refreshed before rerunning the policy
  pipeline.

phase: 07 official collections and shell reduction
commit: working tree after 3a284e181ec8e5d9ebe7152cf104d313e6df0059
files changed:
  playbooks/promote-policy-rpm.yml
  playbooks/deploy-policy.yml
  docs/blastwall-v3/shell-and-collection-exceptions.md
tests run:
  PASS python3 tests/policy_static.py
  PASS ansible-playbook --syntax-check playbooks/promote-policy-rpm.yml
  PASS ansible-playbook --syntax-check playbooks/deploy-policy.yml
evidence captured:
  Blastwall marker helper rendering now uses ansible.builtin.command argv in
  promote-policy-rpm.yml and deploy-policy.yml.
security invariants checked:
  remaining raw ipa CLI use is bounded to explicit fallback paths.
open issues:
  Some lab and fallback shell remains documented as exceptions.
next phase handoff:
  Continue collection replacements opportunistically without broadening stable
  SPO or SELinux claims.

phase: 08 static tests and contracts
commit: working tree after 3a284e181ec8e5d9ebe7152cf104d313e6df0059
files changed:
  tests/policy_static.py
tests run:
  PASS python3 tests/policy_static.py
evidence captured:
  static contracts now reject skeleton KRA health, default HBAC operation-test
  execution, candidate-derived post-promotion defaults, retrieve-existing in
  stable-v3 preflight, and unguarded raw ipa fallback.
security invariants checked:
  signer private key remains excluded from verifier/preflight jobs.
  breakglass bypass rules remain constrained by verifier behavior.
open issues:
  Live destructive negative gate remains the required proof beyond static tests.
next phase handoff:
  Run full local validation, then live Calabi evidence collection when the lab
  boundary is ready.
```

## Phases 09-11 - Live Evidence and Release Documentation

```text
phase: 09 Calabi destructive negative gate
commit: working tree after 3a284e181ec8e5d9ebe7152cf104d313e6df0059
files changed:
  docs/blastwall-v3/calabi-negative-evidence.md
tests run:
  pending live destructive matrix
evidence captured:
  negative evidence template created; no new destructive live matrix is claimed.
  Non-destructive Calabi readiness check on 2026-05-17 reached
  bastion-01.workshop.lan through virt-01, confirmed oc whoami=system:admin,
  OpenShift 4.20.15, six Ready nodes, Controller route
  workshop-aap-controller-aap.apps.ocp.workshop.lan, and awx 24.6.1.
  Controller project Blastwall is still pinned to branch
  blastwall-v3-signed-attestation at revision
  3a284e181ec8e5d9ebe7152cf104d313e6df0059, so destructive Controller-visible
  negative testing is intentionally held until this working-tree change set is
  staged or published where AAP can execute it.
security invariants checked:
  docs keep negative evidence as pending and do not treat local tests as live
  destructive proof.
open issues:
  missing envelope, missing index, wrong generation, revocation, expiry, policy
  drift, KRA canary, vault auth, signature tamper, and profile mismatch live
  cases remain pending.
next phase handoff:
  Publish/stage the working tree into the AAP Project source, refresh
  Controller configuration, run the healthy policy pipeline, then execute the
  destructive negative cases from the Calabi runbook.

phase: 10 multi-host and continuous verification plan
commit: working tree after 3a284e181ec8e5d9ebe7152cf104d313e6df0059
files changed:
  docs/blastwall-v3/multi-host-continuous-verification-plan.md
tests run:
  PASS npm run test:docs
evidence captured:
  three-host and S-range next gates documented without blocking current code
  hardening.
security invariants checked:
  stable-v3 candidate is not overstated as fleet-scale S-range proof.
open issues:
  live 3+ host and 10+ host mixed-state gates remain future work.
next phase handoff:
  Use this plan after destructive single-host negative evidence is complete.

phase: 11 documentation and release decision
commit: working tree after 3a284e181ec8e5d9ebe7152cf104d313e6df0059
files changed:
  docs/blastwall-v3/eigenstate-1.18.1-integration.md
  docs/blastwall-v3/external-review-packet.md
  docs/blastwall-v3/stable-v3-readiness-checklist.md
tests run:
  PASS npm run test:docs
evidence captured:
  docs now state eigenstate.ipa 1.18.1 dependency, current Controller-visible
  healthy workflow 2843, and the then-current live-evidence hold before
  the destructive matrix was attached.
security invariants checked:
  claim boundary remains stable-candidate, not production-stable fleet proof.
open issues:
  historical phase state remained a live-evidence hold until the later
  destructive live matrix was run and attached.
next phase handoff:
  Run full validation; if clean, run live Calabi gates or publish the branch as
  a code-hardening checkpoint with live evidence explicitly pending.

phase: 12 current live Calabi stable-v3 gate
commit: 56f7c451a281bda5f5a1dbd1a8fac12d00097410
files changed:
  playbooks/preflight.yml
  playbooks/attestation-vault-health.yml
  playbooks/promote-policy-rpm.yml
  playbooks/deploy-policy.yml
  tests/policy_static.py
  docs/blastwall-v3/calabi-negative-evidence.md
  docs/blastwall-v3/eigenstate-1.18.1-integration.md
  docs/blastwall-v3/external-review-packet.md
  docs/blastwall-v3/shell-and-collection-exceptions.md
  docs/blastwall-v3/stable-v3-readiness-checklist.md
tests run:
  PASS python3 tests/policy_static.py
  PASS git diff --check
  PASS npm run test:docs
  PASS ansible-playbook --syntax-check playbooks/preflight.yml playbooks/attestation-vault-health.yml playbooks/promote-policy-rpm.yml playbooks/deploy-policy.yml
  PASS Controller project sync 2834 at revision 56f7c451a281bda5f5a1dbd1a8fac12d00097410
  PASS AAP workflow 2843 full stable-v3 policy pipeline
  PASS AAP job 2839 standalone stable-v3 preflight
  PASS AAP job 2835 failed closed for unresolved configured KRA server
evidence captured:
  Workflow 2843 passed with build 2848, render SPO 2852, install 2853,
  apply/validate SPO 2857, verify managed host 2861, sign attestation 2865,
  promote marker 2869, inventory sync 2873, and post-promotion preflight 2876.
  The v3 marker published generation 1779093311 with attestation hash
  4d382ebdee93fe0c37f1585711d2216465a09f18c8c359e142b2b2558582840b.
  Policy drift and untrusted signer negative jobs 2827 and 2830 failed as
  expected. Bad KRA job 2831 exposed a gap; after the guard, job 2835 failed at
  getent resolution for missing-kra.workshop.lan.
security invariants checked:
  stable-v3 no longer accepts a configured KRA server list that cannot resolve
  before vault artifact reads.
  OpenShift/SPO still admits the derived underscore process types and validates
  standard/nested probes with Fragnesia coverage.
open issues:
  Missing artifact, missing index, wrong generation/replay, revocation, expiry,
  KRA canary, vault auth, signature tamper, profile mismatch, and breakglass
  destructive cases still need controlled live execution before final stable-v3.
next phase handoff:
  Complete the remaining destructive negative matrix or publish this branch as
  a partial-live-evidence stable-v3 candidate for external review.
```

## Phase 13 - Hardening Pack Closure

```text
phase: 13 hardening pack closure
commit: 7e6bf82
files changed:
  playbooks/attestation-vault-health.yml
  playbooks/promote-policy-rpm.yml
  playbooks/deploy-policy.yml
  tests/test_blastwall_attestation_sign.py
  tests/policy_static.py
  docs/blastwall-v3/calabi-negative-evidence.md
  docs/blastwall-v3/multi-host-continuous-verification-plan.md
  docs/blastwall-v3/shell-and-collection-exceptions.md
  V3_IMPLEMENTATION_LEDGER.md
  V3_OPTIMIZATION_LEDGER.md
tests added:
  deterministic resolve-existing vault artifact mapping
  digest-mismatch rejection before artifact verification
  static guards for preflight artifact read ordering and marker fallback readback
tests run:
  PASS python3 -m pytest -q tests/test_blastwall_attestation_sign.py
  PASS python3 tests/policy_static.py
  PASS ansible-playbook --syntax-check playbooks/promote-policy-rpm.yml playbooks/deploy-policy.yml playbooks/attestation-vault-health.yml playbooks/preflight.yml
  PASS make test-fast
  PASS npm run test:docs
evidence captured:
  stable-v3 preflight remains collection-backed for KRA reads, with marker
  digest checked during the envelope vault_artifact read before signature
  verification.
  attestation-vault-health.yml now requires explicit vault scope/owner inputs
  instead of silently using service/blastwall-attestation defaults.
  raw ipa host-mod fallback writes now perform immediate host userClass readback
  assertions in promotion and deploy/rollback marker paths.
security invariants checked:
  v3 markers remain locators only.
  KRA custody remains collection-backed on the stable-v3 path.
  raw IPA fallback remains disabled unless explicitly approved with a reason,
  and it can no longer proceed without marker readback proof.
open issues:
  current hardening code has not yet been replayed through the Controller.
  destructive live cases remain pending before final production stable-v3.
next phase handoff:
  Refresh the AAP Project to this working tree, rerun the healthy policy
  pipeline, then execute the destructive negative matrix from the Calabi
  evidence packet.
```

## Phase 14 - RC Evidence State Normalization

```text
phase: 14 rc evidence state normalization
commit: working tree after 14f7f472f70c1eb66f8ece35b194ed4e2da8b137
files changed:
  tools/blastwall_attestation.py
  tools/blastwall_attestation_verify.py
  tools/blastwall_attestation_sign.py
  tests/test_blastwall_attestation_index.py
  tests/test_blastwall_attestation_verify.py
  tests/test_blastwall_attestation_sign.py
  tests/policy_static.py
  docs/blastwall-v3/evidence-consistency-matrix.md
  docs/blastwall-v3/stable-v3-rc-decision.md
  docs/blastwall-v3/scheduled-loop-soak.md
  docs/blastwall-v3/governance-owner-assignment.md
  docs/blastwall-v3/second-maintainer-diagnostic-exercise.md
  docs/blastwall-v3/final-stable-v3-decision.md
tests added:
  normalized digest mismatch failure state
  normalized revoked-marker failure state
  breakglass rejection for digest mismatch and revoked marker
  static rejection of stale attestation failure state names in tools
tests run:
  PASS python3 -m pytest -q tests/test_blastwall_attestation_index.py tests/test_blastwall_attestation_verify.py tests/test_blastwall_attestation_sign.py
  PASS read-only Calabi Controller schedule query
  PASS ansible-galaxy collection list eigenstate.ipa
  PASS ansible-doc collection surface checks for idm, vault_health, vault_artifact, access_path, and sudo_risk
evidence captured:
  AAP schedules 6 through 9 are enabled.
  Scheduled KRA health jobs 3776, 3797, and 3802 passed.
  Scheduled candidate preflight 3780 passed.
  Scheduled runtime workflow 3781 passed.
  Scheduled inventory audits 3778, 3799, and 3804 failed closed only on the
  intentional missing-artifact fixture.
security invariants checked:
  breakglass remains limited to attestation/index visibility failures.
  digest and revocation are security/attestation failures, not infrastructure
  visibility bypass cases.
open issues:
  governance owner assignment remains pending.
  destructive digest-mismatch and revoked-marker cases need re-capture after
  this source normalization is synced into Controller.
next phase handoff:
  Run the full local validation suite, commit and push, sync Controller to the
  pushed commit, then re-run the two normalized destructive cases when the lab
  window is available.
```
