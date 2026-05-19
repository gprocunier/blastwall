# V3 Negative Gate Execution Ledger

## Branch

```yaml
target_branch: blastwall-v3-signed-attestation
working_branch: blastwall-v3-negative-gate-calabi
git_sha_start: d5c0877100ec782f866b6806370492e30f78f06d
git_sha_end: pending
date_started: 2026-05-19T02:46:31Z
date_completed: pending
executor: main-thread architecture lead with bounded worker checks
```

## Baseline State

```yaml
local_dirty_state:
  tracked_changes: none at phase start
  untracked_existing:
    - WORK_LEDGER.md
    - artifacts/
    - tests/test_traffic_control_userns_precondition_probe.py
    - tests/trigger-traffic-control-userns-precondition.py
collection_floor:
  requirements.yml: eigenstate.ipa 1.18.1
  execution-environment/requirements.yml: eigenstate.ipa 1.18.1
  poc-calabi/requirements.yml: eigenstate.ipa 1.18.1
local_collections_observed:
  eigenstate.ipa: 1.18.1
  freeipa.ansible_freeipa: 1.16.0
aap_project:
  id: 8
  name: Blastwall
  scm_branch_at_phase_start: blastwall-v3-signed-attestation
  scm_revision_at_phase_start: d5c0877100ec782f866b6806370492e30f78f06d
  last_update_failed: false
scope_freeze:
  new_selinux_deny_scopes: none proposed
  profile_semantics_changes: none proposed
  marker_grammar_changes: none proposed
```

## Phase Status

| Phase | Status | Owner | Commit(s) | Tests | Evidence | Residual risk |
|---:|---|---|---|---|---|---|
| 00 | complete | PM + 5.5 | pending | baseline commands | branch/source/AAP state recorded | AAP project still points at target branch until working branch is pushed and selected |
| 01 | complete | Test Harness | pending | `make test-fast`; `python3 tests/policy_static.py`; registry validation; drift check; `python3 -m pytest -q tests`; syntax checks for preflight/sign/promote/attestation-vault-health | all passed; `167 passed` in full pytest; static coverage confirmed for collection floor, profile-derived post-promotion preflight, raw IPA fallback approval/readback, explicit KRA inputs, and no marker-only stable-v3 pass | none |
| 02 | complete | KRA/Vault | `78c7c51`, `6d5e65a` | syntax check; `python3 tests/policy_static.py`; AAP project sync to `6d5e65a`; live AAP health jobs `3292` and `3290` | healthy job `3292` passed; missing-canary job `3290` failed as `FAIL_CANARY_MISSING` with IdM, KRA, and vault reachable | canary-positive freshness remains optional unless a real canary vault is configured |
| 03 | complete | Architecture | `a801759`, `39e83c2`, `cb59520`, `09e73a6`, `21d637f`, `3cca7ff`, `06e7831` | syntax check; `python3 tests/policy_static.py`; live AAP marker harness jobs | controlled stale-host marker harness created as JT `30`; restore job `3389` passed; IdM Admin credential corrected to real IdM admin secret; golden preflight job `3471` passed after destructive restores | collection `ipahost` still fails on this host and uses documented lab-only CLI fallback |
| 04 | complete | KRA/Vault | `06e7831` | live AAP preflight against controlled stale host | missing envelope job `3421` failed as `FAIL_ATTESTATION_NOT_VISIBLE`; missing index job `3439` failed as `FAIL_INDEX_NOT_VISIBLE`; digest mismatch job `3457` failed with `failure_class=digest_mismatch` under `FAIL_ATTESTATION_NOT_VISIBLE`; restore jobs `3425`, `3443`, `3461` completed | digest mismatch is not surfaced as a distinct top-level failure state |
| 05 | pending | Attestation | | | | pending |
| 06 | pending | Attestation | | | | pending |
| 07 | pending | Preflight | | | | pending |
| 08 | pending | Inventory | | | | pending |
| 09 | pending | AAP/Ops | | | | pending |
| 10 | in_progress | Collections | | read-only audit | Spark worker reported command/shell exception drift | pending static/doc updates |
| 11 | pending | Docs/PM | | | | pending |
| 12 | pending | Architecture | | | | pending |

## Security Invariants Checked

```text
- marker is locator only: Phase 01 static/source checks pass
- signed envelope required: Phase 01 static/source checks pass
- latest index required: Phase 01 static/source checks pass
- live policy hash required: Phase 01 static/source checks pass
- KRA infra split: live AAP health job `3292` passed and missing-canary job `3290` failed as `FAIL_CANARY_MISSING` without host-drift ambiguity
- breakglass boundaries: local/source coverage partial; live negative matrix pending
- raw CLI fallback: source checks pass for current fallback controls; negative-gate harness fallback is documented as lab-only and is not a default production AAP template
```

## Phase 02 KRA Health Notes

```yaml
initial_health_job:
  aap_job_id: 3271
  git_sha: d5c0877100ec782f866b6806370492e30f78f06d
  result: FAIL
  observed_failure_state: FAIL_INFRA_VAULT_KRA
  observed_message: "ipalib finalize failed: 'Env' object has no attribute 'server'"
  triage:
    classification: likely fresh-deploy bug
    rerun_likelihood: 10
    reason: standalone attestation-vault-health.yml did not bootstrap FreeIPA client config in the Controller EE, while sign/preflight already do
  corrective_patch:
    - bootstrap /etc/ipa/default.conf before eigenstate.ipa.vault_health
    - install injected IPA CA when Controller credential provides one
    - register Blastwall attestation vault health as a managed v3 AAP job template
project_sync:
  aap_project_id: 8
  branch: blastwall-v3-negative-gate-calabi
  scm_revision: 6d5e65a9d3c11569682135be5db41bbddc7872f8
  project_update_job: 3286
healthy_health_job:
  aap_job_id: 3292
  git_sha: 6d5e65a9d3c11569682135be5db41bbddc7872f8
  result: PASS
  status: successful
  failure_state: none
  failure_class: none
  idm_reachable: true
  vault_reachable: true
  kra_available: true
  message: vault health check passed
controlled_canary_failure:
  aap_job_id: 3290
  git_sha: 6d5e65a9d3c11569682135be5db41bbddc7872f8
  result: FAIL_EXPECTED
  status: failed
  injected_canary: blastwall-negative-gate-missing-canary
  failure_state: FAIL_CANARY_MISSING
  failure_class: vault_not_found
  idm_reachable: true
  vault_reachable: true
  kra_available: true
  canary_present: false
  message: "canary vault 'blastwall-negative-gate-missing-canary' was not found"
concurrent_job_note:
  aap_job_id: 3287
  status: error
  reason: Controller-side concurrent launch errored during host resolution; rerun job 3292 established healthy baseline on the same commit
```

## Phase 03 Harness Safety Notes

```yaml
golden_host: mirror-registry.workshop.lan
negative_host: stale-blastwall-01.workshop.lan
current_project_revision: 06e7831204858495085492d4803c8d929108ef30
project_sync_job: 3388
marker_harness:
  job_template_id: 30
  name: Blastwall negative gate IdM marker harness
  default_production_template: false
  credential: Blastwall IdM Admin
  collection_first: true
  lab_only_cli_fallback: true
idm_admin_credential_repair:
  reason: Controller admin password and IdM admin password diverged in the lab
  source_secret: aap/workshop-aap-admin-password
  affected_credential_id: 8
restore_proof:
  aap_job_id: 3389
  result: PASS
  restored_userclass_count: 1
post_destructive_golden_preflight:
  aap_job_id: 3471
  host: mirror-registry.workshop.lan
  result: PASS
```

## Phase 04 Artifact Visibility Notes

```yaml
baseline_artifacts:
  policy_sha256: 4b3e1d30e364331d408d8531d871ffcce23805a89b4cf44bd2977854be35bfc2
  registry_sha256: c8a533efc7ce60604d2a770964eea582005dde49ac2b882eea38c9701d612486
  probe_report_sha256: 16dc41143e934a4a1cad5c138867a8dfe0e9dec8fa12ff7dda6456302a190625
  attestation_ref: shared/blastwall-attestation/blastwall-attestations/mirror-registry.workshop.lan/base/1779161194.json
  attestation_sha256: 8d7f4a9844d7bceee2e0114ae55f66aa507e541676aad98ad3667c09701c3b11
  generation: 1779161194
  signer_kid: 8e62ab6d10d1a1a6b4261c4ee3fe79f76545c6d6
missing_envelope:
  mutation_job: 3414
  preflight_job: 3421
  restore_job: 3425
  host: stale-blastwall-01.workshop.lan
  observed_failure_state: FAIL_ATTESTATION_NOT_VISIBLE
  failure_class: vault_not_found
missing_index:
  mutation_job: 3432
  preflight_job: 3439
  restore_job: 3443
  host: stale-blastwall-01.workshop.lan
  observed_failure_state: FAIL_INDEX_NOT_VISIBLE
  failure_class: vault_not_found
digest_mismatch:
  mutation_job: 3450
  preflight_job: 3457
  restore_job: 3461
  host: stale-blastwall-01.workshop.lan
  observed_failure_state: FAIL_ATTESTATION_NOT_VISIBLE
  failure_class: digest_mismatch
  note: digest mismatch is fail-closed but currently folded under envelope visibility
```

## Destructive Negative Evidence Summary

| Case | Expected | Observed | AAP job | Result |
|---|---|---|---|---|
| Missing envelope | `FAIL_ATTESTATION_NOT_VISIBLE` | `FAIL_ATTESTATION_NOT_VISIBLE`, `failure_class=vault_not_found` | mutation `3414`, preflight `3421`, restore `3425` | PASS_FAIL_CLOSED |
| Missing index | `FAIL_INDEX_NOT_VISIBLE` | `FAIL_INDEX_NOT_VISIBLE`, `failure_class=vault_not_found` | mutation `3432`, preflight `3439`, restore `3443` | PASS_FAIL_CLOSED |
| Digest mismatch | digest/integrity failure | `FAIL_ATTESTATION_NOT_VISIBLE`, `failure_class=digest_mismatch` | mutation `3450`, preflight `3457`, restore `3461` | PASS_FAIL_CLOSED_WITH_STATE_GAP |

## Mixed-State Evidence Summary

| Host | State | Inventory | Preflight | Result |
|---|---|---|---|---|
| pending | pending | pending | pending | pending |

## Continuous Verification Plan

```text
workflow: pending
schedule: pending
alert outputs: pending
owner: pending
```

## Final Decision

```text
verdict: pending
reason: negative-gate execution in progress
stable-v3 source readiness: pending Phase 12
stable-v3 publication: HOLD pending destructive live evidence, mixed-state validation, continuous verification, and governance ownership
remaining_blockers: Phases 01-12
```
