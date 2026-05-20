# V3 Negative Gate Execution Ledger

## Branch

```yaml
target_branch: blastwall-v3-signed-attestation
working_branch: blastwall-v3-negative-gate-calabi
git_sha_start: d5c0877100ec782f866b6806370492e30f78f06d
git_sha_end: 3ff61e0a8c98439a3d3c238e687306dd2dfaafee
git_sha_end_note: live-tested source state; evidence docs are recorded on the published branch head
date_started: 2026-05-19T02:46:31Z
date_completed: 2026-05-19T05:26:28Z
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
| 04 | complete | KRA/Vault | `06e7831` plus `f50c122` recapture | live AAP preflight; source regression tests | missing envelope job `3421` failed as `FAIL_ATTESTATION_NOT_VISIBLE`; missing index job `3439` failed as `FAIL_INDEX_NOT_VISIBLE`; final digest mismatch recapture job `4233` failed as `FAIL_ATTESTATION_INTEGRITY` | none for covered cases |
| 05 | complete | Attestation | `3ff61e0` plus `f50c122` recapture | live AAP artifact harness, marker harness, inventory sync, preflight jobs, source regression tests | replay job `3531` failed as `FAIL_REPLAYED_ATTESTATION`; expiry job `3557` failed as `FAIL_STALE_ATTESTATION`; revoked-index job `3579` failed as `FAIL_REVOKED_ATTESTATION`; final revoked-marker recapture job `4255` failed as `FAIL_REVOKED_ATTESTATION` | none for covered cases |
| 06 | complete | Attestation | `3ff61e0` | live AAP preflight against golden and controlled stale-host artifacts | policy drift job `3478` failed as `FAIL_DRIFTED_POLICY`; signer allowlist mismatch job `3485` failed as `FAIL_SIGNER_UNTRUSTED`; signature tamper job `3505` failed as `FAIL_SIGNATURE_INVALID`; profile mismatch job `3623` failed as `FAIL_PROFILE_MISMATCH`; host binding job `3649` failed as `FAIL_BINDING_MISMATCH` | none for covered cases |
| 07 | complete | Preflight | `3ff61e0` plus `f50c122` recapture | live AAP breakglass positive/rejection jobs; source regression tests | missing-envelope breakglass job `3667` passed only with scoped metadata; drift job `3682`, signer job `3686`, signature job `3509`, profile job `3627`, and replay job `3535` all rejected breakglass; source tests reject breakglass for digest mismatch and revoked marker | none for covered cases |
| 08 | complete | Inventory | `fb339d7` | inventory sync and mixed-state proof | inventory sync `3712`; candidate preflight `3725` passed; stale preflight `3728` failed closed; profile-base preflight `3723` failed closed on broken fixture; strict audit `3772` failed closed on the missing artifact fixture | none for covered candidate scope |
| 09 | complete | AAP/Ops | `0ddfb81` -> `9e9e5e8` | live AAP schedules and strict audit | schedules `6` through `9` installed; KRA health `3731`, candidate preflight `3735`, runtime `3736`, strict audit `3772`, and scheduled jobs through `3804` recorded | long-duration operations soak still needs ownership |
| 10 | complete | Collections | `3ff61e0` | syntax/static checks; no-shell artifact harness | artifact harness uses `ansible.builtin.command` with `argv` plus `eigenstate.ipa.vault_artifact`; static guard added so it is not registered as a production template | existing lab-only marker harness still has documented CLI fallback |
| 11 | complete | Docs/PM | pending | evidence packet updates | ledger, negative evidence packet, release decision, evidence index, readiness checklist, and external review packet include destructive negative job IDs through `3693` | none |
| 12 | complete | Architecture | pending | final architecture review | release posture is `GO for external review` and `HOLD for stable-v3 publication pending governance and custody readiness` | governance owner assignment, stable-v3 non-shared custody health, and S-range remain publication blockers |

## Security Invariants Checked

```text
- marker is locator only: Phase 01 static/source checks pass
- signed envelope required: Phase 01 static/source checks pass
- latest index required: Phase 01 static/source checks pass
- live policy hash required: Phase 01 static/source checks pass
- policy drift failure: live AAP preflight job `3478` failed as `FAIL_DRIFTED_POLICY`
- signer allowlist failure: live AAP preflight job `3485` failed as `FAIL_SIGNER_UNTRUSTED`
- KRA infra split: live AAP health job `3292` passed and missing-canary job `3290` failed as `FAIL_CANARY_MISSING` without host-drift ambiguity
- breakglass boundaries: live AAP jobs `3667`, `3682`, `3686`, `3509`, `3627`, and `3535` prove infra-only bypass and security-failure rejection
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
  historical_mutation_job: 3450
  historical_preflight_job: 3457
  historical_restore_job: 3461
  recapture_artifact_job: 4222
  recapture_mutation_job: 4226
  recapture_inventory_update: 4230
  recapture_preflight_job: 4233
  recapture_restore_job: 4237
  recapture_restore_inventory: 4241
  host: stale-blastwall-01.workshop.lan
  observed_failure_state_historical: FAIL_ATTESTATION_NOT_VISIBLE
  observed_failure_state_final: FAIL_ATTESTATION_INTEGRITY
  failure_class: digest_mismatch
  note: final recapture ran after Controller project sync 4221 to f50c1228ddcf4544a38634f05fd87179210c6917
```

## Phase 05-07 Attestation and Breakglass Notes

```yaml
policy_hash_drift:
  preflight_job: 3478
  commit: c5241c21293c3fe372d3ab5ba3bb4d1f03192c9c
  host: mirror-registry.workshop.lan
  mutation: none
  current_policy_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  observed_failure_state: FAIL_DRIFTED_POLICY
  message: current installed policy hash does not match signed payload
  breakglass_status: pending explicit rejection proof
signer_not_allowlisted:
  preflight_job: 3485
  commit: c5241c21293c3fe372d3ab5ba3bb4d1f03192c9c
  host: mirror-registry.workshop.lan
  mutation: none
  signer_allowlist: "0000000000000000000000000000000000000000"
  observed_failure_state: FAIL_SIGNER_UNTRUSTED
  message: signer_kid is not allowlisted
  breakglass_status: pending explicit rejection proof
pending_crypto_binding_cases:
  - none in required Phase 06 set
signature_tamper:
  artifact_job: 3494
  mutation_job: 3498
  preflight_job: 3505
  breakglass_preflight_job: 3509
  restore_job: 3513
  restore_sync: 3517
  host: stale-blastwall-01.workshop.lan
  observed_failure_state: FAIL_SIGNATURE_INVALID
  breakglass_result: rejected
replayed_generation:
  artifact_job: 3520
  mutation_job: 3524
  preflight_job: 3531
  breakglass_preflight_job: 3535
  restore_job: 3539
  restore_sync: 3543
  observed_failure_state: FAIL_REPLAYED_ATTESTATION
  breakglass_result: rejected
expired_attestation:
  artifact_job: 3546
  mutation_job: 3550
  preflight_job: 3557
  restore_job: 3561
  restore_sync: 3565
  observed_failure_state: FAIL_STALE_ATTESTATION
revoked_index:
  artifact_job: 3568
  mutation_job: 3572
  preflight_job: 3579
  restore_job: 3583
  restore_sync: 3587
  observed_failure_state: FAIL_REVOKED_ATTESTATION
revoked_marker:
  historical_artifact_job: 3590
  historical_mutation_job: 3594
  historical_preflight_job: 3601
  historical_restore_job: 3605
  historical_restore_sync: 3609
  recapture_artifact_job: 4244
  recapture_mutation_job: 4248
  recapture_inventory_update: 4252
  recapture_preflight_job: 4255
  recapture_restore_job: 4259
  recapture_restore_inventory: 4263
  final_safety_restore: 4266
  final_inventory_update: 4270
  observed_failure_state_historical: FAIL_LOCATOR_REJECTED
  observed_failure_state_final: FAIL_REVOKED_ATTESTATION
  message_historical: "invalid v3 marker locator: marker is revoked"
profile_mismatch:
  artifact_job: 3612
  mutation_job: 3616
  preflight_job: 3623
  breakglass_preflight_job: 3627
  restore_job: 3631
  restore_sync: 3635
  observed_failure_state: FAIL_PROFILE_MISMATCH
  breakglass_result: rejected
host_binding_mismatch:
  artifact_job: 3638
  mutation_job: 3642
  preflight_job: 3649
  restore_job: 3653
  restore_sync: 3657
  observed_failure_state: FAIL_BINDING_MISMATCH
breakglass_missing_envelope:
  mutation_job: 3660
  preflight_job: 3667
  restore_job: 3671
  restore_sync: 3675
  observed_status: PASS
  override_failure_state: FAIL_ATTESTATION_NOT_VISIBLE
breakglass_policy_drift:
  preflight_job: 3682
  observed_failure_state: FAIL_DRIFTED_POLICY
breakglass_signer_untrusted:
  preflight_job: 3686
  observed_failure_state: FAIL_SIGNER_UNTRUSTED
post_matrix_restore:
  inventory_sync: 3690
  golden_preflight_job: 3693
  mirror_marker: active v3 base
  stale_marker: original reference-v2/v1-style fixture only
```

## Destructive Negative Evidence Summary

| Case | Expected | Observed | AAP job | Result |
|---|---|---|---|---|
| Missing envelope | `FAIL_ATTESTATION_NOT_VISIBLE` | `FAIL_ATTESTATION_NOT_VISIBLE`, `failure_class=vault_not_found` | mutation `3414`, preflight `3421`, restore `3425` | PASS_FAIL_CLOSED |
| Missing index | `FAIL_INDEX_NOT_VISIBLE` | `FAIL_INDEX_NOT_VISIBLE`, `failure_class=vault_not_found` | mutation `3432`, preflight `3439`, restore `3443` | PASS_FAIL_CLOSED |
| Digest mismatch | `FAIL_ATTESTATION_INTEGRITY` | final recapture `4233` failed as `FAIL_ATTESTATION_INTEGRITY`; historical `3457` failed closed before normalization | artifact `4222`, mutation `4226`, inventory `4230`, preflight `4233`, restore `4237`, sync `4241` | PASS_FAIL_CLOSED |
| Policy hash drift | `FAIL_DRIFTED_POLICY` | `FAIL_DRIFTED_POLICY`, `current installed policy hash does not match signed payload` | preflight `3478` | PASS_FAIL_CLOSED |
| Signer not allowlisted | `FAIL_SIGNER_UNTRUSTED` | `FAIL_SIGNER_UNTRUSTED`, `signer_kid is not allowlisted` | preflight `3485` | PASS_FAIL_CLOSED |
| Signature tamper | `FAIL_SIGNATURE_INVALID` | `FAIL_SIGNATURE_INVALID`, `signature verification failed` | artifact `3494`, mutation `3498`, preflight `3505`, breakglass `3509`, restore `3513` | PASS_FAIL_CLOSED_BREAKGLASS_REJECTED |
| Replayed generation | `FAIL_REPLAYED_ATTESTATION` | `FAIL_REPLAYED_ATTESTATION`, `attestation generation is older than latest index` | artifact `3520`, mutation `3524`, preflight `3531`, breakglass `3535`, restore `3539` | PASS_FAIL_CLOSED_BREAKGLASS_REJECTED |
| Expired attestation | `FAIL_STALE_ATTESTATION` | `FAIL_STALE_ATTESTATION`, `attestation evidence is outside validity window` | artifact `3546`, mutation `3550`, preflight `3557`, restore `3561` | PASS_FAIL_CLOSED |
| Revoked latest index | `FAIL_REVOKED_ATTESTATION` | `FAIL_REVOKED_ATTESTATION`, `latest index is revoked` | artifact `3568`, mutation `3572`, preflight `3579`, restore `3583` | PASS_FAIL_CLOSED |
| Revoked marker | `FAIL_REVOKED_ATTESTATION` | final recapture `4255` failed as `FAIL_REVOKED_ATTESTATION`; historical `3601` failed closed before normalization | artifact `4244`, mutation `4248`, inventory `4252`, preflight `4255`, restore `4259`, sync `4263`, final restore `4266`, sync `4270` | PASS_FAIL_CLOSED |
| Profile mismatch | `FAIL_PROFILE_MISMATCH` | `FAIL_PROFILE_MISMATCH`, `payload profiles do not match required profiles` | artifact `3612`, mutation `3616`, preflight `3623`, breakglass `3627`, restore `3631` | PASS_FAIL_CLOSED_BREAKGLASS_REJECTED |
| Host binding mismatch | `FAIL_BINDING_MISMATCH` | `FAIL_BINDING_MISMATCH`, `payload subject_host does not match selected host` | artifact `3638`, mutation `3642`, preflight `3649`, restore `3653` | PASS_FAIL_CLOSED |
| Breakglass missing envelope | scoped infra bypass | `PASS`, `override_failure_state=FAIL_ATTESTATION_NOT_VISIBLE` | mutation `3660`, preflight `3667`, restore `3671` | PASS_ALLOWED_INFRA_ONLY |
| Breakglass policy drift | reject security failure | `FAIL_DRIFTED_POLICY` | preflight `3682` | PASS_REJECTED |
| Breakglass signer untrusted | reject security failure | `FAIL_SIGNER_UNTRUSTED` | preflight `3686` | PASS_REJECTED |

## Mixed-State Evidence Summary

| Host | State | Inventory | Preflight | Result |
|---|---|---|---|---|
| mirror-registry.workshop.lan | current signed stable-v3 marker | sync `3690` | job `3693` passed | PASS |
| stale-blastwall-01.workshop.lan | original reference-v2/v1-style stale marker | sync `3690` | not eligible for stable-v3 after restore | PASS_STALE_FIXTURE |
| missing-artifact-blastwall-01.workshop.lan | current v3 marker pointing at absent envelope | sync `3712` | profile preflight `3723` and strict audit `3772` failed closed | PASS_FAIL_CLOSED |

## Continuous Verification Plan

```text
workflow: Blastwall policy pipeline plus standalone Blastwall preflight and Blastwall attestation vault health templates
schedule: proposed hourly vault health, daily preflight, weekly destructive-negative rehearsal on fixture hosts
alert outputs: AAP job failure_state, verifier JSON, vault_error_type, selected_hosts, stale_hosts
owner: pending governance assignment
```

## Final Decision

```text
verdict: HOLD for stable-v3 publication pending governance and custody readiness.
reason: destructive negative security cases fail closed, mixed-state evidence is captured, and schedules are installed, but governance owners remain pending and stable-v3 non-shared custody is not live-green in Calabi.
stable-v3 source readiness: GO for external review.
stable-v3 publication: HOLD pending governance approval and service-owned or named-user custody health
remaining_blockers: governance owner assignment; stable-v3 non-shared custody health; S-range scale evidence
```
