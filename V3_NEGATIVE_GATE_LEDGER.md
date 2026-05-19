# V3 Negative Gate Execution Ledger

## Branch

```yaml
target_branch: blastwall-v3-signed-attestation
working_branch: blastwall-v3-negative-gate-calabi
git_sha_start: d5c0877100ec782f866b6806370492e30f78f06d
git_sha_end: pending
date_started: 2026-05-19T02:46:31Z
date_completed: pending
executor: Codex 5.5 main thread with bounded Spark worker checks
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
| 03 | pending | Architecture | | | | pending |
| 04 | pending | KRA/Vault | | | | pending |
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
- raw CLI fallback: source checks pass for current fallback controls; read-only audit found revoke playbook command-shell exception to classify
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

## Destructive Negative Evidence Summary

| Case | Expected | Observed | AAP job | Result |
|---|---|---|---|---|
| pending | pending | pending | pending | pending |

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
