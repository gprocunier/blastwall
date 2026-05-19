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
| 02 | in_progress | KRA/Vault | pending | AAP job `3271` exposed standalone KRA health bootstrap failure; local syntax/static checks pass after patch | job `3271` failed with `ipalib finalize failed: 'Env' object has no attribute 'server'`; classified likely fresh-deploy bug, rerun-likelihood 10% | rerun healthy and controlled canary-missing failure after Controller sync |
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
- KRA infra split: source checks pass; live health checks pending
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
