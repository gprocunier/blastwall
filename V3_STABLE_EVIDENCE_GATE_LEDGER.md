# V3 Stable Evidence Gate Ledger

## Branch

```yaml
repo: https://github.com/gprocunier/blastwall
target_branch: blastwall-v3-signed-attestation
working_branch: blastwall-v3-signed-attestation
head_start: d5c0877100ec782f866b6806370492e30f78f06d
head_after_negative_gate_adoption: d6365aa841802ebbdd083852b506bf37c6484c06
head_after_negative_gate_adoption_summary: "d6365aa negative-gate: record destructive Calabi evidence"
date_started_utc: 2026-05-19T15:55:51Z
date_completed_utc: pending
tracked_status_at_start: clean
untracked_existing_preserved:
  - WORK_LEDGER.md
  - artifacts/
  - tests/test_traffic_control_userns_precondition_probe.py
  - tests/trigger-traffic-control-userns-precondition.py
```

## Scope Freeze

```yaml
v3_architecture: preserve
healthy_path_v3_evidence: preserve
stable_v3_publication: HOLD until required evidence is complete
s_range_claim: HOLD
new_selinux_deny_scopes: prohibited
new_marker_grammar: prohibited
new_profile_names: prohibited
kvm_policy_work: prohibited
seccomp_implementation: prohibited
bpf_lsm_implementation: prohibited
signature_algorithm_change: prohibited
new_cryptographic_trust_model: prohibited
core_invariant: "Inventory selects. Markers locate. Vault artifacts carry signed evidence. Preflight verifies. AAP records evidence. SELinux enforces on the host."
```

## Dependency Floor

```yaml
requirements.yml:
  eigenstate.ipa: "1.18.1"
execution-environment/requirements.yml:
  eigenstate.ipa: "1.18.1"
poc-calabi/requirements.yml:
  eigenstate.ipa: "1.18.1"
```

## Phase Status

| Phase | State | Owner | Commit | Tests | Evidence | Notes |
|---:|---|---|---|---|---|---|
| 00 | complete | Main thread | `d5c0877` -> `d6365aa` | branch/status/dependency checks | target branch current, tracked clean, scope frozen; previous negative-gate tracked work fast-forwarded into target branch | untracked evidence files intentionally preserved |
| 01 | complete | Source quality | `d6365aa` | `python3 tests/policy_static.py`; registry validation; drift check; `python3 -m pytest -q tests` (`167 passed`); `make test-fast`; playbook syntax check including negative-gate harnesses; `python3 -m py_compile tools/blastwall_negative_gate_artifacts.py` | all source/static checks passed after negative-gate adoption; syntax warning only from empty localhost inventory context | GO for live destructive/adoption work |
| 02 | pending | KRA/vault | pending | pending | pending | positive and negative KRA health evidence required |
| 03 | pending | Harness | pending | pending | pending | prior negative-gate branch has useful harness changes; target branch still needs review/adoption decision |
| 04 | pending | Artifact visibility | pending | pending | pending | missing envelope/index evidence required |
| 05 | pending | Attestation negatives | pending | pending | pending | replay, expiry, revocation evidence required |
| 06 | pending | Crypto/binding/drift | pending | pending | pending | signature, signer, host/profile, registry, policy drift evidence required |
| 07 | pending | Breakglass | pending | pending | pending | infra-only bypass and trust-failure rejection required |
| 08 | pending | Mixed state | pending | pending | pending | three-host gate required |
| 09 | pending | Continuous verification | pending | pending | pending | schedule or implemented loop required |
| 10 | pending | Legacy helper cleanup | pending | pending | pending | classify custody/helper paths |
| 11 | pending | Shell/collection review | pending | pending | pending | classify shell exceptions |
| 12 | pending | Docs/external packet | pending | pending | pending | update review artifacts |
| 13 | pending | Architecture decision | pending | pending | pending | final GO/HOLD decision |

## No-Go Review Log

```yaml
trust_model_no_go: none_observed_at_baseline
breakglass_no_go: none_observed_at_baseline
kra_vault_no_go: none_observed_at_baseline
marker_publication_no_go: none_observed_at_baseline
evidence_no_go: stable_v3_publication_remains_hold
scope_no_go: none_observed_at_baseline
```

## Prior Evidence Branch Context

```yaml
source_branch: blastwall-v3-negative-gate-calabi
head: d6365aa
purpose: destructive negative evidence and lab-only harness work from the previous gate
current_target_branch_delta:
  - docs/blastwall-v3/calabi-negative-evidence.md
  - docs/blastwall-v3/evidence-index.md
  - docs/blastwall-v3/external-review-packet.md
  - docs/blastwall-v3/multi-host-continuous-verification-plan.md
  - docs/blastwall-v3/shell-and-collection-exceptions.md
  - docs/blastwall-v3/stable-v3-readiness-checklist.md
  - docs/blastwall-v3/stable-v3-release-decision.md
  - playbooks/attestation-vault-health.yml
  - playbooks/negative-gate-attestation-artifacts.yml
  - playbooks/negative-gate-idm-marker.yml
  - tests/policy_static.py
  - tools/blastwall_negative_gate_artifacts.py
adoption_rule: review and carry forward only stable-evidence-gate-appropriate tracked changes; do not add intentionally untracked evidence files
adoption_status: fast-forwarded into target branch before live target-branch rerun
```

## Destructive Negative Evidence

| Case | Expected | Observed | AAP workflow/job | Restore verified | GO/HOLD |
|---|---|---|---|---|---|
| pending | pending | pending | pending | pending | HOLD |

## Mixed-State Evidence

| Host | Marker state | Artifact state | Inventory group | Preflight result | Notes |
|---|---|---|---|---|---|
| pending | pending | pending | pending | pending | pending |

## Continuous Verification Evidence

| Check | Schedule | Output | Owner | Status |
|---|---|---|---|---|
| pending | pending | pending | pending | HOLD |

## Stable-v3 Decision

```text
HOLD
```
