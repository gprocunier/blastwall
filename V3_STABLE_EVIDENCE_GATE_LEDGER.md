# V3 Stable Evidence Gate Ledger

## Branch

```yaml
repo: https://github.com/gprocunier/blastwall
target_branch: blastwall-v3-signed-attestation
working_branch: blastwall-v3-signed-attestation
head_start: d5c0877100ec782f866b6806370492e30f78f06d
head_after_negative_gate_adoption: d6365aa841802ebbdd083852b506bf37c6484c06
head_after_continuous_loop: 9e9e5e8ac555a4492ca9580e6c513b6763bdbe8b
head_after_docs_decision: 789e95f82a91a5541e0ef7889dab9fc7595a5454
head_after_rc_evidence_patch: working tree
date_started_utc: 2026-05-19T15:55:51Z
date_completed_utc: 2026-05-19T19:42:00Z
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
stable_v3_publication: HOLD until governance owners and sign-off are assigned
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

## Phase Status

| Phase | State | Commit | Tests | Evidence | Notes |
|---:|---|---|---|---|---|
| 00 | complete | `d5c0877` -> `d6365aa` | branch/status/dependency checks | target branch current; negative-gate tracked work fast-forwarded into target branch | untracked evidence files intentionally preserved |
| 01 | complete | `d6365aa` | `python3 tests/policy_static.py`; registry validation; drift check; `python3 -m pytest -q tests` (`167 passed`); `make test-fast`; playbook syntax checks | source/static gate passed after negative-gate adoption | no scope expansion |
| 02 | complete | carried forward | `ansible-playbook --syntax-check playbooks/attestation-vault-health.yml`; policy static | health job `3698` passed; missing-canary job `3701` failed `FAIL_CANARY_MISSING`; bad KRA job `3702` failed closed on DNS | KRA primary remains explicit |
| 03 | complete | carried forward | negative marker/artifact harness syntax; policy static | destructive harnesses ran on controlled Calabi fixture host and restored after each case | harness templates remain lab-only |
| 04 | complete | carried forward | negative matrix live jobs | missing envelope `3421`, missing index `3439`, digest mismatch `3457` failed closed | restore jobs `3425`, `3443`, `3461` |
| 05 | complete | carried forward | negative matrix live jobs | replay `3531`, expiry `3557`, revoked index `3579` failed closed | restore jobs `3539`, `3561`, `3583` |
| 06 | complete | carried forward | negative matrix live jobs | drift `3478`, signer-untrusted `3485`, signature tamper `3505`, profile mismatch `3623`, host binding `3649` failed closed | breakglass rejected security failures |
| 07 | complete | carried forward | negative matrix live jobs | breakglass `3667` passed only for scoped `FAIL_ATTESTATION_NOT_VISIBLE`; jobs `3509`, `3535`, `3627`, `3682`, `3686` rejected security failures | infra-only boundary preserved |
| 08 | complete | `fb339d7` | live AAP jobs | inventory sync `3712`; profile-group preflight `3723` failed on broken fixture; candidate preflight `3725` passed valid host; stale preflight `3728` failed closed | three-host mixed-state behavior observed |
| 09 | complete | `0ddfb81` -> `9e9e5e8` | `python3 tests/policy_static.py`; `python3 -m pytest -q tests/test_audit_blastwall_inventory.py`; syntax; `git diff --check` | schedules `6`-`9` installed; KRA health `3731` passed; candidate preflight `3735` passed; runtime workflow `3736` passed; strict inventory audit `3772` failed closed on missing artifact | audit bootstrap fixed and rerun on target branch |
| 10 | complete | `9e9e5e8` | helper path search; policy static guards | stable-v3 custody path is `eigenstate.ipa.vault_artifact`; Blastwall Python handles artifact construction and verification semantics | raw helper modes are compatibility/test surfaces, not default custody |
| 11 | complete | `9e9e5e8` | shell search; syntax; docs review | remaining stable-v3 shell use classified, including inventory audit Kerberos bootstrap | no unexplained shell in the critical path |
| 12 | complete | `789e95f` | docs and ledgers updated | external review packet, readiness checklist, evidence index, runbooks, and decision docs refreshed | claim boundary remains explicit |
| 13 | complete | `789e95f` | final review | source/evidence gate ready for external review; publication still held on governance owner/sign-off | no no-go condition observed |
| 14 | complete | working tree | targeted attestation pytest; read-only AAP schedule query; collection availability check | digest/revoked source states normalized; RC decision, evidence matrix, governance, second-maintainer, final decision, and scheduled-loop soak docs added | destructive re-capture pending after Controller sync |

## Destructive Negative Evidence

| Case | Expected | Observed | AAP job(s) | Restore verified | GO/HOLD |
|---|---|---|---|---|---|
| Missing envelope | `FAIL_ATTESTATION_NOT_VISIBLE` | failed closed with `failure_class=vault_not_found` | mutation `3414`, preflight `3421` | `3425` | GO |
| Missing index | `FAIL_INDEX_NOT_VISIBLE` | failed closed with `failure_class=vault_not_found` | mutation `3432`, preflight `3439` | `3443` | GO |
| Digest mismatch | `FAIL_ATTESTATION_INTEGRITY` | historical job failed closed with `failure_class=digest_mismatch`; source normalized in RC evidence patch | mutation `3450`, preflight `3457` | `3461` | GO; re-capture pending |
| Policy drift | `FAIL_DRIFTED_POLICY` | failed closed | preflight `3478`, breakglass rejection `3682` | n/a | GO |
| Signer untrusted | `FAIL_SIGNER_UNTRUSTED` | failed closed | preflight `3485`, breakglass rejection `3686` | n/a | GO |
| Signature tamper | `FAIL_SIGNATURE_INVALID` | failed closed; breakglass rejected | artifact `3494`, mutation `3498`, preflight `3505`, breakglass `3509` | `3513`, sync `3517` | GO |
| Replay | `FAIL_REPLAYED_ATTESTATION` | failed closed; breakglass rejected | artifact `3520`, mutation `3524`, preflight `3531`, breakglass `3535` | `3539`, sync `3543` | GO |
| Expiry | `FAIL_STALE_ATTESTATION` | failed closed | artifact `3546`, mutation `3550`, preflight `3557` | `3561`, sync `3565` | GO |
| Revoked latest index | `FAIL_REVOKED_ATTESTATION` | failed closed | artifact `3568`, mutation `3572`, preflight `3579` | `3583`, sync `3587` | GO |
| Revoked marker | `FAIL_REVOKED_ATTESTATION` | historical job failed closed during locator resolution; source normalized in RC evidence patch | artifact `3590`, mutation `3594`, preflight `3601` | `3605`, sync `3609` | GO; re-capture pending |
| Profile mismatch | `FAIL_PROFILE_MISMATCH` | failed closed; breakglass rejected | artifact `3612`, mutation `3616`, preflight `3623`, breakglass `3627` | `3631`, sync `3635` | GO |
| Host binding mismatch | `FAIL_BINDING_MISMATCH` | failed closed | artifact `3638`, mutation `3642`, preflight `3649` | `3653`, sync `3657` | GO |
| Infra breakglass | scoped visibility bypass only | `3667` passed only for scoped missing-envelope visibility failure | mutation `3660`, preflight `3667` | `3671`, sync `3675` | GO |

## Mixed-State Evidence

| Host | Marker state | Artifact state | Inventory group | Result | Notes |
|---|---|---|---|---|---|
| `mirror-registry.workshop.lan` | active v3 `base` marker | envelope and latest index visible | `blastwall_policy_candidate`, `blastwall_policy_current`, `blastwall_profile_base` | candidate preflight `3725` passed; audit `3772` report had `failure_state=null` | valid control host |
| `stale-blastwall-01.workshop.lan` | legacy/reference marker | no v3 proof | `blastwall_policy_stale`, `blastwall_inventory_marker_parse_error` | preflight `3728` failed closed; audit records parser errors | stale fixture preserved |
| `missing-artifact-blastwall-01.workshop.lan` | active v3 `base` marker | marker points at absent envelope | `blastwall_policy_current`, `blastwall_profile_base` | profile-group preflight `3723` failed; strict audit `3772` failed with `FAIL_ATTESTATION_NOT_VISIBLE` and `vault_error_type=not_found` | broken-attestation fixture |

## Continuous Verification Evidence

| Check | Schedule | Output | Owner | Status |
|---|---|---|---|---|
| KRA health and canary | schedule `6`, `Blastwall stable-v3 KRA health hourly` | manual `3731` and scheduled `3776`, `3797`, `3802` passed with canary present, `vault_reachable=true`, `kra_available=true` | governance owner pending | installed and firing |
| Inventory audit | schedule `7`, `Blastwall stable-v3 inventory audit hourly` | manual `3772` and scheduled `3778`, `3799`, `3804` authenticated, verified the valid host, and failed closed on the broken fixture | governance owner pending | installed and firing |
| Candidate preflight | schedule `8`, `Blastwall stable-v3 candidate preflight daily` | manual `3735` and scheduled `3780` passed against `blastwall_policy_candidate` | governance owner pending | installed and firing |
| Runtime verification | schedule `9`, `Blastwall stable-v3 runtime verification daily` | manual workflow `3736` and scheduled workflow `3781` passed against the candidate group | governance owner pending | installed and firing |

## Helper and Shell Classification

```yaml
stable_v3_custody_path: eigenstate.ipa.vault_artifact
blastwall_python_role: signing, verifying, locator resolution, deterministic artifact construction
raw_helper_default_custody: prohibited
sign_store_readback: compatibility/test helper only; not used by sign-attestation playbook
build_artifacts: stable signer artifact construction before vault_artifact custody
verify_existing: stable verification semantics after vault_artifact readback or marker promotion
retrieve_existing: promotion compatibility helper; not used by stable-v3 preflight
resolve_existing: stable preflight locator-to-vault-name resolver; no custody
shell_exceptions: documented in docs/blastwall-v3/shell-and-collection-exceptions.md
```

## Stable-v3 Decision

```text
Source/evidence readiness: GO for external review.
Publication decision: HOLD until governance owners and sign-off are assigned.
S-range claim: HOLD until broader scale evidence is captured.
Post-normalization recapture: HOLD for digest mismatch and revoked-marker live proof after Controller sync.
```
