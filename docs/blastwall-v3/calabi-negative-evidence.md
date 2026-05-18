# Calabi Negative Evidence Packet (Destructive v3 Gate)

## Purpose

Collect destructive negative evidence for Blastwall v3 stable-v3 policy gates on Calabi. This is a required Phase 09 evidence lane and is currently incomplete.

## Scope

- Target branch: `blastwall-v3-signed-attestation`
- Goal: prove fail-closed behavior and infra-only breakglass constraints under live negative conditions.

## Required case set

Each case below must be captured against a controlled/disposable Calabi host:

- Missing envelope
- Missing index
- Wrong generation / replayed attestation
- Revoked marker/index
- Expired attestation
- Policy hash drift
- KRA canary stale or missing
- Vault auth failure
- Signature tamper
- Profile mismatch

## Expected failure behavior

- `FAIL_ATTESTATION_NOT_VISIBLE`: envelope missing or not visible from configured KRA path.
- `FAIL_INDEX_NOT_VISIBLE`: index missing or stale/inaccessible.
- Replay / binding anomalies: `FAIL_REPLAYED_ATTESTATION` or binding failure.
- `FAIL_REVOKED_ATTESTATION`: revoked marker/index.
- Host-verification failures (`FAIL_DRIFTED_POLICY`, bad signature, profile mismatch, signer mismatch): **no breakglass bypass**.
- Infrastructure-class failures may allow breakglass only when explicitly scoped and operator approved.

## Evidence status (this pack)

| Case | Expected | Live Calabi capture |
|---|---|---|
| Missing envelope | `FAIL_ATTESTATION_NOT_VISIBLE` | pending |
| Missing index | `FAIL_INDEX_NOT_VISIBLE` | pending |
| Wrong generation | replay/binding failure | pending |
| Revoked marker/index | `FAIL_REVOKED_ATTESTATION` | pending |
| Expired attestation | expired attestation failure | pending |
| Policy hash drift | `FAIL_DRIFTED_POLICY` | pending |
| KRA stale/missing canary | infra visibility failure | pending |
| Vault auth failure | auth/infra failure | pending |
| Signature tamper | signature failure | pending |
| Profile mismatch | binding/match failure | pending |

## Capture template

```yaml
phase: 09
commit:
test_or_gate:
environment:
commands:
results:
AAP_workflow_ids:
AAP_job_ids:
host:
profile:
attestation_mode:
marker:
vault_primary:
policy_sha256:
registry_sha256:
failure_state:
vault_error_type:
kra_available:
retry_attempted:
breakglass_enabled:
breakglass_result:
operator_summary:
attachments:
```

## Hold note

No live destructive negative matrix results are currently attached in-repo for this phase. Local regression tests continue to cover the same failure classes in the offline test matrix; per execution-pack rules, they are not being treated here as substitute live negative evidence.
