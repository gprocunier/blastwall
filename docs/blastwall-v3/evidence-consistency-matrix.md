# Stable-v3 Evidence Consistency Matrix

Date: 2026-05-19 UTC
Branch: `blastwall-v3-signed-attestation`

This matrix reconciles the live Calabi evidence with the current source
failure-state contract. Historical live jobs remain named as observed; source
normalizations added after those jobs are called out separately so reviewers do
not confuse an old Controller run with current code behavior.

The machine-readable contract for current expected states is
`docs/blastwall-v3/failure-state-manifest.yml`.

| Case | Expected state | Observed live state | AAP job/workflow | Host | Breakglass | Restore proof | Follow-up |
|---|---|---|---|---|---|---|---|
| Missing envelope | `FAIL_ATTESTATION_NOT_VISIBLE` | `FAIL_ATTESTATION_NOT_VISIBLE`, `failure_class=vault_not_found` | mutation `3414`, preflight `3421` | `stale-blastwall-01.workshop.lan` | allowed only in scoped infra case `3667` | `3425` | none |
| Missing index | `FAIL_INDEX_NOT_VISIBLE` | `FAIL_INDEX_NOT_VISIBLE`, `failure_class=vault_not_found` | mutation `3432`, preflight `3439` | `stale-blastwall-01.workshop.lan` | not used | `3443` | none |
| Digest mismatch | `FAIL_ATTESTATION_INTEGRITY` | historical live job `3457` failed closed with `failure_class=digest_mismatch` under the envelope-read guard | mutation `3450`, preflight `3457` | `stale-blastwall-01.workshop.lan` | source tests reject breakglass | `3461` | re-capture destructive case after this source patch is Controller-visible |
| Replay | `FAIL_REPLAYED_ATTESTATION` | `FAIL_REPLAYED_ATTESTATION` | artifact `3520`, mutation `3524`, preflight `3531` | `stale-blastwall-01.workshop.lan` | rejected in `3535` | `3539`, sync `3543` | none |
| Revoked latest index | `FAIL_REVOKED_ATTESTATION` | `FAIL_REVOKED_ATTESTATION` | artifact `3568`, mutation `3572`, preflight `3579` | `stale-blastwall-01.workshop.lan` | not used | `3583`, sync `3587` | none |
| Revoked marker | `FAIL_REVOKED_ATTESTATION` | historical live job `3601` failed closed during locator resolution before this source patch normalized the message | artifact `3590`, mutation `3594`, preflight `3601` | `stale-blastwall-01.workshop.lan` | source tests reject breakglass | `3605`, sync `3609` | re-capture revoked-marker case after this source patch is Controller-visible |
| Expired | `FAIL_STALE_ATTESTATION` | `FAIL_STALE_ATTESTATION` | artifact `3546`, mutation `3550`, preflight `3557` | `stale-blastwall-01.workshop.lan` | not used | `3561`, sync `3565` | none |
| Policy drift | `FAIL_DRIFTED_POLICY` | `FAIL_DRIFTED_POLICY` | preflight `3478`; breakglass `3682` | `mirror-registry.workshop.lan` | rejected in `3682` | n/a | none |
| Signer untrusted | `FAIL_SIGNER_UNTRUSTED` | `FAIL_SIGNER_UNTRUSTED` | preflight `3485`; breakglass `3686` | `mirror-registry.workshop.lan` | rejected in `3686` | n/a | none |
| Signature tamper | `FAIL_SIGNATURE_INVALID` | `FAIL_SIGNATURE_INVALID` | artifact `3494`, mutation `3498`, preflight `3505` | `stale-blastwall-01.workshop.lan` | rejected in `3509` | `3513`, sync `3517` | none |
| Profile mismatch | `FAIL_PROFILE_MISMATCH` | `FAIL_PROFILE_MISMATCH` | artifact `3612`, mutation `3616`, preflight `3623` | `stale-blastwall-01.workshop.lan` | rejected in `3627` | `3631`, sync `3635` | none |
| Host binding mismatch | `FAIL_BINDING_MISMATCH` | `FAIL_BINDING_MISMATCH` | artifact `3638`, mutation `3642`, preflight `3649` | `stale-blastwall-01.workshop.lan` | not used | `3653`, sync `3657` | none |

## Source Normalization

The current source maps marker and latest-index revocation into the same
`FAIL_REVOKED_ATTESTATION` family. Digest disagreement between marker, latest
index, and envelope now maps to `FAIL_ATTESTATION_INTEGRITY`.

Targeted regression coverage:

- `tests/test_blastwall_attestation_index.py`
- `tests/test_blastwall_attestation_verify.py`
- `tests/test_blastwall_attestation_sign.py`
- `tests/policy_static.py`

## Decision Impact

No stable-v3 security bypass is open from the historical state-surface gaps.
Both gaps were already fail-closed live. The source now exposes clearer
operator states, but the next destructive rehearsal should re-run the digest
mismatch and revoked-marker cases after the Controller project is synced to the
post-normalization commit.
