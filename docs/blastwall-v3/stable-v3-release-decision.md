# Stable-v3 Release Decision

## Verdict

`HOLD for stable-v3 publication pending evidence.`

## Source Readiness

`GO for stable-v3 source readiness.`

The current branch preserves the marker-as-locator design, signed-envelope
verification, latest-index replay guard, live policy hash binding, explicit KRA
topology, and infrastructure-only breakglass boundary. The destructive Calabi
negative matrix now proves the required security failures fail closed.

## Publication Hold

Publication remains held for evidence and governance, not for a known
security-bypass bug.

Hold items:

- The required three-host mixed-state gate is not complete. Calabi currently
  has a current stable-v3 host and a stale fixture host; the third revoked or
  broken fixture host is still pending.
- Continuous verification is planned but not yet installed as a
  governance-owned schedule.
- Governance owners for signer custody, KRA/vault operations, revocation, and
  breakglass approval still need final assignment before a stable publication
  claim.
- Revoked marker evidence fails closed at locator resolution with
  `invalid v3 marker locator: marker is revoked`; revoked latest-index evidence
  provides the top-level `FAIL_REVOKED_ATTESTATION` state.

## Evidence Summary

- Current branch: `blastwall-v3-negative-gate-calabi`.
- Current Controller-visible commit:
  `3ff61e0a8c98439a3d3c238e687306dd2dfaafee`.
- Project sync to current commit: `3489`.
- Post-matrix inventory sync: `3690`.
- Post-matrix golden preflight: `3693`, successful.
- Controlled stale-host restores:
  `3513`, `3539`, `3561`, `3583`, `3605`, `3631`, `3653`, and `3671`.

Fail-closed destructive evidence:

- Missing envelope: `3421`, `FAIL_ATTESTATION_NOT_VISIBLE`.
- Missing index: `3439`, `FAIL_INDEX_NOT_VISIBLE`.
- Digest mismatch: `3457`, fail-closed with `failure_class=digest_mismatch`.
- Policy drift: `3478`, `FAIL_DRIFTED_POLICY`.
- Signer untrusted: `3485`, `FAIL_SIGNER_UNTRUSTED`.
- Signature tamper: `3505`, `FAIL_SIGNATURE_INVALID`.
- Replay: `3531`, `FAIL_REPLAYED_ATTESTATION`.
- Expiry: `3557`, `FAIL_STALE_ATTESTATION`.
- Revoked latest index: `3579`, `FAIL_REVOKED_ATTESTATION`.
- Profile mismatch: `3623`, `FAIL_PROFILE_MISMATCH`.
- Host binding mismatch: `3649`, `FAIL_BINDING_MISMATCH`.

Breakglass evidence:

- Allowed infra-only bypass: `3667`, pass via scoped breakglass for
  `FAIL_ATTESTATION_NOT_VISIBLE`.
- Rejected security failures: `3509` signature tamper, `3535` replay,
  `3627` profile mismatch, `3682` policy drift, and `3686` signer untrusted.

## Release Action

Continue external review on this branch with the publication decision held.
The next release-gate branch should add a third fixture host or equivalent
mixed-state inventory proof, then install or explicitly approve the continuous
verification schedule.

## Final Architecture Review Memo

```yaml
verdict:
  source_readiness: GO for stable-v3 source readiness.
  publication: HOLD for stable-v3 publication pending evidence.
go_items:
  - marker remains a locator and is not the trust proof
  - preflight verifies signed envelope and latest index
  - live policy hash drift fails closed
  - KRA visibility failures remain separated from host/security failures
  - breakglass is infrastructure-only
  - destructive negatives for replay, expiry, signature, signer, profile, host binding, policy drift, and revoked latest index are live-proven
hold_items:
  - three-host mixed-state gate is not live-proven
  - continuous verification schedule is planned but not governance-owned/installed
  - revoked marker fails closed at locator resolution rather than the revoked-attestation top-level state
no_go_items: []
evidence_summary:
  - current branch commit: 3ff61e0a8c98439a3d3c238e687306dd2dfaafee
  - post-matrix golden preflight: 3693
  - primary evidence index: docs/blastwall-v3/evidence-index.md
recommended_next_branch_or_release_action:
  - keep publication held
  - run the three-host mixed-state gate
  - assign and install the continuous verification schedule
```
