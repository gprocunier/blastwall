# Stable-v3 Release Decision

## Verdict

`HOLD for stable-v3 publication pending governance owner assignment and sign-off.`

## Source And Evidence Readiness

`GO for external review of the stable-v3 source and Calabi evidence gate.`

The current branch preserves the marker-as-locator design, signed-envelope
verification, latest-index replay guard, live policy hash binding, explicit KRA
topology, and infrastructure-only breakglass boundary. The live evidence now
covers healthy execution, destructive fail-closed cases, three-host mixed-state
selection, and the installed continuous verification loop.

## Publication Hold

Publication remains held for governance, not for a known security-bypass bug.

Hold items:

- Boundary owner, incident response owner, signer owner, KRA/vault owner,
  revocation authority, and breakglass approval path still need final
  assignment before a stable publication claim.
- The S-range claim remains held until a broader mixed-state scale gate is run.
- Revoked marker evidence fails closed at locator resolution with
  `invalid v3 marker locator: marker is revoked`; revoked latest-index evidence
  provides the top-level `FAIL_REVOKED_ATTESTATION` state.

Completed items since the prior decision:

- Three-host mixed-state gate completed with a current valid host, stale legacy
  host, and current-but-broken-attestation host.
- AAP continuous verification schedules were installed and exercised.
- Strict inventory audit now authenticates to FreeIPA in the Controller EE and
  reports missing artifacts as `FAIL_ATTESTATION_NOT_VISIBLE` instead of
  `auth_failure`.

## Evidence Summary

- Current branch: `blastwall-v3-signed-attestation`.
- Current branch head:
  `789e95f82a91a5541e0ef7889dab9fc7595a5454`.
- Controller-visible evidence commit:
  `9e9e5e8ac555a4492ca9580e6c513b6763bdbe8b`.
- Project sync to evidence commit: `3771`.
- Post-matrix restore sync from destructive packet: `3690`.
- Post-matrix golden preflight: `3693`, successful.
- Three-host inventory sync: `3712`.
- Candidate-only preflight: `3725`, successful.
- Stale-host preflight: `3728`, failed closed.
- Broken-attestation profile preflight: `3723`, failed closed.
- Continuous schedules: `6` hourly KRA health, `7` hourly inventory audit,
  `8` daily candidate preflight, `9` daily runtime verification.
- Continuous loop checks: KRA health `3731`, candidate preflight `3735`,
  runtime workflow `3736`, strict inventory audit `3772`.

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

Proceed with external review of `blastwall-v3-signed-attestation` and keep the
stable-v3 publication decision held until named owners and sign-off are in
place. Do not claim S-range readiness from this evidence packet.

## Final Architecture Review Memo

```yaml
verdict:
  source_readiness: GO for external review.
  publication: HOLD pending governance owner assignment and sign-off.
  s_range_claim: HOLD pending broader scale evidence.
go_items:
  - marker remains a locator and is not the trust proof
  - preflight verifies signed envelope and latest index
  - live policy hash drift fails closed
  - KRA visibility failures remain separated from host/security failures
  - breakglass is infrastructure-only
  - destructive negatives for replay, expiry, signature, signer, profile, host binding, policy drift, and revoked latest index are live-proven
  - three-host mixed-state selection and failure behavior are live-proven
  - continuous verification schedules are installed and exercised
hold_items:
  - named governance owners and sign-off are not recorded
  - S-range mixed-state scale evidence is not captured
  - revoked marker fails closed at locator resolution rather than the revoked-attestation top-level state
no_go_items: []
evidence_summary:
  - current branch head: 789e95f82a91a5541e0ef7889dab9fc7595a5454
  - controller-visible evidence commit: 9e9e5e8ac555a4492ca9580e6c513b6763bdbe8b
  - strict inventory audit: 3772
  - primary evidence ledger: V3_STABLE_EVIDENCE_GATE_LEDGER.md
recommended_next_branch_or_release_action:
  - keep publication held
  - assign owners and sign off the operating model
  - run the S-range scale gate before making an S-range claim
```
