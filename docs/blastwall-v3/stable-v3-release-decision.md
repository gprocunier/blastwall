# Stable-v3 Release Decision

## Verdict

`GO for Blastwall v3 reference exemplar publication.`

Operational boundaries are recorded in
`docs/blastwall-v3/operational-guidance.md`.

## Source And Evidence Readiness

`GO for external review of the stable-v3 source and Calabi evidence gate.`

The current branch preserves the marker-as-locator design, signed-envelope
verification, latest-index replay guard, live policy hash binding, explicit KRA
topology, and infrastructure-only breakglass boundary. The live evidence now
covers Calabi reference topology execution, destructive fail-closed cases,
three-host mixed-state selection, and the installed continuous verification
loop.

## Adopter Responsibilities

Blastwall v3 can publish as a reference exemplar. Organizations that adopt the
pattern should staff and record the operating model before treating it as their
local control.

- Boundary owner, incident response owner, signer owner, KRA/vault owner,
  revocation authority, and breakglass approval path still need final
  assignment before local operation.
- Fleet-scale evidence remains future validation until a broader mixed-state
  scale gate is run.
- Stable-v3 shared vault custody is rejected; Calabi shared-vault evidence
  remains lab/RC reference evidence.
- Stable-v3 service-owned custody is live-green in Calabi reference evidence
  as of 2026-05-25. This proves the reference service-custody path.

Completed items since the prior decision:

- Three-host mixed-state gate completed with a current valid host, stale legacy
  host, and current-but-broken-attestation host.
- AAP continuous verification schedules were installed and exercised.
- Strict inventory audit now authenticates to FreeIPA in the Controller EE and
  reports missing artifacts as `FAIL_ATTESTATION_NOT_VISIBLE` instead of
  `auth_failure`.
- Scheduled runs `3776`, `3778`, `3780`, `3781`, `3797`, `3799`, `3802`, and
  `3804` confirm the schedule loop is firing; the audit failures are the
  expected broken-fixture fail-closed result.
- Stable-v3 shared-custody guard job `3918` failed closed.
- Transition-v3 lab/RC shared-custody health job `3922`, policy pipeline
  workflow `4046`, standalone signed preflight job `4082`, and runtime
  workflow `4102` passed.
- Digest mismatch and revoked-marker destructive cases were re-captured on
  commit `f50c1228ddcf4544a38634f05fd87179210c6917`: preflight `4233`
  failed as `FAIL_ATTESTATION_INTEGRITY`, and preflight `4255` failed as
  `FAIL_REVOKED_ATTESTATION`.
- Stable-v3 service-owned custody was refreshed on commit
  `93fab21cd548c4ff7ca2d2addb21ecc1ad5c2cc3`: KRA health `4872` passed,
  shared-custody rejection `4876` failed closed, candidate preflight `4918`
  passed, policy pipeline workflow `4922` passed, runtime workflow `4968`
  passed, and inventory audit `4989` verified the valid host while failing
  closed on the intentional broken fixture.

## Evidence Summary

- Current publication branch: `v3`.
- Current branch head: use `origin/v3`; this decision does not self-pin the
  branch commit.
- Latest publication-polish commit before the metadata refresh:
  `b87dc6e0edb536c3a919a881d616060c6a20f354`.
- Controller-visible commit observed at 2026-05-20 UTC:
  `f50c1228ddcf4544a38634f05fd87179210c6917`, project update `4221`.
- Three-host evidence project sync: `3771` to
  `9e9e5e8ac555a4492ca9580e6c513b6763bdbe8b`.
- Post-matrix restore sync from destructive packet: `3690`.
- Post-matrix golden preflight: `3693`, successful.
- Three-host inventory sync: `3712`.
- Candidate-only preflight: `3725`, successful.
- Stale-host preflight: `3728`, failed closed.
- Broken-attestation profile preflight: `3723`, failed closed.
- Continuous schedules: `6` hourly KRA health, `7` hourly inventory audit,
  `8` daily candidate preflight, `9` daily runtime verification.
- Continuous loop checks: KRA health `3731`, candidate preflight `3735`,
  runtime workflow `3736`, strict inventory audit `3772`, scheduled KRA health
  `3776`/`3797`/`3802`, scheduled preflight `3780`, scheduled runtime `3781`,
  and scheduled audits `3778`/`3799`/`3804`.
- Stable shared custody rejection: `3918` and `4876`.
- Stable service-owned custody refresh: KRA health `4872`, candidate preflight
  `4918`, policy pipeline `4922`, runtime workflow `4968`, and inventory audit
  `4989`.
- Corrected transition-v3 lab/RC path: KRA health `3922`, policy pipeline
  `4046`, standalone preflight `4082`, runtime workflow `4102`, and strict
  audit `4098` expected fixture fail-closed.

Fail-closed destructive evidence:

- Missing envelope: `3421`, `FAIL_ATTESTATION_NOT_VISIBLE`.
- Missing index: `3439`, `FAIL_INDEX_NOT_VISIBLE`.
- Digest mismatch: historical `3457` failed closed with
  `failure_class=digest_mismatch`; final recapture `4233` failed as
  `FAIL_ATTESTATION_INTEGRITY`.
- Policy drift: `3478`, `FAIL_DRIFTED_POLICY`.
- Signer untrusted: `3485`, `FAIL_SIGNER_UNTRUSTED`.
- Signature tamper: `3505`, `FAIL_SIGNATURE_INVALID`.
- Replay: `3531`, `FAIL_REPLAYED_ATTESTATION`.
- Expiry: `3557`, `FAIL_STALE_ATTESTATION`.
- Revoked latest index: `3579`, `FAIL_REVOKED_ATTESTATION`.
- Revoked marker: historical `3601` failed closed; final recapture `4255`
  failed as `FAIL_REVOKED_ATTESTATION`.
- Profile mismatch: `3623`, `FAIL_PROFILE_MISMATCH`.
- Host binding mismatch: `3649`, `FAIL_BINDING_MISMATCH`.

Breakglass evidence:

- Allowed infra-only bypass: `3667`, pass via scoped breakglass for
  `FAIL_ATTESTATION_NOT_VISIBLE`.
- Rejected security failures: `3509` signature tamper, `3535` replay,
  `3627` profile mismatch, `3682` policy drift, and `3686` signer untrusted.

## Release Action

Proceed with reference exemplar publication from `v3`. Use
`docs/blastwall-v3/governance-owner-assignment.md` as the adopter governance
worksheet before operating the pattern locally. Capture fleet-scale evidence
before making fleet-scale readiness claims from this packet.

## Final Architecture Review Memo

```yaml
verdict:
  reference_exemplar_publication: GO.
  calabi_reference_topology_evidence: GO.
  stable_v3_service_custody_demonstration: GO.
  fleet_scale_evidence: future validation.
go_items:
  - marker remains a locator and is not the trust proof
  - preflight verifies signed envelope and latest index
  - live policy hash drift fails closed
  - KRA visibility failures remain separated from host/security failures
  - breakglass is infrastructure-only
  - destructive negatives for replay, expiry, signature, signer, profile, host binding, policy drift, revoked latest index, revoked marker, and digest mismatch are live-proven
  - stable-v3 rejects shared vault custody
  - transition-v3 lab/RC shared-custody path remains usable and explicitly labelled
  - three-host mixed-state selection and failure behavior are live-proven
  - continuous verification schedules are installed and exercised
adopter_follow_up:
  - assign named governance owners and sign-off before local operation
  - capture fleet-scale mixed-state evidence before expanding the claim
evidence_summary:
  - controller-visible commit at 2026-05-20 UTC: f50c1228ddcf4544a38634f05fd87179210c6917
  - service-custody refresh at 2026-05-25 UTC: 93fab21cd548c4ff7ca2d2addb21ecc1ad5c2cc3
  - strict inventory audit: 3772
  - scheduled loop latest jobs: 3802 and 3804
  - final destructive recapture: 4233 and 4255
  - service-custody health and runtime: 4872, 4922, 4968, 4989
  - primary evidence ledger: V3_STABLE_EVIDENCE_GATE_LEDGER.md
recommended_next_branch_or_release_action:
  - publish the reference exemplar from v3
  - assign adopter owners before local operation
  - run a fleet-scale gate before making fleet-scale claims
```
