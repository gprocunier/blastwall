# Stable-v3 Reference Exemplar Decision

Date: 2026-05-19 UTC
Publication branch: `v3`

Operating boundary: `docs/blastwall-v3/operational-guidance.md`.

## Decision

```text
reference exemplar publication:
  GO

Calabi reference topology evidence:
  GO

stable-v3 service-owned custody demonstration:
  GO

fleet-scale evidence:
  future validation
```

## Evidence Basis

The RC evidence package preserves the v3 architecture:

- markers locate evidence but are not the trust proof;
- signed envelopes and signed latest-generation indexes are mandatory in
  stable-v3;
- live policy hash verification remains mandatory;
- inventory selects only and preflight is authoritative;
- KRA/vault visibility failures remain separate from security failures;
- breakglass is scoped to infrastructure visibility failures only.

## Completed Evidence

- Healthy signed-attestation policy pipelines and runtime verification are
  recorded in AAP, including workflow `2843`, runtime workflow `3736`, and
  corrected transition-v3 lab/RC workflow `4102`.
- Destructive fail-closed evidence covers missing envelope, missing index, replay,
  expiry, revoked latest index, policy drift, signer trust, signature tamper,
  profile mismatch, host binding mismatch, and breakglass rejection.
- Three-host mixed-state evidence covers a current valid host, a stale legacy
  host, and a current marker with missing attestation evidence.
- Continuous verification schedules `6` through `9` are installed and have
  scheduled runs recorded.
- Source now normalizes digest mismatch to `FAIL_ATTESTATION_INTEGRITY` and
  revoked marker to `FAIL_REVOKED_ATTESTATION`; final live recapture jobs
  `4233` and `4255` prove those states on Controller-visible commit
  `f50c1228ddcf4544a38634f05fd87179210c6917`.
- Stable-v3 rejects shared vault custody in job `3918`. Transition-v3 lab/RC
  shared custody remains explicit and usable.
- Stable-v3 service-owned custody is live-green in the Calabi demonstration
  environment after KRA health `4872`, policy pipeline `4922`, runtime
  workflow `4968`, and inventory audit `4989`.

## Adopter Follow-Up

- Named owners and sign-off should be recorded before local operation.
- The scheduled-loop soak has initial and hourly evidence, but a longer
  24-hour or 72-hour soak is still an adopter operating-readiness item.
- Fleet-scale readiness should wait for a 10+ host mixed-state gate,
  external review, and local ownership evidence.

## Adopter Governance Worksheet

`docs/blastwall-v3/governance-owner-assignment.md` is the adopter assignment
surface. Pending rows mean the exemplar has not been staffed for local
operation; they do not block publishing the upstream reference exemplar.

## Claim Boundary

```text
The current decision covers the Calabi reference topology and the signed
evidence gate behavior recorded in the ledgers. Fleet-scale readiness,
external red-team completion, and broad portability require separate evidence
before adopters expand the claim.
```

## Sign-Off

| Role | Name | Sign-off | Date |
|---|---|---:|---|
| Boundary owner | pending | no | pending |
| Incident response owner | pending | no | pending |
| Signer owner | pending | no | pending |
| KRA/vault owner | pending | no | pending |
| Revocation authority | pending | no | pending |
| Breakglass approver | pending | no | pending |
| Second maintainer-developer | pending | no | pending |
