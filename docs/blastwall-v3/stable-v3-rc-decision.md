# Stable-v3 RC Decision

Date: 2026-05-19 UTC
Branch: `blastwall-v3-signed-attestation`

Operating boundary: `docs/blastwall-v3/operational-guidance.md`.

## Decision

```text
stable-v3 engineering RC:
  GO

stable-v3 publication:
  HOLD

S-range:
  HOLD
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
- Destructive negative evidence covers missing envelope, missing index, replay,
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

## Remaining Holds

- Stable-v3 publication remains held until named owners and sign-off are
  recorded.
- Stable-v3 service-owned or named-user custody is not live-green in Calabi;
  jobs `3914`, `3987`, and `3991` failed in the vault-health path.
- The scheduled-loop soak has initial and hourly evidence, but a longer
  24-hour or 72-hour soak is still an operating-readiness item.
- S-range remains held until a 10+ host mixed-state gate, external red-team
  review, and ownership/scale evidence are complete.

## Governance Owner Status

`docs/blastwall-v3/governance-owner-assignment.md` is the required assignment
surface. All owner rows remain pending until a human owner accepts the role.

## Explicit Non-Claims

```text
This decision does not claim 10+ host S-range fleet evidence.
This decision does not claim independent external red-team completion.
This decision does not claim final publication approval while governance owners are pending.
This decision does not claim broad portability beyond the Calabi reference topology.
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
