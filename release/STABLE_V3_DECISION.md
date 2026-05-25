# Stable-v3 Release Decision

Date: 2026-05-20
Latest update: 2026-05-25
Publication branch: `v3`
Controller-visible evidence commit: `93fab21cd548c4ff7ca2d2addb21ecc1ad5c2cc3`
Latest publication-polish commit before this metadata refresh:
  `b87dc6e0edb536c3a919a881d616060c6a20f354`
Former implementation branch: `blastwall-v3-signed-attestation`
Decision:
  Reference exemplar publication: GO
  Calabi reference topology evidence: GO
  Stable-v3 service-owned custody demonstration: GO
  Fleet-scale evidence: future validation

## Summary

Blastwall v3 is ready to publish as a reference exemplar for operating a
signed-evidence gate in the Calabi demonstration environment. The packet shows
how marker selection, signed envelope verification, latest-index replay
protection, live policy binding, explicit KRA custody, and infrastructure-only
breakglass fit together as an auditable control pattern.

Stable-v3 service-owned custody health is live-green in Calabi as of
2026-05-25. The adopter governance worksheet remains pending by design: it is
the surface an organization completes before operating the pattern as a local
control, not a blocker for publishing the upstream exemplar.

The Controller-visible evidence commit above was observed after project update
`4871` on 2026-05-25 UTC. The publication branch is intentionally not
self-pinned to the current file's own commit; use `origin/v3` for the current
publication HEAD.

## Evidence Accepted

- Healthy Calabi KRA/AAP/SPO path is recorded through policy pipeline `2843`,
  post-promotion preflight `2876`, earlier policy pipeline `2177`, and runtime
  workflow `2227`.
- Destructive fail-closed matrix covers missing envelope, missing index, digest
  mismatch, policy drift, signer trust, signature tamper, replay, expiry,
  revoked latest index, profile mismatch, host binding mismatch, and breakglass
  rejection for security failures.
- Breakglass passed only for scoped artifact visibility infrastructure failure
  in job `3667`.
- Three-host mixed-state gate is recorded through inventory sync `3712`,
  preflight jobs `3723`, `3725`, `3728`, and strict inventory audit `3772`.
- Continuous verification schedules are installed as AAP schedules `6`, `7`,
  `8`, and `9`; initial checks `3731`, `3735`, `3736`, and `3772` are
  recorded.
- Scheduled checks have fired: KRA health `3776`, `3797`, and `3802` passed;
  candidate preflight `3780` passed; runtime workflow `3781` passed; inventory
  audits `3778`, `3799`, and `3804` failed closed on the intentional
  missing-artifact fixture.
- Source normalizes digest disagreement to `FAIL_ATTESTATION_INTEGRITY` and
  revoked marker to `FAIL_REVOKED_ATTESTATION`.
- Final normalized destructive recapture is recorded: digest mismatch
  preflight `4233` failed as `FAIL_ATTESTATION_INTEGRITY`; revoked-marker
  preflight `4255` failed as `FAIL_REVOKED_ATTESTATION`; final restore
  inventory update `4270` passed.
- Stable-v3 shared vault custody was rejected in job `3918`; transition-v3
  lab/RC shared custody remains usable and explicitly labelled.
- Stable-v3 service-owned custody is live-green in Calabi after the non-shared
  vault argument fix: KRA health `4872` passed with canary present, shared
  custody rejection `4876` failed closed, policy pipeline `4922` passed with
  signer `4940`, promotion `4944`, and preflight `4951`, and runtime workflow
  `4968` passed with preflight `4977` and managed-host verification `4981`.
- Attestation inventory audit `4989` failed closed on the intentional
  `missing-artifact-blastwall-01.workshop.lan` fixture while verifying the
  valid mirror host through service custody.

## Future Adoption Work

- Assign local governance owners before operating the pattern as an
  organization-owned control.
- Confirm local retention, escalation, and review expectations for AAP
  schedules `6` through `9`.
- Capture fleet-scale mixed-state evidence before expanding the claim beyond
  the Calabi reference topology.

## Gate Conditions Reviewed

The exemplar evidence preserves the core stable-v3 gates:

- v3 marker alone does not make a host suitable.
- preflight cannot pass without signed evidence in stable-v3.
- live current policy hash remains mandatory.
- artifact and index visibility failures remain distinct from security
  failures.
- breakglass remains infrastructure-only.
- no new SELinux scope, marker grammar, profile, signature algorithm, or trust
  model was added in this gate.

## Adopter Governance Worksheet

```text
Boundary owner: pending
Incident response owner: pending
Second maintainer: pending
Escalation path: pending
```

Pending rows above mean an adopter has not yet staffed the operating model.
They do not block publication of the upstream reference exemplar.

## Stable-v3 Scope

This decision covers the v3 signed-attestation candidate gate for the current
Calabi lab topology, with explicit KRA primary, signed envelope and latest
index verification, live policy hash binding, and AAP-recorded evidence.

## Claim Boundary

This packet demonstrates the Calabi reference topology and the signed-evidence
gate behavior recorded above. Broader fleet-scale, portability, signer
isolation, or multi-replica KRA claims require local evidence before adopters
expand the claim.

## Required Follow-Up

- Assign and record adopter governance owners before local operation.
- Confirm exemplar retention and escalation expectations for AAP schedules `6`
  through `9`.
- Run a fleet-scale mixed-state gate before making fleet-scale readiness
  claims.

## Sign-Off

```text
Architecture lead: pending
Project owner: pending
Boundary owner: pending
Security reviewer: pending
```
