# Stable-v3 Release Decision

Date: 2026-05-19
Branch: `blastwall-v3-signed-attestation`
Commit: see current branch head
Decision: HOLD

## Summary

Blastwall v3 source and Calabi lab evidence are ready for external review. The
publication decision remains held because governance owners and sign-off are
not recorded. This is a release-governance hold, not an identified
marker-only, breakglass, or verifier bypass.

The live Controller-visible evidence commit is
`14f7f472f70c1eb66f8ece35b194ed4e2da8b137` as observed at
2026-05-19T19:40Z. The RC evidence source patch adds clearer
failure-state normalization and review documents on top of that branch state.

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

## Evidence Missing

- Named governance owners and sign-off for stable-v3 operation.
- Destructive re-capture for digest mismatch and revoked marker after the
  post-normalization source patch is synced into Controller.
- S-range scale evidence. The current evidence proves the candidate
  mixed-state gate, not broad S-range readiness.

## No-Go Conditions Reviewed

No no-go condition was observed:

- v3 marker alone does not make a host suitable.
- preflight cannot pass without signed evidence in stable-v3.
- live current policy hash remains mandatory.
- artifact and index visibility failures remain distinct from security
  failures.
- breakglass remains infrastructure-only.
- no new SELinux scope, marker grammar, profile, signature algorithm, or trust
  model was added in this gate.

## Governance / Owner Assignment

```text
Boundary owner: pending
Incident response owner: pending
Second maintainer: pending
Escalation path: pending
```

## Stable-v3 Scope

This decision covers the v3 signed-attestation candidate gate for the current
Calabi lab topology, with explicit KRA primary, signed envelope and latest
index verification, live policy hash binding, and AAP-recorded evidence.

## Explicit Non-Goals

- No S-range readiness claim.
- No new SELinux deny scope.
- No new profile or marker grammar.
- No change to the signature algorithm or trust model.
- No implicit KRA replica discovery.

## Required Follow-Up

- Assign and record stable-v3 governance owners.
- Confirm retention and escalation for AAP schedules `6` through `9`.
- Sync the post-normalization commit into Controller and re-capture digest
  mismatch plus revoked-marker destructive cases.
- Run the S-range mixed-state scale gate before claiming S-range readiness.

## Sign-Off

```text
Architecture lead: pending
Project owner: pending
Boundary owner: pending
Security reviewer: pending
```
