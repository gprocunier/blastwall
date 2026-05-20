# Multi-Host and Continuous Verification Plan

## Goal

Define the next gate after the destructive negative pass: repeated proof in
mixed-host and S-range scenarios without overstating the current two-host
Calabi fixture evidence.

## Candidate scope vs S-range scope

- **stable-v3 candidate**: one-to-few host proofs for release-readiness, with explicit positive and negative failure-state checks.
- **S-range gate**: mixed-host confidence check for repeatability across lifecycle transitions, including stale/revoked/recovered states and profile mix.

## Multi-host candidate gate (minimum)

For initial multi-host validation, run at least:

- Host A: current signed stable-v3 marker state
- Host B: stale/unsigned reference-v2 state
- Host C: revoked or broken attestation state

Gate coverage required:

- inventory sync and selection for mixed states
- post-promotion preflight across mixed host set
- runtime verification and probe parity
- policy hash and profile transitions

Current Calabi fixture status:

- Host A: `mirror-registry.workshop.lan`; current signed stable-v3 base marker;
  candidate preflight job `3725` passed and strict inventory audit job `3772`
  reported no attestation failure for this host.
- Host B: `stale-blastwall-01.workshop.lan`; original reference marker only
  after restores; stale-host preflight job `3728` failed closed and inventory
  audit records parser errors for the legacy marker.
- Host C: `missing-artifact-blastwall-01.workshop.lan`; current v3 marker
  points at an absent envelope. Profile-base preflight job `3723` failed
  closed when this host was included, and strict inventory audit job `3772`
  reported `FAIL_ATTESTATION_NOT_VISIBLE` with `vault_error_type=not_found`.

## S-range planning

- Scale gate to 10+ hosts.
- Include all states: current, stale, revoked, rollback, dry-run.
- Include onboarding/decommissioning paths.
- Prove behavior under mixed profile requirements and cross-host drift scenarios.
- Capture failure-class continuity with explicit host-level evidence per case.

## Continuous verification schedule

The first stable-v3 operating loop is installed as AAP schedules on the
`blastwall-v3-signed-attestation` branch:

- Schedule `6`: `Blastwall stable-v3 KRA health hourly`.
- Schedule `7`: `Blastwall stable-v3 inventory audit hourly`.
- Schedule `8`: `Blastwall stable-v3 candidate preflight daily`.
- Schedule `9`: `Blastwall stable-v3 runtime verification daily`.

The schedule payloads retain machine-readable evidence including group counts,
stale/current membership, KRA health, canary state, attestation visibility,
current-to-stale movement, and failure state fields.

Initial exercised checks:

- KRA health job `3731` passed with canary present.
- Candidate preflight job `3735` passed.
- Runtime verification workflow `3736` passed.
- Strict inventory audit job `3772` verified the valid host and failed closed
  on the missing-artifact fixture with `FAIL_ATTESTATION_NOT_VISIBLE`.
- Scheduled runs `3776`, `3797`, and `3802` kept KRA health green.
- Scheduled candidate preflight `3780` and scheduled runtime workflow `3781`
  passed.
- Scheduled inventory audit `3778`, `3799`, and `3804` failed closed on the
  intentional missing-artifact fixture while keeping the valid host clean.

The destructive negative harnesses remain unscheduled and lab-only:

- `Blastwall negative gate attestation artifact harness`.
- `Blastwall negative gate IdM marker harness`.

Run them as explicit destructive rehearsals on fixture hosts before release
candidates, not as continuous production schedules.

Continue centralizing evidence snapshots with:

- AAP workflow/job IDs,
- `failure_state`,
- `vault_error_type`,
- selected/current/stale hosts,
- attestation refs and digests.

## Evidence required before stable-v3 go decision

- Live positive evidence already on record:
  - Latest Controller-visible Calabi stable-v3 policy pipeline `2843`
    completed successfully on this branch, including post-promotion preflight
    job `2876`.
  - Current negative-gate branch post-matrix golden preflight `3693`
    completed successfully after destructive restores.
  - Earlier v3 implementation records also include policy pipeline `2177`,
    runtime verification `2227`, and managed-host verification `2240`.
- Live candidate evidence now on record:
  - Three-host inventory sync `3712` selected current valid, stale legacy, and
    broken-current marker states.
  - Candidate preflight `3725`, stale preflight `3728`, profile-base preflight
    `3723`, and strict inventory audit `3772` proved the expected split.
  - Continuous schedules `6` through `9` are installed and initial runs are
    recorded.
  - Corrected transition-v3 lab/RC shared-custody path passed policy pipeline
    workflow `4046`, standalone signed preflight `4082`, and runtime workflow
    `4102`; strict audit `4098` failed closed on the intentional
    missing-artifact fixture.
  - Digest mismatch and revoked-marker recaptures failed closed as
    `FAIL_ATTESTATION_INTEGRITY` in job `4233` and
    `FAIL_REVOKED_ATTESTATION` in job `4255`.
- Missing evidence to complete broader claims:
  - S-range mixed-state gate at 10+ hosts
  - live-green stable-v3 service-owned or named-user custody health
  - named owners, retention, and escalation paths for the schedule
  - longer 24-hour or 72-hour soak window after ownership is assigned

## Decision posture

Until those items complete, the documentation-led decision is
`HOLD for stable-v3 publication pending governance owner assignment, custody
health, and sign-off.`
