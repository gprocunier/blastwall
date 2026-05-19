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
  post-matrix preflight job `3693` passed after inventory sync `3690`.
- Host B: `stale-blastwall-01.workshop.lan`; original reference marker only
  after restores; used for destructive mutation and restored after each case.
- Host C: pending. The current inventory has no third fixture host, so the
  required three-host mixed-state gate is not complete.

## S-range planning

- Scale gate to 10+ hosts.
- Include all states: current, stale, revoked, rollback, dry-run.
- Include onboarding/decommissioning paths.
- Prove behavior under mixed profile requirements and cross-host drift scenarios.
- Capture failure-class continuity with explicit host-level evidence per case.

## Continuous verification options to implement

- Schedule `Blastwall attestation vault health` hourly against
  `idm-01.workshop.lan` with a configured canary when governance assigns an
  owner.
- Schedule `Blastwall preflight` daily for `blastwall_profile_base` and alert on
  any non-`PASS` verifier report.
- Schedule `Blastwall runtime verification` daily or per-change for managed
  hosts where probe regeneration is safe.
- Schedule `audit-inventory-membership.yml` or the Controller inventory source
  sync plus marker audit daily, retaining group counts and parse warnings.
- Keep `Blastwall negative gate attestation artifact harness` and
  `Blastwall negative gate IdM marker harness` unscheduled and lab-only; run
  them as an explicit destructive rehearsal on fixture hosts before release
  candidates.
- Centralize evidence snapshots with:
  - AAP workflow/job IDs,
  - `failure_state`,
  - `vault_error_type`,
  - `selected_hosts`,
  - `stale_hosts`,
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
- Missing evidence to complete:
  - multi-host candidate gate at 3+ hosts
  - S-range mixed-state gate at 10+ hosts
  - governance-approved continuous telemetry cadence and retention notes

## Decision posture

Until those items complete, the documentation-led decision is
`HOLD for stable-v3 publication pending evidence.`
