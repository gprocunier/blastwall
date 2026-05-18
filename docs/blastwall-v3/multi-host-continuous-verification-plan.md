# Multi-Host and Continuous Verification Plan

## Goal

Define the next gate after this remediation pass: repeated proof in mixed-host and S-range scenarios without blocking the current stable-v3 candidate hardening work.

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

## S-range planning

- Scale gate to 10+ hosts.
- Include all states: current, stale, revoked, rollback, dry-run.
- Include onboarding/decommissioning paths.
- Prove behavior under mixed profile requirements and cross-host drift scenarios.
- Capture failure-class continuity with explicit host-level evidence per case.

## Continuous verification options to implement

- Scheduled AAP runtime verification workflow for managed-host attestation and preflight.
- Scheduled inventory audit pass with marker-vs-verifier drift checks.
- Host-local periodic checks where probe evidence can be regenerated safely.
- Central collection of evidence snapshots and a failure-class rollup view.
- SIEM export or equivalent telemetry for:
  - current↔stale transitions
  - attestation expiry/revocation events

## Evidence required before stable-v3 go decision

- Live positive evidence already on record:
  - Latest Controller-visible Calabi stable-v3 policy pipeline `2645`
    completed successfully on this branch, including post-promotion preflight
    job `2678`.
  - Earlier v3 implementation records also include policy pipeline `2177`,
    runtime verification `2227`, and managed-host verification `2240`.
- Missing evidence to complete:
  - phase 09 negative destructive matrix
  - multi-host candidate gate at 3+ hosts
  - S-range mixed-state gate at 10+ hosts
  - continuous telemetry capture cadence and retention notes

## Decision posture

Until those items complete, the documentation-led decision is `HOLD_LIVE_EVIDENCE`.
