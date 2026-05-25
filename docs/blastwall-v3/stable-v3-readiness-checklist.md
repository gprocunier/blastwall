# Stable-v3 Readiness Checklist

Use this checklist before claiming stable-v3.

Read `docs/blastwall-v3/operational-guidance.md` before using this checklist.
It defines the stable-v3 operating boundary, custody expectations, destructive
re-capture triggers, and Calabi reference-topology limits.

## Governance

- Boundary owner named and reachable.
- Incident response owner named and reachable.
- Second maintainer-developer can reproduce verifier and inventory diagnostics.
- Signer owner named.
- KRA/vault owner named.
- Revocation authority named.
- Breakglass approval path named and tested.
- Governance assignment is recorded in
  `docs/blastwall-v3/governance-owner-assignment.md`.

## Configuration and ownership

- `eigenstate.ipa` `1.18.1` or newer is installed in the AAP execution
  environment and bastion validation path.
- `BLASTWALL_ATTESTATION_MODE` = `stable-v3` is explicitly set.
- Primary KRA server configured and documented.
- Explicit vault owner and non-shared scope are configured for the
  service-owned or named-user path.
- AAP signer-job custody credential has KRA vault write/read authority for the
  selected scope. Shared-vault custody is lab/RC evidence only and is rejected
  for stable-v3.
- Signer certificate allowlist is populated.
- CA trust bundle is current and committed to environment.
- Marker policy includes:
  - `v=3`,
  - `state` in `active` or `lab-active` only for selection,
  - `attest_ref`,
  - `attest_sha256`,
  - `signer_kid`,
  - `generation`,
  - `exp`.

## Verification behavior checks

- Inventory exposes `idm_userclass`, `idm_userclass_raw`,
  `idm_userclass_type`, and `idm_schema_warnings`; marker-bearing hosts with
  schema warnings are not silently accepted.
- `eigenstate.ipa.access_path` reports principal, HBAC, sudo, and SELinux map
  readiness before host launch.
- `eigenstate.ipa.sudo_risk` reports no unapproved high or unknown risk.
- `eigenstate.ipa.vault_health` reports `failure_class=none` before any
  stable-v3 artifact read.
- `eigenstate.ipa.vault_artifact` verifies envelope and latest-index custody
  digests.
- Marker parse accepts v3 only where expected.
- v3 marker is treated as locator; signature is the proof.
- Stable-v3 requires successful envelope fetch and signature verification.
- Stable-v3 requires signed latest-generation index check.
- Stable-v3 requires live policy hash verification.
- Stable-v3 rejects expired, revoked, tampered, replayed, and binding-mismatched attestations.
- Infrastructure and host failures are not merged into one class.
- Breakglass is rejected for host-verification failures.

## Failure-state checks

The canonical expected-state contract is
`docs/blastwall-v3/failure-state-manifest.yml`.

- Missing attestation fetch: observed as `FAIL_ATTESTATION_NOT_VISIBLE`.
- Missing latest index: observed as `FAIL_INDEX_NOT_VISIBLE`.
- Digest disagreement: observed live as `FAIL_ATTESTATION_INTEGRITY` in final
  recapture job `4233`; historical Calabi job `3457` failed closed before the
  normalized source state was Controller-visible.
- Revoked marker or latest index: revoked-index job `3579` and final
  revoked-marker recapture job `4255` failed as `FAIL_REVOKED_ATTESTATION`;
  historical revoked-marker job `3601` failed closed before the normalized
  source state was Controller-visible.
- KRA unavailable during audit: observed as `FAIL_KRA_UNAVAILABLE` with
  `vault_error_type` details.
- Signature failure: security fail, not recoverable via breakglass.
- Marker tamper mismatch: security fail, not recoverable via breakglass.
- Host drift: security fail, not recoverable via breakglass.

## Stable-v3 vs transition-v3

- `reference-v2`: v2 marker acceptance remains a reference-only behavior.
- `transition-v3`: v2 and v3 markers may both appear; v3 verification is preferred; strict checks may be warning-based.
- `stable-v3`: v3 marker + signed evidence required; rollback and bypass modes disabled; marker-only path is not accepted.
- `breakglass`: infra-only exception mode with short time window and audit.

## Run acceptance evidence

Minimum evidence package for sign-off:

- KRA health summary.
- A successful valid v3 preflight example.
- A failed infrastructure example (visible distinction).
- A failed signature/binding example (no breakglass pass).
- A revocation example and re-attestation recovery example.
- Calabi v3 KRA gate evidence bundle, including AAP job IDs and artifact references.

Current Calabi RC evidence:

- Healthy-path Calabi v3 KRA/AAP/SPO gate completed on 2026-05-18 UTC.
- Latest pre-mortem remediation evidence completed on 2026-05-20 UTC after
  Controller project sync `4221` to
  `f50c1228ddcf4544a38634f05fd87179210c6917`.
- Stable-v3 shared-custody guard job `3918` failed closed with
  `stable-v3 rejects shared vault scope`. Earlier non-shared custody probes
  `3914`, `3987`, and `3991` failed before the non-shared argument
  remediation and are superseded by service-owned KRA health job `4872`,
  which passed with the canary present.
- Stable-v3 service-custody refresh on 2026-05-25 used Controller project
  sync `4871` to commit `93fab21cd548c4ff7ca2d2addb21ecc1ad5c2cc3`.
  Shared-custody rejection `4876` failed closed. Policy pipeline workflow
  `4922`, candidate preflight `4918`, runtime workflow `4968`, and
  schedule-equivalent inventory audit `4989` exercised the service-owned path.
- Transition-v3 lab/RC shared-custody health job `3922` passed. Corrected
  transition-v3 lab/RC policy pipeline workflow `4046`, standalone signed
  preflight job `4082`, and runtime workflow `4102` passed. Strict inventory
  audit job `4098` failed closed on the intentional missing-artifact fixture.
- Final destructive recapture after source normalization: digest mismatch
  preflight job `4233` failed as `FAIL_ATTESTATION_INTEGRITY`; revoked-marker
  preflight job `4255` failed as `FAIL_REVOKED_ATTESTATION`. Restore jobs and
  inventory updates `4237`, `4241`, `4259`, `4263`, `4266`, and `4270`
  returned the fixture host to its original reference marker.
- Earlier target-branch continuous-evidence check completed on 2026-05-19 UTC
  at `9e9e5e8ac555a4492ca9580e6c513b6763bdbe8b`.
- Latest Controller-visible stable-v3 policy pipeline workflow `2843` passed,
  including OpenShift/SPO apply-validation job `2857`, managed-host
  verification job `2861`, sign-attestation job `2865`, marker-promotion job
  `2869`, and post-promotion preflight job `2876`.
- Standalone stable-v3 preflight job `2839` passed after the configured-KRA
  fail-closed guard was added.
- Earlier policy pipeline workflow `2177` passed.
- Earlier runtime verification workflow `2227` passed.
- Runtime preflight job `2839` retrieved marker-referenced KRA artifacts and
  verified the signed envelope plus latest index.
- Managed-host verification job `2861` passed with evidence digest
  `16dc41143e934a4a1cad5c138867a8dfe0e9dec8fa12ff7dda6456302a190625`.
- Live negative preflight jobs captured policy drift (`2827`,
  `FAIL_DRIFTED_POLICY`), untrusted signer (`2830`, `FAIL_SIGNER_UNTRUSTED`),
  and unresolved configured KRA server (`2835`, fail-closed DNS resolution).
- Current negative-gate branch evidence also covers missing envelope (`3421`),
  missing index (`3439`), digest mismatch (`3457`), signature tamper (`3505`),
  replay (`3531`), expiry (`3557`), revoked latest index (`3579`), profile
  mismatch (`3623`), host binding mismatch (`3649`), scoped breakglass
  allowance (`3667`), and breakglass rejection for policy drift (`3682`),
  untrusted signer (`3686`), signature tamper (`3509`), replay (`3535`), and
  profile mismatch (`3627`).
- Post-matrix inventory sync `3690` restored `mirror-registry.workshop.lan` to
  the active v3 marker and `stale-blastwall-01.workshop.lan` to its original
  stale fixture marker; golden preflight job `3693` passed on the current
  branch commit.
- Three-host mixed-state gate is complete for the candidate scope:
  inventory sync `3712` selected current valid, stale legacy, and
  current-broken-attestation hosts; candidate preflight `3725` passed the valid
  host; stale preflight `3728` failed closed; profile-group preflight `3723`
  failed closed when the broken fixture was included.
- Continuous verification schedules are installed in AAP: `6` hourly KRA
  health, `7` hourly inventory audit, `8` daily candidate preflight, and `9`
  daily runtime verification. KRA health `3731`, candidate preflight `3735`,
  and runtime workflow `3736` passed.
- Scheduled runs after installation also fired: KRA health `3776`, `3797`,
  and `3802` passed; candidate preflight `3780` passed; runtime workflow
  `3781` passed; inventory audit `3778`, `3799`, and `3804` failed closed on
  the intentional missing-artifact fixture.
- Strict inventory audit job `3772` authenticated to FreeIPA, verified the
  valid mirror host, and failed closed on the broken current marker with
  `FAIL_ATTESTATION_NOT_VISIBLE` and `vault_error_type=not_found`.
- Remaining publication hold: governance owners and sign-off must be assigned.
  The S-range claim remains held pending broader scale evidence.

## Go/No-Go

- GO only if all checklist items above are complete, evidence artifacts are
  attached, and governance owners are named.
- No-Go if any owner is missing, any infra-only exception is undocumented, or any security failure class is bypassed.
