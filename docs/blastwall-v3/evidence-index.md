# Stable-v3 Evidence Index

## Primary Artifacts

- `V3_STABLE_EVIDENCE_GATE_LEDGER.md`: current execution ledger for the
  stable-evidence gate.
- `V3_NEGATIVE_GATE_LEDGER.md`: destructive negative gate execution ledger with
  job IDs, restore proofs, and residual risks.
- `docs/blastwall-v3/calabi-negative-evidence.md`: reviewer-facing destructive
  and mixed-state evidence packet.
- `docs/blastwall-v3/multi-host-continuous-verification-plan.md`: mixed-state
  and continuous verification operating plan.
- `docs/blastwall-v3/stable-v3-release-decision.md`: current release posture.
- `docs/blastwall-v3/stable-v3-rc-decision.md`: RC-level GO/HOLD decision.
- `docs/blastwall-v3/operational-guidance.md`: stable-v3 operating boundary,
  custody expectations, breakglass audit rules, and claim limits.
- `docs/blastwall-v3/failure-state-manifest.yml`: machine-readable expected
  failure-state contract.
- `docs/blastwall-v3/evidence-consistency-matrix.md`: live/source
  failure-state reconciliation.
- `docs/blastwall-v3/scheduled-loop-soak.md`: scheduled-loop evidence.
- `docs/blastwall-v3/governance-owner-assignment.md`: required owner
  assignment surface.

## Controller Evidence

- Project: `Blastwall`, ID `8`.
- Branch: `blastwall-v3-signed-attestation`.
- Boundary: Calabi evidence is reference-topology evidence, not broad
  portability proof.
- Current synced commit observed at 2026-05-19T19:40Z:
  `14f7f472f70c1eb66f8ece35b194ed4e2da8b137`.
- Earlier three-host evidence project update: `3771` to
  `9e9e5e8ac555a4492ca9580e6c513b6763bdbe8b`.
- Inventory source: `9`.
- Preflight job template: `10`.
- Runtime verification workflow template: `15`.
- Policy pipeline workflow template: `19`.
- Attestation vault health template: `29`.
- Negative IdM marker harness: `30`, lab-only.
- Negative attestation artifact harness: `31`, lab-only.
- Inventory membership audit template: `32`.

## Healthy Path

- Healthy vault job: `3292`, successful.
- Missing canary health job: `3290`, failed as `FAIL_CANARY_MISSING`.
- Fresh signing job: `3305`, generation `1779161194`.
- Fresh promotion job: `3313`, successful.
- Baseline preflight job: `3320`, successful.
- Post-Phase-04 golden preflight: `3471`, successful.
- Post-matrix inventory sync: `3690`, successful.
- Post-matrix golden preflight: `3693`, successful.
- Later target-branch KRA health job: `3731`, successful.
- Later target-branch candidate preflight job: `3735`, successful.
- Later target-branch runtime workflow: `3736`, successful.
- Scheduled candidate preflight job: `3780`, successful.
- Scheduled runtime workflow: `3781`, successful.

## KRA Health

- Positive health: `3698`, successful.
- Missing canary: `3701`, failed as `FAIL_CANARY_MISSING`.
- Bad configured KRA primary/server: `3702`, failed closed on
  `missing-kra.workshop.lan`.
- Canary health after schedules: `3731`, `3776`, `3797`, and `3802`,
  successful with canary present.

## Artifact Visibility

- Missing envelope: mutation `3414`, preflight `3421`, restore `3425`.
- Missing index: mutation `3432`, preflight `3439`, restore `3443`.
- Digest mismatch: mutation `3450`, preflight `3457`, restore `3461`.
  Source now normalizes this verifier path to `FAIL_ATTESTATION_INTEGRITY`;
  re-capture is pending after Controller sync to the post-normalization commit.

## Replay, Expiry, Revocation

- Replayed generation: artifact `3520`, mutation `3524`, preflight `3531`,
  breakglass rejection `3535`, restore `3539`, restore sync `3543`.
- Expired attestation: artifact `3546`, mutation `3550`, preflight `3557`,
  restore `3561`, restore sync `3565`.
- Revoked latest index: artifact `3568`, mutation `3572`, preflight `3579`,
  restore `3583`, restore sync `3587`.
- Revoked marker: artifact `3590`, mutation `3594`, preflight `3601`,
  restore `3605`, restore sync `3609`.
  Source now normalizes this locator path to `FAIL_REVOKED_ATTESTATION`;
  re-capture is pending after Controller sync to the post-normalization commit.

## Crypto, Binding, and Drift

- Policy drift: preflight `3478`; breakglass rejection `3682`.
- Signer untrusted: preflight `3485`; breakglass rejection `3686`.
- Signature tamper: artifact `3494`, mutation `3498`, preflight `3505`,
  breakglass rejection `3509`, restore `3513`, restore sync `3517`.
- Profile mismatch: artifact `3612`, mutation `3616`, preflight `3623`,
  breakglass rejection `3627`, restore `3631`, restore sync `3635`.
- Host binding mismatch: artifact `3638`, mutation `3642`, preflight `3649`,
  restore `3653`, restore sync `3657`.

## Breakglass

- Missing-envelope allowed bypass: mutation `3660`, preflight `3667`, restore
  `3671`, restore sync `3675`.
- Security-failure rejections: `3509`, `3535`, `3627`, `3682`, `3686`.

## Mixed-State Gate

- Inventory sync `3712`: selected current valid, stale legacy, and
  current-broken-attestation hosts.
- Profile-base preflight `3723`: failed closed because the broken current
  marker host was included in the selected group.
- Candidate preflight `3725`: passed for `mirror-registry.workshop.lan`.
- Stale-host preflight `3728`: failed closed for
  `stale-blastwall-01.workshop.lan`.
- Strict inventory audit `3772`: verified the valid host and failed closed for
  `missing-artifact-blastwall-01.workshop.lan` with
  `FAIL_ATTESTATION_NOT_VISIBLE`, `vault_error_type=not_found`.

## Continuous Verification

- Schedule `6`: `Blastwall stable-v3 KRA health hourly`, enabled.
- Schedule `7`: `Blastwall stable-v3 inventory audit hourly`, enabled.
- Schedule `8`: `Blastwall stable-v3 candidate preflight daily`, enabled.
- Schedule `9`: `Blastwall stable-v3 runtime verification daily`, enabled.
- Exercised checks: `3731`, `3735`, `3736`, `3772`, `3776`, `3778`,
  `3780`, `3781`, `3797`, `3799`, `3802`, `3804`.

## Current Artifact Bindings

- Policy NEVRA: `blastwall-selinux-0.6.1-0.rc1`.
- Policy hash:
  `4b3e1d30e364331d408d8531d871ffcce23805a89b4cf44bd2977854be35bfc2`.
- Registry hash:
  `c8a533efc7ce60604d2a770964eea582005dde49ac2b882eea38c9701d612486`.
- Probe report hash:
  `16dc41143e934a4a1cad5c138867a8dfe0e9dec8fa12ff7dda6456302a190625`.
- Current golden attestation ref:
  `shared/blastwall-attestation/blastwall-attestations/mirror-registry.workshop.lan/base/1779161194.json`.
- Custody note: current Calabi golden evidence used shared lab/RC vault
  custody. Stable-v3 rejects shared vault scope.
- Current golden attestation hash:
  `8d7f4a9844d7bceee2e0114ae55f66aa507e541676aad98ad3667c09701c3b11`.
- Signer KID:
  `8e62ab6d10d1a1a6b4261c4ee3fe79f76545c6d6`.
