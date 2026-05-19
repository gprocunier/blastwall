# Stable-v3 Evidence Index

## Primary Artifacts

- `V3_NEGATIVE_GATE_LEDGER.md`: phase-by-phase execution ledger with job IDs,
  restore proofs, and residual risks.
- `docs/blastwall-v3/calabi-negative-evidence.md`: reviewer-facing destructive
  negative evidence packet.
- `docs/blastwall-v3/multi-host-continuous-verification-plan.md`: remaining
  mixed-state and continuous verification plan.
- `docs/blastwall-v3/stable-v3-release-decision.md`: current release posture.

## Controller Evidence

- Project: `Blastwall`, ID `8`.
- Branch: `blastwall-v3-negative-gate-calabi`.
- Current synced commit: `3ff61e0a8c98439a3d3c238e687306dd2dfaafee`.
- Project update: `3489`.
- Preflight job template: `10`.
- Negative IdM marker harness: `30`, lab-only.
- Negative attestation artifact harness: `31`, lab-only.
- Attestation vault health template: `29`.

## Healthy Path

- Healthy vault job: `3292`, successful.
- Missing canary health job: `3290`, failed as `FAIL_CANARY_MISSING`.
- Fresh signing job: `3305`, generation `1779161194`.
- Fresh promotion job: `3313`, successful.
- Baseline preflight job: `3320`, successful.
- Post-Phase-04 golden preflight: `3471`, successful.
- Post-matrix inventory sync: `3690`, successful.
- Post-matrix golden preflight: `3693`, successful.

## Artifact Visibility

- Missing envelope: mutation `3414`, preflight `3421`, restore `3425`.
- Missing index: mutation `3432`, preflight `3439`, restore `3443`.
- Digest mismatch: mutation `3450`, preflight `3457`, restore `3461`.

## Replay, Expiry, Revocation

- Replayed generation: artifact `3520`, mutation `3524`, preflight `3531`,
  breakglass rejection `3535`, restore `3539`, restore sync `3543`.
- Expired attestation: artifact `3546`, mutation `3550`, preflight `3557`,
  restore `3561`, restore sync `3565`.
- Revoked latest index: artifact `3568`, mutation `3572`, preflight `3579`,
  restore `3583`, restore sync `3587`.
- Revoked marker: artifact `3590`, mutation `3594`, preflight `3601`,
  restore `3605`, restore sync `3609`.

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
- Current golden attestation hash:
  `8d7f4a9844d7bceee2e0114ae55f66aa507e541676aad98ad3667c09701c3b11`.
- Signer KID:
  `8e62ab6d10d1a1a6b4261c4ee3fe79f76545c6d6`.
