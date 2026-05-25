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
- Current synced commit observed at 2026-05-25 UTC:
  `93fab21cd548c4ff7ca2d2addb21ecc1ad5c2cc3`, project update `4871`.
- Previous normalized failure-state capture commit observed at 2026-05-20 UTC:
  `f50c1228ddcf4544a38634f05fd87179210c6917`, project update `4221`.
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
- Stable-v3 shared-custody guard: `3918`, failed closed with
  `stable-v3 rejects shared vault scope`.
- Stable-v3 service-custody guard after remediation: KRA health `4872`
  passed with canary present; shared-custody rejection `4876` failed closed.
- Stable-v3 service-custody policy pipeline: workflow `4922`, successful,
  including build `4927`, install `4932`, managed-host verification `4936`,
  sign `4940`, promotion `4944`, and post-promotion preflight `4951`.
- Stable-v3 service-custody runtime verification: workflow `4968`,
  successful, including preflight `4977` and managed-host verification `4981`.
- Transition-v3 lab/RC shared-custody health: `3922`, successful.
- Corrected transition-v3 lab/RC policy pipeline: workflow `4046`, successful,
  including sign `4064`, promotion `4068`, and post-promotion preflight `4075`.
- Standalone signed transition-v3 preflight: `4082`, successful.
- Runtime verification retry after a transient Controller project timeout:
  workflow `4102`, successful.
- Strict inventory audit after transition-v3 correction: `4098`, failed closed
  on the intentional missing-artifact fixture after verifying the valid host.

## KRA Health

- Positive health: `3698`, successful.
- Missing canary: `3701`, failed as `FAIL_CANARY_MISSING`.
- Bad configured KRA primary/server: `3702`, failed closed on
  `missing-kra.workshop.lan`.
- Canary health after schedules: `3731`, `3776`, `3797`, and `3802`,
  successful with canary present.
- Earlier stable-v3 non-shared custody probes: `3914`, `3987`, and `3991`,
  failed in the live vault-health path before the AAP argument-shape
  remediation. They are superseded by service-custody KRA health `4872`.

## Artifact Visibility

- Missing envelope: mutation `3414`, preflight `3421`, restore `3425`.
- Missing index: mutation `3432`, preflight `3439`, restore `3443`.
- Digest mismatch historical: mutation `3450`, preflight `3457`, restore
  `3461`; failed closed before source normalization.
- Digest mismatch final recapture: artifact `4222`, mutation `4226`, inventory
  `4230`, preflight `4233` failed as `FAIL_ATTESTATION_INTEGRITY`, restore
  `4237`, restore inventory `4241`.

## Replay, Expiry, Revocation

- Replayed generation: artifact `3520`, mutation `3524`, preflight `3531`,
  breakglass rejection `3535`, restore `3539`, restore sync `3543`.
- Expired attestation: artifact `3546`, mutation `3550`, preflight `3557`,
  restore `3561`, restore sync `3565`.
- Revoked latest index: artifact `3568`, mutation `3572`, preflight `3579`,
  restore `3583`, restore sync `3587`.
- Revoked marker historical: artifact `3590`, mutation `3594`, preflight
  `3601`, restore `3605`, restore sync `3609`; failed closed before source
  normalization.
- Revoked marker final recapture: artifact `4244`, mutation `4248`, inventory
  `4252`, preflight `4255` failed as `FAIL_REVOKED_ATTESTATION`, restore
  `4259`, restore inventory `4263`, final safety restore `4266`, final
  inventory `4270`.

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
- Service-custody attestation audit `4989`: verified
  `mirror-registry.workshop.lan` through service custody and failed closed on
  the intentional `missing-artifact-blastwall-01.workshop.lan` fixture with
  `marker has expired`.

## Continuous Verification

- Schedule `6`: `Blastwall stable-v3 KRA health hourly`, enabled.
- Schedule `7`: `Blastwall stable-v3 inventory audit hourly`, enabled.
- Schedule `8`: `Blastwall stable-v3 candidate preflight daily`, enabled.
- Schedule `9`: `Blastwall stable-v3 runtime verification daily`, enabled.
- Exercised checks: `3731`, `3735`, `3736`, `3772`, `3776`, `3778`,
  `3780`, `3781`, `3797`, `3799`, `3802`, `3804`, plus the 2026-05-25
  service-custody refresh `4872`, `4876`, `4918`, `4922`, `4968`, and `4989`.

## Current Artifact Bindings

- Policy NEVRA: `blastwall-selinux-0.6.1-0.rc1`.
- Policy hash:
  `4b3e1d30e364331d408d8531d871ffcce23805a89b4cf44bd2977854be35bfc2`.
- Registry hash:
  `c8a533efc7ce60604d2a770964eea582005dde49ac2b882eea38c9701d612486`.
- Probe report hash:
  `16dc41143e934a4a1cad5c138867a8dfe0e9dec8fa12ff7dda6456302a190625`.
- Current golden attestation ref:
  `service/blastwall-attestation/blastwall-attestations/mirror-registry.workshop.lan/base/1779671333.json`.
- Custody note: current Calabi stable-v3 evidence uses service-owned vault
  custody. Stable-v3 rejects shared vault scope; transition-v3 may still use
  explicitly labelled lab/RC shared custody.
- Current golden attestation hash:
  `91fe290862f5b23e32a26a747fa56f03d1e8dcdd8103c96a773ca9a160b31604`.
- Signer KID:
  `8e62ab6d10d1a1a6b4261c4ee3fe79f76545c6d6`.
- Generation: `1779671333`.
