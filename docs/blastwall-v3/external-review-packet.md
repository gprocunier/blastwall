# External Review Packet: Blastwall v3 Signed Attestation

## Working Scope

This packet is the review-facing summary for v3 signed attestation controls on Blastwall.
It is focused on trust and failure behavior in host selection, attestation retrieval,
signature verification, and KRA assumptions.

## Executive summary

v3 changes host trust from marker-claimed state to verified signed evidence.

- Host marker is still required for selection.
- Signature is the trust proof.
- Preflight verifies marker binding, signer trust, index freshness, and live host state in stable-v3.
- KRA-backed IdM vault paths are treated as part of the trust dependency graph.
- This branch requires `eigenstate.ipa >= 1.18.1` for normalized inventory,
  `access_path`, `sudo_risk`, `vault_health`, and `vault_artifact`.

## Quick reviewer checklist

- Can a marker be trusted without signed proof? No.
- Can preflight fail closed on host-state mismatch? Yes.
- Can the same host present different results across inventory and preflight? Yes, and preflight wins.
- Can KRA visibility failures be distinguished from host verification failures? Yes, with named failure states.
- Can breakglass bypass signature/drift/revocation failures? No.

## Trust boundary disclosure

Initial signer deployment may colocate signer and AAP workflow execution.
This improves operability but does not protect against a fully compromised AAP controller.

For high-assurance usage, operators should evaluate stronger signer isolation before claiming final stable posture.

## Evidence map

Reference documents:

- `docs/blastwall-v3/signed-attestation-design.md`
- `docs/blastwall-v3/operational-guidance.md`
- `docs/blastwall-v3/stable-v3-readiness-checklist.md`
- `docs/blastwall-v3/operator-runbook.md`
- `docs/blastwall-v3/kra-topology-runbook.md`
- `docs/blastwall-v3/revocation-and-breakglass.md`
- `docs/blastwall-v3/evidence-consistency-matrix.md`
- `docs/blastwall-v3/failure-state-manifest.yml`
- `docs/blastwall-v3/scheduled-loop-soak.md`
- `docs/blastwall-v3/stable-v3-rc-decision.md`
- `docs/blastwall-v3/governance-owner-assignment.md`
- `V3_IMPLEMENTATION_LEDGER.md`
- `tools/blastwall_attestation_verify.py`
- `tools/blastwall_attestation_sign.py`
- `tools/audit_blastwall_inventory.py`

## Calabi evidence

Latest target-branch evidence was captured on 2026-05-20 UTC on
`blastwall-v3-signed-attestation`. The AAP project was synced to
`f50c1228ddcf4544a38634f05fd87179210c6917` by project update `4221`.

Calabi is the current reference topology evidence path. It proves this
workstation to `virt-01` to bastion to IdM/AAP/KRA path; it does not prove
broad portability across arbitrary RHEL, OpenShift, IdM, AAP, or KRA
generations.

- `Calabi path`: workstation to `virt-01` (`172.18.0.224`) to bastion
  (`172.16.0.30`).
- `AAP project branch`: `blastwall-v3-signed-attestation`.
- `KRA primary`: `idm-01.workshop.lan`.
- `KRA server list`: `idm-01.workshop.lan`.
- `KRA scope/owner`: `shared` / `blastwall-attestation` for Calabi lab/RC
  custody. Stable-v3 rejects shared vault scope.
- `Signer KID`: `8e62ab6d10d1a1a6b4261c4ee3fe79f76545c6d6`.
- `Policy NEVRA`: `blastwall-selinux-0.6.1-0.rc1`.
- `Policy hash`:
  `4b3e1d30e364331d408d8531d871ffcce23805a89b4cf44bd2977854be35bfc2`.
- `Registry hash`:
  `c8a533efc7ce60604d2a770964eea582005dde49ac2b882eea38c9701d612486`.
- `Current golden attestation ref`:
  `shared/blastwall-attestation/blastwall-attestations/mirror-registry.workshop.lan/base/1779161194.json`.
- `Current golden attestation hash`:
  `8d7f4a9844d7bceee2e0114ae55f66aa507e541676aad98ad3667c09701c3b11`.

Healthy-path evidence remains on record:

- Policy pipeline workflow `2843`, OpenShift/SPO apply-validation job `2857`,
  managed-host verification job `2861`, sign-attestation job `2865`,
  marker-promotion job `2869`, and post-promotion preflight job `2876`
  completed successfully on the signed-attestation branch.
- Earlier policy pipeline workflow `2177` and runtime verification workflow
  `2227` completed successfully.
- Managed-host evidence digest
  `16dc41143e934a4a1cad5c138867a8dfe0e9dec8fa12ff7dda6456302a190625`
  confirmed the deny probes still block AF_ALG, BPF map/prog load, AF_PACKET,
  user namespace, `io_uring_setup`, Dirty Frag `NETLINK_XFRM`, Dirty Frag
  `AF_RXRPC`, and Fragnesia `AF_ALG` entry points with `EPERM`/`EACCES`
  evidence.

Live negative checks currently recorded:

- Drifted current policy hash: AAP preflight jobs `2827` and `3478` failed
  with `FAIL_DRIFTED_POLICY`.
- Bad signer allowlist: AAP preflight jobs `2830` and `3485` failed with
  `FAIL_SIGNER_UNTRUSTED`.
- Bad configured KRA primary/server: AAP preflight job `2835` failed closed at
  configured KRA resolution for `missing-kra.workshop.lan`.
- KRA health: job `3698` passed, missing-canary job `3701` failed
  `FAIL_CANARY_MISSING`, and bad-primary job `3702` failed closed.
- Stable-v3 shared-custody guard: job `3918` failed closed with
  `stable-v3 rejects shared vault scope`.
- Earlier stable-v3 non-shared custody probes `3914`, `3987`, and `3991`
  failed before the non-shared argument remediation. They are superseded by
  service-owned KRA health `4872`, shared rejection `4876`, policy pipeline
  `4922`, runtime workflow `4968`, and inventory audit `4989`.
- Transition-v3 lab/RC shared-custody path: health job `3922`, policy pipeline
  workflow `4046`, standalone signed preflight `4082`, and runtime workflow
  `4102` passed. Strict audit `4098` failed closed on the intentional
  missing-artifact fixture.
- Destructive artifact visibility: `3421` missing envelope and `3439` missing
  index failed closed. Final digest mismatch recapture used artifact `4222`,
  mutation `4226`, inventory `4230`, and preflight `4233`, which failed as
  `FAIL_ATTESTATION_INTEGRITY`; restore `4237` and inventory `4241` succeeded.
- Destructive security failures: `3505` signature tamper, `3531` replay,
  `3557` expiry, `3579` revoked latest index, `3623` profile mismatch, and
  `3649` host binding mismatch failed closed.
- Revoked marker handling now maps to the `FAIL_REVOKED_ATTESTATION` family.
  Historical live job `3601` was already fail-closed. Final revoked-marker
  recapture used artifact `4244`, mutation `4248`, inventory `4252`, and
  preflight `4255`, which failed as `FAIL_REVOKED_ATTESTATION`; restore
  `4259`, inventory `4263`, final safety restore `4266`, and final inventory
  `4270` succeeded.
- Breakglass: `3667` passed only for scoped missing-envelope infrastructure
  visibility; `3509`, `3535`, `3627`, `3682`, and `3686` rejected security
  failures.
- Restore proof: inventory sync `3690` showed the current mirror marker and
  stale fixture marker restored; golden preflight `3693` passed afterward.

Mixed-state and continuous verification evidence are now installed and
exercised:

- Inventory sync `3712` showed three controlled states: current valid
  `mirror-registry.workshop.lan`, stale legacy `stale-blastwall-01.workshop.lan`,
  and current-but-broken `missing-artifact-blastwall-01.workshop.lan`.
- Candidate preflight job `3725` passed the valid host.
- Stale preflight job `3728` failed closed on the stale fixture.
- Profile-base preflight job `3723` failed closed because the broken fixture
  was intentionally included in that group.
- AAP schedules `6` through `9` install hourly KRA health, hourly inventory
  audit, daily candidate preflight, and daily runtime verification.
- KRA health job `3731` passed with canary present.
- Candidate preflight job `3735` passed and runtime workflow `3736` passed.
- Strict inventory audit job `3772` authenticated to FreeIPA, verified the
  valid mirror host, and failed closed on
  `missing-artifact-blastwall-01.workshop.lan` with
  `FAIL_ATTESTATION_NOT_VISIBLE` and `vault_error_type=not_found`.
- Scheduled loop checks fired at `17:00Z`, `18:00Z`, and `19:00Z` on
  2026-05-19. KRA health jobs `3776`, `3797`, and `3802` passed; candidate
  preflight `3780` passed; runtime workflow `3781` passed; inventory audit
  jobs `3778`, `3799`, and `3804` failed closed on the intentional
  missing-artifact fixture while the valid host remained clean.

Remaining hold: source and lab evidence are ready for external review, but
stable-v3 publication still needs named governance owners and sign-off. The
S-range claim remains held until broader scale evidence is captured.

## Failure-state map

- `FAIL_KRA_UNAVAILABLE`: audit-side KRA or vault infrastructure outage.
- `FAIL_ATTESTATION_NOT_VISIBLE`: signed artifact visible in marker but not in configured KRA path.
- `FAIL_INDEX_NOT_VISIBLE`: index not visible or not current in configured path.
- `FAIL_ATTESTATION_INTEGRITY`: marker, latest index, or envelope digest disagreement.
- `FAIL_SIGNER_UNTRUSTED`: signer certificate or allowlist failure.
- `FAIL_SIGNATURE_INVALID`, `FAIL_BINDING_MISMATCH`, `FAIL_DRIFTED_POLICY`, `FAIL_REVOKED_ATTESTATION`: host/security failures.

## Open risks

- AAP/signer co-location remains a governance decision, not a cryptographic replacement for AAP compromise.
- Cross-replica KRA behavior must remain explicit; implicit replica discovery is disallowed in stable-v3.

## Reviewer acceptance criteria

- Confirm marker-vs-proof split is explicit in operator and preflight behavior.
- Confirm latest-generation replay protection and live host check in stable-v3.
- Confirm breakglass cannot bypass host trust failures.
- Confirm evidence package includes both healthy and failed cases, including KRA and security failure classes.
- Confirm ownership and escalation paths are named and staffed.
