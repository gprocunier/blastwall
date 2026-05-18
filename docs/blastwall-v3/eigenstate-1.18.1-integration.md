# eigenstate.ipa 1.18.1 Integration

## Objective

This document records how Blastwall v3 depends on `eigenstate.ipa 1.18.1` and where that dependency is enforced for stable-v3 attestation flows.

## Dependency floor

- `requirements.yml` pins `eigenstate.ipa: 1.18.1`
- `execution-environment/requirements.yml` pins `eigenstate.ipa: 1.18.1`
- `poc-calabi/requirements.yml` pins `eigenstate.ipa: 1.18.1`

## Runtime contracts used in v3

- Inventory selection consumes normalized IdM companion fields from `eigenstate.ipa.idm` and does not perform host proof in inventory.
- Host preflight reads vault evidence through:
  - `eigenstate.ipa.access_path`
  - `eigenstate.ipa.sudo_risk`
  - `eigenstate.ipa.vault_health`
  - `eigenstate.ipa.vault_artifact`
- Verifier logic evaluates signed envelope/index material, latest-generation replay checks, policy hash binding, host/profile binding, and signer trust.
- Revocation/breakglass behavior follows v3 policy:
  - Infrastructure visibility failures are distinguishable.
  - Host-verification failures remain fail-closed.
- Stable-v3 remains collection-first: raw CLI fallback paths must be explicitly approved and read-back validated before any operational exception.
- The standalone KRA health gate uses `eigenstate.ipa.vault_health`; it is not
  a placeholder around Blastwall vault helper scripts.
- The default preflight path does not run the isolated HBAC operation test.
  Operators can enable that diagnostic with `BLASTWALL_RUN_HBAC_OPERATION_TEST=true`.
- Post-promotion preflight defaults to the profile-derived group, not the
  stale/candidate group used to install and promote a candidate policy.

## What is currently evidenced in-repo

- `tests/policy_static.py` enforces `eigenstate.ipa >= 1.18.1` across all three requirements files listed above.
- The latest Controller-visible healthy Calabi policy pipeline recorded for this
  branch is workflow `2843`, successful, with OpenShift/SPO apply-validation job
  `2857` and post-promotion preflight job `2876`.
- Partial live negative evidence is recorded for drifted policy hash, untrusted
  signer allowlist, and unresolved configured KRA server.
- `V3_IMPLEMENTATION_LEDGER.md` records earlier healthy-path evidence and
  remains historical context for the v3 signed-attestation implementation.

## Open execution items tied to this dependency set

- `docs/blastwall-v3/calabi-negative-evidence.md` must be completed with live destructive negative cases before final stable-v3 release claim.
- `docs/blastwall-v3/multi-host-continuous-verification-plan.md` must define S-range and continuous verification evidence cadence before an external `GO_STABLE_V3_CANDIDATE`.

## Release claim boundary

At present, the repo supports a `HOLD_PARTIAL_LIVE_EVIDENCE` posture for
stable-v3 finalization: dependency alignment, positive execution evidence, SPO
validation, and selected negative cases exist, but the full destructive live
negative matrix is not yet completed in this package.
