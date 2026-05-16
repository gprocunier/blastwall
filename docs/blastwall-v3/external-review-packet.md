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
- `docs/blastwall-v3/stable-v3-readiness-checklist.md`
- `docs/blastwall-v3/operator-runbook.md`
- `docs/blastwall-v3/kra-topology-runbook.md`
- `docs/blastwall-v3/revocation-and-breakglass.md`
- `blastwall_v3_codex_implementation_pack/phases/PHASE_14_DOCS_GOVERNANCE_AND_EXTERNAL_REVIEW.md`
- `blastwall_v3_codex_implementation_pack/calabi/CALABI_V3_KRA_GATE_RUNBOOK.md`
- `blastwall_v3_codex_implementation_pack/appendices/ACCEPTANCE_TEST_CATALOG.md`
- `blastwall_v3_codex_implementation_pack/appendices/V3_FAILURE_STATES.md`

## Calabi evidence placeholders

Populate this section during live gate execution:

- `Calabi host`: `<pending>`
- `KRA primary`: `<pending>`
- `KRA server list`: `<pending>`
- `signer host/job`: `<pending>`
- `AAP workflow run(s)`: `<pending>`
- `valid base host preflight`: `<pending>`
- `missing artifact negative case`: `<pending>`
- `missing index negative case`: `<pending>`
- `revocation negative case`: `<pending>`
- `breakglass infrastructure case`: `<pending>`

## Failure-state map

- `FAIL_KRA_UNAVAILABLE`: audit-side KRA or vault infrastructure outage.
- `FAIL_ATTESTATION_NOT_VISIBLE`: signed artifact visible in marker but not in configured KRA path.
- `FAIL_INDEX_NOT_VISIBLE`: index not visible or not current in configured path.
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
