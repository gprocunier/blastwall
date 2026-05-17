# Stable-v3 Readiness Checklist

Use this checklist before claiming stable-v3.

## Governance

- Boundary owner named and reachable.
- Incident response owner named and reachable.
- Second maintainer-developer can reproduce verifier and inventory diagnostics.
- Signer owner named.
- KRA/vault owner named.
- Revocation authority named.
- Breakglass approval path named and tested.

## Configuration and ownership

- `eigenstate.ipa` `1.18.1` or newer is installed in the AAP execution
  environment and bastion validation path.
- `BLASTWALL_ATTESTATION_MODE` = `stable-v3` is explicitly set.
- Primary KRA server configured and documented.
- Explicit vault owner and scope are configured for service-owned path.
- AAP signer-job custody credential has KRA vault write/read authority for the
  selected scope. For shared-vault RC validation this is normally an IdM admin
  credential; for production prefer a dedicated service-owned principal.
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

- Missing attestation fetch: observed as `FAIL_ATTESTATION_NOT_VISIBLE`.
- Missing latest index: observed as `FAIL_INDEX_NOT_VISIBLE`.
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

- Healthy-path Calabi v3 KRA/AAP gate completed on 2026-05-17 UTC.
- Policy pipeline workflow `2177` passed.
- Runtime verification workflow `2227` passed.
- Runtime preflight job `2236` retrieved marker-referenced KRA artifacts and
  verified the signed envelope plus latest index.
- Managed-host verification job `2240` passed with evidence digest
  `16dc41143e934a4a1cad5c138867a8dfe0e9dec8fa12ff7dda6456302a190625`.
- Destructive live negative cases are not yet part of the Calabi RC evidence
  packet; local regression tests cover those failure classes.

## Go/No-Go

- GO only if all checklist items above are complete and evidence artifacts are attached.
- No-Go if any owner is missing, any infra-only exception is undocumented, or any security failure class is bypassed.
