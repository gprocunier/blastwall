# Calabi Negative Evidence Packet (Destructive v3 Gate)

## Purpose

Collect negative evidence for Blastwall v3 stable-v3 policy gates on Calabi.
This is the Phase 08 evidence lane. It now contains partial live Calabi
coverage; the full destructive matrix is still incomplete.

## Scope

- Target branch: `blastwall-v3-signed-attestation`
- Goal: prove fail-closed behavior and infra-only breakglass constraints under live negative conditions.

## Required case set

Each case below must be captured against a controlled/disposable Calabi host:

- Missing envelope
- Missing index
- Wrong generation / replayed attestation
- Revoked marker/index
- Expired attestation
- Policy hash drift
- KRA canary stale or missing
- Vault auth failure
- Breakglass infra-visibility bypass
- Breakglass rejection for security failures
- Signature tamper
- Profile mismatch

## Expected failure behavior

- `FAIL_ATTESTATION_NOT_VISIBLE`: envelope missing or not visible from configured KRA path.
- `FAIL_INDEX_NOT_VISIBLE`: index missing or stale/inaccessible.
- Replay / binding anomalies: `FAIL_REPLAYED_ATTESTATION` or binding failure.
- `FAIL_REVOKED_ATTESTATION`: revoked marker/index.
- Host-verification failures (`FAIL_DRIFTED_POLICY`, bad signature, profile mismatch, signer mismatch): **no breakglass bypass**.
- Infrastructure-class failures may allow breakglass only when explicitly scoped and operator approved.

## Evidence status (this pack)

| Case | Expected | Live Calabi capture |
|---|---|---|
| Missing envelope | `FAIL_ATTESTATION_NOT_VISIBLE` | pending |
| Missing index | `FAIL_INDEX_NOT_VISIBLE` | pending |
| Wrong generation | replay/binding failure | pending |
| Revoked marker/index | `FAIL_REVOKED_ATTESTATION` | pending |
| Expired attestation | expired attestation failure | pending |
| Policy hash drift | `FAIL_DRIFTED_POLICY` | AAP preflight job `2827`, failed as expected |
| KRA stale/missing canary | infra visibility failure | pending |
| Vault auth failure | auth/infra failure | pending |
| Breakglass infra-visibility bypass | scoped breakglass may pass only for artifact/index visibility | pending |
| Breakglass security failure rejection | breakglass rejected for signature, drift, profile, and revocation failures | pending |
| Signature tamper | signature failure | pending |
| Profile mismatch | binding/match failure | pending |

## Current live evidence

Positive current-branch gate on 2026-05-18 UTC:

- Branch: `blastwall-v3-signed-attestation`.
- Commit: `56f7c451a281bda5f5a1dbd1a8fac12d00097410`.
- Controller project sync: `2834`, successful, project revision
  `56f7c451a281bda5f5a1dbd1a8fac12d00097410`.
- Full policy pipeline workflow: `2843`, successful.
- OpenShift/SPO apply-validation node: job `2857`, successful.
- Managed-host verification node: job `2861`, successful.
- Sign-attestation node: job `2865`, successful.
- Marker-promotion node: job `2869`, successful.
- Post-promotion preflight node: job `2876`, successful.
- Standalone positive stable-v3 preflight after the KRA fail-closed fix:
  job `2839`, successful.

Current artifact bindings:

- Policy NEVRA: `blastwall-selinux-0.6.1-0.rc1`.
- Policy hash:
  `4b3e1d30e364331d408d8531d871ffcce23805a89b4cf44bd2977854be35bfc2`.
- Registry hash:
  `c8a533efc7ce60604d2a770964eea582005dde49ac2b882eea38c9701d612486`.
- RPM hash:
  `0c25e56e120a6e1f38d89300b3598cd4066967ef4136204610134fdd12735f45`.
- Probe report hash:
  `16dc41143e934a4a1cad5c138867a8dfe0e9dec8fa12ff7dda6456302a190625`.
- Attestation ref:
  `shared/blastwall-attestation/blastwall-attestations/mirror-registry.workshop.lan/base/1779093311.json`.
- Attestation hash:
  `4d382ebdee93fe0c37f1585711d2216465a09f18c8c359e142b2b2558582840b`.
- Signer KID:
  `8e62ab6d10d1a1a6b4261c4ee3fe79f76545c6d6`.
- Generation: `1779093311`.

Non-mutating negative checks captured on 2026-05-18 UTC:

- Drifted current policy hash: AAP preflight job `2827` failed as expected
  with `FAIL_DRIFTED_POLICY`.
- Bad signer allowlist: AAP preflight job `2830` failed as expected with
  `FAIL_SIGNER_UNTRUSTED`.
- Bad KRA primary/server before the fix: AAP preflight job `2831` unexpectedly
  succeeded even with `missing-kra.workshop.lan`; this exposed a fail-open
  validation gap where the downstream collection could still reach the default
  IPA path.
- Bad KRA primary/server after the fix: AAP preflight job `2835` failed as
  expected at `Resolve configured stable-v3 KRA vault servers` with
  `getent hosts missing-kra.workshop.lan` returning `rc=2`.

## Capture template

```yaml
phase: 09
commit:
test_or_gate:
environment:
commands:
results:
AAP_workflow_ids:
AAP_job_ids:
host:
profile:
attestation_mode:
marker:
vault_primary:
policy_sha256:
registry_sha256:
failure_state:
vault_error_type:
kra_available:
retry_attempted:
breakglass_enabled:
breakglass_result:
operator_summary:
attachments:
```

## Hold note

The Calabi live evidence is partial. Current healthy-path, SPO, drift,
untrusted-signer, and unresolved-configured-KRA cases are captured above. The
remaining destructive cases in the table still need controlled live execution
before a final stable-v3 release claim. The current hardening patch adds local
guards and tests but must be replayed through the Controller before replacing
the live evidence commit above.
