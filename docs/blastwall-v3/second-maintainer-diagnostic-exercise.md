# Second Maintainer Diagnostic Exercise

## Purpose

The second maintainer-developer must be able to diagnose stable-v3 failures
without relying on the original implementer. This exercise is a sign-off
checklist for parser, preflight, inventory, KRA, and breakglass diagnosis.

## Required Exercises

1. Run the local verifier tests:

   ```sh
   python3 -m pytest -q tests/test_blastwall_attestation_verify.py
   ```

2. Explain why a v3 marker alone is not sufficient for launch suitability.

3. Given a failed preflight report, classify the failure as one of:

   - attestation infrastructure visibility,
   - signer/signature trust,
   - binding/profile/replay,
   - live host policy drift,
   - marker parse/version/state.

4. Demonstrate that breakglass only applies to:

   - `FAIL_ATTESTATION_NOT_VISIBLE`,
   - `FAIL_INDEX_NOT_VISIBLE`.

5. Demonstrate that breakglass does not apply to:

   - `FAIL_ATTESTATION_INTEGRITY`,
   - `FAIL_REVOKED_ATTESTATION`,
   - `FAIL_SIGNATURE_INVALID`,
   - `FAIL_SIGNER_UNTRUSTED`,
   - `FAIL_PROFILE_MISMATCH`,
   - `FAIL_BINDING_MISMATCH`,
   - `FAIL_DRIFTED_POLICY`,
   - `FAIL_REPLAYED_ATTESTATION`.

6. On the Calabi bastion, verify the collection floor:

   ```sh
   ansible-galaxy collection list eigenstate.ipa
   ansible-doc -t inventory eigenstate.ipa.idm
   ansible-doc -t module eigenstate.ipa.vault_health
   ansible-doc -t module eigenstate.ipa.vault_artifact
   ansible-doc -t module eigenstate.ipa.access_path
   ansible-doc -t filter eigenstate.ipa.sudo_risk
   ```

## Current Exercise Status

The commands above were run from the Calabi bastion on 2026-05-19 UTC during
the RC evidence pass. `eigenstate.ipa 1.18.1` was installed, and every listed
`ansible-doc` lookup passed. Human second-maintainer sign-off is still pending.
