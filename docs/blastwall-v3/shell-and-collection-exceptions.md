# Shell and Collection Exceptions

Blastwall v3 uses `eigenstate.ipa >= 1.18.1`, `freeipa.ansible_freeipa`,
`kubernetes.core`, and `ansible.builtin.command` with `argv` for stable control
paths where practical. Remaining shell use is classified here so reviewers can
distinguish stable-v3 exceptions from reference-v2 and lab paths.

```yaml
exceptions:
  - id: BW-SHELL-001
    file: playbooks/preflight.yml
    task_name: Authenticate FreeIPA client for live stable-v3 marker lookups
    classification: approved_exception
    reason: Raw live marker readback is a disabled-by-default inventory-lag fallback.
    required_controls:
      - BLASTWALL_ALLOW_IPA_CLI_FALLBACK
      - BLASTWALL_ALLOW_IPA_CLI_FALLBACK_REASON
      - read-back marker validation

  - id: BW-SHELL-002
    file: playbooks/preflight.yml
    task_name: FreeIPA CLI fallback read live stable-v3 host marker hints from FreeIPA
    classification: approved_exception
    reason: Temporary live marker readback fallback until all deployments rely on inventory refresh.
    required_controls:
      - BLASTWALL_ALLOW_IPA_CLI_FALLBACK
      - BLASTWALL_ALLOW_IPA_CLI_FALLBACK_REASON
      - parser-backed marker validation

  - id: BW-SHELL-003
    file: playbooks/deploy-policy.yml
    task_name: FreeIPA CLI fallback marker publication and rollback blocks
    classification: approved_exception
    reason: Reference-v2 compatibility fallback guarded by rescue and read-back behavior.
    required_controls:
      - named FreeIPA CLI fallback boundary
      - collection-first marker publication path

  - id: BW-SHELL-004
    file: playbooks/promote-policy-rpm.yml
    task_name: FreeIPA CLI fallback marker publication blocks
    classification: approved_exception
    reason: Reference-v2 compatibility fallback guarded by rescue and read-back behavior.
    required_controls:
      - named FreeIPA CLI fallback boundary
      - collection-first marker publication path

  - id: BW-SHELL-005
    file: playbooks/build-policy-rpm.yml
    task_name: Authenticate to IdM for package build evidence
    classification: approved_exception
    reason: Kerberos bootstrap shell retained outside the stable-v3 attestation proof path.
    required_controls:
      - no marker publication
      - no attestation custody

  - id: BW-SHELL-006
    file: playbooks/install-policy-rpm.yml
    task_name: Authenticate to IdM before install verification
    classification: approved_exception
    reason: Kerberos bootstrap shell retained for managed-host install path.
    required_controls:
      - no attestation signing
      - managed-host verification still runs separately

  - id: BW-SHELL-007
    file: playbooks/credential-smoke.yml
    task_name: Authenticate to IdM for credential smoke
    classification: lab_only
    reason: Diagnostic smoke test for credential wiring.
    required_controls:
      - no policy mutation
      - no marker publication

  - id: BW-SHELL-008
    file: playbooks/verify-managed-host.yml
    task_name: Authenticate to IdM for managed-host verification
    classification: approved_exception
    reason: Verification playbook bootstrap; probe execution uses command tasks.
    required_controls:
      - no marker publication
      - probe evidence remains fail-closed

  - id: BW-SHELL-009
    file: playbooks/revoke-blastwall-attestation.yml
    task_name: Revoke marker and publish revocation evidence
    classification: approved_exception
    reason: Revocation path still uses raw IPA CLI while collection read-back replacement is pending.
    required_controls:
      - operator-directed recovery path
      - stable-v3 preflight remains fail-closed on revoked markers

  - id: BW-SHELL-010
    file: playbooks/promote-policy-rpm.yml
    task_name: Authenticate IdM principal for FreeIPA collection marker update
    classification: approved_exception
    reason: Kerberos credential-cache bootstrap for FreeIPA collection writes in the Controller EE.
    required_controls:
      - collection performs marker publication
      - no raw IPA marker write in this task
      - qualified IdM principal
      - no_log enabled for credential material
```
