# Base Automation Corpus Replay Report

Status: `HOLD: corpus defined, Calabi replay not rerun in this local pass`

Branch: `blastwall-v2-phase-08-rc1k`

Source commit: `6ec0f9e5759a8c83f75f6c38cb1ec7257b382334`

Corpus playbook: `tests/corpus/base_automation_corpus.yml`

## Scope

The base corpus is designed to prove that ordinary privileged automation still
works under the `blastwall_u:blastwall_r:blastwall_t:s0` login context. It does
not add policy allow rules and does not promote `strange-socket-v1`.

Covered operations:

- SELinux execution context assertion
- package facts query
- file copy, template, directory, and line mutation
- lab-only user create/remove
- systemd unit install, daemon reload, and one-shot service run
- localhost HTTP request with non-fatal handling
- cleanup of lab-created files and user

## Required Live Evidence

- Host: `TBD from Calabi replay`
- RPM NEVRA: `TBD from Calabi replay`
- Marker: `TBD from Calabi replay`
- SELinux context: `TBD from Calabi replay`
- Tasks passed: `TBD from Calabi replay`
- Tasks failed: `TBD from Calabi replay`
- AVCs observed: `TBD from Calabi replay`
- Compatibility exceptions: `TBD from Calabi replay`
- Policy changes requested: none from local remediation

## Failure Triage Rule

If the corpus fails, classify the failure before changing policy:

- expected security denial
- missing lab setup
- real compatibility issue
- unrelated task failure

Real compatibility issues require a written decision before policy change:
split identity/domain, adjust the corpus expectation, or adjust profile policy
with explicit rationale.

## Local Validation

Local validation can prove structure and syntax only. It does not satisfy the
Calabi replay gate by itself.

```bash
ansible-playbook --syntax-check -i localhost, tests/corpus/base_automation_corpus.yml
# PASS
```

## Decision

The corpus artifact exists and is ready for Calabi replay. Stable release claims
remain blocked until the playbook runs through the same SSH, SSSD, PAM, and
SELinux path as normal Blastwall automation and the live evidence fields above
are completed.
