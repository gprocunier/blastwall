# Blastwall v3 KRA Topology Runbook

## Why KRA topology is a separate runbook

v3 uses two IdM-backed paths that behave differently:

- host marker in LDAP userClass,
- attestation artifacts in KRA-backed vault storage.

Both can be healthy independently. A healthy LDAP path does not guarantee KRA-backed artifact visibility.

## Assumptions

- KRA-enabled IdM replicas are explicitly configured.
- signer writes and preflight reads use the same primary by policy.
- service principals are scoped by service owner, not by ad-hoc user automation accounts.
- `eigenstate.ipa >= 1.18.1` is installed wherever stable-v3 signing or
  preflight runs.
- the AAP credential attached to `Blastwall sign attestation` has explicit
  KRA vault write/read authority for the configured scope.

## Service-owned vault recommendation

Use a dedicated service identity for vault artifact writes/reads:

- avoid sharing vault credentials with generic blastwall userClass writers,
- keep artifact path prefixes constrained by a service owner and host scope,
- avoid letting ordinary automation delete or read attestation artifacts,
- ensure service credential rotation and separation from AAP UI session credentials.

## Topology modes

### Same-replica default (recommended for stable-v3)

1. signer workflow writes to `blastwall_attestation_vault_primary`.
2. signer workflow reads back envelope/index from the same primary.
3. marker is published only after successful readback verification.
4. preflight reads from the same primary.

This avoids false stale/visibility failures caused by KRA replication lag during publication windows.

### Explicit multi-replica mode

Use only when explicit configuration and runbook changes are available:

- define ordered `blastwall_attestation_vault_servers`,
- include explicit failover policy,
- report replica inconsistency explicitly; the current local audit helper reports
  `FAIL_KRA_UNAVAILABLE`, `FAIL_ATTESTATION_NOT_VISIBLE`, or
  `FAIL_INDEX_NOT_VISIBLE` rather than silently choosing another replica.

No implicit IdM discovery is allowed in this phase.

## Health checks

Run in this order:

- IdM CA trust present.
- signer certificate still valid and allowed.
- `eigenstate.ipa.vault_health` reports the configured primary is KRA-enabled
  and has `failure_class=none`.
- signer writes envelope and index through `eigenstate.ipa.vault_artifact`.
- signer readback succeeds through the same artifact helper.
- preflight reads envelope and index through `eigenstate.ipa.vault_artifact`
  from primary.
- health canary freshness check for the primary.

Record each check result as pass/fail per run.

In AAP, the stable-v3 evidence loop installs an hourly KRA health schedule
against the configured primary. The Calabi RC path recorded job `3731` as a
passing canary check after the schedule was installed.

## Failure interpretation

- `FAIL_KRA_UNAVAILABLE`: primary KRA unavailable or unhealthy in audit output.
- `FAIL_ATTESTATION_NOT_VISIBLE`: attestation path visibility issue from primary.
- `FAIL_INDEX_NOT_VISIBLE`: latest-generation index not visible from primary.
- `vault_error_type`: structured vault helper detail such as `not_found`,
  `timeout`, `connection_refused`, `auth_failure`, or `proxy_error`.

## Minimum viable configuration

Use explicit values in your controller/inventory variables:

```text
blastwall_attestation_vault_primary: <kra-primary-fqdn>
blastwall_attestation_vault_servers:
  - <kra-primary-fqdn>
blastwall_attestation_vault_scope: service
blastwall_attestation_vault_owner: blastwall-attestation/<kra-primary-fqdn>
```

Do not use defaults for these values in stable-v3.

For Calabi shared-vault RC validation, the AAP controller configuration uses
`BLASTWALL_ATTESTATION_IDM_CREDENTIAL` to select the KRA custody credential for
the signer job. It defaults to `Blastwall IdM Admin` because the policy
maintainer identity is not allowed to create shared KRA vault entries. Prefer a
dedicated service-owned custody principal when that role is provisioned.

## Readiness gates

Before enabling stable-v3 on a host profile:

- run the KRA health playbook,
- confirm same-replica readback from signer and preflight,
- confirm marker publication requires successful artifact readback,
- confirm canary artifact refresh and expiry policy.

If any gate fails, stay in transition-v3 or pause automation until corrected.
