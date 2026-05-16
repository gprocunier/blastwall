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
- configured primary is KRA-enabled.
- signer write path succeeds.
- signer readback succeeds.
- preflight read path succeeds from primary.
- health canary freshness check for the primary.

Record each check result as pass/fail per run.

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

## Readiness gates

Before enabling stable-v3 on a host profile:

- run the KRA health playbook,
- confirm same-replica readback from signer and preflight,
- confirm marker publication requires successful artifact readback,
- confirm canary artifact refresh and expiry policy.

If any gate fails, stay in transition-v3 or pause automation until corrected.
