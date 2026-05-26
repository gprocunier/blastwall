# Tabletop: FAIL_STALE_MARKER

Goal: prove a second maintainer can diagnose a marker/inventory/preflight failure without the primary maintainer.

Scenario:

1. A host moves from `blastwall_policy_current` to `blastwall_policy_stale`.
2. One host has `idm_userclass` as a dict instead of a list.
3. One host has a malformed Blastwall marker.
4. The primary maintainer is unavailable.

Allowed materials:

- `operator-one-page-summary.md`
- `troubleshooting-runbook.md`
- `inventory-diagnostic-decision-tree.md`
- `tools/blastwall_marker.py`
- `tools/audit_blastwall_inventory.py`

Success criteria:

- Identify the schema anomaly host.
- Identify the malformed marker host.
- Explain why preflight failed closed.
- Produce the safe remediation path without disabling marker validation.
- Decide whether this is a deploy issue, IdM/inventory issue, or rollback incident.
