# Phase 08 Calabi Final Checkpoint

Date: 2026-05-15

Branch: `blastwall-v2-phase-08-rc1k`

Commit under local remediation: `6ec0f9e5759a8c83f75f6c38cb1ec7257b382334`

Decision: `HOLD: operational blocker`

## Reason

This local remediation pass changed marker publication, hash semantics,
preflight bypass behavior, inventory anomaly detection, rollback signaling,
OpenShift/SPO fail-closed validation, and operator evidence. Those changes need
fresh Calabi end-to-end evidence before any stable or RC approval.

## Required Calabi Gates

- Gate 1 branch and source identity: `PENDING`
- Gate 2 inventory classification fixtures: `PENDING`
- Gate 3 base AAP verification: `PENDING`
- Gate 4 policy pipeline base path: `PENDING`
- Gate 5 RHEL strange-socket dry-run path: `PENDING`
- Gate 6 rollback simulation: `PENDING`
- Gate 7 base automation corpus replay: `PENDING`
- Gate 8 OpenShift/SPO base and nested: `PENDING`
- Gate 9 OpenShift/SPO strange dry-run: `PENDING`

## Local Artifacts

- Remediation checkpoint:
  `docs/blastwall-v2/phase-08-remediation-checkpoint.md`
- Base corpus report:
  `docs/blastwall-v2/base-corpus-replay-report.md`
- OpenShift/SPO matrix:
  `docs/blastwall-v2/spo-compatibility-matrix.md`
- Inventory audit tool:
  `tools/audit_blastwall_inventory.py`
- Inventory audit playbook:
  `playbooks/audit-inventory-membership.yml`
- Installed policy hash helper:
  `tools/blastwall_policy_hash.py`

## Unresolved Risks

- The base automation corpus has not been replayed through the live Calabi
  SSH, SSSD, PAM, and SELinux path after this remediation patch.
- Rollback marker behavior has static and syntax coverage only until a
  controlled failure is forced in Calabi.
- OpenShift/SPO fail-closed usage guards need a fresh validation job run on the
  live cluster.
- AAP workflow evidence must prove post-promotion preflight still derives the
  profile group after marker promotion.

## Exit Decision

Hold publication until the Calabi gates above pass or a narrower
`REFERENCE ONLY: not stable` decision is explicitly accepted.
