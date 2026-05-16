# V3 Implementation Ledger

## Branch
- branch: blastwall-v3-signed-attestation
- base commit: 6d233cacd5252c1c1487ecec48340c2a2d1dd296
- current commit: HEAD (`feat(marker): reject duplicate reserved marker fields`)

## Phase Status
| Phase | State | Owner | Commit(s) | Tests | Notes |
|---:|---|---|---|---|---|
| 00 | complete | PM + architecture lead | HEAD (`docs(v3): freeze signed attestation baseline`) | `policy_static`, profile validation, drift check, pytest | Branch created from the remediated v2 baseline; design doc copied into `docs/blastwall-v3/`; local baseline passed. |
| 01 | complete | marker agent | HEAD (`feat(marker): reject duplicate reserved marker fields`) | marker, inventory grouping, audit, static | V2 markers reject duplicate reserved fields; inventory and audit fail closed on current+parser-invalid contradictions. |
| 02 | pending | schema agent | pending | pending | Attestation schema and canonical JSON. |
| 03 | pending | signer agent | pending | pending | Signer identity and detached signature verification. |
| 04 | pending | vault/KRA agent | pending | pending | KRA-aware vault custody helpers. |
| 05 | pending | vault/KRA + schema | pending | pending | Latest-generation index and replay control. |
| 06 | pending | marker agent | pending | pending | V3 locator marker grammar. |
| 07 | pending | preflight agent | pending | pending | AAP preflight attestation verification. |
| 08 | pending | AAP agent | pending | pending | Signer and marker-promotion workflows. |
| 09 | pending | inventory agent | pending | pending | Inventory audit and monitoring. |
| 10 | pending | rollback agent | pending | pending | Revocation, rollback, and breakglass. |
| 11 | pending | SPO agent | pending | pending | OpenShift/SPO attestation alignment. |
| 12 | pending | test agent | pending | pending | Negative test matrix. |
| 13 | blocked | PM + architecture lead + Calabi agent | pending | pending | Requires code and local tests to pass before Calabi/KRA gate. |
| 14 | pending | docs agent + PM | pending | pending | Docs, governance, and external review packet. |

## Security Invariants
- marker is locator only
- preflight verifies signed artifact
- stable-v3 live hash mandatory
- latest-generation index mandatory
- KRA primary server explicit
- breakglass cannot bypass failed host verification

## Open Blockers
- Phase 13 is blocked until implementation phases and local tests pass.
- KRA-enabled Calabi vault configuration and signer material have not been validated in this branch yet.

## Calabi Evidence
- Not started for v3. Use `blastwall_v3_codex_implementation_pack/calabi/CALABI_V3_KRA_GATE_RUNBOOK.md` only after code and local tests pass.

## Final Decision
- Pending.

## Phase Handoffs

### Phase 00
- phase: 00
- files changed: `docs/blastwall-v3/signed-attestation-design.md`, `V3_IMPLEMENTATION_LEDGER.md`
- tests added: none
- tests run: `python3 tests/policy_static.py`; `python3 tools/validate_blastwall_profiles.py --registry policy/profiles.yml`; `python3 tools/check_blastwall_drift.py --registry policy/profiles.yml`; `python3 -m pytest -q tests` (`67 passed`)
- open issues: Calabi/KRA validation deferred by design until Phase 13
- security invariants checked: branch split preserves v2 baseline; no SELinux deny scope changes; marker remains locator-only in v3 design
- next recommended phase: commit Phase 00, then start Phase 01

### Phase 01
- phase: 01
- files changed: `tools/blastwall_marker.py`, `tools/render_inventory_profile_groups.py`, `tools/audit_blastwall_inventory.py`, `playbooks/audit-inventory-membership.yml`, `inventory/blastwall-idm.yml`, `poc-calabi/aap/inventory/blastwall-idm.yml`, `tests/test_blastwall_marker.py`, `tests/test_audit_blastwall_inventory.py`, `tests/inventory_grouping.py`, `tests/fixtures/inventory-policy-markers.json`, `tests/policy_static.py`
- tests added: duplicate reserved marker field parser tests; duplicate reserved inventory fixture cases; audit current-marker-parse-error tests
- tests run: `python3 tests/test_blastwall_marker.py`; `python3 tests/inventory_grouping.py`; `python3 tests/test_audit_blastwall_inventory.py`; `python3 tests/policy_static.py`; `git diff --check`
- open issues: none for Phase 01
- security invariants checked: duplicate reserved fields fail closed; unknown non-reserved duplicate fields remain tolerated; inventory selects only and does not verify v3 proof
- next recommended phase: start parallel Batch A after Phase 01 commit
