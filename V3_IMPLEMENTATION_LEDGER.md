# V3 Implementation Ledger

## Branch
- branch: blastwall-v3-signed-attestation
- base commit: 6d233cacd5252c1c1487ecec48340c2a2d1dd296
- current commit: pending stable-v3 verifier commit

## Phase Status
| Phase | State | Owner | Commit(s) | Tests | Notes |
|---:|---|---|---|---|---|
| 00 | complete | PM + architecture lead | HEAD (`docs(v3): freeze signed attestation baseline`) | `policy_static`, profile validation, drift check, pytest | Branch created from the remediated v2 baseline; design doc copied into `docs/blastwall-v3/`; local baseline passed. |
| 01 | complete | marker agent | HEAD (`feat(marker): reject duplicate reserved marker fields`) | marker, inventory grouping, audit, static | V2 markers reject duplicate reserved fields; inventory and audit fail closed on current+parser-invalid contradictions. |
| 02 | complete | schema agent | `a5dbeb0` | attestation pytest, full pytest | Added payload/envelope schemas, duplicate-key JSON loading, deterministic canonical bytes, payload/envelope digest validation. |
| 03 | complete | signer agent | `a5dbeb0` | crypto pytest, full pytest | Added single-format RSA PKCS1v15 detached payload signatures, SKI extraction, CA trust, allowlist, and signer certificate checks. |
| 04 | complete | vault/KRA agent | `a5dbeb0` | vault pytest, full pytest | Added explicit KRA vault configuration, targeted read/write helpers, retry/error context, digest readback, and health playbook skeleton. |
| 05 | complete | vault/KRA + schema | pending | index pytest, full pytest | Added signed latest-generation index schema, signature verification, digest binding, and replay/revocation checks. |
| 06 | complete | marker agent | `a5dbeb0` | marker unittest, full pytest | Added v3 locator marker parser/emitter; valid v3 markers produce hints but never marker-only suitability. |
| 07 | complete | preflight agent | pending | verifier pytest, preflight syntax, full pytest | Added stable-v3 verifier command and preflight wiring requiring marker, envelope, index, signer trust, binding, and current policy hash. |
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

### Phase 02
- phase: 02
- files changed: `policy/attestation-schema.json`, `policy/attestation-envelope-schema.json`, `tools/blastwall_attestation.py`, `tests/test_blastwall_attestation.py`
- tests added: canonical byte stability; duplicate JSON key rejection; unknown envelope version rejection; missing required fields; payload digest invariance; envelope digest stability; generation type and validity-window checks
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation.py tests/test_blastwall_attestation_crypto.py`; `python3 -m pytest -q tests`; `python3 tests/policy_static.py`; profile validation; drift check
- open issues: full RFC 8785 numeric corner cases are intentionally outside the current integer/string payload schema
- security invariants checked: duplicate JSON properties are rejected before canonicalization; unknown envelope versions reject
- next recommended phase: Phase 05 latest-generation index

### Phase 03
- phase: 03
- files changed: `tools/blastwall_attestation.py`, `tests/test_blastwall_attestation_crypto.py`
- tests added: valid signature; tampered payload; untrusted CA; unknown signer allowlist; expired certificate; signer SKI formatting
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation.py tests/test_blastwall_attestation_crypto.py`; `python3 -m pytest -q tests`
- open issues: lab implementation uses `sha256-rsa-pkcs1v15` as the single supported format per phase configuration; PSS remains a future governance decision
- security invariants checked: signer allowlist is mandatory; signer certificate must chain to configured CA; private key material is not logged by tests or helpers
- next recommended phase: Phase 05 latest-generation index

### Phase 04
- phase: 04
- files changed: `tools/blastwall_attestation_vault.py`, `tests/test_blastwall_attestation_vault.py`, `playbooks/attestation-vault-health.yml`
- tests added: explicit primary/server validation; command targeting; read/write digest recording; retry-on-not-found; auth failure non-retry; error classification
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation_vault.py`; `python3 -m pytest -q tests`
- open issues: health playbook is a skeleton until Calabi KRA command details are validated
- security invariants checked: vault helpers require explicit server input; no implicit IdM discovery path was added; structured error context is available
- next recommended phase: Phase 05 latest-generation index

### Phase 05
- phase: 05
- files changed: `policy/attestation-index-schema.json`, `tools/blastwall_attestation.py`, `tests/test_blastwall_attestation_index.py`
- tests added: valid signed latest index; tampered index signature; older attestation generation replay; index digest mismatch; marker digest mismatch; wrong host/profile binding; revoked index
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation.py tests/test_blastwall_attestation_crypto.py tests/test_blastwall_attestation_index.py`; `python3 tests/policy_static.py`; `python3 -m pytest -q tests`; `git diff --check`
- open issues: vault write/read integration for indexes is deferred to signer/preflight workflow phases, using the explicit KRA helper from Phase 04
- security invariants checked: stable-v3 latest index is mandatory in verifier surface; stale generations fail as `FAIL_REPLAYED_ATTESTATION`; revoked index fails closed
- next recommended phase: Phase 07 preflight verification

### Phase 07
- phase: 07
- files changed: `tools/blastwall_attestation_verify.py`, `playbooks/preflight.yml`, `tests/test_blastwall_attestation_verify.py`
- tests added: valid stable-v3 verification; marker-only failure; v2 marker rejection in stable-v3; live policy drift; replayed generation; CLI JSON exit status
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation_verify.py`; `ansible-playbook --syntax-check -i localhost, playbooks/preflight.yml`; `python3 tests/policy_static.py`; profile validation; drift check; `python3 -m pytest -q tests`; `git diff --check`
- open issues: preflight currently verifies artifacts from explicit retrieved envelope/index directories; live Calabi KRA retrieval remains Phase 13 gate work
- security invariants checked: stable-v3 cannot pass from a marker alone; v2 markers are rejected in stable-v3; live policy hash is mandatory; latest index is mandatory
- next recommended phase: Phase 08 signer/promotion workflow

### Phase 06
- phase: 06
- files changed: `tools/blastwall_marker.py`, `tests/test_blastwall_marker.py`
- tests added: v3 locator parse; unknown version; missing locator fields; duplicate reserved fields; bad signer SKI; bad/expired expiry; revoked state; non-integer generation; v3 marker emission
- tests run: `python3 -m unittest tests/test_blastwall_marker.py`; `python3 -m pytest -q tests`
- open issues: inventory v3 hint grouping is deferred until preflight/audit verification wiring
- security invariants checked: v3 marker is a locator hint only; marker-only `check` does not report v3 as suitable; revoked markers are recognized and unsuitable
- next recommended phase: Phase 05 latest-generation index, then Phase 07 preflight verification
