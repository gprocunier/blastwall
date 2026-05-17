# V3 Implementation Ledger

## Branch
- branch: blastwall-v3-signed-attestation
- base commit: 6d233cacd5252c1c1487ecec48340c2a2d1dd296
- current commit: HEAD (`feat(v3-attestation): wire signer audit recovery and review docs`)

## Phase Status
| Phase | State | Owner | Commit(s) | Tests | Notes |
|---:|---|---|---|---|---|
| 00 | complete | PM + architecture lead | `2f23527` | policy static, profile validation, drift check, pytest | Branch created from the remediated v2 baseline; design doc copied into `docs/blastwall-v3/`; local baseline passed. |
| 01 | complete | marker agent | `0cd5d6d` | marker, inventory grouping, audit, static | V2 markers reject duplicate reserved fields; inventory and audit fail closed on current+parser-invalid contradictions. |
| 02 | complete | schema agent | `a5dbeb0` | attestation pytest, full pytest | Added payload/envelope schemas, duplicate-key JSON loading, deterministic canonical bytes, payload/envelope digest validation. |
| 03 | complete | signer agent | `a5dbeb0` | crypto pytest, full pytest | Added single-format RSA PKCS1v15 detached payload signatures, SKI extraction, CA trust, allowlist, and signer certificate checks. |
| 04 | complete | vault/KRA agent | `a5dbeb0` | vault pytest, full pytest | Added explicit KRA vault configuration, targeted read/write helpers, retry/error context, digest readback, and health playbook skeleton. |
| 05 | complete | vault/KRA + schema | `04b8972` | index pytest, full pytest | Added signed latest-generation index schema, signature verification, digest binding, and replay/revocation checks. |
| 06 | complete | marker agent | `a5dbeb0` | marker unittest, full pytest | Added v3 locator marker parser/emitter; valid v3 markers produce hints but never marker-only suitability. |
| 07 | complete | preflight agent | `1fb1a69` | verifier pytest, preflight syntax, full pytest | Added stable-v3 verifier command and preflight wiring requiring marker, envelope, index, signer trust, binding, and current policy hash. |
| 08 | complete | AAP agent | HEAD | sign pytest, syntax, static, full test | Added signer workflow, write/readback verification, separate signer/verifier credentials, and stable-v3 promotion verification. |
| 09 | complete | inventory agent | HEAD | audit pytest, syntax, full test | Inventory remains selector-only while audit can verify attestations and report KRA/visibility failure states. |
| 10 | complete | rollback agent | HEAD | verifier/revocation pytest, syntax, full test | Added revocation helper/playbook and infrastructure-only breakglass for artifact/index visibility failures. |
| 11 | complete | SPO agent | HEAD | attestation/sign/verifier pytest, full test | OCP SPO targets require signed `spo_evidence` without changing workload posture or derived SCC type behavior. |
| 12 | complete | test agent + architecture lead | HEAD | negative matrix pytest, static, full test | Added embedded-artifact marker rejection, expired attestation, wrong index signer, missing index, and v3 static workflow checks. |
| 13 | blocked by lab state | PM + architecture lead + Calabi agent | pending | local validation complete; connectivity check attempted | `virt-01` is reachable, but bastion/IdM/mirror/OpenShift guests are currently shut off. |
| 14 | complete | docs agent + PM | HEAD | docs render, syntax, full test | Added operator, KRA topology, revocation/breakglass, readiness, and external-review docs. |

## Security Invariants
- marker is locator only
- preflight verifies signed artifact
- stable-v3 live hash mandatory
- latest-generation index mandatory
- KRA primary server explicit
- signer workflow writes and reads back envelope plus index before marker publication
- inventory selects only; it never proves launch suitability
- signer private key is scoped to the signer workflow and not attached to preflight or promotion
- breakglass cannot bypass failed host verification

## Open Blockers
- Phase 13 live Calabi gate is not complete in this local source pass.
- Calabi `virt-01` is reachable, but `bastion-01.workshop.lan`, IdM, mirror registry, and OpenShift VMs are currently shut off.
- The v3 branch is local-only; `origin/blastwall-v3-signed-attestation` does not exist yet, so AAP project sync/source-revision Gate 0 cannot pass until the commit is published or otherwise staged.
- KRA-enabled Calabi vault configuration, signer material, AAP branch sync, and AAP source revision must be confirmed before live gate execution.

## Calabi Evidence
- Not completed for v3. `virt-01.workshop.lan` was reachable, but the required lab guests were shut off during the Phase 13 attempt.
- Use the v3 KRA gate runbook after the lab is powered on and this source commit is available to the Calabi/AAP path.

## Final Decision
- Local source GO for Phase 13 gate.
- Live gate HOLD due current lab power state and unpublished v3 branch.
- Release GO/HOLD remains pending live Calabi KRA evidence.

## Phase Handoffs

### Phase 00
- phase: 00
- files changed: `docs/blastwall-v3/signed-attestation-design.md`, `V3_IMPLEMENTATION_LEDGER.md`
- tests added: none
- tests run: `python3 tests/policy_static.py`; `python3 tools/validate_blastwall_profiles.py --registry policy/profiles.yml`; `python3 tools/check_blastwall_drift.py --registry policy/profiles.yml`; `python3 -m pytest -q tests` (`67 passed`)
- open issues: Calabi/KRA validation deferred by design until Phase 13
- security invariants checked: branch split preserves v2 baseline; no SELinux deny scope changes; marker remains locator-only in v3 design

### Phase 01
- phase: 01
- files changed: `tools/blastwall_marker.py`, `tools/render_inventory_profile_groups.py`, `tools/audit_blastwall_inventory.py`, `playbooks/audit-inventory-membership.yml`, `inventory/blastwall-idm.yml`, `poc-calabi/aap/inventory/blastwall-idm.yml`, `tests/test_blastwall_marker.py`, `tests/test_audit_blastwall_inventory.py`, `tests/inventory_grouping.py`, `tests/fixtures/inventory-policy-markers.json`, `tests/policy_static.py`
- tests added: duplicate reserved marker field parser tests; duplicate reserved inventory fixture cases; audit current-marker-parse-error tests
- tests run: `python3 tests/test_blastwall_marker.py`; `python3 tests/inventory_grouping.py`; `python3 tests/test_audit_blastwall_inventory.py`; `python3 tests/policy_static.py`; `git diff --check`
- open issues: none for Phase 01
- security invariants checked: duplicate reserved fields fail closed; unknown non-reserved duplicate fields remain tolerated; inventory selects only and does not verify v3 proof

### Phase 02
- phase: 02
- files changed: `policy/attestation-schema.json`, `policy/attestation-envelope-schema.json`, `tools/blastwall_attestation.py`, `tests/test_blastwall_attestation.py`
- tests added: canonical byte stability; duplicate JSON key rejection; unknown envelope version rejection; missing required fields; payload digest invariance; envelope digest stability; generation type and validity-window checks
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation.py tests/test_blastwall_attestation_crypto.py`; `python3 -m pytest -q tests`; `python3 tests/policy_static.py`; profile validation; drift check
- open issues: full RFC 8785 numeric corner cases are intentionally outside the current integer/string payload schema
- security invariants checked: duplicate JSON properties are rejected before canonicalization; unknown envelope versions reject

### Phase 03
- phase: 03
- files changed: `tools/blastwall_attestation.py`, `tests/test_blastwall_attestation_crypto.py`
- tests added: valid signature; tampered payload; untrusted CA; unknown signer allowlist; expired certificate; signer SKI formatting
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation.py tests/test_blastwall_attestation_crypto.py`; `python3 -m pytest -q tests`
- open issues: lab implementation uses `sha256-rsa-pkcs1v15` as the single supported format per phase configuration; PSS remains a future governance decision
- security invariants checked: signer allowlist is mandatory; signer certificate must chain to configured CA; private key material is not logged by tests or helpers

### Phase 04
- phase: 04
- files changed: `tools/blastwall_attestation_vault.py`, `tests/test_blastwall_attestation_vault.py`, `playbooks/attestation-vault-health.yml`
- tests added: explicit primary/server validation; command targeting; read/write digest recording; retry-on-not-found; auth failure non-retry; error classification
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation_vault.py`; `python3 -m pytest -q tests`
- open issues: health playbook is a skeleton until Calabi KRA command details are validated
- security invariants checked: vault helpers require explicit server input; no implicit IdM discovery path was added; structured error context is available

### Phase 05
- phase: 05
- files changed: `policy/attestation-index-schema.json`, `tools/blastwall_attestation.py`, `tests/test_blastwall_attestation_index.py`
- tests added: valid signed latest index; tampered index signature; older attestation generation replay; index digest mismatch; marker digest mismatch; wrong host/profile binding; revoked index
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation.py tests/test_blastwall_attestation_crypto.py tests/test_blastwall_attestation_index.py`; `python3 tests/policy_static.py`; `python3 -m pytest -q tests`; `git diff --check`
- open issues: vault write/read integration for indexes is deferred to signer/preflight workflow phases, using the explicit KRA helper from Phase 04
- security invariants checked: stable-v3 latest index is mandatory in verifier surface; stale generations fail as `FAIL_REPLAYED_ATTESTATION`; revoked index fails closed

### Phase 06
- phase: 06
- files changed: `tools/blastwall_marker.py`, `tests/test_blastwall_marker.py`
- tests added: v3 locator parse; unknown version; missing locator fields; duplicate reserved fields; bad signer SKI; bad/expired expiry; revoked state; non-integer generation; v3 marker emission
- tests run: `python3 -m unittest tests/test_blastwall_marker.py`; `python3 -m pytest -q tests`
- open issues: inventory v3 hint grouping is deferred until preflight/audit verification wiring
- security invariants checked: v3 marker is a locator hint only; marker-only `check` does not report v3 as suitable; revoked markers are recognized and unsuitable

### Phase 07
- phase: 07
- files changed: `tools/blastwall_attestation_verify.py`, `playbooks/preflight.yml`, `tests/test_blastwall_attestation_verify.py`
- tests added: valid stable-v3 verification; marker-only failure; v2 marker rejection in stable-v3; live policy drift; replayed generation; CLI JSON exit status
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation_verify.py`; `ansible-playbook --syntax-check -i localhost, playbooks/preflight.yml`; `python3 tests/policy_static.py`; profile validation; drift check; `python3 -m pytest -q tests`; `git diff --check`
- open issues: preflight verifies artifacts from explicit retrieved envelope/index directories; live Calabi KRA retrieval remains Phase 13 gate work
- security invariants checked: stable-v3 cannot pass from a marker alone; v2 markers are rejected in stable-v3; live policy hash is mandatory; latest index is mandatory

### Phase 08
- phase: 08
- files changed: `tools/blastwall_attestation_sign.py`, `playbooks/sign-attestation.yml`, `playbooks/promote-policy-rpm.yml`, `aap/vars/blastwall-controller.yml`, `aap/configure-controller.yml`, `tests/test_blastwall_attestation_sign.py`, `tests/policy_static.py`
- tests added: sign-store-readback happy path; policy drift rejection; verify-existing promotion path; signer/verifier AAP credential separation; stable-v3 promotion verification
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation_sign.py`; `ansible-playbook --syntax-check playbooks/sign-attestation.yml playbooks/promote-policy-rpm.yml aap/configure-controller.yml`; `python3 tests/policy_static.py`; `make test`
- open issues: live signer credential material and vault server paths remain Phase 13 validation items
- security invariants checked: signer writes and reads back envelope plus latest index before marker publication; promotion verifies existing signed material before IdM marker write; preflight/promotion receive verifier credential only

### Phase 09
- phase: 09
- files changed: `tools/audit_blastwall_inventory.py`, `tests/test_audit_blastwall_inventory.py`, `playbooks/audit-inventory-membership.yml`, `tests/fixtures/phase09_current_marker_valid_inventory.json`, `tests/fixtures/phase09_current_marker_missing_artifact_inventory.json`, `tests/fixtures/phase09_current_marker_stale_inventory.json`, `tests/fixtures/phase09_current_marker_parser_invalid_inventory.json`, `tests/fixtures/phase09_current_marker_dry_run_without_allow_inventory.json`
- tests added: current marker + valid attestation, missing artifact visibility, parser-invalid marker, stale generation, dry-run marker without allow on a current marker
- tests run: `python3 -m pytest -q tests/test_audit_blastwall_inventory.py`; `ansible-playbook --syntax-check playbooks/audit-inventory-membership.yml`; `make test`
- open issues: attestation source artifacts are still injected in tests via an injectable `read_vault_artifact` callback
- security invariants checked: inventory remains selector-only for grouping; attestation verification only runs when enabled and can enforce infrastructure failure splits by fail flags

### Phase 10
- phase: 10
- files changed: `tools/blastwall_attestation_verify.py`, `playbooks/preflight.yml`, `tools/blastwall_attestation_revocation.py`, `playbooks/revoke-blastwall-attestation.yml`, `tests/test_blastwall_attestation_verify.py`, `tests/test_blastwall_attestation_revocation.py`
- tests added: revoked marker, revoked index, tombstoned attestation artifact, breakglass scope and infrastructure-only bypass checks
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation_verify.py`; `python3 -m pytest -q tests/test_blastwall_attestation_revocation.py`; `ansible-playbook --syntax-check playbooks/preflight.yml playbooks/revoke-blastwall-attestation.yml`; `make test`
- open issues: breakglass remains signed-mode scoped by design; explicit Calabi KRA recovery still belongs to Phase 13
- security invariants checked: revoked marker and index fail closed; profile mismatch, signature, policy drift, and replay failures are not bypassed by breakglass; breakglass only bypasses attestation/index visibility failures

### Phase 11
- phase: 11
- files changed: `policy/attestation-schema.json`, `tools/blastwall_attestation_sign.py`, `tools/blastwall_attestation_verify.py`, `tests/test_blastwall_attestation.py`, `tests/test_blastwall_attestation_sign.py`, `tests/test_blastwall_attestation_verify.py`
- tests added: target-specific `spo_evidence` schema requirement tests for OCP SPO targets; OCP signer payload generation tests with/without `spo_evidence`; OCP attestation verification tests for `ocp-spo-standard` and `ocp-spo-nested` plus invalid validation-results rejection
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation.py tests/test_blastwall_attestation_sign.py tests/test_blastwall_attestation_verify.py`; `make test`
- open issues: no phase-specific open issues identified
- security invariants checked: RHEL and OCP attestation artifacts use the same envelope/index model and same signing/envelope/index schema; OCP targets require `spo_evidence` but do not alter target/type derivation or workload classes

### Phase 12
- phase: 12
- files changed: `tools/blastwall_marker.py`, `tests/test_blastwall_marker.py`, `tests/test_blastwall_attestation.py`, `tests/test_blastwall_attestation_index.py`, `tests/policy_static.py`
- tests added: v3 marker embedded artifact rejection; expired payload window failure; wrong signer index failure; missing index visibility failure; static checks for signer/preflight separation and write-readback-before-marker workflow
- tests run: `python3 -m pytest -q tests/test_blastwall_marker.py tests/test_blastwall_attestation.py tests/test_blastwall_attestation_index.py`; `python3 tests/policy_static.py`; `make test`
- open issues: no phase-specific open issues identified
- security invariants checked: markers cannot carry inline artifacts; stable-v3 cannot pass without latest-generation index; wrong signer and expired artifacts fail closed

### Phase 13
- phase: 13
- files changed: `V3_IMPLEMENTATION_LEDGER.md`
- tests added: none
- tests run: local prerequisites only: `make test`; Ansible syntax checks; docs placeholder-term scan; Calabi connectivity/power-state check
- open issues: live Calabi KRA/AAP gate is blocked because lab guests are shut off and the v3 branch is not published to `origin`; AAP project branch and source revision must match the committed v3 branch before execution
- security invariants checked: local gate prerequisites are green; no live evidence bundle exists yet; release GO remains unavailable without KRA/AAP evidence

### Phase 14
- phase: 14
- files changed: `docs/blastwall-v3/operator-runbook.md`, `docs/blastwall-v3/kra-topology-runbook.md`, `docs/blastwall-v3/revocation-and-breakglass.md`, `docs/blastwall-v3/stable-v3-readiness-checklist.md`, `docs/blastwall-v3/external-review-packet.md`
- tests added: none
- tests run: `npm run test:docs` via `make test`; docs placeholder-term scan
- open issues: Calabi evidence placeholders remain pending in `docs/blastwall-v3/external-review-packet.md`; service vault owner naming remains environment-specific pending policy finalization
- security invariants checked: docs describe marker-as-locator behavior, stable-v3 fail-closed outcomes, mode controls, infrastructure-only breakglass, and KRA health assumptions
