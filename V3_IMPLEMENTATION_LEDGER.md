# V3 Implementation Ledger

## Branch
- branch: blastwall-v3-signed-attestation
- base commit: 6d233cacd5252c1c1487ecec48340c2a2d1dd296
- current commit: working tree after `14f7f472f70c1eb66f8ece35b194ed4e2da8b137`
- implementation gate commit: `02c4d7490bfa7671802a71d3079846c27bd92b11`

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
| 08 | complete | AAP agent | `02c4d74` | sign pytest, syntax, static, full test, Calabi AAP gate | Added signer workflow, write/readback verification, separate signer/verifier credentials, stable-v3 promotion verification, and KRA custody credential use for preflight reads. |
| 09 | complete | inventory agent | HEAD | audit pytest, syntax, full test | Inventory remains selector-only while audit can verify attestations and report KRA/visibility failure states. |
| 10 | complete | rollback agent | HEAD | verifier/revocation pytest, syntax, full test | Added revocation helper/playbook and infrastructure-only breakglass for artifact/index visibility failures. |
| 11 | complete | SPO agent | HEAD | attestation/sign/verifier pytest, full test | OCP SPO targets require signed `spo_evidence` without changing workload posture or derived SCC type behavior. |
| 12 | complete | test agent + architecture lead | HEAD | negative matrix pytest, static, full test | Added embedded-artifact marker rejection, expired attestation, wrong index signer, missing index, and v3 static workflow checks. |
| 13 | complete | PM + architecture lead + Calabi agent | `02c4d74` | bastion `make test-fast`; Calabi AAP policy pipeline `2177`; Calabi AAP runtime verification `2227` | Live healthy-path KRA/AAP gate passed with signed stable-v3 marker publication, KRA readback, post-promotion preflight, runtime preflight, SPO validation, and managed-host probes. |
| 14 | complete | docs agent + PM | HEAD | docs render, syntax, full test | Added operator, KRA topology, revocation/breakglass, readiness, and external-review docs. |
| 15 | complete | hardening gate | HEAD | sign pytest, policy static, syntax, `make test-fast`, docs test | Replaced prior weak KRA/preflight edges, classified shell exceptions, and recorded the destructive negative packet. |
| 16 | complete | stable-evidence gate | `9e9e5e8` | policy static, audit pytest, syntax, live AAP jobs | Installed continuous schedules, fixed Controller-side inventory audit FreeIPA bootstrap, completed three-host mixed-state evidence, and recorded strict audit fail-closed behavior. |
| 17 | complete | RC evidence gate | working tree | attestation targeted pytest, policy static pending, docs pending | Normalized digest and revoked-marker failure states, added RC decision/governance/soak evidence docs, and refreshed scheduled-loop evidence. |

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
- No source or evidence blocker remains for external review of the stable-v3
  candidate gate.
- Standalone stable-v3 runtime verification requires an explicit
  `BLASTWALL_CURRENT_POLICY_SHA256`. The policy pipeline supplies this from
  install artifacts; manually launched runtime gates must pass the same value.
- Final stable-v3 publication still needs named governance owners, live-green
  custody health, and sign-off.
- Stable-v3 service-owned or named-user custody health is not yet live-green
  in Calabi; jobs `3914`, `3987`, and `3991` failed in the vault-health path.
- S-range readiness is not claimed; run the broader mixed-state scale gate
  before making an S-range claim.

## Calabi Evidence
- Date: 2026-05-17 UTC.
- Lab path: workstation to `virt-01` (`172.18.0.224`) to Calabi bastion
  (`172.16.0.30`); bastion checkout
  `/opt/openshift/aws-metal-openshift-demo/blastwall`.
- OpenShift access: `oc whoami` returned `system:admin`; cluster reported 6 nodes.
- AAP project branch: `blastwall-v3-signed-attestation`.
- Implementation gate source revision:
  `02c4d7490bfa7671802a71d3079846c27bd92b11`.
- Signer certificate: subject `O=WORKSHOP.LAN, CN=idm-01.workshop.lan`;
  signer SKI `8e62ab6d10d1a1a6b4261c4ee3fe79f76545c6d6`;
  valid `2026-05-17T00:58:03Z` through `2028-05-17T00:58:03Z`.
- KRA vault configuration: primary `idm-01.workshop.lan`; server list
  `idm-01.workshop.lan`; scope `shared`; owner `blastwall-attestation`.
- Policy pipeline workflow `2177` completed successfully at
  `2026-05-17T05:07:22Z`.
  - `policy_project_sync` job `2178`: successful.
  - `policy_inventory_sync` job `2179`: successful.
  - `build_policy_rpm` job `2182`: successful.
  - `render_spo_policy_crs` job `2186`: successful.
  - `install_candidate_policy_rpm` job `2187`: successful.
  - `apply_validate_spo_policy_crs` job `2191`: successful.
  - `verify_candidate_host` job `2195`: successful.
  - `sign_attestation` job `2199`: successful.
  - `promote_policy_marker` job `2203`: successful.
  - `post_promotion_inventory_sync` job `2207`: successful.
  - `post_promotion_preflight` job `2210`: successful.
- Policy artifacts from job `2187`:
  - NEVRA: `blastwall-selinux-0.6.1-0.rc1`.
  - policy hash:
    `4b3e1d30e364331d408d8531d871ffcce23805a89b4cf44bd2977854be35bfc2`.
  - RPM hash:
    `4af7a532c90629a78f0491589eacf1d0e2a440a547ab82d83b6a7c0072fbd098`.
- Signed attestation artifacts from job `2199`:
  - generation `1778994368`.
  - attestation ref:
    `shared/blastwall-attestation/blastwall-attestations/mirror-registry.workshop.lan/base/1778994368.json`.
  - attestation hash:
    `c84bb22a1944862ae0db74eeed5cc1153ded23d19afce3fcb4486f7fcb1ec190`.
  - marker:
    `blastwall:v=3;state=active;target=rhel-login;rpm=blastwall-selinux-0.6.1-0.rc1;profiles=base;attest_ref=shared/blastwall-attestation/blastwall-attestations/mirror-registry.workshop.lan/base/1778994368.json;attest_sha256=c84bb22a1944862ae0db74eeed5cc1153ded23d19afce3fcb4486f7fcb1ec190;signer_kid=8e62ab6d10d1a1a6b4261c4ee3fe79f76545c6d6;exp=2026-05-17T06:06:09Z;generation=1778994368`.
- Runtime verification workflow `2227` completed successfully at
  `2026-05-17T05:12:19Z`.
  - `project_sync` job `2228`: successful.
  - `credential_smoke` job `2229`: successful.
  - `inventory_sync` job `2233`: successful.
  - `preflight` job `2236`: successful.
  - `verify_managed_host` job `2240`: successful.
- Runtime preflight job `2236` retrieved the marker-referenced attestation and
  latest index from KRA, materialized local envelope/index files, and verified:
  `status=PASS`, `failure_state=null`, `attestation_generation=1778994368`,
  `index_generation=1778994368`, `signer_kid=8e62ab6d10d1a1a6b4261c4ee3fe79f76545c6d6`.
- Managed-host verification job `2240` ran as
  `blastwall_u:blastwall_r:blastwall_t:s0` on `mirror-registry.workshop.lan`.
  Evidence digest:
  `16dc41143e934a4a1cad5c138867a8dfe0e9dec8fa12ff7dda6456302a190625`.
  Probes blocked AF_ALG, BPF map/prog load, AF_PACKET, user namespace,
  `io_uring_setup`, Dirty Frag `NETLINK_XFRM`, Dirty Frag `AF_RXRPC`, and
  Fragnesia `AF_ALG` entry points with `EPERM`/`EACCES` evidence.

## Final Decision
- Phase 13 healthy Calabi KRA/AAP gate: GO.
- Release review package: GO for healthy-path evidence.
- Final production stable-v3 claim remains conditional on external reviewer
  acceptance of local negative coverage or a follow-up destructive live negative
  evidence run.

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
- tests run: local prerequisites: `make test`; Ansible syntax checks; docs placeholder-term scan; bastion `make test-fast`; Calabi AAP policy pipeline `2177`; Calabi AAP runtime verification `2227`
- open issues: standalone runtime launches must provide `BLASTWALL_CURRENT_POLICY_SHA256`; destructive live negative evidence remains optional pending external reviewer request
- security invariants checked: signed marker publication requires signer write/readback; preflight retrieves marker-referenced envelope/index from configured KRA primary; verifier enforces signer allowlist, latest index, marker binding, registry hash, policy hash, and host/profile binding; managed-host probes confirm the intended RHEL policy denies remain active

### Phase 14
- phase: 14
- files changed: `docs/blastwall-v3/operator-runbook.md`, `docs/blastwall-v3/kra-topology-runbook.md`, `docs/blastwall-v3/revocation-and-breakglass.md`, `docs/blastwall-v3/stable-v3-readiness-checklist.md`, `docs/blastwall-v3/external-review-packet.md`
- tests added: none
- tests run: `npm run test:docs` via `make test`; docs placeholder-term scan
- open issues: Calabi evidence placeholders remain pending in `docs/blastwall-v3/external-review-packet.md`; service vault owner naming remains environment-specific pending policy finalization
- security invariants checked: docs describe marker-as-locator behavior, stable-v3 fail-closed outcomes, mode controls, infrastructure-only breakglass, and KRA health assumptions

### Phase 15
- phase: 15 hardening pack closure
- files changed: `playbooks/attestation-vault-health.yml`, `playbooks/promote-policy-rpm.yml`, `playbooks/deploy-policy.yml`, `tests/test_blastwall_attestation_sign.py`, `tests/policy_static.py`, `docs/blastwall-v3/calabi-negative-evidence.md`, `docs/blastwall-v3/multi-host-continuous-verification-plan.md`, `docs/blastwall-v3/shell-and-collection-exceptions.md`, `V3_OPTIMIZATION_LEDGER.md`
- tests added: deterministic `resolve-existing` vault artifact mapping; digest-mismatch rejection before artifact verification; static checks for collection-backed preflight artifact read ordering, explicit KRA health scope/owner inputs, and post-write host userClass readback after raw IPA CLI fallback
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation_sign.py`; `python3 tests/policy_static.py`; `ansible-playbook --syntax-check playbooks/promote-policy-rpm.yml playbooks/deploy-policy.yml playbooks/attestation-vault-health.yml playbooks/preflight.yml`; `make test-fast`; `npm run test:docs`
- open issues: current hardening patch has not yet replaced the prior Controller-visible live evidence commit; destructive Calabi cases for missing envelope/index, replay, revocation, expiry, KRA canary, vault auth, signature tamper, profile mismatch, and breakglass boundaries remain the production stable-v3 hold
- security invariants checked: stable-v3 preflight resolves marker locators then reads envelope/index through `eigenstate.ipa.vault_artifact` before verifier execution; KRA health no longer supplies implicit scope/owner defaults; raw `ipa host-mod` fallback remains disabled by default and now requires immediate post-write host marker readback before proceeding

### Phase 16
- phase: 16 stable evidence gate
- files changed: `aap/vars/blastwall-controller.yml`, `aap/configure-controller.yml`, `poc-calabi/aap/20-configure-controller.yml`, `playbooks/audit-inventory-membership.yml`, `tests/policy_static.py`, `V3_STABLE_EVIDENCE_GATE_LEDGER.md`, `docs/blastwall-v3/*`, `release/STABLE_V3_DECISION.md`
- tests added: static guards for continuous schedules and inventory audit FreeIPA bootstrap
- tests run: `python3 tests/policy_static.py`; `python3 -m pytest -q tests/test_audit_blastwall_inventory.py`; `ansible-playbook --syntax-check playbooks/audit-inventory-membership.yml`; `git diff --check`; live AAP project sync `3771`; strict audit job `3772`
- open issues: stable-v3 publication remains held pending governance owner assignment, live-green custody health, and sign-off; S-range claim remains held pending broader scale evidence
- security invariants checked: inventory remains selector-only; strict audit retrieves signed evidence from explicit KRA path before treating a current marker as valid; missing artifact is reported as `FAIL_ATTESTATION_NOT_VISIBLE` instead of marker suitability or generic auth failure

### Phase 17
- phase: 17 stable-v3 RC evidence gate
- files changed: `tools/blastwall_attestation.py`, `tools/blastwall_attestation_verify.py`, `tools/blastwall_attestation_sign.py`, attestation tests, `tests/policy_static.py`, `docs/blastwall-v3/*`, `V3_*_LEDGER.md`, `release/STABLE_V3_DECISION.md`
- tests added: digest mismatch maps to `FAIL_ATTESTATION_INTEGRITY`; revoked marker maps to `FAIL_REVOKED_ATTESTATION`; breakglass cannot bypass either; static guard rejects stale attestation failure states in tools
- tests run: `python3 -m pytest -q tests/test_blastwall_attestation_index.py tests/test_blastwall_attestation_verify.py tests/test_blastwall_attestation_sign.py` (`45 passed`); live Controller read-only schedule query and collection availability check
- open issues: governance owners remain pending; stable-v3 service-owned or named-user custody health is not live-green in Calabi; S-range remains future work
- security invariants checked: marker remains locator only; breakglass remains infrastructure visibility only; signed envelope/latest index/live hash requirements are unchanged; scheduled loop fired without unexpected state movement
