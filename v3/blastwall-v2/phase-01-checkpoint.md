# Blastwall v2 Phase Checkpoint

## Phase

- Phase ID: 01
- Phase name: Profile registry and schema validation
- Branch: `blastwall-v2-phase-01-profile-registry`
- Commit: pending local checkpoint commit
- Date/time: 2026-05-10T14:40:51-04:00
- Operator: release automation

## Objective

Introduce a profile registry that describes the current Blastwall posture as the
operator-facing `base` profile, represents `base-nested` as a controlled variant,
records planned strange-socket work as non-active metadata, and validates the
registry without changing active enforcement behavior.

## Repository State

```bash
git status --short
 M package.json
?? docs/blastwall-v2/phase-01-checkpoint.md
?? docs/blastwall-v2/profiles.md
?? policy/profiles.yml
?? tests/test_validate_blastwall_profiles.py
?? tools/

git diff --stat
package.json | 2 +-
```

Untracked Phase 01 additions:

```text
docs/blastwall-v2/phase-01-checkpoint.md
docs/blastwall-v2/profiles.md
policy/profiles.yml
tests/test_validate_blastwall_profiles.py
tools/validate_blastwall_profiles.py
```

## Files Changed

| File | Change summary | Reason |
|---|---|---|
| `policy/profiles.yml` | Added profile registry with targets, permission sets, active scopes, `base`, planned `strange-socket-v1`, and `base-nested` variant. | Required Phase 01 registry. |
| `tools/validate_blastwall_profiles.py` | Added static validator for registry structure, references, artifacts, evidence states, duplicate keys, base scope order, variant deltas, and release-validation evidence. | Required Phase 01 schema/static validation. |
| `tests/test_validate_blastwall_profiles.py` | Added validator unit tests covering valid registry, unknown references, missing fields, duplicate keys, evidence states, missing artifacts, missing probes, and malformed list fields. | Required Phase 01 validator tests. |
| `docs/blastwall-v2/profiles.md` | Added profile/scope/variant/target explanation and current known validation gaps. | Required operator-facing profile documentation. |
| `docs/blastwall-v2/phase-01-checkpoint.md` | Added this checkpoint report. | Required phase checkpoint. |
| `package.json` | Added profile validation and validator unit tests to `npm run test:policy`. | Keeps registry validation in the existing lightweight policy test path. |

## Tests Run

| Command | Result | Notes |
|---|---|---|
| `python3 tools/validate_blastwall_profiles.py --registry policy/profiles.yml` | PASS | Registry validates. |
| `python3 tests/test_validate_blastwall_profiles.py` | PASS | 11 unit tests passed. |
| `python3 -m pytest -q tests || true` | PASS | 11 pytest-discovered tests passed. |
| `npm run test:policy` | PASS | Registry validation, validator tests, policy static checks, inventory grouping, and OpenShift/SPO static checks passed. |
| `git diff --check` | PASS | No whitespace errors. |

## Calabi Lab Validation

| Target | Command or validation | Result | Evidence file |
|---|---|---|---|
| RHEL login | Not run in Phase 01. Repository/schema-only change. | SKIP | `policy/profiles.yml` |
| OpenShift/SPO standard | Not run in Phase 01. Repository/schema-only change. | SKIP | `policy/profiles.yml` |
| OpenShift/SPO nested | Not run in Phase 01. Repository/schema-only change. | SKIP | `policy/profiles.yml` |
| AAP preflight | Not run in Phase 01. No marker/preflight behavior changed. | SKIP | `policy/profiles.yml` |
| IdM marker | Not run in Phase 01. Marker v2 is explicitly not published in this phase. | SKIP | `policy/profiles.yml` |

## Acceptance Criteria

| Criterion | Result | Evidence |
|---|---|---|
| Registry exists and validates. | PASS | `policy/profiles.yml`; `python3 tools/validate_blastwall_profiles.py --registry policy/profiles.yml` |
| `base` exactly matches current scope posture. | PASS | Validator enforces exact scope order: `alg_socket`, `bpf`, `capability2_bpf`, `packet_socket`, `userns`, `io_uring`, `xfrm`, `rxrpc`, `selfprotect`. |
| `base-nested` is represented as a variant/delta. | PASS | `variants.base-nested` derives from `base` and removes only `userns`. |
| `strange-socket-v1`, if present, is clearly non-active/planned. | PASS | Present as `status: planned`; validator requires it remain planned in Phase 01. |
| No enforcement behavior changed. | PASS | No `policy/*.cil`, OpenShift/SPO manifests, playbooks, inventory, or AAP behavior changed. |
| Validator tests pass. | PASS | `python3 tests/test_validate_blastwall_profiles.py`; 11 tests passed. |

## Security Posture Impact

- Enforcement changed: no
- New denials added: no
- Existing denials weakened: no
- Marker behavior changed: no
- OpenShift behavior changed: no

## Risks and Unknowns

- Calabi lab smoke was not run because Phase 01 only changes repository metadata and validation.
- `capability2_bpf` remains intentionally modeled as static/shared evidence because no dedicated runtime probe exists yet.
- `selfprotect` remains intentionally modeled as playbook evidence because no standalone trigger exists yet.
- The registry now names planned strange-socket scopes, but they have no target support and no enforcement until the later dry-run phase.
- OpenShift `.status.usage` hardening remains deferred to Phase 04.

## Rollback Plan

```bash
git checkout -- package.json
git rm policy/profiles.yml
git rm tools/validate_blastwall_profiles.py
git rm tests/test_validate_blastwall_profiles.py
git rm docs/blastwall-v2/profiles.md
git rm docs/blastwall-v2/phase-01-checkpoint.md
```

If committed, revert the Phase 01 checkpoint commit instead.

## Recommendation

- Go/no-go recommendation: go for Phase 02 after human review.
- Required human decision: Greg must approve Phase 01 checkpoint before Phase 02 starts.
- Next phase if approved: Phase 02, marker v2, inventory, and preflight logic.
