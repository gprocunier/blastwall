# Blastwall v2 Phase Checkpoint

## Phase

- Phase ID: 00
- Phase name: Repository intake and baseline
- Branch: `blastwall-v2-phase-00-repo-baseline`
- Commit: `01ce705`
- Date/time: 2026-05-10T14:26:38-04:00
- Operator: release automation

## Objective

Record the current Blastwall repository layout, current base deny posture,
RHEL and OpenShift policy artifacts, safe probes, marker/inventory/preflight
logic, build/test entry points, and Calabi assumptions before any v2
profile-aware control-plane implementation begins.

## Repository State

```bash
git status --short
?? docs/blastwall-v2/

git diff --stat
# no tracked diff yet; Phase 00 files are untracked until staged

git diff --no-index --stat /dev/null docs/blastwall-v2/repo-baseline.md
/dev/null => docs/blastwall-v2/repo-baseline.md | 188 ++++++++++++++++++++++++

git diff --no-index --stat /dev/null docs/blastwall-v2/phase-00-checkpoint.md
docs/blastwall-v2/phase-00-checkpoint.md | 95 ++++++++++++++++++++++
```

## Files Changed

| File | Change summary | Reason |
|---|---|---|
| `docs/blastwall-v2/repo-baseline.md` | Added Phase 00 repository baseline. | Required Phase 00 deliverable. |
| `docs/blastwall-v2/phase-00-checkpoint.md` | Added checkpoint skeleton and initial repository state. | Required phase checkpoint. |

## Tests Run

| Command | Result | Notes |
|---|---|---|
| `git diff --check` | PASS | No whitespace errors. |
| `npm run test:policy` | PASS | Validated 8 deny scopes, marker grouping, AAP/static wiring, and 12 OpenShift/SPO YAML files. |

## Calabi Lab Validation

| Target | Command or validation | Result | Evidence file |
|---|---|---|---|
| RHEL login | Not run in Phase 00. | SKIP | `docs/blastwall-v2/repo-baseline.md` |
| OpenShift/SPO standard | Not run in Phase 00. | SKIP | `docs/blastwall-v2/repo-baseline.md` |
| OpenShift/SPO nested | Not run in Phase 00. | SKIP | `docs/blastwall-v2/repo-baseline.md` |
| AAP preflight | Not run in Phase 00. | SKIP | `docs/blastwall-v2/repo-baseline.md` |
| IdM marker | Not run in Phase 00. | SKIP | `docs/blastwall-v2/repo-baseline.md` |

## Acceptance Criteria

| Criterion | Result | Evidence |
|---|---|---|
| Baseline document exists. | PASS | `docs/blastwall-v2/repo-baseline.md` |
| Current base deny scopes are mapped to files or explicitly marked missing. | PASS | `docs/blastwall-v2/repo-baseline.md` |
| Current probes are mapped to scopes or explicitly marked missing. | PASS | `docs/blastwall-v2/repo-baseline.md` |
| Current OpenShift/SPO artifacts are mapped or explicitly marked absent. | PASS | `docs/blastwall-v2/repo-baseline.md` |
| Build/test commands are documented. | PASS | `docs/blastwall-v2/repo-baseline.md` |
| No enforcement behavior changed. | PASS | Only `docs/blastwall-v2/` files changed. |

## Security Posture Impact

- Enforcement changed: no
- New denials added: no
- Existing denials weakened: no
- Marker behavior changed: no
- OpenShift behavior changed: no

## Risks and Unknowns

- Calabi lab validation was not run because Phase 00 only requires optional smoke validation.
- `capability2_bpf` has policy/static coverage but no dedicated runtime probe.
- `selfprotect` is validated through a Calabi playbook, not a standalone trigger script.
- OpenShift SCCs and static checks still hardcode SPO usage strings; this is expected to be addressed in Phase 04.

## Rollback Plan

```bash
git rm -r docs/blastwall-v2
```

## Recommendation

- Go/no-go recommendation: go for Phase 01 after human review.
- Required human decision: Greg must approve Phase 00 checkpoint before Phase 01 starts.
- Next phase if approved: Phase 01, profile registry and schema validation.
