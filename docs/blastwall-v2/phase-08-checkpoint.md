# Phase 08 Checkpoint: Release, Documentation, and Backlog

Date: 2026-05-11
Branch: `blastwall-v2-phase-08-rc1k`

## Release Decision

`base` and `base-nested` are release-stable v2 profile semantics.

`strange-socket-v1` is name-frozen but remains dry-run and opt-in. It has RHEL
and OpenShift/SPO lab evidence, but is not part of the default posture.

## Documentation Added

- `docs/blastwall-v2/release-notes.md`
- `docs/blastwall-v2/developer-guide.md`
- `docs/blastwall-v2/backlog.md`

## Release Notes

The release notes freeze:

- stable profile names
- dry-run profile name
- version guidance for `0.6.0` and `0.6.1-0.rc1`
- OpenShift/SPO status-derived usage contract
- Calabi Phase 07 evidence
- rollback rules
- publishable versus dry-run scope

## Backlog

Deferred work is recorded for:

- ordinary automation corpus testing before strange-socket promotion
- stale/missing marker negative tests for required strange profile evidence
- rollback evidence for RHEL and OpenShift/SPO strange resources
- additional RHEL generation matrix
- split-domain policy work
- future candidate surfaces
- public docs conversion of v2 Markdown notes into first-class HTML

## Sanitization

Publish-readiness review found the Phase 07/08 changes fit the fresh-deploy
path:

- strange sockets remain explicit dry-run or opt-in resources
- defaults still use `base` and `base-nested`
- no local lab path is required by default runtime behavior
- direct rendered-bundle path support in `apply-validate-spo-policy-crs.yml`
  preserves AAP inline-artifact behavior and enables operator inspection
- node validation harness fix is general publishable logic, not rerun recovery

## Validation

Completed validation for this checkpoint:

```bash
python3 tools/validate_blastwall_profiles.py --registry policy/profiles.yml \
  && python3 tools/check_blastwall_drift.py --registry policy/profiles.yml
# PASS

python3 -m pytest -q tests
# 35 passed

npm run test:policy && npm run test:openshift
# PASS

npm ci
npx playwright install --with-deps chromium
npm run test:docs
# 107 passed

git diff --check
# PASS

make test || true
make rpm || true
# Historical Phase 08 caveat: root Makefile targets did not exist at the time
# of initial checkpoint validation.

make test-fast
# PASS after adding root validation targets.

make test
# PASS after adding root validation targets.

make policy-check
# Expected workstation failure: /usr/share/selinux/devel/Makefile is missing.

make rpm
# Expected boundary failure: RPM builds run through playbooks/build-policy-rpm.yml
# on a RHEL-capable bastion/AAP target.

BLASTWALL_POLICY_VERSION=0.6.1 BLASTWALL_POLICY_RELEASE=0.rc1 \
  ansible-playbook playbooks/render-spo-policy-crs.yml
# PASS; bundle sha256:
# 60b7d8803deaa44d34fb81e46beda7aac64ce4abeea90169777789f110d02d38
```

Calabi validation inherited from Phase 07:

- live OpenShift/SPO apply/validate passed for standard, nested, standard
  strange, and nested strange validation jobs
- worker-scoped strange profile validation passed on all three workers

RPM packaging evidence:

- local workstation `make policy-check` is not usable because
  `/usr/share/selinux/devel/Makefile` is not installed locally
- root `make rpm` intentionally points operators to the supported
  `playbooks/build-policy-rpm.yml` RHEL/AAP packaging path
- bastion direct RPM build succeeded for `0.6.1-0.rc1`
- RPM artifact:
  `/var/tmp/blastwall-policy-pipeline-local/artifacts/blastwall-selinux-0.6.1-0.rc1.noarch.rpm`
- RPM sha256:
  `d7ceaccc8d2b7a6c0e84ff42e61143d9dcbb3e092f4dc84e9be7f756f81b6f46`

## Stop Condition

Stop for human review before push, tag, or stable release publication.
