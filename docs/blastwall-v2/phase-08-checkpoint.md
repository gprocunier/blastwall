# Phase 08 Checkpoint: Release, Documentation, and Backlog

Date: 2026-05-11
Branch: `blastwall-v2-phase-08-rc1k`

## RC1k Closure Update

Date: 2026-05-14

The final closure patch keeps the Phase 08 scope frozen and addresses the
Calabi/AAP release-gate wiring found in external review:

- Calabi Controller configuration now defaults project sync to
  `blastwall-v2-phase-08-rc1k` through `BLASTWALL_PROJECT_BRANCH`, while keeping
  `BLASTWALL_PROJECT_URL` overrideable.
- `BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP` is overrideable and defaults to
  the Calabi candidate cohort.
- The Calabi selection fixture defaults the stale seed host to the same
  `mirror-registry.workshop.lan` host selected by `blastwall_policy_candidate`.
- RPM dry-run strange-socket activation uses explicit boolean coercion in the
  module list and install command path.
- OpenShift/SPO strange render/apply toggles accept AAP workflow extra vars as
  Ansible variables, with environment fallback preserved.
- OpenShift/SPO apply validation removes all prior validation jobs before
  applying the selected base or dry-run strange validation set, so stale failed
  jobs do not pollute operator evidence.
- Policy-pipeline post-promotion preflight can target the just-promoted
  candidate cohort before running the parser-backed marker check, which avoids
  relying on dry-run inventory grouping that cannot receive workflow extra vars.

This update does not add new deny scopes, marker grammar, OpenShift/SPO
profiles, or strange-socket production promotion.

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

Additional RC1k closure validation:

```bash
python3 tests/policy_static.py
python3 tests/inventory_grouping.py
python3 -m pytest -q tests
npm run test:policy
npm run test:openshift
make test-fast
ansible-playbook --syntax-check -i localhost, poc-calabi/aap/20-configure-controller.yml
ansible-playbook --syntax-check -i localhost, poc-calabi/aap/25-seed-selection-fixture.yml
ansible-playbook --syntax-check -i localhost, playbooks/install-policy-rpm.yml
ansible-playbook --syntax-check -i localhost, playbooks/preflight.yml
ansible-playbook --syntax-check -i localhost, aap/configure-controller.yml
npm run test:docs
git diff --check
# PASS locally on 2026-05-14
```

Calabi live gate note:

- Correct boundary remains workstation staging, `virt-01` jump, then
  bastion-local execution.
- Calabi connectivity was restored on 2026-05-14: `virt-01`, bastion,
  OpenShift API, AAP, SPO, and mirror registry were reachable; all six
  OpenShift nodes reported `Ready`; worker MCP settled to updated and
  non-degraded.
- `poc-calabi/aap/00-aap-readiness.yml` passed, including OpenShift admin
  access, AAP gateway readiness, mirror registry TLS/API readiness, pull-secret
  coverage, and an in-namespace pull of
  `mirror-registry.workshop.lan:8443/init/bootstrap-toolbox:latest`.
- `poc-calabi/aap/20-configure-controller.yml` passed and live Controller API
  state showed project `Blastwall` syncing
  `https://github.com/gprocunier/blastwall.git` branch
  `blastwall-v2-phase-08-rc1k`. Project update `1263` succeeded at revision
  `8f8b3e6f6cb4496bb25848cdd5fc6097e3e989d0`; the final strange-profile AAP
  run synced revision `a7c753cd51d84834d1101856bf47a77dda86d50a`.
- AAP policy pipeline workflow `1293`, launched as `blastwall-demo`, passed
  with project sync, inventory sync, RPM build, candidate install,
  OpenShift/SPO render, OpenShift/SPO apply validation, managed-host
  verification, marker promotion, post-promotion inventory sync, and preflight
  all successful.
- AAP runtime verification workflow `1326`, launched as `blastwall-demo`,
  passed with project sync, credential smoke, inventory sync, preflight, and
  managed-host verification all successful.
- AAP dry-run strange policy pipeline workflow `1376`, launched as
  `blastwall-demo`, passed end to end at published branch revision
  `a7c753cd51d84834d1101856bf47a77dda86d50a`. Nodes succeeded for project sync
  `1377`, inventory sync `1378`, RPM build `1381`, candidate install `1385`,
  SPO render `1386`, SPO apply/validate `1390`, managed-host verify `1394`,
  marker promotion `1398`, post-promotion inventory sync `1402`, and
  post-promotion preflight `1405`.
- Workflow `1376` built and installed `blastwall-selinux-0.6.1-0.rc1` with RPM
  sha256 `0c7ff0e06764a6be7228e3d49e46c1976a6fecfb603938b962b7789eef00b140`,
  promoted a v2 `lab-active` marker with
  `profiles=base,strange-socket-v1`, then passed post-promotion parser
  preflight with required profiles `base,strange-socket-v1`.
- Managed-host verification on `mirror-registry.workshop.lan` produced blocked
  evidence for AF_ALG, BPF map/program load, AF_PACKET, user namespace,
  io_uring, Dirty Frag NETLINK_XFRM, Dirty Frag AF_RXRPC, and Fragnesia
  AF_ALG probes. Workflow `1376` also produced blocked strange-socket dry-run
  evidence for AF_XDP, AF_TIPC, AF_CAN, AF_BLUETOOTH, AF_NFC, AF_KCM, and
  AF_RDS.
- OpenShift/SPO AAP apply validation used the Calabi
  `calabi-ocp420-rawprofile-underscore` mode and validated
  `blastwall.process` -> `blastwall_.process` and
  `blastwallnested.process` -> `blastwallnested_.process`.
- Final OpenShift/SPO strange validation reported RawSelinuxProfile usages
  `blastwall.process`, `blastwallnested.process`, `blastwallstrange.process`,
  and `blastwallnestedstrange.process`; SCC bindings used the derived underscore
  types `blastwall_.process`, `blastwallnested_.process`,
  `blastwallstrange_.process`, and `blastwallnestedstrange_.process`. All four
  validation jobs succeeded.
- Staged direct dry-run strange OpenShift/SPO validation passed from the
  bastion checkout with Ansible extra vars only:
  `BLASTWALL_SPO_INCLUDE_STRANGE_SOCKET_V1=true` and
  `BLASTWALL_SPO_VALIDATE_STRANGE_SOCKET_V1=true`. Bundle sha256 was
  `8d28745c909fa37967a72703d5a0445f2ef39613a0e53d46ae7ac095222cbc5a`; usage
  strings were `blastwall.process`, `blastwallnested.process`,
  `blastwallstrange.process`, and `blastwallnestedstrange.process`; hydrated SCC
  types were the derived underscore forms; validation summaries passed for
  standard, nested, standard-strange, and nested-strange.

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
