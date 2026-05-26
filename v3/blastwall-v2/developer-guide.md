# Blastwall v2 Developer Guide

## Registry

`policy/profiles.yml` is the source of metadata truth for v2 policy semantics.
It does not generate policy. It records the contract that hand-written CIL,
OpenShift/SPO manifests, probes, docs, and playbooks must satisfy.

The top-level objects are:

- `targets`: runtime paths such as `rhel-login`, `ocp-spo-standard`, and
  `ocp-spo-nested`.
- `permission_sets`: named permission lists reused by scopes.
- `scopes`: one enforceable deny unit.
- `profiles`: operator-facing posture names.
- `variants`: controlled deltas from a profile.

Validate the registry before changing enforcement:

```bash
make registry-check
```

## Adding A Scope

Add a new scope only when it has:

- exploit signal or a clear posture-hardening rationale
- a target object class or equivalent enforcement surface
- expected evidence for present and absent class cases
- target support entries for every runtime path in scope
- a safe probe or a documented static-check exception
- docs explaining why the surface belongs in this automation boundary

For RHEL login targets, add a CIL artifact under `policy/` with both `deny` and
`neverallow` guards. Optional SELinux object classes must be wrapped in
`(optional ...)`.

This wrapper is a portability mechanism only. Optional wrapping allows a single
policy artifact to install across kernel versions that do not support a class, but it
does not define runtime evidence status. Evidence outcomes (`SKIP_ABSENT`,
`FAIL_MISSING_CLASS_REQUIRED`, `BLOCKED`, etc.) come from the registry scope
contract in `policy/profiles.yml`.

For OpenShift/SPO targets, add or update `RawSelinuxProfile` manifests and keep
runtime binding based on `RawSelinuxProfile.status.usage`.

Release marker semantics for current RC (RC1k):

- Production RHEL markers use `state=active` claims with `profiles=base`.
  OpenShift nested workloads use the `base-nested` registry variant through the
  `ocp-spo-nested` target, not a RHEL marker profile.
- Dry-run claims are non-production: they require `state=lab-active` and an explicit
  dry-run allow signal (for example, `--allow-dry-run-profiles`) during marker
  emission and preflight.

## Adding A Profile

A profile is a named operator posture. Prefer adding a profile when the new
surface set needs explicit opt-in, separate validation, or separate lifecycle
semantics.

Rules:

- active profiles may reference only active scopes
- dry-run profiles may reference active and dry-run scopes
- profile names become marker and inventory contract, so rename before release
  if the name is wrong
- do not silently change profile membership after publishing a stable release

`strange-socket-v1` is the model for a dry-run profile. It extends `base`, adds
only first-wave unusual socket families, and stays separate from the default
posture.

## Adding A Variant

Use a variant when a runtime path needs a controlled delta from a profile rather
than a new policy family.

`base-nested` is the current model:

- base profile: `base`
- removed scope: `userns`
- target: `ocp-spo-nested`
- reason: pod-level user namespace behavior is required for nested OpenShift
  workloads

The drift checker verifies that variant removals come from the base profile and
that target support matches the effective scope set.

## Adding A Target

Targets must declare their mechanism. OpenShift/SPO targets must also declare:

```yaml
usage_source: status.usage
```

Do not hardcode SPO process type strings in runtime harnesses. The live cluster
owns the usage value; playbooks and scripts derive the SCC-compatible process
type from that value.

## Safe Probe Requirements

A safe probe:

- attempts only the minimum entry point needed to prove reachability
- does not exploit a vulnerability
- does not bind, connect, transmit, or mutate state unless the target surface
  explicitly requires it and the behavior is benign
- reports `BLOCKED`, `SKIP_ABSENT`, `FAIL_ALLOWED`, `FAIL_UNKNOWN`, or
  `FAIL_MISSING_CLASS_REQUIRED`
- treats absent optional classes per scope evidence contract, not by CIL wrapper
  shape
- treats unexpected errno values as `FAIL_UNKNOWN`, not blocked evidence

For example, `io_uring` may be optional in CIL for portability, while a supported
release matrix can still require `FAIL_MISSING_CLASS_REQUIRED` when `io_uring` is
expected but missing.

Runtime probes must fail when a protected surface succeeds.

## Drift Checks

`tools/check_blastwall_drift.py` is the release guardrail. It checks:

- profile status and profile scope compatibility
- variant deltas
- CIL artifact presence, object classes, permissions, optional wrappers, and
  `deny` plus `neverallow`
- OpenShift/SPO policy presence and status-derived usage rules
- required probe or evidence-source presence
- docs coverage for checked profiles and variants
- runtime harnesses avoiding legacy hardcoded SPO type strings

The CIL parser is intentionally scoped to the deny/neverallow forms used by the
current policy artifacts. Extend the parser and add regression tests before
introducing quoted identifiers or more complex CIL expressions.

Run it before every formal push, release, or tag.

## Publish Hygiene

Before publishing:

```bash
make test
```

Then do a sanitization pass:

- remove or gate rerun-only behavior
- keep lab-only flags explicit
- keep dry-run profile activation explicit
- keep current RC (RC1k) non-goals (`KVM`, `seccomp`, and `BPF LSM`) explicit in release docs
- verify defaults still represent fresh-deploy behavior
- record deferred work instead of hiding it in comments or local scripts

## Build Boundaries

Use the root `Makefile` for local validation:

- `make test-fast`: registry, drift, Python, policy, OpenShift, and diff checks
- `make test`: `test-fast` plus Playwright documentation rendering
- `make policy-check`: SELinux policy source check on hosts with
  `selinux-policy-devel`
- `make policy-build`: local `blastwall.pp` build on hosts with
  `selinux-policy-devel`

For a reproducible docs-only check:

```bash
npm ci
npx playwright install --with-deps chromium
npm run test:docs
```

RPM release artifacts are intentionally built through
`playbooks/build-policy-rpm.yml` on a RHEL-capable bastion or AAP build target.
The root `make rpm` target fails with guidance rather than treating local RPM
packaging as a supported workstation contract.
