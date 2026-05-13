# Blastwall v2 Release Notes

Date: 2026-05-13

## Release Semantics

Blastwall v2 freezes three operator-facing policy names:

- `base`: the stable RHEL login posture for `blastwall_t`.
- `base-nested`: the stable OpenShift/SPO nested workload variant of `base`.
- `strange-socket-v1`: a dry-run, opt-in profile for first-wave unusual socket
  families.

`strange-socket-v1` is intentionally not folded into `base` or
`base-nested`. It has RHEL and OpenShift/SPO lab evidence, but remains a
separate profile until ordinary automation corpus testing and release approval
show that the extra socket denials belong in the default posture.

## Version Guidance

Use this split when publishing artifacts:

- `0.6.0`: profile-aware v2 control plane, marker v2, inventory/preflight
  selection, registry/drift checks, and OpenShift/SPO status-derived usage.
- `0.6.1-0.rc1`: lab release candidate for `strange-socket-v1` dry-run
  validation.
- RC1j (current): release-semantics consolidation for marker and strange OpenShift
  compatibility behavior on the same `0.6.1-0.rc1` RPM identity.

Do not publish a stable artifact that changes profile membership without
returning through Calabi validation and updating these notes.

## Stable V2 Control Plane

The v2 control plane adds:

- `policy/profiles.yml` registry for targets, scopes, profiles, variants, and
  validation evidence.
- Registry schema validation and drift checks across CIL, OpenShift/SPO,
  probes, docs, and profile metadata.
- Marker v2 grammar with version, state, target, RPM, registry hash, policy
  hash, profiles, and scopes.
- Inventory grouping for current, stale, base, and `strange-socket-v1` profile
  evidence.
- Fail-closed preflight when required profile evidence is missing, stale, or
  mismatched.
- AAP policy pipeline nodes for RPM build, OpenShift/SPO bundle render,
  candidate install, verification, marker promotion, inventory sync, and
  post-promotion preflight.

## RC1j Release Semantics

- Production RHEL release path is marker-driven and uses `state=active` with
  `profiles=base`. Nested OpenShift behavior uses the `base-nested` registry
  variant through `ocp-spo-nested`, not a RHEL marker profile.
- Dry-run policy paths use `state=lab-active` and require the explicit dry-run
  allow signal during marker emission/preflight (`--allow-dry-run-profiles`) before
  accepting markers that include `profiles=base,strange-socket-v1`.
- `blastwall-strange` and `blastwall-nested-strange` are explicitly non-default:
  they are not in the base bundle and only appear through opt-in render/validation
  overlays.

## Fragnesia Triage

Fragnesia was disclosed on May 13, 2026 as a separate ESP-in-TCP/XFRM issue in
the Dirty Frag family. The current RC keeps `base` unchanged because the enforceable
surfaces are already part of the current posture: `xfrm` blocks NETLINK_XFRM
state creation, `alg_socket` blocks the AF_ALG helper path, and `userns` blocks
the normal RHEL login route to namespace-local network administration. The safe
Dirty Frag probe now also checks the Fragnesia AF_ALG prerequisite.

## OpenShift/SPO

The stable OpenShift path uses `RawSelinuxProfile.status.usage` as the source
of truth. Static manifests carry placeholders, then runtime playbooks derive
SCC-compatible SELinux process types from the live cluster.

Stable workload classes:

- `blastwall`: standard workload class.
- `blastwall-nested`: explicit nested workload class with pod-level user
  namespaces.

Dry-run, lab-only opt-in classes:

- `blastwall-strange`
- `blastwall-nested-strange`

`readOnlyRootFilesystem: false` in validation-job SCCs is an intentionally narrow
validation-image posture for current RC probe execution, not a blanket production
container default.

On the validated Calabi OCP 4.20 lab, SPO reported these usage strings:

- `blastwall.process`
- `blastwallnested.process`
- `blastwallstrange.process`
- `blastwallnestedstrange.process`

The runtime SCC types were:

- `blastwall_.process`
- `blastwallnested_.process`
- `blastwallstrange_.process`
- `blastwallnestedstrange_.process`

SPO now has an explicit usage-to-SCC mode for this release:

- `calabi-ocp420-rawprofile-underscore` (default): derives underscore suffix in the
  process type (`blastwall_.process`) before SCC hydration.
- `status-usage-direct`: uses `status.usage` unchanged for SCC and probe expectations.

`calabi-ocp420-rawprofile-underscore` remains the default because direct
`status.usage` to `seLinuxOptions.type` binding was rejected in the Calabi OCP
4.20 lab and is non-default until future validated clusters prove otherwise.

OpenShift/SPO release-decision record (RC1j):

- OCP 4.20 / SPO 0.10
  - `RawSelinuxProfile`: `blastwall` / `blastwallnested` / `blastwallstrange` /
    `blastwallnestedstrange`
  - `status.usage`: `blastwall.process`, `blastwallnested.process`,
    `blastwallstrange.process`, `blastwallnestedstrange.process`
  - SCC type used: `blastwall_.process`, `blastwallnested_.process`,
    `blastwallstrange_.process`, `blastwallnestedstrange_.process`
  - Admitted pod context: derived usage matched `probeContext.processType`
  - Mode: `calabi-ocp420-rawprofile-underscore` (default)
  - Result: PASS on all validation jobs
- Older clusters may require direct `status.usage` passthrough mode (`status-usage-direct`);
  this remains a compatibility fallback with no acceptance default.

## Calabi Evidence

Checkpoint evidence lives in:

- `docs/blastwall-v2/phase-05-checkpoint.md`
- `docs/blastwall-v2/phase-06-checkpoint.md`
- `docs/blastwall-v2/phase-07-checkpoint.md`

The Phase 07 gate validated the OpenShift/SPO strange profile pair with:

- rendered bundle SHA256
  `60b7d8803deaa44d34fb81e46beda7aac64ce4abeea90169777789f110d02d38`
- four successful validation jobs:
  - `standard_profile: passed`
  - `nested_profile: passed`
  - `standard-strange_profile: passed`
  - `nested-strange_profile: passed`
- worker-scoped validation on `ocp-worker-01`, `ocp-worker-02`, and
  `ocp-worker-03`
- all seven first-wave strange socket probes returning `BLOCKED` on each
  worker for both standard and nested strange classes

## Rollback

Rollback rules:

- For RHEL login policy, reinstall or downgrade the prior `blastwall-selinux`
  RPM, remove dry-run modules when present, and republish the marker only after
  host verification succeeds.
- For OpenShift/SPO, stop assigning workloads to `blastwall-strange` or
  `blastwall-nested-strange`, then delete the strange validation jobs, SCCs,
  RBAC, and RawSelinuxProfile resources if the opt-in profile must be removed.
- Do not edit IdM marker state by hand to claim coverage that has not been
  verified by the relevant playbook path.

## Release Judgment

Publishable:

- `base`
- `base-nested`
- profile registry and drift checks
- marker v2 and profile-aware preflight
- OpenShift/SPO standard and nested status-derived usage handling

Dry-run only:

- `strange-socket-v1`
- `blastwall-strange`
- `blastwall-nested-strange`

Deferred:

- promotion of strange socket surfaces into `base`
- KVM hardening path
- seccomp changes in prior checkpoint material (not yet in current release posture)
- BPF LSM integration as product posture
- expanded ordinary automation corpus replay for strange sockets
- additional RHEL generation matrix beyond current Calabi proof
- policy split-domain work outside the current profile model
