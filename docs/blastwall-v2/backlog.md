# Blastwall v2 Backlog

## Release-Blocking Only If Strange Sockets Become Stable

These items are not required for publishing the v2 control plane, but they are
required before promoting `strange-socket-v1` into the default posture:

- Replay a representative ordinary automation corpus under
  `base,strange-socket-v1`.
- Confirm package, service, file transfer, template/content deployment, API,
  and OpenShift administration workflows still behave as expected.
- Add explicit stale/missing marker negative tests for required
  `base,strange-socket-v1` evidence in AAP.
- Capture rollback evidence for removing the dry-run RHEL module and removing
  OpenShift/SPO strange profile resources.
- Validate at least one additional supported RHEL generation if the target
  release promise spans more than the current lab endpoint.

## RC1k Release-Semantics Decisions

- Production RHEL marker path is `state=active` with `profiles=base`, and must be
  accepted by normal preflight without dry-run opt-in toggles. Nested OpenShift
  workflow uses the `base-nested` registry variant through `ocp-spo-nested`, not a
  RHEL marker profile.
- Dry-run marker acceptance is non-production by default: `state=lab-active` plus
  explicit dry-run allow flag in marker emission/preflight workflows.
- Strange OpenShift/SPO profiles (`blastwall-strange`, `blastwall-nested-strange`)
  remain opt-in and are rendered, then validated, only when explicitly requested.
- `readOnlyRootFilesystem: false` is documented as a validation-image posture for
  runtime probes and SCC validation jobs only; it is not a broad production
  recommendation.
- Keep `KVM`, `seccomp`, and `BPF LSM` as RC1k roadmap
  entries only; no production intent is claimed yet.

## Split-Domain Work

Deferred by design:

- separate SELinux domains for automation classes that need broad capabilities
- separate IdM host groups or service identities for workflows that need an
  exception surface
- target-specific OpenShift workload classes beyond standard and nested
- mapping AAP job templates to required policy profiles instead of one shared
  automation posture

This work should stay outside the current release unless a real automation
workflow proves that shared `blastwall_t` is the wrong boundary.

## Candidate Future Surfaces

Potential future deny scopes need exploit signal, automation-impact review, and
safe probes before implementation. Candidates should stay in backlog until they
meet that bar.

Candidate areas:

- additional netlink families
- key-management surfaces
- perf/event tracing surfaces
- kernel tracing and observability surfaces
- filesystem notification or mount-related surfaces
- container runtime helper boundaries

Do not add a candidate surface solely because SELinux can name it. The release
bar is: clear risk, low expected value for privileged automation, safe proof,
and no unexplained ordinary automation breakage.

## OpenShift/SPO Follow-Up

- Keep `blastwall-strange` and `blastwall-nested-strange` out of the default base
  artifact and only in render-on-demand overlays.
- Add public OpenShift/SPO demo output for the strange classes if they remain
  visible in documentation.
- Keep validating `.status.usage` behavior when the Security Profiles Operator
  version changes.
- Watch Pod Security warnings around explicit SELinux type assignment and keep
  SCC admission evidence in the validation output.

## Documentation Follow-Up

- Convert the v2 Markdown notes into first-class HTML pages if the public site
  becomes the primary distribution surface for release documentation.
- Refresh public diagrams if `strange-socket-v1` moves from dry-run to stable.
- Add a compact release checklist to the public Day 2 operations page after the
  release path stops changing.
