# Blastwall v2 Experimental README

Blastwall v2 is the experimental profile-aware control plane for Blastwall. It
keeps the original goal intact: privileged automation should not land on managed
hosts with the same unconstrained local shape as a human administrator. The v2
work makes that boundary easier to reason about, easier to validate, and safer
to expand.

The current release-candidate identity is `0.6.1-0.rc1`. The stable v2 posture
is still `base` for RHEL login automation and `base-nested` for the OpenShift
nested workload variant. `strange-socket-v1` remains a lab-only dry-run profile.

## What v1 Proved

Blastwall v1 proved the core enforcement idea:

- an automation login can be mapped into `blastwall_t`
- SELinux can deny risky kernel surfaces to that confined automation domain
- IdM can carry the identity and host-selection relationship
- AAP can run preflight and verification workflows against managed hosts
- the same posture can be demonstrated with local Ansible, AAP, and OpenShift/SPO

That proof is still valid. The v2 work does not replace the v1 enforcement
model; it adds the release and operations machinery needed to evolve the model
without relying on hand-maintained assumptions.

## What Was Hard In v1

The v1 tree had a practical problem: it treated Blastwall as one posture. That
worked for the first proof, but it became fragile once the project needed to
answer normal release questions.

The main issues were:

- Policy scope was implicit. A reader had to compare CIL, OpenShift/SPO YAML,
  probes, docs, and playbooks to understand what `blastwall` meant.
- Drift was easy. A permission could be added to one artifact and not another,
  or a probe could drift away from the documented policy surface.
- Host suitability was too string-oriented. Markers were useful evidence, but
  the contract did not carry enough versioned structure to prove profile, scope,
  registry, RPM, and policy identity together.
- AAP targeting mixed two concerns: candidate policy rollout and runtime
  profile verification. That made it harder to safely stage upgrades while still
  verifying only hosts that claim the required profile.
- OpenShift/SPO behavior needed a stronger compatibility contract. The live
  cluster exposes `RawSelinuxProfile.status.usage`, while the admitted SCC type
  on the validated Calabi OCP 4.20/SPO 0.10 path uses the derived underscore
  form such as `blastwall_.process`.
- New vulnerability response needed a safe experimental lane. Dirty Frag,
  Fragnesia, and unusual socket-family work should be testable without silently
  expanding the default automation posture.
- Evidence semantics were not strict enough. A blocked probe, an absent optional
  class, and an unexpected kernel or protocol failure need different release
  meanings.

In short: v1 proved enforcement. v2 makes the enforcement contract explicit and
release-checkable.

## What v2 Adds

### Profile Registry

`policy/profiles.yml` is the new metadata contract for v2. It records:

- supported targets such as `rhel-login`, `ocp-spo-standard`, and
  `ocp-spo-nested`
- permission sets and scope membership
- operator-facing profiles such as `base` and `strange-socket-v1`
- controlled variants such as `base-nested`
- evidence expectations for present, optional, and missing kernel surfaces

The registry does not generate policy. It states what the handwritten policy,
OpenShift/SPO manifests, probes, docs, and playbooks must agree on.

### Drift Checking

`tools/check_blastwall_drift.py` turns the registry into a release gate. It
checks that CIL and SPO deny/neverallow permissions exactly match the registry,
that optional classes are wrapped where required, that probes exist for required
evidence, and that docs mention checked profiles and variants.

This is a major change from v1. The release gate now fails on both missing and
extra permissions. That matters because an extra permission in a deny block is a
behavior change, not harmless metadata.

### Marker v2

The v2 marker format carries structured evidence:

```text
blastwall:v=2;state=active;target=rhel-login;rpm=...;registry_sha256=...;policy_sha256=...;profiles=base;scopes=...
```

That gives preflight and inventory enough information to reject stale,
malformed, unknown, or profile-incomplete claims. The marker includes both the
registry hash and the installed policy hash, so a host cannot look suitable just
because it has an old string that resembles a successful install.

Legacy v1 markers remain accepted only for the base compatibility path.

### Parser-Backed Preflight

Preflight now uses the marker parser rather than trusting broad regular
expressions. It checks required profiles, accepted RPM identity, registry hash,
scope expansion, and dry-run allowance.

This lets v2 fail closed when:

- the registry hash is stale
- the required profile is missing
- a marker is malformed
- a dry-run profile is present without explicit dry-run approval
- an unknown profile or unknown scope is needed to satisfy the claim

### Profile-Aware Inventory

The IdM inventory path now produces profile-aware groups:

- `blastwall_policy_current`
- `blastwall_policy_stale`
- `blastwall_profile_base`
- `blastwall_profile_strange_socket_v1`

Runtime verification can target `blastwall_profile_base` by default, while the
policy pipeline can still use a separate candidate cohort for staged rollout.
That separation matters operationally: installing or promoting a candidate RPM
is not the same decision as verifying hosts that already claim a release profile.

### AAP Pipeline Separation

The v2 AAP model separates two targeting controls:

- `BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP` selects the host cohort used to
  build, install, and promote a policy candidate.
- `BLASTWALL_AAP_VERIFY_TARGET_GROUP` selects hosts that should be verified for
  the required runtime profile, defaulting to `blastwall_profile_base`.

This avoids a common release trap: treating every stale host as a safe policy
candidate, or treating every policy candidate as already suitable for runtime
verification.

### OpenShift/SPO Compatibility

The OpenShift path keeps `RawSelinuxProfile.status.usage` as the source of
truth, then derives the SCC-compatible SELinux process type for the validated
Calabi OCP 4.20/SPO 0.10 behavior.

For example:

```text
status.usage: blastwall.process
SCC type:     blastwall_.process
```

The direct `status.usage` form remains available as a compatibility mode, but
it is not the default release behavior until live validation proves it works on
the target cluster family.

### Experimental Profile Lane

`strange-socket-v1` is the model for safe policy expansion. It adds first-wave
unusual socket families as a dry-run profile:

- `bluetooth_socket`
- `can_socket`
- `kcm_socket`
- `nfc_socket`
- `rds_socket`
- `tipc_socket`
- `xdp_socket`

It is not folded into `base`. It requires explicit dry-run intent, uses
`state=lab-active`, and has separate RHEL and OpenShift/SPO validation paths.
That lets the project gather evidence without silently changing the default
automation boundary.

### Probe Semantics

Probe results now use a small release vocabulary:

- `BLOCKED`
- `SKIP_ABSENT`
- `FAIL_ALLOWED`
- `FAIL_UNKNOWN`
- `FAIL_MISSING_CLASS_REQUIRED`

Only `EPERM` and `EACCES` count as blocked evidence. Unexpected errno values,
protocol failures, or kernel surprises are not treated as success. This keeps
the release signal honest: a test that did not prove denial does not become
evidence of protection.

## Practical Improvements

For operators, v2 makes Blastwall easier to run safely:

- Host claims are profile-aware and hash-bound.
- AAP can stage policy candidates separately from runtime verification.
- Preflight rejects stale or incomplete evidence before workflow execution.
- Dry-run scope expansion is explicit and reversible.
- OpenShift/SPO binding follows the live cluster usage contract.

For maintainers, v2 makes Blastwall easier to change:

- New scopes must be represented in the registry.
- Drift checks catch missing and extra permissions.
- Safe probes have defined result semantics.
- Docs and release notes have profile and variant anchors.
- Experimental profiles can collect evidence before becoming default posture.

For reviewers, v2 makes Blastwall easier to audit:

- `policy/profiles.yml` explains the intended behavior.
- `tools/check_blastwall_drift.py` proves artifacts match that behavior.
- marker v2 explains what each host is claiming.
- AAP and inventory docs show which hosts are candidates and which are verified.
- OpenShift/SPO compatibility is documented as a validated mode, not guessed
  from static YAML.

## Current Boundaries

v2 is still experimental. The current release candidate does not promote
`strange-socket-v1` into the default posture, does not add KVM or seccomp
hardening, and does not claim broad RHEL/OpenShift generation coverage beyond
the validated Calabi evidence path.

The important release discipline is that `base` remains conservative while new
surfaces move through explicit profile, probe, drift, and lab evidence gates.

## Validation

Use the fast local gate for routine review:

```bash
make test-fast
```

Use the full local gate, including documentation rendering, before publication:

```bash
make test
```

RHEL RPM build and live Calabi/AAP/OpenShift evidence remain environment-bound
release gates rather than generic workstation commands.
