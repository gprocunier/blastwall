# Blastwall v2 Profile Model

Blastwall v2 separates operator-facing profiles from implementation scopes.

- A `scope` is one enforceable deny unit, such as `alg_socket`, `bpf`, or
  `io_uring`.
- A `profile` is the named posture an operator can ask for and reason about.
- A `variant` is a controlled delta from a profile, not a separate policy
  family.
- A `target` is a runtime path that consumes a profile, such as RHEL login or
  an OpenShift Security Profiles Operator workload path.

The registry at `policy/profiles.yml` is metadata. It does not generate CIL,
publish markers, install policy, or change enforcement. The hand-written CIL and
OpenShift manifests remain readable source artifacts.

Optional `CIL` wrappers are a portability control, not an evidence contract. They
keep scope artifacts loadable across kernel variants while the registry controls how
absent classes are interpreted in probe outcomes.

## Current Profiles

`base` is the current Blastwall deny posture:

- `alg_socket`
- `bpf`
- `capability2_bpf`
- `packet_socket`
- `userns`
- `io_uring`
- `xfrm`
- `rxrpc`
- `selfprotect`

The May 13, 2026 Fragnesia disclosure does not add a new default scope. It
reuses the existing XFRM/ESP surface already covered by `xfrm`; the published
PoC also needs AF_ALG helper access and ordinary unprivileged namespace setup,
which are covered by `alg_socket` and `userns` on the RHEL login path.

`base-nested` is represented as a variant of `base` for the OpenShift nested
workload path. It removes only `userns`; every other base scope remains part of
the intended nested posture where the target supports it.

Together `base` and `base-nested` are the production OpenShift/SPO postures;
other OpenShift profiles remain opt-in.

`userns` remains part of the RHEL `base` marker contract, but its SELinux object
class is optional in the registry because OpenShift runtime-default seccomp can
surface user namespace creation as `ENOSYS` before SELinux can produce denial
evidence. In that case the OpenShift probe reports `SKIP_ABSENT` explicitly, by
scope contract.

`strange-socket-v1` is a lab-only dry-run profile that extends `base` with the
first unusual socket-family wave:

- `xdp_socket`
- `tipc_socket`
- `can_socket`
- `bluetooth_socket`
- `nfc_socket`
- `kcm_socket`
- `rds_socket`

The profile is packaged only as dry-run payload for the RHEL login target and as
opt-in OpenShift/SPO validation profiles named `blastwall-strange` and
`blastwall-nested-strange`. It is not part of the default install path,
default marker requirement, or production posture. Lab activation requires the
explicit
dry-run install flag or the explicit strange OpenShift workload class, plus
evidence from `tests/trigger-strange-socket-v1-deny.py` or
`tests/openshift/blastwall_spo_probe.py`; `BLOCKED` and `SKIP_ABSENT` are both
acceptable only for optional absent first-wave classes. Unexpected errno values
are `FAIL_UNKNOWN`, and reachable protected surfaces are `FAIL_ALLOWED`.

## Target Notes

The RHEL login path supports the full `base` posture, including policy
self-protection. The OpenShift/SPO standard and nested paths carry the workload
socket/syscall deny posture but do not currently model RHEL login
self-protection.

The registry records known validation gaps instead of hiding them:

- `capability2_bpf` is currently validated by static checks and the combined
  BPF CIL module, but it has no dedicated runtime probe.
- `selfprotect` is validated through the Calabi self-protection playbook rather
  than a standalone `tests/trigger-*` probe.
- `io_uring` rules may remain optional in CIL for portability, while the supported
  RC matrix can still require `FAIL_MISSING_CLASS_REQUIRED` when `io_uring` is
  expected and therefore not optional for that target.
- `strange-socket-v1` remains dry-run. The OpenShift/SPO form is deliberately
  separate from the base `blastwall` and `blastwallnested` profiles so standard
  workloads do not inherit the first-wave socket denies silently.
