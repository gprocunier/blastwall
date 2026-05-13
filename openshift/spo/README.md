# Blastwall OpenShift/SPO Path

This tree installs the OpenShift workload forms of Blastwall with Security
Profiles Operator (SPO). It does not use a custom RHCOS image and it does not
deliver SELinux policy with MachineConfig.

The OpenShift subject shape is intentionally different from the RHEL login
path:

```text
system_u:system_r:blastwall_.process:s0:cX,cY
system_u:system_r:blastwallnested_.process:s0:cX,cY
system_u:system_r:blastwallstrange_.process:s0:cX,cY
system_u:system_r:blastwallnestedstrange_.process:s0:cX,cY
```

The important OpenShift boundary is the SPO-created process type:
`blastwall_.process` for standard workloads and `blastwallnested_.process` for
nested workloads. The RHEL/IdM/AAP path still uses
`blastwall_u:blastwall_r:blastwall_t:s0` for SSH login sessions on managed
hosts.

SPO usage-to-SCC type resolution is now explicit and supports two modes:

- `calabi-ocp420-rawprofile-underscore` (default): reads `.status.usage` and
  transforms `blastwall.process` into `blastwall_.process` for SCC compatibility.
- `status-usage-direct`: reads `.status.usage` and uses it as-is (for example,
  `blastwall.process` stays `blastwall.process`).

The mode can be selected with:

- `--usage-mode` for
  `openshift/spo/scripts/validate-blastwall-spo-nodes.sh`, or
- `blastwall_spo_selinux_type_resolution_mode` for
  `playbooks/apply-validate-spo-policy-crs.yml`.

The playbook and script both log the selected mode in their evidence output.

## Workload Classes

- `blastwall` is the standard/default class. It denies workload-created user
  namespaces plus xfrm, RxRPC, AF_ALG, BPF, packet socket, and io_uring.
- `blastwall-nested` is the explicit exception class for workloads that need
  pod-level user namespace behavior. It omits the user namespace deny, requires
  `spec.hostUsers: false`, and still denies xfrm, RxRPC, AF_ALG, BPF, packet
  socket, and io_uring.
- `blastwall-strange` and `blastwall-nested-strange` are dry-run opt-in classes
  for `strange-socket-v1`. They add xdp, TIPC, CAN, Bluetooth, NFC, KCM, and
  RDS socket-class probes without changing the default standard or nested
  profiles.

## Apply Order

Verify the RawSelinuxProfile schema on the target cluster first:

```bash
oc explain rawselinuxprofile.spec --api-version=security-profiles-operator.x-k8s.io/v1alpha2
```

Then apply the base resources and read the usage values:

```bash
oc apply -k openshift/spo
oc -n blastwall-spo wait --for=condition=ready rawselinuxprofile/blastwall --timeout=180s
oc -n blastwall-spo wait --for=condition=ready rawselinuxprofile/blastwallnested --timeout=180s
oc -n blastwall-spo get rawselinuxprofile blastwall -o jsonpath='{.status.usage}{"\n"}'
oc -n blastwall-spo get rawselinuxprofile blastwallnested -o jsonpath='{.status.usage}{"\n"}'
```

On the validated OCP 4.20 lab, `status.usage` reports `blastwall.process`
and `blastwallnested.process`, while admitted pods run with the SELinux
runtime types:

```text
blastwall_.process
blastwallnested_.process
```

The static SCC manifests use placeholders. Use
`playbooks/apply-validate-spo-policy-crs.yml` or
`openshift/spo/scripts/validate-blastwall-spo-nodes.sh` to hydrate SCCs and
validation jobs from the target cluster. The harness reads `status.usage`,
derives the SCC-compatible SELinux type, and then validates standard and nested
workloads separately.

Do not bind the SCC directly to `status.usage` by default. Calabi OCP 4.20/SPO
0.10 rejected direct `blastwall.process` admission, while the derived
`blastwall_.process` type matched the admitted pod context. Keep using the default
Calabi mode unless a validated cluster proves otherwise.

## What The Base Applies

- `blastwall-spo` namespace for the SPO profile object.
- `blastwall-workloads` namespace for examples and validation.
- `RawSelinuxProfile/blastwall`, inheriting the OpenShift container policy and
  applying raw CIL deny and neverallow rules to the profile process type.
- `RawSelinuxProfile/blastwallnested`, the enforcement resource for the public
  `blastwall-nested` class. It omits only the user namespace deny for
  pod-level user namespace workloads.
- `SecurityContextConstraints/blastwall-confined`, hydrated from the standard
  profile usage without fixing the namespace MCS level.
- `SecurityContextConstraints/blastwall-nested`, hydrated from the nested
  profile usage with `userNamespaceLevel: RequirePodLevel` and without fixing
  the namespace MCS level. Its UID and group strategy fields use
  `RunAsAny` because OpenShift interprets those IDs inside the pod user
  namespace.
- Separate service accounts and RBAC for `blastwall-runner` and
  `blastwall-nested-runner`, plus a probe ConfigMap.

## Strange Overlay

Apply the `strange-socket-v1` overlay when you want the opt-in dry-run class.

```bash
oc apply -k openshift/spo-overlays/strange-socket-v1
oc -n blastwall-spo wait --for=condition=ready rawselinuxprofile/blastwallstrange --timeout=180s
oc -n blastwall-spo wait --for=condition=ready rawselinuxprofile/blastwallnestedstrange --timeout=180s
oc -n blastwall-spo get rawselinuxprofile blastwallstrange -o jsonpath='{.status.usage}{"\n"}'
oc -n blastwall-spo get rawselinuxprofile blastwallnestedstrange -o jsonpath='{.status.usage}{"\n"}'
```

When included, the overlay adds:

- `RawSelinuxProfile/blastwallstrange` and
  `RawSelinuxProfile/blastwallnestedstrange`, the opt-in dry-run
  `strange-socket-v1` profile resources.
- `SecurityContextConstraints/blastwall-strange` and
  `SecurityContextConstraints/blastwall-nested-strange`, hydrated from the
  matching dry-run profile usage.
- `strange-socket-v1/tests/50-validation-job-strange.yaml` and
  `RoleBasedAccessControl` objects
  used by strange-class validation.

The SCC denies privileged containers, host networking, host PID, host IPC, host
ports, hostPath volumes, privilege escalation, and added capabilities.

## Example Workload

```bash
oc apply -f openshift/spo/examples/blastwall-protected-deployment.yaml
oc apply -f openshift/spo/examples/blastwall-nested-deployment.yaml
oc -n blastwall-workloads rollout status deploy/blastwall-demo
oc -n blastwall-workloads rollout status deploy/blastwall-nested-demo
oc -n blastwall-workloads exec deploy/blastwall-demo -- \
  sh -c 'id -Z 2>/dev/null || cat /proc/self/attr/current'
oc -n blastwall-workloads exec deploy/blastwall-nested-demo -- \
  sh -c 'id -Z 2>/dev/null || cat /proc/self/attr/current; cat /proc/self/uid_map; cat /proc/self/gid_map'
```

The standard deployment uses `openshift.io/required-scc: blastwall-confined`
and `blastwall-runner`. The nested deployment uses
`openshift.io/required-scc: blastwall-nested`, `blastwall-nested-runner`, and
`spec.hostUsers: false`.

## Node Validation

Run safe probes with:

```bash
openshift/spo/scripts/validate-blastwall-spo-nodes.sh --class both --all
openshift/spo/scripts/validate-blastwall-spo-nodes.sh --class strange --role worker
```

The harness only attempts entry-point probes. It does not run exploit code.
`PASS`, `BLOCKED`, `SKIP`, and `SKIP_ABSENT` are acceptable per-probe outcomes.
`FAIL` means a protected surface succeeded or the pod did not run with the
expected SELinux type.

Infra and control-plane validation depends on cluster scheduling policy. Use
`--role infra`, `--role master`, or `--selector` only when those nodes are meant
to accept this non-privileged test pod.

## OpenShift Version Assumption

The nested SCC uses `userNamespaceLevel: RequirePodLevel`, validated on the
OCP 4.20 lab. Operators should verify support with:

```bash
oc explain scc.userNamespaceLevel
oc explain pod.spec.hostUsers
```

This tree contains only OpenShift/SPO resources and examples. Fleet governance
objects are not part of this bundle.
