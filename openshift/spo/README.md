# Blastwall OpenShift/SPO Path

This tree installs the OpenShift workload forms of Blastwall with Security
Profiles Operator (SPO). It does not use a custom RHCOS image and it does not
deliver SELinux policy with MachineConfig.

The OpenShift subject shape is intentionally different from the RHEL login
path:

```text
system_u:system_r:blastwall_.process:s0:cX,cY
system_u:system_r:blastwallnested_.process:s0:cX,cY
```

The important OpenShift boundary is the SPO-created process type:
`blastwall_.process` for standard workloads and `blastwallnested_.process` for
nested workloads. The RHEL/IdM/AAP path still uses
`blastwall_u:blastwall_r:blastwall_t:s0` for SSH login sessions on managed
hosts.

## Workload Classes

- `blastwall` is the standard/default class. It denies workload-created user
  namespaces plus xfrm, RxRPC, AF_ALG, BPF, packet socket, and io_uring.
- `blastwall-nested` is the explicit exception class for workloads that need
  pod-level user namespace behavior. It omits the user namespace deny, requires
  `spec.hostUsers: false`, and still denies xfrm, RxRPC, AF_ALG, BPF, packet
  socket, and io_uring.

## Apply Order

Verify the RawSelinuxProfile schema on the target cluster first:

```bash
oc explain rawselinuxprofile.spec --api-version=security-profiles-operator.x-k8s.io/v1alpha2
```

Then apply the base resources:

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

## What The Base Applies

- `blastwall-spo` namespace for the SPO profile object.
- `blastwall-workloads` namespace for examples and validation.
- `RawSelinuxProfile/blastwall`, inheriting the OpenShift container policy and
  applying raw CIL deny and neverallow rules to the profile process type.
- `RawSelinuxProfile/blastwallnested`, the enforcement resource for the public
  `blastwall-nested` class. It omits only the user namespace deny for
  pod-level user namespace workloads.
- `SecurityContextConstraints/blastwall-confined`, requiring type
  `blastwall_.process` without fixing the namespace MCS level.
- `SecurityContextConstraints/blastwall-nested`, requiring type
  `blastwallnested_.process` and `userNamespaceLevel: RequirePodLevel` without
  fixing the namespace MCS level. Its UID and group strategy fields use
  `RunAsAny` because OpenShift interprets those IDs inside the pod user
  namespace.
- Separate service accounts and RBAC for `blastwall-runner` and
  `blastwall-nested-runner`, plus a probe ConfigMap.

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
```

The harness only attempts entry-point probes. It does not run exploit code.
`PASS`, `BLOCKED`, and `SKIP` are acceptable per-probe outcomes. `FAIL` means a
protected surface succeeded or the pod did not run with the expected SELinux
type.

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
