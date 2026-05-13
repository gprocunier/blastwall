# Phase 07 Checkpoint: OpenShift/SPO Strange Socket Gate

Date: 2026-05-11
Branch: `blastwall-v2-phase-07-spo-strange-socket-gate`

## Decision

GO for keeping `strange-socket-v1` as a dry-run OpenShift/SPO profile pair.

NO-GO for promoting the profile into the default `blastwall` or
`blastwallnested` OpenShift workload classes. The lab evidence supports an
explicit opt-in profile, not a silent default posture change.

## Implemented Shape

The default OpenShift/SPO profiles remain unchanged:

- `RawSelinuxProfile/blastwall`
- `RawSelinuxProfile/blastwallnested`

The dry-run strange-socket path is separate:

- `RawSelinuxProfile/blastwallstrange`
- `RawSelinuxProfile/blastwallnestedstrange`
- `SecurityContextConstraints/blastwall-strange`
- `SecurityContextConstraints/blastwall-nested-strange`
- `Job/blastwall-strange-spo-validation`
- `Job/blastwall-nested-strange-spo-validation`

The separate resources prevent the first-wave socket denies from leaking into
ordinary OpenShift workloads.

## Local Validation

PASS: `oc kustomize openshift/spo` renders the new strange resources.

PASS: `BLASTWALL_POLICY_VERSION=0.6.1 BLASTWALL_POLICY_RELEASE=0.rc1 ansible-playbook playbooks/render-spo-policy-crs.yml`

Rendered bundle:

- Path: `/var/tmp/blastwall-policy-pipeline/artifacts/openshift-spo/blastwall-spo-crs.yaml`
- SHA256: `60b7d8803deaa44d34fb81e46beda7aac64ce4abeea90169777789f110d02d38`
- Profiles: `blastwall`, `blastwallnested`, `blastwallstrange`, `blastwallnestedstrange`
- SCCs: `blastwall-confined`, `blastwall-nested`, `blastwall-strange`, `blastwall-nested-strange`

PASS: `python tests/openshift/validate_spo_manifests.py`

PASS: `python -m pytest tests/test_check_blastwall_drift.py -q`

PASS: `python tools/check_blastwall_drift.py`

## Calabi Live Validation

Target:

- Bastion: `cloud-user@172.16.0.30` through `root@172.18.0.224`
- Repo path: `/opt/openshift/aws-metal-openshift-demo/blastwall`
- Kubeconfig: `$HOME/etc/kubeconfig.local`
- OpenShift tools: `/opt/openshift/aws-metal-openshift-demo/generated/tools/4.20.15/bin`

PASS: rendered and applied the SPO bundle using the same apply/validate
playbook path:

```bash
BLASTWALL_POLICY_VERSION=0.6.1 BLASTWALL_POLICY_RELEASE=0.rc1 \
  ansible-playbook playbooks/render-spo-policy-crs.yml

ansible-playbook playbooks/apply-validate-spo-policy-crs.yml \
  -e blastwall_spo_bundle_path=/var/tmp/blastwall-policy-pipeline/artifacts/openshift-spo/blastwall-spo-crs.yaml
```

Observed `status.usage` values:

- `blastwall`: `blastwall.process`
- `blastwallnested`: `blastwallnested.process`
- `blastwallstrange`: `blastwallstrange.process`
- `blastwallnestedstrange`: `blastwallnestedstrange.process`

Derived SCC SELinux types:

- `blastwall_.process`
- `blastwallnested_.process`
- `blastwallstrange_.process`
- `blastwallnestedstrange_.process`

Validation jobs passed:

- `standard_profile: passed`
- `nested_profile: passed`
- `standard-strange_profile: passed`
- `nested-strange_profile: passed`

PASS: worker-scoped validation across `ocp-worker-01`, `ocp-worker-02`, and
`ocp-worker-03`:

```bash
openshift/spo/scripts/validate-blastwall-spo-nodes.sh --class strange --role worker
```

For both `standard-strange` and `nested-strange`, all first-wave socket probes
returned `BLOCKED` on each worker:

- `AF_XDP`
- `AF_TIPC`
- `AF_CAN`
- `AF_BLUETOOTH`
- `AF_NFC`
- `AF_KCM`
- `AF_RDS`

Expected runtime skips:

- `userns`: `SKIP_ABSENT` or nested "second user namespace not required"
- `io_uring_setup`: `SKIP_ABSENT`

Nested strange pods also reported valid `uid_map` and `gid_map` entries.

## Breakage Notes

- The default `blastwall` and `blastwallnested` resources do not contain the
  strange-socket-v1 surfaces. Static validation now asserts this.
- The dry-run strange profiles are opt-in through separate SCCs, service
  accounts, RBAC, validation jobs, and node-scoped harness classes.
- The apply playbook now supports a direct rendered bundle path as well as the
  existing AAP inline artifact path. This enables live bastion validation
  without changing the AAP contract.
- The node validation harness was fixed to parse the last JSON result line
  instead of assuming the final log line is JSON.

## Recommendation

Keep `strange-socket-v1` as lab-only dry-run for now. The OpenShift/SPO path is
ready for continued testing and AAP workflow inclusion, but promotion into
default policy should wait for ordinary workload corpus testing and an explicit
product decision on whether these socket classes belong in the base posture.
