# OpenShift/SPO Compatibility Matrix

Status: version-bounded compatibility evidence

The OpenShift/SPO contract is intentionally narrow. Blastwall reads
`RawSelinuxProfile.status.usage` as the source of truth, then derives the SCC
SELinux type only for known observed usage shapes. Unknown shapes fail closed.

## Proven Mode

Compatibility mode: `calabi-ocp420-rawprofile-underscore`

Cluster: Calabi on-prem OpenShift lab

OCP version: `4.20`

SPO version: `0.10`

Date: 2026-05-15 live Calabi replay on branch
`blastwall-v2-phase-08-rc1k`, commit
`4dca61afba413383ebe48f1b07a1c413bb1affb1`.

Evidence:

- Base and nested:
  `/tmp/blastwall-phase08-rc1k-live-20260515T034134Z/gate10-spo-base-apply-validate.log`
- Strange dry-run:
  `/tmp/blastwall-phase08-rc1k-live-20260515T034134Z/gate11-spo-strange-apply-validate.log`

| RawSelinuxProfile | Observed status.usage | SCC type used | Admitted pod context | Validation class | Result |
|---|---|---|---|---|---|
| `blastwall` | `blastwall.process` | `blastwall_.process` | `blastwall_.process` | standard | PASS |
| `blastwallnested` | `blastwallnested.process` | `blastwallnested_.process` | `blastwallnested_.process` | nested | PASS |
| `blastwallstrange` | `blastwallstrange.process` | `blastwallstrange_.process` | `blastwallstrange_.process` | standard-strange | PASS |
| `blastwallnestedstrange` | `blastwallnestedstrange.process` | `blastwallnestedstrange_.process` | `blastwallnestedstrange_.process` | nested-strange | PASS |

## Non-Default Mode

Mode: `status-usage-direct`

Directly binding SCC `seLinuxOptions.type` to `status.usage` was tested in the
Calabi OCP 4.20/SPO 0.10 lab and rejected by admission. Do not make this the
default unless fresh live validation proves admission and runtime probes pass.

## Runtime Gate

`playbooks/apply-validate-spo-policy-crs.yml` must record:

- raw `.status.usage`
- derived SCC type
- admitted pod SELinux context
- expected process type
- validation class

`openshift/spo/scripts/validate-blastwall-spo-nodes.sh` must reject unknown
usage formats with `FAIL: Unknown OpenShift/SPO status.usage format`.

## Upstream Stability Tracking

Open item: ask the Security Profiles Operator project for guidance on whether
`RawSelinuxProfile.status.usage` is a stable API-level binding input for SCC
SELinux type selection. This response should be recorded here before any broad
OpenShift stable claim.

## Decision

RHEL `base` claims do not depend on SPO. OpenShift claims remain bounded to the
observed Calabi OCP 4.20/SPO 0.10 behavior until the compatibility matrix is
extended with fresh cluster evidence.
