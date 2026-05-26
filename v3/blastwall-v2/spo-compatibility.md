# OpenShift/SPO Compatibility Matrix

Blastwall treats the Security Profiles Operator reported usage string as the
source of truth. Runtime harnesses must read `RawSelinuxProfile.status.usage`
before binding workloads, then derive the SELinux type accepted by SCC
`seLinuxOptions.type` and validation probe expectations.

Strange OpenShift/SPO profiles are opt-in only and are not rendered in the base
OpenShift bundle by default. They are activated through explicit render/validation
overlays.

In OpenShift/SPO, `blastwall` and `blastwall-nested` are the production
stable workload classes. `blastwall-strange` and `blastwall-nested-strange`
are lab-only, opt-in dry-run profiles.

Usage-mode behavior is explicit and selectable:

- `calabi-ocp420-rawprofile-underscore` (default): derive `blastwall_.process`
  from `blastwall.process`.
- `status-usage-direct`: pass `status.usage` through unchanged.

## Decision Record

| OCP version | SPO version | RawSelinuxProfile | `status.usage` | SCC type used | Admitted pod context | Mode | Result |
|---|---|---|---|---|---|---|---|
| 4.20 | 0.10 | `RawSelinuxProfile/blastwall` | `blastwall.process` | `blastwall_.process` | `blastwall_.process` | `calabi-ocp420-rawprofile-underscore` | PASS |
| 4.20 | 0.10 | `RawSelinuxProfile/blastwallnested` | `blastwallnested.process` | `blastwallnested_.process` | `blastwallnested_.process` | `calabi-ocp420-rawprofile-underscore` | PASS |
| 4.20 | 0.10 | `RawSelinuxProfile/blastwallstrange` | `blastwallstrange.process` | `blastwallstrange_.process` | `blastwallstrange_.process` | `calabi-ocp420-rawprofile-underscore` | PASS (lab opt-in) |
| 4.20 | 0.10 | `RawSelinuxProfile/blastwallnestedstrange` | `blastwallnestedstrange.process` | `blastwallnestedstrange_.process` | `blastwallnestedstrange_.process` | `calabi-ocp420-rawprofile-underscore` | PASS (lab opt-in) |

| OCP version | SPO version | Notes |
|---|---|---|
| older | version-dependent | Do not bind SCC `seLinuxOptions.type` directly to `status.usage`; derive from cluster-reported usage as appropriate for the platform and compare probe context. |

Directly binding SCC `seLinuxOptions.type` to `status.usage` was tested in the
Calabi OCP 4.20/SPO 0.10 lab and rejected by admission. Treat this as a
non-default path. The default
`calabi-ocp420-rawprofile-underscore` mode keeps the derived underscore SCC
type until live validation proves a direct binding is accepted on the target
platform.

## Harness Rules

- Static manifests carry SELinux type placeholders until the target cluster
  reports `status.usage`.
- `playbooks/apply-validate-spo-policy-crs.yml` applies prerequisites, waits for
  RawSelinuxProfile readiness, reads `status.usage`, applies selected mode-based
  resolution, hydrates SCC and validation job objects, and then runs separate
  standard, nested, standard-strange, and nested-strange jobs when the rendered
  bundle includes the dry-run profile.
- `openshift/spo/scripts/validate-blastwall-spo-nodes.sh` follows the same
  runtime path for node-scoped validation pods and writes the selected usage mode
  into the JSON summary artifact.
- Probe code requires `BLASTWALL_EXPECTED_SELINUX_TYPE`; it must not silently
  fall back to a guessed process type.
- Documentation may mention legacy process-type strings only as compatibility
  evidence, not as executable defaults.

`readOnlyRootFilesystem=false` is set for validation-image pods and validation SCC
contexts used to probe the runtime behavior in current RC test paths. It is not a broad
production recommendation for normal workload posture.
