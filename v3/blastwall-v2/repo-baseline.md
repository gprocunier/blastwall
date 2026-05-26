# Blastwall v2 Repository Baseline

Phase 00 records the current Blastwall repository state before profile-aware
control-plane work begins. It is intentionally descriptive: no policy,
inventory, marker, AAP, or OpenShift behavior changes are introduced here.

## Starting State

- Branch: `blastwall-v2-phase-00-repo-baseline`
- Starting branch before Phase 00: `main`
- Starting worktree state: clean
- Current policy version: `0.5.2`
- Current policy release: `1`
- Current RPM NEVRA: `blastwall-selinux-0.5.2-1`

Version anchors are spread across:

- `policy/Makefile`
- `poc-calabi/group_vars/all.yml`
- `playbooks/build-policy-rpm.yml`
- `playbooks/install-policy-rpm.yml`
- `playbooks/deploy-policy.yml`
- `playbooks/promote-policy-rpm.yml`
- `playbooks/render-spo-policy-crs.yml`
- `.github/workflows/policy-pipeline-smoke.yml`

## Repository Layout

| Path | Current role |
|---|---|
| `policy/` | RHEL login SELinux source, support modules, deny CIL modules, and local Makefile. |
| `tests/` | RHEL safe probes, static policy tests, inventory grouping tests, docs tests, and OpenShift/SPO static validation. |
| `openshift/spo/` | OpenShift Security Profiles Operator manifests, SCC bindings, validation job, examples, and helper scripts. |
| `playbooks/` | Generic Ansible build, install, deploy, preflight, verification, marker promotion, and SPO render/apply paths. |
| `inventory/` | Generic `eigenstate.ipa.idm` inventory source for IdM host/userClass marker grouping. |
| `aap/` | Generic Automation Controller object configuration and variables. |
| `poc-calabi/` | Calabi-specific Ansible and AAP lab overlay. |
| `execution-environment/` | AAP execution environment definition and dependencies. |
| `docs/` | Static GitHub Pages documentation and diagram assets. |
| `.github/workflows/` | CI, lab smoke, and policy-pipeline smoke workflows. |

## Build, Packaging, and Test Entry Points

| Entry point | Purpose |
|---|---|
| `make -C policy check` | Confirms policy source and listed CIL modules exist. |
| `make -C policy` | Builds `blastwall.pp` through SELinux devel Makefile. |
| `make -C policy install` | Installs `blastwall.pp`, support CIL, and deny CIL modules with `semodule -i`. |
| `playbooks/build-policy-rpm.yml` | Builds `blastwall-selinux` RPM from the checked-out policy source. |
| `playbooks/install-policy-rpm.yml` | Installs a candidate policy RPM on target hosts. |
| `playbooks/deploy-policy.yml` | Deploys policy modules, SELinux user context, and optional IdM marker. |
| `playbooks/promote-policy-rpm.yml` | Publishes a verified marker after candidate validation. |
| `playbooks/render-spo-policy-crs.yml` | Renders the OpenShift/SPO CR bundle as an AAP artifact. |
| `playbooks/apply-validate-spo-policy-crs.yml` | Applies and validates rendered OpenShift/SPO CRs in a cluster. |
| `npm run test:policy` | Runs policy static checks, inventory grouping checks, and OpenShift/SPO manifest checks. |
| `npm run test:openshift` | Runs only OpenShift/SPO static manifest checks. |
| `npm run test:docs` | Runs Playwright documentation rendering tests. |

CI runs docs, policy static tests, and Ansible syntax checks in
`.github/workflows/ci.yml`. A separate self-hosted
`.github/workflows/policy-pipeline-smoke.yml` launches the AAP policy pipeline.

## Current Base Deny Scope Map

The current RHEL login enforcement anchor is `policy/Makefile`:

- `SUPPORT_POLICIES := blastwall-sshd-login`
- `DENY_POLICIES := blastwall-alg-socket-deny blastwall-bpf-deny blastwall-policy-selfprotect blastwall-packet-socket-deny blastwall-userns-deny blastwall-io-uring-deny blastwall-xfrm-deny blastwall-rxrpc-deny`

| Scope | RHEL artifact | Probe or validation | OpenShift/SPO standard | OpenShift/SPO nested | Notes |
|---|---|---|---|---|---|
| `alg_socket` | `policy/blastwall-alg-socket-deny.cil` | `tests/trigger-copyfail-afalg.py`; `playbooks/verify-managed-host.yml` copies/runs it. | `openshift/spo/10-rawselinuxprofile-blastwall.yaml` | `openshift/spo/11-rawselinuxprofile-blastwall-nested.yaml` | Safe AF_ALG/authencesn bind probe. |
| `bpf` | `policy/blastwall-bpf-deny.cil` | `tests/trigger-bpf-deny.py`; static checks in `tests/policy_static.py`. | `openshift/spo/10-rawselinuxprofile-blastwall.yaml` | `openshift/spo/11-rawselinuxprofile-blastwall-nested.yaml` | Probe covers `BPF_MAP_CREATE` and `BPF_PROG_LOAD`. |
| `capability2_bpf` | Combined in `policy/blastwall-bpf-deny.cil` | Static OpenShift expected surface only; no dedicated runtime probe. | `openshift/spo/10-rawselinuxprofile-blastwall.yaml` | `openshift/spo/11-rawselinuxprofile-blastwall-nested.yaml` | Treat as a separate registry scope even though RHEL CIL shares the BPF module. |
| `packet_socket` | `policy/blastwall-packet-socket-deny.cil` | `tests/trigger-packet-socket-deny.py`; `playbooks/verify-managed-host.yml` copies/runs it. | `openshift/spo/10-rawselinuxprofile-blastwall.yaml` | `openshift/spo/11-rawselinuxprofile-blastwall-nested.yaml` | Safe AF_PACKET socket creation probe. |
| `userns` | `policy/blastwall-userns-deny.cil` | `tests/trigger-userns-deny.py`; `tests/openshift/blastwall_spo_probe.py`. | `openshift/spo/10-rawselinuxprofile-blastwall.yaml` | intentionally absent | Nested is a controlled delta that omits only user namespace denial. |
| `io_uring` | `policy/blastwall-io-uring-deny.cil` | `tests/trigger-io-uring-deny.py`; `tests/openshift/blastwall_spo_probe.py`. | `openshift/spo/10-rawselinuxprofile-blastwall.yaml` | `openshift/spo/11-rawselinuxprofile-blastwall-nested.yaml` | RHEL CIL uses an optional block for policy generations without the class. |
| `xfrm` | `policy/blastwall-xfrm-deny.cil` | `tests/trigger-dirtyfrag-deny.py`; `tests/openshift/blastwall_spo_probe.py`. | `openshift/spo/10-rawselinuxprofile-blastwall.yaml` | `openshift/spo/11-rawselinuxprofile-blastwall-nested.yaml` | Covers `netlink_xfrm_socket`. |
| `rxrpc` | `policy/blastwall-rxrpc-deny.cil` | `tests/trigger-dirtyfrag-deny.py`; `tests/openshift/blastwall_spo_probe.py`. | `openshift/spo/10-rawselinuxprofile-blastwall.yaml` | `openshift/spo/11-rawselinuxprofile-blastwall-nested.yaml` | Required RxRPC class evidence is `FAIL_MISSING_CLASS_REQUIRED` when the class is absent. |
| `selfprotect` | `policy/blastwall-policy-selfprotect.cil` | `poc-calabi/35-test-self-protection.yml`; static deny/neverallow check. | absent | absent | RHEL-login-only protection for SELinux policy manipulation paths. |

## Current OpenShift/SPO State

OpenShift currently uses `RawSelinuxProfile`, not plain `SelinuxProfile`.

| Resource | File | Current behavior |
|---|---|---|
| `RawSelinuxProfile/blastwall` | `openshift/spo/10-rawselinuxprofile-blastwall.yaml` | Standard profile. Inherits `container`, denies base surfaces including `user_namespace create`. |
| `RawSelinuxProfile/blastwallnested` | `openshift/spo/11-rawselinuxprofile-blastwall-nested.yaml` | Nested variant. Inherits `container`, keeps base denials except user namespace denial. |
| `SecurityContextConstraints/blastwall-confined` | `openshift/spo/20-scc-blastwall-confined.yaml` | Binds workloads to `blastwall_.process`. |
| `SecurityContextConstraints/blastwall-nested` | `openshift/spo/20-scc-blastwall-confined.yaml` | Binds nested workloads to `blastwallnested_.process` and requires pod-level user namespaces. |
| Validation ConfigMap/job | `openshift/spo/40-test-harness-configmap.yaml`, `openshift/spo/tests/50-validation-job.yaml` | Runs pod-level safe probes and verifies context/profile behavior. |

Historical Phase 04 risk visible in the Phase 00 baseline: the SCC manifests and
static tests still hardcoded `blastwall_.process` and `blastwallnested_.process`.
This was superseded by the Phase 04/RC path, where runtime harnesses read
`RawSelinuxProfile.status.usage` and derive the SCC-compatible process type
before validation.

## Current Marker, Inventory, and Preflight State

Current host markers are v1-style `blastwall:` userClass markers, for example:

```text
blastwall:state=active;rpm=blastwall-selinux-0.5.2-1;rpm_sha256=<64hex>;alg=deny;bpf=deny;self=deny;pkt=deny;userns=deny;iou=deny;xfrm=deny;rxrpc=deny
```

Current marker behavior:

- `playbooks/deploy-policy.yml` publishes active or failed markers during policy deployment.
- `playbooks/promote-policy-rpm.yml` publishes active or failed markers during policy pipeline promotion.
- Both current paths write IdM `userclass` values with `freeipa.ansible_freeipa.ipahost`, with a FreeIPA CLI fallback in promotion.
- `inventory/blastwall-idm.yml` and `poc-calabi/aap/inventory/blastwall-idm.yml` group hosts into `blastwall_policy_current`, `blastwall_policy_stale`, and `blastwall_policy_candidate`.
- `tests/inventory_grouping.py` validates marker parsing and current/stale grouping with `tests/fixtures/inventory-policy-markers.json`.
- `playbooks/preflight.yml` selects profile-specific groups such as `blastwall_profile_base` or `blastwall_profile_strange_socket_v1`, records stale hosts, validates IdM HBAC/sudo/SELinux map state, and fails closed when no selected hosts are eligible.

Explicitly absent from the current repository:

- Marker v2 token `blastwall:v=2`
- `profiles=` marker field
- `registry_sha256=` marker field
- `policy_sha256=` marker field
- Central profile registry file

Legacy note: `scripts/update-host-marker.sh` still writes description-style
markers. Static tests require the current playbooks to use `userclass` and clear
legacy description markers.

## Current Documentation State

The public documentation is static HTML under `docs/`, with diagrams in
`docs/assets/diagrams/`.

Relevant current docs:

- `README.md`
- `THREAT-MODEL.md`
- `policy/README.md`
- `AAP-DEMO.md`
- `openshift/spo/README.md`
- `docs/index.html`
- `docs/architecture.html`
- `docs/day2-operations.html`
- `docs/openshift-spo.html`
- `docs/openshift-spo-demo.html`
- `docs/aap-demo.html`
- `docs/ansible-lab.html`
- `docs/reference.html`

## Phase 00 Gaps to Carry Forward

| Gap | Phase impact |
|---|---|
| No central profile registry exists. | Phase 01 should introduce it without changing enforcement. |
| `capability2_bpf` has policy/static coverage but no dedicated runtime probe. | Registry should model the scope honestly and mark probe coverage as shared or missing. |
| `selfprotect` has a Calabi playbook validation path but no standalone `tests/trigger-*` probe. | Registry should treat the evidence source separately from socket/syscall probes. |
| `openshift/spo/20-scc-blastwall-confined.yaml` hardcodes SPO usage strings. | Phase 04 must switch harness/application logic to status-derived `.status.usage` where possible. |
| Current marker is v1-style and NEVRA/SHA keyed, not registry/profile keyed. | Phase 02 must preserve v1 parsing while adding marker v2. |
| `base-nested` is not a durable internal profile name yet. | Phase 01 should map current OpenShift nested behavior as a variant/delta of `base`. |

## Assumptions to Verify in Calabi

Phase 00 does not require Calabi lab validation. Before later gates, verify:

1. RHEL managed hosts are RHEL 9.4 or newer with SELinux enforcing.
2. Installed SELinux userspace supports CIL `deny`.
3. `blastwall_u:blastwall_r:blastwall_t:s0` login transition still works for the managed automation identity.
4. `blastwall-selinux-0.5.2-1` and all listed deny modules are installed on current target hosts.
5. Existing v1 userClass markers match installed RPM and 64-character RPM SHA-256.
6. AAP inventory still groups current/stale hosts as expected.
7. AAP preflight fails closed when only stale hosts are present.
8. OpenShift SPO reports `.status.usage` for both `blastwall` and `blastwallnested`.
9. OpenShift standard and nested validations still show only the intended user namespace delta.
10. Self-protection playbook still proves `blastwall_t` cannot remove deny modules through expanded sudo.

## No Enforcement Delta

This Phase 00 baseline did not modify:

- `policy/`
- `openshift/spo/`
- `playbooks/`
- `inventory/`
- `aap/`
- `poc-calabi/`
- tests or workflows

The only intended repository additions are documentation artifacts under
`docs/blastwall-v2/`.
