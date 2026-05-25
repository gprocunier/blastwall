# blastwall v3

`blastwall` is a proof of concept for privileged automation security on RHEL.
The core idea is unchanged from the original project: automation should not
arrive on managed hosts with the same unconstrained local shape as a human
administrator.

The v3 branch turns that proof into a signed-evidence reference exemplar. IdM
records which automation identity may reach which host, AAP acts on that state,
SELinux confines the session after login, and stable-v3 preflight verifies
signed evidence before a selected host is trusted for launch.

## What v3 Changes

v1 proved the host-local SELinux boundary. v2 made the policy posture
profile-aware and release-checkable. v3 keeps those controls and changes the
trust model:

```text
v2 marker:
  The marker is the structured host claim.

v3 marker:
  The marker is a locator.
  Signed evidence, latest-generation index state, and live host checks are the
  trust proof.
```

Stable-v3 requires the marker-referenced attestation envelope to be visible in
the configured KRA-backed IdM vault path, signed by a trusted signer, current
according to the latest-generation index, bound to the requested host/profile
set, and consistent with live policy state on the host. A marker alone cannot
make a host suitable.

## Start Here

| Need | Start With |
| --- | --- |
| Review the v3 trust and evidence model | [`External Review Packet`](docs/blastwall-v3/external-review-packet.md) |
| Understand marker-as-locator and signature verification | [`Signed Attestation Design`](docs/blastwall-v3/signed-attestation-design.md) |
| Operate the reference path | [`Operator Runbook`](docs/blastwall-v3/operator-runbook.md) |
| Understand custody, breakglass, and adopter expectations | [`Operational Guidance`](docs/blastwall-v3/operational-guidance.md) |
| Review KRA/vault topology | [`KRA Topology Runbook`](docs/blastwall-v3/kra-topology-runbook.md) |
| Review revocation and exception handling | [`Revocation and Breakglass`](docs/blastwall-v3/revocation-and-breakglass.md) |
| Understand OpenShift workload confinement | [`OpenShift/SPO`](https://blastwall.org/openshift-spo.html) |
| Record the OpenShift workload proof | [`OpenShift/SPO Demo`](https://blastwall.org/openshift-spo-demo.html) |
| Inspect current evidence | [`Evidence Index`](docs/blastwall-v3/evidence-index.md) |
| Check readiness before operating the pattern | [`Stable-v3 Readiness Checklist`](docs/blastwall-v3/stable-v3-readiness-checklist.md) |
| Assign local ownership before operation | [`Adopter Governance Worksheet`](docs/blastwall-v3/governance-owner-assignment.md) |
| See how v1 and v2 led to v3 | [`v3 Design Journey`](v3-experimental-README.md) |

The original GitHub Pages site remains the root public entry point for the
earlier Blastwall proof: <https://blastwall.org/>. This branch is the current
signed-evidence documentation and implementation line.

## What The Reference Exemplar Demonstrates

Blastwall v3 joins four responsibilities that are usually discussed separately:

| Part | Role In v3 |
| --- | --- |
| SELinux | Enforces the host-local automation boundary after login. |
| IdM | Records identity, host scope, HBAC, sudo, SELinux maps, marker hints, and KRA-backed vault artifacts. |
| `eigenstate.ipa` | Turns IdM state into inventory facts and provides access-path, sudo-risk, vault-health, and vault-artifact checks. |
| AAP | Launches signing, promotion, preflight, runtime verification, inventory audit, and scheduled evidence workflows. |

The Calabi reference topology exercises the signed evidence path with
service-owned custody, destructive failure cases, revocation, scoped
breakglass, and continuous verification. It is evidence for this reference
topology and operating model; adopters should complete their own ownership,
retention, and scale evidence before treating the pattern as a local operating
control.

## Repository Map

| Path | Purpose |
| --- | --- |
| `docs/blastwall-v3/` | v3 design, runbooks, evidence packet, readiness checklist, and adopter worksheet. |
| `tools/blastwall_attestation_*.py` | Signing, verification, vault, index, and audit helper surfaces. |
| `playbooks/` | AAP/Ansible workflows for signing, promotion, preflight, health, audit, and runtime verification. |
| `aap/` | Controller configuration-as-code for v3 job templates, credentials, workflows, and schedules. |
| `policy/` | SELinux reference-policy module, CIL deny rules, and profile registry. |
| `openshift/spo/` | OpenShift Security Profiles Operator path and validation harness. |
| `inventory/` | `eigenstate.ipa.idm` inventory source for AAP. |
| `poc-calabi/` | Calabi lab overlay used to record and replay the proof. |

## Requirements

- RHEL or compatible hosts with SELinux enforcing.
- IdM/FreeIPA with KRA for identity state and attestation artifact custody.
- AAP/Automation Controller for the Controller-based workflow.
- [`eigenstate.ipa`](https://gprocunier.github.io/eigenstate-ipa/) 1.18.1 or
  newer for inventory-aware IdM state and v3 vault/access helpers.
- OpenShift with Security Profiles Operator for the OpenShift workload path.
- Ansible collection dependencies from `collections/requirements.yml`.

Install collection dependencies with:

```bash
ansible-galaxy collection install -r collections/requirements.yml
```

## Local Validation

Run the fast local release checks with:

```bash
make test-fast
```

Run the full local suite, including Playwright documentation rendering, with:

```bash
make test
```

Targeted v3 documentation and policy checks:

```bash
python3 tests/policy_static.py
npm run test:policy
npm run test:docs
```

SELinux policy compilation requires the platform policy development Makefile.
Use `make policy-check` or `make policy-build` only on hosts with
`selinux-policy-devel` installed. RPM release artifacts are built through
`playbooks/build-policy-rpm.yml` on a RHEL-capable bastion or AAP target; the
root `make rpm` target documents that boundary rather than packaging locally.
