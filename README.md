# blastwall

`blastwall` is a proof of concept for privileged automation security on RHEL.
The idea is simple: automation should not arrive on managed hosts with the same
unconfined local shape as a human operator. Red Hat Identity Management (IdM)
should decide who may run, Ansible Automation Platform (AAP) should act on that
state, and SELinux should confine the session when it reaches the host.

The first concrete target was the [`copy.fail`](https://copy.fail/) exploit
path. The current proof also covers
[`Dirty Frag`](https://github.com/V4bel/dirtyfrag), which was publicly
documented on May 7, 2026 and relies on xfrm-ESP and RxRPC page-cache write
paths. Anthony Green's
[`block-copyfail`](https://github.com/atgreen/block-copyfail) shows the precise
BPF LSM answer for that vulnerability. Blastwall takes a different angle: if a
risky kernel surface should be unavailable to privileged automation identities,
can that mitigation move through the same SELinux, IdM, AAP, and RHEL content
delivery model operators already understand?

That gives Blastwall a dual use. It can react to an unfixed CVE by denying a
risky surface for automation accounts before the whole fleet is patched. It can
also become proactive automation posture: a CI/CD-managed policy boundary that
operators tighten over time as they learn what privileged automation should
never need to do.

This follows from the argument I made in
[`privileged-automation-security`](https://gprocunier.github.io/privileged-automation-security/):
automation moves too quickly and too broadly to inherit every assumption we
make about an interactive privileged shell.

## Start Here

The GitHub Pages site is the best entry point:
[`gprocunier.github.io/blastwall`](https://gprocunier.github.io/blastwall/).

| Need | Start With |
| --- | --- |
| Understand the 2-minute model | [`Architecture`](https://gprocunier.github.io/blastwall/architecture.html) |
| Understand where policy comes from and how it is maintained | [`Day 2 Operations`](https://gprocunier.github.io/blastwall/day2-operations.html) |
| Understand the OpenShift workload path | [`OpenShift/SPO`](https://gprocunier.github.io/blastwall/openshift-spo.html) |
| Understand the v1 -> v2 -> v3 experimental architecture | [`v3 Experimental README`](v3-experimental-README.md) |
| Review v2 release semantics and backlog | [`Release Notes`](https://gprocunier.github.io/blastwall/blastwall-v2/release-notes.md) |
| Watch the operator-facing proof | [`AAP Demo`](https://gprocunier.github.io/blastwall/aap-demo.html) |
| Inspect the bootstrap and host-local mechanics | [`Ansible Demo`](https://gprocunier.github.io/blastwall/demo.html) |
| Reproduce the AAP recording | [`AAP Lab`](https://gprocunier.github.io/blastwall/quick-demo.html) |
| Reproduce the Ansible-only proof | [`Ansible Lab`](https://gprocunier.github.io/blastwall/ansible-lab.html) |
| Record the OpenShift/SPO proof | [`OpenShift/SPO Demo`](https://gprocunier.github.io/blastwall/openshift-spo-demo.html) |
| Understand the IdM relationship model | [`IdM Control Model`](https://gprocunier.github.io/blastwall/idm-control-model.html) |
| Understand the SELinux boundary | [`SELinux Control Model`](https://gprocunier.github.io/blastwall/selinux-control-model.html) |
| Compare Blastwall with adjacent tools | [`Comparison`](https://gprocunier.github.io/blastwall/comparable-approaches.html) |
| Review assumptions and attack paths | [`Threat Model`](https://gprocunier.github.io/blastwall/threat-model.html) |
| Look up terms and acronyms | [`Glossary`](https://gprocunier.github.io/blastwall/glossary.html) |
| Look up exact objects and expected outputs | [`Reference`](https://gprocunier.github.io/blastwall/reference.html) |

## What It Proves

Blastwall joins four responsibilities that are usually discussed separately:

| Part | Role |
| --- | --- |
| SELinux | Enforces the host-local automation boundary. |
| IdM | Records identity, host scope, HBAC, sudo, SELinux user maps, and host markers. |
| `eigenstate.ipa` | Reads IdM state into inventory-visible facts. |
| AAP | Launches workflows, runs preflight checks, selects suitable hosts, and records evidence. |

The recorded demos show that an automation identity can land in
`blastwall_u:blastwall_r:blastwall_t:s0`, use sudo without escaping that
domain, and hit denied AF_ALG, BPF, packet_socket, userns, io_uring, xfrm, and
RxRPC probes.
The userns denial is the clearest proactive posture example: user namespaces are
often useful in exploit chains, and this automation identity has no expected
reason to create them.
The AAP path also shows Controller-visible credential smoke, IdM inventory sync,
preflight selection, workflow node status, and managed-host verification output.

## Repository Map

| Path | Purpose |
| --- | --- |
| `policy/` | SELinux reference-policy module and CIL deny rule. |
| `openshift/spo/` | Security Profiles Operator profile, SCC, RBAC, examples, and UBI-based validation harness for OpenShift workloads. |
| `idm/` | IdM group, hostgroup, HBAC, sudo, and SELinux user-map examples. |
| `inventory/` | `eigenstate.ipa.idm` inventory source for AAP. |
| `playbooks/` | Preflight, deployment, credential smoke, and verification playbooks. |
| `aap/` | Controller configuration-as-code for the AAP workflow. |
| `execution-environment/` | AAP execution environment definition. |
| `poc-calabi/` | Calabi lab overlay used to record and replay the proof. |
| `docs/` | GitHub Pages documentation and recordings. |
| `docs/blastwall-v2/` | v2 profile model, marker contract, release notes, developer guide, checkpoints, and backlog. |

## Requirements

- RHEL or compatible hosts with SELinux enforcing.
- IdM/FreeIPA for identity, HBAC, sudo, SELinux user mapping, and host markers.
- AAP/Automation Controller for the Controller-based workflow.
- OpenShift with Security Profiles Operator for the OpenShift workload path.
- [`eigenstate.ipa`](https://gprocunier.github.io/eigenstate-ipa/) for
  inventory-aware IdM state.
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

SELinux policy compilation requires the platform policy development Makefile.
Use `make policy-check` or `make policy-build` only on hosts with
`selinux-policy-devel` installed. RPM release artifacts are built through
`playbooks/build-policy-rpm.yml` on a RHEL-capable bastion or AAP target; the
root `make rpm` target documents that boundary rather than packaging locally.

## Documentation Shape

The docs intentionally separate reader needs:

- `architecture.html` explains the control chain and authority boundaries.
- `day2-operations.html` explains where policy comes from, how operators build
  a baseline disposition, and how new CVEs become tested deny scopes.
- `openshift-spo.html` explains the OpenShift workload confinement path with
  Security Profiles Operator, SCC selection, and safe node validation.
- `blastwall-v2/release-notes.md` freezes the v2 profile semantics, including
  the stable `base` and `base-nested` profiles and the dry-run
  `strange-socket-v1` profile.
- demo pages explain what the recordings prove.
- lab pages guide replay from a prepared environment.
- comparison and threat-model pages review scope fit, assumptions, attack
  paths, and residual risk.
- glossary and reference pages define terms, exact objects, and expected
  outputs.

That split keeps the landing page and README from becoming a maze of setup
steps, architecture debate, and term definitions.
