# blastwall

`blastwall` is a proof of concept for using SELinux user confinement as an
exploit firewall for privileged automation.

This follows from the argument I made in
[`privileged-automation-security`](https://gprocunier.github.io/privileged-automation-security/):
I do not want automation to inherit the same assumptions as an unconfined human
operator and then move faster.  I want automation to start constrained.  I want
movement out of that constraint to be narrow, deliberate, and visible.

The first concrete target is the Copy Fail exploit path.  This project is
inspired by Anthony Green's
[`block-copyfail`](https://github.com/atgreen/block-copyfail) PoC.  Anthony's
project uses BPF LSM to block only `AF_ALG` binds for `authencesn`.  That is
the right shape when the mitigation needs kernel argument precision.

Blastwall asks a different question.  If the vulnerable path should be blocked
for privileged automation identities, can I make that part of the same
SELinux, IdM, AAP, and content-delivery model I already expect RHEL operators
to understand?  SELinux cannot inspect the `authencesn` algorithm string, so
this PoC blocks the broader surface for mapped automation sessions:
`blastwall_u` domains are denied `alg_socket` access entirely.

## Why This Matters Now

The rate at which new exploit surfaces are discovered is accelerating.
Agentic AI tools can now perform autonomous vulnerability research: code
auditing, fuzzing, binary analysis, and exploit chain construction.  These
tools are compressing the timeline between "vulnerability exists" and "exploit
is weaponized."  What once took dedicated research teams months can now surface
in days or hours.

This changes the risk calculus for automation.  Every automation identity that
runs unconfined is a standing invitation: when the next kernel 0-day drops, that
identity already has the access, the speed, and the reach to move laterally
across the entire fleet before a patch is even available.  Organizations that
adopt broad privileged automation without confinement are building a
superhighway.  High speed, high privilege, low friction, and an attacker only
needs one exploit to get on the road.

The question is not whether a new kernel vulnerability will appear.  It is
whether your automation identities are already constrained enough that the
vulnerability's blast radius is bounded before you even know the CVE number.
Blastwall is designed around that assumption: confine first, deny broad exploit
surfaces for automation by default, and make the confinement lifecycle fast
enough to add new deny scopes as threats emerge, faster than kernel patches
move through the fleet.

A formal threat model covering scope, trust boundaries, adversary capabilities,
and concrete attack paths is in [`THREAT-MODEL.md`](THREAT-MODEL.md).

## Demo Paths

The GitHub Pages site is the best starting point:
[`gprocunier.github.io/blastwall`](https://gprocunier.github.io/blastwall/).

Start with the
[`AAP Demo`](https://gprocunier.github.io/blastwall/aap-demo.html) when the
goal is the show path: Controller health, object inventory, workflow launch,
preflight, node status, job stdout, and managed-host verification.  That is the
operator-facing path I would show first.

Use the
[`Glossary`](https://gprocunier.github.io/blastwall/glossary.html) when the
docs move quickly through AAP, IdM, SELinux, BPF LSM, or Calabi terminology.

Use the
[`Ansible Demo`](https://gprocunier.github.io/blastwall/demo.html) when the
goal is to inspect the bootstrap proof and host-local mechanics.  It shows the
PoC from `bastion-01`: IdM creates and proves `svc-ansible-runner`,
`eigenstate.ipa` validates the read-side gate, direct GSSAPI SSH probes land in
`blastwall_u:blastwall_r:blastwall_t:s0`, the target audit log shows denied
AF_ALG, BPF, packet_socket, and userns activity, the io_uring probe shows
`io_uring_setup` blocked, and the final self-protection step proves SELinux
blocks a sudo-expanded `semodule` breakout.

Both recordings were made in
[`Calabi`](https://gprocunier.github.io/calabi/), my lab project for folding a
realistic disconnected OpenShift and support-services environment into a
controlled nested-KVM system. Calabi is not a required platform for Blastwall.
It is the validation lab I used because it gives the proof a real IdM server,
bastion host, mirror registry, Kerberos flow, and managed endpoint instead of a
mock topology.

### AAP Lab

[`docs/quick-demo.html`](docs/quick-demo.html) is the replay exercise for the
AAP path.  It assumes the Calabi AAP preparation is already in place, then uses
the `awx` CLI to show Controller health, configured objects, workflow launch,
node status, and verification stdout.

### Ansible Lab

[`docs/ansible-lab.html`](docs/ansible-lab.html) is the replay exercise for the
Ansible/bootstrap path.  It follows the playbook chain that creates the IdM
shape, validates the read-side gate, deploys policy, runs direct probes, reads
audit evidence, and proves policy self-protection.

## The Argument

I do not think FreeIPA should author SELinux policy.  I think FreeIPA should
map named identities into SELinux users and roles that already exist on the
endpoint.  I also do not think AAP should discover halfway through a play that
the target host was not in the right confinement state.

The model has four parts:

1. SELinux is the host-local boundary.  Local policy on each managed RHEL host
   defines `blastwall_u`, `blastwall_r`, and the confined automation domain
   `blastwall_root_local_t`.
2. FreeIPA/IdM is the authority.  It maps AAP automation identities into
   `blastwall_u` with an HBAC-linked SELinux user map and carries the host
   groups, sudo rules, and optional coverage markers.
3. [`eigenstate.ipa`](https://gprocunier.github.io/eigenstate-ipa/) is the
   state translator.  It turns IdM state into inventory-visible facts that AAP
   can act on without making Controller parse IdM policy directly.
4. AAP is the actuator and evidence surface.  It syncs the project and
   inventory, runs preflight, chooses current hosts, launches verification, and
   leaves operator-readable workflow and job output.

For readers who do not already live inside FreeIPA/IdM object models, the
published docs include a warmer explanation of this relationship in
[`IdM Control Model`](https://gprocunier.github.io/blastwall/idm-control-model.html).
The short analogy is dispatch and job-site control: AAP dispatches the work,
IdM keeps the records, `eigenstate.ipa` reads those records into inventory
facts, and SELinux enforces the boundary after the session lands.

The point is not to replace kernel patches.  The point is to make privileged
automation land inside a narrow domain where known exploit surfaces can be
blocked quickly while the real fix is still moving through the fleet.

## Inspiration: block-copyfail

`block-copyfail` is the reference point for this work because it shows the
kernel-native shape of the mitigation:

- hook the relevant LSM decision point;
- inspect the syscall argument that contains the algorithm name;
- deny only the vulnerable `authencesn` AF_ALG bind;
- leave unrelated AF_ALG users alone.

That precision is the strength of BPF LSM.  Blastwall does not compete with it
on per-argument filtering.  It borrows the same practical lesson, which is that
the exploit should be stopped before it reaches the vulnerable kernel path, and
then moves the control boundary into the automation trust model.

![Copy Fail precision tool versus Blastwall automation boundary](docs/assets/diagrams/copy-fail-map.svg)

## Why I Would Build This

I would build this because the logistics matter.

In a RHEL automation estate, a versioned SELinux policy RPM is often easier to
stage, promote, audit, and roll back than a new set of eBPF probes.  That does
not make SELinux more precise.  It makes the mitigation fit the machinery that
already exists around RHEL operations.

If the exploit can be mitigated by denying a broad surface for automation
identities, this is the kind of workflow I want:

![Blastwall policy rollout and inventory feedback flow](docs/assets/diagrams/rollout-flow.svg)

That path is operationally ordinary:

- RPM versioning gives the mitigation a concrete artifact name.
- Satellite can stage, promote, pin, report, and roll back the package.
- AAP can install the package with normal `dnf` workflows.
- IdM can expose which identities and hosts are in scope.
- [`eigenstate.ipa`](https://gprocunier.github.io/eigenstate-ipa/) can make
  AAP aware of SELinux maps, HBAC access, sudo policy, and optional host
  coverage markers before a job starts.
- Audit and change control can reason about
  `blastwall-selinux-0.5.0-1` more easily than a dynamically attached probe.

The tradeoff is precision.  BPF LSM can inspect kernel hook arguments and block
one exact shape, such as `authencesn` in `socket_bind`.  Blastwall blocks
broader SELinux surfaces for a specific subject: privileged automation mapped
into `blastwall_u`.

That is often acceptable for automation.  Many AAP jobs do not need
`AF_ALG`, BPF, raw packet sockets, user namespace creation, or `io_uring`.  Blocking
those surfaces for automation identities is part of the point.

The short version:

```text
BPF LSM is the precision tool.
Blastwall is the identity, policy, and delivery model.
```

## What This Adds To AAP And IdM

The important question is not only "can this exploit be blocked?"  It is also:

- which automation identities are allowed to run on this host;
- whether those identities land in a confined SELinux user;
- whether sudo reaches root without escaping confinement;
- whether AAP can tell which hosts have the required mitigation before running;
- whether policy coverage can be versioned, rolled out, and audited through
  IdM-visible host state.

That is where the combination of
[`eigenstate.ipa`](https://gprocunier.github.io/eigenstate-ipa/), AAP, and IdM
matters.  IdM is the source of truth for identity, host scope, HBAC, sudo,
SELinux user mapping, and
optional host policy markers.  AAP consumes that truth before execution.
SELinux provides the host-local enforcement once the automation session lands.

![IdM, eigenstate.ipa, AAP, SSH, and SELinux enforcement flow](docs/assets/diagrams/idm-aap-flow.svg)

The host is not merely patched or unpatched.  For a given job, it is suitable
or unsuitable based on current IdM state and local policy coverage.

## Coverage Expansion Model

Treat Blastwall as a small policy product, not a one-off rule.  If another
high-value exploit surface should be blocked for automation before the fleet is
patched, the workflow is:

1. Define the new exploit surface in terms SELinux can enforce.
2. Add a new policy scope to the Blastwall policy source.
3. Generate and review the updated policy module/RPM.
4. Bump the Blastwall policy version.
5. Roll out the policy to eligible hosts.
6. Update the IdM host marker with the new version and coverage claims.
7. Let AAP inventory and preflight prefer only hosts with the required coverage.

That keeps emergency mitigations from becoming untracked local state.  Each new
rule has a version, a stated scope, and an inventory-visible rollout state.

### Self-Protection Scope

Policy self-protection is now a base Blastwall scope.  It is not an
exploit-specific mitigation like `alg_socket` or `bpf` or `io_uring`.  It protects the wall
itself.

The current self-protection CIL denies `blastwall_t` from executing SELinux
policy-management entry points such as `semodule`, `semanage`, `setsebool`, and
`load_policy`, from using SELinux `security` class permissions such as
`load_policy`, `setenforce`, and `setbool`, and from writing the local SELinux
policy store under the common targeted-policy types.  I deliberately do not deny
process context setters like `setexec` or `setkeycreate`; sudo needs those to
honor the `role=blastwall_r` and `type=blastwall_t` options without falling back
to an unconfined context.

The Calabi validation playbook temporarily adds `/usr/sbin/semodule` to the
Blastwall sudo command group, proves the automation user can see that expanded
sudo surface, then attempts to remove a deny module.  The expected result is not
a sudo rejection.  The expected result is SELinux denying execution from
`blastwall_t` against `semanage_exec_t`, with the Blastwall modules still
installed afterwards.

![Coverage expansion lifecycle from exploit surface to AAP preflight](docs/assets/diagrams/coverage-flow.svg)

## Architecture Flow

![Blastwall architecture flow from AAP job to SELinux denial](docs/assets/diagrams/architecture-flow.svg)

## Repository Layout

- `policy/` - SELinux reference-policy module and login context template.
- `idm/` - IdM object creation example for group, HBAC, sudo, and user map.
- `inventory/` - [`eigenstate.ipa.idm`](https://gprocunier.github.io/eigenstate-ipa/) inventory source for AAP.
- `playbooks/` - AAP/controller preflight and managed-host verification. The
  policy deployment playbook is bootstrap/operator material, not part of the
  confined AAP verification workflow.
- `aap/` - Controller configuration-as-code for the Blastwall AAP path.
- `execution-environment/` - Blastwall AAP execution environment definition.
- `tests/` - safe AF_ALG, BPF, packet_socket, userns, and io_uring probes used to verify denial.
- `poc-calabi/` - Calabi lab exercise for replaying the proof path after
  watching the demo.

## AAP Setup

The AAP path turns Blastwall into a Controller-launched workflow instead of a
manual bastion sequence. The Controller configuration lives under `aap/`, and
the execution environment definition lives under `execution-environment/`.
The full recorded demo path, including the separate AAP landing-zone guidance,
is documented in [`AAP-DEMO.md`](AAP-DEMO.md).
The published AAP recording and breakdown are available at
[`docs/aap-demo.html`](docs/aap-demo.html).

The intended Controller objects are:

- Organization: `Blastwall`
- Project: `Blastwall`, SCM URL `https://github.com/gprocunier/blastwall.git`, branch `main`
- Execution Environment: `Blastwall EE`
- EE image: `registry.example.com/blastwall/blastwall-ee:0.5.0`
- Inventory: `Blastwall IdM Inventory`
- Inventory source: `inventory/blastwall-idm.yml`
- Credential type: `Blastwall IdM Runtime`
- Machine credential: `svc-ansible-runner`
- Workflow template: `Blastwall policy rollout`

The IdM runtime credential injects `IPA_SERVER`, `IPA_DOMAIN`, `IPA_REALM`,
`IPA_PRINCIPAL`, `IPA_CERT`, `KRB5_CONFIG`, and `BLASTWALL_IDENTITY`. For
production-style runs, prefer a least-privilege IdM service principal with
`IPA_KEYTAB`. The password fallback uses `IPA_PASSWORD`; `IPA_ADMIN_PASSWORD`
is still injected as a compatibility alias for the current `eigenstate.ipa`
inventory plugin and accepted by the Calabi lab scripts. The
certificate, Kerberos configuration, and optional keytab are injected as runtime
files; secret values are not stored in this repository. The preflight play
writes a minimal FreeIPA client config inside the execution environment before
using `ipalib`-backed lookups.

Build the EE with:

```bash
ansible-builder build \
  -f execution-environment/execution-environment.yml \
  --build-arg PKGMGR=/usr/bin/microdnf \
  --build-arg PYCMD=/usr/bin/python3.12 \
  -t blastwall-ee:0.5.0
```

In Calabi, the recorded path pushes the EE to the lab's IdM-certified mirror
registry and points the AAP inventory source at the Calabi adapter inventory:

```text
mirror-registry.workshop.lan:8443/blastwall/blastwall-ee:0.5.0
mirror-registry.workshop.lan:8443/blastwall/blastwall-ee:latest
poc-calabi/aap/inventory/blastwall-idm.yml
```

The EE base image is pinned by digest in `execution-environment/` so rebuilds
start from the same Red Hat image. System RPM versions are still resolved by
the subscribed RHEL repositories at build time; capture the final image digest
from your registry if you need a fully locked production artifact.

The Calabi overlay under `poc-calabi/aap/` runs from `bastion-01`, prepares an
IdM demo launcher named `blastwall-demo`, and performs:

```bash
ansible-playbook poc-calabi/aap/00-aap-readiness.yml
ansible-playbook poc-calabi/aap/05-configure-ee-registry.yml
ansible-playbook poc-calabi/aap/10-build-and-push-ee.yml
ansible-playbook poc-calabi/aap/15-prepare-demo-user.yml
ansible-playbook poc-calabi/aap/20-configure-controller.yml
ansible-playbook poc-calabi/aap/25-seed-selection-fixture.yml
ansible-playbook poc-calabi/aap/30-launch-workflow.yml
ansible-playbook poc-calabi/aap/40-collect-evidence.yml
```

Admin access is used for setup and troubleshooting. The workflow itself is
launched by the demo user, while target automation obtains a Kerberos ticket
and connects over SSH as `svc-ansible-runner`.

The recorded operator path uses the conventional `awx` CLI for visible AAP
interaction. The setup playbooks can reconcile Controller state, but the demo
surface should show AAP directly: health, configured objects, workflow launch,
node status, and job stdout.

The hosted CI path still covers static policy checks, docs rendering, and
Ansible syntax. Live enforcement validation belongs to the lab because it needs
Controller, IdM, the EE registry, and the managed host. The manual
`lab-smoke` GitHub Actions workflow is scoped for a self-hosted
`blastwall-lab` runner and launches the AAP workflow, then checks credential
smoke, current/stale host selection, and managed-host denial output.

The AAP workflow is deliberately a current-host verification path. Policy RPM
installation, SELinux policy mutation, and IdM marker publication happen in the
bootstrap or content-delivery path before this workflow runs. That separation is
part of the design: Blastwall self-protection should stop a confined
`blastwall_t` session from changing the policy that confines it.

```mermaid
flowchart LR
  org["Organization: Blastwall"]
  project["Project: Blastwall"]
  ee["Blastwall EE"]
  inventory["Blastwall IdM Inventory"]
  source["inventory/blastwall-idm.yml"]
  idmcred["Blastwall IdM Runtime"]
  machine["svc-ansible-runner"]
  workflow["Blastwall policy rollout"]
  credential["Credential smoke"]
  org --> project
  org --> ee
  org --> inventory
  project --> source --> inventory
  ee --> source
  idmcred --> source
  idmcred --> credential
  idmcred --> workflow
  machine --> workflow
```

```mermaid
flowchart TD
  launch["IdM-backed AAP user launches workflow"]
  project["Project sync"]
  credential["Credential smoke"]
  inventory["IdM inventory sync"]
  preflight["Preflight"]
  fail["Fail closed"]
  verify["Verify managed host"]
  evidence["Collect evidence"]
  launch --> project --> credential --> inventory --> preflight
  preflight -- unsuitable --> fail
  preflight -- suitable --> verify --> evidence
```

## Requirements

Managed RHEL hosts need:

- SELinux enforcing.
- SELinux userspace 3.6 or newer for CIL `deny` rules.
- `selinux-policy-devel`
- `checkpolicy`
- `policycoreutils-python-utils`
- `make`

AAP execution environments that run the preflight need:

- [`eigenstate.ipa`](https://gprocunier.github.io/eigenstate-ipa/)
- `python3-ipalib`
- `python3-ipaclient`
- `krb5-workstation`
- an IdM principal keytab or password, plus a CA certificate

The workflow includes a credential-smoke node before inventory sync. It proves
the injected `Blastwall IdM Runtime` credential can authenticate and read the
expected IdM state before AAP depends on that credential for inventory and
preflight.

Install Ansible collection dependencies with:

```bash
ansible-galaxy collection install -r requirements.yml
```

## Quick Demo Flow

On each managed host, install the local SELinux policy and login context:

```bash
sudo make -C policy install
sudo install -D -m 0644 \
  policy/contexts/blastwall_u \
  /etc/selinux/targeted/contexts/users/blastwall_u
sudo semanage user -a -R blastwall_r -r s0 blastwall_u
```

If `blastwall_u` already exists, modify it instead:

```bash
sudo semanage user -m -R blastwall_r -r s0 blastwall_u
```

In IdM, create the automation group, managed-host group, HBAC rule, sudo rule,
and SELinux user map described by [`idm/bootstrap-blastwall.yml`](idm/bootstrap-blastwall.yml).
The Calabi lab exercise in [`poc-calabi/`](poc-calabi/) shows the full object
creation path with Ansible.

In AAP, sync inventory from:

```text
inventory/blastwall-idm.yml
```

Before any mutation job, run:

```text
playbooks/credential-smoke.yml
playbooks/preflight.yml
```

Then run the managed-host verification:

```text
playbooks/verify-managed-host.yml
```

## Runtime Enforcement Flow

![Runtime enforcement sequence for mapped automation sessions](docs/assets/diagrams/runtime-flow.svg)

## Optional Host Suitability Markers

[`eigenstate.ipa.idm`](https://gprocunier.github.io/eigenstate-ipa/) can
export IdM host attributes into inventory hostvars.
This PoC uses `idm_description` as a simple marker carrier because it is already
available from normal host records.

The bootstrap or policy deployment path writes one marker per verified coverage
claim:

```text
blastwall_policy_rpm=blastwall-selinux-0.5.0-1
blastwall_policy_state=active
blastwall_policy_alg_socket=denied
blastwall_policy_bpf=denied
blastwall_policy_selfprotect=denied
blastwall_policy_packet_socket=denied
blastwall_policy_userns=denied
blastwall_policy_io_uring=denied
```

When coverage expands, add markers only for surfaces that are actually enforced
and locally verified.  Avoid overloading a single boolean; AAP should be able to
ask for the exact policy version and deny scopes a job requires.

Inventory groups then split eligible hosts into:

- `blastwall_policy_current`
- `blastwall_policy_stale`

These markers are supplementary.  They help AAP choose the best candidates
when several hosts are HBAC-eligible.  They do not replace live SELinux, HBAC,
sudo, and runtime verification.

The Calabi AAP demo seeds `stale-blastwall-01.workshop.lan` as an IdM-only
stale host. That lets the AAP workflow show both `selected_hosts` and
`stale_hosts` while verification remains limited to the real current host,
`mirror-registry.workshop.lan`.

![Host suitability marker flow from local proof to AAP target decision](docs/assets/diagrams/marker-flow.svg)

## Candidate Selection With Multiple Coverages

When two hosts are both reachable and mapped into `blastwall_u`, AAP should
prefer the host with the newest policy and the coverage required by the job.  A
job that only needs the Copy Fail mitigation can accept `alg_socket=denied`; a
job responding to a newer exploit can require both the older and newer markers.

![AAP candidate selection with multiple coverage markers](docs/assets/diagrams/candidate-flow.svg)

The markers are not proof by themselves.  The rollout workflow should update
the marker only after local verification confirms the policy is installed and
the expected denial is observable.

## Type Alias Note

The reference-policy user template creates the concrete domain `blastwall_t`.
The policy also defines `blastwall_root_local_t` as a type alias so the public
PoC context names describe the root-local automation intent.  Some SELinux
tools canonicalize aliases back to `blastwall_t`; the verification play accepts
both names as long as the SELinux user and role remain `blastwall_u` and
`blastwall_r`.

## Important Limitation

SELinux can block broad object class access for a confined automation domain.
It cannot match kernel hook arguments such as `authencesn` inside
`struct sockaddr_alg`.  The current policy denies the demonstrated automation
surfaces: `alg_socket` for Copy Fail, `bpf`, `packet_socket`,
`userns_create`, and `io_uring`.  It also carries a self-protection scope that blocks
`blastwall_t` from running SELinux policy-management tools or writing the local
SELinux policy store.  If the requirement is argument-level precision while
preserving other uses of a blocked class, keep using an eBPF LSM mitigation like
Anthony Green's `block-copyfail`.

![SELinux broad class denial versus BPF LSM argument precision](docs/assets/diagrams/limitation-flow.svg)

This PoC uses a CIL `deny` module because current distribution policy may grant
socket permissions through inherited user-domain attributes.  The deny rule
subtracts `alg_socket` access from `blastwall_t`; the paired `neverallow` keeps
future policy changes from silently restoring the permission.

The `io_uring` deny scope uses a CIL `optional` block so the module installs
cleanly on kernels that predate the `io_uring` object class.  When the class
is absent, the deny rule is silently skipped; when the class is present, the
deny and neverallow apply.  This is the convention for any future scope that
references a kernel object class not guaranteed to exist on all supported
RHEL versions.

## When To Choose Which

I would use `block-copyfail`-style BPF LSM when I need the narrowest runtime
mitigation and I want to preserve unrelated AF_ALG use.  It is shaped around
the vulnerable kernel argument, which is exactly why it is useful.

I would use Blastwall when the mitigation should be tied to automation identity,
host scope, and the way RHEL estates are actually operated.  The advantage is
not finer kernel inspection.  The advantage is that the same control plane
answers:

- who may automate this host;
- what SELinux user they receive;
- what sudo policy they inherit;
- what exploit surfaces the host policy claims to cover;
- whether AAP should run, skip, or remediate the host.

The two approaches compose well.  BPF LSM gives me precision at the kernel
hook.  Blastwall gives me an identity-scoped automation boundary and a rollout
record that AAP can use before it touches the host.
