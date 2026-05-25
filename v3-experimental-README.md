# Blastwall v3 Design Journey

This note explains the design journey from the original Blastwall proof through
the v3 signed-evidence reference exemplar. For the current v3 front door, start
with [`README.md`](README.md) and the
[`external review packet`](docs/blastwall-v3/external-review-packet.md).

Blastwall v3 continues the same core idea from v1 and v2: privileged automation
should not arrive on a managed host with the same unconstrained local shape as a
human administrator.

The v3 change is about trust. v1 proved host-local SELinux enforcement. v2 made
the policy posture profile-aware, hash-bound, and release-checkable. v3 keeps
those controls and adds signed evidence so a host marker is no longer trusted
just because it is present in IdM.

Current branch:

```text
v3
```

Required collection baseline:

```text
eigenstate.ipa >= 1.18.1
```

Current release-candidate RPM identity:

```text
blastwall-selinux-0.6.1-0.rc1
```

## The Journey

Blastwall has moved through three distinct maturity stages.

### v1: Prove the Boundary

v1 answered the first question:

```text
Can privileged automation be placed in a confined SELinux domain and still do
useful operator work?
```

The answer was yes. v1 showed that:

- IdM can decide which automation identity may reach which managed host.
- HBAC, sudo, and SELinux user maps can place that identity into
  `blastwall_u:blastwall_r:blastwall_t:s0`.
- The automation identity can use root EUID without escaping the
  `blastwall_t` domain.
- SELinux can deny high-risk kernel surfaces such as AF_ALG, BPF,
  packet sockets, user namespaces, `io_uring`, xfrm, and RxRPC.
- The proof can be replayed through Ansible, AAP, and OpenShift/SPO paths.

That was the enforcement proof. It made Blastwall real.

### v1 Problem: One Posture, Too Much Implicit State

The v1 tree treated Blastwall mostly as one posture. That was acceptable for a
proof, but it was weak release engineering.

The hard parts were:

- Policy scope was implicit across CIL, OpenShift/SPO YAML, probes, playbooks,
  demos, and docs.
- A permission could drift in one artifact without being caught elsewhere.
- Probe evidence did not have strict enough release semantics.
- AAP candidate rollout and runtime verification were too easy to blur.
- Host markers were useful operational evidence but not a rich, versioned
  contract.
- New vulnerability response needed a safe lane for deciding whether a surface
  belongs in default posture or in experimental evidence gathering.

In short: v1 proved enforcement, but it did not make the enforcement contract
easy enough to audit or evolve.

### v2: Make the Contract Release-Checkable

v2 answered the second question:

```text
Can Blastwall turn the v1 proof into a profile-aware control plane with
repeatable release gates?
```

v2 added the release contract around the enforcement model.

The central piece is `policy/profiles.yml`. It records targets, profiles,
scopes, permissions, and expected evidence. The registry does not generate the
policy. It defines what the handwritten policy, OpenShift/SPO manifests, tests,
docs, and playbooks must agree on.

v2 made these changes:

- `base` became an explicit profile rather than an implied bundle.
- `base-nested` became the OpenShift/SPO nested workload variant.
- `strange-socket-v1` became a dry-run profile for experimental socket-family
  expansion.
- Drift checking started failing on missing and extra permissions.
- Marker v2 carried profile, scope, registry hash, policy hash, RPM identity,
  target, and state.
- Preflight moved from broad regex validation to parser-backed marker checks.
- IdM inventory gained profile-aware groups.
- AAP separated policy candidate rollout from runtime profile verification.
- OpenShift/SPO kept `RawSelinuxProfile.status.usage` as source of truth while
  preserving the Calabi-proven derived SCC type behavior.
- Probe results were standardized around `BLOCKED`, `SKIP_ABSENT`,
  `FAIL_ALLOWED`, `FAIL_UNKNOWN`, and `FAIL_MISSING_CLASS_REQUIRED`.

The current active `base` posture covers these scopes:

- `alg_socket`
- `bpf`
- `capability2_bpf`
- `packet_socket`
- `userns`
- `io_uring`
- `xfrm`
- `rxrpc`
- `selfprotect`

Dirty Frag and Fragnesia fit that model without creating a new default profile.
Their relevant entry points map onto existing base surfaces: xfrm, RxRPC,
AF_ALG, and user namespaces. The safe probe checks entry-point reachability; it
does not execute exploit payload logic.

### v2 Problem: The Marker Was Still a Claim

v2 made host claims structured and release-checkable, but the marker remained a
string stored in IdM `userClass`.

A v2 marker can say:

```text
blastwall:v=2;state=active;target=rhel-login;rpm=...;registry_sha256=...;policy_sha256=...;profiles=base;scopes=...
```

That is useful. It is not cryptographic attestation.

If a principal has enough authority to write marker-like host metadata, the
marker can become a convincing claim unless preflight independently verifies the
host. v2 does perform parser and hash checks, but the marker itself is still the
evidence claim.

That is the trust gap v3 addresses.

## v3: Make the Marker a Locator, Not the Proof

v3 answers the third question:

```text
Can Blastwall preserve the v2 release model while requiring signed evidence
before a host is trusted for launch?
```

The v3 model changes the meaning of the marker.

```text
v2 marker:
  The marker is the host evidence claim.

v3 marker:
  The marker points to signed evidence.
  Inventory may use it as a selection hint.
  Preflight must retrieve and verify the signed attestation before launch.
```

The marker is now a locator. The proof is a signed attestation envelope stored
in an IdM vault and verified during preflight.

## What v3 Adds

### Signed Attestation Payloads

The v3 attestation payload binds:

- subject host
- target runtime path
- profile set
- scope set
- registry hash
- installed policy hash
- probe evidence hash
- RPM identity
- source revision
- workflow identity
- signer identity
- validity window
- generation

The payload is canonicalized as JSON and signed using the branch's single
supported signature format. Duplicate JSON keys, unsupported versions,
tampering, expired windows, wrong host binding, wrong profile binding, wrong
registry hash, and wrong policy hash fail closed.

### Signed Envelopes and Latest-Generation Indexes

The signed envelope carries the attestation payload and detached signature.

The latest-generation index prevents replay. Stable-v3 does not accept a valid
old attestation if a newer signed generation exists for the host/profile set.
Revoked indexes and tombstoned artifacts fail closed.

### KRA-Backed IdM Vault Storage

v3 stores attestation artifacts in IdM vault paths backed by KRA. The stable
path now uses `eigenstate.ipa.vault_health` before retrieval and
`eigenstate.ipa.vault_artifact` for envelope and latest-index custody. That
adds an explicit trust dependency:

- LDAP marker visibility is not the same as KRA vault artifact visibility.
- Signer writes and preflight reads must target configured KRA-enabled servers.
- The default stable-v3 topology uses the same KRA primary for signer write,
  signer readback, marker publication, and preflight read.
- Missing artifact and missing index cases have named failure states rather
  than being collapsed into generic preflight failure.

### Marker v3

A v3 marker looks like this:

```text
blastwall:v=3;state=active;target=rhel-login;rpm=...;profiles=base;attest_ref=...;attest_sha256=...;signer_kid=...;exp=...;generation=...
```

The marker does not carry inline proof. It carries enough location and digest
metadata for preflight to retrieve the signed envelope and verify that the
retrieved artifact is the one the marker claimed.

### Stable-v3 Preflight

Stable-v3 preflight requires:

- normalized IdM inventory fields from `eigenstate.ipa.idm`,
- an `eigenstate.ipa.access_path` readiness result for principal, HBAC, sudo,
  and SELinux map state,
- `eigenstate.ipa.sudo_risk` classification without an unapproved high-risk
  finding,
- a healthy KRA/vault plane reported by `eigenstate.ipa.vault_health`,
- a parseable v3 marker,
- successful KRA retrieval of the marker-referenced envelope,
- successful KRA retrieval of the latest-generation index,
- digest match between marker and envelope,
- signer certificate chain to the trusted CA,
- signer key identifier in the allowlist,
- valid signature over canonical payload bytes,
- host, target, RPM, registry, profile, and scope binding,
- live installed-policy hash match,
- latest-generation index match,
- non-expired and non-revoked evidence.

A marker alone cannot make a host suitable in stable-v3.

### AAP Signer and Verifier Separation

v3 separates the signing and verification surfaces:

- The signer workflow receives signer material and KRA write/read custody.
- Promotion verifies signed material before publishing a marker.
- Preflight receives verifier trust material and KRA read custody.
- The signer private key is not attached to preflight or marker promotion.

Stable-v3 rejects shared vault custody. The Calabi reference exemplar records a
service-owned custody path for stable-v3, while explicit transition/RC modes can
still use lab shared custody for bounded compatibility work.

### Audit, Revocation, and Breakglass

v3 inventory still selects; it does not prove launch suitability. Audit can
verify current markers against signed evidence and split infrastructure
visibility failures from host trust failures.

Revocation can invalidate markers, tombstone artifacts, and publish revoked
indexes.

Breakglass is intentionally narrow. It can only apply to attestation
infrastructure visibility failures such as missing envelope or missing index.
It cannot bypass invalid signatures, untrusted signers, policy drift, profile
mismatch, replay, revocation, or host binding failure.

### OpenShift/SPO Attestation Evidence

v3 extends signed evidence to OpenShift/SPO targets without changing the
validated workload posture. SPO attestations require target-specific
`spo_evidence`, while the underlying compatibility rule remains the same as v2:
`RawSelinuxProfile.status.usage` is source of truth, and the Calabi OCP
4.20/SPO 0.10 path keeps the derived underscore SCC type behavior.

## End-to-End Flow

The stable-v3 path is:

```text
source policy + profiles.yml
  -> drift checks and local tests
  -> build policy RPM
  -> install candidate policy
  -> verify managed-host probes and policy hash
  -> create canonical attestation payload
  -> sign envelope
  -> write envelope and latest index to configured KRA vault path
  -> read back and verify envelope and index
  -> publish v3 locator marker to IdM
  -> inventory groups selected hosts from marker hints
  -> preflight retrieves KRA artifacts
  -> preflight verifies signature, index, binding, and live policy hash
  -> runtime workflow proceeds only after verification passes
```

## Current Evidence

The current v3 branch is ready as a reference exemplar publication. The current
evidence packet lives in:

- `docs/blastwall-v3/external-review-packet.md`
- `docs/blastwall-v3/evidence-index.md`
- `docs/blastwall-v3/calabi-negative-evidence.md`
- `docs/blastwall-v3/failure-state-manifest.yml`
- `docs/blastwall-v3/final-stable-v3-decision.md`

The Calabi reference topology records healthy service-owned custody evidence,
signed policy pipeline evidence, runtime verification, inventory audit,
destructive failure cases, revoked-attestation handling, scoped breakglass, and
scheduled continuous verification. The evidence proves the reference path and
operating pattern; adopters should add local ownership, retention, escalation,
and scale evidence before treating the pattern as their own operating control.

## What v3 Does Not Claim

v3 signed attestation does not make Blastwall independent of trusted
infrastructure.

It does not protect against:

- full IdM compromise,
- full AAP controller compromise,
- compromise of the signing key,
- authorized signing of malicious policy,
- SELinux disabled on the host,
- kernel compromise that disables MAC enforcement,
- sudo expansion that routes around the intended boundary.

The current implementation also does not claim broad RHEL or OpenShift
generation coverage beyond the validated Calabi path.

The v3 claim is narrower and more precise:

```text
In stable-v3 mode, a selected host is not trusted merely because IdM contains a
marker. The marker must point to signed evidence, the evidence must be current,
the signer must be trusted, the latest-generation index must agree, and the
host's live policy hash must still match the signed claim.
```

## Practical Improvements

For operators, v3 improves launch safety:

- Inventory remains useful for grouping, but preflight is authoritative.
- Markers are no longer treated as proof.
- Signed evidence has a validity window and generation.
- KRA artifact visibility failures are distinguishable from host trust
  failures.
- Breakglass cannot bypass host verification failures.

For maintainers, v3 improves release discipline:

- v2 profile and drift checks remain in force.
- Signing, promotion, and preflight have separate credentials.
- Replay, revocation, and missing-artifact cases have regression coverage.
- RHEL and OpenShift/SPO attestations use the same envelope and index model.

For reviewers, v3 improves auditability:

- `docs/blastwall-v3/signed-attestation-design.md` explains the trust model.
- `V3_IMPLEMENTATION_LEDGER.md` records implementation phases and live gate
  evidence.
- `docs/blastwall-v3/external-review-packet.md` summarizes current evidence.
- `tools/blastwall_attestation_verify.py` is the core verifier surface.
- `tests/test_blastwall_attestation_verify.py` and related attestation tests
  cover negative trust cases.

## Validation

Use the fast local gate for routine review:

```bash
make test-fast
```

Use the full local gate, including documentation rendering, before publication:

```bash
make test
```

Targeted v3 checks:

```bash
python3 -m pytest -q tests/test_blastwall_attestation.py \
  tests/test_blastwall_attestation_crypto.py \
  tests/test_blastwall_attestation_index.py \
  tests/test_blastwall_attestation_sign.py \
  tests/test_blastwall_attestation_vault.py \
  tests/test_blastwall_attestation_verify.py \
  tests/test_blastwall_attestation_revocation.py

python3 tests/policy_static.py
```

RHEL RPM build and live Calabi/AAP/OpenShift evidence remain environment-bound
release gates rather than generic workstation commands.
