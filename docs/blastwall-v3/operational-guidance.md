# Blastwall v3 Operational Guidance

## Purpose

This guidance defines the operating boundary for stable-v3 claims. Stable-v3
is a signed evidence gate for a defined RHEL, IdM, AAP, KRA, and optional
OpenShift/SPO reference topology. It is not full remote attestation, not a
general fleet portability claim, and not a publication decision while
governance owners remain pending.

Use this document with:

- `docs/blastwall-v3/stable-v3-readiness-checklist.md`
- `docs/blastwall-v3/operator-runbook.md`
- `docs/blastwall-v3/kra-topology-runbook.md`
- `docs/blastwall-v3/revocation-and-breakglass.md`
- `docs/blastwall-v3/evidence-index.md`
- `docs/blastwall-v3/failure-state-manifest.yml`

## Service-Owned Signer And Vault Custody

Stable-v3 must use service-owned or named-user custody for signer and vault
operations. Shared vault scope is lab/RC custody and is rejected for stable-v3
because it blurs the ownership boundary reviewers need to audit.

Stable operation requires:

- a named signer owner;
- a named KRA/vault owner;
- a configured vault primary and explicit server list;
- a vault scope that is not `shared`;
- signer allowlist ownership and review;
- a documented rotation and revocation path.

Transition or RC workflows may still use shared vault custody when they label
it as lab/RC evidence and do not present the result as stable-v3 publication
readiness.

## Signer Separation And Lifecycle

The signer key and AAP workflow may be colocated in RC evidence, but that is
not defense in depth against full AAP compromise. For production-like posture,
prefer a dedicated signer principal, a dedicated signer certificate profile,
and a signer credential that ordinary policy deployment or marker-writing jobs
cannot read.

Required lifecycle expectations:

- signer owner accepts primary and backup responsibility;
- signer certificate issuance profile is documented;
- signer allowlist changes are reviewed;
- signer rotation is rehearsed before publication;
- revoked signer material fails closed in verifier tests;
- AAP preflight and marker promotion do not receive signer private-key access.

## Breakglass Audit Expectations

Breakglass is an infrastructure-visibility exception only. It cannot bypass
signature, signer allowlist, replay, drift, integrity, profile, host binding,
revocation, expiry, or host-security failures.

Every breakglass run must include:

- explicit host scope;
- explicit profile scope matching the requested profile set;
- ticket;
- approver;
- reason;
- timeout;
- post-use review and normal-mode recovery evidence.

If either host verification failure or attestation security failure is present,
do not use breakglass.

## Destructive Re-Capture Triggers

Re-capture destructive evidence when a change touches any verifier/preflight
behavior that operators rely on during a failure.

Required re-capture triggers:

- verifier or preflight failure-state classification changes;
- marker grammar or marker signing/index semantics change;
- AAP workflow wiring changes how artifacts are built, stored, retrieved, or
  verified;
- KRA vault custody path or replica-selection behavior changes;
- failure-state contract in `docs/blastwall-v3/failure-state-manifest.yml`
  changes.

Destructive re-capture is not required for prose-only clarification, provided
the documented failure-state contract and AAP wiring remain unchanged.

## Calabi Evidence Boundary

Calabi evidence proves the current reference path. It does not prove broad
portability across arbitrary IdM, KRA, AAP, RHEL, OpenShift, or SPO generations.

When using Calabi evidence:

- call it reference-topology evidence;
- keep shared-vault Calabi custody labelled as lab/RC custody;
- do not infer S-range readiness from Calabi-only runs;
- preserve job IDs, artifact hashes, branch commits, and restore proofs;
- separate observed runtime behavior from future portability goals.

## Ordinary Automation Corpus Replay

The stable-v3 gate does not replace ordinary automation compatibility testing.
Before expanding a claim, replay ordinary automation against the managed-host
profile set and confirm expected service, package, user, group, systemd, SSH,
and IdM workflows still pass.

If ordinary automation replay expands required SELinux allowances, treat that
as a separate policy-scope change and rerun the relevant evidence packet.

## SPO, KRA, And S-Range Non-Claims

Current OpenShift/SPO evidence is branch evidence for the validated path. It is
not a broad OpenShift generation claim and not cluster-independent runtime
attestation.

Current KRA evidence proves explicit primary-path behavior in the reference
topology. It is not a multi-replica failover or replication-lag claim until a
separate packet proves those cases.

The S-range claim remains on hold until broader mixed-state scale evidence is
captured and reviewed.

## Reference Topology Positioning

The stable-v3 claim should be stated narrowly:

Blastwall v3 is a signed evidence gate for a defined RHEL/IdM/AAP/KRA reference
topology, validated in Calabi, with publication held until governance owners
accept the operating model and stable-v3 custody health is live-green.

Do not present stable-v3 as enterprise-ready publication, S-range proof, broad
RHEL/OpenShift portability, or controller-independent attestation without new
evidence and an updated release decision.
