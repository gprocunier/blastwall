# External Review Packet: Blastwall v3 Signed Attestation

## Working Scope

This packet is the review-facing summary for v3 signed attestation controls on Blastwall.
It is focused on trust and failure behavior in host selection, attestation retrieval,
signature verification, and KRA assumptions.

## Executive summary

v3 changes host trust from marker-claimed state to verified signed evidence.

- Host marker is still required for selection.
- Signature is the trust proof.
- Preflight verifies marker binding, signer trust, index freshness, and live host state in stable-v3.
- KRA-backed IdM vault paths are treated as part of the trust dependency graph.
- This branch requires `eigenstate.ipa >= 1.18.1` for normalized inventory,
  `access_path`, `sudo_risk`, `vault_health`, and `vault_artifact`.

## Quick reviewer checklist

- Can a marker be trusted without signed proof? No.
- Can preflight fail closed on host-state mismatch? Yes.
- Can the same host present different results across inventory and preflight? Yes, and preflight wins.
- Can KRA visibility failures be distinguished from host verification failures? Yes, with named failure states.
- Can breakglass bypass signature/drift/revocation failures? No.

## Trust boundary disclosure

Initial signer deployment may colocate signer and AAP workflow execution.
This improves operability but does not protect against a fully compromised AAP controller.

For high-assurance usage, operators should evaluate stronger signer isolation before claiming final stable posture.

## Evidence map

Reference documents:

- `docs/blastwall-v3/signed-attestation-design.md`
- `docs/blastwall-v3/stable-v3-readiness-checklist.md`
- `docs/blastwall-v3/operator-runbook.md`
- `docs/blastwall-v3/kra-topology-runbook.md`
- `docs/blastwall-v3/revocation-and-breakglass.md`
- `V3_IMPLEMENTATION_LEDGER.md`
- `tools/blastwall_attestation_verify.py`
- `tools/blastwall_attestation_sign.py`
- `tools/audit_blastwall_inventory.py`

## Calabi evidence

Latest live healthy-path gate completed on 2026-05-18 UTC on the
`blastwall-v3-signed-attestation` branch with the `eigenstate.ipa` 1.18.1
surfaces available. Partial live negative evidence is recorded; the remaining
destructive negative matrix is still a separate required gate before final
stable-v3 release approval.

- `Calabi path`: workstation to `virt-01` (`172.18.0.224`) to bastion
  (`172.16.0.30`).
- `AAP project branch`: `blastwall-v3-signed-attestation`.
- `Latest Controller-visible gate commit`:
  `56f7c451a281bda5f5a1dbd1a8fac12d00097410`.
- `KRA primary`: `idm-01.workshop.lan`.
- `KRA server list`: `idm-01.workshop.lan`.
- `KRA scope/owner`: `shared` / `blastwall-attestation`.
- `Signer`: AAP sign job `2865`, signer SKI
  `8e62ab6d10d1a1a6b4261c4ee3fe79f76545c6d6`.
- `Latest policy pipeline`: AAP workflow `2843`, successful.
- `Latest OpenShift/SPO apply-validation`: AAP job `2857`, successful.
- `Latest post-promotion preflight`: AAP job `2876`, successful.
- `Standalone valid stable-v3 preflight`: AAP job `2839`, successful.
- `Earlier policy pipeline`: AAP workflow `2177`, successful.
- `Earlier runtime verification`: AAP workflow `2227`, successful.
- `Valid base host preflight`: AAP job `2839`, successful. It retrieved the
  signed envelope and latest index from KRA and returned `status=PASS`,
  `failure_state=null`.
- `Managed-host verification`: AAP job `2861`, successful. Evidence digest
  `16dc41143e934a4a1cad5c138867a8dfe0e9dec8fa12ff7dda6456302a190625`.
- `Policy NEVRA`: `blastwall-selinux-0.6.1-0.rc1`.
- `Policy hash`:
  `4b3e1d30e364331d408d8531d871ffcce23805a89b4cf44bd2977854be35bfc2`.
- `Registry hash`:
  `c8a533efc7ce60604d2a770964eea582005dde49ac2b882eea38c9701d612486`.
- `RPM hash`:
  `0c25e56e120a6e1f38d89300b3598cd4066967ef4136204610134fdd12735f45`.
- `Attestation ref`:
  `shared/blastwall-attestation/blastwall-attestations/mirror-registry.workshop.lan/base/1779093311.json`.
- `Attestation hash`:
  `4d382ebdee93fe0c37f1585711d2216465a09f18c8c359e142b2b2558582840b`.
- `Index generation`: `1779093311`.
- `Marker`:
  `blastwall:v=3;state=active;target=rhel-login;rpm=blastwall-selinux-0.6.1-0.rc1;profiles=base;attest_ref=shared/blastwall-attestation/blastwall-attestations/mirror-registry.workshop.lan/base/1779093311.json;attest_sha256=4d382ebdee93fe0c37f1585711d2216465a09f18c8c359e142b2b2558582840b;signer_kid=8e62ab6d10d1a1a6b4261c4ee3fe79f76545c6d6;exp=2026-05-18T09:35:12Z;generation=1779093311`.

The live gate also confirmed the managed-host policy still blocks the current
probe set, including AF_ALG, BPF map/prog load, AF_PACKET, user namespace,
`io_uring_setup`, Dirty Frag `NETLINK_XFRM`, Dirty Frag `AF_RXRPC`, and
Fragnesia `AF_ALG` entry points with `EPERM`/`EACCES` evidence.

Live negative checks currently recorded:

- Drifted current policy hash: AAP preflight job `2827` failed with
  `FAIL_DRIFTED_POLICY`.
- Bad signer allowlist: AAP preflight job `2830` failed with
  `FAIL_SIGNER_UNTRUSTED`.
- Bad configured KRA primary/server: AAP preflight job `2835` failed closed at
  `Resolve configured stable-v3 KRA vault servers` for
  `missing-kra.workshop.lan`.

Destructive live negative cases for missing artifact, missing index, revocation,
expiry, and breakglass are not fully recorded in this packet. Those failure
classes remain covered by the local regression matrix and require controlled
Calabi execution before final production stable-v3 sign-off.

## Failure-state map

- `FAIL_KRA_UNAVAILABLE`: audit-side KRA or vault infrastructure outage.
- `FAIL_ATTESTATION_NOT_VISIBLE`: signed artifact visible in marker but not in configured KRA path.
- `FAIL_INDEX_NOT_VISIBLE`: index not visible or not current in configured path.
- `FAIL_SIGNER_UNTRUSTED`: signer certificate or allowlist failure.
- `FAIL_SIGNATURE_INVALID`, `FAIL_BINDING_MISMATCH`, `FAIL_DRIFTED_POLICY`, `FAIL_REVOKED_ATTESTATION`: host/security failures.

## Open risks

- AAP/signer co-location remains a governance decision, not a cryptographic replacement for AAP compromise.
- Cross-replica KRA behavior must remain explicit; implicit replica discovery is disallowed in stable-v3.

## Reviewer acceptance criteria

- Confirm marker-vs-proof split is explicit in operator and preflight behavior.
- Confirm latest-generation replay protection and live host check in stable-v3.
- Confirm breakglass cannot bypass host trust failures.
- Confirm evidence package includes both healthy and failed cases, including KRA and security failure classes.
- Confirm ownership and escalation paths are named and staffed.
