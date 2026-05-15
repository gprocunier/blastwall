# Phase 08 Calabi Final Checkpoint

Date: 2026-05-15

Branch: `blastwall-v2-phase-08-rc1k`

Final validated commit:
`4dca61afba413383ebe48f1b07a1c413bb1affb1`

Decision: `PASS: live Calabi gates complete; stable sign-off still separate`

Evidence directory:
`/tmp/blastwall-phase08-rc1k-live-20260515T034134Z` on the Calabi bastion.

## Live Gate Results

- Gate 1 branch and source identity: `PASS`
  - AAP project `Blastwall` on branch `blastwall-v2-phase-08-rc1k`
  - AAP project revision:
    `4dca61afba413383ebe48f1b07a1c413bb1affb1`
  - Evidence: `gate12-aap-source-identity-final.json`
- Gate 2 inventory classification fixtures: `PASS`
  - Base mode selected `mirror-registry.workshop.lan` for `base`.
  - Dry-run mode selected `base,strange-socket-v1` only after matching marker
    evidence.
  - The stale fixture host remained fail-closed in marker parse error grouping.
- Gate 3 base AAP verification: `PASS`
  - Workflow `1532`, verify job `1545`
  - No `FAIL_ALLOWED`, `FAIL_UNKNOWN`, or
    `FAIL_MISSING_CLASS_REQUIRED` evidence.
- Gate 4 policy pipeline base path: `PASS`
  - Workflow `1675`
  - Jobs `1676`, `1677`, `1680`, `1684`, `1685`, `1689`, `1693`,
    `1697`, and `1700` all successful.
- Gate 5 RHEL strange-socket dry-run path: `PASS`
  - Workflow `1549`
  - Dry-run module `blastwall-strange-socket-v1-deny` installed only for the
    explicit dry-run run and removed when base mode was restored.
- Gate 6 rollback simulation: `PASS`
  - Controlled failure produced rollback marker evidence and restored policy
    state.
  - Evidence: `gate06-rollback-controlled-failure.log`,
    `gate06-rollback-idm-marker.log`
- Gate 7 base automation corpus replay: `PASS`
  - Evidence: `gate09-base-corpus-after-systemd-policy.log`
  - Corpus completed under
    `blastwall_u:blastwall_r:blastwall_t:s0` on
    `mirror-registry.workshop.lan`.
- Gate 8 OpenShift/SPO base and nested: `PASS`
  - Evidence: `gate10-spo-base-render.log`,
    `gate10-spo-base-apply-validate.log`
  - `status.usage` values `blastwall.process` and
    `blastwallnested.process` were converted to derived SCC types
    `blastwall_.process` and `blastwallnested_.process`.
- Gate 9 OpenShift/SPO strange dry-run: `PASS`
  - Evidence: `gate11-spo-strange-render.log`,
    `gate11-spo-strange-apply-validate.log`
  - Standard, nested, standard-strange, and nested-strange validation jobs all
    passed with the Calabi OCP 4.20/SPO 0.10 derived-type mode.

## Final Target State

- Target host: `mirror-registry.workshop.lan`
- RPM: `blastwall-selinux-0.6.1-0.rc1.noarch`
- Marker:
  `blastwall:v=2;state=active;target=rhel-login;rpm=blastwall-selinux-0.6.1-0.rc1;registry_sha256=c8a533efc7ce60604d2a770964eea582005dde49ac2b882eea38c9701d612486;policy_sha256=4b3e1d30e364331d408d8531d871ffcce23805a89b4cf44bd2977854be35bfc2;profiles=base;scopes=alg_socket,bpf,capability2_bpf,packet_socket,userns,io_uring,xfrm,rxrpc,selfprotect`
- Active modules exclude `blastwall-strange-socket-v1-deny` in final base
  mode.

## Live Findings Resolved During Gate

- The base corpus exposed two real compatibility gaps in ordinary privileged
  automation under `blastwall_t`:
  - local user/group management needed standard `useradd_t` and `groupadd_t`
    transitions.
  - systemd lifecycle management needed standard `systemctl` execution and
    `init_t:system reload` access.
- Both were implemented through RHEL reference-policy interfaces in
  `policy/blastwall.te`, guarded by `tests/policy_static.py`, rebuilt through
  AAP, and replayed successfully.

## Remaining Release Decisions

- Stable publication still requires human release approval and ownership
  assignment.
- OpenShift claims remain version-bounded to the observed Calabi OCP 4.20/SPO
  0.10 behavior.
- `strange-socket-v1` remains lab-only dry-run evidence, not a default stable
  RHEL profile.
