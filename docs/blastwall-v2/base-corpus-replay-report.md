# Base Automation Corpus Replay Report

Status: `PASS: replayed in live Calabi lab`

Branch: `blastwall-v2-phase-08-rc1k`

Source commit:
`4dca61afba413383ebe48f1b07a1c413bb1affb1`

Corpus playbook: `tests/corpus/base_automation_corpus.yml`

Live evidence:
`/tmp/blastwall-phase08-rc1k-live-20260515T034134Z/gate09-base-corpus-after-systemd-policy.log`

## Scope

The base corpus proves that ordinary privileged automation still works under the
`blastwall_u:blastwall_r:blastwall_t:s0` login context. It does not promote
`strange-socket-v1`.

Covered operations:

- SELinux execution context assertion
- package facts query
- file copy, template, directory, and line mutation
- lab-only user create/remove
- systemd unit install, daemon reload, and one-shot service run
- localhost HTTP request with non-fatal handling
- cleanup of lab-created files and user

## Live Evidence

- Host: `mirror-registry.workshop.lan`
- RPM NEVRA: `blastwall-selinux-0.6.1-0.rc1.noarch`
- Marker:
  `blastwall:v=2;state=active;target=rhel-login;rpm=blastwall-selinux-0.6.1-0.rc1;registry_sha256=c8a533efc7ce60604d2a770964eea582005dde49ac2b882eea38c9701d612486;policy_sha256=4b3e1d30e364331d408d8531d871ffcce23805a89b4cf44bd2977854be35bfc2;profiles=base;scopes=alg_socket,bpf,capability2_bpf,packet_socket,userns,io_uring,xfrm,rxrpc,selfprotect`
- SELinux context: `blastwall_u:blastwall_r:blastwall_t:s0`
- Tasks passed: `16`
- Tasks failed: `0`
- AVCs observed: none required for the final passing replay
- Compatibility exceptions: none
- Policy changes requested by replay:
  - allow standard user/group management transitions from `blastwall_t`
  - allow standard systemd lifecycle management needed by `daemon-reload`

## Failure Triage

The first live replay failed before final pass and was classified as a real
compatibility issue, not a stale-lab artifact:

- `useradd` could not open `/etc/gshadow` under `blastwall_t`, while the same
  target operation succeeded as unconfined `cloud-user`.
- `systemctl daemon-reload` was denied under `blastwall_t`, while the same
  target operation succeeded as unconfined `cloud-user`.

The policy fix uses standard RHEL reference-policy interfaces in
`policy/blastwall.te` rather than ad hoc raw allow rules. Static guards in
`tests/policy_static.py` now require those interfaces.

## Local Validation

```bash
ansible-playbook --syntax-check -i localhost, tests/corpus/base_automation_corpus.yml
# PASS

python3 tests/policy_static.py
# PASS

python3 -m pytest -q tests
# 65 passed
```

## Decision

The base corpus gate is complete for the Calabi Phase 08 RC path. It validates
the same SSH, SSSD, PAM, sudo, and SELinux login path used by normal Blastwall
automation.
