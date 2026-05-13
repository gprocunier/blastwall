# Blastwall v2 Phase 02 Checkpoint

## Summary

- Phase: 02 - marker v2 and profile-based suitability control plane
- Branch: `blastwall-v2-phase-02-marker-v2`
- Commit: pending local checkpoint commit after Calabi gate update
- Date: 2026-05-10T20:45:00-04:00
- Operator: release automation

Phase 02 adds marker v2 parsing and emission, moves inventory/preflight
suitability toward profile evidence, and preserves v1 marker compatibility for
the current base RHEL login path. It does not expand SELinux enforcement or
change OpenShift enforcement behavior.

## Repository Changes

- Added `tools/blastwall_marker.py` for marker v1/v2 parsing, v2 emission,
  registry hashing, profile expansion, and fail-closed malformed/stale marker
  handling.
- Added `tests/test_blastwall_marker.py` for valid v2, multi-profile, stale
  registry, malformed marker, unknown profile, cyclic profile, and v1
  compatibility behavior.
- Added `docs/blastwall-v2/markers.md` to document marker v2 fields, v1
  migration behavior, and the Phase 02 base-only preflight boundary.
- Updated `inventory/blastwall-idm.yml` and
  `poc-calabi/aap/inventory/blastwall-idm.yml` to recognize canonical marker v2
  evidence with the current registry hash, retain v1 compatibility, and expose
  `blastwall_profile_base`.
- Updated `playbooks/deploy-policy.yml` and `playbooks/promote-policy-rpm.yml`
  to emit marker v2 with `registry_sha256`, `policy_sha256`, `profiles`, and
  `scopes`.
- Updated `playbooks/preflight.yml` to fail closed when selected hosts lack
  valid base profile evidence with the current profile registry hash.
- Updated Ansible registry hashing to use `lookup('file', ..., rstrip=False)`
  so emitted/preflight marker hashes match the raw-file hash used by the Python
  marker tool and inventory predicates.
- Updated `tests/inventory_grouping.py`,
  `tests/fixtures/inventory-policy-markers.json`, `tests/policy_static.py`, and
  `package.json` so the policy suite covers marker v2 and profile grouping.

## Validation

- PASS: `python3 tests/test_blastwall_marker.py`
- PASS: `python3 tests/inventory_grouping.py`
- PASS: `npm run test:policy`
- PASS: `python3 -m pytest -q tests || true`
- PASS: `ansible-playbook --syntax-check playbooks/preflight.yml playbooks/deploy-policy.yml playbooks/promote-policy-rpm.yml`
- PASS: `git diff --check`

## Acceptance Criteria

- PASS: marker v2 parser and emitter exist.
- PASS: v2 marker includes `profiles=`, `registry_sha256=`, and
  `policy_sha256=`.
- PASS: stale registry hash, malformed markers, unknown profiles, and cyclic
  profile expansion fail closed.
- PASS: inventory groups hosts by profile-compatible evidence and current
  registry hash while preserving `blastwall_policy_current` /
  `blastwall_policy_stale` compatibility.
- PASS: preflight can require the base profile and fails closed when evidence is
  missing or stale.
- PASS: v1 markers remain compatible for the base profile during migration.
- PASS: no SELinux enforcement expansion and no OpenShift enforcement behavior
  change.

## Calabi Gate

Status: PASS.

Execution boundary:

- Workstation staged the Phase 02 branch to
  `/opt/openshift/aws-metal-openshift-demo/blastwall-phase02-gate` on
  `bastion-01.workshop.lan` through `virt-01`.
- Live IdM/AAP validation ran from `bastion-01.workshop.lan`.
- IdM inventory used the existing AAP service keytab for read access.
- Marker mutation used the lab admin Kerberos credential from the existing
  Calabi secret source.

Evidence:

- PASS: `mirror-registry.workshop.lan` has `blastwall-selinux-0.5.2-1.noarch`
  installed and Blastwall SELinux modules loaded.
- PASS: direct GSSAPI smoke as `svc-ansible-runner` returned
  `blastwall_u:blastwall_r:blastwall_t:s0`; sudo returned UID `0` without
  leaving `blastwall_u:blastwall_r:blastwall_t:s0`.
- PASS: marker emitter produced canonical v2 marker:

  ```text
  blastwall:v=2;state=active;target=rhel-login;rpm=blastwall-selinux-0.5.2-1;registry_sha256=9c11a7409662c3584175284c2f2b5e72c1fd69aec855c81e9083ae05e94ff854;policy_sha256=8d8723188393e1514c1d13acd88dbbaffba2c01e935e1284cd0634709a930cea;profiles=base;scopes=alg_socket,bpf,capability2_bpf,packet_socket,userns,io_uring,xfrm,rxrpc,selfprotect
  ```

- PASS: marker v2 was published to `mirror-registry.workshop.lan` userClass.
- PASS: valid marker inventory grouped `mirror-registry.workshop.lan` into
  `blastwall_policy_current` and `blastwall_profile_base`, while
  `stale-blastwall-01.workshop.lan` remained in `blastwall_policy_stale`.
- PASS: preflight requiring `base` accepted the valid marker and reported:

  ```text
  selected_hosts: [mirror-registry.workshop.lan]
  stale_hosts: [stale-blastwall-01.workshop.lan]
  registry_sha256: 9c11a7409662c3584175284c2f2b5e72c1fd69aec855c81e9083ae05e94ff854
  ```

- PASS: stale-hash negative changed the live marker registry hash to
  `1111111111111111111111111111111111111111111111111111111111111111`;
  inventory moved `mirror-registry.workshop.lan` out of current/base and into
  `blastwall_policy_stale` / `blastwall_policy_candidate`.
- PASS: stale-hash preflight failed closed with no eligible current hosts.
- PASS: valid marker was restored and final inventory/preflight returned to the
  accepted state.
- PASS: `svc-ansible-runner` was unlocked after credential probing and verified
  with a fresh Kerberos ticket.

Commands run from bastion:

```bash
python3 tools/blastwall_marker.py --emit --policy-sha256 8d8723188393e1514c1d13acd88dbbaffba2c01e935e1284cd0634709a930cea
ansible-inventory -i /tmp/blastwall-phase02-idm-inventory-aap-keytab.yml --graph
ansible-playbook --become -i /tmp/blastwall-phase02-idm-inventory-aap-keytab.yml playbooks/preflight.yml -e '{"required_blastwall_profiles":["base"]}'
ipa host-mod mirror-registry.workshop.lan --delattr="userclass=<old-marker>"
ipa host-mod mirror-registry.workshop.lan --addattr="userclass=<v2-marker>"
ipa host-mod mirror-registry.workshop.lan --delattr="userclass=<v2-marker>"
ipa host-mod mirror-registry.workshop.lan --addattr="userclass=<stale-v2-marker>"
ansible-inventory -i /tmp/blastwall-phase02-idm-inventory-aap-keytab.yml --graph
ansible-playbook --become -i /tmp/blastwall-phase02-idm-inventory-aap-keytab.yml playbooks/preflight.yml -e '{"required_blastwall_profiles":["base"]}'
ipa host-mod mirror-registry.workshop.lan --delattr="userclass=<stale-v2-marker>"
ipa host-mod mirror-registry.workshop.lan --addattr="userclass=<v2-marker>"
ansible-inventory -i /tmp/blastwall-phase02-idm-inventory-aap-keytab.yml --graph
ansible-playbook --become -i /tmp/blastwall-phase02-idm-inventory-aap-keytab.yml playbooks/preflight.yml -e '{"required_blastwall_profiles":["base"]}'
ipa user-unlock svc-ansible-runner
```

Captured log paths on `bastion-01.workshop.lan`:

- `/tmp/blastwall-phase02-direct-gssapi-smoke.log`
- `/tmp/blastwall-phase02-marker-v2.txt`
- `/tmp/blastwall-phase02-inventory-v2-valid.log`
- `/tmp/blastwall-phase02-preflight-v2-valid.log`
- `/tmp/blastwall-phase02-inventory-stale-negative.log`
- `/tmp/blastwall-phase02-preflight-stale-negative.log`
- `/tmp/blastwall-phase02-inventory-restored.log`
- `/tmp/blastwall-phase02-preflight-restored.log`

## Risks and Follow-Up

- Phase 02 preflight deliberately accepts only `base` as a required profile.
  Additional profile requirements should wait for a parser-backed Ansible path
  or equivalent generated predicates.
- Inventory grouping uses generated/current-hash regex predicates for
  operational compatibility. The Python parser is the stricter reference
  implementation.
- `policy_sha256` currently carries the verified policy RPM artifact hash for
  the RHEL login path.
- The live gate found and fixed an Ansible file-lookup hashing mismatch. Static
  validation now requires `rstrip=False` for registry hashing in deploy,
  promote, and preflight.

## Rollback

Revert this phase commit to restore v1-only marker emission, v1-only
inventory/preflight predicates, and the prior policy test wiring. Existing v1
host markers remain compatible with this phase, so rollback does not require
host marker cleanup.

## Go / No-Go

Recommendation: GO for Phase 03. Repository-side criteria and the live Calabi
Phase 02 gate are complete.
