# Blastwall v2 Troubleshooting Runbook

Use parser output and inventory audit output before changing policy.

## FAIL_STALE_MARKER

Run `tools/blastwall_marker.py check` against the host marker with the current registry hash and accepted RPM. If it fails, repair marker publication through the deploy or promote playbook; do not hand-edit a success marker.

## Host In Wrong Inventory Group

Run `playbooks/audit-inventory-membership.yml` or `tools/audit_blastwall_inventory.py` against `ansible-inventory --list`. Check `changed_hosts`, `current_to_stale`, `schema_errors`, and `marker_parse_errors`.

## Missing idm_userclass

Confirm the IdM host object has the Blastwall marker in userClass. Missing userClass means the inventory plugin cannot prove the host claim.

## Malformed Marker

Run `tools/blastwall_marker.py check --markers-stdin`. Malformed markers must be republished through controlled playbooks after verification.

## Registry Hash Mismatch

Recompute `sha256sum policy/profiles.yml` on the source branch used by AAP. A stale registry hash means the host claim was made against a different profile contract.

## Policy Hash Mismatch

Run `tools/blastwall_policy_hash.py --root <installed-policy-root>` on the target payload. The marker `policy_sha256` must match the installed policy payload, not the RPM artifact hash.

## No Eligible Hosts

Check the selected profile group and the post-promotion target override. Empty `BLASTWALL_POST_PROMOTION_PREFLIGHT_TARGET_GROUP` means derive the group from required profiles.

## Dry-Run Marker Rejected

`strange-socket-v1` requires `BLASTWALL_ALLOW_DRY_RUN_PROFILES=true`; production preflight must reject lab-active dry-run markers.

## Rollback Failed

A `state=rollback-failed` marker is an incident signal. Inspect rollback verification output for remaining modules, login-context mismatch, and IdM marker write status.

## SPO Usage Mismatch

Check `RawSelinuxProfile.status.usage`, selected resolution mode, derived SCC type, and admitted pod context. Unknown `status.usage` formats must fail closed.
