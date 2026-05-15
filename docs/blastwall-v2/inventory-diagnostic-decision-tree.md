# Inventory Diagnostic Decision Tree

Start with `ansible-inventory --list`.

1. Host missing from inventory: check IdM host filter, HBAC group scope, and `eigenstate.ipa` source configuration.
2. Host in `blastwall_inventory_schema_error`: inspect `idm_userclass` type. Dict, null, or mixed lists are schema anomalies and should be escalated to the IdM/inventory owner.
3. Host in `blastwall_inventory_marker_parse_error`: run `tools/blastwall_marker.py check` with current registry hash and accepted RPM.
4. Host in `blastwall_policy_stale`: compare marker state, registry hash, policy hash, RPM NEVRA, target, profiles, and scopes.
5. Host in `blastwall_policy_current` but wrong profile group: verify required profiles and dry-run allow setting.
6. Post-promotion preflight selects no hosts: ensure the post-promotion override is empty so preflight derives `blastwall_profile_base` or `blastwall_profile_strange_socket_v1`.
7. Group count changed unexpectedly: compare the current audit report with the previous snapshot and investigate `current_to_stale` before running workloads.
