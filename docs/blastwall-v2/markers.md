# Blastwall v2 Markers

Blastwall v2 markers move the host suitability claim from per-scope sprawl to
profile membership.

The canonical marker shape is:

```text
blastwall:v=2;state=active;target=rhel-login;rpm=<NEVRA>;registry_sha256=<64hex>;policy_sha256=<64hex>;profiles=base;scopes=alg_socket,bpf,capability2_bpf,packet_socket,userns,io_uring,xfrm,rxrpc,selfprotect
```

Rules:

- `profiles=` is the operator-facing claim.
- `scopes=` is retained for debugging and drift checks.
- `registry_sha256=` is the SHA-256 of `policy/profiles.yml` at marker emission time.
- `policy_sha256=` is the verified policy RPM artifact hash for the RHEL login path.
- A v2 marker is unsuitable if any of these fail: parsing, required fields, hash format,
  RPM allow-list, target match, unknown profile/scope names, stale
  `registry_sha256`, malformed scope sets, or required profile coverage.
- By default, all claimed profiles must be production `active`. `status: dry-run`
  profiles require `--allow-dry-run-profiles` and produce/require `lab-active`
  marker state; `planned` and `deprecated` profiles are always unsuitable.

Scope validation is exact:

- The set of `scopes` must match the registry-expanded scope set for `profiles`.
- Missing scopes fail closed.
- Extra scopes fail closed.

## v1 Compatibility

Existing v1 markers remain parseable during migration:

```text
blastwall:state=active;rpm=blastwall-selinux-0.5.2-1;rpm_sha256=<64hex>;alg=deny;bpf=deny;self=deny;pkt=deny;userns=deny;iou=deny;xfrm=deny;rxrpc=deny
```

V1 compatibility is limited to `base` only. A v1 marker can satisfy only the `base`
profile and only when it matches expected rpm/hash/state and required flags.
Any requirement beyond `base` (for example `strange-socket-v1`) fails closed.

## Inventory and Preflight

The IdM inventory keeps the existing `blastwall_policy_current` and
`blastwall_policy_stale` groups for AAP compatibility and adds
`blastwall_profile_base` and `blastwall_profile_strange_socket_v1` for
profile-oriented grouping. The inventory v2 predicate pins the current
`policy/profiles.yml` registry hash so stale profile claims route back through
the stale/candidate path.

Runtime verification and preflight targeting are profile-aware. The AAP
verification workflow resolves this with `BLASTWALL_AAP_VERIFY_TARGET_GROUP`
(`blastwall_profile_base` by default) and should point at profile-specific
groups such as `blastwall_profile_base` or `blastwall_profile_strange_socket_v1`
for explicit `strange-socket-v1` dry-run runs.

Preflight now reads `BLASTWALL_REQUIRED_POLICY_PROFILES` (default: `base`) and
calls `tools/blastwall_marker.py check` for parser-backed validation.

Candidate staging for policy promotion is intentionally cohort-based and is
controlled separately by `BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP`. This is
kept distinct from preflight targeting:

- Stale host remediation uses
  `BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP=blastwall_policy_candidate`.
- Base/current verification uses
  `BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP=blastwall_profile_base` (or an
  explicit curated base cohort), and `BLASTWALL_AAP_VERIFY_TARGET_GROUP=blastwall_profile_base`.
- Base-current to strange-socket dry-run rollout uses
  `BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP=blastwall_profile_base` (or an
  explicit curated base-current lab cohort), then verifies after promotion with
  `BLASTWALL_AAP_VERIFY_TARGET_GROUP=blastwall_profile_strange_socket_v1`.

Current preflight behavior is fail-closed for all of these:

- Unknown or malformed marker data.
- Unknown required/declared profiles.
- Unknown scope names.
- Stale registry hash.
- Bad hash format for `registry_sha256` or `policy_sha256`.
- Unsupported `target` value.
- v2 scope set that does not exactly match expanded profile scopes.
- v1 marker evidence when any required profile is not `base`.

A typical environment pairing is:

```text
BLASTWALL_REQUIRED_POLICY_PROFILES=base,strange-socket-v1
BLASTWALL_ALLOW_DRY_RUN_PROFILES=true
BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP=blastwall_profile_base
BLASTWALL_AAP_VERIFY_TARGET_GROUP=blastwall_profile_strange_socket_v1
```

The playbook passes that through `--required-profiles-csv`, `--expected-registry-sha256`,
`--accepted-rpm`, `--expected-target`, and `--markers-stdin` into:

```text
python3 tools/blastwall_marker.py check \
  --registry policy/profiles.yml \
  --allow-dry-run-profiles \
  --expected-registry-sha256 <sha256> \
  --accepted-rpm blastwall-selinux-0.6.1-0.rc1 \
  --expected-target rhel-login \
  --required-profiles-csv base,strange-socket-v1 \
  --markers-stdin
```

## Migration Procedure

- Do not hand-edit markers.
- During upgrade, deploy and verify a candidate RPM by the managed path (policy
  build/install + managed-host verification).
- Promote only a fully verified candidate via managed promotion.
- Managed promotion writes canonical v2 marker state in IdM evidence using the
  canonical parser-backed marker format.
- Legacy and stale marker evidence remain in `blastwall_policy_candidate` and
  `blastwall_policy_stale` until parser validation passes and promotion succeeds.
- After validation, successful promotion moves evidence to `blastwall_policy_current`
  and profile-specific groups (for example `blastwall_profile_base` or
  `blastwall_profile_strange_socket_v1` when requested).

## Examples

### Required profile: `base`

```text
BLASTWALL_REQUIRED_POLICY_PROFILES=base
```

Example accepted marker:

```text
blastwall:v=2;state=active;target=rhel-login;rpm=blastwall-selinux-0.6.1-0.rc1;registry_sha256=<current-profiles-sha256>;policy_sha256=<policy-rpm-sha256>;profiles=base;scopes=alg_socket,bpf,capability2_bpf,packet_socket,userns,io_uring,xfrm,rxrpc,selfprotect
```

### Required profiles: `base,strange-socket-v1`

```text
BLASTWALL_REQUIRED_POLICY_PROFILES=base,strange-socket-v1
```

Example accepted dry-run marker (scopes include all base + inherited strange socket scopes):

```text
blastwall:v=2;state=lab-active;target=rhel-login;rpm=blastwall-selinux-0.6.1-0.rc1;registry_sha256=<current-profiles-sha256>;policy_sha256=<policy-rpm-sha256>;profiles=base,strange-socket-v1;scopes=alg_socket,bpf,capability2_bpf,packet_socket,userns,io_uring,xfrm,rxrpc,selfprotect,bluetooth_socket,can_socket,kcm_socket,nfc_socket,rds_socket,tipc_socket,xdp_socket
```
