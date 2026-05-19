# Scheduled-Loop Soak Evidence

## Soak Window

```text
start: 2026-05-19T17:00:00Z
latest_observed: 2026-05-19T19:40:25Z
duration_observed: about 2h40m
environment: Calabi on-prem AAP/OpenShift lab
branch: blastwall-v3-signed-attestation
controller_project_revision_at_query: 14f7f472f70c1eb66f8ece35b194ed4e2da8b137
```

## Schedule Definitions

| Schedule | ID | Enabled | Rule | Next run observed at 2026-05-19T19:40Z |
|---|---:|---:|---|---|
| Blastwall stable-v3 KRA health hourly | `6` | yes | hourly from `2026-05-19T17:00:00Z` | `2026-05-19T20:00:00Z` |
| Blastwall stable-v3 inventory audit hourly | `7` | yes | hourly from `2026-05-19T17:00:00Z` | `2026-05-19T20:00:00Z` |
| Blastwall stable-v3 candidate preflight daily | `8` | yes | daily from `2026-05-19T17:00:00Z` | `2026-05-20T17:00:00Z` |
| Blastwall stable-v3 runtime verification daily | `9` | yes | daily from `2026-05-19T17:00:00Z` | `2026-05-20T17:00:00Z` |

## Schedule Results

| Schedule | Job/workflow IDs | Expected | Observed | Failure state | Notes |
|---|---|---|---|---|---|
| Hourly KRA health | manual `3731`; scheduled `3776`, `3797`, `3802` | PASS | PASS | none | scheduled `3802` reported canary present, `vault_reachable=true`, `kra_available=true` |
| Hourly inventory audit | manual `3772`; scheduled `3778`, `3799`, `3804` | expected fixture fail-closed | failed closed | `FAIL_ATTESTATION_NOT_VISIBLE` on broken fixture | valid mirror host remained clean; missing-artifact fixture stayed blocked with `vault_error_type=not_found` |
| Daily candidate preflight | manual `3735`; scheduled `3780` | PASS | PASS | none | candidate host `mirror-registry.workshop.lan` passed |
| Daily runtime verification | manual workflow `3736`; scheduled workflow `3781` | PASS | PASS | none | scheduled workflow ran preflight and managed-host verification successfully |

## Observations

The first scheduled loop did not show unexpected movement. The expected broken
fixture continued to fail closed while the valid current host continued to
verify. Hourly KRA health stayed green through the observed window.

## Unexpected Movement

```text
current_to_stale: none observed in scheduled evidence
stale_to_current: none observed in scheduled evidence
revoked: none newly observed in scheduled evidence
expired: none newly observed in scheduled evidence
```

## Decision Impact

The scheduled-loop evidence is sufficient for RC review and for proving the
schedule wiring works. It is not yet a long-duration operations soak. Stable-v3
publication remains held until governance owners accept the loop and a longer
retention/escalation window is approved.
