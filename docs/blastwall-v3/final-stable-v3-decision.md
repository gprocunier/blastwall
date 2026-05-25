# Final Stable-v3 Decision

## Summary

Stable-v3 is ready for reference exemplar publication. The code and evidence
packet show the v3 trust model, Calabi reference topology, fail-closed failure
states, service-owned custody path, and continuous verification loop.

Governance ownership remains an adopter worksheet: an organization should name
the people who will operate, review, and escalate the control before treating
the pattern as its own operating control.

The operating boundary for that claim is
`docs/blastwall-v3/operational-guidance.md`.

## Decision Table

| Claim | Decision | Reason |
|---|---:|---|
| Reference exemplar publication | GO | Source gates pass locally, Controller-visible evidence exists, destructive cases fail closed, service-owned custody is live-green, and schedule wiring is active. |
| Calabi reference topology evidence | GO | The packet records the workstation to `virt-01` to bastion to IdM/AAP/KRA path with job IDs and restore proof. |
| Stable-v3 service-owned custody demonstration | GO | KRA health `4872`, policy pipeline `4922`, runtime workflow `4968`, and inventory audit `4989` exercised the service-owned path. |
| Fleet-scale evidence | Future validation | 10+ host mixed-state evidence is outside this exemplar and should be captured before expanding the claim. |

## Evidence Attached

- `V3_STABLE_EVIDENCE_GATE_LEDGER.md`
- `V3_NEGATIVE_GATE_LEDGER.md`
- `docs/blastwall-v3/evidence-index.md`
- `docs/blastwall-v3/operational-guidance.md`
- `docs/blastwall-v3/failure-state-manifest.yml`
- `docs/blastwall-v3/evidence-consistency-matrix.md`
- `docs/blastwall-v3/calabi-negative-evidence.md`
- `docs/blastwall-v3/scheduled-loop-soak.md`
- `docs/blastwall-v3/stable-v3-rc-decision.md`
- `docs/blastwall-v3/external-review-packet.md`

## Adopter Work Before Operation

- Governance owners are pending in
  `docs/blastwall-v3/governance-owner-assignment.md`.
- Stable-v3 service-owned custody is live-green in Calabi reference evidence
  as of jobs `4872`, `4922`, `4968`, and `4989`.
- Longer retention and escalation windows should be assigned before local
  operation of the schedule loop.
- Fleet-scale behavior should be captured before making fleet-scale claims.

## Required Next Action

Publish the reference exemplar from `v3`. Adopters should complete the
governance worksheet and local evidence review before operating the pattern.
