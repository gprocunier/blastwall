# Final Stable-v3 Decision

## Summary

Stable-v3 is an engineering RC for external review, not a final publication
release. The code and evidence packet are ready for reviewers to evaluate the
v3 trust model and Calabi evidence. Publication remains held on governance
ownership and sign-off.

The operating boundary for that claim is
`docs/blastwall-v3/operational-guidance.md`.

## Decision Table

| Claim | Decision | Reason |
|---|---:|---|
| Engineering RC | GO | Source gates pass locally, Controller-visible evidence exists, destructive negative cases fail closed, and schedule wiring is active. |
| Stable-v3 publication | HOLD | Required governance owners/sign-off are not assigned, and stable-v3 non-shared custody health is not live-green. |
| S-range | HOLD | 10+ host fleet evidence is excluded from this pack and not complete. |

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

## Remaining Risks

- Governance owners are pending.
- Stable-v3 service-owned or named-user custody is not live-green in Calabi;
  jobs `3914`, `3987`, and `3991` failed in the vault-health path.
- Long-duration scheduled-loop soak is not complete.
- S-range scale behavior is not proven.

## Required Next Action

Assign owners, resolve stable-v3 service-owned or named-user custody health in
Calabi, then decide whether the publication hold can move to sign-off review.
