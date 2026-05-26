# Stable Or Reference Decision

Decision: `HOLD: Phase 08 gates pass; stable release approval pending`

Date: 2026-05-15

Boundary owner: TBD

Incident response owner: TBD

Second maintainer-developer: TBD

Escalation path: TBD

Accepted constraints:

- RHEL `base` is the only candidate stable RHEL profile.
- `strange-socket-v1` remains dry-run and lab-only.
- OpenShift/SPO claims are limited to version-bounded evidence.
- Calabi gates, corpus replay, rollback simulation, and OpenShift/SPO replay
  completed on 2026-05-15 for commit
  `4dca61afba413383ebe48f1b07a1c413bb1affb1`.
- Stable publication is blocked until human release approval, ownership
  assignment, and second-maintainer exercise are complete.
