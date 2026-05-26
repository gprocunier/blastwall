# Ownership And Escalation

Blastwall needs a named boundary owner because the control chain crosses IdM, AAP, Linux/SELinux, security review, and OpenShift/SPO.

Required named roles before stable publication:

- Boundary owner: triages cross-component incidents and decides routing.
- SELinux policy owner: owns CIL, profile registry, drift checks, and policy hash semantics.
- AAP workflow owner: owns job templates, workflow artifacts, inventory sync, and evidence retention.
- IdM owner: owns userClass marker storage, HBAC, sudo, SELinux maps, and marker write authority.
- OpenShift owner: owns SPO/SCC compatibility validation.
- Second maintainer-developer: can patch marker parser, drift checker, inventory grouping, and preflight logic.

Escalate immediately when a host moves from current to stale without a planned deployment, rollback publishes `rollback-failed`, selected-host marker validation is bypassed, or a probe reports `FAIL_ALLOWED` or `FAIL_UNKNOWN`.
