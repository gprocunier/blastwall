# Scope Triage Policy

Do not add new enforcement surfaces because SELinux can name them.

New scopes require all of the following:

- exploit or threat signal tied to privileged automation
- ordinary automation impact analysis
- safe RHEL probe
- OpenShift/SPO target support plan when applicable
- rollback plan
- documentation update
- explicit human approval

Default decision: no new scope.

Deferred areas include KVM enforcement, seccomp enforcement, BPF LSM enforcement, and additional socket families until they have evidence, corpus replay, and ownership.
