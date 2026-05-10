# Blastwall Policy Modules

Each deny scope is a standalone CIL file loaded alongside the base
`blastwall.pp` module.  The `Makefile` lists active enforcement helpers in
`SUPPORT_POLICIES`, active deny scopes in `DENY_POLICIES`, and loads them in a
single `semodule -i` call.

`blastwall-sshd-login.cil` is a support module, not a deny scope. It lets sshd
complete the `pam_selinux` selected-context transition into `blastwall_t` so
GSSAPI automation can enter the confined domain before the deny scopes are
tested.

## Optional blocks

Some SELinux object classes are only present on newer kernels.  For
example, `io_uring` exists on RHEL 9+ but not RHEL 7/8.  When a deny
scope targets a class that may not exist on all deployment targets, the
CIL rules are wrapped in a CIL `optional` block:

```cil
(optional blastwall_io_uring_deny
  (deny blastwall_t self (io_uring (cmd override_creds sqpoll)))
  (neverallow blastwall_t self (io_uring (cmd override_creds sqpoll))))
```

If the class is unknown to the running kernel's policy, `semodule`
silently discards the block instead of failing.  This keeps the policy
RPM a single artifact across RHEL versions.  The host marker script
gates scope-specific markers on the class actually existing in
`/sys/fs/selinux/class/`, so inventory correctly reflects what is
enforced on each host.

## Adding a new scope

1. Write a `.cil` file following the deny + neverallow pattern.
2. Add the module name to `DENY_POLICIES` in the `Makefile`.
3. Add a marker entry to `scripts/update-host-marker.sh`.
4. Add an inventory group condition to `inventory/blastwall-idm.yml`.
5. Write a test probe in `tests/`.
6. Bump the policy version.

Support modules that keep login or packaging mechanics working belong in
`SUPPORT_POLICIES`, not `DENY_POLICIES`.

## Current Dirty Frag response

Blastwall `0.5.2` adds two deny scopes for the Dirty Frag disclosure:

- `blastwall-xfrm-deny.cil` denies `netlink_xfrm_socket` access so confined
  automation cannot register XFRM/IPsec state.
- `blastwall-rxrpc-deny.cil` denies `rxrpc_socket` access so confined
  automation cannot open the RxRPC protocol entry point.

The matching safe probe is `tests/trigger-dirtyfrag-deny.py`.  It only checks
entry-point reachability and does not run exploit payload logic.
