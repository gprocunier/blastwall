# Blastwall v2 Operator Summary

Blastwall confines privileged automation that enters managed RHEL hosts through the approved IdM, AAP, SSH, SSSD, and PAM path. The protected login context is `blastwall_u:blastwall_r:blastwall_t:s0`.

Blastwall prevents selected risky kernel interfaces from succeeding under that confined automation identity. The base profile covers AF_ALG, BPF, `capability2 bpf`, packet sockets, user namespace creation, io_uring, NETLINK_XFRM, AF_RXRPC, and policy self-protection.

Blastwall does not replace patching, SELinux enforcing mode, IdM security, AAP security, sudo review, seccomp, BPF LSM, EDR, or runtime detection. AAP and IdM are trusted control-plane components.

`base` is the only stable RHEL marker profile in this RC. `strange-socket-v1` is dry-run and lab-only. It must require explicit dry-run allow flags and must not be treated as production-stable.

A host is protected only when all of these are true: inventory places it in the expected Blastwall profile group, preflight validates the marker with `tools/blastwall_marker.py check`, verification probes report `BLOCKED` or acceptable `SKIP_ABSENT`, and the marker registry and policy hashes match the intended release.

If a host is not protected, do not bypass preflight. Check inventory group membership, marker parser output, registry hash, policy hash, SELinux login context, and probe evidence before changing policy.
