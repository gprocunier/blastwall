#!/usr/bin/env python3
"""Safe Dirty Frag / Fragnesia entry-point probe for Blastwall verification.

This probe does not run exploit logic.  It only tries to open kernel entry
points used by the public Dirty Frag and Fragnesia write-ups: NETLINK_XFRM for
the xfrm-ESP control plane, AF_RXRPC for the RxRPC path, and AF_ALG for
Fragnesia's AES helper.  Blastwall should deny each surface for the confined
automation domain.  AF_RXRPC and AF_ALG are required release surfaces, so
absence is reported as FAIL_MISSING_CLASS_REQUIRED rather than skipped.

Exit codes:
    0   BLOCKED      - no Dirty Frag / Fragnesia entry point was reachable
    1   FAIL_*       - at least one required entry point was reachable or unknown
"""

import errno
import socket
import sys


NETLINK_XFRM = getattr(socket, "NETLINK_XFRM", 6)
AF_RXRPC = getattr(socket, "AF_RXRPC", 33)
AF_ALG = getattr(socket, "AF_ALG", 38)


def check_socket(label, family, socktype, proto, skip_errnos=()):
    try:
        sock = socket.socket(family, socktype, proto)
    except PermissionError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            print(f"BLOCKED: {label} socket creation denied with errno {exc.errno}")
            return "blocked"
        print(f"FAIL: unexpected {label} permission error: {exc}", file=sys.stderr)
        return "failed"
    except OSError as exc:
        if exc.errno in skip_errnos:
            print(f"FAIL_MISSING_CLASS_REQUIRED: {label} unavailable on this kernel: {exc}")
            return "failed"
        print(f"FAIL_UNKNOWN: {label} failed with unexpected errno: {exc}")
        return "failed"

    sock.close()
    print(f"FAIL_ALLOWED: {label} socket creation succeeded")
    return "failed"


def main() -> int:
    results = [
        check_socket(
            "Dirty Frag NETLINK_XFRM",
            socket.AF_NETLINK,
            socket.SOCK_RAW,
            NETLINK_XFRM,
        ),
        check_socket(
            "Dirty Frag AF_RXRPC",
            AF_RXRPC,
            socket.SOCK_DGRAM,
            0,
            skip_errnos=(errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.ENOPROTOOPT),
        ),
        check_socket(
            "Fragnesia AF_ALG",
            AF_ALG,
            socket.SOCK_SEQPACKET,
            0,
            skip_errnos=(errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.ENOPROTOOPT),
        ),
    ]

    return 1 if "failed" in results else 0


if __name__ == "__main__":
    raise SystemExit(main())
