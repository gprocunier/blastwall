#!/usr/bin/env python3
"""Safe Dirty Frag entry-point probe for Blastwall verification.

This probe does not run Dirty Frag exploit logic.  It only tries to open the
kernel entry points the public write-up relies on: NETLINK_XFRM for the
xfrm-ESP path and AF_RXRPC for the RxRPC path.  Blastwall should deny both for
the confined automation domain.  If AF_RXRPC is absent from the kernel, that
side is reported as SKIP.

Exit codes:
    0   BLOCKED/SKIP - no Dirty Frag entry point was reachable
    1   FAIL         - at least one entry point was reachable
"""

import errno
import socket
import sys


NETLINK_XFRM = getattr(socket, "NETLINK_XFRM", 6)
AF_RXRPC = getattr(socket, "AF_RXRPC", 33)


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
            print(f"SKIP: {label} unavailable on this kernel: {exc}")
            return "skipped"
        print(f"INFO: {label} did not reach success path: {exc}")
        return "blocked"

    sock.close()
    print(f"FAIL: {label} socket creation succeeded")
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
    ]

    return 1 if "failed" in results else 0


if __name__ == "__main__":
    raise SystemExit(main())
