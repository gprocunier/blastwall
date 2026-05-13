#!/usr/bin/env python3
"""Safe AF_ALG/authencesn bind probe.

This does not perform a Copy Fail exploit.  It only attempts to bind an AF_ALG
socket to the vulnerable template name so policy can prove the path is denied.
"""

import errno
import socket
import struct
import sys


AF_ALG = getattr(socket, "AF_ALG", 38)


def main() -> int:
    try:
        sock = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            print(f"BLOCKED: AF_ALG socket creation denied with errno {exc.errno}")
            return 0
        if exc.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
            print(f"FAIL_MISSING_CLASS_REQUIRED: could not create AF_ALG socket: {exc}", file=sys.stderr)
            return 1
        print(f"FAIL_UNKNOWN: could not create AF_ALG socket: {exc}", file=sys.stderr)
        return 1

    try:
        # Python exposes AF_ALG bind as a tuple: (type, name).
        sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    except PermissionError as exc:
        if exc.errno == errno.EPERM:
            print("BLOCKED: AF_ALG authencesn bind denied with EPERM")
            return 0
        print(f"FAIL: unexpected permission error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        # ENOENT/EINVAL can mean the algorithm is unavailable or patched out.
        print(f"FAIL_UNKNOWN: bind did not reach blocked evidence path: {exc}")
        return 1
    finally:
        sock.close()

    print("FAIL_ALLOWED: authencesn AF_ALG bind succeeded")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
