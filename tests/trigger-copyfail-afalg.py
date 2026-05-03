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
        print(f"SKIP: could not create AF_ALG socket: {exc}", file=sys.stderr)
        return 77

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
        print(f"INFO: bind did not reach success path: {exc}")
        return 0
    finally:
        sock.close()

    print("FAIL: authencesn AF_ALG bind succeeded")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
