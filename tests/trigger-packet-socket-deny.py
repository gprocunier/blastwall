#!/usr/bin/env python3
"""Safe AF_PACKET socket probe for verifying SELinux packet_socket denial.

Attempts to create an AF_PACKET/SOCK_RAW socket, which is the entry
point for CVE-2025-38617 and CVE-2026-31504.  If SELinux policy denies
packet_socket operations for the calling domain, the socket call fails
with EPERM.

Exit codes:
    0   BLOCKED  - AF_PACKET socket creation denied with EPERM
    1   FAIL_ALLOWED                  - socket creation succeeded
    1   FAIL_UNKNOWN                  - unexpected errno or probe failure
    1   FAIL_MISSING_CLASS_REQUIRED   - AF_PACKET not available
"""

import errno
import os
import socket
import sys

AF_PACKET = getattr(socket, "AF_PACKET", 17)
ETH_P_ALL = 0x0003

def main():
    try:
        sock = socket.socket(AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            print("BLOCKED: AF_PACKET socket creation denied with "
                  "errno %d  [CVE-2025-38617, CVE-2026-31504]" % exc.errno)
            return 0
        print("FAIL: unexpected permission error: %s" % exc, file=sys.stderr)
        return 1
    except OSError as exc:
        if exc.errno == errno.EAFNOSUPPORT:
            print("FAIL_MISSING_CLASS_REQUIRED: AF_PACKET not supported on this system")
            return 1
        print("FAIL_UNKNOWN: AF_PACKET socket creation failed with %s "
              "(not EPERM/EACCES, cannot count as blocked evidence)" % exc)
        return 1

    sock.close()
    print("FAIL_ALLOWED: AF_PACKET socket creation succeeded - "
          "policy is NOT denying packet_socket")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
