#!/usr/bin/env python3
"""Safe user namespace creation probe for verifying SELinux userns denial.

Attempts to create a user namespace via unshare(CLONE_NEWUSER).  If
SELinux policy denies user_namespace create for the calling domain,
the syscall fails with EPERM.

User namespaces are the first step in many kernel exploit chains.
CVE-2025-38617 uses them to obtain CAP_NET_RAW unprivileged.

Exit codes:
    0   BLOCKED  - unshare(CLONE_NEWUSER) denied with EPERM/EACCES
    0   INFO     - denied for a non-permission reason
    1   FAIL     - user namespace creation succeeded (policy is NOT protecting)
   77   SKIP     - user namespaces not available
"""

import ctypes
import ctypes.util
import errno
import os
import sys

CLONE_NEWUSER = 0x10000000

def main():
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        print("SKIP: cannot find libc")
        sys.exit(77)

    libc = ctypes.CDLL(libc_name, use_errno=True)

    # Fork first so we don't unshare our own process if it succeeds
    pid = os.fork()
    if pid == 0:
        # Child: attempt unshare
        ret = libc.unshare(ctypes.c_int(CLONE_NEWUSER))
        if ret == 0:
            # unshare succeeded, namespace was created
            os._exit(1)
        err = ctypes.get_errno()
        if err == errno.EPERM:
            os._exit(10)
        elif err == errno.EACCES:
            os._exit(13)
        elif err == errno.EINVAL:
            os._exit(77)
        else:
            os._exit(2)

    # Parent: wait for child
    _, status = os.waitpid(pid, 0)
    exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 99

    if exit_code in (10, 13):
        errno_name = "EPERM" if exit_code == 10 else "EACCES"
        errno_value = errno.EPERM if exit_code == 10 else errno.EACCES
        print("BLOCKED: unshare(CLONE_NEWUSER) denied with "
              f"{errno_name} errno {errno_value}  [exploit chain enabler]")
        return 0
    elif exit_code == 1:
        print("FAIL: unshare(CLONE_NEWUSER) succeeded - "
              "policy is NOT denying user namespace creation")
        return 1
    elif exit_code == 77:
        print("SKIP: user namespaces not available on this kernel")
        return 77
    else:
        print("INFO: unshare(CLONE_NEWUSER) failed with unexpected "
              "error (exit %d)" % exit_code)
        return 0

if __name__ == "__main__":
    raise SystemExit(main())
