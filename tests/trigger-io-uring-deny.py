#!/usr/bin/env python3
"""Safe io_uring probe for verifying SELinux io_uring denial.

Attempts io_uring_setup(2) with a minimal 1-entry submission queue.
If SELinux policy denies io_uring operations for the calling domain,
the syscall fails with EPERM.

CVE-2026-43006 is the current open vulnerability; the io_uring
subsystem has a long history of privilege escalation bugs.

Exit codes:
    0   BLOCKED  - io_uring_setup denied with EPERM
    0   INFO     - denied for a non-permission reason
    1   FAIL     - io_uring_setup succeeded (policy is NOT protecting)
   77   SKIP     - io_uring not available on this kernel
"""

import ctypes
import ctypes.util
import errno
import os
import sys

def main():
    machine = os.uname().machine
    nr_table = {
        "x86_64": 425,
        "aarch64": 425,
        "s390x": 425,
        "ppc64le": 425,
    }
    NR_IO_URING_SETUP = nr_table.get(machine)
    if NR_IO_URING_SETUP is None:
        print("SKIP: unsupported architecture %s" % machine)
        sys.exit(77)

    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        print("SKIP: cannot find libc")
        sys.exit(77)
    libc = ctypes.CDLL(libc_name, use_errno=True)

    # struct io_uring_params (120 bytes, mostly zeros for defaults)
    PARAMS_SIZE = 120
    params = (ctypes.c_char * PARAMS_SIZE)()

    fd = libc.syscall(ctypes.c_long(NR_IO_URING_SETUP),
                      ctypes.c_uint(1),
                      ctypes.byref(params))

    if fd >= 0:
        os.close(fd)
        print("FAIL: io_uring_setup succeeded - "
              "policy is NOT denying io_uring  [CVE-2026-43006]")
        sys.exit(1)

    err = ctypes.get_errno()
    if err == errno.EPERM:
        print("BLOCKED: io_uring_setup denied with EPERM  [CVE-2026-43006]")
        sys.exit(0)
    elif err == errno.ENOSYS:
        print("SKIP: io_uring not available on this kernel")
        sys.exit(77)
    else:
        print("INFO: io_uring_setup failed with %s "
              "(not EPERM, may not be SELinux)" %
              errno.errorcode.get(err, str(err)))
        sys.exit(0)

if __name__ == "__main__":
    main()
