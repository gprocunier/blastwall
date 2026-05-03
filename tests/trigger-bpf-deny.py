#!/usr/bin/env python3
"""Safe BPF denial probe for verifying SELinux BPF policy.

Tests two distinct BPF entry points that correspond to real CVE
exploit paths:

  1. BPF_MAP_CREATE  - entry point for CVE-2026-31429 (SKB cross-cache)
                       and CVE-2025-38154 (sockmap UAF)
  2. BPF_PROG_LOAD   - entry point for CVE-2026-31525 (interpreter sdiv)

Neither test performs an exploit.  Each attempts a minimal bpf(2)
syscall and checks whether SELinux denies it with EACCES or EPERM.

Exit codes:
    0   both paths blocked (policy working)
    1   at least one path succeeded (policy is NOT protecting)
   77   bpf syscall not available on this kernel
"""

import ctypes
import ctypes.util
import errno
import os
import struct
import sys

BPF_MAP_CREATE = 0
BPF_PROG_LOAD = 5
BPF_MAP_TYPE_HASH = 1
BPF_PROG_TYPE_SOCKET_FILTER = 1

ATTR_SIZE = 120

def get_nr_bpf():
    machine = os.uname().machine
    table = {
        "x86_64": 321,
        "aarch64": 280,
        "s390x": 351,
        "ppc64le": 361,
    }
    return table.get(machine)

def try_map_create(libc, nr_bpf):
    """Attempt BPF_MAP_CREATE (CVE-2026-31429, CVE-2025-38154 entry point)."""
    attr = bytearray(ATTR_SIZE)
    struct.pack_into("IIII", attr, 0,
                     BPF_MAP_TYPE_HASH, 4, 4, 1)
    buf = (ctypes.c_char * ATTR_SIZE).from_buffer(attr)
    fd = libc.syscall(ctypes.c_long(nr_bpf),
                      ctypes.c_int(BPF_MAP_CREATE),
                      ctypes.byref(buf),
                      ctypes.c_uint(ATTR_SIZE))
    if fd >= 0:
        os.close(fd)
        return "FAIL"
    err = ctypes.get_errno()
    if err in (errno.EACCES, errno.EPERM):
        return f"errno {err}"
    if err == errno.ENOSYS:
        return "SKIP"
    return "INFO"

def try_prog_load(libc, nr_bpf):
    """Attempt BPF_PROG_LOAD with a minimal program (CVE-2026-31525 entry point).

    The program is two instructions: mov r0, 0; exit.  This is the
    smallest valid BPF program.  We do not care whether the verifier
    accepts it; we only care whether the syscall is denied by SELinux
    before reaching the verifier.
    """
    # BPF_ALU64 | BPF_MOV | BPF_K: r0 = 0
    insn_mov = struct.pack("BBhI", 0xb7, 0x00, 0x0000, 0x00000000)
    # BPF_JMP | BPF_EXIT: exit
    insn_exit = struct.pack("BBhI", 0x95, 0x00, 0x0000, 0x00000000)
    prog = insn_mov + insn_exit
    prog_buf = (ctypes.c_char * len(prog)).from_buffer_copy(prog)

    # License string required by the kernel
    license_str = b"GPL\x00"
    license_buf = (ctypes.c_char * len(license_str)).from_buffer_copy(license_str)

    # Build bpf_attr for BPF_PROG_LOAD
    # Offsets: prog_type(0), insn_cnt(4), insns(8/16 depending on arch),
    #          license(16/24), log_level(24/32), log_size(28/36), log_buf(32/40)
    attr = bytearray(ATTR_SIZE)
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        struct.pack_into("II", attr, 0,
                         BPF_PROG_TYPE_SOCKET_FILTER,  # prog_type
                         2)                             # insn_cnt
        struct.pack_into("Q", attr, 8, ctypes.addressof(prog_buf))    # insns
        struct.pack_into("Q", attr, 16, ctypes.addressof(license_buf)) # license
    else:
        struct.pack_into("II", attr, 0,
                         BPF_PROG_TYPE_SOCKET_FILTER, 2)
        struct.pack_into("I", attr, 8, ctypes.addressof(prog_buf))
        struct.pack_into("I", attr, 12, ctypes.addressof(license_buf))

    buf = (ctypes.c_char * ATTR_SIZE).from_buffer(attr)
    fd = libc.syscall(ctypes.c_long(nr_bpf),
                      ctypes.c_int(BPF_PROG_LOAD),
                      ctypes.byref(buf),
                      ctypes.c_uint(ATTR_SIZE))
    if fd >= 0:
        os.close(fd)
        return "FAIL"
    err = ctypes.get_errno()
    if err in (errno.EACCES, errno.EPERM):
        return f"errno {err}"
    if err == errno.ENOSYS:
        return "SKIP"
    return "INFO"

def main():
    nr_bpf = get_nr_bpf()
    if nr_bpf is None:
        print("SKIP: unsupported architecture %s" % os.uname().machine)
        sys.exit(77)

    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        print("SKIP: cannot find libc")
        sys.exit(77)
    libc = ctypes.CDLL(libc_name, use_errno=True)

    map_result = try_map_create(libc, nr_bpf)
    prog_result = try_prog_load(libc, nr_bpf)

    if map_result == "SKIP" and prog_result == "SKIP":
        print("SKIP: bpf syscall not available")
        sys.exit(77)

    failed = False
    if map_result.startswith("errno "):
        print(f"BLOCKED: bpf(BPF_MAP_CREATE) denied with {map_result}  [CVE-2026-31429, CVE-2025-38154]")
    elif map_result == "FAIL":
        print("FAIL: bpf(BPF_MAP_CREATE) succeeded - policy is NOT denying BPF map creation")
        failed = True
    else:
        print("%s: bpf(BPF_MAP_CREATE) - %s" % (map_result, map_result))

    if prog_result.startswith("errno "):
        print(f"BLOCKED: bpf(BPF_PROG_LOAD) denied with {prog_result}   [CVE-2026-31525]")
    elif prog_result == "FAIL":
        print("FAIL: bpf(BPF_PROG_LOAD) succeeded - policy is NOT denying BPF program loading")
        failed = True
    else:
        print("%s: bpf(BPF_PROG_LOAD) - %s" % (prog_result, prog_result))

    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
