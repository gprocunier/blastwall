#!/usr/bin/env python3
"""Safe OpenShift/SPO probe harness for the Blastwall workload profile."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


EXPECTED_TYPE = os.environ.get("BLASTWALL_EXPECTED_SELINUX_TYPE", "blastwall_.process")
PROFILE_CLASS = os.environ.get("BLASTWALL_PROFILE_CLASS", "standard")


@dataclass
class ProbeResult:
    name: str
    status: str
    detail: str


def classify_errno(value: int | None) -> str:
    if value in (errno.EPERM, errno.EACCES):
        return "BLOCKED"
    if value in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.ENOPROTOOPT, errno.ENOSYS):
        return "SKIP"
    return "FAIL"


def read_context() -> str:
    try:
        context = subprocess.check_output(["id", "-Z"], text=True, stderr=subprocess.STDOUT).strip()
        if context:
            return context
    except Exception:
        pass

    try:
        return Path("/proc/self/attr/current").read_text(encoding="utf-8", errors="replace").strip("\x00\n")
    except Exception as exc:  # pragma: no cover - depends on container image
        return f"unavailable: {exc}"


def probe_socket(name: str, family: int, socktype: int, proto: int = 0) -> ProbeResult:
    try:
        sock = socket.socket(family, socktype, proto)
        sock.close()
        return ProbeResult(name, "FAIL", "socket creation succeeded")
    except OSError as exc:
        return ProbeResult(name, classify_errno(exc.errno), f"errno {exc.errno}: {exc.strerror}")


def probe_userns() -> ProbeResult:
    libc = ctypes.CDLL(None, use_errno=True)
    clone_newuser = 0x10000000
    rc = libc.unshare(clone_newuser)
    if rc == 0:
        return ProbeResult("userns", "FAIL", "unshare(CLONE_NEWUSER) succeeded")

    err = ctypes.get_errno()
    if err in (errno.EPERM, errno.EACCES):
        return ProbeResult("userns", "BLOCKED", f"errno {err}: {os.strerror(err)}")
    if err in (errno.EINVAL, errno.ENOSYS):
        return ProbeResult("userns", "SKIP", f"errno {err}: {os.strerror(err)}")
    return ProbeResult("userns", "FAIL", f"errno {err}: {os.strerror(err)}")


def read_proc_file(name: str, path: str) -> ProbeResult:
    try:
        value = Path(path).read_text(encoding="utf-8", errors="replace").strip()
        return ProbeResult(name, "PASS", value.replace("\n", " | "))
    except Exception as exc:  # pragma: no cover - depends on container runtime
        return ProbeResult(name, "SKIP", f"unavailable: {exc}")


def syscall_number(name: str) -> int | None:
    if os.uname().machine != "x86_64":
        return None
    return {
        "bpf": 321,
        "io_uring_setup": 425,
    }.get(name)


def probe_bpf() -> ProbeResult:
    number = syscall_number("bpf")
    if number is None:
        return ProbeResult("bpf", "SKIP", "syscall number unavailable for this architecture")

    libc = ctypes.CDLL(None, use_errno=True)
    attr = ctypes.create_string_buffer(256)
    # BPF_MAP_CREATE, BPF_MAP_TYPE_ARRAY, key_size=4, value_size=4, max_entries=1.
    struct.pack_into("IIIII", attr, 0, 1, 4, 4, 1, 0)
    rc = libc.syscall(number, 0, ctypes.byref(attr), ctypes.sizeof(attr))
    if rc >= 0:
        os.close(rc)
        return ProbeResult("bpf", "FAIL", "BPF_MAP_CREATE succeeded")

    err = ctypes.get_errno()
    if err in (errno.EPERM, errno.EACCES):
        return ProbeResult("bpf", "BLOCKED", f"errno {err}: {os.strerror(err)}")
    if err in (errno.ENOSYS, errno.EINVAL, errno.E2BIG):
        return ProbeResult("bpf", "SKIP", f"errno {err}: {os.strerror(err)}")
    return ProbeResult("bpf", "FAIL", f"errno {err}: {os.strerror(err)}")


def probe_io_uring_setup() -> ProbeResult:
    number = syscall_number("io_uring_setup")
    if number is None:
        return ProbeResult("io_uring_setup", "SKIP", "syscall number unavailable for this architecture")

    libc = ctypes.CDLL(None, use_errno=True)
    params = ctypes.create_string_buffer(256)
    rc = libc.syscall(number, 2, ctypes.byref(params))
    if rc >= 0:
        os.close(rc)
        return ProbeResult("io_uring_setup", "FAIL", "io_uring_setup succeeded")

    err = ctypes.get_errno()
    if err in (errno.EPERM, errno.EACCES):
        return ProbeResult("io_uring_setup", "BLOCKED", f"errno {err}: {os.strerror(err)}")
    if err in (errno.ENOSYS, errno.EINVAL):
        return ProbeResult("io_uring_setup", "SKIP", f"errno {err}: {os.strerror(err)}")
    return ProbeResult("io_uring_setup", "FAIL", f"errno {err}: {os.strerror(err)}")


def probe_syscall(name: str) -> ProbeResult:
    number = syscall_number(name)
    if number is None:
        return ProbeResult(name, "SKIP", "syscall number unavailable for this architecture")

    libc = ctypes.CDLL(None, use_errno=True)
    rc = libc.syscall(number, 0, 0, 0)
    if rc == 0:
        return ProbeResult(name, "FAIL", "syscall unexpectedly succeeded")

    err = ctypes.get_errno()
    if err in (errno.EPERM, errno.EACCES):
        return ProbeResult(name, "BLOCKED", f"errno {err}: {os.strerror(err)}")
    if err in (errno.ENOSYS, errno.EINVAL, errno.EFAULT):
        return ProbeResult(name, "SKIP", f"errno {err}: {os.strerror(err)}")
    return ProbeResult(name, "FAIL", f"errno {err}: {os.strerror(err)}")


def as_dict(result: ProbeResult) -> dict[str, str]:
    return {"name": result.name, "status": result.status, "detail": result.detail}


def main() -> int:
    context = read_context()
    userns_result = probe_userns()
    if PROFILE_CLASS == "nested" and userns_result.name == "userns":
        if userns_result.status == "FAIL" and "succeeded" in userns_result.detail:
            userns_result = ProbeResult("userns", "PASS", "unshare(CLONE_NEWUSER) succeeded")
        elif userns_result.status in ("BLOCKED", "SKIP"):
            userns_result = ProbeResult("userns", userns_result.status, f"second user namespace not required: {userns_result.detail}")

    results = [
        ProbeResult("selinux_context", "PASS" if EXPECTED_TYPE in context else "FAIL", context),
        probe_socket("NETLINK_XFRM", socket.AF_NETLINK, socket.SOCK_RAW, 6),
        probe_socket("AF_RXRPC", getattr(socket, "AF_RXRPC", 33), socket.SOCK_DGRAM, 0),
        probe_socket("AF_PACKET", socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)),
        probe_socket("AF_ALG", getattr(socket, "AF_ALG", 38), socket.SOCK_SEQPACKET, 0),
        userns_result,
        probe_bpf(),
        probe_io_uring_setup(),
    ]
    if PROFILE_CLASS == "nested":
        results.extend([
            read_proc_file("uid_map", "/proc/self/uid_map"),
            read_proc_file("gid_map", "/proc/self/gid_map"),
        ])
    overall = "PASS" if all(result.status in ("PASS", "BLOCKED", "SKIP") for result in results) else "FAIL"

    print(f"Profile class: {PROFILE_CLASS}")
    print(f"SELinux context: {context}")
    for result in results:
        print(f"{result.status}: {result.name}: {result.detail}")
    print(json.dumps({
        "overall": overall,
        "profile_class": PROFILE_CLASS,
        "expected_type": EXPECTED_TYPE,
        "selinux_context": context,
        "results": [as_dict(result) for result in results],
    }, sort_keys=True))

    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
