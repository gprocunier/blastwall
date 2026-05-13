#!/usr/bin/env python3
"""Safe strange-socket-v1 probe for Blastwall lab validation.

The probe only attempts benign socket creation for low-value socket families.
It does not bind, connect, send, receive, or exercise protocol payloads.

Exit codes:
    0   BLOCKED/SKIP_ABSENT - no first-wave socket was reachable
    1   FAIL_ALLOWED        - at least one socket creation succeeded
    1   FAIL_UNKNOWN        - unexpected errno or probe failure
"""

from __future__ import annotations

import errno
import json
import socket
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


SELINUX_CLASS_DIR = Path("/sys/fs/selinux/class")
SKIP_ERRNOS = {
    errno.EAFNOSUPPORT,
    errno.EINVAL,
    errno.ENODEV,
    errno.ENOENT,
    errno.ENOPROTOOPT,
    errno.EPROTONOSUPPORT,
    errno.ESOCKTNOSUPPORT,
}


@dataclass(frozen=True)
class ProbeCase:
    name: str
    object_class: str
    family: int
    socktype: int
    protocol: int


@dataclass
class ProbeResult:
    name: str
    object_class: str
    status: str
    detail: str


def _family(name: str, fallback: int) -> int:
    return int(getattr(socket, name, fallback))


PROBES = [
    ProbeCase("AF_XDP", "xdp_socket", _family("AF_XDP", 44), socket.SOCK_RAW, 0),
    ProbeCase("AF_TIPC", "tipc_socket", _family("AF_TIPC", 30), socket.SOCK_RDM, 0),
    ProbeCase("AF_CAN", "can_socket", _family("AF_CAN", 29), socket.SOCK_RAW, getattr(socket, "CAN_RAW", 1)),
    ProbeCase("AF_BLUETOOTH", "bluetooth_socket", _family("AF_BLUETOOTH", 31), socket.SOCK_RAW, 0),
    ProbeCase("AF_NFC", "nfc_socket", _family("AF_NFC", 39), socket.SOCK_RAW, 0),
    ProbeCase("AF_KCM", "kcm_socket", _family("AF_KCM", 41), socket.SOCK_DGRAM, 0),
    ProbeCase("AF_RDS", "rds_socket", _family("AF_RDS", 21), socket.SOCK_SEQPACKET, 0),
]


def _class_absent(probe: ProbeCase) -> bool:
    return SELINUX_CLASS_DIR.exists() and not (SELINUX_CLASS_DIR / probe.object_class).exists()


def check_socket(probe: ProbeCase) -> ProbeResult:
    if _class_absent(probe):
        return ProbeResult(probe.name, probe.object_class, "SKIP_ABSENT", "SELinux object class is absent")

    try:
        sock = socket.socket(probe.family, probe.socktype, probe.protocol)
    except PermissionError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return ProbeResult(probe.name, probe.object_class, "BLOCKED", f"socket creation denied: errno {exc.errno}")
        return ProbeResult(probe.name, probe.object_class, "FAIL_UNKNOWN", f"unexpected permission error: {exc}")
    except OSError as exc:
        if exc.errno in SKIP_ERRNOS:
            return ProbeResult(probe.name, probe.object_class, "SKIP_ABSENT", f"socket unavailable: {exc}")
        return ProbeResult(probe.name, probe.object_class, "FAIL_UNKNOWN", f"socket creation failed before use: {exc}")

    sock.close()
    return ProbeResult(probe.name, probe.object_class, "FAIL_ALLOWED", "socket creation succeeded")


def main() -> int:
    results = [check_socket(probe) for probe in PROBES]
    for result in results:
        print(f"{result.status}: {result.name} {result.object_class}: {result.detail}")
    print(json.dumps({"results": [asdict(result) for result in results]}, sort_keys=True))
    return 1 if any(result.status in {"FAIL_ALLOWED", "FAIL_UNKNOWN"} for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
