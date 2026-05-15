#!/usr/bin/env python3
"""Compute a canonical Blastwall installed policy payload hash."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path


BASE_PAYLOAD_FILES = [
    "blastwall.pp",
    "blastwall-role.cil",
    "blastwall-sshd-login.cil",
    "blastwall-alg-socket-deny.cil",
    "blastwall-bpf-deny.cil",
    "blastwall-policy-selfprotect.cil",
    "blastwall-packet-socket-deny.cil",
    "blastwall-userns-deny.cil",
    "blastwall-io-uring-deny.cil",
    "blastwall-xfrm-deny.cil",
    "blastwall-rxrpc-deny.cil",
    "contexts/blastwall_u",
]
DRY_RUN_PAYLOAD_FILES = [
    "blastwall-strange-socket-v1-deny.cil",
    "dry-run/blastwall-strange-socket-v1-deny.cil",
]


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_payload(root: Path, include_dry_run: bool = False, files: list[str] | None = None) -> list[dict[str, str | int]]:
    """Return deterministic file evidence for the installed policy payload."""

    selected = list(files or BASE_PAYLOAD_FILES)
    if include_dry_run:
        selected.extend(DRY_RUN_PAYLOAD_FILES)

    records: list[dict[str, str | int]] = []
    seen: set[str] = set()
    for rel_path in selected:
        if rel_path in seen:
            continue
        seen.add(rel_path)
        path = root / rel_path
        if not path.is_file():
            continue
        metadata = path.stat()
        records.append(
            {
                "path": rel_path,
                "mode": stat.S_IMODE(metadata.st_mode),
                "size": metadata.st_size,
                "sha256": _hash_file(path),
            }
        )

    records.sort(key=lambda item: str(item["path"]))
    return records


def payload_sha256(records: list[dict[str, str | int]]) -> str:
    """Hash path, mode, size, and content digest for each payload file."""

    digest = hashlib.sha256()
    for record in records:
        line = (
            f"{record['path']}\0"
            f"{record['mode']}\0"
            f"{record['size']}\0"
            f"{record['sha256']}\n"
        )
        digest.update(line.encode("utf-8"))
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--include-dry-run", action="store_true")
    parser.add_argument("--file", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    records = collect_payload(
        args.root,
        include_dry_run=args.include_dry_run,
        files=args.file or None,
    )
    if not records:
        print(f"FAIL: no Blastwall policy payload files found under {args.root}", file=sys.stderr)
        return 1

    digest = payload_sha256(records)
    if args.json:
        print(json.dumps({"policy_sha256": digest, "files": records}, sort_keys=True))
    else:
        print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
