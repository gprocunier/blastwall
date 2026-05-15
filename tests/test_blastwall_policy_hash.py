#!/usr/bin/env python3
"""Tests for Blastwall installed policy payload hashing."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HASH_PATH = ROOT / "tools" / "blastwall_policy_hash.py"

spec = importlib.util.spec_from_file_location("blastwall_policy_hash", HASH_PATH)
policy_hash = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(policy_hash)


class BlastwallPolicyHashTests(unittest.TestCase):
    def test_hash_changes_when_payload_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "blastwall.pp").write_text("base policy\n", encoding="utf-8")
            first = policy_hash.payload_sha256(policy_hash.collect_payload(root))
            (root / "blastwall.pp").write_text("changed policy\n", encoding="utf-8")
            second = policy_hash.payload_sha256(policy_hash.collect_payload(root))
        self.assertNotEqual(first, second)

    def test_dry_run_payload_is_only_included_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "blastwall.pp").write_text("base policy\n", encoding="utf-8")
            (root / "blastwall-strange-socket-v1-deny.cil").write_text("dry run\n", encoding="utf-8")
            base_only = policy_hash.payload_sha256(policy_hash.collect_payload(root))
            with_dry_run = policy_hash.payload_sha256(
                policy_hash.collect_payload(root, include_dry_run=True)
            )
        self.assertNotEqual(base_only, with_dry_run)

    def test_records_are_sorted_by_relative_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "b.cil").write_text("b\n", encoding="utf-8")
            (root / "a.cil").write_text("a\n", encoding="utf-8")
            records = policy_hash.collect_payload(root, files=["b.cil", "a.cil"])
        self.assertEqual([record["path"] for record in records], ["a.cil", "b.cil"])


if __name__ == "__main__":
    unittest.main()
