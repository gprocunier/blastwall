#!/usr/bin/env python3
"""Tests for Blastwall inventory audit reports."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

AUDIT_PATH = TOOLS / "audit_blastwall_inventory.py"
MARKER_PATH = TOOLS / "blastwall_marker.py"

audit_spec = importlib.util.spec_from_file_location("audit_blastwall_inventory", AUDIT_PATH)
audit = importlib.util.module_from_spec(audit_spec)
assert audit_spec.loader is not None
audit_spec.loader.exec_module(audit)

marker_spec = importlib.util.spec_from_file_location("blastwall_marker", MARKER_PATH)
marker = importlib.util.module_from_spec(marker_spec)
assert marker_spec.loader is not None
marker_spec.loader.exec_module(marker)


class BlastwallInventoryAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = marker.load_registry()
        self.registry_hash = marker.registry_sha256()
        self.base_marker = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash="a" * 64,
            rpm=marker.DEFAULT_RPM,
        )

    def audit(self, inventory, previous=None):
        return audit.audit_inventory(
            inventory,
            registry=self.registry,
            expected_registry_sha256=self.registry_hash,
            allow_dry_run_profiles=False,
            accepted_rpms={marker.DEFAULT_RPM},
            required_profiles={"base"},
            previous=previous,
        )

    def test_schema_errors_are_reported(self) -> None:
        inventory = {
            "_meta": {
                "hostvars": {
                    "dict.example.com": {"idm_userclass": {"bad": "shape"}},
                    "none.example.com": {"idm_userclass": None},
                    "mixed.example.com": {"idm_userclass": [self.base_marker, 7]},
                }
            }
        }
        report = self.audit(inventory)
        self.assertEqual(set(report["schema_errors"]), {"dict.example.com", "none.example.com", "mixed.example.com"})

    def test_marker_parse_errors_are_reported(self) -> None:
        inventory = {
            "_meta": {
                "hostvars": {
                    "bad-marker.example.com": {
                        "idm_userclass": [
                            self.base_marker.replace(self.registry_hash, "1" * 64)
                        ]
                    }
                }
            }
        }
        report = self.audit(inventory)
        self.assertIn("bad-marker.example.com", report["marker_parse_errors"])
        self.assertIn("registry_sha256 is stale", report["marker_parse_errors"]["bad-marker.example.com"])

    def test_current_marker_parse_error_contradiction_is_reported(self) -> None:
        inventory = {
            "_meta": {
                "hostvars": {
                    "bad-current.example.com": {
                        "idm_userclass": [
                            self.base_marker.replace(self.registry_hash, "1" * 64)
                        ]
                    }
                }
            },
            "blastwall_policy_current": {"hosts": ["bad-current.example.com"]},
        }
        report = self.audit(inventory)
        self.assertEqual(report["current_marker_parse_error_hosts"], ["bad-current.example.com"])

    def test_fail_on_current_marker_parse_error_cli_exits_nonzero(self) -> None:
        inventory = {
            "_meta": {
                "hostvars": {
                    "bad-current.example.com": {
                        "idm_userclass": [
                            self.base_marker.replace(self.registry_hash, "1" * 64)
                        ]
                    }
                }
            },
            "blastwall_policy_current": {"hosts": ["bad-current.example.com"]},
        }
        with tempfile.TemporaryDirectory(prefix="blastwall-audit-test-") as temp_dir:
            inventory_path = Path(temp_dir) / "inventory.json"
            inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(AUDIT_PATH),
                    "--inventory-json",
                    str(inventory_path),
                    "--fail-on-current-marker-parse-error",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(result.returncode, 1, result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["current_marker_parse_error_hosts"], ["bad-current.example.com"])

    def test_current_to_stale_movement_is_reported(self) -> None:
        current_inventory = {
            "_meta": {"hostvars": {"host.example.com": {"idm_userclass": []}}},
            "blastwall_policy_stale": {"hosts": ["host.example.com"]},
        }
        previous = {
            "host_groups": {
                "host.example.com": ["blastwall_policy_current", "blastwall_profile_base"]
            }
        }
        report = self.audit(current_inventory, previous=previous)
        self.assertEqual(report["current_to_stale"], ["host.example.com"])


if __name__ == "__main__":
    unittest.main()
