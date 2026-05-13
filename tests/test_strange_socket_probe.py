#!/usr/bin/env python3
"""Unit tests for the strange-socket-v1 safe probe."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE_PATH = ROOT / "tests" / "trigger-strange-socket-v1-deny.py"

spec = importlib.util.spec_from_file_location("trigger_strange_socket_v1_deny", PROBE_PATH)
probe = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["trigger_strange_socket_v1_deny"] = probe
spec.loader.exec_module(probe)


class StrangeSocketProbeTests(unittest.TestCase):
    def test_first_wave_probe_list_is_complete(self) -> None:
        self.assertEqual(
            {case.object_class for case in probe.PROBES},
            {
                "xdp_socket",
                "tipc_socket",
                "can_socket",
                "bluetooth_socket",
                "nfc_socket",
                "kcm_socket",
                "rds_socket",
            },
        )

    def test_absent_selinux_class_reports_skip_absent(self) -> None:
        case = probe.ProbeCase("AF_TEST", "definitely_absent_socket", 9999, 1, 0)
        result = probe.check_socket(case)
        if probe.SELINUX_CLASS_DIR.exists():
            self.assertEqual(result.status, "SKIP_ABSENT")
        else:
            self.assertIn(result.status, {"BLOCKED", "SKIP_ABSENT", "FAIL_ALLOWED", "FAIL_UNKNOWN"})


if __name__ == "__main__":
    unittest.main()
