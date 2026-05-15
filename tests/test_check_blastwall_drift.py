#!/usr/bin/env python3
"""Unit tests for the Blastwall drift checker."""

from __future__ import annotations

import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "tools" / "check_blastwall_drift.py"
REGISTRY_PATH = ROOT / "policy" / "profiles.yml"

spec = importlib.util.spec_from_file_location("check_blastwall_drift", CHECKER_PATH)
checker = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(checker)


class BlastwallDriftCheckerTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.registry = yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))

    def write_registry(self, registry) -> Path:
        temp = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yml", delete=False)
        with temp:
            yaml.safe_dump(registry, temp, sort_keys=False)
        return Path(temp.name)

    def write_root_artifact(self, relative_path: str, content: str) -> Path:
        path = ROOT / relative_path
        path.write_text(content, encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def write_temp_root_artifact(self, *, suffix: str, content: str) -> str:
        temp = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            prefix="tmp-extra-",
            suffix=suffix,
            dir=ROOT / "tests",
            delete=False,
        )
        with temp:
            temp.write(content)
        path = Path(temp.name)
        self.addCleanup(path.unlink, missing_ok=True)
        return path.relative_to(ROOT).as_posix()

    def check_registry(self, registry):
        path = self.write_registry(registry)
        try:
            return checker.check_drift(path)
        finally:
            path.unlink(missing_ok=True)

    def assert_error_contains(self, registry, expected: str) -> None:
        result = self.check_registry(registry)
        self.assertTrue(result.errors, "expected drift check to fail")
        self.assertTrue(
            any(expected in error for error in result.errors),
            f"expected {expected!r} in {result.errors!r}",
        )

    def test_current_registry_has_no_blocking_drift(self) -> None:
        result = checker.check_drift(REGISTRY_PATH)
        self.assertEqual(result.errors, [])
        self.assertFalse(any(record.startswith("DEFERRED") for record in result.records), result.records)

    def test_active_profile_cannot_reference_planned_scope(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["profiles"]["base"]["scopes"].append("xdp_socket")
        registry["scopes"]["xdp_socket"]["status"] = "planned"
        self.assert_error_contains(registry, "active profile base references unsupported scope xdp_socket")

    def test_dry_run_profile_may_reference_dry_run_scope(self) -> None:
        result = checker.check_drift(REGISTRY_PATH)
        self.assertFalse(
            any("dry-run profile strange-socket-v1" in error for error in result.errors),
            result.errors,
        )

    def test_cil_artifact_must_have_deny_plus_neverallow(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["scopes"]["alg_socket"]["target_support"]["rhel-login"]["artifact"] = "policy/blastwall-role.cil"
        self.assert_error_contains(registry, "artifact lacks deny plus neverallow")

    def test_required_safe_probe_must_exist(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["scopes"]["alg_socket"]["target_support"]["rhel-login"]["validation"][
            "probe"
        ] = "tests/missing-probe.py"
        self.assert_error_contains(registry, "required probe missing")

    def test_variant_remove_scope_must_come_from_base_profile(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["variants"]["base-nested"]["remove"] = ["xdp_socket"]
        self.assert_error_contains(registry, "variant base-nested removes scope not in base profile")

    def test_optional_class_artifact_must_be_optional_wrapped(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["scopes"]["io_uring"]["target_support"]["rhel-login"]["artifact"] = "policy/blastwall-bpf-deny.cil"
        self.assert_error_contains(registry, "optional class lacks optional wrapper")

    def test_cil_artifact_rejects_extra_permission(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["scopes"]["alg_socket"]["target_support"]["rhel-login"]["artifact"] = (
            self.write_temp_root_artifact(
                suffix=".cil",
                content="""
(deny blastwall_t self (alg_socket
  (accept append bind connect create getattr getopt ioctl listen lock map
   name_bind read recv_msg recvfrom relabelfrom relabelto send_msg sendto
   setattr setopt shutdown write bogus_perm)))
(neverallow blastwall_t self (alg_socket
  (accept append bind connect create getattr getopt ioctl listen lock map
   name_bind read recv_msg recvfrom relabelfrom relabelto send_msg sendto
   setattr setopt shutdown write bogus_perm)))
""",
            )
        )
        self.assert_error_contains(registry, "extra bogus_perm")

    def test_spo_artifact_rejects_extra_io_uring_map_permission(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["scopes"]["io_uring"]["target_support"]["ocp-spo-standard"]["artifact"] = (
            self.write_temp_root_artifact(
                suffix=".yaml",
                content="""
apiVersion: security-profiles-operator.x-k8s.io/v1alpha2
kind: RawSelinuxProfile
metadata:
  name: tmp-extra-io-uring
spec:
  policy: |
    (blockinherit container)
    (optional tmp_io_uring
      (deny process self (io_uring (cmd map override_creds sqpoll)))
      (neverallow process self (io_uring (cmd map override_creds sqpoll))))
""",
            )
        )
        self.assert_error_contains(registry, "extra map")

    def test_cil_parse_error_is_reported_explicitly(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["scopes"]["alg_socket"]["target_support"]["rhel-login"]["artifact"] = (
            self.write_temp_root_artifact(
                suffix=".cil",
                content="(deny blastwall_t self (alg_socket (create read))\n",
            )
        )
        self.assert_error_contains(registry, "FAIL_CIL_PARSE_ERROR")

    def test_checked_profile_must_be_documented(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["profiles"]["undocumented-profile"] = {
            "description": "Dry-run profile intentionally missing from docs.",
            "status": "dry-run",
            "scopes": ["alg_socket"],
        }
        self.assert_error_contains(registry, "dry-run profile undocumented-profile is not mentioned")

    def test_spo_targets_must_use_status_usage_contract(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["targets"]["ocp-spo-standard"]["usage_source"] = "hardcoded"
        self.assert_error_contains(registry, "target ocp-spo-standard must declare usage_source: status.usage")


if __name__ == "__main__":
    unittest.main()
