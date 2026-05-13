#!/usr/bin/env python3
"""Unit tests for the Blastwall profile registry validator."""

from __future__ import annotations

import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "tools" / "validate_blastwall_profiles.py"
REGISTRY_PATH = ROOT / "policy" / "profiles.yml"

spec = importlib.util.spec_from_file_location("validate_blastwall_profiles", VALIDATOR_PATH)
validator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(validator)


class ProfileRegistryValidatorTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.registry = yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))

    def write_registry(self, registry) -> Path:
        temp = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yml", delete=False)
        with temp:
            yaml.safe_dump(registry, temp, sort_keys=False)
        return Path(temp.name)

    def assert_error_contains(self, registry, expected: str) -> None:
        path = self.write_registry(registry)
        try:
            errors = validator.validate_registry(path)
        finally:
            path.unlink(missing_ok=True)
        self.assertTrue(errors, "expected validation to fail")
        self.assertTrue(
            any(expected in error for error in errors),
            f"expected {expected!r} in {errors!r}",
        )

    def test_current_registry_validates(self) -> None:
        self.assertEqual(validator.validate_registry(REGISTRY_PATH), [])

    def test_dry_run_scopes_require_target_support(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["scopes"]["xdp_socket"]["target_support"] = {}
        self.assert_error_contains(registry, "dry-run scope xdp_socket must declare target_support")

    def test_unknown_scope_referenced_by_profile_fails(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["profiles"]["base"]["scopes"].append("missing_scope")
        self.assert_error_contains(registry, "profile base references unknown scope")

    def test_unknown_scope_removed_by_variant_fails(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["variants"]["base-nested"]["remove"] = ["missing_scope"]
        self.assert_error_contains(registry, "variant base-nested removes unknown scope")

    def test_missing_required_field_fails(self) -> None:
        registry = copy.deepcopy(self.registry)
        del registry["scopes"]["alg_socket"]["description"]
        self.assert_error_contains(registry, "scope alg_socket missing required field: description")

    def test_duplicate_mapping_key_fails(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yml", delete=False) as temp:
            temp.write(
                "schema: blastwall.profile/v1\n"
                "version: 1\n"
                "targets: {}\n"
                "permission_sets: {}\n"
                "scopes:\n"
                "  duplicate: {}\n"
                "  duplicate: {}\n"
                "profiles: {}\n"
                "variants: {}\n"
            )
            path = Path(temp.name)
        try:
            errors = validator.validate_registry(path)
        finally:
            path.unlink(missing_ok=True)
        self.assertTrue(any("duplicate mapping key: duplicate" in error for error in errors), errors)

    def test_unsupported_evidence_state_fails(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["scopes"]["alg_socket"]["evidence"]["present"] = "MAYBE"
        self.assert_error_contains(registry, "unsupported evidence state")

    def test_required_scope_absent_evidence_cannot_skip(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["scopes"]["rxrpc"]["evidence"]["absent"] = "SKIP_ABSENT"
        self.assert_error_contains(
            registry, "scope rxrpc required class_presence cannot use SKIP_ABSENT when class is required"
        )

    def test_io_uring_absent_evidence_is_not_skip(self) -> None:
        registry = copy.deepcopy(self.registry)
        self.assertEqual(
            registry["scopes"]["io_uring"]["evidence"].get("absent"),
            "FAIL_MISSING_CLASS_REQUIRED",
        )

    def test_missing_artifact_when_target_claims_support_fails(self) -> None:
        registry = copy.deepcopy(self.registry)
        del registry["scopes"]["alg_socket"]["target_support"]["rhel-login"]["artifact"]
        self.assert_error_contains(registry, "scope alg_socket target rhel-login missing artifact path")

    def test_missing_probe_for_required_safe_probe_fails(self) -> None:
        registry = copy.deepcopy(self.registry)
        del registry["scopes"]["alg_socket"]["target_support"]["rhel-login"]["validation"]["probe"]
        self.assert_error_contains(registry, "scope alg_socket target rhel-login release validation is missing probe")

    def test_profile_extends_must_be_list(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["profiles"]["strange-socket-v1"]["extends"] = "base"
        self.assert_error_contains(registry, "profile strange-socket-v1 extends must be a list")

    def test_variant_targets_must_be_list(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["variants"]["base-nested"]["targets"] = "ocp-spo-nested"
        self.assert_error_contains(registry, "variant base-nested targets must be a list")

    def test_variant_remove_entries_must_be_strings(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["variants"]["base-nested"]["remove"] = [42]
        self.assert_error_contains(registry, "variant base-nested remove entries must be strings")


if __name__ == "__main__":
    unittest.main()
