#!/usr/bin/env python3
"""Tests for Blastwall marker parsing and emission."""

from __future__ import annotations

import importlib.util
import datetime
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKER_PATH = ROOT / "tools" / "blastwall_marker.py"
MARKER_CLI_TIMEOUT = 30
LEGACY_V1_MARKER = (
    "blastwall:state=active;rpm=blastwall-selinux-0.5.2-1;"
    "rpm_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;"
    "alg=deny;bpf=deny;self=deny;pkt=deny;userns=deny;iou=deny;xfrm=deny;rxrpc=deny"
)

spec = importlib.util.spec_from_file_location("blastwall_marker", MARKER_PATH)
marker = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["blastwall_marker"] = marker
spec.loader.exec_module(marker)


class BlastwallMarkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = marker.load_registry()
        self.registry_hash = marker.registry_sha256()
        self.policy_hash = "b" * 64

    def parse(
        self,
        text: str,
        required_profiles: set[str] | None = None,
        expected_target: str | None = None,
        allow_dry_run_profiles: bool = False,
    ):
        return marker.parse_marker(
            text,
            registry=self.registry,
            expected_registry_sha256=self.registry_hash,
            expected_target=expected_target,
            required_profiles=required_profiles,
            allow_dry_run_profiles=allow_dry_run_profiles,
        )

    def v3_marker(
        self,
        state: str = "active",
        *,
        profiles: list[str] | None = None,
        attest_ref: str = "shared/blastwall-attestations/example.json",
        attest_sha256: str = "e" * 64,
        signer_kid: str = "4c2a9f12ab34cd56ef7890ab1234567890abcdef",
        generation: int = 7,
        exp: datetime.datetime | None = None,
        allow_dry_run_profiles: bool = False,
    ) -> str:
        exp = exp or (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1))
        return marker.emit_marker_v3(
            registry=self.registry,
            rpm=marker.DEFAULT_RPM,
            profiles=profiles or ["base"],
            state=state,
            attest_ref=attest_ref,
            attest_sha256=attest_sha256,
            signer_kid=signer_kid,
            exp=exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            generation=generation,
            allow_dry_run_profiles=allow_dry_run_profiles,
        )

    def run_emit_cli(self, args: list[str], expect_success: bool = True):
        command = [
            sys.executable,
            str(MARKER_PATH),
            "--emit",
            "--policy-sha256",
            self.policy_hash,
            *args,
        ]
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=MARKER_CLI_TIMEOUT)
        if expect_success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def run_check_cli(
        self,
        marker_text: str,
        required_profiles: str = "base",
        *,
        extra_args: list[str] | None = None,
        expect_success: bool = True,
    ):
        command = [
            sys.executable,
            str(MARKER_PATH),
            "check",
            "--markers-stdin",
            "--required-profiles-csv",
            required_profiles,
            "--expected-registry-sha256",
            self.registry_hash,
        ]
        if extra_args:
            command.extend(extra_args)
        result = subprocess.run(
            command,
            input=json.dumps([marker_text]),
            check=False,
            capture_output=True,
            text=True,
            timeout=MARKER_CLI_TIMEOUT,
        )
        if expect_success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertEqual(result.returncode, 1, result.stderr)
        if result.stdout:
            return json.loads(result.stdout)
        return result

    def test_valid_v2_marker_parses(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        parsed = self.parse(text, allow_dry_run_profiles=True)
        self.assertTrue(parsed.suitable, parsed.errors)
        self.assertEqual(parsed.version, 2)
        self.assertEqual(parsed.profiles, {"base"})
        self.assertIn("alg_socket", parsed.scopes)
        self.assertIn("selfprotect", parsed.scopes)

    def test_multiple_profiles_parse(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
            profiles=["base", "strange-socket-v1"],
            allow_dry_run_profiles=True,
        )
        parsed = self.parse(text, allow_dry_run_profiles=True)
        self.assertTrue(parsed.suitable, parsed.errors)
        self.assertEqual(parsed.profiles, {"base", "strange-socket-v1"})
        self.assertIn("xdp_socket", parsed.scopes)

    def test_base_strange_socket_v1_marker_from_emit_stays_valid(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
            profiles=["base", "strange-socket-v1"],
            allow_dry_run_profiles=True,
        )
        parsed = self.parse(
            text,
            required_profiles={"base", "strange-socket-v1"},
            allow_dry_run_profiles=True,
        )
        self.assertTrue(parsed.suitable, parsed.errors)
        self.assertEqual(parsed.profiles, {"base", "strange-socket-v1"})
        self.assertIn("xdp_socket", parsed.scopes)

    def test_base_profile_rejects_extra_profile_scopes(self) -> None:
        base_scopes = ",".join(self.registry["profiles"]["base"]["scopes"])
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        text = text.replace(
            f"scopes={base_scopes}",
            f"scopes={base_scopes},xdp_socket",
        )
        parsed = self.parse(text)
        self.assertFalse(parsed.suitable, parsed.errors)
        self.assertTrue(any("marker scopes not implied by selected profiles" in error for error in parsed.errors), parsed.errors)

    def test_base_profile_rejects_unknown_scope(self) -> None:
        base_scopes = ",".join(self.registry["profiles"]["base"]["scopes"])
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        text = text.replace(
            f"scopes={base_scopes}",
            f"scopes={base_scopes},evil_scope",
        )
        parsed = self.parse(text)
        self.assertFalse(parsed.suitable, parsed.errors)
        self.assertTrue(any("marker scopes unknown to registry" in error for error in parsed.errors), parsed.errors)

    def test_v2_marker_accepts_unknown_fields(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        text = f"{text};notes=inventory-test;origin=option-a"
        parsed = self.parse(text)
        self.assertTrue(parsed.suitable, parsed.errors)
        self.assertEqual(parsed.profiles, {"base"})

    def test_v2_marker_accepts_duplicate_unknown_fields(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        parsed = self.parse(f"{text};notes=first;notes=second")
        self.assertTrue(parsed.suitable, parsed.errors)

    def test_v2_marker_rejects_duplicate_reserved_fields(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        fields = {
            key: value
            for key, value in (
                token.split("=", 1)
                for token in text.removeprefix("blastwall:").split(";")
                if "=" in token
            )
        }
        for field in ["v", "state", "rpm", "registry_sha256", "policy_sha256", "profiles", "scopes"]:
            with self.subTest(field=field):
                parsed = self.parse(f"{text};{field}={fields[field]}")
                self.assertFalse(parsed.suitable)
                self.assertIn(f"duplicate reserved marker field: {field}", parsed.errors)

    def _remove_marker_field(self, text: str, field: str) -> str:
        stripped = text.removeprefix("blastwall:")
        return "blastwall:" + ";".join(
            token for token in stripped.split(";") if not token.startswith(f"{field}=") and token
        )

    def test_valid_v3_marker_parses_as_locator_hint(self) -> None:
        text = self.v3_marker()
        parsed = self.parse(text, allow_dry_run_profiles=True)
        self.assertFalse(parsed.suitable)
        self.assertTrue(parsed.hint, parsed.errors)
        self.assertEqual(parsed.version, 3)
        self.assertEqual(parsed.state, "active")
        self.assertEqual(parsed.generation, 7)
        self.assertEqual(parsed.signer_kid, "4c2a9f12ab34cd56ef7890ab1234567890abcdef")
        self.assertEqual(parsed.attest_ref, "shared/blastwall-attestations/example.json")

    def test_check_cli_does_not_treat_v3_locator_as_suitable(self) -> None:
        result = self.run_check_cli(self.v3_marker(), expect_success=False)
        self.assertFalse(result["suitable"])
        self.assertEqual(result["hints"][0]["version"], 3)
        self.assertEqual(result["hints"][0]["attest_sha256"], "e" * 64)

    def test_v3_marker_rejects_unknown_version(self) -> None:
        text = (
            "blastwall:v=9;state=active;target=rhel-login;"
            f"rpm={marker.DEFAULT_RPM};profiles=base;"
            "attest_ref=shared/blastwall-attestations/example.json;"
            "attest_sha256=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee;"
            "signer_kid=4c2a9f12ab34cd56ef7890ab1234567890abcdef;"
            "exp=2099-01-01T00:00:00Z;generation=1"
        )
        parsed = self.parse(text)
        self.assertFalse(parsed.suitable, parsed.errors)
        self.assertIn("unsupported marker version: 9", parsed.errors)

    def test_v3_marker_rejects_missing_required_fields(self) -> None:
        text = self.v3_marker()
        for field in ["attest_ref", "attest_sha256", "signer_kid", "exp", "generation"]:
            with self.subTest(field=field):
                parsed = self.parse(self._remove_marker_field(text, field))
                self.assertFalse(parsed.suitable, parsed.errors)
                self.assertIn(f"missing {field}", parsed.errors)

    def test_v3_marker_rejects_duplicate_reserved_fields(self) -> None:
        text = self.v3_marker()
        parsed = self.parse(f"{text};generation=8")
        self.assertFalse(parsed.suitable, parsed.errors)
        self.assertIn("duplicate reserved marker field: generation", parsed.errors)

    def test_v3_marker_rejects_invalid_signer_kid(self) -> None:
        parsed = self.parse(self._remove_marker_field(self.v3_marker(), "signer_kid") + ";signer_kid=AA11")
        self.assertFalse(parsed.suitable, parsed.errors)
        self.assertIn("signer_kid is not lowercase SKI hex", parsed.errors)

    def test_v3_marker_rejects_embedded_artifact_as_attest_ref(self) -> None:
        text = (
            self._remove_marker_field(self.v3_marker(), "attest_ref")
            + ';attest_ref={"envelope_version":1,"payload":{}}'
        )
        parsed = self.parse(text)
        self.assertFalse(parsed.hint, parsed.errors)
        self.assertIn("attest_ref is not a vault locator", parsed.errors)

    def test_v3_marker_rejects_invalid_expiry_format(self) -> None:
        parsed = self.parse(self._remove_marker_field(self.v3_marker(), "exp") + ";exp=2026-01-01 00:00:00")
        self.assertFalse(parsed.suitable, parsed.errors)
        self.assertIn("exp is not RFC3339 UTC timestamp", parsed.errors)

    def test_v3_marker_rejects_expired(self) -> None:
        text = self.v3_marker()
        expired = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        text = self._remove_marker_field(text, "exp") + f";exp={expired.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        parsed = self.parse(text)
        self.assertFalse(parsed.suitable, parsed.errors)
        self.assertIn("marker has expired", parsed.errors)

    def test_v3_marker_rejects_revoked_state(self) -> None:
        parsed = self.parse(self.v3_marker(state="revoked"))
        self.assertFalse(parsed.suitable, parsed.errors)
        self.assertIn("marker is revoked", parsed.errors)

    def test_v3_marker_rejects_non_integer_generation(self) -> None:
        parsed = self.parse(self._remove_marker_field(self.v3_marker(), "generation") + ";generation=one")
        self.assertFalse(parsed.suitable, parsed.errors)
        self.assertIn("generation is not integer", parsed.errors)

    def test_emit_marker_v3_includes_locator_inputs(self) -> None:
        text = marker.emit_marker_v3(
            registry=self.registry,
            rpm=marker.DEFAULT_RPM,
            profiles=["base"],
            state="active",
            attest_ref="shared/blastwall-attestations/example.json",
            attest_sha256="a" * 64,
            signer_kid="4c2a9f12ab34cd56ef7890ab1234567890abcdef",
            exp=(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            generation=99,
        )
        self.assertIn("attest_ref=shared/blastwall-attestations/example.json", text)
        self.assertIn("attest_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", text)
        self.assertIn("signer_kid=4c2a9f12ab34cd56ef7890ab1234567890abcdef", text)
        self.assertIn("generation=99", text)

    def test_emit_marker_v3_rejects_missing_locator(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing attest_ref"):
            marker.emit_marker_v3(
                registry=self.registry,
                rpm=marker.DEFAULT_RPM,
                profiles=["base"],
                state="active",
                attest_ref="",
                attest_sha256="a" * 64,
                signer_kid="4c2a9f12ab34cd56ef7890ab1234567890abcdef",
                exp=(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                generation=1,
            )

    def test_emit_marker_v3_rejects_embedded_artifact_locator(self) -> None:
        with self.assertRaisesRegex(ValueError, "attest_ref is not a vault locator"):
            marker.emit_marker_v3(
                registry=self.registry,
                rpm=marker.DEFAULT_RPM,
                profiles=["base"],
                attest_ref='{"envelope_version":1}',
                attest_sha256="a" * 64,
                signer_kid="4c2a9f12ab34cd56ef7890ab1234567890abcdef",
                exp=(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                generation=1,
            )

    def test_v2_marker_accepts_reordered_scopes(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        expected_scopes = ",".join(self.registry["profiles"]["base"]["scopes"])
        text = text.replace(
            f"scopes={expected_scopes}",
            "scopes=rxrpc,xfrm,selfprotect,io_uring,userns,packet_socket,capability2_bpf,bpf,alg_socket",
        )
        parsed = self.parse(text)
        self.assertTrue(parsed.suitable, parsed.errors)
        self.assertEqual(parsed.scopes, marker.expand_profiles(self.registry, {"base"}))

    def test_required_profiles_parse_regardless_of_marker_order(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
            profiles=["strange-socket-v1", "base"],
            allow_dry_run_profiles=True,
        )
        parsed = self.parse(
            text,
            required_profiles={"base", "strange-socket-v1"},
            allow_dry_run_profiles=True,
        )
        self.assertTrue(parsed.suitable, parsed.errors)
        self.assertEqual(parsed.profiles, {"base", "strange-socket-v1"})

    def test_future_profile_superset_fails(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
            profiles=["base", "strange-socket-v1"],
            allow_dry_run_profiles=True,
        ).replace("profiles=base,strange-socket-v1", "profiles=base,strange-socket-v1,future-profile")
        parsed = self.parse(
            text,
            required_profiles={"base", "strange-socket-v1"},
            allow_dry_run_profiles=True,
        )
        self.assertFalse(parsed.suitable)
        self.assertIn("unknown profile: future-profile", parsed.errors)

    def test_expected_target_mismatch_fails(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        parsed = self.parse(text, expected_target="ocp-spo-standard")
        self.assertFalse(parsed.suitable)
        self.assertTrue(any("target mismatch" in err for err in parsed.errors), parsed.errors)

    def test_missing_profiles_field_fails(self) -> None:
        text = (
            "blastwall:v=2;state=active;target=rhel-login;"
            f"rpm={marker.DEFAULT_RPM};registry_sha256={self.registry_hash};"
            f"policy_sha256={self.policy_hash};scopes=alg_socket,bpf"
        )
        parsed = self.parse(text)
        self.assertFalse(parsed.suitable)
        self.assertIn("missing profiles", parsed.errors)

    def test_emit_marker_deduplicates_profiles_preserving_order(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
            profiles=["base", "strange-socket-v1", "base", "strange-socket-v1"],
            allow_dry_run_profiles=True,
        )
        self.assertIn("profiles=base,strange-socket-v1", text)
        parsed = self.parse(text, allow_dry_run_profiles=True)
        self.assertTrue(parsed.suitable, parsed.errors)
        self.assertEqual(parsed.profiles, {"base", "strange-socket-v1"})

    def test_unknown_only_profile_cannot_satisfy_required_evidence(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        ).replace("profiles=base", "profiles=future-profile")
        parsed = self.parse(text)
        self.assertFalse(parsed.suitable)
        self.assertIn("required profile missing", parsed.errors)

    def test_required_strange_socket_profile_fails_closed(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        parsed = self.parse(
            text,
            required_profiles={"base", "strange-socket-v1"},
            allow_dry_run_profiles=False,
        )
        self.assertFalse(parsed.suitable)
        self.assertIn("required profile missing", parsed.errors)

    def test_missing_registry_hash_fails(self) -> None:
        text = (
            "blastwall:v=2;state=active;target=rhel-login;"
            f"rpm={marker.DEFAULT_RPM};policy_sha256={self.policy_hash};"
            "profiles=base;scopes=alg_socket"
        )
        parsed = self.parse(text)
        self.assertFalse(parsed.suitable)
        self.assertIn("missing registry_sha256", parsed.errors)

    def test_non_hex_policy_hash_fails(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        ).replace(f"policy_sha256={self.policy_hash}", "policy_sha256=not-a-hash")
        parsed = self.parse(text)
        self.assertFalse(parsed.suitable)
        self.assertIn("policy_sha256 is not 64 lowercase hex", parsed.errors)

    def test_expected_policy_hash_mismatch_fails(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        parsed = marker.parse_marker(
            text,
            registry=self.registry,
            expected_registry_sha256=self.registry_hash,
            expected_policy_sha256="c" * 64,
        )
        self.assertFalse(parsed.suitable)
        self.assertIn("policy_sha256 does not match installed policy payload", parsed.errors)

    def test_check_cli_rejects_wrong_expected_policy_hash(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        result = self.run_check_cli(
            text,
            extra_args=["--expected-policy-sha256", "c" * 64],
            expect_success=False,
        )
        flattened_errors = [error for marker_errors in result["errors"] for error in marker_errors]
        self.assertIn("policy_sha256 does not match installed policy payload", flattened_errors)

    def test_check_cli_rejects_wrong_accepted_rpm(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        result = self.run_check_cli(
            text,
            extra_args=["--accepted-rpm", "blastwall-selinux-9.9.9-1"],
            expect_success=False,
        )
        flattened_errors = [error for marker_errors in result["errors"] for error in marker_errors]
        self.assertIn("marker rpm is not accepted", flattened_errors)

    def test_failed_and_rollback_states_are_not_suitable(self) -> None:
        for state in ["failed", "rollback-active", "rollback-failed"]:
            text = marker.emit_marker_v2(
                registry=self.registry,
                registry_hash=self.registry_hash,
                policy_hash=self.policy_hash,
                rpm=marker.DEFAULT_RPM,
                state=state,
            )
            parsed = self.parse(text)
            self.assertFalse(parsed.suitable)
            self.assertEqual(parsed.state, state)

    def test_unknown_required_profile_fails(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        ).replace("profiles=base", "profiles=base,missing")
        parsed = self.parse(text, required_profiles={"base", "missing"})
        self.assertFalse(parsed.suitable)
        self.assertIn("unknown required profile: missing", parsed.errors)

    def test_emit_v2_base_and_strange_socket_profile_expands_registry_scopes(self) -> None:
        marker_text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
            profiles=["base", "strange-socket-v1"],
            allow_dry_run_profiles=True,
        )
        parsed = self.parse(
            marker_text,
            required_profiles={"base", "strange-socket-v1"},
            allow_dry_run_profiles=True,
        )
        self.assertTrue(parsed.suitable, parsed.errors)
        self.assertEqual(
            parsed.scopes,
            marker.expand_profiles(self.registry, {"base", "strange-socket-v1"}),
        )

    def test_smoke_cli_emit_base(self) -> None:
        marker_text = self.run_emit_cli([])
        parsed = self.parse(marker_text)
        self.assertTrue(parsed.suitable, parsed.errors)
        self.assertEqual(parsed.profiles, {"base"})
        self.assertEqual(parsed.state, "active")

    def test_smoke_cli_emit_strange_with_dry_run_allow(self) -> None:
        marker_text = self.run_emit_cli([
            "--allow-dry-run-profiles",
            "--profile",
            "strange-socket-v1",
        ])
        parsed = self.parse(marker_text)
        required_profiles = {"base", "strange-socket-v1"}
        parsed = self.parse(
            marker_text,
            required_profiles=required_profiles,
            allow_dry_run_profiles=True,
        )
        self.assertTrue(parsed.suitable, parsed.errors)
        self.assertEqual(parsed.profiles, required_profiles)
        self.assertEqual(parsed.state, "lab-active")

    def test_smoke_cli_rejects_strange_without_dry_run_allow(self) -> None:
        result = self.run_emit_cli(["--profile", "base", "--profile", "strange-socket-v1"], expect_success=False)
        self.assertIn("FAIL: dry-run profile not allowed: strange-socket-v1", result.stdout)

    def test_smoke_check_cli_reads_markers_from_stdin(self) -> None:
        marker_text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        result = self.run_check_cli(marker_text)
        self.assertTrue(result["suitable"])
        self.assertEqual(result["checked"], 1)
        self.assertEqual(result["matches"][0]["profiles"], ["base"])
        self.assertEqual(result["matches"][0]["version"], 2)

    def test_smoke_check_cli_rejects_legacy_base_plus_strange(self) -> None:
        result = self.run_check_cli(
            LEGACY_V1_MARKER,
            required_profiles="base,strange-socket-v1",
            expect_success=False,
        )
        self.assertFalse(result["suitable"])
        flattened_errors = [error for marker_errors in result["errors"] for error in marker_errors]
        self.assertIn("legacy marker can only satisfy base profile", flattened_errors)

    def test_emit_unknown_profile_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown profile: missing"):
            marker.emit_marker_v2(
                registry=self.registry,
                registry_hash=self.registry_hash,
                policy_hash=self.policy_hash,
                rpm=marker.DEFAULT_RPM,
                profiles=["base", "missing"],
            )

    def test_profile_cycle_fails_closed(self) -> None:
        registry = {
            "profiles": {
                "base": {"extends": ["loop"], "scopes": ["alg_socket"]},
                "loop": {"extends": ["base"], "scopes": ["bpf"]},
            }
        }
        text = (
            "blastwall:v=2;state=active;target=rhel-login;"
            f"rpm={marker.DEFAULT_RPM};registry_sha256={self.registry_hash};"
            f"policy_sha256={self.policy_hash};profiles=base;scopes=alg_socket,bpf"
        )
        parsed = marker.parse_marker(
            text,
            registry=registry,
            expected_registry_sha256=self.registry_hash,
        )
        self.assertFalse(parsed.suitable)
        self.assertIn("profile cycle detected: base", parsed.errors)

    def test_stale_registry_hash_fails(self) -> None:
        text = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash="a" * 64,
            policy_hash=self.policy_hash,
            rpm=marker.DEFAULT_RPM,
        )
        parsed = self.parse(text)
        self.assertFalse(parsed.suitable)
        self.assertIn("registry_sha256 is stale", parsed.errors)

    def test_v1_marker_maps_to_base_compatibility(self) -> None:
        text = (
            "blastwall:state=active;rpm=blastwall-selinux-0.5.2-1;"
            "rpm_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;"
            "alg=deny;bpf=deny;self=deny;pkt=deny;userns=deny;iou=deny;xfrm=deny;rxrpc=deny"
        )
        parsed = self.parse(text)
        self.assertTrue(parsed.suitable, parsed.errors)
        self.assertTrue(parsed.legacy)
        self.assertEqual(parsed.profiles, {"base"})

    def test_malformed_marker_fails_closed(self) -> None:
        parsed = self.parse("blastwall:v=2;state")
        self.assertFalse(parsed.suitable)
        self.assertIn("malformed marker token", parsed.errors)

    def test_legacy_marker_cannot_satisfy_non_base_profile(self) -> None:
        text = (
            "blastwall:state=active;rpm=blastwall-selinux-0.5.2-1;"
            "rpm_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;"
            "alg=deny;bpf=deny;self=deny;pkt=deny;userns=deny;iou=deny;xfrm=deny;rxrpc=deny"
        )
        parsed = self.parse(text, required_profiles={"strange-socket-v1"})
        self.assertFalse(parsed.suitable)
        self.assertIn("legacy marker can only satisfy base profile", parsed.errors)


if __name__ == "__main__":
    unittest.main()
