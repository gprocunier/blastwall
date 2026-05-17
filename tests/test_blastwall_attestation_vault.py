#!/usr/bin/env python3
"""Unit tests for Blastwall KRA vault helpers."""

from __future__ import annotations

import hashlib
import importlib.util
import errno
import subprocess
import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
VAULT_PATH = ROOT / "tools" / "blastwall_attestation_vault.py"

spec = importlib.util.spec_from_file_location("blastwall_attestation_vault", VAULT_PATH)
vault = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["blastwall_attestation_vault"] = vault
spec.loader.exec_module(vault)


class FakeVaultCommandRunner:
    """Capture vault command calls and return scripted outputs."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, command, input_data=None):
        self.calls.append({"command": command, "input_data": input_data})
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class BlastwallVaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = vault.VaultConfig.from_mapping(
            {
                "blastwall_attestation_vault_primary": "idm-01.workshop.lan",
                "blastwall_attestation_vault_servers": ["idm-01.workshop.lan", "idm-02.workshop.lan"],
                "blastwall_attestation_vault_scope": "service",
                "blastwall_attestation_vault_owner": "blastwall-attestation/idm-01.workshop.lan",
                "blastwall_attestation_vault_retry_not_found": True,
                "blastwall_attestation_vault_retry_attempts": 3,
                "blastwall_attestation_vault_retry_delay_seconds": 0,
            }
        )

    def assert_command_targets_server(self, command: list[str], *, server: str, vault_ref: str) -> None:
        self.assertIn("--server", command)
        server_index = command.index("--server")
        self.assertEqual(command[server_index + 1], server)

        self.assertIn("--vault-ref", command)
        ref_index = command.index("--vault-ref")
        self.assertEqual(command[ref_index + 1], vault_ref)

    def test_config_requires_primary_in_server_list(self) -> None:
        with self.assertRaises(ValueError):
            vault.VaultConfig.from_mapping(
                {
                    "blastwall_attestation_vault_primary": "idm-01.workshop.lan",
                    "blastwall_attestation_vault_servers": ["idm-02.workshop.lan"],
                }
            )

    def test_write_records_server_ref_and_digest(self) -> None:
        payload = '{"attestation":"v3"}'
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        ref = "service/blastwall-attestation/blastwall-attestations/host/base/9.json"
        runner = FakeVaultCommandRunner(
            [
                vault.VaultCommandResult(stdout=b"", stderr=b"", returncode=0),
            ]
        )

        result = vault.write_vault_artifact(
            server="idm-01.workshop.lan",
            config=self.config,
            vault_ref=ref,
            payload=payload,
            command_runner=runner,
        )

        self.assertEqual(result.server, "idm-01.workshop.lan")
        self.assertEqual(result.vault_ref, ref)
        self.assertEqual(result.digest, expected)
        self.assertEqual(result.attempts, 1)
        self.assertEqual(result.retry_attempted, False)
        self.assert_command_targets_server(runner.calls[0]["command"], server="idm-01.workshop.lan", vault_ref=ref)

    def test_read_returns_payload_and_digest(self) -> None:
        ref = "service/blastwall-attestation/blastwall-attestations/host/base/9.json"
        payload = b'{"attestation":"v3","version":3}'
        expected = hashlib.sha256(payload).hexdigest()
        runner = FakeVaultCommandRunner(
            [vault.VaultCommandResult(stdout=payload, stderr=b"", returncode=0)]
        )

        result = vault.read_vault_artifact(
            server="idm-01.workshop.lan",
            config=self.config,
            vault_ref=ref,
            command_runner=runner,
        )

        self.assertEqual(result.payload, payload)
        self.assertEqual(result.digest, expected)
        self.assertEqual(result.server, "idm-01.workshop.lan")
        self.assert_command_targets_server(runner.calls[0]["command"], server="idm-01.workshop.lan", vault_ref=ref)

    def test_readback_digest_verification_happy_path(self) -> None:
        ref = "service/blastwall-attestation/blastwall-attestations/host/base/9.json"
        payload = b'{"attestation":"v3","version":3}'
        expected = hashlib.sha256(payload).hexdigest()
        runner = FakeVaultCommandRunner(
            [vault.VaultCommandResult(stdout=payload, stderr=b"", returncode=0)]
        )

        result = vault.read_vault_artifact_with_digest(
            server="idm-01.workshop.lan",
            config=self.config,
            vault_ref=ref,
            expected_digest=expected,
            command_runner=runner,
        )
        self.assertEqual(result.digest, expected)

    def test_readback_digest_verification_detects_mismatch(self) -> None:
        ref = "service/blastwall-attestation/blastwall-attestations/host/base/9.json"
        payload = b'{"attestation":"v3","version":3}'
        runner = FakeVaultCommandRunner(
            [vault.VaultCommandResult(stdout=payload, stderr=b"", returncode=0)]
        )

        with self.assertRaises(vault.VaultReadbackDigestMismatch):
            vault.read_vault_artifact_with_digest(
                server="idm-01.workshop.lan",
                config=self.config,
                vault_ref=ref,
                expected_digest="0" * 64,
                command_runner=runner,
            )

    def test_default_runner_accepts_readwrite_call_shape(self) -> None:
        original = vault._run_ipa_vault_command
        calls = []

        def fake_run_ipa_vault_command(command, *, input_data=None, timeout=None):
            calls.append({"command": command, "input_data": input_data, "timeout": timeout})
            return vault.VaultCommandResult(stdout=b"", stderr=b"", returncode=0)

        vault._run_ipa_vault_command = fake_run_ipa_vault_command
        try:
            result = vault._run_command(["blastwall-ipa-vault", "write"], b"payload")
        finally:
            vault._run_ipa_vault_command = original

        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls[0]["input_data"], b"payload")

    def test_read_retry_on_not_found_when_enabled(self) -> None:
        ref = "service/blastwall-attestation/blastwall-attestation-index/host/base.json"
        payload = b'{"index":1}'
        runner = FakeVaultCommandRunner(
            [
                vault.VaultCommandResult(stdout=b"", stderr=b"not found", returncode=1),
                vault.VaultCommandResult(stdout=payload, stderr=b"", returncode=0),
            ]
        )

        result = vault.read_vault_artifact(
            server="idm-01.workshop.lan",
            config=self.config,
            vault_ref=ref,
            command_runner=runner,
        )

        self.assertEqual(result.payload, payload)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(result.retry_attempted, True)
        self.assertEqual(len(runner.calls), 2)

    def test_auth_failure_is_structured_and_not_retried(self) -> None:
        ref = "service/blastwall-attestation/blastwall-attestations/host/base/9.json"
        runner = FakeVaultCommandRunner(
            [
                vault.VaultCommandResult(
                    stdout=b"",
                    stderr=b"authentication failed",
                    returncode=1,
                ),
                vault.VaultCommandResult(stdout=b'{"ok":true}', stderr=b"", returncode=0),
            ]
        )

        with self.assertRaises(vault.VaultCommandError) as exc:
            vault.read_vault_artifact(
                server="idm-01.workshop.lan",
                config=self.config,
                vault_ref=ref,
                command_runner=runner,
            )
        self.assertEqual(exc.exception.context.vault_error_type, vault.VaultErrorType.AUTH_FAILURE)
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(exc.exception.context.attempts, 1)

    def test_classify_not_found(self) -> None:
        error_type = vault.classify_vault_error(returncode=1, stderr="No such vault artifact")
        self.assertEqual(error_type, vault.VaultErrorType.NOT_FOUND)

    def test_classify_connection_refused_by_exception(self) -> None:
        error_type = vault.classify_vault_error(error=OSError(errno.ECONNREFUSED, "connection refused"))
        self.assertEqual(error_type, vault.VaultErrorType.CONNECTION_REFUSED)

    def test_classify_timeout_by_exception(self) -> None:
        error_type = vault.classify_vault_error(error=subprocess.TimeoutExpired(cmd=["blastwall-ipa-vault"], timeout=5))
        self.assertEqual(error_type, vault.VaultErrorType.TIMEOUT)


if __name__ == "__main__":
    unittest.main()
