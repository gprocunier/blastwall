#!/usr/bin/env python3
"""Tests for the Blastwall v3 attestation signing workflow helper."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from dataclasses import replace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import blastwall_attestation as attestation  # noqa: E402
import blastwall_attestation_sign as signer  # noqa: E402
import blastwall_attestation_vault as vault  # noqa: E402
import blastwall_marker as marker  # noqa: E402


def _keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem_private_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _pem_certificate(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _certificate(
    *,
    common_name: str,
    issuer_name: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
    subject_key: rsa.RSAPrivateKey,
    is_ca: bool = False,
) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
    )
    if is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


class MemoryVault:
    def __init__(self) -> None:
        self.payloads: dict[str, bytes] = {}
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], input_data: bytes | None) -> vault.VaultCommandResult:
        self.commands.append(command)
        ref = command[command.index("--vault-ref") + 1]
        if "write" in command:
            self.payloads[ref] = input_data or b""
            return vault.VaultCommandResult(stdout=b"", stderr=b"", returncode=0)
        if ref not in self.payloads:
            return vault.VaultCommandResult(stdout=b"", stderr=b"not found", returncode=44)
        return vault.VaultCommandResult(stdout=self.payloads[ref], stderr=b"", returncode=0)


class BlastwallAttestationSignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = marker.load_registry()
        self.registry_sha = marker.registry_sha256()
        ca_key = _keypair()
        signer_key = _keypair()
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "blastwall-test-ca")])
        self.ca_cert = _certificate(
            common_name="blastwall-test-ca",
            issuer_name=ca_name,
            issuer_key=ca_key,
            subject_key=ca_key,
            is_ca=True,
        )
        self.signer_cert = _certificate(
            common_name="blastwall-attestation-signer",
            issuer_name=self.ca_cert.subject,
            issuer_key=ca_key,
            subject_key=signer_key,
        )
        self.signer_kid = attestation.extract_signer_kid(self.signer_cert)
        self.spo_evidence = {
            "bundle_sha256": "d" * 64,
            "validation_output_digest": "e" * 64,
            "spo_version": "spo-0.10.0",
            "ocp_version": "4.16.0",
            "status_usage": "blastwall.process",
            "scc_type": "s0:c123,c456",
            "admitted_pod_context": "system_u:system_r:system_dbusd_t:s0",
            "validation_results": {"standard_profile": "passed"},
        }
        self.temp = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp.name)
        self.signer_key_path = self.temp_path / "signer.key"
        self.signer_cert_path = self.temp_path / "signer.pem"
        self.ca_path = self.temp_path / "ca.pem"
        self.signer_key_path.write_bytes(_pem_private_key(signer_key))
        self.signer_cert_path.write_bytes(_pem_certificate(self.signer_cert))
        self.ca_path.write_bytes(_pem_certificate(self.ca_cert))
        self.inputs = signer.SignInputs(
            subject_host="mirror-registry.workshop.lan",
            target="rhel-login",
            rpm_nevra=marker.DEFAULT_RPM,
            policy_sha256="b" * 64,
            registry_sha256=self.registry_sha,
            probe_report_sha256="c" * 64,
            profiles=["base"],
            state="active",
            generation=7,
            source_revision="1234567890abcdef1234567890abcdef12345678",
            aap_workflow_job_id=1234,
            valid_for_seconds=3600,
            nonce="unit-test",
            signer_key=self.signer_key_path,
            signer_certificate=self.signer_cert_path,
            ca_bundle=self.ca_path,
            signer_allowlist=[self.signer_kid],
            spo_evidence=None,
            allow_dry_run_profiles=False,
        )
        self.ocp_inputs = replace(
            self.inputs,
            target="ocp-spo-standard",
            spo_evidence=self.spo_evidence,
        )
        self.vault_config = vault.VaultConfig(
            primary="idm-01.workshop.lan",
            servers=("idm-01.workshop.lan",),
            retry_delay_seconds=0,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_sign_store_readback_materializes_verified_marker(self) -> None:
        memory_vault = MemoryVault()
        report = signer.sign_store_readback(
            self.inputs,
            registry=self.registry,
            vault_config=self.vault_config,
            envelope_dir=self.temp_path / "envelopes",
            index_dir=self.temp_path / "indexes",
            command_runner=memory_vault,
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["attestation_sha256"], report["verification"]["details"]["attest_sha256"])
        self.assertEqual(report["index_generation"], 7)
        self.assertEqual(report["signer_kid"], self.signer_kid)
        self.assertIn("blastwall:v=3;", report["marker"])
        self.assertTrue(Path(report["envelope_file"]).exists())
        self.assertTrue(Path(report["index_file"]).exists())
        envelope = json.loads(Path(report["envelope_file"]).read_text(encoding="utf-8"))
        index = json.loads(Path(report["index_file"]).read_text(encoding="utf-8"))
        self.assertEqual(attestation.attestation_envelope_sha256(envelope), report["attestation_sha256"])
        self.assertEqual(attestation.latest_index_sha256(index), report["index_sha256"])
        envelope_file_sha = hashlib.sha256(Path(report["envelope_file"]).read_bytes()).hexdigest()
        index_file_sha = hashlib.sha256(Path(report["index_file"]).read_bytes()).hexdigest()
        self.assertEqual(envelope_file_sha, report["attestation_sha256"])
        self.assertEqual(index_file_sha, report["index_sha256"])
        self.assertNotIn("PRIVATE KEY", json.dumps(report))
        self.assertTrue(any("--server" in command and "idm-01.workshop.lan" in command for command in memory_vault.commands))

    def test_retrieve_existing_materializes_marker_referenced_artifacts(self) -> None:
        memory_vault = MemoryVault()
        signed = signer.sign_store_readback(
            self.inputs,
            registry=self.registry,
            vault_config=self.vault_config,
            envelope_dir=None,
            index_dir=None,
            command_runner=memory_vault,
        )
        retrieved = signer.retrieve_existing_artifacts(
            self.inputs,
            registry=self.registry,
            vault_config=self.vault_config,
            marker_text=signed["marker"],
            envelope_dir=self.temp_path / "retrieved_envelopes",
            index_dir=self.temp_path / "retrieved_indexes",
            command_runner=memory_vault,
        )
        self.assertEqual(retrieved["status"], "PASS")
        self.assertEqual(retrieved["attestation_ref"], signed["attestation_ref"])
        self.assertEqual(retrieved["attestation_sha256"], signed["attestation_sha256"])
        self.assertEqual(retrieved["verification"]["status"], "PASS")
        self.assertTrue(Path(retrieved["envelope_file"]).exists())
        self.assertTrue(Path(retrieved["index_file"]).exists())
        self.assertTrue(any(command[1] == "read" for command in memory_vault.commands))

    def test_resolve_existing_maps_marker_to_deterministic_vault_artifacts(self) -> None:
        memory_vault = MemoryVault()
        signed = signer.sign_store_readback(
            self.inputs,
            registry=self.registry,
            vault_config=self.vault_config,
            envelope_dir=None,
            index_dir=None,
            command_runner=memory_vault,
        )
        resolved = signer.resolve_existing_artifacts(
            self.inputs,
            registry=self.registry,
            vault_config=self.vault_config,
            marker_text=signed["marker"],
            envelope_dir=self.temp_path / "resolved_envelopes",
            index_dir=self.temp_path / "resolved_indexes",
        )
        self.assertEqual(resolved["status"], "PASS")
        self.assertEqual(resolved["attestation_ref"], signed["attestation_ref"])
        self.assertEqual(resolved["attestation_sha256"], signed["attestation_sha256"])
        self.assertEqual(resolved["index_ref"], signed["index_ref"])
        self.assertEqual(
            resolved["vault_artifacts"]["envelope"]["name"],
            signer._vault_artifact_name(signed["attestation_ref"]),
        )
        self.assertEqual(
            resolved["vault_artifacts"]["index"]["name"],
            signer._vault_artifact_name(signed["index_ref"]),
        )
        self.assertEqual(Path(resolved["envelope_file"]).name, f"{self.inputs.subject_host}.json")
        self.assertEqual(Path(resolved["index_file"]).name, f"{self.inputs.subject_host}.json")

    def test_resolve_existing_revoked_marker_reports_revoked_attestation_state(self) -> None:
        memory_vault = MemoryVault()
        signed = signer.sign_store_readback(
            self.inputs,
            registry=self.registry,
            vault_config=self.vault_config,
            envelope_dir=None,
            index_dir=None,
            command_runner=memory_vault,
        )
        revoked_marker = marker.emit_marker_v3(
            registry=self.registry,
            rpm=self.inputs.rpm_nevra,
            profiles=self.inputs.profiles,
            target=self.inputs.target,
            state="revoked",
            attest_ref=signed["attestation_ref"],
            attest_sha256=signed["attestation_sha256"],
            signer_kid=signed["signer_kid"],
            exp=(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            generation=signed["index_generation"],
        )
        with self.assertRaisesRegex(ValueError, "FAIL_REVOKED_ATTESTATION"):
            signer.resolve_existing_artifacts(
                self.inputs,
                registry=self.registry,
                vault_config=self.vault_config,
                marker_text=revoked_marker,
                envelope_dir=self.temp_path / "revoked_envelopes",
                index_dir=self.temp_path / "revoked_indexes",
            )

    def test_retrieve_existing_rejects_digest_mismatch_before_signature_verification(self) -> None:
        memory_vault = MemoryVault()
        signed = signer.sign_store_readback(
            self.inputs,
            registry=self.registry,
            vault_config=self.vault_config,
            envelope_dir=None,
            index_dir=None,
            command_runner=memory_vault,
        )
        memory_vault.payloads[signed["attestation_ref"]] = b"tampered envelope readback"
        with self.assertRaises(vault.VaultReadbackDigestMismatch):
            signer.retrieve_existing_artifacts(
                self.inputs,
                registry=self.registry,
                vault_config=self.vault_config,
                marker_text=signed["marker"],
                envelope_dir=self.temp_path / "digest_mismatch_envelopes",
                index_dir=self.temp_path / "digest_mismatch_indexes",
                command_runner=memory_vault,
            )

    def test_sign_store_readback_with_ocp_spo_evidence(self) -> None:
        memory_vault = MemoryVault()
        report = signer.sign_store_readback(
            self.ocp_inputs,
            registry=self.registry,
            vault_config=self.vault_config,
            envelope_dir=self.temp_path / "ocp_envelopes",
            index_dir=self.temp_path / "ocp_indexes",
            command_runner=memory_vault,
        )
        payload = json.loads(Path(report["envelope_file"]).read_text(encoding="utf-8"))["payload"]
        self.assertEqual(payload["target"], "ocp-spo-standard")
        self.assertIn("spo_evidence", payload)
        self.assertEqual(payload["spo_evidence"]["ocp_version"], "4.16.0")

    def test_sign_store_readback_ocp_without_spo_evidence_fails_schema_validation(self) -> None:
        memory_vault = MemoryVault()
        bad_inputs = replace(self.inputs, target="ocp-spo-standard", spo_evidence=None)
        with self.assertRaisesRegex(ValueError, "schema validation failed"):
            signer.sign_store_readback(
                bad_inputs,
                registry=self.registry,
                vault_config=self.vault_config,
                envelope_dir=self.temp_path / "bad_ocp_envelopes",
                index_dir=self.temp_path / "bad_ocp_indexes",
                command_runner=memory_vault,
            )

    def test_rhel_and_ocp_targets_share_envelope_and_index_model(self) -> None:
        memory_vault = MemoryVault()
        rhel_report = signer.sign_store_readback(
            self.inputs,
            registry=self.registry,
            vault_config=self.vault_config,
            envelope_dir=self.temp_path / "rhel_envelopes",
            index_dir=self.temp_path / "rhel_indexes",
            command_runner=memory_vault,
        )
        ocp_report = signer.sign_store_readback(
            self.ocp_inputs,
            registry=self.registry,
            vault_config=self.vault_config,
            envelope_dir=self.temp_path / "ocp_envelopes",
            index_dir=self.temp_path / "ocp_indexes",
            command_runner=memory_vault,
        )
        rhel_envelope = json.loads(Path(rhel_report["envelope_file"]).read_text(encoding="utf-8"))
        ocp_envelope = json.loads(Path(ocp_report["envelope_file"]).read_text(encoding="utf-8"))
        rhel_index = json.loads(Path(rhel_report["index_file"]).read_text(encoding="utf-8"))
        ocp_index = json.loads(Path(ocp_report["index_file"]).read_text(encoding="utf-8"))
        self.assertEqual(set(rhel_envelope.keys()), set(ocp_envelope.keys()))
        self.assertEqual(set(rhel_index.keys()), set(ocp_index.keys()))

    def test_verify_existing_rejects_policy_drift(self) -> None:
        memory_vault = MemoryVault()
        report = signer.sign_store_readback(
            self.inputs,
            registry=self.registry,
            vault_config=self.vault_config,
            envelope_dir=self.temp_path / "envelopes",
            index_dir=self.temp_path / "indexes",
            command_runner=memory_vault,
        )
        drifted_inputs = signer.SignInputs(
            **{**self.inputs.__dict__, "policy_sha256": "d" * 64}
        )
        with self.assertRaisesRegex(ValueError, "FAIL_DRIFTED_POLICY"):
            signer.verify_existing_artifacts(
                drifted_inputs,
                registry=self.registry,
                envelope_text=Path(report["envelope_file"]).read_text(encoding="utf-8"),
                index_text=Path(report["index_file"]).read_text(encoding="utf-8"),
            )

    def test_failure_report_includes_structured_vault_context(self) -> None:
        context = vault.VaultErrorContext(
            server="idm-01.workshop.lan",
            vault_ref="shared/blastwall-attestation/test.json",
            vault_error_type=vault.VaultErrorType.AUTH_FAILURE,
            message="vault write failed: rc=1",
            command=["blastwall-ipa-vault", "write"],
            returncode=1,
            stderr="ipa: ERROR: Insufficient access",
        )
        report = signer._failure_report(vault.VaultCommandError(context))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["vault_error"]["vault_error_type"], "auth_failure")
        self.assertEqual(report["vault_error"]["stderr"], "ipa: ERROR: Insufficient access")

    def test_failure_report_extracts_failure_state_prefix(self) -> None:
        report = signer._failure_report(
            ValueError("FAIL_REVOKED_ATTESTATION: invalid v3 marker locator: marker is revoked")
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_state"], "FAIL_REVOKED_ATTESTATION")

    def test_stable_v3_rejects_shared_vault_scope(self) -> None:
        shared_config = vault.VaultConfig(
            primary="idm-01.workshop.lan",
            servers=("idm-01.workshop.lan",),
            scope="shared",
            owner="blastwall-attestation",
            retry_delay_seconds=0,
        )
        with self.assertRaisesRegex(ValueError, "FAIL_STABLE_V3_SHARED_CUSTODY"):
            signer._assert_vault_custody_allowed(
                attestation_mode="stable-v3",
                vault_config=shared_config,
            )

    def test_transition_v3_permits_explicit_shared_vault_scope(self) -> None:
        shared_config = vault.VaultConfig(
            primary="idm-01.workshop.lan",
            servers=("idm-01.workshop.lan",),
            scope="shared",
            owner="blastwall-attestation",
            retry_delay_seconds=0,
        )
        signer._assert_vault_custody_allowed(
            attestation_mode="transition-v3",
            vault_config=shared_config,
        )

    def test_vault_config_defaults_retry_fields_for_build_artifacts_cli(self) -> None:
        config = signer._vault_config(
            argparse.Namespace(
                vault_primary="idm-01.workshop.lan",
                vault_servers_csv="idm-01.workshop.lan",
                vault_scope="shared",
                vault_owner="blastwall-attestation",
            )
        )
        self.assertFalse(config.retry_not_found)
        self.assertEqual(config.retry_attempts, vault.DEFAULT_RETRY_ATTEMPTS)
        self.assertEqual(config.retry_delay_seconds, vault.DEFAULT_RETRY_DELAY_SECONDS)


if __name__ == "__main__":
    unittest.main()
