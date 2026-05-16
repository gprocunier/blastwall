#!/usr/bin/env python3
"""Tests for Blastwall v3 attestation verifier."""

from __future__ import annotations

import datetime
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import blastwall_attestation as attestation  # noqa: E402
import blastwall_attestation_verify as verifier  # noqa: E402
import blastwall_marker as marker  # noqa: E402


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def _keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _certificate(
    *,
    subject_common_name: str,
    issuer_common_name: str,
    issuer_key: rsa.RSAPrivateKey,
    subject_key: rsa.RSAPrivateKey,
    serial_number: int,
    is_ca: bool = False,
) -> x509.Certificate:
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_common_name)]))
        .public_key(subject_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(minutes=120))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def _pem_bytes(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _pem_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


class BlastwallAttestationVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = marker.load_registry()
        self.registry_hash = marker.registry_sha256()
        self.ca_key = _keypair()
        self.ca_cert = _certificate(
            subject_common_name="BlastwallTestCA",
            issuer_common_name="BlastwallTestCA",
            issuer_key=self.ca_key,
            subject_key=self.ca_key,
            serial_number=1,
            is_ca=True,
        )
        self.signer_key = _keypair()
        self.signer_cert = _certificate(
            subject_common_name="blastwall-attestation-signer",
            issuer_common_name="BlastwallTestCA",
            issuer_key=self.ca_key,
            subject_key=self.signer_key,
            serial_number=2,
        )
        self.signer_kid = attestation.extract_signer_kid(self.signer_cert)
        now = _now()
        self.policy_sha = "b" * 64
        self.payload: dict[str, Any] = {
            "attestation_version": 1,
            "subject_host": "mirror-registry.workshop.lan",
            "target": "rhel-login",
            "state": "active",
            "rpm_nevra": marker.DEFAULT_RPM,
            "registry_sha256": self.registry_hash,
            "policy_sha256": self.policy_sha,
            "profiles": ["base"],
            "scopes": sorted(marker.expand_profiles(self.registry, {"base"})),
            "probe_report_sha256": "c" * 64,
            "aap_workflow_job_id": 1234,
            "source_revision": "1234567890abcdef1234567890abcdef12345678",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "not_before": (now - datetime.timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "not_after": (now + datetime.timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
            "generation": 7,
            "signer_kid": self.signer_kid,
            "nonce": "nonce",
        }
        self.attest_ref = "service/blastwall-attestation/blastwall-attestations/mirror/base/7.json"
        self.envelope = attestation.build_attestation_envelope(
            self.payload,
            private_key=_pem_private_key(self.signer_key),
            signer_certificate=_pem_bytes(self.signer_cert),
        )
        self.envelope_sha = attestation.attestation_envelope_sha256(self.envelope)
        self.index = attestation.build_latest_index(
            {
                "subject_host": self.payload["subject_host"],
                "target": self.payload["target"],
                "profile_set": self.payload["profiles"],
                "latest_generation": self.payload["generation"],
                "latest_attest_ref": self.attest_ref,
                "latest_attest_sha256": self.envelope_sha,
                "state": "active",
                "issued_at": self.payload["issued_at"],
                "not_before": self.payload["not_before"],
                "not_after": self.payload["not_after"],
            },
            private_key=_pem_private_key(self.signer_key),
            signer_certificate=_pem_bytes(self.signer_cert),
        )
        self.marker_text = marker.emit_marker_v3(
            registry=self.registry,
            rpm=marker.DEFAULT_RPM,
            profiles=["base"],
            attest_ref=self.attest_ref,
            attest_sha256=self.envelope_sha,
            signer_kid=self.signer_kid,
            exp=(now + datetime.timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
            generation=7,
        )

    def verify(self, **kwargs: Any):
        return verifier.verify_attestation_for_marker(
            marker_text=kwargs.get("marker_text", self.marker_text),
            envelope_text=kwargs.get("envelope_text", json.dumps(self.envelope)),
            index_text=kwargs.get("index_text", json.dumps(self.index)),
            registry=self.registry,
            expected_registry_sha256=self.registry_hash,
            expected_host=kwargs.get("expected_host", "mirror-registry.workshop.lan"),
            expected_target="rhel-login",
            expected_rpm=marker.DEFAULT_RPM,
            current_policy_sha256=kwargs.get("current_policy_sha256", self.policy_sha),
            required_profiles=["base"],
            signer_certificate=kwargs.get("signer_certificate", self.signer_cert),
            ca_bundle=kwargs.get("ca_bundle", _pem_bytes(self.ca_cert)),
            signer_allowlist=kwargs.get("signer_allowlist", [self.signer_kid]),
            now=_now(),
        )

    def test_valid_attestation_passes(self) -> None:
        report = self.verify()
        self.assertEqual(report.status, "PASS", report.to_dict())
        self.assertEqual(report.details["attestation_generation"], 7)

    def test_marker_only_fails_without_envelope(self) -> None:
        report = self.verify(envelope_text=None)
        self.assertEqual(report.status, "FAIL")
        self.assertEqual(report.failure_state, "FAIL_ATTESTATION_NOT_VISIBLE")

    def test_v2_marker_fails_stable_v3(self) -> None:
        v2_marker = marker.emit_marker_v2(
            registry=self.registry,
            registry_hash=self.registry_hash,
            policy_hash=self.policy_sha,
            rpm=marker.DEFAULT_RPM,
        )
        report = self.verify(marker_text=v2_marker)
        self.assertEqual(report.failure_state, "FAIL_UNSUPPORTED_MARKER_VERSION")

    def test_live_policy_hash_drift_fails(self) -> None:
        report = self.verify(current_policy_sha256="d" * 64)
        self.assertEqual(report.status, "FAIL")
        self.assertEqual(report.failure_state, "FAIL_DRIFTED_POLICY")

    def test_replayed_generation_fails(self) -> None:
        replay_index = attestation.build_latest_index(
            {**self.index, "latest_generation": 8},
            private_key=_pem_private_key(self.signer_key),
            signer_certificate=_pem_bytes(self.signer_cert),
        )
        report = self.verify(index_text=json.dumps(replay_index))
        self.assertEqual(report.failure_state, "FAIL_REPLAYED_ATTESTATION")

    def test_cli_reports_json_and_exit_status(self) -> None:
        with tempfile.TemporaryDirectory(prefix="blastwall-attest-verify-") as temp_dir:
            temp = Path(temp_dir)
            envelope_path = temp / "envelope.json"
            index_path = temp / "index.json"
            cert_path = temp / "signer.pem"
            ca_path = temp / "ca.pem"
            envelope_path.write_text(json.dumps(self.envelope), encoding="utf-8")
            index_path.write_text(json.dumps(self.index), encoding="utf-8")
            cert_path.write_bytes(_pem_bytes(self.signer_cert))
            ca_path.write_bytes(_pem_bytes(self.ca_cert))
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "blastwall_attestation_verify.py"),
                    "--marker",
                    self.marker_text,
                    "--envelope-json",
                    str(envelope_path),
                    "--index-json",
                    str(index_path),
                    "--signer-certificate",
                    str(cert_path),
                    "--ca-bundle",
                    str(ca_path),
                    "--signer-allowlist-csv",
                    self.signer_kid,
                    "--expected-host",
                    "mirror-registry.workshop.lan",
                    "--expected-registry-sha256",
                    self.registry_hash,
                    "--current-policy-sha256",
                    self.policy_sha,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
