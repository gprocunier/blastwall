#!/usr/bin/env python3
"""Tests for Blastwall signed latest-generation indexes."""

from __future__ import annotations

import datetime
import importlib.util
import json
import sys
import unittest
from copy import deepcopy
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
ATTESTATION_PATH = ROOT / "tools" / "blastwall_attestation.py"

spec = importlib.util.spec_from_file_location("blastwall_attestation", ATTESTATION_PATH)
attestation = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(attestation)


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


class BlastwallAttestationIndexTests(unittest.TestCase):
    def setUp(self) -> None:
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
        self.payload: dict[str, Any] = {
            "attestation_version": 1,
            "subject_host": "mirror-registry.workshop.lan",
            "target": "rhel-login",
            "state": "active",
            "rpm_nevra": "blastwall-selinux-0.6.1-0.rc1",
            "registry_sha256": "a" * 64,
            "policy_sha256": "b" * 64,
            "profiles": ["base"],
            "scopes": ["alg_socket"],
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
        self.index_payload = {
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
        }
        self.index = self.build_index()
        self.marker = {
            "attest_ref": self.attest_ref,
            "attest_sha256": self.envelope_sha,
        }

    def build_index(self, **overrides: Any) -> dict[str, Any]:
        index_payload = {**self.index_payload, **overrides}
        return attestation.build_latest_index(
            index_payload,
            private_key=_pem_private_key(self.signer_key),
            signer_certificate=_pem_bytes(self.signer_cert),
        )

    def verify(self, index: dict[str, Any] | None = None, marker: dict[str, Any] | None = None):
        return attestation.verify_latest_index(
            self.envelope,
            index or self.index,
            marker or self.marker,
            now=_now(),
            signer_certificate=self.signer_cert,
            ca_bundle=_pem_bytes(self.ca_cert),
            signer_allowlist=[self.signer_kid],
        )

    def test_valid_latest_index_verifies(self) -> None:
        result = self.verify()
        self.assertEqual(result["attestation_generation"], 7)
        self.assertEqual(result["index_generation"], 7)
        self.assertEqual(result["attest_sha256"], self.envelope_sha)

    def test_index_signature_tamper_fails(self) -> None:
        index = deepcopy(self.index)
        index["latest_generation"] = 8
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            self.verify(index=index)

    def test_older_attestation_generation_fails_replay(self) -> None:
        index = self.build_index(latest_generation=8)
        with self.assertRaises(attestation.AttestationVerificationError) as exc:
            self.verify(index=index)
        self.assertEqual(exc.exception.failure_state, "FAIL_REPLAYED_ATTESTATION")

    def test_index_digest_mismatch_fails(self) -> None:
        index = self.build_index(latest_attest_sha256="d" * 64)
        with self.assertRaises(attestation.AttestationVerificationError) as exc:
            self.verify(index=index)
        self.assertEqual(exc.exception.failure_state, "FAIL_ATTESTATION_DIGEST")

    def test_marker_digest_mismatch_fails(self) -> None:
        marker = {"attest_ref": self.attest_ref, "attest_sha256": "e" * 64}
        with self.assertRaises(attestation.AttestationVerificationError) as exc:
            self.verify(marker=marker)
        self.assertEqual(exc.exception.failure_state, "FAIL_ATTESTATION_DIGEST")

    def test_wrong_host_fails_binding(self) -> None:
        index = self.build_index(subject_host="other.example.com")
        with self.assertRaises(attestation.AttestationVerificationError) as exc:
            self.verify(index=index)
        self.assertEqual(exc.exception.failure_state, "FAIL_BINDING_MISMATCH")

    def test_wrong_profile_fails_binding(self) -> None:
        index = self.build_index(profile_set=["base", "strange-socket-v1"])
        with self.assertRaises(attestation.AttestationVerificationError) as exc:
            self.verify(index=index)
        self.assertEqual(exc.exception.failure_state, "FAIL_PROFILE_MISMATCH")

    def test_index_signed_by_wrong_signer_fails(self) -> None:
        other_key = _keypair()
        other_cert = _certificate(
            subject_common_name="other-attestation-signer",
            issuer_common_name="BlastwallTestCA",
            issuer_key=self.ca_key,
            subject_key=other_key,
            serial_number=3,
        )
        index = attestation.build_latest_index(
            self.index_payload,
            private_key=_pem_private_key(other_key),
            signer_certificate=_pem_bytes(other_cert),
        )
        with self.assertRaisesRegex(ValueError, "index signer_kid does not match certificate"):
            self.verify(index=index)

    def test_index_missing_in_stable_v3_verifier_fails(self) -> None:
        import blastwall_attestation_verify as verifier
        import blastwall_marker as marker_tool

        marker = {
            "attest_ref": self.attest_ref,
            "attest_sha256": self.envelope_sha,
        }
        marker_text = marker_tool.emit_marker_v3(
            registry=marker_tool.load_registry(),
            rpm=self.payload["rpm_nevra"],
            profiles=self.payload["profiles"],
            attest_ref=marker["attest_ref"],
            attest_sha256=marker["attest_sha256"],
            signer_kid=self.signer_kid,
            exp=self.payload["not_after"],
            generation=self.payload["generation"],
        )
        report = verifier.verify_attestation_for_marker(
            marker_text=marker_text,
            envelope_text=json.dumps(self.envelope),
            index_text=None,
            registry=marker_tool.load_registry(),
            expected_registry_sha256=marker_tool.registry_sha256(),
            expected_host=self.payload["subject_host"],
            expected_target=self.payload["target"],
            expected_rpm=self.payload["rpm_nevra"],
            current_policy_sha256=self.payload["policy_sha256"],
            required_profiles=self.payload["profiles"],
            signer_certificate=self.signer_cert,
            ca_bundle=_pem_bytes(self.ca_cert),
            signer_allowlist=[self.signer_kid],
            now=_now(),
        )
        self.assertEqual(report.failure_state, "FAIL_INDEX_NOT_VISIBLE")

    def test_revoked_index_fails(self) -> None:
        index = self.build_index(state="revoked", latest_generation=7)
        with self.assertRaises(attestation.AttestationVerificationError) as exc:
            self.verify(index=index)
        self.assertEqual(exc.exception.failure_state, "FAIL_REVOKED_ATTESTATION")


if __name__ == "__main__":
    unittest.main()
