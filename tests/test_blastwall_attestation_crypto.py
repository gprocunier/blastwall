#!/usr/bin/env python3
"""Tests for signed attestation payload verification."""

from __future__ import annotations

import datetime
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

import importlib.util
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
ATTESTATION_PATH = ROOT / "tools" / "blastwall_attestation.py"

spec = importlib.util.spec_from_file_location("blastwall_attestation", ATTESTATION_PATH)
attestation = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(attestation)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def _ca_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _certificate(
    *,
    subject_common_name: str,
    issuer_common_name: str,
    issuer_key: rsa.RSAPrivateKey,
    subject_key: rsa.RSAPrivateKey,
    serial_number: int,
    is_ca: bool = False,
    validity_delta_minutes: int = 60,
    not_before_delta: int = -1,
) -> x509.Certificate:
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_common_name)]))
        .public_key(subject_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(now + datetime.timedelta(minutes=not_before_delta))
        .not_valid_after(now + datetime.timedelta(minutes=validity_delta_minutes))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
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


class BlastwallAttestationCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ca_key = _ca_keypair()
        self.ca_cert = _certificate(
            subject_common_name="CN=BlastwallTestCA",
            issuer_common_name="CN=BlastwallTestCA",
            issuer_key=self.ca_key,
            subject_key=self.ca_key,
            serial_number=11,
            is_ca=True,
            validity_delta_minutes=240,
        )
        self.signer_key = _ca_keypair()
        self.signer_cert = _certificate(
            subject_common_name="CN=blastwall-attestation-signer",
            issuer_common_name="CN=BlastwallTestCA",
            issuer_key=self.ca_key,
            subject_key=self.signer_key,
            serial_number=100,
            validity_delta_minutes=120,
        )
        self.signer_kid = attestation.extract_signer_kid(self.signer_cert)

        untrusted_ca_key = _ca_keypair()
        self.untrusted_ca_cert = _certificate(
            subject_common_name="CN=UntrustedCA",
            issuer_common_name="CN=UntrustedCA",
            issuer_key=untrusted_ca_key,
            subject_key=untrusted_ca_key,
            serial_number=13,
            is_ca=True,
            validity_delta_minutes=240,
        )
        self.untrusted_signer_key = _ca_keypair()
        self.untrusted_signer_cert = _certificate(
            subject_common_name="CN=untrusted-attestation-signer",
            issuer_common_name="CN=UntrustedCA",
            issuer_key=untrusted_ca_key,
            subject_key=self.untrusted_signer_key,
            serial_number=101,
            validity_delta_minutes=120,
        )

        self.ca_bundle = (
            _pem_bytes(self.ca_cert)
            + b"\n"
            + _pem_bytes(self.untrusted_ca_cert)
        )

        now = _now()
        self.base_payload: dict[str, Any] = {
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
            "generation": 1,
            "signer_kid": self.signer_kid,
            "nonce": "nonce",
        }

    def _envelope(self, *, signer_key, signer_cert) -> dict[str, Any]:
        return attestation.build_attestation_envelope(
            self.base_payload,
            private_key=_pem_private_key(signer_key),
            signer_certificate= _pem_bytes(signer_cert),
            signature_algorithm=attestation.SUPPORTED_SIGNATURE_ALGORITHM,
        )

    def test_valid_signature_verifies(self) -> None:
        envelope = self._envelope(signer_key=self.signer_key, signer_cert=self.signer_cert)
        result = attestation.verify_attestation_envelope(
            envelope,
            signer_certificate=self.signer_cert,
            ca_bundle=self.ca_bundle,
            signer_allowlist=[self.signer_kid],
        )
        self.assertEqual(result["payload"]["subject_host"], "mirror-registry.workshop.lan")
        self.assertEqual(result["signer_kid"], self.signer_kid)

    def test_wrong_payload_fails_signature(self) -> None:
        envelope = self._envelope(signer_key=self.signer_key, signer_cert=self.signer_cert)
        envelope["payload"]["subject_host"] = "other.example.com"
        with self.assertRaisesRegex(ValueError, "payload_sha256 does not match canonical payload"):
            attestation.verify_attestation_envelope(
                envelope,
                signer_certificate=self.signer_cert,
                ca_bundle=self.ca_bundle,
                signer_allowlist=[self.signer_kid],
            )

    def test_wrong_signer_fails_allowlist(self) -> None:
        payload = dict(self.base_payload)
        payload["signer_kid"] = attestation.extract_signer_kid(self.untrusted_signer_cert)
        envelope = attestation.build_attestation_envelope(
            payload,
            private_key=_pem_private_key(self.untrusted_signer_key),
            signer_certificate=_pem_bytes(self.untrusted_signer_cert),
            signature_algorithm=attestation.SUPPORTED_SIGNATURE_ALGORITHM,
        )
        with self.assertRaisesRegex(ValueError, "signer_kid is not allowlisted"):
            attestation.verify_attestation_envelope(
                envelope,
                signer_certificate=self.untrusted_signer_cert,
                ca_bundle=self.ca_bundle,
                signer_allowlist=[self.signer_kid],
            )

    def test_untrusted_ca_fails(self) -> None:
        with self.assertRaisesRegex(ValueError, "not trusted by configured CA bundle"):
            attestation.verify_attestation_envelope(
                self._envelope(
                    signer_key=self.untrusted_signer_key,
                    signer_cert=self.untrusted_signer_cert,
                ),
                signer_certificate=self.untrusted_signer_cert,
                ca_bundle=_pem_bytes(self.ca_cert),
                signer_allowlist=[attestation.extract_signer_kid(self.untrusted_signer_cert)],
            )

    def test_expired_certificate_is_rejected(self) -> None:
        expired_ca_key = _ca_keypair()
        expired_ca_cert = _certificate(
            subject_common_name="CN=ExpiredCA",
            issuer_common_name="CN=ExpiredCA",
            issuer_key=expired_ca_key,
            subject_key=expired_ca_key,
            serial_number=1000,
            is_ca=True,
            validity_delta_minutes=-1,
            not_before_delta=-120,
        )
        expired_signer_key = _ca_keypair()
        expired_signer_cert = _certificate(
            subject_common_name="CN=expired-signer",
            issuer_common_name="CN=ExpiredCA",
            issuer_key=expired_ca_key,
            subject_key=expired_signer_key,
            serial_number=1001,
            validity_delta_minutes=-1,
            not_before_delta=-120,
        )
        # keep payload signer_kid aligned with the expired cert
        payload = dict(self.base_payload)
        payload["signer_kid"] = attestation.extract_signer_kid(expired_signer_cert)
        envelope = attestation.build_attestation_envelope(
            payload,
            private_key=_pem_private_key(expired_signer_key),
            signer_certificate=_pem_bytes(expired_signer_cert),
            signature_algorithm=attestation.SUPPORTED_SIGNATURE_ALGORITHM,
        )
        with self.assertRaisesRegex(ValueError, "signer certificate has expired"):
            attestation.verify_attestation_envelope(
                envelope,
                signer_certificate=expired_signer_cert,
                ca_bundle=_pem_bytes(expired_ca_cert),
                signer_allowlist=[attestation.extract_signer_kid(expired_signer_cert)],
            )

    def test_ski_format_is_required_and_lowercase(self) -> None:
        self.assertEqual(attestation.normalize_ski(self.signer_kid.upper()), self.signer_kid.lower())
        with self.assertRaisesRegex(ValueError, "signer_kid must not include colons"):
            attestation.normalize_ski(f"{self.signer_kid[:2]}:{self.signer_kid[2:]}")


if __name__ == "__main__":
    unittest.main()
