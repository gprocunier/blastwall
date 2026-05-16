#!/usr/bin/env python3
"""Tests for Blastwall inventory audit reports."""

from __future__ import annotations

import datetime
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

AUDIT_PATH = TOOLS / "audit_blastwall_inventory.py"
MARKER_PATH = TOOLS / "blastwall_marker.py"
ATTESTATION_PATH = TOOLS / "blastwall_attestation.py"

audit_spec = importlib.util.spec_from_file_location("audit_blastwall_inventory", AUDIT_PATH)
audit = importlib.util.module_from_spec(audit_spec)
assert audit_spec.loader is not None
audit_spec.loader.exec_module(audit)

marker_spec = importlib.util.spec_from_file_location("blastwall_marker", MARKER_PATH)
marker = importlib.util.module_from_spec(marker_spec)
assert marker_spec.loader is not None
marker_spec.loader.exec_module(marker)

attestation_spec = importlib.util.spec_from_file_location("blastwall_attestation", ATTESTATION_PATH)
attestation = importlib.util.module_from_spec(attestation_spec)
assert attestation_spec.loader is not None
attestation_spec.loader.exec_module(attestation)


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
        .not_valid_after(now + datetime.timedelta(hours=2))
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


def _load_json_fixture(name: str) -> dict:
    return json.loads((ROOT / "tests" / "fixtures" / name).read_text(encoding="utf-8"))


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

    def _build_v3_attestation_bundle(
        self,
        *,
        host: str,
        generation: int,
        index_latest_generation: int | None = None,
        index_state: str = "active",
        now: datetime.datetime | None = None,
    ) -> tuple[str, dict[str, str], dict[str, bytes], bytes]:
        now = now or _now()
        marker_profile = ["base"]
        policy_sha256 = "b" * 64
        payload = {
            "attestation_version": 1,
            "subject_host": host,
            "target": "rhel-login",
            "state": "active",
            "rpm_nevra": marker.DEFAULT_RPM,
            "registry_sha256": self.registry_hash,
            "policy_sha256": policy_sha256,
            "profiles": marker_profile,
            "scopes": sorted(marker.expand_profiles(self.registry, set(marker_profile))),
            "probe_report_sha256": "c" * 64,
            "aap_workflow_job_id": 1234,
            "source_revision": "1234567890abcdef1234567890abcdef12345678",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "not_before": (now - datetime.timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
            "not_after": (now + datetime.timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
            "generation": generation,
            "signer_kid": self.signer_kid,
            "nonce": "phase09",
        }
        attest_ref = f"service/blastwall-attestation/blastwall-attestations/{host}/base/{generation}.json"
        envelope = attestation.build_attestation_envelope(
            payload,
            private_key=_pem_private_key(self.signer_key),
            signer_certificate=_pem_bytes(self.signer_cert),
        )
        envelope_text = json.dumps(envelope, separators=(",", ":"), sort_keys=True)
        envelope_digest = attestation.attestation_envelope_sha256(envelope)
        index_latest = index_latest_generation if index_latest_generation is not None else generation
        index_payload = {
            "subject_host": host,
            "target": "rhel-login",
            "profile_set": marker_profile,
            "latest_generation": index_latest,
            "latest_attest_ref": attest_ref,
            "latest_attest_sha256": envelope_digest,
            "state": index_state,
            "issued_at": payload["issued_at"],
            "not_before": payload["not_before"],
            "not_after": payload["not_after"],
        }
        index = attestation.build_latest_index(
            index_payload,
            private_key=_pem_private_key(self.signer_key),
            signer_certificate=_pem_bytes(self.signer_cert),
        )
        index_text = json.dumps(index, separators=(",", ":"), sort_keys=True)
        marker_text = marker.emit_marker_v3(
            registry=self.registry,
            rpm=marker.DEFAULT_RPM,
            profiles=marker_profile,
            state="active",
            attest_ref=attest_ref,
            attest_sha256=envelope_digest,
            signer_kid=self.signer_kid,
            exp=now + datetime.timedelta(hours=1),
            generation=generation,
        )
        artifacts = {
            attest_ref: envelope_text,
            f"service/blastwall-attestation/blastwall-attestation-index/{host}/base.json": index_text,
        }
        artifacts_bytes = {
            ref: text.encode("utf-8") for ref, text in artifacts.items()
        }
        return marker_text, artifacts, artifacts_bytes, _pem_bytes(self.signer_cert)

    def _read_vault_artifact(self, artifacts: dict[str, str]) -> Callable:
        def _read(*, server: str, config: audit.blastwall_attestation_vault.VaultConfig, vault_ref: str) -> audit.blastwall_attestation_vault.VaultReadResult:
            if vault_ref in artifacts:
                payload = artifacts[vault_ref].encode("utf-8")
                return audit.blastwall_attestation_vault.VaultReadResult(
                    server=server,
                    vault_ref=vault_ref,
                    payload=payload,
                    digest=hashlib.sha256(payload).hexdigest(),
                    attempts=1,
                    retry_attempted=False,
                )
            context = audit.blastwall_attestation_vault.VaultErrorContext(
                server=server,
                vault_ref=vault_ref,
                vault_error_type=audit.blastwall_attestation_vault.VaultErrorType.NOT_FOUND,
                message="artifact not found",
                command=["eigenstate-ipa", "vault", "read"],
                attempts=1,
                retry_attempted=False,
            )
            raise audit.blastwall_attestation_vault.VaultCommandError(context)

        return _read

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

    def test_current_marker_with_valid_attestation_reports_pass(self) -> None:
        fixture = _load_json_fixture("phase09_current_marker_valid_inventory.json")
        marker_text, artifacts, _, signer_cert_pem = self._build_v3_attestation_bundle(
            host="phase09-valid-attestation.example.com",
            generation=7,
        )
        fixture = json.loads(json.dumps(fixture).replace("MARKER", marker_text))

        with tempfile.TemporaryDirectory() as temp_dir:
            signer_cert_path = Path(temp_dir) / "signer.pem"
            ca_bundle_path = Path(temp_dir) / "ca.pem"
            signer_cert_path.write_bytes(signer_cert_pem)
            ca_bundle_path.write_bytes(_pem_bytes(self.ca_cert))
            report = audit.audit_inventory(
                fixture,
                registry=self.registry,
                expected_registry_sha256=self.registry_hash,
                allow_dry_run_profiles=False,
                accepted_rpms={marker.DEFAULT_RPM},
                required_profiles={"base"},
                verify_attestations=True,
                vault_server="vault.example.com",
                signer_certificate=signer_cert_path,
                ca_bundle=ca_bundle_path,
                signer_allowlist=[self.signer_kid],
                read_vault_artifact=self._read_vault_artifact(artifacts),
            )
        host = "phase09-valid-attestation.example.com"
        self.assertEqual(report["current_marker_without_valid_attestation_hosts"], [])
        self.assertIn(host, report["current_marker_attestation_reports"])
        self.assertIsNone(report["current_marker_attestation_reports"][host]["failure_state"])
        self.assertEqual(
            report["current_marker_attestation_reports"][host]["index_generation_seen"],
            7,
        )

    def test_current_marker_with_missing_attestation_artifact_is_not_visible(self) -> None:
        fixture = _load_json_fixture("phase09_current_marker_missing_artifact_inventory.json")
        marker_text, artifacts, _, signer_cert_pem = self._build_v3_attestation_bundle(
            host="phase09-missing-artifact.example.com",
            generation=7,
        )
        fixture = json.loads(json.dumps(fixture).replace("MARKER", marker_text))
        read_artifact = self._read_vault_artifact({"not-a-key": "value"})

        with tempfile.TemporaryDirectory() as temp_dir:
            signer_cert_path = Path(temp_dir) / "signer.pem"
            ca_bundle_path = Path(temp_dir) / "ca.pem"
            signer_cert_path.write_bytes(signer_cert_pem)
            ca_bundle_path.write_bytes(_pem_bytes(self.ca_cert))
            report = audit.audit_inventory(
                fixture,
                registry=self.registry,
                expected_registry_sha256=self.registry_hash,
                allow_dry_run_profiles=False,
                accepted_rpms={marker.DEFAULT_RPM},
                required_profiles={"base"},
                verify_attestations=True,
                vault_server="vault.example.com",
                signer_certificate=signer_cert_path,
                ca_bundle=ca_bundle_path,
                signer_allowlist=[self.signer_kid],
                read_vault_artifact=read_artifact,
            )
        host = "phase09-missing-artifact.example.com"
        self.assertEqual(
            report["current_marker_attestation_not_visible_hosts"],
            [host],
        )
        self.assertEqual(
            report["current_marker_attestation_reports"][host]["failure_state"],
            "FAIL_ATTESTATION_NOT_VISIBLE",
        )

    def test_current_marker_with_parser_invalid_marker_stays_in_parse_error_list(self) -> None:
        fixture = _load_json_fixture("phase09_current_marker_parser_invalid_inventory.json")
        report = audit.audit_inventory(
            fixture,
            registry=self.registry,
            expected_registry_sha256=self.registry_hash,
            allow_dry_run_profiles=False,
            accepted_rpms={marker.DEFAULT_RPM},
            required_profiles={"base"},
            verify_attestations=True,
            vault_server="vault.example.com",
            signer_allowlist=[self.signer_kid],
            read_vault_artifact=self._read_vault_artifact({}),
        )
        self.assertEqual(
            report["current_marker_parse_error_hosts"],
            ["phase09-parser-invalid.example.com"],
        )
        self.assertEqual(
            report["current_marker_without_valid_attestation_hosts"],
            [],
        )

    def test_current_marker_with_stale_generation_is_reported(self) -> None:
        fixture = _load_json_fixture("phase09_current_marker_stale_inventory.json")
        marker_text, artifacts, _, signer_cert_pem = self._build_v3_attestation_bundle(
            host="phase09-stale-generation.example.com",
            generation=7,
            index_latest_generation=9,
        )
        fixture = json.loads(json.dumps(fixture).replace("MARKER", marker_text))
        with tempfile.TemporaryDirectory() as temp_dir:
            signer_cert_path = Path(temp_dir) / "signer.pem"
            ca_bundle_path = Path(temp_dir) / "ca.pem"
            signer_cert_path.write_bytes(signer_cert_pem)
            ca_bundle_path.write_bytes(_pem_bytes(self.ca_cert))
            report = audit.audit_inventory(
                fixture,
                registry=self.registry,
                expected_registry_sha256=self.registry_hash,
                allow_dry_run_profiles=False,
                accepted_rpms={marker.DEFAULT_RPM},
                required_profiles={"base"},
                verify_attestations=True,
                vault_server="vault.example.com",
                signer_certificate=signer_cert_path,
                ca_bundle=ca_bundle_path,
                signer_allowlist=[self.signer_kid],
                read_vault_artifact=self._read_vault_artifact(artifacts),
            )
        host = "phase09-stale-generation.example.com"
        self.assertEqual(
            report["current_marker_without_valid_attestation_hosts"],
            [host],
        )
        self.assertIn(
            "FAIL_REPLAYED_ATTESTATION",
            report["current_marker_attestation_reports"][host]["failure_state"],
        )

    def test_current_marker_with_dry_run_profile_without_allow_flag_is_parse_invalid(self) -> None:
        fixture = _load_json_fixture("phase09_current_marker_dry_run_without_allow_inventory.json")
        with tempfile.TemporaryDirectory() as temp_dir:
            signer_cert_path = Path(temp_dir) / "signer.pem"
            ca_bundle_path = Path(temp_dir) / "ca.pem"
            signer_cert_path.write_bytes(_pem_bytes(self.signer_cert))
            ca_bundle_path.write_bytes(_pem_bytes(self.ca_cert))
            report = audit.audit_inventory(
                fixture,
                registry=self.registry,
                expected_registry_sha256=self.registry_hash,
                allow_dry_run_profiles=False,
                accepted_rpms={marker.DEFAULT_RPM},
                required_profiles={"base"},
                verify_attestations=True,
                vault_server="vault.example.com",
                signer_certificate=signer_cert_path,
                ca_bundle=ca_bundle_path,
                signer_allowlist=[self.signer_kid],
                read_vault_artifact=self._read_vault_artifact({}),
            )
        self.assertEqual(
            report["current_marker_parse_error_hosts"],
            ["phase09-dry-run-without-allow.example.com"],
        )


if __name__ == "__main__":
    unittest.main()
