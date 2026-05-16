#!/usr/bin/env python3
"""Tests for attestation JSON canonicalization and schema validation."""

from __future__ import annotations

import json
import unittest
from copy import deepcopy

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTESTATION_PATH = ROOT / "tools" / "blastwall_attestation.py"

spec = importlib.util.spec_from_file_location("blastwall_attestation", ATTESTATION_PATH)
attestation = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(attestation)


class BlastwallAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_payload = {
            "attestation_version": 1,
            "subject_host": "mirror-registry.workshop.lan",
            "target": "rhel-login",
            "state": "active",
            "rpm_nevra": "blastwall-selinux-0.6.1-0.rc1",
            "registry_sha256": "a" * 64,
            "policy_sha256": "b" * 64,
            "profiles": ["base", "strange-socket-v1"],
            "scopes": ["alg_socket", "bpf", "self"],
            "probe_report_sha256": "c" * 64,
            "aap_workflow_job_id": 1234,
            "source_revision": "1234567890abcdef1234567890abcdef12345678",
            "issued_at": "2026-05-16T14:00:00Z",
            "not_before": "2026-05-16T14:00:00Z",
            "not_after": "2026-05-16T15:00:00Z",
            "generation": 7,
            "signer_kid": "4c2a9f12ab34cd56ef7890ab1234567890abcdef",
            "nonce": "n1",
        }

    def _payload_text(self, payload: dict[str, object]) -> str:
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)

    def test_canonical_bytes_are_stable(self) -> None:
        payload_a = self.sample_payload
        payload_b = dict(self.sample_payload)
        payload_b["aap_workflow_job_id"] = 4321
        payload_b["aap_workflow_job_id"] = 1234
        payload_b["state"] = "active"
        payload_c = {
            "source_revision": "1234567890abcdef1234567890abcdef12345678",
            "attestation_version": 1,
            "subject_host": "mirror-registry.workshop.lan",
            "target": "rhel-login",
            "state": "active",
            "rpm_nevra": "blastwall-selinux-0.6.1-0.rc1",
            "registry_sha256": "a" * 64,
            "policy_sha256": "b" * 64,
            "profiles": ["base", "strange-socket-v1"],
            "scopes": ["alg_socket", "bpf", "self"],
            "probe_report_sha256": "c" * 64,
            "aap_workflow_job_id": 1234,
            "not_before": "2026-05-16T14:00:00Z",
            "not_after": "2026-05-16T15:00:00Z",
            "issued_at": "2026-05-16T14:00:00Z",
            "generation": 7,
            "signer_kid": "4c2a9f12ab34cd56ef7890ab1234567890abcdef",
            "nonce": "n1",
        }
        first = attestation.canonical_json_bytes(payload_a)
        second = attestation.canonical_json_bytes(payload_c)
        self.assertEqual(first, second)

    def test_payload_digest_invariant_under_formatting_variations(self) -> None:
        payload = json.loads(self._payload_text(deepcopy(self.sample_payload)))
        text_a = self._payload_text(payload)
        text_b = json.dumps(payload, indent=2, sort_keys=False)
        first = attestation.parse_json_no_duplicates(text_a)
        second = attestation.parse_json_no_duplicates(text_b)
        first_bytes = attestation.canonical_json_bytes(first)
        second_bytes = attestation.canonical_json_bytes(second)
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(
            attestation.attestation_payload_sha256(first),
            attestation.attestation_payload_sha256(second),
        )

    def test_duplicate_json_key_rejected(self) -> None:
        duplicate_key_payload = (
            '{"attestation_version":1,"subject_host":"a","subject_host":"b",'
            '"target":"t","state":"active","rpm_nevra":"x",'
            '"registry_sha256":"a0000000000000000000000000000000000000000000000000000000000000000",'
            '"policy_sha256":"b0000000000000000000000000000000000000000000000000000000000000000",'
            '"profiles":["base"],"scopes":["x"],"probe_report_sha256":"c000000000000000000000000000000000000000000000000000000000000000",'
            '"aap_workflow_job_id":1,"source_revision":"1","issued_at":"2026-05-16T14:00:00Z",'
            '"not_before":"2026-05-16T14:00:00Z","not_after":"2026-05-16T15:00:00Z",'
            '"generation":1,"signer_kid":"4c2a9f12ab34cd56ef7890ab1234567890abcdef","nonce":"x"}'
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON property"):
            attestation.parse_attestation_payload(duplicate_key_payload)

    def test_unknown_envelope_version_rejected(self) -> None:
        envelope = {
            "envelope_version": 99,
            "payload": self.sample_payload,
            "payload_sha256": attestation.attestation_payload_sha256(self.sample_payload),
            "signature_algorithm": "sha256-rsa-pkcs1v15",
            "signature": "AA==",
            "signer_kid": "4c2a9f12ab34cd56ef7890ab1234567890abcdef",
            "signer_certificate_subject": "CN=blastwall",
            "signer_certificate_serial": "1",
            "created_at": "2026-05-16T14:00:00Z",
        }
        with self.assertRaisesRegex(ValueError, "unsupported envelope_version"):
            attestation.parse_attestation_envelope(json.dumps(envelope))

    def test_missing_required_payload_field_rejected(self) -> None:
        payload = deepcopy(self.sample_payload)
        del payload["subject_host"]
        with self.assertRaisesRegex(ValueError, "schema validation failed"):
            attestation.validate_attestation_payload(payload)

    def test_generation_requires_integer(self) -> None:
        payload = deepcopy(self.sample_payload)
        payload["generation"] = "7"
        with self.assertRaisesRegex(ValueError, "schema validation failed"):
            attestation.validate_attestation_payload(payload)

    def test_payload_validity_window_parsing(self) -> None:
        payload = deepcopy(self.sample_payload)
        payload["not_before"] = "2026-05-16 14:00:00"
        with self.assertRaisesRegex(ValueError, "schema validation failed"):
            attestation.parse_attestation_payload(json.dumps(payload))

    def test_envelope_digest_is_stable_under_formatting(self) -> None:
        envelope = {
            "envelope_version": 1,
            "payload": self.sample_payload,
            "payload_sha256": attestation.attestation_payload_sha256(self.sample_payload),
            "signature_algorithm": "sha256-rsa-pkcs1v15",
            "signature": "AA==",
            "signer_kid": "4c2a9f12ab34cd56ef7890ab1234567890abcdef",
            "signer_certificate_subject": "CN=blastwall",
            "signer_certificate_serial": "1",
            "created_at": "2026-05-16T14:00:00Z",
        }
        envelope_text = json.dumps(envelope, indent=2, sort_keys=False)
        parsed = attestation.parse_attestation_envelope(envelope_text)
        self.assertEqual(
            attestation.attestation_envelope_sha256(parsed),
            attestation.attestation_envelope_sha256(envelope),
        )


if __name__ == "__main__":
    unittest.main()
