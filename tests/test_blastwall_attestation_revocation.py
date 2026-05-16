#!/usr/bin/env python3
"""Tests for Blastwall v3 attestation revocation helpers."""

from __future__ import annotations

import datetime
import json
import unittest
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import blastwall_marker as marker  # noqa: E402
import blastwall_attestation_revocation as revocation  # noqa: E402


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def _keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class BlastwallAttestationRevocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = marker.load_registry(Path("policy/profiles.yml"))
        self.registry_hash = marker.registry_sha256(Path("policy/profiles.yml"))
        self.signer_kid = "0" * 40
        self.attest_ref = "service/blastwall-attestation/blastwall-attestations/mirror/base/7.json"
        self.attest_sha256 = "a" * 64

    def make_v3_marker(self, *, state: str = "active", profiles: list[str] | None = None) -> str:
        now = _now()
        return marker.emit_marker_v3(
            registry=self.registry,
            rpm=marker.DEFAULT_RPM,
            profiles=profiles or ["base"],
            attest_ref=self.attest_ref,
            attest_sha256=self.attest_sha256,
            signer_kid=self.signer_kid,
            exp=(now + datetime.timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
            generation=7,
            state=state,
        )

    def test_marker_to_revoked_marker_preserves_reference_fields(self) -> None:
        active = self.make_v3_marker()
        revoked = revocation.marker_to_revoked_marker(
            marker_text=active,
            registry=self.registry,
            expected_registry_sha256=self.registry_hash,
        )
        parsed = marker.parse_marker(
            revoked,
            registry=self.registry,
            expected_registry_sha256=self.registry_hash,
            accepted_rpms={marker.DEFAULT_RPM},
        )
        self.assertEqual(parsed.version, 3)
        self.assertEqual(parsed.state, "revoked")
        self.assertEqual(parsed.attest_ref, self.attest_ref)
        self.assertEqual(parsed.attest_sha256, self.attest_sha256)

    def test_marker_to_revoked_marker_rejects_invalid_input(self) -> None:
        revoked_input = self.make_v3_marker(state="revoked")
        with self.assertRaisesRegex(ValueError, "marker parse rejected"):
            revocation.marker_to_revoked_marker(
                marker_text=revoked_input,
                registry=self.registry,
                expected_registry_sha256=self.registry_hash,
            )

    def test_tombstone_payload_builds_status_and_timestamp(self) -> None:
        payload = revocation.build_tombstone_payload(
            reason="revoked for host compromise",
            revoked_at=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(payload["status"], revocation.DEFAULT_TOMBSTONE_STATUS)
        self.assertEqual(payload["reason"], "revoked for host compromise")
        self.assertEqual(payload["revoked_at"], "2026-01-01T00:00:00Z")

    def test_tombstone_json_shape(self) -> None:
        raw = revocation.build_tombstone_json(reason="operator incident")
        payload = json.loads(raw)
        self.assertEqual(payload["status"], revocation.DEFAULT_TOMBSTONE_STATUS)
        self.assertEqual(payload["reason"], "operator incident")


if __name__ == "__main__":
    unittest.main()
