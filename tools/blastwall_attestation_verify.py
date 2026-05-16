#!/usr/bin/env python3
"""Verify Blastwall v3 marker locators against signed attestation artifacts."""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import blastwall_attestation
import blastwall_marker


@dataclass
class VerificationReport:
    status: str
    failure_state: str | None = None
    message: str = ""
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "failure_state": self.failure_state,
            "message": self.message,
            "details": self.details or {},
        }


def _load_json_path(path: Path | None) -> str | None:
    if path is None:
        return None
    return sys.stdin.read() if str(path) == "-" else path.read_text(encoding="utf-8")


def _marker_failure_state(errors: list[str]) -> str:
    if any("duplicate reserved marker field" in error for error in errors):
        return "FAIL_DUPLICATE_RESERVED_MARKER_FIELD"
    if any("unsupported marker version" in error for error in errors):
        return "FAIL_UNSUPPORTED_MARKER_VERSION"
    if any("marker is revoked" in error for error in errors):
        return "FAIL_REVOKED_MARKER"
    if any("marker has expired" in error for error in errors):
        return "FAIL_EXPIRED_MARKER"
    return "FAIL_MARKER_TAMPERED"


def _crypto_failure_state(error: ValueError) -> str:
    message = str(error)
    if "signature verification failed" in message:
        return "FAIL_SIGNATURE_INVALID"
    if "allowlisted" in message or "not trusted" in message or "signer certificate" in message:
        return "FAIL_SIGNER_UNTRUSTED"
    if "payload_sha256" in message or "digest" in message:
        return "FAIL_ATTESTATION_DIGEST"
    if "unsupported envelope_version" in message:
        return "FAIL_UNSUPPORTED_ENVELOPE_VERSION"
    if "duplicate JSON property" in message:
        return "FAIL_JSON_CANONICALIZATION"
    return "FAIL_BINDING_MISMATCH"


def _verify_payload_binding(
    *,
    payload: Mapping[str, Any],
    parsed_marker: blastwall_marker.MarkerResult,
    expected_host: str,
    expected_target: str,
    expected_rpm: str,
    expected_registry_sha256: str,
    current_policy_sha256: str,
    required_profiles: list[str],
    registry: Mapping[str, Any],
) -> None:
    if payload["subject_host"] != expected_host:
        raise blastwall_attestation.AttestationVerificationError(
            "FAIL_BINDING_MISMATCH",
            "payload subject_host does not match selected host",
        )
    if payload["target"] != expected_target or parsed_marker.target != expected_target:
        raise blastwall_attestation.AttestationVerificationError(
            "FAIL_BINDING_MISMATCH",
            "payload or marker target does not match expected target",
        )
    if payload["rpm_nevra"] != expected_rpm or parsed_marker.rpm != expected_rpm:
        raise blastwall_attestation.AttestationVerificationError(
            "FAIL_BINDING_MISMATCH",
            "payload or marker rpm does not match expected rpm",
        )
    if payload["registry_sha256"] != expected_registry_sha256:
        raise blastwall_attestation.AttestationVerificationError(
            "FAIL_REGISTRY_MISMATCH",
            "payload registry_sha256 does not match expected registry hash",
        )
    if payload["policy_sha256"] != current_policy_sha256:
        raise blastwall_attestation.AttestationVerificationError(
            "FAIL_DRIFTED_POLICY",
            "current installed policy hash does not match signed payload",
        )
    if list(payload["profiles"]) != required_profiles:
        raise blastwall_attestation.AttestationVerificationError(
            "FAIL_PROFILE_MISMATCH",
            "payload profiles do not match required profiles",
        )
    expected_scopes = sorted(blastwall_marker.expand_profiles(dict(registry), set(required_profiles)))
    if sorted(payload["scopes"]) != expected_scopes:
        raise blastwall_attestation.AttestationVerificationError(
            "FAIL_PROFILE_MISMATCH",
            "payload scopes do not match profile registry expansion",
        )


def verify_attestation_for_marker(
    *,
    marker_text: str,
    envelope_text: str | None,
    index_text: str | None,
    registry: Mapping[str, Any],
    expected_registry_sha256: str,
    expected_host: str,
    expected_target: str,
    expected_rpm: str,
    current_policy_sha256: str,
    required_profiles: list[str],
    signer_certificate: Path,
    ca_bundle: Path,
    signer_allowlist: list[str],
    now: datetime.datetime | None = None,
) -> VerificationReport:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    parsed_marker = blastwall_marker.parse_marker(
        marker_text,
        registry=dict(registry),
        expected_registry_sha256=expected_registry_sha256,
        expected_target=expected_target,
        accepted_rpms={expected_rpm},
        required_profiles=set(required_profiles),
        allow_dry_run_profiles=True,
    )
    if parsed_marker.version != 3:
        return VerificationReport(
            status="FAIL",
            failure_state="FAIL_UNSUPPORTED_MARKER_VERSION",
            message="stable-v3 requires a v3 attestation marker",
            details={"marker_errors": parsed_marker.errors, "marker_version": parsed_marker.version},
        )
    if parsed_marker.errors or not parsed_marker.hint:
        return VerificationReport(
            status="FAIL",
            failure_state=_marker_failure_state(parsed_marker.errors),
            message="v3 marker locator is invalid",
            details={"marker_errors": parsed_marker.errors},
        )
    if not envelope_text:
        return VerificationReport(
            status="FAIL",
            failure_state="FAIL_ATTESTATION_NOT_VISIBLE",
            message="attestation envelope is not available",
            details={"attest_ref": parsed_marker.attest_ref},
        )
    if not index_text:
        return VerificationReport(
            status="FAIL",
            failure_state="FAIL_INDEX_NOT_VISIBLE",
            message="latest-generation index is not available",
            details={"attest_ref": parsed_marker.attest_ref},
        )

    try:
        envelope = blastwall_attestation.parse_attestation_envelope(envelope_text)
        index = blastwall_attestation.parse_latest_index(index_text)
        verified = blastwall_attestation.verify_latest_index(
            envelope,
            index,
            parsed_marker,
            now=now,
            signer_certificate=signer_certificate,
            ca_bundle=ca_bundle,
            signer_allowlist=signer_allowlist,
        )
        _verify_payload_binding(
            payload=verified["payload"],
            parsed_marker=parsed_marker,
            expected_host=expected_host,
            expected_target=expected_target,
            expected_rpm=expected_rpm,
            expected_registry_sha256=expected_registry_sha256,
            current_policy_sha256=current_policy_sha256,
            required_profiles=required_profiles,
            registry=registry,
        )
    except blastwall_attestation.AttestationVerificationError as exc:
        return VerificationReport(
            status="FAIL",
            failure_state=exc.failure_state,
            message=str(exc),
        )
    except ValueError as exc:
        return VerificationReport(
            status="FAIL",
            failure_state=_crypto_failure_state(exc),
            message=str(exc),
        )

    return VerificationReport(
        status="PASS",
        details={
            "attest_ref": parsed_marker.attest_ref,
            "attest_sha256": verified["attest_sha256"],
            "attestation_generation": verified["attestation_generation"],
            "index_generation": verified["index_generation"],
            "signer_kid": parsed_marker.signer_kid,
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=blastwall_marker.DEFAULT_REGISTRY)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--envelope-json", type=Path)
    parser.add_argument("--index-json", type=Path)
    parser.add_argument("--signer-certificate", type=Path, required=True)
    parser.add_argument("--ca-bundle", type=Path, required=True)
    parser.add_argument("--signer-allowlist-csv", required=True)
    parser.add_argument("--expected-host", required=True)
    parser.add_argument("--expected-target", default="rhel-login")
    parser.add_argument("--expected-rpm", default=blastwall_marker.DEFAULT_RPM)
    parser.add_argument("--expected-registry-sha256")
    parser.add_argument("--current-policy-sha256", required=True)
    parser.add_argument("--required-profiles-csv", default="base")
    args = parser.parse_args()

    registry = blastwall_marker.load_registry(args.registry)
    required_profiles = [item for item in args.required_profiles_csv.split(",") if item]
    report = verify_attestation_for_marker(
        marker_text=args.marker,
        envelope_text=_load_json_path(args.envelope_json),
        index_text=_load_json_path(args.index_json),
        registry=registry,
        expected_registry_sha256=args.expected_registry_sha256 or blastwall_marker.registry_sha256(args.registry),
        expected_host=args.expected_host,
        expected_target=args.expected_target,
        expected_rpm=args.expected_rpm,
        current_policy_sha256=args.current_policy_sha256,
        required_profiles=required_profiles or ["base"],
        signer_certificate=args.signer_certificate,
        ca_bundle=args.ca_bundle,
        signer_allowlist=[item for item in args.signer_allowlist_csv.split(",") if item],
    )
    print(json.dumps(report.to_dict(), sort_keys=True))
    return 0 if report.status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
