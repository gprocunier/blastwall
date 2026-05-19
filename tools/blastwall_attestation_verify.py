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


@dataclass(frozen=True)
class BreakglassContext:
    enabled: bool
    approved_by: str
    ticket: str
    reason: str
    scope_host: str
    scope_profiles: tuple[str, ...]
    valid_until: datetime.datetime | None


INFRASTRUCTURE_FAILURE_STATES = {
    "FAIL_ATTESTATION_NOT_VISIBLE",
    "FAIL_INDEX_NOT_VISIBLE",
}


def _parse_breakglass_profiles(raw_profiles: str | None) -> tuple[str, ...]:
    parsed = [profile.strip() for profile in (raw_profiles or "").split(",") if profile.strip()]
    return tuple(sorted(dict.fromkeys(parsed)))


def _parse_breakglass_unix_ts(value: str | None) -> datetime.datetime | None:
    if not value:
        return None
    return datetime.datetime.fromtimestamp(float(value), tz=datetime.timezone.utc)


def _make_breakglass_context(args: argparse.Namespace) -> BreakglassContext | None:
    if not args.breakglass:
        return None
    valid_until = _parse_breakglass_unix_ts(args.breakglass_until)
    return BreakglassContext(
        enabled=True,
        approved_by=args.breakglass_approved_by,
        ticket=args.breakglass_ticket,
        reason=args.breakglass_reason,
        scope_host=args.breakglass_host,
        scope_profiles=_parse_breakglass_profiles(args.breakglass_profiles_csv),
        valid_until=valid_until,
    )


def _assert_breakglass_scope(
    *,
    ctx: BreakglassContext | None,
    expected_host: str,
    expected_profiles: list[str],
    now: datetime.datetime,
) -> str | None:
    if ctx is None or not ctx.enabled:
        return None
    if not ctx.approved_by or not ctx.ticket or not ctx.reason:
        return "FAIL_BREAKGLASS_SCOPE"
    if not ctx.scope_host:
        return "FAIL_BREAKGLASS_SCOPE"
    if ctx.scope_host != expected_host:
        return "FAIL_BREAKGLASS_SCOPE"
    if not ctx.scope_profiles:
        return "FAIL_BREAKGLASS_SCOPE"
    if tuple(sorted(expected_profiles)) != ctx.scope_profiles:
        return "FAIL_BREAKGLASS_SCOPE"
    if not ctx.valid_until or ctx.valid_until <= now:
        return "FAIL_BREAKGLASS_EXPIRED"
    return None


def _is_infrastructure_failure(failure_state: str) -> bool:
    return failure_state in INFRASTRUCTURE_FAILURE_STATES


def _can_use_breakglass(
    *,
    failure_state: str,
    ctx: BreakglassContext | None,
    expected_host: str,
    expected_profiles: list[str],
    now: datetime.datetime,
) -> bool:
    if _is_infrastructure_failure(failure_state) and ctx is not None and ctx.enabled:
        return _assert_breakglass_scope(
            ctx=ctx,
            expected_host=expected_host,
            expected_profiles=expected_profiles,
            now=now,
        ) is None
    return False


def _maybe_bypass_with_breakglass(
    *,
    failure_state: str,
    message: str,
    details: dict[str, Any],
    now: datetime.datetime,
    breakglass: BreakglassContext | None,
    expected_host: str,
    expected_profiles: list[str],
) -> VerificationReport:
    if breakglass is None:
        return VerificationReport(status="FAIL", failure_state=failure_state, message=message, details=details)
    scope_error = _assert_breakglass_scope(
        ctx=breakglass,
        expected_host=expected_host,
        expected_profiles=expected_profiles,
        now=now,
    )
    if not _can_use_breakglass(
        failure_state=failure_state,
        ctx=breakglass,
        expected_host=expected_host,
        expected_profiles=expected_profiles,
        now=now,
    ):
        if _is_infrastructure_failure(failure_state) and scope_error is not None:
            details = dict(details)
            details["breakglass_scope_error"] = scope_error
            return VerificationReport(
                status="FAIL",
                failure_state=scope_error,
                message=f"breakglass scope invalid: {scope_error}",
                details=details,
            )
        return VerificationReport(status="FAIL", failure_state=failure_state, message=message, details=details)

    if _is_infrastructure_failure(failure_state):
        return VerificationReport(
            status="PASS",
            message=f"pass via scoped breakglass: {failure_state}",
            details={
                "attest_ref": details.get("attest_ref"),
                "override_failure_state": failure_state,
                "breakglass": {
                    "approved_by": breakglass.approved_by,
                    "ticket": breakglass.ticket,
                    "reason": breakglass.reason,
                    "scope_host": breakglass.scope_host,
                    "scope_profiles": list(breakglass.scope_profiles),
                    "scope_valid_until": breakglass.valid_until.isoformat() if breakglass.valid_until else None,
                },
            },
        )

    return VerificationReport(status="FAIL", failure_state=failure_state, message=message, details=details)


def _is_tombstoned_artifact(envelope_text: str | None) -> bool:
    if not envelope_text:
        return False
    try:
        payload = json.loads(envelope_text)
    except json.JSONDecodeError:
        return False
    return bool(payload.get("status") in {"blastwall-attestation-tombstone", "blastwall-attestation-tombstoned", "tombstoned"})


def _load_json_path(path: Path | None) -> str | None:
    if path is None:
        return None
    if str(path) == "-":
        return sys.stdin.read()
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def _marker_failure_state(errors: list[str]) -> str:
    if any("duplicate reserved marker field" in error for error in errors):
        return "FAIL_DUPLICATE_RESERVED_MARKER_FIELD"
    if any("unsupported marker version" in error for error in errors):
        return "FAIL_UNSUPPORTED_MARKER_VERSION"
    if any("marker is revoked" in error for error in errors):
        return "FAIL_REVOKED_ATTESTATION"
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
        return "FAIL_ATTESTATION_INTEGRITY"
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


def _is_ocp_spo_target(target: str) -> bool:
    return target in {"ocp-spo-standard", "ocp-spo-nested"}


def _validate_spo_evidence(
    *,
    payload: Mapping[str, Any],
    expected_target: str,
) -> None:
    evidence = payload.get("spo_evidence")
    if not isinstance(evidence, Mapping):
        raise blastwall_attestation.AttestationVerificationError(
            "FAIL_SPO_EVIDENCE_MISSING",
            "OpenShift/SPO attestation payload is missing spo_evidence",
        )
    validation_results = evidence.get("validation_results")
    if not isinstance(validation_results, Mapping) or not validation_results:
        raise blastwall_attestation.AttestationVerificationError(
            "FAIL_SPO_EVIDENCE_INVALID",
            "spo_evidence.validation_results must be a non-empty object",
        )
    required_fields = [
        "bundle_sha256",
        "validation_output_digest",
        "spo_version",
        "ocp_version",
        "status_usage",
        "scc_type",
        "admitted_pod_context",
    ]
    missing = [item for item in required_fields if not evidence.get(item)]
    if missing:
        raise blastwall_attestation.AttestationVerificationError(
            "FAIL_SPO_EVIDENCE_INVALID",
            f"spo_evidence is missing required fields for OpenShift/SPO payload: {', '.join(missing)}",
        )
    expected_validation_token = "standard" if expected_target == "ocp-spo-standard" else "nested"
    if not any(key.startswith(expected_validation_token) for key in validation_results):
        raise blastwall_attestation.AttestationVerificationError(
            "FAIL_SPO_EVIDENCE_INVALID",
            f"spo_evidence.validation_results missing expected {expected_validation_token} entry",
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
    breakglass: BreakglassContext | None = None,
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
        return _maybe_bypass_with_breakglass(
            failure_state="FAIL_UNSUPPORTED_MARKER_VERSION",
            message="stable-v3 requires a v3 attestation marker",
            details={"marker_errors": parsed_marker.errors, "marker_version": parsed_marker.version},
            now=now,
            breakglass=breakglass,
            expected_host=expected_host,
            expected_profiles=required_profiles,
        )
    if parsed_marker.errors or not parsed_marker.hint:
        return _maybe_bypass_with_breakglass(
            failure_state=_marker_failure_state(parsed_marker.errors),
            message="v3 marker locator is invalid",
            details={"marker_errors": parsed_marker.errors},
            now=now,
            breakglass=breakglass,
            expected_host=expected_host,
            expected_profiles=required_profiles,
        )
    if not envelope_text:
        return _maybe_bypass_with_breakglass(
            failure_state="FAIL_ATTESTATION_NOT_VISIBLE",
            message="attestation envelope is not available",
            details={"attest_ref": parsed_marker.attest_ref},
            now=now,
            breakglass=breakglass,
            expected_host=expected_host,
            expected_profiles=required_profiles,
        )
    if _is_tombstoned_artifact(envelope_text):
        return _maybe_bypass_with_breakglass(
            failure_state="FAIL_MISSING_ATTESTATION",
            message="attestation artifact is tombstoned",
            details={"attest_ref": parsed_marker.attest_ref},
            now=now,
            breakglass=breakglass,
            expected_host=expected_host,
            expected_profiles=required_profiles,
        )
    if not index_text:
        return _maybe_bypass_with_breakglass(
            failure_state="FAIL_INDEX_NOT_VISIBLE",
            message="latest-generation index is not available",
            details={"attest_ref": parsed_marker.attest_ref},
            now=now,
            breakglass=breakglass,
            expected_host=expected_host,
            expected_profiles=required_profiles,
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
        if _is_ocp_spo_target(expected_target):
            _validate_spo_evidence(
                payload=verified["payload"],
                expected_target=expected_target,
            )
    except blastwall_attestation.AttestationVerificationError as exc:
        return _maybe_bypass_with_breakglass(
            failure_state=exc.failure_state,
            message=str(exc),
            details={},
            now=now,
            breakglass=breakglass,
            expected_host=expected_host,
            expected_profiles=required_profiles,
        )
    except ValueError as exc:
        return _maybe_bypass_with_breakglass(
            failure_state=_crypto_failure_state(exc),
            message=str(exc),
            details={},
            now=now,
            breakglass=breakglass,
            expected_host=expected_host,
            expected_profiles=required_profiles,
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
    parser.add_argument("--breakglass", action="store_true")
    parser.add_argument("--breakglass-host")
    parser.add_argument("--breakglass-profiles-csv")
    parser.add_argument("--breakglass-approved-by")
    parser.add_argument("--breakglass-ticket")
    parser.add_argument("--breakglass-reason")
    parser.add_argument("--breakglass-until")
    args = parser.parse_args()

    registry = blastwall_marker.load_registry(args.registry)
    required_profiles = [item for item in args.required_profiles_csv.split(",") if item]
    normalized_profiles = sorted(set(required_profiles or ["base"]))
    breakglass = _make_breakglass_context(args)
    if breakglass is not None and not breakglass.scope_profiles:
        breakglass = BreakglassContext(
            enabled=True,
            approved_by=breakglass.approved_by,
            ticket=breakglass.ticket,
            reason=breakglass.reason,
            scope_host=breakglass.scope_host,
            scope_profiles=tuple(sorted(set(required_profiles or ["base"]))),
            valid_until=breakglass.valid_until,
        )
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
        required_profiles=normalized_profiles,
        signer_certificate=args.signer_certificate,
        ca_bundle=args.ca_bundle,
        signer_allowlist=[item for item in args.signer_allowlist_csv.split(",") if item],
        breakglass=breakglass,
    )
    print(json.dumps(report.to_dict(), sort_keys=True))
    return 0 if report.status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
