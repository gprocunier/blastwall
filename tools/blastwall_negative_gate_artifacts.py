#!/usr/bin/env python3
"""Build lab-only negative attestation artifacts for the stable-v3 gate."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping

import blastwall_attestation
import blastwall_attestation_sign
import blastwall_attestation_vault
import blastwall_marker


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = Path("/tmp/blastwall-negative-gate-artifacts")
ZERO_SHA256 = "0" * 64


def _timestamp(value: datetime.datetime) -> str:
    return value.astimezone(datetime.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_text(value: Mapping[str, Any]) -> str:
    return blastwall_attestation.canonical_json_bytes(value).decode("utf-8")


def _vault_artifact_name(vault_ref: str) -> str:
    return "blastwall-" + hashlib.sha256(vault_ref.encode("utf-8")).hexdigest()[:48]


def _artifact_refs(
    *,
    scope: str,
    owner: str,
    host: str,
    profiles: list[str],
    generation: int,
) -> tuple[str, str]:
    profile_key = "+".join(profiles)
    envelope_ref = blastwall_attestation_vault.build_vault_ref(
        scope=scope,
        owner=owner,
        kind="blastwall-attestations",
        host=host,
        profile=profile_key,
        generation=generation,
    )
    index_ref = blastwall_attestation_vault.build_vault_ref(
        scope=scope,
        owner=owner,
        kind="blastwall-attestation-index",
        host=host,
        profile=profile_key,
        generation=None,
    )
    return envelope_ref, index_ref


def _profile_scopes(registry: Mapping[str, Any], profiles: list[str]) -> list[str]:
    return sorted(blastwall_marker.expand_profiles(dict(registry), set(profiles)))


def _sign_inputs(args: argparse.Namespace, registry_sha256: str) -> blastwall_attestation_sign.SignInputs:
    return blastwall_attestation_sign.SignInputs(
        subject_host=args.host,
        target=args.target,
        rpm_nevra=args.rpm,
        policy_sha256=args.policy_sha256,
        registry_sha256=registry_sha256,
        probe_report_sha256=args.probe_report_sha256,
        profiles=[profile for profile in args.profiles_csv.split(",") if profile] or ["base"],
        state="active",
        generation=args.generation,
        source_revision=args.source_revision,
        aap_workflow_job_id=args.aap_workflow_job_id,
        valid_for_seconds=args.valid_for_seconds,
        nonce=args.nonce,
        spo_evidence=None,
        signer_key=args.signer_key,
        signer_certificate=args.signer_certificate,
        ca_bundle=args.ca_bundle,
        signer_allowlist=[item for item in args.signer_allowlist_csv.split(",") if item],
        allow_dry_run_profiles=args.allow_dry_run_profiles,
    )


def _mutate_payload_for_case(
    *,
    case: str,
    payload: dict[str, Any],
    registry: Mapping[str, Any],
    args: argparse.Namespace,
    now: datetime.datetime,
) -> None:
    if case == "expired":
        issued = now - datetime.timedelta(hours=4)
        not_after = now - datetime.timedelta(hours=3)
        payload["issued_at"] = _timestamp(issued)
        payload["not_before"] = _timestamp(issued)
        payload["not_after"] = _timestamp(not_after)
    elif case == "profile-mismatch":
        mismatch_profiles = [
            profile for profile in args.mismatch_profiles_csv.split(",") if profile
        ] or ["strange-socket-v1"]
        payload["profiles"] = blastwall_marker.canonical_profile_list(
            dict(registry),
            mismatch_profiles,
        )
        payload["scopes"] = _profile_scopes(registry, list(payload["profiles"]))
    elif case == "host-binding-mismatch":
        payload["subject_host"] = args.mismatch_host


def _build_artifacts(args: argparse.Namespace) -> dict[str, Any]:
    registry = blastwall_marker.load_registry(args.registry)
    registry_sha256 = args.registry_sha256 or blastwall_marker.registry_sha256(args.registry)
    inputs = _sign_inputs(args, registry_sha256)
    marker_profiles = blastwall_marker.canonical_profile_list(dict(registry), inputs.profiles)
    envelope_ref, index_ref = _artifact_refs(
        scope=args.vault_scope,
        owner=args.vault_owner,
        host=args.host,
        profiles=marker_profiles,
        generation=args.generation,
    )
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    marker_exp = now + datetime.timedelta(seconds=args.marker_valid_for_seconds)

    payload = blastwall_attestation_sign.build_payload(inputs, registry=registry, now=now)
    _mutate_payload_for_case(
        case=args.case,
        payload=payload,
        registry=registry,
        args=args,
        now=now,
    )
    envelope = blastwall_attestation.build_attestation_envelope(
        payload,
        private_key=args.signer_key,
        signer_certificate=args.signer_certificate,
    )
    envelope_sha = blastwall_attestation.attestation_envelope_sha256(envelope)

    if args.case == "signature-tamper":
        tampered_payload = dict(envelope["payload"])
        tampered_payload["nonce"] = tampered_payload["nonce"] + "-tampered"
        envelope["payload"] = tampered_payload
        envelope["payload_sha256"] = blastwall_attestation.attestation_payload_sha256(tampered_payload)
        envelope_sha = blastwall_attestation.attestation_envelope_sha256(envelope)

    index_generation = args.generation + 1 if args.case == "replayed-generation" else args.generation
    index_state = "revoked" if args.case == "revoked-index" else "active"
    index_payload = {
        "subject_host": payload["subject_host"],
        "target": payload["target"],
        "profile_set": payload["profiles"],
        "latest_generation": index_generation,
        "latest_attest_ref": envelope_ref,
        "latest_attest_sha256": envelope_sha,
        "state": index_state,
        "issued_at": payload["issued_at"],
        "not_before": payload["not_before"],
        "not_after": payload["not_after"],
    }
    if args.case == "expired":
        index_payload["issued_at"] = payload["issued_at"]
        index_payload["not_before"] = payload["not_before"]
        index_payload["not_after"] = payload["not_after"]
    index = blastwall_attestation.build_latest_index(
        index_payload,
        private_key=args.signer_key,
        signer_certificate=args.signer_certificate,
    )

    marker_state = "revoked" if args.case == "revoked-marker" else "active"
    marker = blastwall_marker.emit_marker_v3(
        registry=dict(registry),
        rpm=args.rpm,
        profiles=marker_profiles,
        target=args.target,
        state=marker_state,
        attest_ref=envelope_ref,
        attest_sha256=envelope_sha,
        signer_kid=payload["signer_kid"],
        exp=marker_exp,
        generation=args.generation,
        allow_dry_run_profiles=args.allow_dry_run_profiles,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    envelope_path = args.output_dir / f"{args.host}.envelope.json"
    index_path = args.output_dir / f"{args.host}.index.json"
    envelope_text = _canonical_text(envelope)
    index_text = _canonical_text(index)
    envelope_path.write_text(envelope_text, encoding="utf-8")
    index_path.write_text(index_text, encoding="utf-8")
    return {
        "case": args.case,
        "host": args.host,
        "marker": marker,
        "attestation_ref": envelope_ref,
        "attestation_sha256": envelope_sha,
        "index_ref": index_ref,
        "index_sha256": blastwall_attestation.latest_index_sha256(index),
        "index_generation": index_generation,
        "marker_generation": args.generation,
        "signer_kid": payload["signer_kid"],
        "envelope_file": str(envelope_path),
        "index_file": str(index_path),
        "vault_artifacts": {
            "envelope": {
                "name": _vault_artifact_name(envelope_ref),
                "ref": envelope_ref,
            },
            "index": {
                "name": _vault_artifact_name(index_ref),
                "ref": index_ref,
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--case",
        choices=[
            "valid",
            "replayed-generation",
            "expired",
            "revoked-index",
            "revoked-marker",
            "signature-tamper",
            "profile-mismatch",
            "host-binding-mismatch",
        ],
        required=True,
    )
    parser.add_argument("--registry", type=Path, default=blastwall_marker.DEFAULT_REGISTRY)
    parser.add_argument("--host", required=True)
    parser.add_argument("--mismatch-host", default="mirror-registry.workshop.lan")
    parser.add_argument("--target", default="rhel-login")
    parser.add_argument("--rpm", default=blastwall_marker.DEFAULT_RPM)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--registry-sha256")
    parser.add_argument("--probe-report-sha256", default=ZERO_SHA256)
    parser.add_argument("--profiles-csv", default="base")
    parser.add_argument("--mismatch-profiles-csv", default="strange-socket-v1")
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--source-revision", default="negative-gate")
    parser.add_argument("--aap-workflow-job-id", type=int, default=0)
    parser.add_argument("--valid-for-seconds", type=int, default=86400)
    parser.add_argument("--marker-valid-for-seconds", type=int, default=86400)
    parser.add_argument("--nonce", default="negative-gate")
    parser.add_argument("--signer-key", type=Path, required=True)
    parser.add_argument("--signer-certificate", type=Path, required=True)
    parser.add_argument("--ca-bundle", type=Path, required=True)
    parser.add_argument("--signer-allowlist-csv", required=True)
    parser.add_argument("--vault-scope", default=blastwall_attestation_vault.DEFAULT_VAULT_SCOPE)
    parser.add_argument("--vault-owner", default=blastwall_attestation_vault.DEFAULT_VAULT_OWNER)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--allow-dry-run-profiles", action="store_true")
    args = parser.parse_args()

    try:
        report = _build_artifacts(args)
    except Exception as exc:  # noqa: BLE001 - CLI should print actionable failure text.
        print(json.dumps({"status": "FAIL", "message": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
