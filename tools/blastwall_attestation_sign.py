#!/usr/bin/env python3
"""Build, sign, store, and verify Blastwall v3 attestation artifacts."""

from __future__ import annotations

import argparse
import datetime
import json
import secrets
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography import x509

import blastwall_attestation
import blastwall_attestation_vault
import blastwall_attestation_verify
import blastwall_marker


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENVELOPE_DIR = Path("/tmp/blastwall-attestations/envelopes")
DEFAULT_INDEX_DIR = Path("/tmp/blastwall-attestations/indexes")
DEFAULT_VALID_FOR_SECONDS = 3600
ZERO_SHA256 = "0" * 64


@dataclass(frozen=True)
class SignInputs:
    subject_host: str
    target: str
    rpm_nevra: str
    policy_sha256: str
    registry_sha256: str
    probe_report_sha256: str
    profiles: list[str]
    state: str
    generation: int
    source_revision: str
    aap_workflow_job_id: int
    valid_for_seconds: int
    nonce: str
    spo_evidence: Mapping[str, Any] | None
    signer_key: Path
    signer_certificate: Path
    ca_bundle: Path
    signer_allowlist: list[str]
    allow_dry_run_profiles: bool


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime.datetime) -> str:
    return value.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_text(value: Mapping[str, Any]) -> str:
    return blastwall_attestation.canonical_json_bytes(value).decode("utf-8")


def _load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _read_json_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _source_revision_default() -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError:
        return "unknown"
    revision = completed.stdout.strip()
    return revision or "unknown"


def _workflow_job_id_default() -> int:
    for name in ("AWX_WORKFLOW_JOB_ID", "WORKFLOW_JOB_ID", "AWX_JOB_ID", "JOB_ID"):
        value = __import__("os").environ.get(name, "")
        if value.isdigit():
            return int(value)
    return 0


def _profile_list(args: argparse.Namespace) -> list[str]:
    profiles: list[str] = []
    profiles.extend(args.profile or [])
    profiles.extend(item.strip() for item in (args.profiles_csv or "").split(",") if item.strip())
    return profiles or ["base"]


def _spo_evidence(args: argparse.Namespace) -> Mapping[str, Any] | None:
    if not args.spo_evidence:
        return None
    try:
        parsed = json.loads(args.spo_evidence)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid --spo-evidence JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("--spo-evidence must be a JSON object")
    return parsed


def _signer_allowlist(args: argparse.Namespace) -> list[str]:
    values: list[str] = []
    values.extend(args.signer_allowlist or [])
    values.extend(item.strip() for item in (args.signer_allowlist_csv or "").split(",") if item.strip())
    return values


def _vault_config(args: argparse.Namespace) -> blastwall_attestation_vault.VaultConfig:
    return blastwall_attestation_vault.VaultConfig.from_mapping(
        {
            "blastwall_attestation_vault_primary": args.vault_primary,
            "blastwall_attestation_vault_servers": args.vault_servers_csv,
            "blastwall_attestation_vault_scope": args.vault_scope,
            "blastwall_attestation_vault_owner": args.vault_owner,
            "blastwall_attestation_vault_retry_not_found": args.vault_retry_not_found,
            "blastwall_attestation_vault_retry_attempts": args.vault_retry_attempts,
            "blastwall_attestation_vault_retry_delay_seconds": args.vault_retry_delay_seconds,
        }
    )


def _build_sign_inputs(args: argparse.Namespace, registry_path: Path) -> SignInputs:
    registry_hash = args.registry_sha256 or blastwall_marker.registry_sha256(registry_path)
    return SignInputs(
        subject_host=args.subject_host,
        target=args.target,
        rpm_nevra=args.rpm,
        policy_sha256=args.policy_sha256,
        registry_sha256=registry_hash,
        probe_report_sha256=args.probe_report_sha256,
        profiles=_profile_list(args),
        state=args.state,
        generation=args.generation,
        source_revision=args.source_revision or _source_revision_default(),
        aap_workflow_job_id=args.aap_workflow_job_id,
        valid_for_seconds=args.valid_for_seconds,
        nonce=args.nonce or secrets.token_urlsafe(24),
        spo_evidence=_spo_evidence(args),
        signer_key=args.signer_key,
        signer_certificate=args.signer_certificate,
        ca_bundle=args.ca_bundle,
        signer_allowlist=_signer_allowlist(args),
        allow_dry_run_profiles=args.allow_dry_run_profiles,
    )


def build_payload(
    inputs: SignInputs,
    *,
    registry: Mapping[str, Any],
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    """Build a canonical attestation payload from verified pipeline inputs."""

    if inputs.generation < 0:
        raise ValueError("generation must be non-negative")
    if not inputs.signer_allowlist:
        raise ValueError("at least one signer allowlist entry is required")
    now = now or _utc_now()
    not_after = now + datetime.timedelta(seconds=inputs.valid_for_seconds)
    registry_dict = dict(registry)
    profiles = blastwall_marker.canonical_profile_list(registry_dict, inputs.profiles)
    scopes = sorted(blastwall_marker.expand_profiles(registry_dict, set(profiles)))
    signer_kid = blastwall_attestation.extract_signer_kid(_load_certificate(inputs.signer_certificate))
    if signer_kid not in {blastwall_attestation.normalize_ski(item) for item in inputs.signer_allowlist}:
        raise ValueError("signer certificate SKI is not in signer allowlist")
    payload = {
        "attestation_version": 1,
        "subject_host": inputs.subject_host,
        "target": inputs.target,
        "state": inputs.state,
        "rpm_nevra": inputs.rpm_nevra,
        "registry_sha256": inputs.registry_sha256,
        "policy_sha256": inputs.policy_sha256,
        "profiles": profiles,
        "scopes": scopes,
        "probe_report_sha256": inputs.probe_report_sha256,
        "aap_workflow_job_id": inputs.aap_workflow_job_id,
        "source_revision": inputs.source_revision,
        "issued_at": _timestamp(now),
        "not_before": _timestamp(now),
        "not_after": _timestamp(not_after),
        "generation": inputs.generation,
        "signer_kid": signer_kid,
        "nonce": inputs.nonce,
    }
    if inputs.spo_evidence is not None:
        payload["spo_evidence"] = dict(inputs.spo_evidence)
    blastwall_attestation.validate_attestation_payload(payload)
    return payload


def _artifact_refs(
    *,
    config: blastwall_attestation_vault.VaultConfig,
    host: str,
    profiles: list[str],
    generation: int,
) -> tuple[str, str]:
    profile_key = "+".join(profiles)
    envelope_ref = blastwall_attestation_vault.build_vault_ref(
        scope=config.scope,
        owner=config.owner,
        kind="blastwall-attestations",
        host=host,
        profile=profile_key,
        generation=generation,
    )
    index_ref = blastwall_attestation_vault.build_vault_ref(
        scope=config.scope,
        owner=config.owner,
        kind="blastwall-attestation-index",
        host=host,
        profile=profile_key,
        generation=None,
    )
    return envelope_ref, index_ref


def _materialize_artifacts(
    *,
    envelope_text: str,
    index_text: str,
    envelope_dir: Path | None,
    index_dir: Path | None,
    host: str,
) -> tuple[str | None, str | None]:
    envelope_path = None
    index_path = None
    if envelope_dir is not None:
        envelope_dir.mkdir(parents=True, exist_ok=True)
        envelope_path = envelope_dir / f"{host}.json"
        envelope_path.write_text(envelope_text + "\n", encoding="utf-8")
    if index_dir is not None:
        index_dir.mkdir(parents=True, exist_ok=True)
        index_path = index_dir / f"{host}.json"
        index_path.write_text(index_text + "\n", encoding="utf-8")
    return (str(envelope_path) if envelope_path else None, str(index_path) if index_path else None)


def _verify_marker_artifacts(
    *,
    marker_text: str,
    envelope_text: str,
    index_text: str,
    registry: Mapping[str, Any],
    inputs: SignInputs,
) -> dict[str, Any]:
    report = blastwall_attestation_verify.verify_attestation_for_marker(
        marker_text=marker_text,
        envelope_text=envelope_text,
        index_text=index_text,
        registry=registry,
        expected_registry_sha256=inputs.registry_sha256,
        expected_host=inputs.subject_host,
        expected_target=inputs.target,
        expected_rpm=inputs.rpm_nevra,
        current_policy_sha256=inputs.policy_sha256,
        required_profiles=blastwall_marker.canonical_profile_list(dict(registry), inputs.profiles),
        signer_certificate=inputs.signer_certificate,
        ca_bundle=inputs.ca_bundle,
        signer_allowlist=inputs.signer_allowlist,
    )
    if report.status != "PASS":
        raise ValueError(f"{report.failure_state}: {report.message}")
    return report.to_dict()


def sign_store_readback(
    inputs: SignInputs,
    *,
    registry: Mapping[str, Any],
    vault_config: blastwall_attestation_vault.VaultConfig,
    envelope_dir: Path | None = DEFAULT_ENVELOPE_DIR,
    index_dir: Path | None = DEFAULT_INDEX_DIR,
    command_runner: Callable[[list[str], bytes | None], blastwall_attestation_vault.VaultCommandResult] = blastwall_attestation_vault._run_command,
) -> dict[str, Any]:
    """Sign artifacts, store them in the configured vault, read them back, and verify."""

    payload = build_payload(inputs, registry=registry)
    envelope_ref, index_ref = _artifact_refs(
        config=vault_config,
        host=inputs.subject_host,
        profiles=payload["profiles"],
        generation=inputs.generation,
    )
    envelope = blastwall_attestation.build_attestation_envelope(
        payload,
        private_key=inputs.signer_key,
        signer_certificate=inputs.signer_certificate,
    )
    envelope_sha = blastwall_attestation.attestation_envelope_sha256(envelope)
    index = blastwall_attestation.build_latest_index(
        {
            "subject_host": inputs.subject_host,
            "target": inputs.target,
            "profile_set": payload["profiles"],
            "latest_generation": inputs.generation,
            "latest_attest_ref": envelope_ref,
            "latest_attest_sha256": envelope_sha,
            "state": payload["state"],
            "issued_at": payload["issued_at"],
            "not_before": payload["not_before"],
            "not_after": payload["not_after"],
        },
        private_key=inputs.signer_key,
        signer_certificate=inputs.signer_certificate,
    )
    envelope_text = _canonical_text(envelope)
    index_text = _canonical_text(index)
    envelope_write = blastwall_attestation_vault.write_vault_artifact(
        server=vault_config.primary,
        config=vault_config,
        vault_ref=envelope_ref,
        payload=envelope_text,
        command_runner=command_runner,
    )
    index_write = blastwall_attestation_vault.write_vault_artifact(
        server=vault_config.primary,
        config=vault_config,
        vault_ref=index_ref,
        payload=index_text,
        command_runner=command_runner,
    )
    envelope_read = blastwall_attestation_vault.read_vault_artifact_with_digest(
        server=vault_config.primary,
        config=vault_config,
        vault_ref=envelope_ref,
        expected_digest=envelope_write.digest,
        command_runner=command_runner,
    )
    index_read = blastwall_attestation_vault.read_vault_artifact_with_digest(
        server=vault_config.primary,
        config=vault_config,
        vault_ref=index_ref,
        expected_digest=index_write.digest,
        command_runner=command_runner,
    )
    readback_envelope_text = envelope_read.payload.decode("utf-8")
    readback_index_text = index_read.payload.decode("utf-8")
    marker_text = blastwall_marker.emit_marker_v3(
        registry=dict(registry),
        rpm=inputs.rpm_nevra,
        profiles=payload["profiles"],
        target=inputs.target,
        state=payload["state"],
        attest_ref=envelope_ref,
        attest_sha256=envelope_sha,
        signer_kid=payload["signer_kid"],
        exp=payload["not_after"],
        generation=inputs.generation,
        allow_dry_run_profiles=inputs.allow_dry_run_profiles,
    )
    verification = _verify_marker_artifacts(
        marker_text=marker_text,
        envelope_text=readback_envelope_text,
        index_text=readback_index_text,
        registry=registry,
        inputs=inputs,
    )
    envelope_path, index_path = _materialize_artifacts(
        envelope_text=readback_envelope_text,
        index_text=readback_index_text,
        envelope_dir=envelope_dir,
        index_dir=index_dir,
        host=inputs.subject_host,
    )
    return {
        "status": "PASS",
        "marker": marker_text,
        "attestation_ref": envelope_ref,
        "attestation_sha256": envelope_sha,
        "index_ref": index_ref,
        "index_sha256": blastwall_attestation.latest_index_sha256(index),
        "index_generation": inputs.generation,
        "signer_kid": payload["signer_kid"],
        "vault_server": vault_config.primary,
        "workflow_job_id": inputs.aap_workflow_job_id,
        "source_revision": inputs.source_revision,
        "envelope_file": envelope_path,
        "index_file": index_path,
        "vault_readback": {
            "envelope_attempts": envelope_read.attempts,
            "index_attempts": index_read.attempts,
            "retry_attempted": envelope_read.retry_attempted or index_read.retry_attempted,
        },
        "verification": verification,
    }


def verify_existing_artifacts(
    inputs: SignInputs,
    *,
    registry: Mapping[str, Any],
    envelope_text: str,
    index_text: str,
) -> dict[str, Any]:
    """Verify existing artifacts and return a marker that may be published."""

    envelope = blastwall_attestation.parse_attestation_envelope(envelope_text)
    index = blastwall_attestation.parse_latest_index(index_text)
    payload = envelope["payload"]
    marker_text = blastwall_marker.emit_marker_v3(
        registry=dict(registry),
        rpm=payload["rpm_nevra"],
        profiles=list(payload["profiles"]),
        target=payload["target"],
        state=payload["state"],
        attest_ref=index["latest_attest_ref"],
        attest_sha256=index["latest_attest_sha256"],
        signer_kid=envelope["signer_kid"],
        exp=payload["not_after"],
        generation=payload["generation"],
        allow_dry_run_profiles=inputs.allow_dry_run_profiles,
    )
    verification = _verify_marker_artifacts(
        marker_text=marker_text,
        envelope_text=envelope_text,
        index_text=index_text,
        registry=registry,
        inputs=inputs,
    )
    return {
        "status": "PASS",
        "marker": marker_text,
        "attestation_ref": index["latest_attest_ref"],
        "attestation_sha256": index["latest_attest_sha256"],
        "index_generation": index["latest_generation"],
        "signer_kid": envelope["signer_kid"],
        "vault_server": "",
        "workflow_job_id": payload["aap_workflow_job_id"],
        "source_revision": payload["source_revision"],
        "verification": verification,
    }


def _failure_report(exc: Exception) -> dict[str, Any]:
    report: dict[str, Any] = {"status": "FAIL", "message": str(exc)}
    if isinstance(exc, blastwall_attestation_vault.VaultCommandError):
        report["vault_error"] = exc.context.to_dict()
    return report


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--registry", type=Path, default=blastwall_marker.DEFAULT_REGISTRY)
    parser.add_argument("--subject-host", required=True)
    parser.add_argument("--target", default="rhel-login")
    parser.add_argument("--rpm", default=blastwall_marker.DEFAULT_RPM)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--registry-sha256")
    parser.add_argument("--probe-report-sha256", default=ZERO_SHA256)
    parser.add_argument("--profile", action="append", default=[])
    parser.add_argument("--profiles-csv", default="")
    parser.add_argument("--state", default="active")
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--source-revision", default="")
    parser.add_argument("--aap-workflow-job-id", type=int, default=_workflow_job_id_default())
    parser.add_argument("--valid-for-seconds", type=int, default=DEFAULT_VALID_FOR_SECONDS)
    parser.add_argument("--nonce", default="")
    parser.add_argument("--spo-evidence", default="")
    parser.add_argument("--signer-certificate", type=Path, required=True)
    parser.add_argument("--ca-bundle", type=Path, required=True)
    parser.add_argument("--signer-allowlist", action="append", default=[])
    parser.add_argument("--signer-allowlist-csv", default="")
    parser.add_argument("--allow-dry-run-profiles", action="store_true")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    sign_parser = subparsers.add_parser("sign-store-readback")
    _add_common_args(sign_parser)
    sign_parser.add_argument("--signer-key", type=Path, required=True)
    sign_parser.add_argument("--vault-primary", required=True)
    sign_parser.add_argument("--vault-servers-csv", required=True)
    sign_parser.add_argument("--vault-scope", default=blastwall_attestation_vault.DEFAULT_VAULT_SCOPE)
    sign_parser.add_argument("--vault-owner", default=blastwall_attestation_vault.DEFAULT_VAULT_OWNER)
    sign_parser.add_argument("--vault-retry-not-found", action="store_true", default=True)
    sign_parser.add_argument("--vault-retry-attempts", type=int, default=blastwall_attestation_vault.DEFAULT_RETRY_ATTEMPTS)
    sign_parser.add_argument("--vault-retry-delay-seconds", type=int, default=blastwall_attestation_vault.DEFAULT_RETRY_DELAY_SECONDS)
    sign_parser.add_argument("--envelope-dir", type=Path, default=DEFAULT_ENVELOPE_DIR)
    sign_parser.add_argument("--index-dir", type=Path, default=DEFAULT_INDEX_DIR)

    verify_parser = subparsers.add_parser("verify-existing")
    _add_common_args(verify_parser)
    verify_parser.add_argument("--envelope-json", type=Path, required=True)
    verify_parser.add_argument("--index-json", type=Path, required=True)
    verify_parser.set_defaults(signer_key=Path("/dev/null"))

    args = parser.parse_args()
    registry = blastwall_marker.load_registry(args.registry)
    inputs = _build_sign_inputs(args, args.registry)
    try:
        if args.mode == "sign-store-readback":
            report = sign_store_readback(
                inputs,
                registry=registry,
                vault_config=_vault_config(args),
                envelope_dir=args.envelope_dir,
                index_dir=args.index_dir,
            )
        else:
            report = verify_existing_artifacts(
                inputs,
                registry=registry,
                envelope_text=_read_json_text(args.envelope_json),
                index_text=_read_json_text(args.index_json),
            )
    except Exception as exc:  # noqa: BLE001 - CLI must return structured failure evidence.
        print(json.dumps(_failure_report(exc), sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
