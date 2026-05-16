#!/usr/bin/env python3
"""Audit Blastwall inventory grouping and marker health from ansible-inventory JSON."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable

import blastwall_marker
import blastwall_attestation
import blastwall_attestation_vault
import blastwall_attestation_verify


BLASTWALL_GROUPS = [
    "blastwall_policy_current",
    "blastwall_policy_stale",
    "blastwall_policy_candidate",
    "blastwall_profile_base",
    "blastwall_profile_strange_socket_v1",
    "blastwall_inventory_schema_error",
    "blastwall_inventory_marker_parse_error",
]


ArtifactReadResult = Callable[[str, blastwall_attestation_vault.VaultConfig, str], blastwall_attestation_vault.VaultReadResult]
VerifyAttestationResult = Callable[..., blastwall_attestation_verify.VerificationReport]


def _default_vault_config(vault_server: str, vault_scope: str, vault_owner: str) -> blastwall_attestation_vault.VaultConfig:
    return blastwall_attestation_vault.VaultConfig.from_mapping(
        {
            "blastwall_attestation_vault_primary": vault_server,
            "blastwall_attestation_vault_servers": [vault_server],
            "blastwall_attestation_vault_scope": vault_scope,
            "blastwall_attestation_vault_owner": vault_owner,
        }
    )


def _default_read_artifact(*, server: str, config: blastwall_attestation_vault.VaultConfig, vault_ref: str) -> blastwall_attestation_vault.VaultReadResult:
    return blastwall_attestation_vault.read_vault_artifact(
        server=server,
        config=config,
        vault_ref=vault_ref,
    )


def _vault_read_failure_state(
    *,
    error: BaseException,
) -> tuple[str, bool, bool]:
    if isinstance(error, blastwall_attestation_vault.VaultCommandError):
        context = error.context
        vault_error_type = context.vault_error_type.value
        # A 'not found' response indicates reachable vault + missing artifact, which is an
        # attestation failure, not necessarily infrastructure-unavailable.
        kra_available = context.vault_error_type != blastwall_attestation_vault.VaultErrorType.NOT_FOUND
        return vault_error_type, kra_available, context.retry_attempted

    # Conservative: unknown local runtime errors are treated as infrastructure availability
    # issues for CLI consumers.
    return f"{type(error).__name__}", False, False


def _read_vault_artifact(
    *,
    server: str,
    config: blastwall_attestation_vault.VaultConfig,
    vault_ref: str,
    read_artifact: ArtifactReadResult,
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "text": None,
        "vault_server": server,
        "vault_error_type": None,
        "kra_available": None,
        "retry_attempted": False,
        "retry_servers": [server],
    }

    try:
        result = read_artifact(server=server, config=config, vault_ref=vault_ref)
    except BaseException as exc:  # noqa: BLE001
        error_type, kra_available, retry_attempted = _vault_read_failure_state(error=exc)
        response["vault_error_type"] = error_type
        response["kra_available"] = kra_available
        response["retry_attempted"] = retry_attempted
        return response

    response["text"] = result.payload.decode("utf-8", errors="replace")
    response["kra_available"] = True
    response["retry_attempted"] = result.retry_attempted
    response["retry_servers"] = [server]
    return response


def _empty_attestation_report(vault_server: str | None) -> dict[str, Any]:
    return {
        "vault_server": vault_server,
        "vault_error_type": None,
        "kra_available": None,
        "retry_attempted": False,
        "retry_servers": [],
        "artifact_ref": None,
        "attestation_generation": None,
        "index_generation_seen": None,
        "failure_state": None,
    }


def _build_latest_index_ref(marker: blastwall_marker.MarkerResult) -> str | None:
    if not marker.attest_ref:
        return None
    marker_token = "/blastwall-attestations/"
    if marker_token not in marker.attest_ref:
        return None
    prefix, suffix = marker.attest_ref.split(marker_token, 1)
    head, _ = suffix.rsplit("/", 1) if "/" in suffix else (None, None)
    if not head:
        return None
    return f"{prefix}/blastwall-attestation-index/{head}.json"


def _read_failure_state(
    *,
    missing_artifact: bool,
    vault_error_type: str | None,
) -> str | None:
    if vault_error_type == blastwall_attestation_vault.VaultErrorType.NOT_FOUND.value:
        return "FAIL_ATTESTATION_NOT_VISIBLE" if missing_artifact else "FAIL_INDEX_NOT_VISIBLE"
    if vault_error_type is None:
        return None
    return "FAIL_KRA_UNAVAILABLE"


def _default_verify_attestation(
    *,
    marker_text: str,
    expected_host: str,
    expected_registry_sha256: str,
    registry: dict[str, Any],
    envelope_text: str,
    index_text: str,
    expected_target: str,
    expected_rpm: str,
    required_profiles: list[str],
    now: datetime.datetime | None,
    signer_certificate: Path,
    ca_bundle: Path,
    signer_allowlist: list[str],
) -> blastwall_attestation_verify.VerificationReport:
    envelope = blastwall_attestation.parse_attestation_envelope(envelope_text)
    return blastwall_attestation_verify.verify_attestation_for_marker(
        marker_text=marker_text,
        envelope_text=envelope_text,
        index_text=index_text,
        registry=registry,
        expected_registry_sha256=expected_registry_sha256,
        expected_host=expected_host,
        expected_target=expected_target,
        expected_rpm=expected_rpm,
        current_policy_sha256=envelope["payload"]["policy_sha256"],
        required_profiles=required_profiles,
        signer_certificate=signer_certificate,
        ca_bundle=ca_bundle,
        signer_allowlist=signer_allowlist,
        now=now,
    )


def _verify_current_marker_attestation(
    *,
    marker_text: str,
    marker_result: blastwall_marker.MarkerResult,
    expected_host: str,
    expected_registry_sha256: str,
    registry: dict[str, Any],
    expected_target: str,
    required_profiles: set[str],
    expected_rpm: str,
    vault_server: str,
    vault_scope: str,
    vault_owner: str,
    read_vault_artifact: ArtifactReadResult,
    verify_attestation: VerifyAttestationResult,
    signer_certificate: Path,
    ca_bundle: Path,
    signer_allowlist: list[str],
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    report = _empty_attestation_report(vault_server)
    report["artifact_ref"] = marker_result.attest_ref
    report["attestation_generation"] = marker_result.generation

    if not marker_result.attest_ref:
        report["failure_state"] = "FAIL_INDEX_NOT_VISIBLE"
        return report

    try:
        vault_config = _default_vault_config(vault_server, vault_scope, vault_owner)
    except ValueError:
        report["failure_state"] = "FAIL_KRA_UNAVAILABLE"
        return report
    index_ref = _build_latest_index_ref(marker_result)
    if index_ref is None:
        report["failure_state"] = "FAIL_INDEX_NOT_VISIBLE"
        return report

    envelope_read = _read_vault_artifact(
        server=vault_server,
        config=vault_config,
        vault_ref=marker_result.attest_ref,
        read_artifact=read_vault_artifact,
    )
    if envelope_read["text"] is None:
        report.update({
            "vault_error_type": envelope_read["vault_error_type"],
            "kra_available": envelope_read["kra_available"],
            "retry_attempted": envelope_read["retry_attempted"],
        })
        report["failure_state"] = _read_failure_state(
            missing_artifact=True,
            vault_error_type=envelope_read["vault_error_type"],
        )
        return report

    index_read = _read_vault_artifact(
        server=vault_server,
        config=vault_config,
        vault_ref=index_ref,
        read_artifact=read_vault_artifact,
    )
    if index_read["text"] is None:
        report["failure_state"] = _read_failure_state(
            missing_artifact=False,
            vault_error_type=index_read["vault_error_type"],
        )
        report.update({
            "vault_error_type": index_read["vault_error_type"],
            "kra_available": index_read["kra_available"],
            "retry_attempted": index_read["retry_attempted"],
            "artifact_ref": index_ref,
        })
        return report

    try:
        verification = verify_attestation(
            marker_text=marker_text,
            expected_host=expected_host,
            expected_registry_sha256=expected_registry_sha256,
            registry=registry,
            envelope_text=envelope_read["text"],
            index_text=index_read["text"],
            expected_target=expected_target,
            expected_rpm=expected_rpm,
            required_profiles=sorted(required_profiles),
            now=now or datetime.datetime.now(tz=datetime.timezone.utc),
            signer_certificate=signer_certificate,
            ca_bundle=ca_bundle,
            signer_allowlist=signer_allowlist,
        )
    except Exception as exc:  # noqa: BLE001
        report["failure_state"] = str(exc)
        return report

    report["retry_attempted"] = envelope_read["retry_attempted"] or index_read["retry_attempted"]
    report["vault_error_type"] = envelope_read["vault_error_type"] or index_read["vault_error_type"]
    report["kra_available"] = bool(envelope_read["kra_available"] and index_read["kra_available"])
    report["artifact_ref"] = marker_result.attest_ref
    report["attestation_generation"] = marker_result.generation

    if verification.status != "PASS":
        report["failure_state"] = verification.failure_state
        return report

    details = verification.to_dict().get("details", {})
    report["failure_state"] = None
    report["attestation_generation"] = details.get("attestation_generation")
    report["index_generation_seen"] = details.get("index_generation")
    return report


def _load_json(path: Path | None) -> dict[str, Any]:
    text = sys.stdin.read() if path is None or str(path) == "-" else path.read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("inventory JSON root must be an object")
    return data


def _hostvars(inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    meta = inventory.get("_meta", {})
    values = meta.get("hostvars", {}) if isinstance(meta, dict) else {}
    return values if isinstance(values, dict) else {}


def _group_hosts(inventory: dict[str, Any], group: str) -> set[str]:
    value = inventory.get(group, {})
    hosts = value.get("hosts", []) if isinstance(value, dict) else []
    return set(hosts if isinstance(hosts, list) else [])


def _host_groups(inventory: dict[str, Any]) -> dict[str, list[str]]:
    hosts = set(_hostvars(inventory))
    for group in BLASTWALL_GROUPS:
        hosts.update(_group_hosts(inventory, group))
    return {
        host: sorted(group for group in BLASTWALL_GROUPS if host in _group_hosts(inventory, group))
        for host in sorted(hosts)
    }


def _marker_values(value: Any) -> tuple[list[str], str | None]:
    if value is None:
        return [], "idm_userclass is null"
    if isinstance(value, str):
        return [value] if value.startswith("blastwall:") else [], None
    if isinstance(value, list):
        non_strings = [item for item in value if not isinstance(item, str)]
        if non_strings:
            return [item for item in value if isinstance(item, str) and item.startswith("blastwall:")], "idm_userclass list contains non-string values"
        return [item for item in value if item.startswith("blastwall:")], None
    return [], f"idm_userclass has unsupported type {type(value).__name__}"


def audit_inventory(
    inventory: dict[str, Any],
    *,
    registry: dict[str, Any],
    expected_registry_sha256: str,
    allow_dry_run_profiles: bool,
    accepted_rpms: set[str],
    required_profiles: set[str],
    verify_attestations: bool = False,
    vault_server: str | None = None,
    vault_scope: str = "service",
    vault_owner: str = "blastwall-attestation",
    signer_certificate: Path | None = None,
    ca_bundle: Path | None = None,
    signer_allowlist: list[str] | None = None,
    expected_target: str = "rhel-login",
    expected_rpm: str = blastwall_marker.DEFAULT_RPM,
    previous: dict[str, Any] | None = None,
    now: datetime.datetime | None = None,
    read_vault_artifact: ArtifactReadResult = _default_read_artifact,
    verify_marker_attestation: VerifyAttestationResult = _default_verify_attestation,
) -> dict[str, Any]:
    hostvars = _hostvars(inventory)
    host_groups = _host_groups(inventory)
    schema_errors: dict[str, str] = {}
    marker_parse_errors: dict[str, list[str]] = {}
    legacy_v1_hosts: list[str] = []
    dry_run_marker_hosts: list[str] = []
    current_marker_candidates: dict[str, tuple[str, blastwall_marker.MarkerResult]] = {}

    for host, values in hostvars.items():
        markers, schema_error = _marker_values(values.get("idm_userclass"))
        if schema_error is not None:
            schema_errors[host] = schema_error
        for marker_text in markers:
            parsed = blastwall_marker.parse_marker(
                marker_text,
                registry=registry,
                expected_registry_sha256=expected_registry_sha256,
                expected_target=expected_target,
                accepted_rpms=accepted_rpms,
                required_profiles=required_profiles,
                allow_dry_run_profiles=allow_dry_run_profiles,
            )
            if parsed.legacy:
                legacy_v1_hosts.append(host)
            if "strange-socket-v1" in parsed.profiles:
                dry_run_marker_hosts.append(host)
            if parsed.version == 3 and parsed.hint and parsed.attest_ref:
                current = current_marker_candidates.get(host)
                if current is None or (parsed.generation or -1) > (current[1].generation or -1):
                    current_marker_candidates[host] = (marker_text, parsed)
            if parsed.errors:
                marker_parse_errors.setdefault(host, []).extend(parsed.errors)

    previous_host_groups = {}
    if previous:
        previous_host_groups = previous.get("host_groups", {})
        if not isinstance(previous_host_groups, dict):
            previous_host_groups = {}

    changed_hosts = {}
    current_to_stale = []
    current_hosts = _group_hosts(inventory, "blastwall_policy_current")
    current_marker_parse_error_hosts = sorted(current_hosts.intersection(marker_parse_errors.keys()))
    current_marker_attestation_reports: dict[str, dict[str, Any]] = {}
    current_marker_without_valid_attestation: list[str] = []
    current_marker_not_visible: list[str] = []
    current_marker_kra_unavailable: list[str] = []

    if verify_attestations:
        signer_certificate_path = signer_certificate or Path("")
        ca_bundle_path = ca_bundle or Path("")
        allowlist = signer_allowlist or []
        for host in sorted(current_hosts):
            candidate = current_marker_candidates.get(host)
            if not candidate:
                continue
            marker_text, parsed = candidate
            if not vault_server:
                report = _empty_attestation_report(vault_server)
                report["artifact_ref"] = parsed.attest_ref
                report["attestation_generation"] = parsed.generation
                report["failure_state"] = "FAIL_KRA_UNAVAILABLE"
                current_marker_attestation_reports[host] = report
                current_marker_without_valid_attestation.append(host)
                current_marker_kra_unavailable.append(host)
                continue
            report = _verify_current_marker_attestation(
                marker_text=marker_text,
                marker_result=parsed,
                expected_host=host,
                expected_registry_sha256=expected_registry_sha256,
                registry=registry,
                expected_target=expected_target,
                required_profiles=required_profiles,
                expected_rpm=expected_rpm,
                vault_server=vault_server,
                vault_scope=vault_scope,
                vault_owner=vault_owner,
                read_vault_artifact=read_vault_artifact,
                verify_attestation=verify_marker_attestation,
                signer_certificate=signer_certificate_path,
                ca_bundle=ca_bundle_path,
                signer_allowlist=allowlist,
                now=now,
            )
            current_marker_attestation_reports[host] = report
            if report["failure_state"]:
                current_marker_without_valid_attestation.append(host)
                if report["failure_state"] in {"FAIL_ATTESTATION_NOT_VISIBLE", "FAIL_INDEX_NOT_VISIBLE"}:
                    current_marker_not_visible.append(host)
                if report["failure_state"] == "FAIL_KRA_UNAVAILABLE":
                    current_marker_kra_unavailable.append(host)

            # Keep a stable retry server visibility for the report even when no read occurred.
            if not report["retry_servers"]:
                report["retry_servers"] = [vault_server] if vault_server else []

    for host, groups in host_groups.items():
        old_groups = previous_host_groups.get(host)
        if old_groups is None or sorted(old_groups) == groups:
            continue
        changed_hosts[host] = {"before": sorted(old_groups), "after": groups}
        if "blastwall_policy_current" in old_groups and "blastwall_policy_stale" in groups:
            current_to_stale.append(host)

    return {
        "group_counts": {group: len(_group_hosts(inventory, group)) for group in BLASTWALL_GROUPS},
        "host_groups": host_groups,
        "changed_hosts": changed_hosts,
        "current_to_stale": sorted(current_to_stale),
        "schema_errors": schema_errors,
        "marker_parse_errors": marker_parse_errors,
        "current_marker_parse_error_hosts": current_marker_parse_error_hosts,
        "legacy_v1_marker_hosts": sorted(set(legacy_v1_hosts)),
        "dry_run_marker_hosts": sorted(set(dry_run_marker_hosts)),
        "current_marker_attestation_reports": current_marker_attestation_reports,
        "current_marker_without_valid_attestation_hosts": sorted(current_marker_without_valid_attestation),
        "current_marker_attestation_not_visible_hosts": sorted(current_marker_not_visible),
        "current_marker_kra_unavailable_hosts": sorted(current_marker_kra_unavailable),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory-json", type=Path, default=Path("-"))
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--registry", type=Path, default=blastwall_marker.DEFAULT_REGISTRY)
    parser.add_argument("--expected-target", default="rhel-login")
    parser.add_argument("--expected-registry-sha256")
    parser.add_argument("--accepted-rpm", action="append", default=[])
    parser.add_argument("--required-profiles-csv", default="base")
    parser.add_argument("--allow-dry-run-profiles", action="store_true")
    parser.add_argument("--fail-on-current-to-stale", action="store_true")
    parser.add_argument("--fail-on-current-marker-parse-error", action="store_true")
    parser.add_argument("--verify-attestations", action="store_true")
    parser.add_argument("--vault-server")
    parser.add_argument("--vault-scope", default="service")
    parser.add_argument("--vault-owner", default="blastwall-attestation")
    parser.add_argument("--signer-certificate")
    parser.add_argument("--ca-bundle")
    parser.add_argument("--signer-allowlist-csv", default="")
    parser.add_argument("--expected-rpm", default=blastwall_marker.DEFAULT_RPM)
    parser.add_argument("--fail-on-kra-unavailable", action="store_true")
    parser.add_argument("--fail-on-attestation-not-visible", action="store_true")
    parser.add_argument("--fail-on-current-marker-without-valid-attestation", action="store_true")
    args = parser.parse_args()

    registry = blastwall_marker.load_registry(args.registry)
    inventory = _load_json(args.inventory_json)
    previous = _load_json(args.previous) if args.previous else None
    accepted_rpms = set(args.accepted_rpm) or {blastwall_marker.DEFAULT_RPM}
    required_profiles = {item for item in args.required_profiles_csv.split(",") if item} or {"base"}
    signer_certificate = (
        Path(args.signer_certificate)
        if args.signer_certificate
        else os.getenv("BLASTWALL_ATTESTATION_SIGNER_CERTIFICATE")
    )
    ca_bundle = (
        Path(args.ca_bundle)
        if args.ca_bundle
        else os.getenv("BLASTWALL_ATTESTATION_CA_BUNDLE")
    )
    vault_server = args.vault_server or os.getenv("BLASTWALL_ATTESTATION_VAULT_PRIMARY")
    signer_allowlist = [item for item in args.signer_allowlist_csv.split(",") if item]
    if not signer_allowlist and os.getenv("BLASTWALL_ATTESTATION_SIGNER_ALLOWLIST"):
        signer_allowlist = [
            item
            for item in os.getenv("BLASTWALL_ATTESTATION_SIGNER_ALLOWLIST", "").split(",")
            if item
        ]
    report = audit_inventory(
        inventory,
        registry=registry,
        expected_registry_sha256=args.expected_registry_sha256 or blastwall_marker.registry_sha256(args.registry),
        allow_dry_run_profiles=args.allow_dry_run_profiles,
        accepted_rpms=accepted_rpms,
        required_profiles=required_profiles,
        expected_target=args.expected_target,
        expected_rpm=args.expected_rpm,
        verify_attestations=args.verify_attestations,
        vault_server=vault_server,
        vault_scope=args.vault_scope,
        vault_owner=args.vault_owner,
        signer_certificate=signer_certificate if isinstance(signer_certificate, Path) else None,
        ca_bundle=ca_bundle if isinstance(ca_bundle, Path) else None,
        signer_allowlist=signer_allowlist,
        previous=previous,
    )
    print(json.dumps(report, sort_keys=True))
    if args.fail_on_current_to_stale and report["current_to_stale"]:
        return 1
    if args.fail_on_current_marker_parse_error and report["current_marker_parse_error_hosts"]:
        return 1
    if args.fail_on_current_marker_without_valid_attestation and report["current_marker_without_valid_attestation_hosts"]:
        return 1
    if args.fail_on_attestation_not_visible and report["current_marker_attestation_not_visible_hosts"]:
        return 1
    if args.fail_on_kra_unavailable and report["current_marker_kra_unavailable_hosts"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
