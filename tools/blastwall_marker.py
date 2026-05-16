#!/usr/bin/env python3
"""Blastwall marker v1/v2/v3 parsing and emission helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import datetime
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "policy" / "profiles.yml"
DEFAULT_RPM = "blastwall-selinux-0.6.1-0.rc1"
LEGACY_V1_RPMS = {"blastwall-selinux-0.5.2-1"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
V1_REQUIRED_FLAGS = {
    "state": "active",
    "alg": "deny",
    "bpf": "deny",
    "self": "deny",
    "pkt": "deny",
    "userns": "deny",
    "iou": "deny",
    "xfrm": "deny",
    "rxrpc": "deny",
}
PROFILE_STATUS_ACTIVE = "active"
PROFILE_STATUS_DRY_RUN = "dry-run"
PROFILE_STATUS_PLANNED = "planned"
PROFILE_STATUS_DEPRECATED = "deprecated"
V2_V3_SUPPORTED_STATES = {
    "active",
    "lab-active",
    "revoked",
    "failed",
    "rollback-active",
    "rollback-failed",
}
V3_LOCATOR_FIELDS = {
    "state",
    "target",
    "rpm",
    "profiles",
    "attest_ref",
    "attest_sha256",
    "signer_kid",
    "exp",
    "generation",
}
RESERVED_MARKER_FIELDS = {
    "v",
    "state",
    "target",
    "rpm",
    "registry_sha256",
    "policy_sha256",
    "profiles",
    "scopes",
    "attest_ref",
    "attest_sha256",
    "signer_kid",
    "exp",
    "generation",
}
RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
SIGNER_KID_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass
class MarkerResult:
    raw: str
    version: int | None
    state: str | None = None
    target: str | None = None
    rpm: str | None = None
    registry_sha256: str | None = None
    policy_sha256: str | None = None
    attest_ref: str | None = None
    attest_sha256: str | None = None
    signer_kid: str | None = None
    exp: str | None = None
    generation: int | None = None
    profiles: set[str] = field(default_factory=set)
    scopes: set[str] = field(default_factory=set)
    legacy: bool = False
    suitable: bool = False
    hint: bool = False
    errors: list[str] = field(default_factory=list)


def registry_sha256(path: Path = DEFAULT_REGISTRY) -> str:
    """Return the canonical registry source hash used by marker v2."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_registry(path: Path = DEFAULT_REGISTRY) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("registry root must be a mapping")
    return data


def _split_marker(raw: str) -> tuple[dict[str, str], set[str]]:
    if not raw.startswith("blastwall:"):
        return {}, set()
    fields: dict[str, str] = {}
    duplicate_reserved_fields: set[str] = set()
    for token in raw.removeprefix("blastwall:").split(";"):
        if not token:
            continue
        if "=" not in token:
            fields[f"__malformed_{len(fields)}"] = token
            continue
        key, value = token.split("=", 1)
        if key in fields and key in RESERVED_MARKER_FIELDS:
            duplicate_reserved_fields.add(key)
        fields[key] = value
    return fields, duplicate_reserved_fields


def _csv_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item for item in value.split(",") if item}


def _csv_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item for item in value.split(",") if item]


def _dedupe_profiles(items: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def expand_profiles(
    registry: dict[str, Any],
    profiles: set[str],
    seen: set[str] | None = None,
) -> set[str]:
    expanded: set[str] = set()
    profile_map = registry.get("profiles", {})
    seen = seen or set()
    for profile_name in profiles:
        if profile_name not in profile_map:
            raise ValueError(f"unknown profile: {profile_name}")
        if profile_name in seen:
            raise ValueError(f"profile cycle detected: {profile_name}")
        profile = profile_map[profile_name]
        for parent in profile.get("extends", []):
            expanded.update(expand_profiles(registry, {parent}, seen | {profile_name}))
        expanded.update(profile.get("scopes", []))
    return expanded


def canonical_profile_list(
    registry: dict[str, Any],
    profiles: list[str] | None = None,
) -> list[str]:
    """Return the registry-ordered profile closure for marker v2 emission."""

    requested_profiles = _dedupe_profiles(profiles or ["base"])
    profile_map = registry.get("profiles", {})
    closure: set[str] = set()

    def collect(profile_name: str, stack: tuple[str, ...]) -> None:
        if profile_name not in profile_map:
            raise ValueError(f"unknown profile: {profile_name}")
        if profile_name in stack:
            raise ValueError(f"profile cycle detected: {profile_name}")
        profile = profile_map[profile_name]
        for parent in profile.get("extends", []):
            collect(parent, (*stack, profile_name))
        closure.add(profile_name)

    for profile_name in requested_profiles:
        collect(profile_name, ())

    return [profile_name for profile_name in profile_map if profile_name in closure]


def _profile_status(
    registry: dict[str, Any],
    profile_name: str,
) -> str | None:
    profile = registry.get("profiles", {}).get(profile_name)
    if not isinstance(profile, dict):
        return None
    status = profile.get("status")
    return str(status) if status is not None else None


def _collect_profile_statuses(
    registry: dict[str, Any],
    profiles: set[str],
) -> dict[str, str | None]:
    return {
        profile_name: _profile_status(registry, profile_name)
        for profile_name in profiles
    }


def _parse_expiry(exp: str | None) -> datetime.datetime:
    if not exp:
        raise ValueError("missing exp")
    if not RFC3339_UTC_RE.match(exp):
        raise ValueError("exp is not RFC3339 UTC timestamp")
    parsed = datetime.datetime.fromisoformat(exp.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) != datetime.timedelta(0):
        raise ValueError("exp is not RFC3339 UTC timestamp")
    return parsed


def _parse_generation(raw: str | None) -> int:
    if raw is None:
        raise ValueError("missing generation")
    try:
        generation = int(raw)
    except ValueError as exc:
        raise ValueError("generation is not integer") from exc
    if generation < 0:
        raise ValueError("generation must be non-negative")
    return generation


def _validate_profile_statuses(
    profile_statuses: dict[str, str | None],
    allow_dry_run_profiles: bool,
) -> tuple[set[str], list[str]]:
    dry_run_profiles: set[str] = set()
    errors: list[str] = []
    for profile_name, status in profile_statuses.items():
        if status is None:
            continue
        if status == PROFILE_STATUS_DRY_RUN:
            if allow_dry_run_profiles:
                dry_run_profiles.add(profile_name)
            else:
                errors.append(f"dry-run profile not allowed: {profile_name}")
            continue
        if status == PROFILE_STATUS_PLANNED:
            errors.append(f"planned profile cannot satisfy suitability: {profile_name}")
            continue
        if status == PROFILE_STATUS_DEPRECATED:
            errors.append(f"deprecated profile cannot satisfy suitability: {profile_name}")
            continue
        if status != PROFILE_STATUS_ACTIVE:
            errors.append(f"unknown profile status for {profile_name}: {status}")
    return dry_run_profiles, errors


def parse_marker(
    raw: str,
    *,
    registry: dict[str, Any],
    expected_registry_sha256: str,
    expected_policy_sha256: str | None = None,
    expected_target: str | None = None,
    accepted_rpms: set[str] | None = None,
    required_profiles: set[str] | None = None,
    allow_dry_run_profiles: bool = False,
) -> MarkerResult:
    accepted_rpms = accepted_rpms or {DEFAULT_RPM}
    required_profiles = required_profiles or {"base"}
    result = MarkerResult(raw=raw, version=None)
    fields, duplicate_reserved_fields = _split_marker(raw)
    if not fields:
        result.errors.append("missing blastwall marker prefix")
        return result
    if any(key.startswith("__malformed_") for key in fields):
        result.errors.append("malformed marker token")
        return result
    for key in sorted(duplicate_reserved_fields):
        result.errors.append(f"duplicate reserved marker field: {key}")
    marker_version = fields.get("v")

    if marker_version == "2":
        result.version = 2
        result.state = fields.get("state")
        result.target = fields.get("target")
        result.rpm = fields.get("rpm")
        result.registry_sha256 = fields.get("registry_sha256")
        result.policy_sha256 = fields.get("policy_sha256")
        raw_profile_list = _csv_list(fields.get("profiles"))
        result.profiles = set(raw_profile_list)
        result.scopes = _csv_set(fields.get("scopes"))

        for key in ["state", "target", "rpm", "registry_sha256", "policy_sha256", "profiles", "scopes"]:
            if not fields.get(key):
                result.errors.append(f"missing {key}")
        if expected_target is not None and result.target != expected_target:
            result.errors.append(f"target mismatch: {result.target!r} != {expected_target!r}")
        profile_statuses = _collect_profile_statuses(registry, result.profiles)
        dry_run_profiles, status_errors = _validate_profile_statuses(
            profile_statuses,
            allow_dry_run_profiles=allow_dry_run_profiles,
        )
        result.errors.extend(status_errors)
        required_state = "active"
        if dry_run_profiles:
            required_state = "lab-active"
        if result.state != required_state:
            if required_state == PROFILE_STATUS_ACTIVE:
                result.errors.append("marker state is not active")
            else:
                result.errors.append("marker state must be lab-active for dry-run profiles")
        if result.rpm not in accepted_rpms:
            result.errors.append("marker rpm is not accepted")
        if not result.registry_sha256 or not SHA256_RE.match(result.registry_sha256):
            result.errors.append("registry_sha256 is not 64 lowercase hex")
        elif result.registry_sha256 != expected_registry_sha256:
            result.errors.append("registry_sha256 is stale")
        if not result.policy_sha256 or not SHA256_RE.match(result.policy_sha256):
            result.errors.append("policy_sha256 is not 64 lowercase hex")
        elif expected_policy_sha256 is not None and result.policy_sha256 != expected_policy_sha256:
            result.errors.append("policy_sha256 does not match installed policy payload")

        known_profiles = registry.get("profiles", {})
        unknown_profiles = sorted(result.profiles - set(known_profiles))
        for profile_name in unknown_profiles:
            result.errors.append(f"unknown profile: {profile_name}")
        for profile_name in sorted(required_profiles - set(known_profiles)):
            result.errors.append(f"unknown required profile: {profile_name}")

        if not required_profiles.issubset(result.profiles):
            result.errors.append("required profile missing")

        if not unknown_profiles:
            if raw_profile_list:
                try:
                    expected_profiles = canonical_profile_list(registry, raw_profile_list)
                except ValueError as exc:
                    result.errors.append(str(exc))
                    expected_profiles = []
                if expected_profiles and raw_profile_list != expected_profiles:
                    result.errors.append(
                        "marker profiles are not canonical: expected "
                        f"{','.join(expected_profiles)}"
                    )
            try:
                expanded_scopes = expand_profiles(registry, result.profiles)
            except ValueError as exc:
                result.errors.append(str(exc))
                expanded_scopes = set()
            registry_scopes = set(registry.get("scopes", {}).keys())
            unknown_scopes = sorted(result.scopes - registry_scopes)
            if unknown_scopes:
                result.errors.append(f"marker scopes unknown to registry: {','.join(unknown_scopes)}")
            extra_scopes = sorted(result.scopes - expanded_scopes)
            if extra_scopes:
                result.errors.append(f"marker scopes not implied by selected profiles: {','.join(extra_scopes)}")
            missing_scopes = sorted(expanded_scopes - result.scopes)
            if missing_scopes:
                result.errors.append(f"marker scopes missing expanded profile scopes: {','.join(missing_scopes)}")

        result.suitable = not result.errors
        return result

    if marker_version == "3":
        result.version = 3
        result.state = fields.get("state")
        result.target = fields.get("target")
        result.rpm = fields.get("rpm")
        raw_profile_list = _csv_list(fields.get("profiles"))
        result.profiles = set(raw_profile_list)
        result.attest_ref = fields.get("attest_ref")
        result.attest_sha256 = fields.get("attest_sha256")
        result.signer_kid = fields.get("signer_kid")
        result.exp = fields.get("exp")

        for key in sorted(V3_LOCATOR_FIELDS):
            if not fields.get(key):
                result.errors.append(f"missing {key}")

        if expected_target is not None and result.target != expected_target:
            result.errors.append(f"target mismatch: {result.target!r} != {expected_target!r}")

        if result.rpm not in accepted_rpms:
            result.errors.append("marker rpm is not accepted")

        if not result.attest_sha256 or not SHA256_RE.match(result.attest_sha256):
            result.errors.append("attest_sha256 is not 64 lowercase hex")

        if not result.signer_kid or not SIGNER_KID_RE.match(result.signer_kid):
            result.errors.append("signer_kid is not lowercase SKI hex")

        try:
            result.generation = _parse_generation(fields.get("generation"))
        except ValueError as exc:
            result.errors.append(str(exc))

        try:
            exp_dt = _parse_expiry(fields.get("exp"))
        except ValueError as exc:
            result.errors.append(str(exc))
        else:
            if exp_dt <= datetime.datetime.now(datetime.timezone.utc):
                result.errors.append("marker has expired")

        known_profiles = registry.get("profiles", {})
        unknown_profiles = sorted(result.profiles - set(known_profiles))
        for profile_name in unknown_profiles:
            result.errors.append(f"unknown profile: {profile_name}")
        for profile_name in sorted(required_profiles - set(known_profiles)):
            result.errors.append(f"unknown required profile: {profile_name}")

        if not required_profiles.issubset(result.profiles):
            result.errors.append("required profile missing")

        dry_run_profiles: set[str] = set()
        if not unknown_profiles:
            if raw_profile_list:
                try:
                    expected_profiles = canonical_profile_list(registry, raw_profile_list)
                except ValueError as exc:
                    result.errors.append(str(exc))
                    expected_profiles = []
                if expected_profiles and raw_profile_list != expected_profiles:
                    result.errors.append(
                        "marker profiles are not canonical: expected "
                        f"{','.join(expected_profiles)}"
                    )
            profile_statuses = _collect_profile_statuses(registry, result.profiles)
            dry_run_profiles, status_errors = _validate_profile_statuses(
                profile_statuses,
                allow_dry_run_profiles=allow_dry_run_profiles,
            )
            result.errors.extend(status_errors)

        if result.state not in V2_V3_SUPPORTED_STATES:
            result.errors.append(f"unsupported marker state: {result.state}")
        elif result.state == "revoked":
            result.errors.append("marker is revoked")
        elif result.state not in {"active", "lab-active"}:
            result.errors.append(f"marker state is not suitable: {result.state}")
        else:
            required_state = PROFILE_STATUS_ACTIVE
            if dry_run_profiles:
                required_state = "lab-active"
            if result.state != required_state:
                if required_state == PROFILE_STATUS_ACTIVE:
                    result.errors.append("marker state is not active")
                else:
                    result.errors.append("marker state must be lab-active for dry-run profiles")

        result.hint = not result.errors
        result.suitable = False
        return result

    if marker_version is not None:
        try:
            result.version = int(marker_version)
        except ValueError:
            result.version = None
        result.errors.append(f"unsupported marker version: {marker_version}")
        return result

    result.version = 1
    result.legacy = True
    result.state = fields.get("state")
    result.rpm = fields.get("rpm")
    if result.rpm not in (accepted_rpms | LEGACY_V1_RPMS):
        result.errors.append("legacy marker rpm is not accepted")
    if not SHA256_RE.match(fields.get("rpm_sha256", "")):
        result.errors.append("legacy rpm_sha256 is not 64 lowercase hex")
    for key, expected in V1_REQUIRED_FLAGS.items():
        if fields.get(key) != expected:
            result.errors.append(f"legacy marker missing {key}={expected}")
    if required_profiles != {"base"}:
        result.errors.append("legacy marker can only satisfy base profile")
    if not result.errors:
        result.profiles = {"base"}
        result.scopes = set(registry["profiles"]["base"]["scopes"])
    result.suitable = not result.errors
    return result


def emit_marker_v2(
    *,
    registry: dict[str, Any],
    registry_hash: str,
    policy_hash: str,
    rpm: str,
    target: str = "rhel-login",
    profiles: list[str] | None = None,
    state: str = "active",
    allow_dry_run_profiles: bool = False,
) -> str:
    profile_list = canonical_profile_list(registry, profiles or ["base"])
    profile_set = set(profile_list)
    profile_statuses = _collect_profile_statuses(registry, profile_set)
    dry_run_profiles, status_errors = _validate_profile_statuses(
        profile_statuses,
        allow_dry_run_profiles=allow_dry_run_profiles,
    )
    if status_errors:
        raise ValueError("; ".join(status_errors))
    if dry_run_profiles and state == "active":
        state = "lab-active"
    scopes = expand_profiles(registry, profile_set)
    ordered_scopes = [
        scope for scope in registry["profiles"]["base"]["scopes"] if scope in scopes
    ] + sorted(scopes - set(registry["profiles"]["base"]["scopes"]))
    return (
        "blastwall:"
        f"v=2;state={state};target={target};rpm={rpm};"
        f"registry_sha256={registry_hash};policy_sha256={policy_hash};"
        f"profiles={','.join(profile_list)};scopes={','.join(ordered_scopes)}"
    )


def emit_marker_v3(
    *,
    registry: dict[str, Any],
    rpm: str,
    profiles: list[str] | None = None,
    target: str = "rhel-login",
    state: str = "active",
    attest_ref: str,
    attest_sha256: str,
    signer_kid: str,
    exp: str | datetime.datetime,
    generation: int | str,
    allow_dry_run_profiles: bool = False,
) -> str:
    profile_list = canonical_profile_list(registry, profiles or ["base"])
    profile_set = set(profile_list)
    profile_statuses = _collect_profile_statuses(registry, profile_set)
    dry_run_profiles, status_errors = _validate_profile_statuses(
        profile_statuses,
        allow_dry_run_profiles=allow_dry_run_profiles,
    )
    if status_errors:
        raise ValueError("; ".join(status_errors))
    if state == PROFILE_STATUS_ACTIVE and dry_run_profiles:
        state = "lab-active"
    if state not in V2_V3_SUPPORTED_STATES:
        raise ValueError(f"unsupported marker state: {state}")
    if not attest_ref:
        raise ValueError("missing attest_ref")
    if not SHA256_RE.match(attest_sha256):
        raise ValueError("attest_sha256 is not 64 lowercase hex")
    if not SIGNER_KID_RE.match(signer_kid):
        raise ValueError("signer_kid is not lowercase SKI hex")

    if isinstance(exp, datetime.datetime):
        exp_dt = exp
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=datetime.timezone.utc)
        else:
            exp_dt = exp_dt.astimezone(datetime.timezone.utc)
        exp_text = exp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        exp_text = exp
    exp_dt = _parse_expiry(exp_text)
    if exp_dt <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("exp must be in the future")

    parsed_generation = _parse_generation(str(generation))

    return (
        "blastwall:"
        f"v=3;state={state};target={target};rpm={rpm};"
        f"profiles={','.join(profile_list)};"
        f"attest_ref={attest_ref};attest_sha256={attest_sha256};"
        f"signer_kid={signer_kid};exp={exp_dt:%Y-%m-%dT%H:%M:%SZ};"
        f"generation={parsed_generation}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--emit", action="store_true")
    parser.add_argument("--rpm", default=DEFAULT_RPM)
    parser.add_argument("--policy-sha256")
    parser.add_argument("--allow-dry-run-profiles", action="store_true")
    parser.add_argument("--profile", action="append", default=[])
    parser.add_argument("--target", default="rhel-login")
    parser.add_argument("--state", default="active")
    parser.add_argument("marker", nargs="?")
    subparsers = parser.add_subparsers(dest="mode")

    check_parser = subparsers.add_parser("check", help="check one or more markers")
    check_parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    check_parser.add_argument("--marker", action="append", default=[])
    check_parser.add_argument("--markers-stdin", action="store_true")
    check_parser.add_argument("--required-profile", action="append", default=[])
    check_parser.add_argument("--required-profiles-csv", default="")
    check_parser.add_argument("--accepted-rpm", action="append", default=[])
    check_parser.add_argument("--expected-target")
    check_parser.add_argument("--expected-registry-sha256")
    check_parser.add_argument("--expected-policy-sha256")
    check_parser.add_argument("--allow-dry-run-profiles", action="store_true", dest="check_allow_dry_run_profiles")

    args = parser.parse_args()

    if args.mode == "check":
        registry = load_registry(args.registry)
        expected_hash = args.expected_registry_sha256 or registry_sha256(args.registry)
        required_profiles = set(args.required_profile)
        required_profiles.update(item for item in args.required_profiles_csv.split(",") if item)
        if not required_profiles:
            required_profiles = {"base"}
        accepted_rpms = set(args.accepted_rpm) or {DEFAULT_RPM}
        markers = list(args.marker)
        if args.markers_stdin:
            stdin_text = sys.stdin.read().strip()
            if stdin_text:
                try:
                    loaded_markers = json.loads(stdin_text)
                except json.JSONDecodeError:
                    loaded_markers = [line.strip() for line in stdin_text.splitlines() if line.strip()]
                if isinstance(loaded_markers, str):
                    markers.append(loaded_markers)
                elif isinstance(loaded_markers, list):
                    markers.extend(str(item) for item in loaded_markers)
                else:
                    print("FAIL: --markers-stdin must receive a marker, JSON string, or JSON array")
                    return 2
        parsed = [
            parse_marker(
                marker_text,
                registry=registry,
                expected_registry_sha256=expected_hash,
                expected_policy_sha256=args.expected_policy_sha256,
                expected_target=args.expected_target,
                accepted_rpms=accepted_rpms,
                required_profiles=required_profiles,
                allow_dry_run_profiles=args.allow_dry_run_profiles or args.check_allow_dry_run_profiles,
            )
            for marker_text in markers
            if marker_text.startswith("blastwall:")
        ]
        suitable = [item for item in parsed if item.suitable]
        print(json.dumps({
            "suitable": bool(suitable),
            "checked": len(parsed),
            "required_profiles": sorted(required_profiles),
            "accepted_rpms": sorted(accepted_rpms),
            "matches": [
                {
                    "version": item.version,
                    "legacy": item.legacy,
                    "profiles": sorted(item.profiles),
                    "scopes": sorted(item.scopes),
                }
                for item in suitable
            ],
            "hints": [
                {
                    "version": item.version,
                    "profiles": sorted(item.profiles),
                    "attest_ref": item.attest_ref,
                    "attest_sha256": item.attest_sha256,
                    "signer_kid": item.signer_kid,
                    "generation": item.generation,
                }
                for item in parsed
                if item.hint
            ],
            "errors": [item.errors for item in parsed if item.errors],
        }, sort_keys=True))
        return 0 if suitable else 1

    registry = load_registry(args.registry)
    reg_hash = registry_sha256(args.registry)
    if args.emit:
        if not args.policy_sha256 or not SHA256_RE.match(args.policy_sha256):
            print("FAIL: --policy-sha256 must be 64 lowercase hex")
            return 1
        try:
            marker = emit_marker_v2(
                registry=registry,
                registry_hash=reg_hash,
                policy_hash=args.policy_sha256,
                rpm=args.rpm,
                target=args.target,
                state=args.state,
                allow_dry_run_profiles=args.allow_dry_run_profiles,
                profiles=args.profile or ["base"],
            )
        except ValueError as exc:
            print(f"FAIL: {exc}")
            return 1
        print(marker)
        return 0

    if not args.marker:
        print("FAIL: marker argument is required unless --emit is used")
        return 1
    parsed = parse_marker(args.marker, registry=registry, expected_registry_sha256=reg_hash)
    print(json.dumps({
        "suitable": parsed.suitable,
        "version": parsed.version,
        "legacy": parsed.legacy,
        "hint": parsed.hint,
        "profiles": sorted(parsed.profiles),
        "scopes": sorted(parsed.scopes),
        "errors": parsed.errors,
    }, sort_keys=True))
    return 0 if parsed.suitable else 1


if __name__ == "__main__":
    raise SystemExit(main())
