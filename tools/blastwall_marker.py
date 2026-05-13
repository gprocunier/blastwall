#!/usr/bin/env python3
"""Blastwall marker v1/v2 parsing and emission helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
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


@dataclass
class MarkerResult:
    raw: str
    version: int | None
    state: str | None = None
    target: str | None = None
    rpm: str | None = None
    registry_sha256: str | None = None
    policy_sha256: str | None = None
    profiles: set[str] = field(default_factory=set)
    scopes: set[str] = field(default_factory=set)
    legacy: bool = False
    suitable: bool = False
    errors: list[str] = field(default_factory=list)


def registry_sha256(path: Path = DEFAULT_REGISTRY) -> str:
    """Return the canonical registry source hash used by marker v2."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_registry(path: Path = DEFAULT_REGISTRY) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("registry root must be a mapping")
    return data


def _split_marker(raw: str) -> dict[str, str]:
    if not raw.startswith("blastwall:"):
        return {}
    fields: dict[str, str] = {}
    for token in raw.removeprefix("blastwall:").split(";"):
        if not token:
            continue
        if "=" not in token:
            fields[f"__malformed_{len(fields)}"] = token
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    return fields


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
    expected_target: str | None = None,
    accepted_rpms: set[str] | None = None,
    required_profiles: set[str] | None = None,
    allow_dry_run_profiles: bool = False,
) -> MarkerResult:
    accepted_rpms = accepted_rpms or {DEFAULT_RPM}
    required_profiles = required_profiles or {"base"}
    result = MarkerResult(raw=raw, version=None)
    fields = _split_marker(raw)
    if not fields:
        result.errors.append("missing blastwall marker prefix")
        return result
    if any(key.startswith("__malformed_") for key in fields):
        result.errors.append("malformed marker token")
        return result

    if fields.get("v") == "2":
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
        "profiles": sorted(parsed.profiles),
        "scopes": sorted(parsed.scopes),
        "errors": parsed.errors,
    }, sort_keys=True))
    return 0 if parsed.suitable else 1


if __name__ == "__main__":
    raise SystemExit(main())
