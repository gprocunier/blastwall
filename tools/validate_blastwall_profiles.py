#!/usr/bin/env python3
"""Validate the Blastwall profile registry."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "policy" / "profiles.yml"

TOP_LEVEL_REQUIRED = {
    "schema",
    "version",
    "targets",
    "permission_sets",
    "scopes",
    "profiles",
    "variants",
}
EXPECTED_SCHEMA = "blastwall.profile/v1"
EXPECTED_VERSION = 1
BASE_SCOPE_ORDER = [
    "alg_socket",
    "bpf",
    "capability2_bpf",
    "packet_socket",
    "userns",
    "io_uring",
    "xfrm",
    "rxrpc",
    "selfprotect",
]
EVIDENCE_STATES = {
    "BLOCKED",
    "SKIP_ABSENT",
    "FAIL_ALLOWED",
    "FAIL_UNKNOWN",
    "FAIL_MISSING_CLASS_REQUIRED",
    "FAIL_STALE_MARKER",
}
SCOPE_STATUSES = {"active", "dry-run", "planned", "deprecated"}
PROFILE_STATUSES = {"active", "dry-run", "planned", "deprecated"}
CLASS_PRESENCE = {"required", "optional"}
VALIDATION_TYPES = {"safe_probe", "static_check", "playbook"}


class RegistryError(ValueError):
    """Raised when registry loading fails before semantic validation."""


class UniqueKeyLoader(yaml.SafeLoader):
    """YAML loader that rejects duplicate mapping keys."""


def _construct_mapping(loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise RegistryError(f"duplicate mapping key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def load_registry(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            data = yaml.load(stream, Loader=UniqueKeyLoader)
    except RegistryError:
        raise
    except yaml.YAMLError as exc:
        raise RegistryError(f"invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise RegistryError("registry root must be a mapping")
    return data


def _require_mapping(errors: list[str], registry: dict[str, Any], key: str) -> dict[str, Any]:
    value = registry.get(key)
    if not isinstance(value, dict):
        errors.append(f"{key} must be a mapping")
        return {}
    return value


def _path_exists(path_text: str) -> bool:
    return (ROOT / path_text).exists()


def _string_list(errors: list[str], value: Any, owner: str, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        errors.append(f"{owner} {field} must be a list")
        return []
    strings: list[str] = []
    for item in value:
        if not isinstance(item, str):
            errors.append(f"{owner} {field} entries must be strings")
            continue
        strings.append(item)
    return strings


def validate_registry(path: Path = DEFAULT_REGISTRY) -> list[str]:
    errors: list[str] = []
    try:
        registry = load_registry(path)
    except RegistryError as exc:
        return [str(exc)]

    missing_top_level = sorted(TOP_LEVEL_REQUIRED - set(registry))
    for key in missing_top_level:
        errors.append(f"missing required top-level key: {key}")

    if registry.get("schema") != EXPECTED_SCHEMA:
        errors.append(f"schema must be {EXPECTED_SCHEMA}")
    if registry.get("version") != EXPECTED_VERSION:
        errors.append(f"version must be {EXPECTED_VERSION}")

    targets = _require_mapping(errors, registry, "targets")
    permission_sets = _require_mapping(errors, registry, "permission_sets")
    scopes = _require_mapping(errors, registry, "scopes")
    profiles = _require_mapping(errors, registry, "profiles")
    variants = _require_mapping(errors, registry, "variants")

    for target_name, target in targets.items():
        if not isinstance(target, dict):
            errors.append(f"target {target_name} must be a mapping")
            continue
        for field in ["description", "mechanism"]:
            if field not in target:
                errors.append(f"target {target_name} missing required field: {field}")

    for permission_name, permissions in permission_sets.items():
        if not isinstance(permissions, list) or not permissions:
            errors.append(f"permission_set {permission_name} must be a non-empty list")
            continue
        if any(not isinstance(permission, str) for permission in permissions):
            errors.append(f"permission_set {permission_name} must contain only strings")

    for scope_name, scope in scopes.items():
        if not isinstance(scope, dict):
            errors.append(f"scope {scope_name} must be a mapping")
            continue

        for field in ["description", "status", "object_class", "class_presence", "permission_set"]:
            if field not in scope:
                errors.append(f"scope {scope_name} missing required field: {field}")

        status = scope.get("status")
        if status is not None and status not in SCOPE_STATUSES:
            errors.append(f"scope {scope_name} has unsupported status: {status}")

        class_presence = scope.get("class_presence")
        if class_presence is not None and class_presence not in CLASS_PRESENCE:
            errors.append(f"scope {scope_name} has unsupported class_presence: {class_presence}")

        permission_set = scope.get("permission_set")
        if permission_set is not None and permission_set not in permission_sets:
            errors.append(f"scope {scope_name} references unknown permission_set: {permission_set}")

        evidence = scope.get("evidence", {})
        if evidence is not None and not isinstance(evidence, dict):
            errors.append(f"scope {scope_name} evidence must be a mapping")
            evidence = {}
        for evidence_key, evidence_state in evidence.items():
            if evidence_key not in {"present", "absent"}:
                errors.append(f"scope {scope_name} evidence has unsupported key: {evidence_key}")
            if evidence_state not in EVIDENCE_STATES:
                errors.append(f"scope {scope_name} has unsupported evidence state: {evidence_state}")

        if class_presence == "required":
            if evidence.get("absent") == "SKIP_ABSENT":
                errors.append(
                    f"scope {scope_name} required class_presence cannot use SKIP_ABSENT when class is required"
                )

        target_support = scope.get("target_support", {})
        if status in {"active", "dry-run"} and not isinstance(target_support, dict):
            errors.append(f"{status} scope {scope_name} target_support must be a mapping")
            continue
        if status in {"active", "dry-run"} and not target_support:
            errors.append(f"{status} scope {scope_name} must declare target_support")
            continue
        if target_support and not isinstance(target_support, dict):
            errors.append(f"scope {scope_name} target_support must be a mapping")
            continue

        for target_name, support in target_support.items():
            if target_name not in targets:
                errors.append(f"scope {scope_name} references unknown target: {target_name}")
            if not isinstance(support, dict):
                errors.append(f"scope {scope_name} target {target_name} support must be a mapping")
                continue

            artifact = support.get("artifact")
            if not artifact:
                errors.append(f"scope {scope_name} target {target_name} missing artifact path")
            elif not _path_exists(artifact):
                errors.append(f"scope {scope_name} target {target_name} artifact does not exist: {artifact}")

            validation = support.get("validation", {})
            if not isinstance(validation, dict):
                errors.append(f"scope {scope_name} target {target_name} validation must be a mapping")
                continue

            validation_type = validation.get("type")
            if validation_type not in VALIDATION_TYPES:
                errors.append(f"scope {scope_name} target {target_name} has unsupported validation type: {validation_type}")

            expected = validation.get("expected")
            if expected is not None and expected not in EVIDENCE_STATES:
                errors.append(f"scope {scope_name} target {target_name} has unsupported expected state: {expected}")

            required = validation.get("required_for_release", False)
            if required and validation_type == "safe_probe":
                probe = validation.get("probe")
                if not probe:
                    errors.append(f"scope {scope_name} target {target_name} release validation is missing probe")
                elif not _path_exists(probe):
                    errors.append(f"scope {scope_name} target {target_name} probe does not exist: {probe}")
            elif required:
                evidence_source = validation.get("evidence_source")
                if not evidence_source:
                    errors.append(f"scope {scope_name} target {target_name} release validation is missing evidence_source")
                elif not _path_exists(evidence_source):
                    errors.append(
                        f"scope {scope_name} target {target_name} evidence_source does not exist: {evidence_source}"
                    )

    for profile_name, profile in profiles.items():
        if not isinstance(profile, dict):
            errors.append(f"profile {profile_name} must be a mapping")
            continue
        for field in ["description", "status", "scopes"]:
            if field not in profile:
                errors.append(f"profile {profile_name} missing required field: {field}")
        if profile.get("status") not in PROFILE_STATUSES:
            errors.append(f"profile {profile_name} has unsupported status: {profile.get('status')}")
        profile_scopes = _string_list(errors, profile.get("scopes", []), f"profile {profile_name}", "scopes")
        if not profile_scopes:
            errors.append(f"profile {profile_name} scopes must be a non-empty list")
        for scope_name in profile_scopes:
            if scope_name not in scopes:
                errors.append(f"profile {profile_name} references unknown scope: {scope_name}")
        for parent in _string_list(errors, profile.get("extends"), f"profile {profile_name}", "extends"):
            if parent not in profiles:
                errors.append(f"profile {profile_name} extends unknown profile: {parent}")

    base = profiles.get("base", {})
    if isinstance(base, dict) and base.get("scopes") != BASE_SCOPE_ORDER:
        errors.append("profile base scopes must exactly match the current Blastwall base posture")

    for variant_name, variant in variants.items():
        if not isinstance(variant, dict):
            errors.append(f"variant {variant_name} must be a mapping")
            continue
        for field in ["description", "status", "base_profile", "remove", "reason"]:
            if field not in variant:
                errors.append(f"variant {variant_name} missing required field: {field}")
        base_profile = variant.get("base_profile")
        if base_profile not in profiles:
            errors.append(f"variant {variant_name} references unknown base_profile: {base_profile}")
        remove = _string_list(errors, variant.get("remove", []), f"variant {variant_name}", "remove")
        for scope_name in remove:
            if scope_name not in scopes:
                errors.append(f"variant {variant_name} removes unknown scope: {scope_name}")
            elif base_profile in profiles and isinstance(profiles[base_profile], dict):
                base_scopes = profiles[base_profile].get("scopes", [])
                if scope_name not in base_scopes:
                    errors.append(f"variant {variant_name} removes scope not present in {base_profile}: {scope_name}")
        for target_name in _string_list(errors, variant.get("targets"), f"variant {variant_name}", "targets"):
            if target_name not in targets:
                errors.append(f"variant {variant_name} references unknown target: {target_name}")

    nested = variants.get("base-nested", {})
    if isinstance(nested, dict):
        if nested.get("base_profile") != "base":
            errors.append("variant base-nested must derive from base")
        if nested.get("remove") != ["userns"]:
            errors.append("variant base-nested must remove only userns")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    args = parser.parse_args()

    errors = validate_registry(args.registry)
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1

    print(f"PASS: validated Blastwall profile registry {args.registry}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
