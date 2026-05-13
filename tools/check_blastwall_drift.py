#!/usr/bin/env python3
"""Check Blastwall registry, policy, probe, and documentation drift."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = Path(__file__).resolve().parent
DEFAULT_REGISTRY = ROOT / "policy" / "profiles.yml"
DOC_PATHS = [
    ROOT / "docs" / "blastwall-v2" / "profiles.md",
    ROOT / "docs" / "blastwall-v2" / "markers.md",
    ROOT / "docs" / "openshift-spo.html",
    ROOT / "openshift" / "spo" / "README.md",
]
SPO_EXECUTABLE_USAGE_PATHS = [
    ROOT / "openshift" / "spo" / "20-scc-blastwall-confined.yaml",
    ROOT / "openshift" / "spo" / "40-test-harness-configmap.yaml",
    ROOT / "openshift" / "spo" / "tests" / "50-validation-job.yaml",
    ROOT / "openshift" / "spo" / "scripts" / "validate-blastwall-spo-nodes.sh",
    ROOT / "tests" / "openshift" / "blastwall_spo_probe.py",
    ROOT / "tests" / "openshift" / "validate_spo_manifests.py",
    ROOT / "playbooks" / "apply-validate-spo-policy-crs.yml",
]
SPO_USAGE_DISCOVERY_PATHS = [
    ROOT / "openshift" / "spo" / "scripts" / "validate-blastwall-spo-nodes.sh",
    ROOT / "playbooks" / "apply-validate-spo-policy-crs.yml",
]
LEGACY_SPO_USAGE_STRINGS = [
    "blastwall_" + ".process",
    "blastwallnested_" + ".process",
]
CHECKED_SCOPE_STATUSES = {"active", "dry-run"}
CHECKED_PROFILE_STATUSES = {"active", "dry-run"}

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from validate_blastwall_profiles import load_registry, validate_registry  # noqa: E402


class DriftResult:
    """Collected checker output and hard failures."""

    def __init__(self) -> None:
        self.records: list[str] = []
        self.errors: list[str] = []

    def pass_(self, message: str) -> None:
        self.records.append(f"PASS {message}")

    def skip(self, message: str) -> None:
        self.records.append(f"SKIP_ABSENT {message}")

    def deferred(self, message: str) -> None:
        self.records.append(f"DEFERRED {message}")

    def fail(self, message: str) -> None:
        self.errors.append(message)
        self.records.append(f"FAIL {message}")


def _path(path_text: str) -> Path:
    return ROOT / path_text


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _contains_word(text: str, token: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])", text) is not None


def _tokenize_cil(text: str) -> list[str]:
    stripped_lines = [line.split(";", 1)[0] for line in text.splitlines()]
    return re.findall(r"\(|\)|[^\s()]+", "\n".join(stripped_lines))


def _parse_cil_forms(text: str) -> list[Any]:
    tokens = _tokenize_cil(text)
    index = 0

    def parse_one() -> Any:
        nonlocal index
        if index >= len(tokens):
            raise ValueError("unexpected end of CIL")
        token = tokens[index]
        index += 1
        if token == "(":
            expr: list[Any] = []
            while index < len(tokens) and tokens[index] != ")":
                expr.append(parse_one())
            if index >= len(tokens):
                raise ValueError("unclosed CIL list")
            index += 1
            return expr
        if token == ")":
            raise ValueError("unexpected CIL list close")
        return token

    forms: list[Any] = []
    while index < len(tokens):
        forms.append(parse_one())
    return forms


def _walk_cil_forms(form: Any) -> list[list[Any]]:
    matches: list[list[Any]] = []
    if isinstance(form, list):
        matches.append(form)
        for item in form:
            matches.extend(_walk_cil_forms(item))
    return matches


def _atom_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        atoms: set[str] = set()
        for item in value:
            atoms.update(_atom_set(item))
        return atoms
    return set()


def _rule_permission_sets(policy: str, rule: str, object_class: str) -> list[set[str]]:
    try:
        forms = _parse_cil_forms(policy)
    except ValueError:
        return []

    permissions: list[set[str]] = []
    for form in forms:
        for expr in _walk_cil_forms(form):
            if len(expr) < 4 or expr[0] != rule:
                continue
            class_expr = expr[3]
            if not isinstance(class_expr, list) or not class_expr or class_expr[0] != object_class:
                continue
            permissions.append(_atom_set(class_expr[1:]))
    return permissions


def _check_exact_permissions(
    result: DriftResult,
    *,
    policy: str,
    rel: Path,
    scope_name: str,
    target_name: str,
    object_class: str,
    expected_permissions: set[str],
    label: str,
) -> None:
    for rule in ["deny", "neverallow"]:
        rule_sets = _rule_permission_sets(policy, rule, object_class)
        if not rule_sets:
            result.fail(
                f"scope {scope_name} target {target_name} {label} lacks {rule} permissions "
                f"for {object_class}: {rel}"
            )
            continue
        for actual_permissions in rule_sets:
            missing = sorted(expected_permissions - actual_permissions)
            extra = sorted(actual_permissions - expected_permissions)
            if missing or extra:
                detail = []
                if missing:
                    detail.append("missing " + ",".join(missing))
                if extra:
                    detail.append("extra " + ",".join(extra))
                result.fail(
                    f"scope {scope_name} target {target_name} {label} {rule} permissions drift "
                    f"for {object_class}: {'; '.join(detail)} in {rel}"
                )
            else:
                result.pass_(
                    f"scope {scope_name} target {target_name} {label} {rule} permissions exactly match registry"
                )


def _expand_profile_scopes(registry: dict[str, Any], profile_name: str, seen: set[str] | None = None) -> list[str]:
    if seen is None:
        seen = set()
    if profile_name in seen:
        return []
    seen.add(profile_name)

    profile = registry["profiles"].get(profile_name, {})
    scopes: list[str] = []
    for parent in profile.get("extends", []) or []:
        scopes.extend(_expand_profile_scopes(registry, parent, seen))
    scopes.extend(profile.get("scopes", []) or [])
    return scopes


def _effective_variant_scopes(registry: dict[str, Any], variant_name: str) -> list[str]:
    variant = registry["variants"][variant_name]
    base_scopes = _expand_profile_scopes(registry, variant["base_profile"])
    remove = set(variant.get("remove", []) or [])
    return [scope for scope in base_scopes if scope not in remove]


def _registry_permissions(registry: dict[str, Any], scope: dict[str, Any]) -> list[str]:
    permission_set = scope.get("permission_set")
    permissions = registry.get("permission_sets", {}).get(permission_set, [])
    return permissions if isinstance(permissions, list) else []


def _load_spo_policy(path: Path) -> str:
    documents = list(yaml.safe_load_all(_read_text(path)))
    for document in documents:
        if isinstance(document, dict) and document.get("kind") == "RawSelinuxProfile":
            policy = document.get("spec", {}).get("policy")
            if isinstance(policy, str):
                return policy
    return ""


def _check_registry_schema(registry_path: Path, result: DriftResult) -> bool:
    errors = validate_registry(registry_path)
    if errors:
        for error in errors:
            result.fail(f"registry schema drift: {error}")
        return False
    result.pass_(f"registry schema {registry_path}")
    return True


def _check_active_profiles(registry: dict[str, Any], result: DriftResult) -> None:
    scopes = registry["scopes"]

    for profile_name, profile in registry["profiles"].items():
        profile_status = profile.get("status")
        if profile_status not in CHECKED_PROFILE_STATUSES:
            continue
        allowed_scope_statuses = {"active"} if profile_status == "active" else CHECKED_SCOPE_STATUSES
        expanded = _expand_profile_scopes(registry, profile_name)
        for scope_name in expanded:
            scope = scopes.get(scope_name)
            if not scope:
                result.fail(f"{profile_status} profile {profile_name} references missing scope {scope_name}")
                continue
            if scope.get("status") not in allowed_scope_statuses:
                result.fail(
                    f"{profile_status} profile {profile_name} references unsupported scope "
                    f"{scope_name} ({scope.get('status')})"
                )
        result.pass_(f"{profile_status} profile {profile_name} uses supported scopes only")

    for variant_name, variant in registry["variants"].items():
        if variant.get("status") != "active":
            continue
        base_profile = variant.get("base_profile")
        base_scopes = _expand_profile_scopes(registry, base_profile)
        for removed_scope in variant.get("remove", []) or []:
            if removed_scope not in base_scopes:
                result.fail(f"variant {variant_name} removes scope not in base profile: {removed_scope}")
            elif removed_scope in scopes:
                result.skip(f"variant {variant_name} intentionally removes {removed_scope}")

        effective = _effective_variant_scopes(registry, variant_name)
        for scope_name in effective:
            scope = scopes.get(scope_name)
            if scope and scope.get("status") != "active":
                result.fail(
                    f"active variant {variant_name} inherits non-active scope {scope_name} ({scope.get('status')})"
                )
        result.pass_(f"active variant {variant_name} has registry-derived scope set")


def _check_cil_artifact(
    registry: dict[str, Any],
    result: DriftResult,
    scope_name: str,
    scope: dict[str, Any],
    target_name: str,
    artifact: Path,
) -> None:
    if artifact.suffix != ".cil":
        result.fail(f"scope {scope_name} target {target_name} artifact is not CIL: {artifact.relative_to(ROOT)}")
        return

    text = _read_text(artifact)
    rel = artifact.relative_to(ROOT)
    if "(deny " not in text or "(neverallow " not in text:
        result.fail(f"scope {scope_name} target {target_name} artifact lacks deny plus neverallow: {rel}")
    else:
        result.pass_(f"scope {scope_name} target {target_name} has CIL deny plus neverallow")

    object_class = scope.get("object_class")
    if object_class != "policy_selfprotect" and not _contains_word(text, str(object_class)):
        result.fail(f"scope {scope_name} target {target_name} artifact lacks object class {object_class}: {rel}")

    if scope.get("class_presence") == "optional":
        if "(optional " not in text:
            result.fail(f"scope {scope_name} target {target_name} optional class lacks optional wrapper: {rel}")
        else:
            result.pass_(f"scope {scope_name} target {target_name} optional class is wrapped")

    if object_class == "policy_selfprotect":
        result.pass_(f"scope {scope_name} target {target_name} self-protection artifact uses dedicated policy guard")
        return

    _check_exact_permissions(
        result,
        policy=text,
        rel=rel,
        scope_name=scope_name,
        target_name=target_name,
        object_class=str(object_class),
        expected_permissions=set(_registry_permissions(registry, scope)),
        label="CIL",
    )


def _check_spo_artifact(
    registry: dict[str, Any],
    result: DriftResult,
    scope_name: str,
    scope: dict[str, Any],
    target_name: str,
    artifact: Path,
) -> None:
    policy = _load_spo_policy(artifact)
    rel = artifact.relative_to(ROOT)
    if not policy:
        result.fail(f"scope {scope_name} target {target_name} artifact lacks RawSelinuxProfile policy: {rel}")
        return

    if "(deny " not in policy or "(neverallow " not in policy:
        result.fail(f"scope {scope_name} target {target_name} SPO policy lacks deny plus neverallow: {rel}")
    else:
        result.pass_(f"scope {scope_name} target {target_name} has SPO deny plus neverallow")

    object_class = str(scope.get("object_class"))
    if not _contains_word(policy, object_class):
        result.fail(f"scope {scope_name} target {target_name} SPO policy lacks object class {object_class}: {rel}")

    if scope.get("class_presence") == "optional":
        if "(optional " not in policy:
            result.fail(f"scope {scope_name} target {target_name} optional SPO class lacks optional wrapper: {rel}")
        else:
            result.pass_(f"scope {scope_name} target {target_name} optional SPO class is wrapped")

    _check_exact_permissions(
        result,
        policy=policy,
        rel=rel,
        scope_name=scope_name,
        target_name=target_name,
        object_class=object_class,
        expected_permissions=set(_registry_permissions(registry, scope)),
        label="SPO",
    )


def _check_target_support(registry: dict[str, Any], result: DriftResult) -> None:
    targets = registry["targets"]
    for scope_name, scope in registry["scopes"].items():
        if scope.get("status") not in CHECKED_SCOPE_STATUSES:
            continue
        target_support = scope.get("target_support", {}) or {}
        for target_name, support in target_support.items():
            target = targets.get(target_name, {})
            artifact_text = support.get("artifact")
            artifact = _path(str(artifact_text))
            if not artifact.exists():
                result.fail(f"scope {scope_name} target {target_name} artifact missing: {artifact_text}")
                continue

            mechanism = target.get("mechanism")
            if mechanism == "selinux-cil-deny":
                _check_cil_artifact(registry, result, scope_name, scope, target_name, artifact)
            elif mechanism == "spo-raw-selinux-profile":
                _check_spo_artifact(registry, result, scope_name, scope, target_name, artifact)
            else:
                result.fail(f"scope {scope_name} target {target_name} has unsupported mechanism: {mechanism}")

            validation = support.get("validation", {}) or {}
            if validation.get("required_for_release"):
                if validation.get("type") == "safe_probe":
                    probe = _path(str(validation.get("probe", "")))
                    if not probe.exists():
                        result.fail(f"scope {scope_name} target {target_name} required probe missing: {probe}")
                    else:
                        result.pass_(f"scope {scope_name} target {target_name} required probe exists")
                else:
                    evidence_source = _path(str(validation.get("evidence_source", "")))
                    if not evidence_source.exists():
                        result.fail(
                            f"scope {scope_name} target {target_name} required evidence source missing: "
                            f"{evidence_source}"
                        )
                    else:
                        result.pass_(f"scope {scope_name} target {target_name} required evidence source exists")
            else:
                result.skip(f"scope {scope_name} target {target_name} release probe not required by registry")


def _check_variant_target_mapping(registry: dict[str, Any], result: DriftResult) -> None:
    for variant_name, variant in registry["variants"].items():
        if variant.get("status") != "active":
            continue
        effective = set(_effective_variant_scopes(registry, variant_name))
        removed = set(variant.get("remove", []) or [])
        for target_name in variant.get("targets", []) or []:
            for scope_name in effective:
                scope = registry["scopes"].get(scope_name, {})
                if target_name not in (scope.get("target_support", {}) or {}):
                    if scope_name == "selfprotect":
                        result.skip(f"scope {scope_name} has no {target_name} implementation by current target contract")
                    else:
                        result.fail(f"variant {variant_name} target {target_name} lacks scope support for {scope_name}")
            for scope_name in removed:
                scope = registry["scopes"].get(scope_name, {})
                if target_name in (scope.get("target_support", {}) or {}):
                    result.fail(f"variant {variant_name} target {target_name} still supports removed scope {scope_name}")
            result.pass_(f"variant {variant_name} target {target_name} matches effective scope set")


def _check_docs(registry: dict[str, Any], result: DriftResult) -> None:
    docs_text = "\n".join(_read_text(path) for path in DOC_PATHS if path.exists())
    for profile_name, profile in registry["profiles"].items():
        if profile.get("status") in CHECKED_PROFILE_STATUSES:
            if profile_name not in docs_text:
                result.fail(f"{profile.get('status')} profile {profile_name} is not mentioned in Blastwall docs")
            else:
                result.pass_(f"{profile.get('status')} profile {profile_name} is documented")
    for variant_name, variant in registry["variants"].items():
        if variant.get("status") == "active":
            if variant_name not in docs_text:
                result.fail(f"active variant {variant_name} is not mentioned in Blastwall docs")
            else:
                result.pass_(f"active variant {variant_name} is documented")


def _check_spo_usage_source(registry: dict[str, Any], result: DriftResult) -> None:
    for target_name, target in registry["targets"].items():
        if target.get("mechanism") != "spo-raw-selinux-profile":
            continue
        if target.get("usage_source") != "status.usage":
            result.fail(f"target {target_name} must declare usage_source: status.usage")
        else:
            result.pass_(f"target {target_name} declares usage_source status.usage")

    docs_text = "\n".join(_read_text(path) for path in DOC_PATHS if path.exists())
    if ".status.usage" in docs_text or "status.usage" in docs_text:
        result.pass_("OpenShift docs describe status.usage as the usage source")
    else:
        result.fail("OpenShift docs do not describe status.usage usage discovery")

    hardcoded_paths = [
        path.relative_to(ROOT).as_posix()
        for path in SPO_EXECUTABLE_USAGE_PATHS
        if path.exists() and any(legacy in _read_text(path) for legacy in LEGACY_SPO_USAGE_STRINGS)
    ]
    if hardcoded_paths:
        result.fail(
            "executable OpenShift/SPO harness paths must not hardcode legacy process-type defaults: "
            + ", ".join(hardcoded_paths)
        )
    else:
        result.pass_("OpenShift runtime assets avoid hardcoded legacy SPO process-type defaults")

    missing_usage_discovery = [
        path.relative_to(ROOT).as_posix()
        for path in SPO_USAGE_DISCOVERY_PATHS
        if path.exists() and "status.usage" not in _read_text(path)
    ]
    if missing_usage_discovery:
        result.fail(
            "OpenShift/SPO runtime paths must query status.usage: "
            + ", ".join(missing_usage_discovery)
        )
    else:
        result.pass_("OpenShift/SPO runtime paths query status.usage")


def check_drift(registry_path: Path = DEFAULT_REGISTRY) -> DriftResult:
    registry_path = Path(registry_path)
    result = DriftResult()
    schema_ok = _check_registry_schema(registry_path, result)
    try:
        registry = load_registry(registry_path)
    except Exception as exc:  # noqa: BLE001 - surface loader errors as drift output.
        if schema_ok:
            result.fail(f"registry could not be loaded for drift checks: {exc}")
        return result

    required_mappings = ["targets", "permission_sets", "scopes", "profiles", "variants"]
    if any(not isinstance(registry.get(key), dict) for key in required_mappings):
        return result

    _check_active_profiles(registry, result)
    _check_target_support(registry, result)
    _check_variant_target_mapping(registry, result)
    _check_docs(registry, result)
    _check_spo_usage_source(registry, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY, help="Path to policy/profiles.yml")
    args = parser.parse_args()

    result = check_drift(args.registry)
    for record in result.records:
        print(record)
    if result.errors:
        print(f"FAIL blastwall drift check found {len(result.errors)} blocking error(s)")
        return 1
    print("PASS blastwall drift check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
