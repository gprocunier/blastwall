#!/usr/bin/env python3
"""Render Blastwall profile-grouping fragments for IdM inventories."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from textwrap import dedent
from typing import Any, Dict


ROOT = Path(__file__).resolve().parents[1]
MARKER_PATH = ROOT / "tools" / "blastwall_marker.py"

spec = importlib.util.spec_from_file_location("blastwall_marker", MARKER_PATH)
assert spec is not None
assert spec.loader is not None
blastwall_marker = importlib.util.module_from_spec(spec)
sys.modules["blastwall_marker"] = blastwall_marker
spec.loader.exec_module(blastwall_marker)


DEFAULT_REGISTRY = ROOT / "policy" / "profiles.yml"
DEFAULT_STRANGE_PROFILE = "strange-socket-v1"


def _load_registry(path: Path) -> dict[str, Any]:
    return blastwall_marker.load_registry(path)


def _marker_fields(marker_text: str) -> dict[str, str]:
    values = marker_text.removeprefix("blastwall:").split(";")
    parsed: dict[str, str] = {}
    for value in values:
        if not value or "=" not in value:
            continue
        key, val = value.split("=", 1)
        parsed[key] = val
    return parsed


def _jinja_string(value: str) -> str:
    return json.dumps(value)


def _scope_membership_pattern(scopes: list[str]) -> str:
    unique_scopes: list[str] = []
    for scope in scopes:
        if scope and scope not in unique_scopes:
            unique_scopes.append(scope)
    if not unique_scopes:
        return ".*"
    scope_union = "|".join(re.escape(scope) for scope in unique_scopes)
    presence_checks = "".join(
        f"(?=(?:{re.escape(scope)}|[^;]*,{re.escape(scope)})(?:,|(?=;|$)))"
        for scope in unique_scopes
    )
    scope_list = f"(?:{scope_union})(?:,(?:{scope_union}))*"
    return f"{presence_checks}{scope_list}"


def _reserved_field_uniqueness_patterns() -> list[str]:
    return [
        f"(?!.*(?:^blastwall:|;){re.escape(field)}=[^;]*(?:;[^;]*)*;{re.escape(field)}=)"
        for field in sorted(blastwall_marker.RESERVED_MARKER_FIELDS)
    ]


def _v2_marker_match_expr(state: str, fields: dict[str, str], registry_hash: str) -> str:
    rpm_expr = (
        "(BLASTWALL_REQUIRED_POLICY_MARKER | "
        "default(lookup('env', 'BLASTWALL_REQUIRED_POLICY_MARKER') | "
        f"default({_jinja_string(blastwall_marker.DEFAULT_RPM)}, true), true) | regex_escape)"
    )
    registry_expr = (
        "(BLASTWALL_PROFILE_REGISTRY_SHA256 | "
        "default(lookup('env', 'BLASTWALL_PROFILE_REGISTRY_SHA256') | "
        f"default({_jinja_string(registry_hash)}, true), true) | regex_escape)"
    )
    scope_list = [scope for scope in fields["scopes"].split(",") if scope]
    scope_pattern = _scope_membership_pattern(scope_list)

    pattern_parts = [
        _jinja_string("^"),
        *(_jinja_string(pattern) for pattern in _reserved_field_uniqueness_patterns()),
        *[
            _jinja_string("(?=.*(?:^blastwall:|;)v=2(?:;|$))"),
            _jinja_string(f"(?=.*(?:^blastwall:|;)state={re.escape(state)}(?:;|$))"),
            _jinja_string(f"(?=.*(?:^blastwall:|;)target={re.escape(fields['target'])}(?:;|$))"),
            _jinja_string("(?=.*(?:^blastwall:|;)rpm="),
            rpm_expr,
            _jinja_string("(?:;|$))"),
            _jinja_string("(?=.*(?:^blastwall:|;)registry_sha256="),
            registry_expr,
            _jinja_string("(?:;|$))"),
            _jinja_string("(?=.*(?:^blastwall:|;)policy_sha256=[0-9a-f]{64}(?:;|$))"),
            _jinja_string(f"(?=.*(?:^blastwall:|;)profiles={fields['profiles']}(?:;|$))"),
            _jinja_string(f"(?=.*(?:^blastwall:|;)scopes={scope_pattern}(?=;|$))"),
            _jinja_string("blastwall:"),
        ],
    ]
    pattern_expr = " ~ ".join(pattern_parts)
    return (
        f"(([idm_userclass] if idm_userclass is string else idm_userclass) | "
        f"select('match', {pattern_expr}) | list | length) > 0"
    )


def _v3_marker_hint_match_expr(state: str, fields: dict[str, str]) -> str:
    rpm_expr = (
        "(BLASTWALL_REQUIRED_POLICY_MARKER | "
        "default(lookup('env', 'BLASTWALL_REQUIRED_POLICY_MARKER') | "
        f"default({_jinja_string(blastwall_marker.DEFAULT_RPM)}, true), true) | regex_escape)"
    )
    profile_pattern = re.escape(fields["profiles"])
    target_pattern = re.escape(fields["target"])

    pattern_parts = [
        _jinja_string("^"),
        *(_jinja_string(pattern) for pattern in _reserved_field_uniqueness_patterns()),
        *[
            _jinja_string("(?=.*(?:^blastwall:|;)v=3(?:;|$))"),
            _jinja_string(f"(?=.*(?:^blastwall:|;)state={re.escape(state)}(?:;|$))"),
            _jinja_string(f"(?=.*(?:^blastwall:|;)target={target_pattern}(?:;|$))"),
            _jinja_string("(?=.*(?:^blastwall:|;)rpm="),
            rpm_expr,
            _jinja_string("(?:;|$))"),
            _jinja_string(f"(?=.*(?:^blastwall:|;)profiles={profile_pattern}(?:;|$))"),
            _jinja_string(
                "(?=.*(?:^blastwall:|;)attest_ref=(?:service|shared)/"
                "[A-Za-z0-9._@+=:-]+(?:/[A-Za-z0-9._@+=:-]+)+\\.json(?:;|$))"
            ),
            _jinja_string("(?=.*(?:^blastwall:|;)attest_sha256=[0-9a-f]{64}(?:;|$))"),
            _jinja_string("(?=.*(?:^blastwall:|;)signer_kid=[0-9a-f]{40}(?:;|$))"),
            _jinja_string(
                "(?=.*(?:^blastwall:|;)exp=[0-9]{4}-[0-9]{2}-[0-9]{2}T"
                "[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]+)?Z(?:;|$))"
            ),
            _jinja_string("(?=.*(?:^blastwall:|;)generation=[0-9]+(?:;|$))"),
            _jinja_string("blastwall:"),
        ],
    ]
    pattern_expr = " ~ ".join(pattern_parts)
    return (
        f"(([idm_userclass] if idm_userclass is string else idm_userclass) | "
        f"select('match', {pattern_expr}) | list | length) > 0"
    )


def _legacy_v1_match_expr() -> str:
    marker_values = "([idm_userclass] if idm_userclass is string else idm_userclass)"
    marker_list = f"({marker_values} | select('match', '^blastwall:') | list)"
    marker_csv = f"({marker_list} | join(';'))"
    rpm_match = " or ".join(
        f"'rpm={rpm}' in {marker_csv}" for rpm in sorted(blastwall_marker.LEGACY_V1_RPMS)
    )
    lines = [
        "(\n",
        f"        ({rpm_match})",
        "        and",
        f"        ({marker_list} | select('match', '^blastwall:.*rpm_sha256=[0-9a-f]{{64}}.*') | list | length) > 0",
        "        and",
        f"        'state={blastwall_marker.V1_REQUIRED_FLAGS['state']}' in {marker_csv}",
    ]
    for key, value in blastwall_marker.V1_REQUIRED_FLAGS.items():
        if key == "state":
            continue
        lines.extend([ "        and", f"        '{key}={value}' in {marker_csv}" ])
    lines.append("      )")
    return dedent("\n".join(lines))


def _and_block(*lines: str) -> str:
    return dedent("\n".join(lines)).strip()


def _maybe_indent(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(f"{pad}{line}" if line else "" for line in text.splitlines())


def render_profile_group_expressions(registry_path: Path = DEFAULT_REGISTRY) -> Dict[str, str]:
    """Return profile-aware inventory expression fragments derived from profiles.yml."""
    registry = _load_registry(registry_path)
    registry_hash = blastwall_marker.registry_sha256(registry_path)

    v2_base_marker = blastwall_marker.emit_marker_v2(
        registry=registry,
        registry_hash=registry_hash,
        policy_hash="a" * 64,
        rpm=blastwall_marker.DEFAULT_RPM,
        profiles=["base"],
        allow_dry_run_profiles=False,
    )
    v2_strange_marker = blastwall_marker.emit_marker_v2(
        registry=registry,
        registry_hash=registry_hash,
        policy_hash="a" * 64,
        rpm=blastwall_marker.DEFAULT_RPM,
        profiles=["base", DEFAULT_STRANGE_PROFILE],
        allow_dry_run_profiles=True,
    )
    v3_base_marker = blastwall_marker.emit_marker_v3(
        registry=registry,
        rpm=blastwall_marker.DEFAULT_RPM,
        profiles=["base"],
        attest_ref="shared/blastwall-attestation/blastwall-attestations/example/base/1.json",
        attest_sha256="b" * 64,
        signer_kid="c" * 40,
        exp="2099-01-01T00:00:00Z",
        generation=1,
    )
    v3_strange_marker = blastwall_marker.emit_marker_v3(
        registry=registry,
        rpm=blastwall_marker.DEFAULT_RPM,
        profiles=["base", DEFAULT_STRANGE_PROFILE],
        attest_ref="shared/blastwall-attestation/blastwall-attestations/example/base-strange-socket-v1/1.json",
        attest_sha256="b" * 64,
        signer_kid="c" * 40,
        exp="2099-01-01T00:00:00Z",
        generation=1,
        allow_dry_run_profiles=True,
    )

    base_fields = _marker_fields(v2_base_marker)
    strange_fields = _marker_fields(v2_strange_marker)
    v3_base_fields = _marker_fields(v3_base_marker)
    v3_strange_fields = _marker_fields(v3_strange_marker)

    base_match = _maybe_indent(_v2_marker_match_expr("active", base_fields, registry_hash), 6)
    strange_match = _maybe_indent(
        _v2_marker_match_expr(strange_fields["state"], strange_fields, registry_hash),
        6,
    )
    v3_base_match = _maybe_indent(
        _v3_marker_hint_match_expr("active", v3_base_fields),
        6,
    )
    v3_strange_match = _maybe_indent(
        _v3_marker_hint_match_expr(v3_strange_fields["state"], v3_strange_fields),
        6,
    )
    legacy_match = _legacy_v1_match_expr()

    allow_dry_run = (
        "(BLASTWALL_ALLOW_DRY_RUN_PROFILES | "
        "default(lookup('env', 'BLASTWALL_ALLOW_DRY_RUN_PROFILES') | default('false', true), true) | "
        "bool)"
    )
    signed_attestation_mode = (
        "((BLASTWALL_ATTESTATION_MODE | "
        "default(lookup('env', 'BLASTWALL_ATTESTATION_MODE') | default('reference-v2', true), true)) "
        "in ['stable-v3', 'breakglass'])"
    )
    schema_error = _and_block(
        "(",
        "idm_userclass is defined and",
        "(",
        "  idm_userclass is none",
        "  or idm_userclass is mapping",
        "  or (idm_userclass is not string and idm_userclass is not sequence)",
        "  or (",
        "    idm_userclass is sequence",
        "    and idm_userclass is not string",
        "    and (idm_userclass | select('string') | list | length) != (idm_userclass | list | length)",
        "  )",
        ")",
        ")",
        "or",
        "(",
        "  idm_userclass is defined",
        "  and (",
        "    (idm_schema_warnings is defined and (idm_schema_warnings | list | length) > 0 and " + (
            "((idm_userclass is string and idm_userclass is match('^blastwall:')) or "
            "(idm_userclass is sequence and idm_userclass is not string and "
            "(idm_userclass | select('string') | select('match', '^blastwall:') | list | length) > 0))"
        ) + ")",
        "    or (idm_userclass_type is defined and idm_userclass_type not in ['list', 'missing'] and " + (
            "((idm_userclass is string and idm_userclass is match('^blastwall:')) or "
            "(idm_userclass is sequence and idm_userclass is not string and "
            "(idm_userclass | select('string') | select('match', '^blastwall:') | list | length) > 0))"
        ) + ")",
        "  )",
        ")",
    )
    marker_like = (
        "(idm_userclass is string and idm_userclass is match('^blastwall:')) "
        "or (idm_userclass is sequence and idm_userclass is not string and "
        "(idm_userclass | select('string') | select('match', '^blastwall:') | list | length) > 0)"
    )

    reference_current = _and_block(
        "not " + signed_attestation_mode,
        "and",
        "(",
        f"{base_match}",
        "or",
        f"{legacy_match}",
        "or",
        "(",
        f"      {allow_dry_run}",
        "      and",
        f"{strange_match}",
        "    )",
        ")",
    )
    signed_current = _and_block(
        signed_attestation_mode,
        "and",
        "(",
        f"{v3_base_match}",
        "or",
        "(",
        f"      {allow_dry_run}",
        "      and",
        f"{v3_strange_match}",
        "    )",
        ")",
    )

    profile_base = _and_block(
        "idm_userclass is defined and",
        "(",
        f"{reference_current}",
        "or",
        f"{signed_current}",
        ")",
    )

    profile_strange = _and_block(
        "idm_userclass is defined and",
        "(",
        "(",
        f"      not {signed_attestation_mode}",
        "      and",
        f"      {allow_dry_run}",
        "      and",
        f"{strange_match}",
        "    )",
        "or",
        "(",
        f"      {signed_attestation_mode}",
        "      and",
        f"      {allow_dry_run}",
        "      and",
        f"{v3_strange_match}",
        "    )",
        ")",
    )

    profile_current = profile_base

    profile_stale = _and_block(
        "idm_userclass is not defined or not (",
        f"{profile_current}",
        ")",
    )
    marker_parse_error = _and_block(
        "not (",
        f"{schema_error}",
        ")",
        "and",
        "(",
        f"  {marker_like}",
        ")",
        "and",
        "not (",
        f"{profile_current}",
        ")",
    )

    return {
        "blastwall_policy_current": profile_current,
        "blastwall_policy_stale": profile_stale,
        "blastwall_policy_candidate": profile_stale,
        "blastwall_inventory_schema_error": schema_error,
        "blastwall_inventory_marker_parse_error": marker_parse_error,
        "blastwall_profile_base": profile_base,
        "blastwall_profile_strange_socket_v1": profile_strange,
    }


def main() -> int:
    expressions = render_profile_group_expressions()
    for key, value in expressions.items():
        print(f"{key}:")
        print(value)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
