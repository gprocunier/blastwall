#!/usr/bin/env python3
"""Render Blastwall profile-grouping fragments for IdM inventories."""

from __future__ import annotations

import importlib.util
import json
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
    pattern_expr = " ~ ".join(
        [
            _jinja_string(
                f"^blastwall:v=2;state={state};target={fields['target']};rpm="
            ),
            rpm_expr,
            _jinja_string(";registry_sha256="),
            registry_expr,
            _jinja_string(
                ";policy_sha256=[0-9a-f]{64};"
                f"profiles={fields['profiles']};scopes={fields['scopes']}$"
            ),
        ]
    )
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

    base_fields = _marker_fields(v2_base_marker)
    strange_fields = _marker_fields(v2_strange_marker)

    base_match = _maybe_indent(_v2_marker_match_expr("active", base_fields, registry_hash), 6)
    strange_match = _maybe_indent(
        _v2_marker_match_expr(strange_fields["state"], strange_fields, registry_hash),
        6,
    )
    legacy_match = _legacy_v1_match_expr()

    allow_dry_run = (
        "(BLASTWALL_ALLOW_DRY_RUN_PROFILES | "
        "default(lookup('env', 'BLASTWALL_ALLOW_DRY_RUN_PROFILES') | default('false', true), true) | "
        "bool)"
    )
    schema_error = _and_block(
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
    )
    marker_like = (
        "(idm_userclass is string and idm_userclass is match('^blastwall:')) "
        "or (idm_userclass is sequence and idm_userclass is not string and "
        "(idm_userclass | select('string') | select('match', '^blastwall:') | list | length) > 0)"
    )

    profile_base = _and_block(
        "idm_userclass is defined and",
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

    profile_strange = _and_block(
        "idm_userclass is defined and",
        "(",
        f"        {allow_dry_run}",
        "        and",
        f"{strange_match}",
        "    )",
    )

    profile_current = _and_block(
        "idm_userclass is defined and",
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

    profile_stale = _and_block(
        "idm_userclass is not defined or not (",
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
