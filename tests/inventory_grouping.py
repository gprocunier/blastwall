#!/usr/bin/env python3
"""Validate Blastwall profile-aware marker grouping semantics."""

from pathlib import Path
import importlib.util
import json
import re
import sys
from jinja2 import Environment


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "inventory-policy-markers.json"
MARKER_PATH = ROOT / "tools" / "blastwall_marker.py"
RENDER_INVENTORY_GROUPS = ROOT / "tools" / "render_inventory_profile_groups.py"

spec = importlib.util.spec_from_file_location("blastwall_marker", MARKER_PATH)
marker = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["blastwall_marker"] = marker
spec.loader.exec_module(marker)

renderer_spec = importlib.util.spec_from_file_location(
    "render_inventory_profile_groups",
    RENDER_INVENTORY_GROUPS,
)
renderer = importlib.util.module_from_spec(renderer_spec)
assert renderer_spec.loader is not None
sys.modules["render_inventory_profile_groups"] = renderer
renderer_spec.loader.exec_module(renderer)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def jinja_bool_filter(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def build_inventory_environment(allow_dry_run_profiles: bool) -> Environment:
    env = Environment()
    env.filters["bool"] = jinja_bool_filter
    env.filters["regex_escape"] = re.escape
    env.tests["match"] = lambda value, pattern: re.match(pattern, str(value or "")) is not None

    def lookup(kind: str, name: str) -> str:
        if kind != "env":
            return ""
        values = {
            "BLASTWALL_ALLOW_DRY_RUN_PROFILES": "true" if allow_dry_run_profiles else "false",
            "BLASTWALL_PROFILE_REGISTRY_SHA256": registry_hash,
            "BLASTWALL_REQUIRED_POLICY_MARKER": marker.DEFAULT_RPM,
        }
        return values.get(name, "")

    env.globals["lookup"] = lookup
    return env


def substitute_placeholders(value, registry_hash: str, policy_hash: str):
    if isinstance(value, str):
        return value.replace("{REGISTRY_SHA256}", registry_hash).replace("{POLICY_SHA256}", policy_hash)
    if isinstance(value, list):
        return [substitute_placeholders(item, registry_hash, policy_hash) for item in value]
    if isinstance(value, dict):
        return {
            key: substitute_placeholders(item, registry_hash, policy_hash)
            for key, item in value.items()
        }
    return value


registry = marker.load_registry()
registry_hash = marker.registry_sha256()
policy_hash = "a" * 64
fixture = substitute_placeholders(
    json.loads(FIXTURE.read_text(encoding="utf-8")),
    registry_hash,
    policy_hash,
)

mode_expected = fixture["expected"]
modes = (
    ("default", False),
    ("allow_dry_run", True),
)

actual = {
    mode: {
        "blastwall_policy_current": [],
        "blastwall_policy_stale": [],
        "blastwall_profile_base": [],
        "blastwall_profile_strange_socket_v1": [],
    }
    for mode, _ in modes
}

for mode, allow_dry_run in modes:
    for host in fixture["hosts"]:
        if "description" in host:
            fail("fixture host entries should use idm_userclass, not description")
        markers = host.get("idm_userclass", [])
        if isinstance(markers, str):
            markers = [markers]
        parsed = [
            marker.parse_marker(
                raw,
                registry=registry,
                expected_registry_sha256=registry_hash,
                required_profiles={"base"},
                allow_dry_run_profiles=allow_dry_run,
            )
            for raw in markers
            if isinstance(raw, str) and raw.startswith("blastwall:")
        ]
        current = any(result.suitable and "base" in result.profiles for result in parsed)
        group = "blastwall_policy_current" if current else "blastwall_policy_stale"
        actual[mode][group].append(host["name"])
        if current:
            actual[mode]["blastwall_profile_base"].append(host["name"])
            if any(result.suitable and "strange-socket-v1" in result.profiles for result in parsed):
                actual[mode]["blastwall_profile_strange_socket_v1"].append(host["name"])

rendered_group_expressions = renderer.render_profile_group_expressions()
inventory_actual = {
    mode: {
        "blastwall_policy_current": [],
        "blastwall_policy_stale": [],
        "blastwall_profile_base": [],
        "blastwall_profile_strange_socket_v1": [],
    }
    for mode, _ in modes
}

for mode, allow_dry_run in modes:
    env = build_inventory_environment(allow_dry_run)
    compiled = {
        group: env.compile_expression(rendered_group_expressions[group])
        for group in inventory_actual[mode]
    }
    for host in fixture["hosts"]:
        context = {"idm_fqdn": host["name"]}
        if "idm_userclass" in host:
            host_markers = host.get("idm_userclass", [])
            if isinstance(host_markers, str):
                host_markers = [host_markers]
            context["idm_userclass"] = host_markers
        for group, expression in compiled.items():
            if bool(expression(**context)):
                inventory_actual[mode][group].append(host["name"])

host_names = {host["name"] for host in fixture["hosts"]}

if actual != mode_expected:
    print("FAIL: inventory policy marker grouping mismatch", file=sys.stderr)
    print(json.dumps({"actual": actual, "expected": mode_expected}, indent=2), file=sys.stderr)
    raise SystemExit(1)

if inventory_actual != mode_expected:
    print("FAIL: rendered inventory group expression mismatch", file=sys.stderr)
    print(
        json.dumps({"actual": inventory_actual, "expected": mode_expected}, indent=2),
        file=sys.stderr,
    )
    raise SystemExit(1)

for mode in ("default", "allow_dry_run"):
    current = set(actual[mode]["blastwall_policy_current"])
    stale = set(actual[mode]["blastwall_policy_stale"])
    intersect = current.intersection(stale)
    if intersect:
        fail(f"{mode} mode: current and stale overlap on {sorted(intersect)}")
    if current | stale != host_names:
        missing = sorted(host_names - (current | stale))
        extra = sorted((current | stale) - host_names)
        fail(f"{mode} mode: current+stale partition mismatch (missing={missing}, extra={extra})")

    for profile_group in ("blastwall_profile_base", "blastwall_profile_strange_socket_v1"):
        profile_hosts = set(actual[mode][profile_group])
        if not profile_hosts.issubset(current):
            fail(f"{mode} mode: {profile_group} is not subset of current: {sorted(profile_hosts - current)}")

allow_dry_run_mode = "allow_dry_run"
canonical_strange_host = "v2-strange-socket-lab-active.example.com"
if canonical_strange_host not in actual[allow_dry_run_mode]["blastwall_profile_base"]:
    fail(
        "allow_dry_run mode: canonical strange-socket host must remain in blastwall_profile_base"
    )
if canonical_strange_host not in actual[allow_dry_run_mode]["blastwall_profile_strange_socket_v1"]:
    fail(
        "allow_dry_run mode: canonical strange-socket host must be selected for "
        "blastwall_profile_strange_socket_v1"
    )

print("PASS: inventory marker grouping selects profile-compatible current and stale hosts")
