#!/usr/bin/env python3
"""Audit Blastwall inventory grouping and marker health from ansible-inventory JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import blastwall_marker


BLASTWALL_GROUPS = [
    "blastwall_policy_current",
    "blastwall_policy_stale",
    "blastwall_policy_candidate",
    "blastwall_profile_base",
    "blastwall_profile_strange_socket_v1",
    "blastwall_inventory_schema_error",
    "blastwall_inventory_marker_parse_error",
]


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
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    hostvars = _hostvars(inventory)
    host_groups = _host_groups(inventory)
    schema_errors: dict[str, str] = {}
    marker_parse_errors: dict[str, list[str]] = {}
    legacy_v1_hosts: list[str] = []
    dry_run_marker_hosts: list[str] = []

    for host, values in hostvars.items():
        markers, schema_error = _marker_values(values.get("idm_userclass"))
        if schema_error is not None:
            schema_errors[host] = schema_error
        for marker_text in markers:
            parsed = blastwall_marker.parse_marker(
                marker_text,
                registry=registry,
                expected_registry_sha256=expected_registry_sha256,
                expected_target="rhel-login",
                accepted_rpms=accepted_rpms,
                required_profiles=required_profiles,
                allow_dry_run_profiles=allow_dry_run_profiles,
            )
            if parsed.legacy:
                legacy_v1_hosts.append(host)
            if "strange-socket-v1" in parsed.profiles:
                dry_run_marker_hosts.append(host)
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
    current_marker_parse_error_hosts = sorted(current_hosts.intersection(marker_parse_errors))
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
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory-json", type=Path, default=Path("-"))
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--registry", type=Path, default=blastwall_marker.DEFAULT_REGISTRY)
    parser.add_argument("--expected-registry-sha256")
    parser.add_argument("--accepted-rpm", action="append", default=[])
    parser.add_argument("--required-profiles-csv", default="base")
    parser.add_argument("--allow-dry-run-profiles", action="store_true")
    parser.add_argument("--fail-on-current-to-stale", action="store_true")
    parser.add_argument("--fail-on-current-marker-parse-error", action="store_true")
    args = parser.parse_args()

    registry = blastwall_marker.load_registry(args.registry)
    inventory = _load_json(args.inventory_json)
    previous = _load_json(args.previous) if args.previous else None
    accepted_rpms = set(args.accepted_rpm) or {blastwall_marker.DEFAULT_RPM}
    required_profiles = {item for item in args.required_profiles_csv.split(",") if item} or {"base"}
    report = audit_inventory(
        inventory,
        registry=registry,
        expected_registry_sha256=args.expected_registry_sha256 or blastwall_marker.registry_sha256(args.registry),
        allow_dry_run_profiles=args.allow_dry_run_profiles,
        accepted_rpms=accepted_rpms,
        required_profiles=required_profiles,
        previous=previous,
    )
    print(json.dumps(report, sort_keys=True))
    if args.fail_on_current_to_stale and report["current_to_stale"]:
        return 1
    if args.fail_on_current_marker_parse_error and report["current_marker_parse_error_hosts"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
