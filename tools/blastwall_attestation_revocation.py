#!/usr/bin/env python3
"""Helpers for attestation marker revocation and tombstone artifacts."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Mapping

import blastwall_marker


DEFAULT_TOMBSTONE_STATUS = "blastwall-attestation-tombstoned"


def marker_to_revoked_marker(
    *,
    marker_text: str,
    registry: Mapping[str, Any] | Path,
    expected_registry_sha256: str,
) -> str:
    """Return a valid v3 revoked marker derived from an existing locator marker."""

    registry_obj = _load_registry(registry)
    parsed = blastwall_marker.parse_marker(
        marker_text,
        registry=registry_obj,
        expected_registry_sha256=expected_registry_sha256,
        accepted_rpms={blastwall_marker.DEFAULT_RPM},
        required_profiles=None,
    )
    if parsed.version != 3:
        raise ValueError("only v3 markers can be revoked through this helper")
    if parsed.errors:
        raise ValueError(f"marker parse rejected for revocation helper: {', '.join(parsed.errors)}")
    if (
        not parsed.attest_ref
        or not parsed.attest_sha256
        or not parsed.signer_kid
        or not parsed.profiles
        or parsed.generation is None
        or parsed.target is None
        or parsed.rpm is None
    ):
        raise ValueError("marker is missing required revocation inputs")
    profiles = sorted(parsed.profiles)
    exp = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return blastwall_marker.emit_marker_v3(
        registry=registry_obj,
        rpm=parsed.rpm,
        profiles=profiles,
        attest_ref=parsed.attest_ref,
        attest_sha256=parsed.attest_sha256,
        signer_kid=parsed.signer_kid,
        exp=exp,
        generation=parsed.generation,
        state="revoked",
        allow_dry_run_profiles=True,
    )


def build_tombstone_payload(
    *,
    status: str = DEFAULT_TOMBSTONE_STATUS,
    reason: str | None = None,
    revoked_at: datetime.datetime | None = None,
) -> dict[str, Any]:
    """Build a tombstone payload for attestation artifact replacement."""

    payload: dict[str, Any] = {
        "status": status,
    }
    if reason:
        payload["reason"] = reason
    payload["revoked_at"] = (revoked_at or datetime.datetime.now(datetime.timezone.utc)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return payload


def build_tombstone_json(
    *,
    status: str = DEFAULT_TOMBSTONE_STATUS,
    reason: str | None = None,
    revoked_at: datetime.datetime | None = None,
) -> str:
    """Return canonical JSON for a tombstone payload."""

    return json.dumps(
        build_tombstone_payload(status=status, reason=reason, revoked_at=revoked_at),
        sort_keys=True,
        separators=(",", ":"),
    )


def _load_registry(registry: Mapping[str, Any] | Path) -> dict[str, Any]:
    if isinstance(registry, Path):
        return blastwall_marker.load_registry(registry)
    if not isinstance(registry, Mapping):
        raise TypeError("registry must be a mapping or Path")
    return dict(registry)
