#!/usr/bin/env python3
"""KRA-aware IdM vault helpers for Blastwall signed-attestation helpers.

This module intentionally focuses on explicit vault-server targeting. No DNS
discovery paths are used; callers must supply a concrete vault server.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Iterable, Mapping


class VaultErrorType(str, Enum):
    """Structured vault failure classification."""

    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    CONNECTION_REFUSED = "connection_refused"
    AUTH_FAILURE = "auth_failure"
    PROXY_ERROR = "proxy_error"
    UNKNOWN = "unknown"


DEFAULT_VAULT_SCOPE = "service"
DEFAULT_VAULT_OWNER = "blastwall-attestation"
DEFAULT_RETRY_NOT_FOUND = True
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_RETRY_DELAY_SECONDS = 10


@dataclass(frozen=True)
class VaultCommandResult:
    """Low-level vault command execution result."""

    stdout: bytes
    stderr: bytes
    returncode: int


@dataclass(frozen=True)
class VaultConfig:
    """Explicit vault topology and retry configuration."""

    primary: str
    servers: tuple[str, ...]
    scope: str = DEFAULT_VAULT_SCOPE
    owner: str = DEFAULT_VAULT_OWNER
    retry_not_found: bool = DEFAULT_RETRY_NOT_FOUND
    retry_attempts: int = DEFAULT_RETRY_ATTEMPTS
    retry_delay_seconds: int = DEFAULT_RETRY_DELAY_SECONDS

    def __post_init__(self) -> None:
        if not self.primary:
            raise ValueError("blastwall_attestation_vault_primary must be set")
        if not self.servers:
            raise ValueError("blastwall_attestation_vault_servers must be a non-empty list")
        if self.primary not in self.servers:
            raise ValueError("blastwall_attestation_vault_primary must be listed in blastwall_attestation_vault_servers")
        if self.retry_attempts < 1:
            raise ValueError("blastwall_attestation_vault_retry_attempts must be >= 1")
        if self.retry_delay_seconds < 0:
            raise ValueError("blastwall_attestation_vault_retry_delay_seconds must be >= 0")
        if not self.scope:
            raise ValueError("blastwall_attestation_vault_scope must be set")
        if not self.owner:
            raise ValueError("blastwall_attestation_vault_owner must be set")

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "VaultConfig":
        """Build config from an Ansible/Jinja-like mapping."""

        servers = values.get("blastwall_attestation_vault_servers")
        normalized_servers = _normalize_server_list(servers)
        return cls(
            primary=str(values.get("blastwall_attestation_vault_primary", "")),
            servers=tuple(normalized_servers),
            scope=str(values.get("blastwall_attestation_vault_scope", DEFAULT_VAULT_SCOPE)),
            owner=str(values.get("blastwall_attestation_vault_owner", DEFAULT_VAULT_OWNER)),
            retry_not_found=_coerce_bool(values.get("blastwall_attestation_vault_retry_not_found", DEFAULT_RETRY_NOT_FOUND)),
            retry_attempts=int(values.get("blastwall_attestation_vault_retry_attempts", DEFAULT_RETRY_ATTEMPTS)),
            retry_delay_seconds=int(values.get("blastwall_attestation_vault_retry_delay_seconds", DEFAULT_RETRY_DELAY_SECONDS)),
        )


def _normalize_server_list(value: Any) -> list[str]:
    """Normalize vault server input into a de-duplicated ordered host list."""

    if value is None:
        raise ValueError("blastwall_attestation_vault_servers must be configured explicitly")

    if isinstance(value, str):
        items = [item.strip() for item in value.split(",") if item.strip()]
    elif isinstance(value, (list, tuple, set)):
        items = [str(item).strip() for item in value if str(item).strip()]
    else:
        raise TypeError("blastwall_attestation_vault_servers must be string or list")

    deduped: list[str] = []
    for item in items:
        if item not in deduped:
            deduped.append(item)
    return deduped


@dataclass
class VaultErrorContext:
    server: str
    vault_ref: str
    vault_error_type: VaultErrorType
    message: str
    command: list[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    attempts: int = 1
    retry_attempted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "vault_server": self.server,
            "vault_ref": self.vault_ref,
            "vault_error_type": self.vault_error_type.value,
            "message": self.message,
            "command": " ".join(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "attempts": self.attempts,
            "retry_attempted": self.retry_attempted,
        }


class VaultCommandError(RuntimeError):
    """Raised when a vault command fails with structured context."""

    def __init__(self, context: VaultErrorContext) -> None:
        super().__init__(context.message)
        self.context = context


@dataclass(frozen=True)
class VaultWriteResult:
    server: str
    vault_ref: str
    digest: str
    attempts: int
    retry_attempted: bool


@dataclass(frozen=True)
class VaultReadResult:
    server: str
    vault_ref: str
    payload: bytes
    digest: str
    attempts: int
    retry_attempted: bool


class VaultReadbackDigestMismatch(ValueError):
    """Raised when readback digest does not match write digest."""

    def __init__(self, expected: str, observed: str) -> None:
        super().__init__(f"vault payload digest mismatch: expected={expected}, observed={observed}")
        self.expected = expected
        self.observed = observed


def _decode_text(value: str | bytes) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def classify_vault_error(
    *,
    returncode: int | None = None,
    stdout: str | bytes | None = None,
    stderr: str | bytes | None = None,
    error: BaseException | None = None,
) -> VaultErrorType:
    """Classify failures from vault command execution."""

    if error is not None:
        if isinstance(error, subprocess.TimeoutExpired):
            return VaultErrorType.TIMEOUT
        if isinstance(error, OSError) and getattr(error, "errno", None) == errno.ECONNREFUSED:
            return VaultErrorType.CONNECTION_REFUSED
        details = _textify(error)
    else:
        details = ""

    combined = (details + " " + _decode_text(stdout or "") + " " + _decode_text(stderr or "")).lower()

    if "timeout" in combined:
        return VaultErrorType.TIMEOUT
    if "connection refused" in combined:
        return VaultErrorType.CONNECTION_REFUSED
    if _contains_keyword(combined, ["auth", "authenticate", "permission denied", "krb", "invalid credentials"]):
        return VaultErrorType.AUTH_FAILURE
    if _contains_keyword(combined, ["proxy", "x509", "gateway", "502", "503", "not able to connect through"]):
        return VaultErrorType.PROXY_ERROR
    if _contains_keyword(combined, ["not found", "no such", "404", "missing", "cannot find"]):
        return VaultErrorType.NOT_FOUND

    if returncode is not None and returncode not in (0,):
        if returncode in (1, 2):
            return VaultErrorType.AUTH_FAILURE
        if returncode == 255:
            return VaultErrorType.CONNECTION_REFUSED
        return VaultErrorType.UNKNOWN

    return VaultErrorType.UNKNOWN


def _textify(value: BaseException) -> str:
    if isinstance(value, subprocess.CalledProcessError):
        if value.output is None and value.stderr is None:
            return str(value)
        return f"{value.output!s} {value.stderr!s}"
    return str(value)


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _contains_keyword(value: str, keywords: Iterable[str]) -> bool:
    return any(keyword in value for keyword in keywords)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _run_command(
    command: list[str],
    input_data: bytes | None = None,
    *,
    timeout: int | None = None,
) -> VaultCommandResult:
    if command and command[0] == "blastwall-ipa-vault":
        return _run_ipa_vault_command(command, input_data=input_data, timeout=timeout)

    completed = subprocess.run(
        command,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    return VaultCommandResult(
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
    )


def _run_ipa_vault_command(
    command: list[str],
    *,
    input_data: bytes | None,
    timeout: int | None,
) -> VaultCommandResult:
    operation, server, scope, owner, vault_ref = _parse_logical_vault_command(command)
    if operation == "write":
        if input_data is None:
            input_data = b""
        return _ipa_vault_write(
            server=server,
            scope=scope,
            owner=owner,
            vault_ref=vault_ref,
            payload=input_data,
            timeout=timeout,
        )
    if operation == "read":
        return _ipa_vault_read(
            server=server,
            scope=scope,
            owner=owner,
            vault_ref=vault_ref,
            timeout=timeout,
        )
    raise ValueError(f"unsupported logical vault operation: {operation}")


def _parse_logical_vault_command(command: list[str]) -> tuple[str, str, str, str, str]:
    if len(command) < 3:
        raise ValueError("invalid blastwall vault command")
    operation = command[1]
    try:
        server = command[command.index("--server") + 1]
        scope = command[command.index("--scope") + 1]
        owner = command[command.index("--owner") + 1]
        vault_ref = command[command.index("--vault-ref") + 1]
    except (ValueError, IndexError) as exc:
        raise ValueError("blastwall vault command missing required argument") from exc
    return operation, server, scope, owner, vault_ref


def _ipa_base_command(server: str) -> list[str]:
    return ["ipa", "-e", f"server={server}", "-f", "-n"]


def _ipa_scope_args(scope: str, owner: str) -> list[str]:
    normalized = scope.strip().lower()
    if normalized == "shared":
        return ["--shared"]
    if normalized == "user":
        return ["--user", owner]
    if normalized == "service":
        return ["--service", owner]
    raise ValueError("vault scope must be one of shared, user, or service")


def _vault_name_from_ref(vault_ref: str) -> str:
    digest = hashlib.sha256(vault_ref.encode("utf-8")).hexdigest()[:48]
    return f"blastwall-{digest}"


def _run_ipa(command: list[str], *, timeout: int | None = None) -> VaultCommandResult:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    return VaultCommandResult(
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
    )


def _ipa_vault_write(
    *,
    server: str,
    scope: str,
    owner: str,
    vault_ref: str,
    payload: bytes,
    timeout: int | None,
) -> VaultCommandResult:
    vault_name = _vault_name_from_ref(vault_ref)
    scope_args = _ipa_scope_args(scope, owner)
    add_command = _ipa_base_command(server) + ["vault-add", vault_name, "--type=standard"] + scope_args
    add_result = _run_ipa(add_command, timeout=timeout)
    add_details = (_decode_text(add_result.stdout) + " " + _decode_text(add_result.stderr)).lower()
    if add_result.returncode != 0 and "already exists" not in add_details:
        return add_result

    payload_path = ""
    try:
        with tempfile.NamedTemporaryFile(prefix="blastwall-vault-payload-", delete=False) as payload_file:
            payload_file.write(payload)
            payload_path = payload_file.name
        archive_command = _ipa_base_command(server) + [
            "vault-archive",
            vault_name,
            "--in",
            payload_path,
        ] + scope_args
        return _run_ipa(archive_command, timeout=timeout)
    finally:
        if payload_path:
            try:
                os.unlink(payload_path)
            except FileNotFoundError:
                pass


def _ipa_vault_read(
    *,
    server: str,
    scope: str,
    owner: str,
    vault_ref: str,
    timeout: int | None,
) -> VaultCommandResult:
    vault_name = _vault_name_from_ref(vault_ref)
    scope_args = _ipa_scope_args(scope, owner)
    output_path = ""
    try:
        with tempfile.NamedTemporaryFile(prefix="blastwall-vault-read-", delete=False) as output_file:
            output_path = output_file.name
        retrieve_command = _ipa_base_command(server) + [
            "vault-retrieve",
            vault_name,
            "--out",
            output_path,
        ] + scope_args
        result = _run_ipa(retrieve_command, timeout=timeout)
        if result.returncode != 0:
            return result
        with open(output_path, "rb") as payload_file:
            payload = payload_file.read()
        return VaultCommandResult(stdout=payload, stderr=result.stderr, returncode=0)
    finally:
        if output_path:
            try:
                os.unlink(output_path)
            except FileNotFoundError:
                pass


def vault_write_command(
    *, server: str, scope: str, owner: str, vault_ref: str
) -> list[str]:
    """Build an explicit-vault-write command."""

    return [
        "blastwall-ipa-vault",
        "write",
        "--server",
        server,
        "--scope",
        scope,
        "--owner",
        owner,
        "--vault-ref",
        vault_ref,
    ]


def vault_read_command(
    *, server: str, scope: str, owner: str, vault_ref: str
) -> list[str]:
    """Build an explicit-vault-read command."""

    return [
        "blastwall-ipa-vault",
        "read",
        "--server",
        server,
        "--scope",
        scope,
        "--owner",
        owner,
        "--vault-ref",
        vault_ref,
    ]


def _is_retryable(error_type: VaultErrorType, *, config: VaultConfig) -> bool:
    if error_type == VaultErrorType.NOT_FOUND:
        return config.retry_not_found
    return error_type in {VaultErrorType.TIMEOUT, VaultErrorType.CONNECTION_REFUSED, VaultErrorType.PROXY_ERROR}


CommandRunner = Callable[[list[str], bytes | None], VaultCommandResult]


def _perform_vault_readwrite(
    *,
    command: list[str],
    config: VaultConfig,
    server: str,
    vault_ref: str,
    input_data: bytes | None,
    command_runner: Callable[[list[str], bytes | None], VaultCommandResult],
    operation_name: str,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[VaultCommandResult, int, bool]:
    attempts = 0
    retry_attempted = False

    while True:
        attempts += 1
        try:
            result = command_runner(command, input_data)
        except BaseException as exc:  # noqa: BLE001 - keep raw subprocess exceptions as failure context.
            error_type = classify_vault_error(error=exc)
            if _is_retryable(error_type, config=config) and attempts < config.retry_attempts:
                retry_attempted = True
                sleep(config.retry_delay_seconds)
                continue
            context = VaultErrorContext(
                server=server,
                vault_ref=vault_ref,
                vault_error_type=error_type,
                message=_decode_text(str(exc)),
                command=command,
                attempts=attempts,
                retry_attempted=retry_attempted,
            )
            raise VaultCommandError(context) from exc
        if result.returncode == 0:
            return result, attempts, retry_attempted

        error_type = classify_vault_error(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
        if _is_retryable(error_type, config=config) and attempts < config.retry_attempts:
            retry_attempted = True
            sleep(config.retry_delay_seconds)
            continue

        context = VaultErrorContext(
            server=server,
            vault_ref=vault_ref,
            vault_error_type=error_type,
            message=f"vault {operation_name} failed: rc={result.returncode}",
            command=command,
            returncode=result.returncode,
            stdout=_decode_text(result.stdout),
            stderr=_decode_text(result.stderr),
            attempts=attempts,
            retry_attempted=retry_attempted,
        )
        raise VaultCommandError(context)


def write_vault_artifact(
    *,
    server: str,
    config: VaultConfig,
    vault_ref: str,
    payload: str | bytes,
    command_runner: Callable[[list[str], bytes | None], VaultCommandResult] = _run_command,
) -> VaultWriteResult:
    """Write an attestation artifact to an explicitly-addressed KRA server."""

    if not server:
        raise ValueError("vault server is required")

    payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
    digest = _sha256(payload_bytes)
    command = vault_write_command(
        server=server,
        scope=config.scope,
        owner=config.owner,
        vault_ref=vault_ref,
    )
    _, attempts, retry_attempted = _perform_vault_readwrite(
        command=command,
        config=config,
        server=server,
        vault_ref=vault_ref,
        input_data=payload_bytes,
        command_runner=command_runner,
        operation_name="write",
    )
    return VaultWriteResult(
        server=server,
        vault_ref=vault_ref,
        digest=digest,
        attempts=attempts,
        retry_attempted=retry_attempted,
    )


def read_vault_artifact(
    *,
    server: str,
    config: VaultConfig,
    vault_ref: str,
    command_runner: Callable[[list[str], bytes | None], VaultCommandResult] = _run_command,
) -> VaultReadResult:
    """Read an attestation artifact from an explicitly-addressed KRA server."""

    if not server:
        raise ValueError("vault server is required")

    command = vault_read_command(
        server=server,
        scope=config.scope,
        owner=config.owner,
        vault_ref=vault_ref,
    )
    result, attempts, retry_attempted = _perform_vault_readwrite(
        command=command,
        config=config,
        server=server,
        vault_ref=vault_ref,
        input_data=None,
        command_runner=command_runner,
        operation_name="read",
    )

    payload = _extract_payload(result.stdout)
    return VaultReadResult(
        server=server,
        vault_ref=vault_ref,
        payload=payload,
        digest=_sha256(payload),
        attempts=attempts,
        retry_attempted=retry_attempted,
    )


def _extract_payload(raw: bytes) -> bytes:
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return raw
    if isinstance(envelope, dict) and isinstance(envelope.get("payload"), str):
        return envelope["payload"].encode("utf-8")
    if isinstance(envelope, dict) and isinstance(envelope.get("data"), str):
        return envelope["data"].encode("utf-8")
    return raw


def read_vault_artifact_with_digest(
    *,
    server: str,
    config: VaultConfig,
    vault_ref: str,
    expected_digest: str,
    command_runner: Callable[[list[str], bytes | None], VaultCommandResult] = _run_command,
) -> VaultReadResult:
    """Read artifact and verify readback digest."""

    result = read_vault_artifact(
        server=server,
        config=config,
        vault_ref=vault_ref,
        command_runner=command_runner,
    )
    if result.digest != expected_digest:
        raise VaultReadbackDigestMismatch(expected=expected_digest.lower(), observed=result.digest)
    return result


def build_vault_ref(*, scope: str, owner: str, kind: str, host: str, profile: str, generation: int | None = None) -> str:
    """Build a deterministic vault reference path."""

    parts = [scope, owner, kind, host, profile]
    if generation is None:
        return "/".join(parts) + ".json"
    return "/".join(parts + [f"{generation}.json"])
