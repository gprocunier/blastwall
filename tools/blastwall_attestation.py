#!/usr/bin/env python3
"""Blastwall v3 attestation schemas, canonical serialization, and crypto checks."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509.oid import ExtensionOID
import jsonschema

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PAYLOAD_SCHEMA_PATH = ROOT / "policy" / "attestation-schema.json"
DEFAULT_ENVELOPE_SCHEMA_PATH = ROOT / "policy" / "attestation-envelope-schema.json"

SUPPORTED_SIGNATURE_ALGORITHM = "sha256-rsa-pkcs1v15"
SUPPORTED_ENVELOPE_VERSION = 1

RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
SKI_HEX_RE = re.compile(r"^[0-9a-f]{40}$")


def normalize_ski(raw: str) -> str:
    """Return lowercase hex SKI and enforce canonical formatting."""

    if not isinstance(raw, str):
        raise TypeError("signer key identifier must be a string")
    normalized = raw.strip().lower()
    if ":" in normalized:
        raise ValueError("signer_kid must not include colons")
    if not SKI_HEX_RE.fullmatch(normalized):
        raise ValueError("signer_kid must be lowercase hex (40 chars)")
    return normalized


def parse_utc_timestamp(value: str) -> datetime.datetime:
    """Parse an RFC3339 UTC timestamp string."""

    if not RFC3339_UTC_RE.fullmatch(value):
        raise ValueError(f"invalid RFC3339 UTC timestamp: {value!r}")
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) != datetime.timedelta(0):
        raise ValueError(f"invalid RFC3339 UTC timestamp: {value!r}")
    return parsed


def _no_duplicates_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate JSON property: {key!r}")
        seen.add(key)
        result[key] = value
    return result


def parse_json_no_duplicates(raw: str) -> Any:
    """Parse JSON and fail when duplicate object keys are present."""

    try:
        return json.loads(raw, object_pairs_hook=_no_duplicates_object_pairs)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc


def canonical_json_bytes(payload: Any) -> bytes:
    """Return RFC 8785-like canonical JSON bytes used for signing."""

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def attestation_payload_sha256(payload: Any) -> str:
    """Return hex SHA-256 over canonical payload bytes."""

    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _load_schema(path: Path) -> Mapping[str, Any]:
    return parse_json_no_duplicates(path.read_text(encoding="utf-8"))


def _validate_schema(value: Any, schema_path: Path) -> None:
    schema = _load_schema(schema_path)
    try:
        jsonschema.validate(instance=value, schema=schema)
    except jsonschema.ValidationError as exc:
        raise ValueError(f"schema validation failed: {exc.message}") from exc


def _validate_payload_window(payload: Mapping[str, Any]) -> None:
    issued_at = parse_utc_timestamp(payload["issued_at"])
    not_before = parse_utc_timestamp(payload["not_before"])
    not_after = parse_utc_timestamp(payload["not_after"])
    if not_before > not_after:
        raise ValueError("not_before must be <= not_after")
    if not (not_before <= issued_at <= not_after):
        raise ValueError("issued_at must be within validity window")


def validate_attestation_payload(payload: Mapping[str, Any]) -> None:
    """Validate an attestation payload against the JSON schema."""

    _validate_schema(payload, DEFAULT_PAYLOAD_SCHEMA_PATH)
    _validate_payload_window(payload)


def validate_attestation_envelope(envelope: Mapping[str, Any]) -> None:
    """Validate an attestation envelope against the JSON schema."""

    if envelope.get("envelope_version") != SUPPORTED_ENVELOPE_VERSION:
        raise ValueError(f"unsupported envelope_version: {envelope.get('envelope_version')!r}")
    _validate_schema(envelope, DEFAULT_ENVELOPE_SCHEMA_PATH)
    if envelope.get("signature_algorithm") != SUPPORTED_SIGNATURE_ALGORITHM:
        raise ValueError(
            f"unsupported signature_algorithm: {envelope.get('signature_algorithm')!r}"
        )


def parse_attestation_payload(raw: str) -> Mapping[str, Any]:
    """Parse attestation payload JSON and validate schema and timestamps."""

    payload = parse_json_no_duplicates(raw)
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a JSON object")
    validate_attestation_payload(payload)
    return payload


def parse_attestation_envelope(raw: str) -> Mapping[str, Any]:
    """Parse attestation envelope JSON and validate schema."""

    envelope = parse_json_no_duplicates(raw)
    if not isinstance(envelope, Mapping):
        raise ValueError("envelope must be a JSON object")
    validate_attestation_envelope(envelope)
    payload = envelope.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be an object")
    validate_attestation_payload(payload)
    return envelope


def extract_signer_kid(certificate: x509.Certificate) -> str:
    """Extract lower-case SKI hex from a certificate."""

    try:
        extension = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    except x509.ExtensionNotFound as exc:
        raise ValueError("certificate missing Subject Key Identifier") from exc
    return normalize_ski(extension.value.digest.hex())


def _load_pem_certificate(value: bytes | str | Path | x509.Certificate) -> x509.Certificate:
    if isinstance(value, x509.Certificate):
        return value
    if isinstance(value, Path):
        value = value.read_bytes()
    if isinstance(value, str):
        value = value.encode("utf-8")
    return x509.load_pem_x509_certificate(value)


def _load_private_key(value: bytes | str | Path):
    if isinstance(value, Path):
        value = value.read_bytes()
    if isinstance(value, str):
        value = value.encode("utf-8")
    return serialization.load_pem_private_key(value, password=None)


def _load_ca_certs(value: bytes | str | Path) -> list[x509.Certificate]:
    if isinstance(value, Path):
        value = value.read_bytes()
    if isinstance(value, str):
        value = value.encode("utf-8")
    certs = x509.load_pem_x509_certificates(value)
    if not certs:
        raise ValueError("no CA certificates were loaded")
    return list(certs)


def _as_aware_utc(value: datetime.datetime) -> datetime.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def _cert_not_valid_before(certificate: x509.Certificate) -> datetime.datetime:
    value = certificate.not_valid_before_utc if hasattr(certificate, "not_valid_before_utc") else certificate.not_valid_before
    return _as_aware_utc(value)


def _cert_not_valid_after(certificate: x509.Certificate) -> datetime.datetime:
    value = certificate.not_valid_after_utc if hasattr(certificate, "not_valid_after_utc") else certificate.not_valid_after
    return _as_aware_utc(value)


def _verify_certificate_chain(
    certificate: x509.Certificate,
    trust_bundle: list[x509.Certificate],
    *,
    now: datetime.datetime,
) -> None:
    for authority in trust_bundle:
        if certificate.issuer != authority.subject:
            continue
        if _cert_not_valid_after(authority) < now:
            continue
        if _cert_not_valid_before(authority) > now:
            continue
        try:
            authority.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        except Exception as exc:
            continue
        return
    raise ValueError("signer certificate is not trusted by configured CA bundle")


def _verify_certificate_active(certificate: x509.Certificate, now: datetime.datetime) -> None:
    not_before = _cert_not_valid_before(certificate)
    not_after = _cert_not_valid_after(certificate)
    if now < not_before:
        raise ValueError("signer certificate is not yet valid")
    if now > not_after:
        raise ValueError("signer certificate has expired")


def sign_payload(
    payload: Mapping[str, Any],
    private_key: bytes | str | Path,
    *,
    signature_algorithm: str = SUPPORTED_SIGNATURE_ALGORITHM,
) -> str:
    """Return base64 signature bytes for canonical payload bytes."""

    if signature_algorithm != SUPPORTED_SIGNATURE_ALGORITHM:
        raise ValueError(f"unsupported signature_algorithm: {signature_algorithm!r}")
    key = _load_private_key(private_key)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("signing key must be RSA")
    signature = key.sign(
        canonical_json_bytes(payload),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def build_attestation_envelope(
    payload: Mapping[str, Any],
    *,
    private_key: bytes | str | Path,
    signer_certificate: x509.Certificate | bytes | str | Path,
    signature_algorithm: str = SUPPORTED_SIGNATURE_ALGORITHM,
) -> dict[str, Any]:
    """Build a signed attestation envelope for a validated payload."""

    validate_attestation_payload(payload)
    signature = sign_payload(
        payload,
        private_key,
        signature_algorithm=signature_algorithm,
    )
    if not isinstance(signer_certificate, x509.Certificate):
        signer_certificate = _load_pem_certificate(signer_certificate)
    signer = signer_certificate
    signer_kid = extract_signer_kid(signer)
    payload_sha = attestation_payload_sha256(payload)
    return {
        "envelope_version": SUPPORTED_ENVELOPE_VERSION,
        "payload": dict(payload),
        "payload_sha256": payload_sha,
        "signature_algorithm": signature_algorithm,
        "signature": signature,
        "signer_kid": signer_kid,
        "signer_certificate_subject": signer.subject.rfc4514_string(),
        "signer_certificate_serial": str(signer.serial_number),
        "created_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }


def attestation_envelope_sha256(envelope: Mapping[str, Any]) -> str:
    """Return SHA-256 over canonical signed-envelope bytes."""

    validate_attestation_envelope(envelope)
    return hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()


def _load_envelope_payload(envelope: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = envelope.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be an object")
    validate_attestation_payload(payload)
    return payload


def verify_attestation_envelope(
    envelope: Mapping[str, Any] | str,
    signer_certificate: bytes | str | Path,
    *,
    ca_bundle: bytes | str | Path,
    signer_allowlist: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Verify payload integrity, signature, and signer identity/issuer trust."""

    now = datetime.datetime.now(datetime.timezone.utc)
    if isinstance(envelope, str):
        envelope_obj = parse_attestation_envelope(envelope)
    elif isinstance(envelope, Mapping):
        envelope_obj = dict(envelope)
        validate_attestation_envelope(envelope_obj)
        payload = envelope_obj.get("payload")
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be an object")
        validate_attestation_payload(payload)
    else:
        raise TypeError("envelope must be a JSON string or mapping")

    payload = _load_envelope_payload(envelope_obj)

    payload_bytes = canonical_json_bytes(payload)
    expected_sha = attestation_payload_sha256(payload)
    if expected_sha != envelope_obj["payload_sha256"]:
        raise ValueError("payload_sha256 does not match canonical payload")

    certificate = _load_pem_certificate(signer_certificate)
    parse_utc_timestamp(envelope_obj["created_at"])

    _verify_certificate_active(certificate, now=now)
    trust_bundle = _load_ca_certs(ca_bundle)
    _verify_certificate_chain(certificate, trust_bundle, now=now)

    signer_kid = extract_signer_kid(certificate)
    if normalize_ski(envelope_obj["signer_kid"]) != signer_kid:
        raise ValueError("envelope signer_kid does not match certificate subject key id")
    if normalize_ski(payload["signer_kid"]) != signer_kid:
        raise ValueError("payload signer_kid does not match certificate subject key id")
    if envelope_obj["signer_certificate_subject"] != certificate.subject.rfc4514_string():
        raise ValueError("envelope signer_certificate_subject does not match certificate subject")
    if str(certificate.serial_number) != envelope_obj["signer_certificate_serial"]:
        raise ValueError("envelope signer_certificate_serial does not match certificate")

    if signer_allowlist is not None:
        allowlist = {normalize_ski(item) for item in signer_allowlist}
        if signer_kid not in allowlist:
            raise ValueError("signer_kid is not allowlisted")

    signature_raw = envelope_obj["signature"]
    try:
        signature = base64.b64decode(signature_raw, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("signature is not valid base64") from exc

    public_key = certificate.public_key()
    if not isinstance(public_key, RSAPublicKey):
        raise ValueError("signer certificate must contain an RSA public key")

    try:
        public_key.verify(
            signature,
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise ValueError("signature verification failed") from exc
    except UnsupportedAlgorithm as exc:
        raise ValueError("unsupported signing algorithm in certificate") from exc

    return {
        "envelope": envelope_obj,
        "payload": payload,
        "payload_bytes": payload_bytes,
        "signer_kid": signer_kid,
    }


__all__ = [
    "SUPPORTED_SIGNATURE_ALGORITHM",
    "SUPPORTED_ENVELOPE_VERSION",
    "canonical_json_bytes",
    "attestation_payload_sha256",
    "parse_json_no_duplicates",
    "parse_utc_timestamp",
    "normalize_ski",
    "validate_attestation_payload",
    "validate_attestation_envelope",
    "parse_attestation_payload",
    "parse_attestation_envelope",
    "extract_signer_kid",
    "sign_payload",
    "build_attestation_envelope",
    "attestation_envelope_sha256",
    "verify_attestation_envelope",
]
