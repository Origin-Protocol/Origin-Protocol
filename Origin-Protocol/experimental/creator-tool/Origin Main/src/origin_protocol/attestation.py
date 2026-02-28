from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .keys import load_public_key_bytes, public_key_fingerprint
from .manifest import ORIGIN_VERSION, hash_bytes


@dataclass(frozen=True)
class CreatorAttestation:
    attestation_id: str
    attestation_type: str
    issuer_id: str
    issuer_key_id: str | None
    subject_creator_id: str
    subject_key_id: str
    subject_public_key: str
    issued_at: str
    not_before: str | None = None
    expires_at: str | None = None
    platform_binding: str | None = None
    usage_constraints: tuple[str, ...] | None = None
    region: str | None = None
    expiration_policy: str | None = None
    purpose: str | None = None
    constraints_hash: str | None = None
    signature_algorithm: str = "ed25519"
    schema_version: str = "1.0"
    origin_version: str = ORIGIN_VERSION


def build_attestation(
    issuer_id: str,
    subject_creator_id: str,
    subject_key_id: str,
    subject_public_key_pem: str,
    issuer_public_key_pem: str | None = None,
    attestation_type: str = "creator_identity",
    attestation_id: str | None = None,
    expires_at: str | None = None,
    not_before: str | None = None,
    platform_binding: str | None = None,
    usage_constraints: Iterable[str] | None = None,
    region: str | None = None,
    expiration_policy: str | None = None,
    purpose: str | None = None,
) -> CreatorAttestation:
    constraints_payload: dict[str, object] = {
        "platform_binding": platform_binding,
        "usage_constraints": sorted(usage_constraints or ()),
        "region": region,
        "expiration_policy": expiration_policy,
        "purpose": purpose,
    }
    constraints_hash = hash_bytes(
        json.dumps(constraints_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return CreatorAttestation(
        attestation_id=attestation_id or str(uuid.uuid4()),
        attestation_type=attestation_type,
        issuer_id=issuer_id,
        issuer_key_id=(
            public_key_fingerprint(load_public_key_bytes(issuer_public_key_pem.encode("utf-8")))
            if issuer_public_key_pem
            else None
        ),
        subject_creator_id=subject_creator_id,
        subject_key_id=subject_key_id,
        subject_public_key=subject_public_key_pem,
        issued_at=datetime.now(timezone.utc).isoformat(),
        not_before=not_before,
        expires_at=expires_at,
        platform_binding=platform_binding,
        usage_constraints=tuple(usage_constraints) if usage_constraints is not None else None,
        region=region,
        expiration_policy=expiration_policy,
        purpose=purpose,
        constraints_hash=constraints_hash,
    )


def attestation_to_bytes(attestation: CreatorAttestation) -> bytes:
    payload = {key: value for key, value in asdict(attestation).items() if value is not None}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def attestation_from_bytes(data: bytes) -> CreatorAttestation:
    payload = json.loads(data)
    return CreatorAttestation(
        attestation_id=payload["attestation_id"],
        attestation_type=payload.get("attestation_type", "creator_identity"),
        issuer_id=payload["issuer_id"],
        issuer_key_id=payload.get("issuer_key_id"),
        subject_creator_id=payload["subject_creator_id"],
        subject_key_id=payload["subject_key_id"],
        subject_public_key=payload["subject_public_key"],
        issued_at=payload["issued_at"],
        not_before=payload.get("not_before"),
        expires_at=payload.get("expires_at"),
        platform_binding=payload.get("platform_binding"),
        usage_constraints=tuple(payload.get("usage_constraints", [])) or None,
        region=payload.get("region"),
        expiration_policy=payload.get("expiration_policy"),
        purpose=payload.get("purpose"),
        constraints_hash=payload.get("constraints_hash"),
        signature_algorithm=payload.get("signature_algorithm", "ed25519"),
        schema_version=payload.get("schema_version", "1.0"),
        origin_version=payload.get("origin_version", ORIGIN_VERSION),
    )


def sign_attestation(attestation: CreatorAttestation, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(attestation_to_bytes(attestation))


def verify_attestation(attestation: CreatorAttestation, signature: bytes, issuer_key: Ed25519PublicKey) -> bool:
    try:
        issuer_key.verify(signature, attestation_to_bytes(attestation))
        return True
    except Exception:
        return False


def write_attestation(attestation: CreatorAttestation, path: Path) -> None:
    payload = {key: value for key, value in asdict(attestation).items() if value is not None}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def read_attestation(path: Path) -> CreatorAttestation:
    return attestation_from_bytes(path.read_bytes())


@dataclass(frozen=True)
class IssuerKey:
    issuer_id: str
    key_id: str
    public_key: str
    valid_from: str
    valid_to: str | None = None


def load_trust_store(path: Path) -> tuple[IssuerKey, ...]:
    payload = json.loads(path.read_text())
    issuer_keys: list[IssuerKey] = []
    for item in payload.get("issuer_keys", []):
        issuer_keys.append(
            IssuerKey(
                issuer_id=item["issuer_id"],
                key_id=item["key_id"],
                public_key=item["public_key"],
                valid_from=item["valid_from"],
                valid_to=item.get("valid_to"),
            )
        )
    return tuple(issuer_keys)


def write_trust_store(path: Path, issuer_keys: Iterable[IssuerKey | str]) -> None:
    normalized: list[IssuerKey] = []
    for key in issuer_keys:
        if isinstance(key, IssuerKey):
            normalized.append(key)
            continue
        public_key_pem = key
        key_id = public_key_fingerprint(load_public_key_bytes(public_key_pem.encode("utf-8")))
        normalized.append(
            IssuerKey(
                issuer_id="unknown",
                key_id=key_id,
                public_key=public_key_pem,
                valid_from=datetime.now(timezone.utc).isoformat(),
                valid_to=None,
            )
        )

    payload: dict[str, list[dict[str, object]]] = {
        "issuer_keys": [
            {
                "issuer_id": key.issuer_id,
                "key_id": key.key_id,
                "public_key": key.public_key,
                "valid_from": key.valid_from,
                "valid_to": key.valid_to,
            }
            for key in normalized
        ]
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def validate_attestation_structure(attestation: CreatorAttestation) -> list[str]:
    errors: list[str] = []
    if not attestation.attestation_id:
        errors.append("attestation_id_missing")
    if not attestation.attestation_type:
        errors.append("attestation_type_missing")
    if not attestation.issuer_id:
        errors.append("issuer_id_missing")
    if not attestation.subject_creator_id:
        errors.append("subject_creator_id_missing")
    if not attestation.subject_key_id:
        errors.append("subject_key_id_missing")
    if not attestation.subject_public_key:
        errors.append("subject_public_key_missing")
    for timestamp in (attestation.issued_at, attestation.not_before, attestation.expires_at):
        if timestamp is None:
            continue
        try:
            datetime.fromisoformat(timestamp)
        except ValueError:
            errors.append("invalid_timestamp")
            break
    if attestation.constraints_hash is None:
        errors.append("constraints_hash_missing")
    return errors
