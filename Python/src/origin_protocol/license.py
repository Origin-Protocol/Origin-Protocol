from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .manifest import ORIGIN_VERSION


@dataclass(frozen=True)
class License:
    license_id: str
    user_id: str
    plan: str
    issued_at: str
    expires_at: str
    features: tuple[str, ...]
    device_fingerprint: str | None = None
    max_devices: int | None = None
    offline_grace_days: int | None = None
    issuer_key_id: str | None = None
    origin_schema: str = "1.0"
    signature_algorithm: str = "ed25519"
    origin_version: str = ORIGIN_VERSION


@dataclass(frozen=True)
class LicenseLedgerEntry:
    license_id: str
    revoked_at: str
    reason: str | None = None
    updated_expires_at: str | None = None
    updated_plan: str | None = None
    updated_features: tuple[str, ...] | None = None
    updated_device_fingerprint: str | None = None


@dataclass(frozen=True)
class LicenseRevocationLedger:
    ledger_id: str
    issuer_id: str
    created_at: str
    entries: tuple[LicenseLedgerEntry, ...]
    origin_schema: str = "1.0"
    signature_algorithm: str = "ed25519"
    origin_version: str = ORIGIN_VERSION


def build_license(
    user_id: str,
    plan: str,
    expires_at: str,
    *,
    features: Iterable[str] | None = None,
    device_fingerprint: str | None = None,
    max_devices: int | None = None,
    offline_grace_days: int | None = None,
    issuer_key_id: str | None = None,
) -> License:
    return License(
        license_id=str(uuid.uuid4()),
        user_id=user_id,
        plan=plan,
        issued_at=datetime.now(timezone.utc).isoformat(),
        expires_at=expires_at,
        features=tuple(features or ()),
        device_fingerprint=device_fingerprint,
        max_devices=max_devices,
        offline_grace_days=offline_grace_days,
        issuer_key_id=issuer_key_id,
    )


def license_to_bytes(license_obj: License) -> bytes:
    payload = {key: value for key, value in asdict(license_obj).items() if value is not None}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def license_from_bytes(data: bytes) -> License:
    payload = json.loads(data)
    return License(
        license_id=payload.get("license_id", str(uuid.uuid4())),
        user_id=payload["user_id"],
        plan=payload["plan"],
        issued_at=payload["issued_at"],
        expires_at=payload["expires_at"],
        features=tuple(payload.get("features", [])),
        device_fingerprint=payload.get("device_fingerprint"),
        max_devices=payload.get("max_devices"),
        offline_grace_days=payload.get("offline_grace_days"),
        issuer_key_id=payload.get("issuer_key_id"),
        origin_schema=payload.get("origin_schema", "1.0"),
        signature_algorithm=payload.get("signature_algorithm", "ed25519"),
        origin_version=payload.get("origin_version", ORIGIN_VERSION),
    )


def sign_license(license_obj: License, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(license_to_bytes(license_obj))


def verify_license(license_obj: License, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(signature, license_to_bytes(license_obj))
        return True
    except Exception:
        return False


def validate_license(
    license_obj: License,
    *,
    now: datetime | None = None,
    device_fingerprint: str | None = None,
) -> list[str]:
    errors: list[str] = []
    now = now or datetime.now(timezone.utc)

    try:
        issued_at = datetime.fromisoformat(license_obj.issued_at)
        if issued_at > now:
            errors.append("license_issued_in_future")
    except ValueError:
        errors.append("license_issued_at_invalid")

    try:
        expires_at = datetime.fromisoformat(license_obj.expires_at)
        if expires_at <= now:
            errors.append("license_expired")
    except ValueError:
        errors.append("license_expires_at_invalid")

    if license_obj.device_fingerprint and device_fingerprint:
        if license_obj.device_fingerprint != device_fingerprint:
            errors.append("license_device_mismatch")

    if license_obj.signature_algorithm != "ed25519":
        errors.append("license_signature_algorithm_unsupported")

    return errors


def build_license_ledger(issuer_id: str) -> LicenseRevocationLedger:
    return LicenseRevocationLedger(
        ledger_id=str(uuid.uuid4()),
        issuer_id=issuer_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        entries=(),
    )


def add_license_ledger_entry(
    ledger: LicenseRevocationLedger,
    entry: LicenseLedgerEntry,
) -> LicenseRevocationLedger:
    return LicenseRevocationLedger(
        ledger_id=ledger.ledger_id,
        issuer_id=ledger.issuer_id,
        created_at=ledger.created_at,
        entries=ledger.entries + (entry,),
        origin_schema=ledger.origin_schema,
        signature_algorithm=ledger.signature_algorithm,
        origin_version=ledger.origin_version,
    )


def license_ledger_to_bytes(ledger: LicenseRevocationLedger) -> bytes:
    payload = asdict(ledger)
    payload["entries"] = [
        {key: value for key, value in asdict(item).items() if value is not None}
        for item in ledger.entries
    ]
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def license_ledger_from_bytes(data: bytes) -> LicenseRevocationLedger:
    payload = json.loads(data)
    entries = tuple(
        LicenseLedgerEntry(
            license_id=item["license_id"],
            revoked_at=item["revoked_at"],
            reason=item.get("reason"),
            updated_expires_at=item.get("updated_expires_at"),
            updated_plan=item.get("updated_plan"),
            updated_features=tuple(item.get("updated_features", [])) or None,
            updated_device_fingerprint=item.get("updated_device_fingerprint"),
        )
        for item in payload.get("entries", [])
    )
    return LicenseRevocationLedger(
        ledger_id=payload.get("ledger_id", str(uuid.uuid4())),
        issuer_id=payload["issuer_id"],
        created_at=payload["created_at"],
        entries=entries,
        origin_schema=payload.get("origin_schema", "1.0"),
        signature_algorithm=payload.get("signature_algorithm", "ed25519"),
        origin_version=payload.get("origin_version", ORIGIN_VERSION),
    )


def sign_license_ledger(ledger: LicenseRevocationLedger, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(license_ledger_to_bytes(ledger))


def verify_license_ledger(
    ledger: LicenseRevocationLedger,
    signature: bytes,
    public_key: Ed25519PublicKey,
) -> bool:
    try:
        public_key.verify(signature, license_ledger_to_bytes(ledger))
        return True
    except Exception:
        return False


def write_license_file(
    license_obj: License,
    signature: bytes,
    public_key_pem: bytes,
    path: Path,
) -> None:
    payload = {
        "license": json.loads(license_to_bytes(license_obj).decode("utf-8")),
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key": public_key_pem.decode("utf-8"),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def read_license_file(path: Path) -> tuple[License, bytes, str]:
    payload = json.loads(path.read_text())
    license_obj = license_from_bytes(json.dumps(payload["license"], sort_keys=True).encode("utf-8"))
    signature = base64.b64decode(payload["signature"])
    public_key = payload["public_key"]
    return license_obj, signature, public_key


def write_license_ledger_file(
    ledger: LicenseRevocationLedger,
    signature: bytes,
    public_key_pem: bytes,
    path: Path,
) -> None:
    payload = {
        "ledger": json.loads(license_ledger_to_bytes(ledger).decode("utf-8")),
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key": public_key_pem.decode("utf-8"),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def read_license_ledger_file(path: Path) -> tuple[LicenseRevocationLedger, bytes, str]:
    payload = json.loads(path.read_text())
    ledger = license_ledger_from_bytes(json.dumps(payload["ledger"], sort_keys=True).encode("utf-8"))
    signature = base64.b64decode(payload["signature"])
    public_key = payload["public_key"]
    return ledger, signature, public_key
