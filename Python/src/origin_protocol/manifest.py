from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping
import uuid

ORIGIN_VERSION = "0.1"


@dataclass(frozen=True)
class Manifest:
    manifest_id: str
    origin_schema: str
    creator_id: str
    asset_id: str
    created_at: str
    content_hash: str
    intended_platforms: tuple[str, ...]
    key_id: str | None = None
    platform_binding: str | None = None
    region: str | None = None
    usage_constraints: tuple[str, ...] | None = None
    expiration_policy: str | None = None
    media_metadata: Mapping[str, str] | None = None
    signature_algorithm: str = "ed25519"
    origin_version: str = ORIGIN_VERSION


def hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_manifest(
    file_path: Path,
    creator_id: str,
    asset_id: str,
    intended_platforms: Iterable[str] | None = None,
    key_id: str | None = None,
    platform_binding: str | None = None,
    region: str | None = None,
    usage_constraints: Iterable[str] | None = None,
    expiration_policy: str | None = None,
    media_metadata: Mapping[str, str] | None = None,
) -> Manifest:
    created_at = datetime.now(timezone.utc).isoformat()
    content_hash = hash_file(file_path)
    manifest = Manifest(
        manifest_id=str(uuid.uuid4()),
        origin_schema="1.0",
        creator_id=creator_id,
        asset_id=asset_id,
        created_at=created_at,
        content_hash=content_hash,
        intended_platforms=tuple(intended_platforms or ()),
        key_id=key_id,
        platform_binding=platform_binding,
        region=region,
        usage_constraints=tuple(usage_constraints) if usage_constraints is not None else None,
        expiration_policy=expiration_policy,
        media_metadata=media_metadata,
    )
    return manifest


def manifest_to_bytes(manifest: Manifest) -> bytes:
    payload = {key: value for key, value in asdict(manifest).items() if value is not None}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_hash(manifest: Manifest) -> str:
    return hash_bytes(manifest_to_bytes(manifest))


def write_manifest(manifest: Manifest, path: Path) -> None:
    payload = {key: value for key, value in asdict(manifest).items() if value is not None}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def manifest_from_bytes(data: bytes) -> Manifest:
    payload = json.loads(data)
    return Manifest(
        manifest_id=payload.get("manifest_id", str(uuid.uuid4())),
        origin_schema=payload.get("origin_schema", "1.0"),
        creator_id=payload["creator_id"],
        asset_id=payload["asset_id"],
        created_at=payload["created_at"],
        content_hash=payload["content_hash"],
        intended_platforms=tuple(payload.get("intended_platforms", [])),
        key_id=payload.get("key_id"),
        platform_binding=payload.get("platform_binding"),
        region=payload.get("region"),
        usage_constraints=tuple(payload.get("usage_constraints", [])) or None,
        expiration_policy=payload.get("expiration_policy"),
        media_metadata=payload.get("media_metadata"),
        signature_algorithm=payload.get("signature_algorithm", "ed25519"),
        origin_version=payload.get("origin_version", ORIGIN_VERSION),
    )


def validate_manifest(manifest: Manifest) -> list[str]:
    errors: list[str] = []
    if not manifest.manifest_id:
        errors.append("manifest_id_missing")
    if not manifest.origin_schema:
        errors.append("origin_schema_missing")
    if not manifest.creator_id:
        errors.append("creator_id_missing")
    if not manifest.asset_id:
        errors.append("asset_id_missing")
    if not manifest.created_at:
        errors.append("created_at_missing")
    else:
        try:
            datetime.fromisoformat(manifest.created_at)
        except ValueError:
            errors.append("created_at_invalid")
    if not manifest.content_hash:
        errors.append("content_hash_missing")
    if len(manifest.intended_platforms) == 0:
        errors.append("intended_platforms_missing")
    if manifest.signature_algorithm != "ed25519":
        errors.append("signature_algorithm_unsupported")
    return errors


def read_manifest(path: Path) -> Manifest:
    return manifest_from_bytes(path.read_bytes())
