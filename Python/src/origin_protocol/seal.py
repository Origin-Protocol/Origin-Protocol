from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .manifest import ORIGIN_VERSION, hash_file, hash_bytes


@dataclass(frozen=True)
class Seal:
    media_path: str
    created_at: str
    content_hash: str
    manifest_hash: str
    origin_version: str = ORIGIN_VERSION


def build_seal(file_path: Path, media_path: str, manifest_hash_value: str) -> Seal:
    return Seal(
        media_path=media_path,
        created_at=datetime.now(timezone.utc).isoformat(),
        content_hash=hash_file(file_path),
        manifest_hash=manifest_hash_value,
    )


def seal_to_bytes(seal: Seal) -> bytes:
    payload = asdict(seal)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal_hash(seal: Seal) -> str:
    return hash_bytes(seal_to_bytes(seal))


def seal_from_bytes(data: bytes) -> Seal:
    payload = json.loads(data)
    return Seal(
        media_path=payload["media_path"],
        created_at=payload["created_at"],
        content_hash=payload["content_hash"],
        manifest_hash=payload["manifest_hash"],
        origin_version=payload.get("origin_version", ORIGIN_VERSION),
    )
