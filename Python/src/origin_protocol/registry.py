from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .manifest import ORIGIN_VERSION


@dataclass(frozen=True)
class KeyRecord:
    creator_id: str
    key_id: str
    public_key: str
    status: str
    valid_from: str
    valid_to: str | None = None
    superseded_by: str | None = None


@dataclass(frozen=True)
class KeyRegistry:
    created_at: str
    records: tuple[KeyRecord, ...]
    origin_version: str = ORIGIN_VERSION


def build_registry() -> KeyRegistry:
    return KeyRegistry(
        created_at=datetime.now(timezone.utc).isoformat(),
        records=(),
    )


def add_key_record(registry: KeyRegistry, record: KeyRecord) -> KeyRegistry:
    return KeyRegistry(
        created_at=registry.created_at,
        records=registry.records + (record,),
        origin_version=registry.origin_version,
    )


def revoke_key(registry: KeyRegistry, creator_id: str, key_id: str, superseded_by: str | None = None) -> KeyRegistry:
    updated: list[KeyRecord] = []
    for record in registry.records:
        if record.creator_id == creator_id and record.key_id == key_id:
            updated.append(
                KeyRecord(
                    creator_id=record.creator_id,
                    key_id=record.key_id,
                    public_key=record.public_key,
                    status="revoked",
                    valid_from=record.valid_from,
                    valid_to=datetime.now(timezone.utc).isoformat(),
                    superseded_by=superseded_by,
                )
            )
        else:
            updated.append(record)

    return KeyRegistry(
        created_at=registry.created_at,
        records=tuple(updated),
        origin_version=registry.origin_version,
    )


def registry_to_bytes(registry: KeyRegistry) -> bytes:
    payload = asdict(registry)
    payload["records"] = [
        {key: value for key, value in asdict(item).items() if value is not None}
        for item in registry.records
    ]
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_registry(registry: KeyRegistry, path: Path) -> None:
    payload = asdict(registry)
    payload["records"] = [
        {key: value for key, value in asdict(item).items() if value is not None}
        for item in registry.records
    ]
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def read_registry(path: Path) -> KeyRegistry:
    payload = json.loads(path.read_text())
    records = tuple(
        KeyRecord(
            creator_id=item["creator_id"],
            key_id=item["key_id"],
            public_key=item["public_key"],
            status=item["status"],
            valid_from=item["valid_from"],
            valid_to=item.get("valid_to"),
            superseded_by=item.get("superseded_by"),
        )
        for item in payload.get("records", [])
    )
    return KeyRegistry(
        created_at=payload["created_at"],
        records=records,
        origin_version=payload.get("origin_version", ORIGIN_VERSION),
    )


def find_key_record(registry: KeyRegistry, creator_id: str, key_id: str) -> KeyRecord | None:
    for record in registry.records:
        if record.creator_id == creator_id and record.key_id == key_id:
            return record
    return None


def is_key_active(registry: KeyRegistry, creator_id: str, key_id: str) -> bool:
    record = find_key_record(registry, creator_id, key_id)
    if record is None:
        return False
    return record.status == "active"
