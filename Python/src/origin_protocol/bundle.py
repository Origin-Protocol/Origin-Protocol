from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping
import uuid

from .manifest import ORIGIN_VERSION, hash_bytes


@dataclass(frozen=True)
class BundleEntry:
    path: str
    sha256: str


@dataclass(frozen=True)
class BundleManifest:
    bundle_id: str
    origin_schema: str
    bundle_type: str
    bundle_version: str
    created_at: str
    entries: tuple[BundleEntry, ...]
    signature_metadata: Mapping[str, Mapping[str, str]] | None = None
    manifest_hash: str | None = None
    seal_hash: str | None = None
    media_hash: str | None = None
    proof_chain: Mapping[str, str] | None = None
    media_summary: Mapping[str, str] | None = None
    signature_algorithm: str = "ed25519"
    canonical_order: str = "path-asc"
    canonicalization: str = "json_sorted_utf8"
    origin_version: str = ORIGIN_VERSION


def build_bundle_manifest(
    files: Iterable[tuple[str, bytes]],
    *,
    bundle_type: str = "sealed",
    manifest_hash_value: str | None = None,
    seal_hash_value: str | None = None,
    media_hash_value: str | None = None,
    proof_chain: Mapping[str, str] | None = None,
    media_summary: Mapping[str, str] | None = None,
) -> BundleManifest:
    entries = tuple(
        BundleEntry(path=path, sha256=hash_bytes(content))
        for path, content in sorted(files, key=lambda item: item[0])
    )
    return build_bundle_manifest_from_entries(
        entries,
        bundle_type=bundle_type,
        manifest_hash_value=manifest_hash_value,
        seal_hash_value=seal_hash_value,
        media_hash_value=media_hash_value,
        proof_chain=proof_chain,
        media_summary=media_summary,
    )


def build_bundle_manifest_from_entries(
    entries: Iterable[BundleEntry],
    *,
    bundle_type: str = "sealed",
    signature_metadata: Mapping[str, Mapping[str, str]] | None = None,
    manifest_hash_value: str | None = None,
    seal_hash_value: str | None = None,
    media_hash_value: str | None = None,
    proof_chain: Mapping[str, str] | None = None,
    media_summary: Mapping[str, str] | None = None,
) -> BundleManifest:
    return BundleManifest(
        bundle_id=str(uuid.uuid4()),
        origin_schema="1.0",
        bundle_type=bundle_type,
        bundle_version="1.0",
        created_at=datetime.now(timezone.utc).isoformat(),
        entries=tuple(entries),
        signature_metadata=signature_metadata,
        manifest_hash=manifest_hash_value,
        seal_hash=seal_hash_value,
        media_hash=media_hash_value,
        proof_chain=proof_chain,
        media_summary=media_summary,
    )


def bundle_manifest_to_bytes(manifest: BundleManifest) -> bytes:
    payload = asdict(manifest)
    payload["entries"] = [asdict(entry) for entry in manifest.entries]
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def bundle_manifest_from_bytes(data: bytes) -> BundleManifest:
    payload = json.loads(data)
    entries = tuple(BundleEntry(path=item["path"], sha256=item["sha256"]) for item in payload.get("entries", []))
    return BundleManifest(
        bundle_id=payload.get("bundle_id", str(uuid.uuid4())),
        origin_schema=payload.get("origin_schema", "1.0"),
        bundle_type=payload.get("bundle_type", "sealed"),
        bundle_version=payload.get("bundle_version", "1.0"),
        created_at=payload["created_at"],
        entries=entries,
        signature_metadata=payload.get("signature_metadata"),
        manifest_hash=payload.get("manifest_hash"),
        seal_hash=payload.get("seal_hash"),
        media_hash=payload.get("media_hash"),
        proof_chain=payload.get("proof_chain"),
        media_summary=payload.get("media_summary"),
        signature_algorithm=payload.get("signature_algorithm", "ed25519"),
        canonical_order=payload.get("canonical_order", "path-asc"),
        canonicalization=payload.get("canonicalization", "json_sorted_utf8"),
        origin_version=payload.get("origin_version", ORIGIN_VERSION),
    )
