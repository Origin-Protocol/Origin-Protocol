from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .manifest import Manifest, ORIGIN_VERSION


@dataclass(frozen=True)
class RevocationEntry:
    creator_id: str
    revoked_at: str
    asset_id: str | None = None
    content_hash: str | None = None
    key_id: str | None = None
    reason: str | None = None
    revocation_type: str | None = None
    scope: str | None = None
    valid_before: str | None = None
    platform: str | None = None
    region: str | None = None
    entry_signature: str | None = None


@dataclass(frozen=True)
class RevocationList:
    issuer_creator_id: str
    created_at: str
    entries: tuple[RevocationEntry, ...]
    issuer_public_key: str | None = None
    issuer_role: str | None = None
    sequence_number: int | None = None
    attestation_ref: str | None = None
    registry_ref: str | None = None
    origin_schema: str = "1.0"
    origin_version: str = ORIGIN_VERSION


def build_revocation_list(
    issuer_creator_id: str,
    *,
    issuer_public_key: str | None = None,
    issuer_role: str | None = "creator",
    sequence_number: int | None = 1,
    attestation_ref: str | None = None,
    registry_ref: str | None = None,
) -> RevocationList:
    return RevocationList(
        created_at=datetime.now(timezone.utc).isoformat(),
        entries=(),
        issuer_creator_id=issuer_creator_id,
        issuer_public_key=issuer_public_key,
        issuer_role=issuer_role,
        sequence_number=sequence_number,
        attestation_ref=attestation_ref,
        registry_ref=registry_ref,
    )


def add_revocation_entry(listing: RevocationList, entry: RevocationEntry) -> RevocationList:
    return RevocationList(
        created_at=listing.created_at,
        entries=listing.entries + (entry,),
        issuer_creator_id=listing.issuer_creator_id,
        issuer_public_key=listing.issuer_public_key,
        issuer_role=listing.issuer_role,
        sequence_number=listing.sequence_number,
        attestation_ref=listing.attestation_ref,
        registry_ref=listing.registry_ref,
        origin_schema=listing.origin_schema,
        origin_version=listing.origin_version,
    )


def revocation_list_to_bytes(listing: RevocationList) -> bytes:
    payload = asdict(listing)
    payload["entries"] = [
        {key: value for key, value in asdict(item).items() if value is not None}
        for item in listing.entries
    ]
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_revocation_list(listing: RevocationList, path: Path) -> None:
    payload = asdict(listing)
    payload["entries"] = [
        {key: value for key, value in asdict(item).items() if value is not None}
        for item in listing.entries
    ]
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def read_revocation_list(path: Path) -> RevocationList:
    payload = json.loads(path.read_text())
    entries = tuple(
        RevocationEntry(
            creator_id=item["creator_id"],
            revoked_at=item["revoked_at"],
            asset_id=item.get("asset_id"),
            content_hash=item.get("content_hash"),
            key_id=item.get("key_id"),
            reason=item.get("reason"),
            revocation_type=item.get("revocation_type"),
            scope=item.get("scope"),
            valid_before=item.get("valid_before"),
            platform=item.get("platform"),
            region=item.get("region"),
            entry_signature=item.get("entry_signature"),
        )
        for item in payload.get("entries", [])
    )
    return RevocationList(
        created_at=payload["created_at"],
        entries=entries,
        issuer_creator_id=payload["issuer_creator_id"],
        issuer_public_key=payload.get("issuer_public_key"),
        issuer_role=payload.get("issuer_role"),
        sequence_number=payload.get("sequence_number"),
        attestation_ref=payload.get("attestation_ref"),
        registry_ref=payload.get("registry_ref"),
        origin_schema=payload.get("origin_schema", "1.0"),
        origin_version=payload.get("origin_version", ORIGIN_VERSION),
    )


def sign_revocation_list(listing: RevocationList, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(revocation_list_to_bytes(listing))


def verify_revocation_list(
    listing: RevocationList,
    signature: bytes,
    public_key: Ed25519PublicKey,
) -> bool:
    try:
        public_key.verify(signature, revocation_list_to_bytes(listing))
        return True
    except Exception:
        return False


def is_revoked(manifest: Manifest, listing: RevocationList) -> bool:
    return len(find_revocations(manifest, listing)) > 0


def find_revocations(
    manifest: Manifest,
    listing: RevocationList,
    *,
    platform: str | None = None,
    region: str | None = None,
) -> tuple[RevocationEntry, ...]:
    matches: list[RevocationEntry] = []
    for entry in listing.entries:
        if entry.creator_id != manifest.creator_id:
            continue

        if entry.platform and platform and entry.platform != platform:
            continue
        if entry.region and region and entry.region != region:
            continue

        if entry.valid_before:
            try:
                valid_before = datetime.fromisoformat(entry.valid_before)
                manifest_created = datetime.fromisoformat(manifest.created_at)
                if manifest_created < valid_before:
                    matches.append(entry)
                    continue
            except ValueError:
                pass

        if entry.scope == "creator" and entry.asset_id is None and entry.content_hash is None and entry.key_id is None:
            matches.append(entry)
            continue

        matched = False
        scope = (entry.scope or "").lower()
        if entry.asset_id and entry.asset_id == manifest.asset_id:
            matched = True
        if entry.content_hash and entry.content_hash == manifest.content_hash:
            matched = True
        if scope in {"", "key"} and entry.key_id and entry.key_id == manifest.key_id:
            matched = True

        if matched:
            matches.append(entry)

    return tuple(matches)
