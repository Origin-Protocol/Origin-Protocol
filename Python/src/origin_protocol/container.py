from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .bundle import bundle_manifest_from_bytes
from .keys import load_public_key_bytes, public_key_fingerprint
from .manifest import hash_bytes, hash_file, manifest_from_bytes, manifest_hash
from .mkv import append_origin_tag, extract_origin_payloads as extract_mkv_payloads
from .mp4 import ORIGIN_UUID, insert_uuid_box, extract_uuid_payloads
from .seal import seal_from_bytes, seal_hash

ORIGIN_PAYLOAD_SCHEMA = "1.0"


@dataclass(frozen=True)
class SidecarPayload:
    bundle_manifest: bytes
    bundle_signature: bytes
    manifest: bytes
    manifest_signature: bytes
    seal: bytes
    seal_signature: bytes
    public_key: bytes


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _payload_bytes_for_signature(payload: dict[str, object], signature_field: str) -> bytes:
    signature_payload = dict(payload)
    signature_payload.pop(signature_field, None)
    return json.dumps(signature_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _attach_container_signature(
    payload: dict[str, object],
    signature_field: str,
    private_key: Ed25519PrivateKey,
) -> None:
    signature_bytes = _payload_bytes_for_signature(payload, signature_field)
    signature = private_key.sign(signature_bytes)
    payload[signature_field] = {
        "algorithm": "ed25519",
        "key_id": payload.get("key_id"),
        "signature": _b64encode(signature),
    }


def _load_bundle_payload(bundle_path: Path) -> SidecarPayload:
    from zipfile import ZipFile

    with ZipFile(bundle_path, "r") as bundle:
        return SidecarPayload(
            bundle_manifest=bundle.read("bundle.json"),
            bundle_signature=bundle.read("bundle.sig"),
            manifest=bundle.read("manifest.json"),
            manifest_signature=bundle.read("signature.ed25519"),
            seal=bundle.read("seal.json"),
            seal_signature=bundle.read("seal.ed25519"),
            public_key=bundle.read("public_key.ed25519"),
        )


def _build_origin_payload(
    bundle_path: Path,
    *,
    signature_field: str | None = None,
    signing_key: Ed25519PrivateKey | None = None,
) -> dict[str, object]:
    payload = _load_bundle_payload(bundle_path)
    manifest = manifest_from_bytes(payload.manifest)
    seal = seal_from_bytes(payload.seal)
    key_id = manifest.key_id
    if key_id is None:
        key_id = public_key_fingerprint(load_public_key_bytes(payload.public_key))

    payload_dict: dict[str, object] = {
        "origin_schema": ORIGIN_PAYLOAD_SCHEMA,
        "origin_uuid": ORIGIN_UUID,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "nonce": str(uuid.uuid4()),
        "bundle_hash": hash_file(bundle_path),
        "manifest_hash": manifest_hash(manifest),
        "seal_hash": seal_hash(seal),
        "media_hash": seal.content_hash,
        "key_id": key_id,
        "payload": {
            "bundle.json": _b64encode(payload.bundle_manifest),
            "bundle.sig": _b64encode(payload.bundle_signature),
            "manifest.json": _b64encode(payload.manifest),
            "signature.ed25519": _b64encode(payload.manifest_signature),
            "seal.json": _b64encode(payload.seal),
            "seal.ed25519": _b64encode(payload.seal_signature),
            "public_key.ed25519": _b64encode(payload.public_key),
        },
        "attestation_ref": None,
        "registry_ref": None,
        "revocation_ref": None,
    }
    if signature_field and signing_key:
        _attach_container_signature(payload_dict, signature_field, signing_key)
    return payload_dict


def build_sidecar_from_bundle(bundle_path: Path, media_path: Path, output_path: Path) -> Path:
    if not bundle_path.exists():
        raise FileNotFoundError(bundle_path)
    if not media_path.exists():
        raise FileNotFoundError(media_path)

    sidecar = _build_origin_payload(bundle_path)
    sidecar["media_filename"] = media_path.name

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sidecar, indent=2, sort_keys=True))
    return output_path


def build_payload_from_bundle(bundle_path: Path) -> dict[str, str]:
    from zipfile import ZipFile

    with ZipFile(bundle_path, "r") as bundle:
        payload = {
            "bundle.json": _b64encode(bundle.read("bundle.json")),
            "bundle.sig": _b64encode(bundle.read("bundle.sig")),
            "manifest.json": _b64encode(bundle.read("manifest.json")),
            "signature.ed25519": _b64encode(bundle.read("signature.ed25519")),
            "seal.json": _b64encode(bundle.read("seal.json")),
            "seal.ed25519": _b64encode(bundle.read("seal.ed25519")),
            "public_key.ed25519": _b64encode(bundle.read("public_key.ed25519")),
        }
    return payload


def write_payload_file(bundle_path: Path, output_path: Path) -> Path:
    payload_bytes = build_payload_json_bytes(bundle_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload_bytes)
    return output_path


def build_payload_json_bytes(
    bundle_path: Path,
    *,
    signature_field: str | None = None,
    signing_key: Ed25519PrivateKey | None = None,
) -> bytes:
    payload = _build_origin_payload(
        bundle_path,
        signature_field=signature_field,
        signing_key=signing_key,
    )
    payload = {key: value for key, value in payload.items() if value is not None}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_sidecar(path: Path) -> Mapping[str, object]:
    return json.loads(path.read_text())


def _load_payload_json(payload_bytes: bytes) -> dict[str, object] | None:
    try:
        return json.loads(payload_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return None


def _verify_signature(data: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False


def _decode_bundle_signature(
    signature_bytes: bytes,
    *,
    expected_key_id: str | None = None,
) -> tuple[bytes | None, str | None]:
    try:
        payload = json.loads(signature_bytes)
    except json.JSONDecodeError:
        return signature_bytes, None
    if not isinstance(payload, dict):
        return None, "bundle_manifest_invalid"
    algorithm = payload.get("algorithm")
    key_id = payload.get("key_id")
    signature_b64 = payload.get("signature")
    if algorithm and algorithm != "ed25519":
        return None, "bundle_manifest_invalid"
    if expected_key_id and key_id and key_id != expected_key_id:
        return None, "key_id_mismatch"
    if not isinstance(signature_b64, str):
        return None, "bundle_manifest_invalid"
    try:
        return _b64decode(signature_b64), None
    except Exception:
        return None, "bundle_manifest_invalid"


def _require_fields(payload: Mapping[str, object], fields: tuple[str, ...]) -> bool:
    return all(field in payload for field in fields)


def _parse_created_at(value: object) -> datetime | None:
    if value is None:
        return None
    try:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _pick_latest_payload(candidates: list[bytes]) -> bytes | None:
    best_payload = None
    best_created_at: datetime | None = None
    for payload_bytes in candidates:
        payload = _load_payload_json(payload_bytes)
        if payload is None:
            continue
        created_at = _parse_created_at(payload.get("created_at"))
        if created_at is None:
            continue
        if best_created_at is None or created_at > best_created_at:
            best_created_at = created_at
            best_payload = payload_bytes
    return best_payload


def validate_origin_payload(payload_bytes: bytes, *, fast_fail: bool = False) -> list[str]:
    errors: list[str] = []
    payload = _load_payload_json(payload_bytes)
    if payload is None:
        return ["payload_invalid_json"]

    def _push(code: str) -> bool:
        errors.append(code)
        return fast_fail

    required = (
        "origin_schema",
        "origin_uuid",
        "created_at",
        "nonce",
        "bundle_hash",
        "manifest_hash",
        "seal_hash",
        "media_hash",
        "key_id",
        "payload",
    )
    if not _require_fields(payload, required):
        errors.append("payload_missing_field")
        return errors
    if payload.get("origin_schema") != ORIGIN_PAYLOAD_SCHEMA:
        if _push("origin_schema_mismatch"):
            return errors
    if payload.get("origin_uuid") != ORIGIN_UUID:
        if _push("origin_uuid_mismatch"):
            return errors
    created_at = payload.get("created_at")
    if created_at is None:
        if _push("payload_missing_created_at"):
            return errors
    elif _parse_created_at(created_at) is None:
        if _push("payload_created_at_invalid"):
            return errors
    if not isinstance(payload.get("payload"), dict):
        if _push("payload_missing_payload"):
            return errors

    payload_map = payload.get("payload")
    if not isinstance(payload_map, dict):
        return errors
    payload_map_cast = cast(dict[str, object], payload_map)
    payload_map_cast = {key: str(value) for key, value in payload_map_cast.items()}
    required_payload_fields = (
        "bundle.json",
        "bundle.sig",
        "manifest.json",
        "signature.ed25519",
        "seal.json",
        "seal.ed25519",
        "public_key.ed25519",
    )
    if not _require_fields(payload_map_cast, required_payload_fields):
        errors.append("payload_missing_field")
        return errors

    try:
        bundle_manifest_bytes = _b64decode(payload_map_cast["bundle.json"])
        bundle_sig = _b64decode(payload_map_cast["bundle.sig"])
        manifest_bytes = _b64decode(payload_map_cast["manifest.json"])
        manifest_sig = _b64decode(payload_map_cast["signature.ed25519"])
        seal_bytes = _b64decode(payload_map_cast["seal.json"])
        seal_sig = _b64decode(payload_map_cast["seal.ed25519"])
        public_key_bytes = _b64decode(payload_map_cast["public_key.ed25519"])
    except Exception:
        errors.append("payload_invalid_encoding")
        return errors

    public_key = load_public_key_bytes(public_key_bytes)
    bundle_key_id = public_key_fingerprint(public_key)
    decoded_sig, sig_error = _decode_bundle_signature(bundle_sig, expected_key_id=bundle_key_id)
    if sig_error:
        if _push(sig_error):
            return errors
    if decoded_sig is None:
        if _push("bundle_manifest_invalid"):
            return errors
    elif not _verify_signature(bundle_manifest_bytes, decoded_sig, public_key):
        if _push("bundle_manifest_invalid"):
            return errors

    bundle_manifest = bundle_manifest_from_bytes(bundle_manifest_bytes)
    entries = {entry.path: entry.sha256 for entry in bundle_manifest.entries}
    expected = {
        "manifest.json": manifest_bytes,
        "signature.ed25519": manifest_sig,
        "public_key.ed25519": public_key_bytes,
        "seal.json": seal_bytes,
        "seal.ed25519": seal_sig,
    }
    for path, content in expected.items():
        if path not in entries:
            if _push("bundle_contents_mismatch"):
                return errors
            break
        if hash_bytes(content) != entries[path]:
            if _push("bundle_hash_mismatch"):
                return errors
            break

    manifest = manifest_from_bytes(manifest_bytes)
    if not _verify_signature(manifest_bytes, manifest_sig, public_key):
        if _push("signature_invalid"):
            return errors

    seal = seal_from_bytes(seal_bytes)
    if not _verify_signature(seal_bytes, seal_sig, public_key):
        if _push("seal_invalid"):
            return errors

    if manifest_hash(manifest) != seal.manifest_hash:
        if _push("bundle_manifest_invalid"):
            return errors
    if manifest.content_hash != seal.content_hash:
        if _push("content_hash_mismatch"):
            return errors

    if payload.get("manifest_hash") != manifest_hash(manifest):
        if _push("manifest_hash_mismatch"):
            return errors
    if payload.get("seal_hash") != seal_hash(seal):
        if _push("seal_hash_mismatch"):
            return errors
    if payload.get("media_hash") != seal.content_hash:
        if _push("content_hash_mismatch"):
            return errors

    key_id = manifest.key_id or public_key_fingerprint(public_key)
    if payload.get("key_id") != key_id:
        if _push("key_id_mismatch"):
            return errors

    signature_fields = ["box_signature", "tag_signature", "container_signature"]
    for signature_field in signature_fields:
        signature_payload = payload.get(signature_field)
        if signature_payload is None:
            continue
        if not isinstance(signature_payload, dict):
            if _push("container_signature_invalid"):
                return errors
            continue
        signature_payload_cast = cast(dict[str, object], signature_payload)
        algorithm = signature_payload_cast.get("algorithm")
        sig_key_id = signature_payload_cast.get("key_id")
        signature_b64 = signature_payload_cast.get("signature")
        if algorithm != "ed25519" or sig_key_id != key_id or not isinstance(signature_b64, str):
            if _push("container_signature_invalid"):
                return errors
            continue
        try:
            signature_bytes = _b64decode(signature_b64)
            signed_bytes = _payload_bytes_for_signature(payload, signature_field)
            public_key.verify(signature_bytes, signed_bytes)
        except Exception:
            if _push("container_signature_invalid"):
                return errors

    return errors


def extract_origin_payload(media_path: Path, sidecar_path: Path | None = None) -> bytes | None:
    if sidecar_path is not None and sidecar_path.exists():
        sidecar = _load_sidecar(sidecar_path)
        payload_bytes = json.dumps(sidecar, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if validate_origin_payload(payload_bytes, fast_fail=True) == []:
            return payload_bytes

    if media_path.suffix.lower() == ".json":
        sidecar = _load_sidecar(media_path)
        payload_bytes = json.dumps(sidecar, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if validate_origin_payload(payload_bytes, fast_fail=True) == []:
            return payload_bytes

    suffix = media_path.suffix.lower()
    if suffix in {".mp4", ".mov"}:
        payloads = [payload.payload for payload in extract_uuid_payloads(media_path)]
        valid_payloads = [payload for payload in payloads if validate_origin_payload(payload, fast_fail=True) == []]
        return _pick_latest_payload(valid_payloads)
    if suffix in {".mkv"}:
        payloads = [payload.payload for payload in extract_mkv_payloads(media_path)]
        valid_payloads = [payload for payload in payloads if validate_origin_payload(payload, fast_fail=True) == []]
        return _pick_latest_payload(valid_payloads)
    return None


def verify_sidecar(media_path: Path, sidecar_path: Path, public_key: Ed25519PublicKey | None = None) -> tuple[bool, str | None]:
    if not media_path.exists():
        raise FileNotFoundError(media_path)
    if not sidecar_path.exists():
        raise FileNotFoundError(sidecar_path)

    sidecar = _load_sidecar(sidecar_path)
    required_fields = (
        "origin_schema",
        "origin_uuid",
        "created_at",
        "nonce",
        "bundle_hash",
        "manifest_hash",
        "seal_hash",
        "media_hash",
        "key_id",
        "payload",
    )
    if not _require_fields(sidecar, required_fields):
        return False, "sidecar_missing_field"
    if sidecar.get("origin_schema") != ORIGIN_PAYLOAD_SCHEMA:
        return False, "origin_schema_mismatch"
    if sidecar.get("origin_uuid") != ORIGIN_UUID:
        return False, "origin_uuid_mismatch"

    payload_raw = sidecar.get("payload")
    if not isinstance(payload_raw, dict):
        return False, "sidecar_missing_field"
    payload_raw_cast = cast(dict[str, object], payload_raw)
    payload: dict[str, str] = {key: str(value) for key, value in payload_raw_cast.items()}
    required_payload_fields = (
        "bundle.json",
        "bundle.sig",
        "manifest.json",
        "signature.ed25519",
        "seal.json",
        "seal.ed25519",
        "public_key.ed25519",
    )
    if not _require_fields(payload, required_payload_fields):
        return False, "sidecar_missing_field"

    try:
        bundle_manifest_bytes = _b64decode(payload["bundle.json"])
        bundle_sig = _b64decode(payload["bundle.sig"])
        manifest_bytes = _b64decode(payload["manifest.json"])
        manifest_sig = _b64decode(payload["signature.ed25519"])
        seal_bytes = _b64decode(payload["seal.json"])
        seal_sig = _b64decode(payload["seal.ed25519"])
        public_key_bytes = _b64decode(payload["public_key.ed25519"])
    except Exception:
        return False, "sidecar_payload_invalid"

    if public_key is None:
        public_key = load_public_key_bytes(public_key_bytes)

    bundle_key_id = public_key_fingerprint(public_key)
    decoded_sig, sig_error = _decode_bundle_signature(bundle_sig, expected_key_id=bundle_key_id)
    if sig_error:
        return False, sig_error
    if decoded_sig is None:
        return False, "bundle_manifest_invalid"
    if not _verify_signature(bundle_manifest_bytes, decoded_sig, public_key):
        return False, "bundle_manifest_invalid"

    bundle_manifest = bundle_manifest_from_bytes(bundle_manifest_bytes)
    entries = {entry.path: entry.sha256 for entry in bundle_manifest.entries}
    expected = {
        "manifest.json": manifest_bytes,
        "signature.ed25519": manifest_sig,
        "public_key.ed25519": public_key_bytes,
        "seal.json": seal_bytes,
        "seal.ed25519": seal_sig,
    }

    for path, content in expected.items():
        if path not in entries:
            return False, "bundle_contents_mismatch"
        from .manifest import hash_bytes

        if hash_bytes(content) != entries[path]:
            return False, "bundle_hash_mismatch"

    manifest = manifest_from_bytes(manifest_bytes)
    if not manifest.origin_version:
        return False, "manifest_origin_version_missing"
    if not _verify_signature(manifest_bytes, manifest_sig, public_key):
        return False, "signature_invalid"

    if not _verify_signature(seal_bytes, seal_sig, public_key):
        return False, "seal_invalid"

    seal = seal_from_bytes(seal_bytes)
    if not seal.origin_version:
        return False, "seal_origin_version_missing"
    media_hash = hash_file(media_path)
    if media_hash != seal.content_hash:
        return False, "content_hash_mismatch"

    if manifest_hash(manifest) != seal.manifest_hash:
        return False, "bundle_manifest_invalid"

    if manifest.content_hash != seal.content_hash:
        return False, "content_hash_mismatch"

    if manifest.key_id and str(sidecar.get("key_id")) != manifest.key_id:
        return False, "key_id_mismatch"

    if sidecar.get("manifest_hash") != manifest_hash(manifest):
        return False, "manifest_hash_mismatch"
    if sidecar.get("seal_hash") != seal_hash(seal):
        return False, "seal_hash_mismatch"
    if sidecar.get("media_hash") != seal.content_hash:
        return False, "content_hash_mismatch"
    if sidecar.get("origin_uuid") != ORIGIN_UUID:
        return False, "origin_uuid_mismatch"

    media_filename = sidecar.get("media_filename")
    if media_filename:
        if str(media_filename) != media_path.name:
            return False, "sidecar_media_filename_mismatch"
        if Path(seal.media_path).name != str(media_filename):
            return False, "sidecar_media_filename_mismatch"

    return True, None


def embed_payload(
    bundle_path: Path,
    media_path: Path,
    output_path: Path,
    format_name: str,
    *,
    signing_key: Ed25519PrivateKey | None = None,
) -> Path:
    format_name = format_name.lower()
    if format_name == "sidecar":
        return build_sidecar_from_bundle(bundle_path, media_path, output_path)
    if format_name in {"mp4", "mov", "mkv"}:
        signature_field = "box_signature" if format_name in {"mp4", "mov"} else "tag_signature"
        payload_bytes = build_payload_json_bytes(
            bundle_path,
            signature_field=signature_field,
            signing_key=signing_key,
        )
        if format_name in {"mp4", "mov"}:
            return insert_uuid_box(media_path, output_path, payload_bytes)
        return append_origin_tag(media_path, output_path, payload_bytes)
    raise ValueError(f"Unsupported container format: {format_name}")
