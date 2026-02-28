from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .bundle import bundle_manifest_from_bytes
from .keys import public_key_fingerprint
from .manifest import Manifest, hash_bytes, manifest_hash, manifest_to_bytes, manifest_from_bytes, read_manifest
from .seal import seal_from_bytes, seal_hash

SUPPORTED_BUNDLE_SCHEMAS = {"1.0"}


def _parse_datetime(value: str) -> datetime | None:
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


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
        return base64.b64decode(signature_b64.encode("ascii")), None
    except Exception:
        return None, "bundle_manifest_invalid"


def verify_manifest(manifest: Manifest, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(signature, manifest_to_bytes(manifest))
        return True
    except Exception:
        return False


def verify_bundle(bundle_dir: Path, public_key: Ed25519PublicKey | None = None) -> tuple[bool, Manifest]:
    manifest_path = bundle_dir / "manifest.json"
    signature_path = bundle_dir / "signature.ed25519"
    public_key_path = bundle_dir / "public_key.ed25519"
    if not manifest_path.exists():
        raise FileNotFoundError(manifest_path)

    manifest = read_manifest(manifest_path)

    if not signature_path.exists():
        return False, manifest
    signature = signature_path.read_bytes()

    if public_key is None:
        if not public_key_path.exists():
            return False, manifest
        from .keys import load_public_key

        public_key = load_public_key(public_key_path)

    return verify_manifest(manifest, signature, public_key), manifest


def verify_seal(seal_bytes: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(signature, seal_bytes)
        return True
    except Exception:
        return False


def verify_sealed_bundle(
    bundle_path: Path,
    public_key: Ed25519PublicKey | None = None,
    *,
    strict: bool = True,
) -> tuple[bool, Manifest]:
    ok, manifest, _ = verify_sealed_bundle_detailed(bundle_path, public_key=public_key, strict=strict)
    return ok, manifest


def verify_sealed_bundle_detailed(
    bundle_path: Path,
    public_key: Ed25519PublicKey | None = None,
    *,
    strict: bool = True,
) -> tuple[bool, Manifest, str | None]:
    manifest = Manifest(
        manifest_id="unknown",
        origin_schema="1.0",
        creator_id="unknown",
        asset_id="unknown",
        origin_id=None,
        created_at=datetime.now(timezone.utc).isoformat(),
        content_hash="",
        intended_platforms=(),
        key_id=None,
        signature_algorithm="ed25519",
        origin_version="0.0",
    )

    def _fail(reason: str) -> tuple[bool, Manifest, str]:
        return False, manifest, reason

    with ZipFile(bundle_path, "r") as bundle:
        try:
            bundle_manifest_bytes = bundle.read("bundle.json")
        except KeyError:
            return _fail("bundle_manifest_missing")
        try:
            bundle_sig = bundle.read("bundle.sig")
        except KeyError:
            return _fail("bundle_signature_missing")
        try:
            manifest_bytes = bundle.read("manifest.json")
            manifest_sig = bundle.read("signature.ed25519")
            seal_bytes = bundle.read("seal.json")
            seal_sig = bundle.read("seal.ed25519")
        except KeyError:
            return _fail("bundle_contents_mismatch")

        manifest = manifest_from_bytes(manifest_bytes)

        if public_key is None:
            from .keys import load_public_key_bytes

            public_key = load_public_key_bytes(bundle.read("public_key.ed25519"))

        key_id = manifest.key_id or public_key_fingerprint(public_key)
        decoded_sig, sig_error = _decode_bundle_signature(bundle_sig, expected_key_id=key_id)
        if sig_error:
            return _fail(sig_error)
        if decoded_sig is None:
            return _fail("bundle_manifest_invalid")
        try:
            public_key.verify(decoded_sig, bundle_manifest_bytes)
        except Exception:
            return _fail("bundle_manifest_invalid")

        bundle_manifest = bundle_manifest_from_bytes(bundle_manifest_bytes)
        if bundle_manifest.origin_schema not in SUPPORTED_BUNDLE_SCHEMAS:
            return _fail("bundle_manifest_invalid")
        if bundle_manifest.signature_algorithm != "ed25519":
            return _fail("bundle_manifest_invalid")
        if bundle_manifest.signature_metadata:
            for label in ("bundle", "manifest", "seal"):
                info = bundle_manifest.signature_metadata.get(label)
                if info is None:
                    continue
                if not isinstance(info, dict):
                    return _fail("bundle_manifest_invalid")
                algorithm = info.get("algorithm")
                sig_key_id = info.get("key_id")
                if algorithm and algorithm != "ed25519":
                    return _fail("bundle_manifest_invalid")
                if sig_key_id and key_id and sig_key_id != key_id:
                    return _fail("key_id_mismatch")
        if strict and (
            not bundle_manifest.manifest_hash
            or not bundle_manifest.seal_hash
            or not bundle_manifest.media_hash
        ):
            return _fail("bundle_manifest_invalid")

        expected_paths = {entry.path for entry in bundle_manifest.entries}
        actual_paths = set(bundle.namelist()) - {"bundle.json", "bundle.sig"}
        if expected_paths != actual_paths:
            return _fail("bundle_contents_mismatch")

        for entry in bundle_manifest.entries:
            if hash_bytes(bundle.read(entry.path)) != entry.sha256:
                return _fail("bundle_hash_mismatch")

        if not verify_manifest(manifest, manifest_sig, public_key):
            return _fail("signature_invalid")

        if not verify_seal(seal_bytes, seal_sig, public_key):
            return _fail("seal_invalid")

        seal = seal_from_bytes(seal_bytes)
        manifest_created_at = _parse_datetime(manifest.created_at)
        if manifest_created_at is None:
            return _fail("manifest_created_at_invalid")
        seal_created_at = _parse_datetime(seal.created_at)
        if seal_created_at is None:
            return _fail("seal_timestamp_invalid")
        bundle_created_at = _parse_datetime(bundle_manifest.created_at)
        if bundle_created_at is None:
            return _fail("bundle_manifest_invalid")
        if seal_created_at < manifest_created_at:
            return _fail("seal_timestamp_invalid")
        if bundle_created_at < manifest_created_at:
            return _fail("bundle_manifest_invalid")

        media_path = PurePosixPath(seal.media_path)
        if media_path.is_absolute() or ".." in media_path.parts or not media_path.as_posix().startswith("media/"):
            return _fail("bundle_media_path_invalid")

        if seal.media_path not in expected_paths:
            return _fail("bundle_media_missing")

        if manifest.key_id:
            if len(manifest.key_id) != 64 or any(ch not in "0123456789abcdef" for ch in manifest.key_id.lower()):
                return _fail("key_id_mismatch")

        media_bytes = bundle.read(seal.media_path)
        media_hash = hash_bytes(media_bytes)

        if media_hash != seal.content_hash:
            return _fail("content_hash_mismatch")
        if manifest_hash(manifest) != seal.manifest_hash:
            return _fail("bundle_manifest_invalid")
        if manifest.content_hash != seal.content_hash:
            return _fail("content_hash_mismatch")
        if bundle_manifest.manifest_hash and bundle_manifest.manifest_hash != manifest_hash(manifest):
            return _fail("bundle_manifest_invalid")
        if bundle_manifest.seal_hash and bundle_manifest.seal_hash != seal_hash(seal):
            return _fail("bundle_manifest_invalid")
        if bundle_manifest.media_hash and bundle_manifest.media_hash != seal.content_hash:
            return _fail("content_hash_mismatch")

        return True, manifest, None
