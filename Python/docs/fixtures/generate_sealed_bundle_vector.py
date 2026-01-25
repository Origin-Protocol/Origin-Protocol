from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from zipfile import ZipFile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from origin_protocol.embed import create_sealed_bundle
from origin_protocol.keys import public_key_fingerprint
from origin_protocol.manifest import Manifest, compute_origin_id, hash_file, ORIGIN_VERSION


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    fixture_dir = Path(__file__).parent
    output_zip = fixture_dir / "sealed_bundle_vector.zip"
    output_meta = fixture_dir / "sealed_bundle_vector.json"

    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()
    key_id = public_key_fingerprint(public_key)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        media_path = temp_path / "vector.mp4"
        media_path.write_bytes(b"origin-sealed-vector")

        public_key_path = temp_path / "public_key.ed25519"
        public_key_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        content_hash = hash_file(media_path)
        origin_id = compute_origin_id(key_id, content_hash)
        manifest = Manifest(
            manifest_id="00000000-0000-0000-0000-000000000002",
            origin_schema="1.0",
            creator_id="creator-123",
            asset_id="asset-123",
            origin_id=origin_id,
            created_at="2026-01-15T00:00:00+00:00",
            content_hash=content_hash,
            intended_platforms=("yt", "tt"),
            key_id=key_id,
            signature_algorithm="ed25519",
            origin_version=ORIGIN_VERSION,
        )

        create_sealed_bundle(
            media_path,
            manifest,
            private_key,
            public_key_path,
            output_zip,
            compression=0,  # ZIP_STORED
        )

    zip_hash = _hash_bytes(output_zip.read_bytes())
    entries: list[dict[str, str]] = []
    with ZipFile(output_zip, "r") as bundle:
        for info in sorted(bundle.infolist(), key=lambda item: item.filename):
            data = bundle.read(info.filename)
            entries.append(
                {
                    "path": info.filename,
                    "sha256": _hash_bytes(data),
                }
            )

    payload = {
        "sealed_bundle_path": "docs/fixtures/sealed_bundle_vector.zip",
        "sha256": zip_hash,
        "entries": entries,
        "public_key_pem": public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8"),
        "key_id": key_id,
    }
    output_meta.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print("Sealed bundle vector written to docs/fixtures/")


if __name__ == "__main__":
    main()
