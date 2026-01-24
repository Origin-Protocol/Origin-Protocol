import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from origin_protocol.container import build_payload_from_bundle, build_payload_json_bytes
from origin_protocol.embed import create_sealed_bundle
from origin_protocol.keys import generate_keypair, public_key_fingerprint, save_keypair
from origin_protocol.manifest import build_manifest


class CanonicalizationTests(unittest.TestCase):
    def test_bundle_manifest_entries_sorted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            media_path = temp_path / "sample.mp4"
            media_path.write_bytes(b"origin-protocol-canon")

            keypair = generate_keypair()
            _, public_path = save_keypair(keypair, temp_path)
            key_id = public_key_fingerprint(keypair.public_key)

            manifest = build_manifest(
                file_path=media_path,
                creator_id="creator-1",
                asset_id="asset-1",
                intended_platforms=(),
                key_id=key_id,
            )
            bundle_path = temp_path / "bundle.zip"
            create_sealed_bundle(media_path, manifest, keypair.private_key, public_path, bundle_path)

            from zipfile import ZipFile

            with ZipFile(bundle_path, "r") as bundle:
                bundle_manifest = bundle.read("bundle.json").decode("utf-8")

            import json

            payload = json.loads(bundle_manifest)
            paths = [entry["path"] for entry in payload["entries"]]
            self.assertEqual(paths, sorted(paths))

    def test_payload_export_contains_expected_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            media_path = temp_path / "sample.mp4"
            media_path.write_bytes(b"origin-protocol-payload")

            keypair = generate_keypair()
            _, public_path = save_keypair(keypair, temp_path)
            key_id = public_key_fingerprint(keypair.public_key)

            manifest = build_manifest(
                file_path=media_path,
                creator_id="creator-2",
                asset_id="asset-2",
                intended_platforms=(),
                key_id=key_id,
            )
            bundle_path = temp_path / "bundle.zip"
            create_sealed_bundle(media_path, manifest, keypair.private_key, public_path, bundle_path)

            payload = build_payload_from_bundle(bundle_path)
            expected_keys = {
                "bundle.json",
                "bundle.sig",
                "manifest.json",
                "signature.ed25519",
                "seal.json",
                "seal.ed25519",
                "public_key.ed25519",
            }
            self.assertEqual(set(payload.keys()), expected_keys)

    def test_payload_json_contains_schema_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            media_path = temp_path / "sample.mp4"
            media_path.write_bytes(b"origin-protocol-schema")

            keypair = generate_keypair()
            _, public_path = save_keypair(keypair, temp_path)
            key_id = public_key_fingerprint(keypair.public_key)

            manifest = build_manifest(
                file_path=media_path,
                creator_id="creator-3",
                asset_id="asset-3",
                intended_platforms=(),
                key_id=key_id,
            )
            bundle_path = temp_path / "bundle.zip"
            create_sealed_bundle(media_path, manifest, keypair.private_key, public_path, bundle_path)

            payload_bytes = build_payload_json_bytes(bundle_path)
            import json

            payload = json.loads(payload_bytes.decode("utf-8"))
            for key in ("manifest_hash", "bundle_hash", "key_id", "media_hash", "origin_uuid"):
                self.assertIn(key, payload)


if __name__ == "__main__":
    unittest.main()
