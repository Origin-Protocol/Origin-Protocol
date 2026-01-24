import tempfile
import unittest
from pathlib import Path

from origin_protocol.container import build_payload_json_bytes
from origin_protocol.embed import create_sealed_bundle
from origin_protocol.keys import generate_keypair, public_key_fingerprint, save_keypair
from origin_protocol.manifest import build_manifest
from origin_protocol.mkv import append_origin_tag, extract_origin_payloads


class MkvEmbedTests(unittest.TestCase):
    def test_append_origin_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            media_path = temp_path / "sample.mkv"
            media_path.write_bytes(b"\x1A\x45\xDF\xA3")  # EBML header start

            keypair = generate_keypair()
            _, public_path = save_keypair(keypair, temp_path)
            key_id = public_key_fingerprint(keypair.public_key)

            manifest = build_manifest(
                file_path=media_path,
                creator_id="creator-mkv",
                asset_id="asset-mkv",
                intended_platforms=(),
                key_id=key_id,
            )
            bundle_path = temp_path / "bundle.zip"
            create_sealed_bundle(media_path, manifest, keypair.private_key, public_path, bundle_path)

            payload_bytes = build_payload_json_bytes(bundle_path)
            output_path = temp_path / "output.mkv"
            append_origin_tag(media_path, output_path, payload_bytes)

            payloads = extract_origin_payloads(output_path)
            self.assertEqual(len(payloads), 1)
            self.assertEqual(payloads[0].payload, payload_bytes)

    def test_append_origin_tag_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            media_path = temp_path / "sample.mkv"
            media_path.write_bytes(b"\x1A\x45\xDF\xA3")

            keypair = generate_keypair()
            _, public_path = save_keypair(keypair, temp_path)
            key_id = public_key_fingerprint(keypair.public_key)

            manifest = build_manifest(
                file_path=media_path,
                creator_id="creator-mkv",
                asset_id="asset-mkv",
                intended_platforms=(),
                key_id=key_id,
            )
            bundle_path = temp_path / "bundle.zip"
            create_sealed_bundle(media_path, manifest, keypair.private_key, public_path, bundle_path)

            payload_bytes = build_payload_json_bytes(bundle_path)
            output_path = temp_path / "output.mkv"
            append_origin_tag(media_path, output_path, payload_bytes)

            tampered = output_path.read_bytes().replace(payload_bytes, payload_bytes[:-1] + b"X")
            output_path.write_bytes(tampered)

            payloads = extract_origin_payloads(output_path)
            self.assertNotEqual(payloads[0].payload, payload_bytes)


if __name__ == "__main__":
    unittest.main()
