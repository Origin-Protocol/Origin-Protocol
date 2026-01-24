import tempfile
import unittest
from pathlib import Path

from origin_protocol.container import build_payload_json_bytes
from origin_protocol.embed import create_sealed_bundle
from origin_protocol.keys import generate_keypair, public_key_fingerprint, save_keypair
from origin_protocol.manifest import build_manifest
from origin_protocol.mp4 import append_uuid_box, extract_uuid_payloads, insert_uuid_box


class Mp4EmbedTests(unittest.TestCase):
    def test_append_uuid_box(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            media_path = temp_path / "sample.mp4"
            media_path.write_bytes(
                b"\x00\x00\x00\x14ftypisom\x00\x00\x00\x00isom"  # minimal ftyp box
            )

            keypair = generate_keypair()
            _, public_path = save_keypair(keypair, temp_path)
            key_id = public_key_fingerprint(keypair.public_key)

            manifest = build_manifest(
                file_path=media_path,
                creator_id="creator-mp4",
                asset_id="asset-mp4",
                intended_platforms=(),
                key_id=key_id,
            )
            bundle_path = temp_path / "bundle.zip"
            create_sealed_bundle(media_path, manifest, keypair.private_key, public_path, bundle_path)

            payload_bytes = build_payload_json_bytes(bundle_path)
            output_path = temp_path / "output.mp4"
            insert_uuid_box(media_path, output_path, payload_bytes)

            payloads = extract_uuid_payloads(output_path)
            self.assertEqual(len(payloads), 1)
            self.assertEqual(payloads[0].payload, payload_bytes)

    def test_insert_uuid_box_under_udta(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            media_path = temp_path / "sample.mp4"

            def box(name: bytes, payload: bytes) -> bytes:
                return (len(payload) + 8).to_bytes(4, "big") + name + payload

            ftyp = box(b"ftyp", b"isom" + b"\x00\x00\x00\x00" + b"isom")
            moov = box(b"moov", box(b"udta", b""))
            media_path.write_bytes(ftyp + moov)

            keypair = generate_keypair()
            _, public_path = save_keypair(keypair, temp_path)
            key_id = public_key_fingerprint(keypair.public_key)

            manifest = build_manifest(
                file_path=media_path,
                creator_id="creator-mp4",
                asset_id="asset-mp4",
                intended_platforms=(),
                key_id=key_id,
            )
            bundle_path = temp_path / "bundle.zip"
            create_sealed_bundle(media_path, manifest, keypair.private_key, public_path, bundle_path)

            payload_bytes = build_payload_json_bytes(bundle_path)
            output_path = temp_path / "output.mp4"
            append_uuid_box(media_path, output_path, payload_bytes)

            payloads = extract_uuid_payloads(output_path)
            self.assertEqual(len(payloads), 1)
            self.assertEqual(payloads[0].payload, payload_bytes)

    def test_insert_uuid_box_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            media_path = temp_path / "sample.mp4"
            media_path.write_bytes(b"\x00\x00\x00\x14ftypisom\x00\x00\x00\x00isom")

            keypair = generate_keypair()
            _, public_path = save_keypair(keypair, temp_path)
            key_id = public_key_fingerprint(keypair.public_key)

            manifest = build_manifest(
                file_path=media_path,
                creator_id="creator-mp4",
                asset_id="asset-mp4",
                intended_platforms=(),
                key_id=key_id,
            )
            bundle_path = temp_path / "bundle.zip"
            create_sealed_bundle(media_path, manifest, keypair.private_key, public_path, bundle_path)

            payload_bytes = build_payload_json_bytes(bundle_path)
            output_path = temp_path / "output.mp4"
            insert_uuid_box(media_path, output_path, payload_bytes)

            tampered = output_path.read_bytes().replace(payload_bytes, payload_bytes[:-1] + b"X")
            output_path.write_bytes(tampered)

            payloads = extract_uuid_payloads(output_path)
            self.assertNotEqual(payloads[0].payload, payload_bytes)


if __name__ == "__main__":
    unittest.main()
