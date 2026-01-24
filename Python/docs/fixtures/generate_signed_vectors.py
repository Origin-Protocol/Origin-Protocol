import json
import tempfile
from pathlib import Path

from origin_protocol.bundle import bundle_manifest_to_bytes
from origin_protocol.embed import create_sealed_bundle
from origin_protocol.keys import generate_keypair, public_key_fingerprint, save_keypair
from origin_protocol.manifest import build_manifest, manifest_to_bytes
from origin_protocol.seal import seal_to_bytes, build_seal


def main() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        media_path = temp_path / "sample.mp4"
        media_path.write_bytes(b"origin-signed-vector")

        keypair = generate_keypair()
        _, public_path = save_keypair(keypair, temp_path)
        key_id = public_key_fingerprint(keypair.public_key)

        manifest = build_manifest(
            file_path=media_path,
            creator_id="creator-vector",
            asset_id="asset-vector",
            intended_platforms=("yt",),
            key_id=key_id,
        )

        bundle_path = temp_path / "bundle.zip"
        create_sealed_bundle(media_path, manifest, keypair.private_key, public_path, bundle_path)

        from zipfile import ZipFile

        with ZipFile(bundle_path, "r") as bundle:
            fixture_dir = Path(__file__).parent
            (fixture_dir / "vector_manifest.json").write_bytes(bundle.read("manifest.json"))
            (fixture_dir / "vector_signature.ed25519").write_bytes(bundle.read("signature.ed25519"))
            (fixture_dir / "vector_public_key.ed25519").write_bytes(bundle.read("public_key.ed25519"))
            (fixture_dir / "vector_seal.json").write_bytes(bundle.read("seal.json"))
            (fixture_dir / "vector_seal.ed25519").write_bytes(bundle.read("seal.ed25519"))
            (fixture_dir / "vector_bundle.json").write_bytes(bundle.read("bundle.json"))
            (fixture_dir / "vector_bundle.sig").write_bytes(bundle.read("bundle.sig"))

        print("Signed vector fixtures written to docs/fixtures/")


if __name__ == "__main__":
    main()
