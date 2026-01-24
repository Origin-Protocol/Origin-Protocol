from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .bundle import build_bundle_manifest, bundle_manifest_to_bytes
from .manifest import Manifest, manifest_hash, manifest_to_bytes, write_manifest
from .seal import build_seal, seal_hash, seal_to_bytes


@dataclass(frozen=True)
class BundlePaths:
    directory: Path
    manifest: Path
    signature: Path
    public_key: Path


def create_bundle(
    manifest: Manifest,
    private_key: Ed25519PrivateKey,
    public_key_path: Path,
    output_dir: Path,
) -> BundlePaths:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"
    signature_path = output_dir / "signature.ed25519"
    public_key_dest = output_dir / "public_key.ed25519"

    write_manifest(manifest, manifest_path)
    signature = private_key.sign(manifest_to_bytes(manifest))
    signature_path.write_bytes(signature)
    public_key_dest.write_bytes(public_key_path.read_bytes())

    return BundlePaths(
        directory=output_dir,
        manifest=manifest_path,
        signature=signature_path,
        public_key=public_key_dest,
    )


def create_sealed_bundle(
    file_path: Path,
    manifest: Manifest,
    private_key: Ed25519PrivateKey,
    public_key_path: Path,
    output_path: Path,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    media_path = f"media/{file_path.name}"
    manifest_bytes = manifest_to_bytes(manifest)
    manifest_sig = private_key.sign(manifest_bytes)
    seal = build_seal(file_path, media_path, manifest_hash(manifest))
    seal_bytes = seal_to_bytes(seal)
    seal_sig = private_key.sign(seal_bytes)

    public_key_bytes = public_key_path.read_bytes()
    media_bytes = file_path.read_bytes()
    bundle_manifest = build_bundle_manifest(
        (
            ("manifest.json", manifest_bytes),
            ("signature.ed25519", manifest_sig),
            ("public_key.ed25519", public_key_bytes),
            ("seal.json", seal_bytes),
            ("seal.ed25519", seal_sig),
            (media_path, media_bytes),
        ),
        bundle_type="sealed",
        manifest_hash_value=manifest_hash(manifest),
        seal_hash_value=seal_hash(seal),
        media_hash_value=seal.content_hash,
        proof_chain={
            "manifest_hash": manifest_hash(manifest),
            "seal_hash": seal_hash(seal),
            "media_hash": seal.content_hash,
        },
    )
    bundle_manifest_bytes = bundle_manifest_to_bytes(bundle_manifest)
    bundle_sig = private_key.sign(bundle_manifest_bytes)

    def _write_bytes(bundle: ZipFile, name: str, data: bytes) -> None:
        info = ZipInfo(name)
        info.date_time = (1980, 1, 1, 0, 0, 0)
        info.compress_type = ZIP_DEFLATED
        info.external_attr = 0
        info.create_system = 0
        info.flag_bits = 0
        bundle.writestr(info, data, compresslevel=9)

    with ZipFile(output_path, "w", compression=ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, data in sorted(
            (
                ("bundle.json", bundle_manifest_bytes),
                ("bundle.sig", bundle_sig),
                ("manifest.json", manifest_bytes),
                ("signature.ed25519", manifest_sig),
                ("public_key.ed25519", public_key_bytes),
                ("seal.json", seal_bytes),
                ("seal.ed25519", seal_sig),
                (media_path, media_bytes),
            ),
            key=lambda item: item[0],
        ):
            _write_bytes(bundle, name, data)

    return output_path
