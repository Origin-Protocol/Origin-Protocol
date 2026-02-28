from __future__ import annotations

import base64
import json
from dataclasses import dataclass
import mimetypes
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .bundle import BundleEntry, build_bundle_manifest_from_entries, bundle_manifest_to_bytes
from .keys import load_public_key_bytes, public_key_fingerprint
from .manifest import Manifest, hash_bytes, manifest_hash, manifest_to_bytes, write_manifest
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

    seal_bytes = _load_origin_seal()
    if seal_bytes:
        assets_dir = output_dir / "assets"
        assets_dir.mkdir(parents=True, exist_ok=True)
        (assets_dir / "origin-seal.png").write_bytes(seal_bytes)

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
    *,
    compression: int = ZIP_DEFLATED,
    compresslevel: int = 9,
    allow_zip64: bool = True,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    media_path = f"media/{file_path.name}"
    manifest_bytes = manifest_to_bytes(manifest)
    manifest_sig = private_key.sign(manifest_bytes)
    seal = build_seal(file_path, media_path, manifest_hash(manifest))
    seal_bytes = seal_to_bytes(seal)
    seal_sig = private_key.sign(seal_bytes)

    public_key_bytes = public_key_path.read_bytes()
    bundle_key_id = manifest.key_id or public_key_fingerprint(load_public_key_bytes(public_key_bytes))
    mime_type, _ = mimetypes.guess_type(file_path.name)
    media_summary = {
        "filename": file_path.name,
        "bytes": str(file_path.stat().st_size),
        "mime_type": mime_type or "application/octet-stream",
    }
    seal_asset_bytes = _load_origin_seal()
    seal_asset_path = "assets/origin-seal.png"
    entries = (
        BundleEntry(path="manifest.json", sha256=hash_bytes(manifest_bytes)),
        BundleEntry(path="signature.ed25519", sha256=hash_bytes(manifest_sig)),
        BundleEntry(path="public_key.ed25519", sha256=hash_bytes(public_key_bytes)),
        BundleEntry(path="seal.json", sha256=hash_bytes(seal_bytes)),
        BundleEntry(path="seal.ed25519", sha256=hash_bytes(seal_sig)),
        BundleEntry(path=media_path, sha256=seal.content_hash),
    )
    if seal_asset_bytes:
        entries = entries + (BundleEntry(path=seal_asset_path, sha256=hash_bytes(seal_asset_bytes)),)
    bundle_manifest = build_bundle_manifest_from_entries(
        entries,
        bundle_type="sealed",
        signature_metadata={
            "bundle": {"algorithm": "ed25519", "key_id": bundle_key_id},
            "manifest": {"algorithm": "ed25519", "key_id": bundle_key_id},
            "seal": {"algorithm": "ed25519", "key_id": bundle_key_id},
        },
        manifest_hash_value=manifest_hash(manifest),
        seal_hash_value=seal_hash(seal),
        media_hash_value=seal.content_hash,
        proof_chain={
            "manifest_hash": manifest_hash(manifest),
            "seal_hash": seal_hash(seal),
            "media_hash": seal.content_hash,
        },
        media_summary=media_summary,
    )
    bundle_manifest_bytes = bundle_manifest_to_bytes(bundle_manifest)
    bundle_sig = private_key.sign(bundle_manifest_bytes)
    bundle_sig_envelope = {
        "algorithm": "ed25519",
        "key_id": bundle_key_id,
        "signature": base64.b64encode(bundle_sig).decode("ascii"),
    }
    bundle_sig_bytes = json.dumps(bundle_sig_envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _write_bytes(bundle: ZipFile, name: str, data: bytes) -> None:
        info = ZipInfo(name)
        info.date_time = (1980, 1, 1, 0, 0, 0)
        info.compress_type = compression
        info.external_attr = 0
        info.create_system = 0
        info.flag_bits = 0
        if info.compress_type == ZIP_STORED:
            bundle.writestr(info, data)
        else:
            bundle.writestr(info, data, compresslevel=compresslevel)

    def _write_file(bundle: ZipFile, name: str, path: Path) -> None:
        info = ZipInfo(name)
        info.date_time = (1980, 1, 1, 0, 0, 0)
        info.compress_type = compression
        info.external_attr = 0
        info.create_system = 0
        info.flag_bits = 0
        with bundle.open(info, "w") as dest, path.open("rb") as src:
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                dest.write(chunk)

    with ZipFile(output_path, "w", compression=compression, compresslevel=compresslevel, allowZip64=allow_zip64) as bundle:
        for name, data in sorted(
            (
                ("bundle.json", bundle_manifest_bytes),
                ("bundle.sig", bundle_sig_bytes),
                ("manifest.json", manifest_bytes),
                ("signature.ed25519", manifest_sig),
                ("public_key.ed25519", public_key_bytes),
                ("seal.json", seal_bytes),
                ("seal.ed25519", seal_sig),
            ),
            key=lambda item: item[0],
        ):
            _write_bytes(bundle, name, data)
        if seal_asset_bytes:
            _write_bytes(bundle, seal_asset_path, seal_asset_bytes)
        _write_file(bundle, media_path, file_path)

    return output_path


def _load_origin_seal() -> bytes | None:
    try:
        asset = files("origin_protocol").joinpath("assets", "origin-seal.png")
        if not asset.is_file():
            return None
        return asset.read_bytes()
    except Exception:
        return None
