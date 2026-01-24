from __future__ import annotations

import base64
import json
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from origin_protocol.container import build_payload_json_bytes, build_sidecar_from_bundle
from origin_protocol.attestation import build_attestation, sign_attestation, write_attestation, write_trust_store, IssuerKey
from origin_protocol.embed import create_sealed_bundle
from origin_protocol.keys import generate_keypair, public_key_fingerprint, save_keypair
from origin_protocol.manifest import build_manifest
from origin_protocol.reasons import REJECTION_REASONS
from origin_protocol.registry import build_registry, add_key_record, write_registry, KeyRecord
from origin_protocol.revocation import build_revocation_list, write_revocation_list

FIXTURES = ROOT / "tests" / "eval" / "fixtures"
MEDIA_DIR = FIXTURES / "media"
SIDECAR_DIR = FIXTURES / "sidecar"
MP4_DIR = FIXTURES / "mp4"
MKV_DIR = FIXTURES / "mkv"
BUNDLE_DIR = FIXTURES / "bundles"
ATTESTATION_DIR = FIXTURES / "attestation"
REGISTRY_DIR = FIXTURES / "registry"
REVOCATION_DIR = FIXTURES / "revocation"
TMP_DIR = FIXTURES / "tmp"


def write_minimal_mp4(path: Path) -> None:
    ftyp = struct.pack(
        ">I4s4sI4s4s",
        24,
        b"ftyp",
        b"isom",
        0,
        b"isom",
        b"iso2",
    )
    mdat = struct.pack(">I4s8s", 16, b"mdat", b"\x00" * 8)
    path.write_bytes(ftyp + mdat)


def write_minimal_mkv(path: Path) -> None:
    path.write_bytes(b"\x1A\x45\xDF\xA3\x9F" + b"matroska")


def rewrite_zip(src: Path, dest: Path, replacements: dict[str, bytes]) -> None:
    with ZipFile(src, "r") as bundle:
        files = {name: bundle.read(name) for name in bundle.namelist()}
    for name, value in replacements.items():
        files[name] = value

    def _write_bytes(handle: ZipFile, name: str, data: bytes) -> None:
        info = ZipInfo(name)
        info.date_time = (1980, 1, 1, 0, 0, 0)
        info.compress_type = ZIP_DEFLATED
        info.external_attr = 0
        info.create_system = 0
        info.flag_bits = 0
        handle.writestr(info, data, compresslevel=9)

    dest.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(dest, "w", compression=ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, data in sorted(files.items()):
            _write_bytes(bundle, name, data)


def build_fixtures() -> None:
    MEDIA_DIR.mkdir(parents=True, exist_ok=True)
    SIDECAR_DIR.mkdir(parents=True, exist_ok=True)
    MP4_DIR.mkdir(parents=True, exist_ok=True)
    MKV_DIR.mkdir(parents=True, exist_ok=True)
    BUNDLE_DIR.mkdir(parents=True, exist_ok=True)
    ATTESTATION_DIR.mkdir(parents=True, exist_ok=True)
    REGISTRY_DIR.mkdir(parents=True, exist_ok=True)
    REVOCATION_DIR.mkdir(parents=True, exist_ok=True)
    TMP_DIR.mkdir(parents=True, exist_ok=True)

    media_path = MEDIA_DIR / "valid_media.mp4"
    write_minimal_mp4(media_path)

    mkv_base = MEDIA_DIR / "valid_media.mkv"
    write_minimal_mkv(mkv_base)

    keypair = generate_keypair()
    _, public_path = save_keypair(keypair, TMP_DIR)
    key_id = public_key_fingerprint(keypair.public_key)

    issuer_keypair = generate_keypair()
    _, issuer_public_path = save_keypair(issuer_keypair, TMP_DIR / "issuer")
    issuer_public_pem = issuer_public_path.read_text()
    issuer_key_id = public_key_fingerprint(issuer_keypair.public_key)

    manifest = build_manifest(
        file_path=media_path,
        creator_id="creator-eval",
        asset_id="asset-eval",
        intended_platforms=("platform-1",),
        key_id=key_id,
    )

    sealed_bundle = BUNDLE_DIR / "sealed_bundle_valid.zip"
    create_sealed_bundle(media_path, manifest, keypair.private_key, public_path, sealed_bundle)

    build_sidecar_from_bundle(sealed_bundle, media_path, SIDECAR_DIR / "valid_sidecar.json")

    payload_bytes = build_payload_json_bytes(sealed_bundle)

    mp4_base = MEDIA_DIR / "mp4_base.mp4"
    write_minimal_mp4(mp4_base)

    from origin_protocol.mp4 import insert_uuid_box

    insert_uuid_box(mp4_base, MP4_DIR / "mp4_with_valid_uuid_payload.mp4", payload_bytes)

    minimal_payload = json.dumps({"origin_schema": "1.0"}).encode("utf-8")
    insert_uuid_box(mp4_base, MP4_DIR / "mp4_with_wrong_uuid.mp4", minimal_payload)

    mkv_valid = MKV_DIR / "mkv_with_valid_origin_tag.mkv"
    mkv_truncated = MKV_DIR / "mkv_with_truncated_tag.mkv"
    name_marker = b"\x45\xA3ORIGIN"

    def _vint_size(value: int) -> bytes:
        if value < (1 << 7) - 1:
            return bytes([0x80 | value])
        if value < (1 << 14) - 1:
            return bytes([0x40 | (value >> 8), value & 0xFF])
        if value < (1 << 21) - 1:
            return bytes([0x20 | (value >> 16), (value >> 8) & 0xFF, value & 0xFF])
        if value < (1 << 28) - 1:
            return bytes(
                [
                    0x10 | (value >> 24),
                    (value >> 16) & 0xFF,
                    (value >> 8) & 0xFF,
                    value & 0xFF,
                ]
            )
        raise ValueError("Payload too large for fixture")

    mkv_valid.write_bytes(
        b"MKV" + name_marker + b"\x44\x87" + _vint_size(len(payload_bytes)) + payload_bytes
    )
    truncated_payload = b"{\"origin_schema\":"
    mkv_truncated.write_bytes(
        b"MKV" + name_marker + b"\x44\x87" + _vint_size(len(truncated_payload)) + truncated_payload
    )

    sidecar_tampered = SIDECAR_DIR / "sidecar_with_tampered_manifest.json"
    sidecar_wrong_key = SIDECAR_DIR / "sidecar_with_wrong_public_key.json"

    sidecar_payload = json.loads((SIDECAR_DIR / "valid_sidecar.json").read_text())
    manifest_bytes = base64.b64decode(sidecar_payload["payload"]["manifest.json"])
    manifest_obj = json.loads(manifest_bytes.decode("utf-8"))
    manifest_obj["creator_id"] = f"{manifest_obj.get('creator_id', 'creator')}-tampered"
    manifest_bytes = json.dumps(manifest_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sidecar_payload["payload"]["manifest.json"] = base64.b64encode(manifest_bytes).decode("ascii")
    sidecar_tampered.write_text(json.dumps(sidecar_payload, indent=2, sort_keys=True))

    wrong_keypair = generate_keypair()
    _, wrong_public_path = save_keypair(wrong_keypair, TMP_DIR / "wrong")
    sidecar_payload = json.loads((SIDECAR_DIR / "valid_sidecar.json").read_text())
    sidecar_payload["payload"]["public_key.ed25519"] = base64.b64encode(
        wrong_public_path.read_bytes()
    ).decode("ascii")
    sidecar_wrong_key.write_text(json.dumps(sidecar_payload, indent=2, sort_keys=True))

    tampered_bundle = BUNDLE_DIR / "sealed_bundle_tampered_manifest.zip"
    with ZipFile(sealed_bundle, "r") as bundle:
        bundle_sig = bundle.read("bundle.sig")
    tampered_sig = bundle_sig[:-1] + bytes([bundle_sig[-1] ^ 0xFF])
    rewrite_zip(sealed_bundle, tampered_bundle, {"bundle.sig": tampered_sig})

    wrong_seal = BUNDLE_DIR / "sealed_bundle_wrong_seal.zip"
    with ZipFile(sealed_bundle, "r") as bundle:
        seal_sig = bundle.read("seal.ed25519")
    tampered_seal = seal_sig[:-1] + bytes([seal_sig[-1] ^ 0xFF])
    rewrite_zip(sealed_bundle, wrong_seal, {"seal.ed25519": tampered_seal})

    registry = build_registry()
    registry = add_key_record(
        registry,
        KeyRecord(
            creator_id="creator-eval",
            key_id=key_id,
            public_key=public_path.read_text(),
            status="active",
            valid_from="2024-01-01T00:00:00+00:00",
        ),
    )
    write_registry(registry, REGISTRY_DIR / "registry_active.json")

    empty_registry = build_registry()
    write_registry(empty_registry, REGISTRY_DIR / "registry_empty.json")

    attestation = build_attestation(
        issuer_id="issuer-1",
        subject_creator_id="creator-eval",
        subject_key_id=key_id,
        subject_public_key_pem=public_path.read_text(),
        issuer_public_key_pem=issuer_public_pem,
        platform_binding=None,
        usage_constraints=None,
        region=None,
        purpose=None,
    )
    attestation_path = ATTESTATION_DIR / "attestation_valid.json"
    write_attestation(attestation, attestation_path)
    attestation_sig = sign_attestation(attestation, issuer_keypair.private_key)
    (ATTESTATION_DIR / "attestation_valid.sig").write_bytes(attestation_sig)

    tampered_sig = attestation_sig[:-1] + bytes([attestation_sig[-1] ^ 0xFF])
    (ATTESTATION_DIR / "attestation_invalid.sig").write_bytes(tampered_sig)

    attestation_bad_creator = build_attestation(
        issuer_id="issuer-1",
        subject_creator_id="creator-other",
        subject_key_id=key_id,
        subject_public_key_pem=public_path.read_text(),
        issuer_public_key_pem=issuer_public_pem,
    )
    write_attestation(attestation_bad_creator, ATTESTATION_DIR / "attestation_creator_mismatch.json")
    (ATTESTATION_DIR / "attestation_creator_mismatch.sig").write_bytes(
        sign_attestation(attestation_bad_creator, issuer_keypair.private_key)
    )

    attestation_expired = build_attestation(
        issuer_id="issuer-1",
        subject_creator_id="creator-eval",
        subject_key_id=key_id,
        subject_public_key_pem=public_path.read_text(),
        issuer_public_key_pem=issuer_public_pem,
        expires_at="2000-01-01T00:00:00+00:00",
    )
    write_attestation(attestation_expired, ATTESTATION_DIR / "attestation_expired.json")
    (ATTESTATION_DIR / "attestation_expired.sig").write_bytes(
        sign_attestation(attestation_expired, issuer_keypair.private_key)
    )

    trust_store = (
        IssuerKey(
            issuer_id="issuer-1",
            key_id=issuer_key_id,
            public_key=issuer_public_pem,
            valid_from="2024-01-01T00:00:00+00:00",
        ),
    )
    write_trust_store(ATTESTATION_DIR / "trust_store.json", trust_store)

    revocation_list = build_revocation_list("creator-eval")
    write_revocation_list(revocation_list, REVOCATION_DIR / "revocation_empty.json")

    truth_table = {
        code: {
            "message": reason.message,
            "category": reason.category,
            "subcategory": reason.subcategory,
            "severity": reason.severity,
            "is_fatal": reason.is_fatal,
            "creator_action": reason.creator_action,
            "platform_action": reason.platform_action,
            "remediation": reason.remediation,
            "docs_url": reason.docs_url,
        }
        for code, reason in REJECTION_REASONS.items()
    }
    truth_path = ROOT / "tests" / "eval" / "golden_rejection_codes.json"
    truth_path.write_text(json.dumps(truth_table, indent=2, sort_keys=True))


if __name__ == "__main__":
    build_fixtures()
    print("Fixtures generated.")
