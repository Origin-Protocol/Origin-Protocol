import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from origin_protocol.attestation import (
    build_attestation,
    sign_attestation,
    write_attestation,
    write_trust_store,
)
from origin_protocol.embed import create_sealed_bundle
from origin_protocol.keys import generate_keypair, public_key_fingerprint, save_keypair
from origin_protocol.manifest import build_manifest
from origin_protocol.policy import VerificationPolicy, verify_sealed_bundle_with_policy
from origin_protocol.revocation import (
    RevocationEntry,
    add_revocation_entry,
    build_revocation_list,
    write_revocation_list,
)
from origin_protocol.container import build_sidecar_from_bundle, verify_sidecar
from origin_protocol.verify import verify_sealed_bundle


class OriginProtocolTests(unittest.TestCase):
    def _write_media(self, path: Path, content: bytes) -> None:
        path.write_bytes(content)

    def test_sealed_bundle_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            media_path = temp_path / "sample.mp4"
            self._write_media(media_path, b"origin-protocol-test")

            keypair = generate_keypair()
            _, public_path = save_keypair(keypair, temp_path)
            key_id = public_key_fingerprint(keypair.public_key)

            manifest = build_manifest(
                file_path=media_path,
                creator_id="creator-1",
                asset_id="asset-1",
                intended_platforms=("yt",),
                key_id=key_id,
            )
            bundle_path = temp_path / "bundle.zip"
            create_sealed_bundle(media_path, manifest, keypair.private_key, public_path, bundle_path)

            ok, _ = verify_sealed_bundle(bundle_path)
            self.assertTrue(ok)

    def test_sidecar_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            media_path = temp_path / "sample.mp4"
            self._write_media(media_path, b"origin-protocol-test-sidecar")

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

            sidecar_path = temp_path / "origin.sidecar.json"
            build_sidecar_from_bundle(bundle_path, media_path, sidecar_path)

            ok, reason = verify_sidecar(media_path, sidecar_path)
            self.assertTrue(ok, msg=reason)

    def test_policy_revocation_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            media_path = temp_path / "sample.mp4"
            self._write_media(media_path, b"origin-protocol-test-revocation")

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

            revocation_list = build_revocation_list("creator-3")
            revocation_list = add_revocation_entry(
                revocation_list,
                RevocationEntry(
                    creator_id="creator-3",
                    revoked_at="2026-01-01T00:00:00+00:00",
                    content_hash=manifest.content_hash,
                ),
            )
            revocation_path = temp_path / "revocation.json"
            write_revocation_list(revocation_list, revocation_path)

            policy = VerificationPolicy(
                require_revocation_check=True,
                revocation_list_path=revocation_path,
            )
            result = verify_sealed_bundle_with_policy(bundle_path, policy)
            self.assertFalse(result.ok)
            self.assertIn("revoked", result.reasons)

    def test_policy_attestation_allows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            media_path = temp_path / "sample.mp4"
            self._write_media(media_path, b"origin-protocol-test-attest")

            keypair = generate_keypair()
            _, public_path = save_keypair(keypair, temp_path)
            key_id = public_key_fingerprint(keypair.public_key)

            manifest = build_manifest(
                file_path=media_path,
                creator_id="creator-4",
                asset_id="asset-4",
                intended_platforms=(),
                key_id=key_id,
            )
            bundle_path = temp_path / "bundle.zip"
            create_sealed_bundle(media_path, manifest, keypair.private_key, public_path, bundle_path)

            issuer = generate_keypair()
            issuer_public_pem = issuer.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")
            subject_public_pem = keypair.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

            attestation = build_attestation(
                issuer_id="issuer-1",
                subject_creator_id="creator-4",
                subject_key_id=key_id,
                subject_public_key_pem=subject_public_pem,
                expires_at="2099-01-01T00:00:00+00:00",
            )
            attestation_path = temp_path / "attestation.json"
            write_attestation(attestation, attestation_path)

            attestation_sig = sign_attestation(attestation, issuer.private_key)
            attestation_sig_path = temp_path / "attestation.sig"
            attestation_sig_path.write_bytes(attestation_sig)

            trust_store_path = temp_path / "trust_store.json"
            write_trust_store(trust_store_path, [issuer_public_pem])

            policy = VerificationPolicy(
                require_attestation=True,
                attestation_path=attestation_path,
                attestation_signature_path=attestation_sig_path,
                trust_store_path=trust_store_path,
            )
            result = verify_sealed_bundle_with_policy(bundle_path, policy)
            self.assertTrue(result.ok, msg=result.reasons)


if __name__ == "__main__":
    unittest.main()
