from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cryptography.hazmat.primitives import serialization

from .attestation import read_attestation, verify_attestation, load_trust_store
from .keys import load_public_key_bytes, public_key_fingerprint
from .manifest import Manifest, hash_file
from .registry import read_registry
from .revocation import find_revocations, read_revocation_list
from .seal import seal_from_bytes
from .verify import verify_bundle, verify_sealed_bundle


@dataclass(frozen=True)
class VerificationPolicy:
    platform: str | None = None
    region: str | None = None
    usage_context: str | None = None
    attestation_purpose: str | None = None
    require_platform_match: bool = False
    require_creator_id: str | None = None
    require_content_hash_match: bool = True
    require_seal: bool = False
    revocation_list_path: Path | None = None
    require_revocation_check: bool = False
    key_registry_path: Path | None = None
    require_key_registry: bool = False
    require_key_id_match: bool = False
    attestation_path: Path | None = None
    attestation_signature_path: Path | None = None
    trust_store_path: Path | None = None
    require_attestation: bool = False


class PolicyProfile:
    STRICT = "strict"      # Full crypto + registry + revocation + attestation
    STANDARD = "standard"  # Crypto + registry + revocation, attestation optional
    PERMISSIVE = "permissive"  # Signature-only, minimal checks


@dataclass(frozen=True)
class PolicyResult:
    ok: bool
    reasons: tuple[str, ...]
    manifest: Manifest
    revocation_entries: tuple[object, ...] = ()


def apply_policy_profile(policy: VerificationPolicy, profile: str) -> VerificationPolicy:
    profile = profile.lower()
    if profile == PolicyProfile.PERMISSIVE:
        return policy
    if profile == PolicyProfile.STANDARD:
        return replace(
            policy,
            require_platform_match=True,
            require_seal=True,
            require_key_registry=True,
            require_key_id_match=True,
            require_revocation_check=True,
            require_attestation=False,
        )
    if profile == PolicyProfile.STRICT:
        return replace(
            policy,
            require_platform_match=True,
            require_seal=True,
            require_key_registry=True,
            require_key_id_match=True,
            require_revocation_check=True,
            require_attestation=True,
        )
    raise ValueError(f"Unknown policy profile: {profile}")


def build_policy_for_profile(profile: str) -> VerificationPolicy:
    base = VerificationPolicy()
    return apply_policy_profile(base, profile)


def _evaluate_policy(
    manifest: Manifest,
    policy: VerificationPolicy,
    file_path: Path | None,
    content_hash_verified: bool,
) -> list[str]:
    reasons: list[str] = []

    if policy.require_platform_match:
        if not policy.platform:
            reasons.append("platform_missing")
        elif policy.platform not in manifest.intended_platforms:
            reasons.append("platform_mismatch")

    if policy.require_creator_id:
        if manifest.creator_id != policy.require_creator_id:
            reasons.append("creator_mismatch")

    if policy.require_content_hash_match:
        if not content_hash_verified:
            if file_path is None:
                reasons.append("content_hash_unchecked")
            elif hash_file(file_path) != manifest.content_hash:
                reasons.append("content_hash_mismatch")

    return reasons


def _evaluate_attestation(
    manifest: Manifest,
    policy: VerificationPolicy,
    public_key: Ed25519PublicKey,
) -> list[str]:
    reasons: list[str] = []

    if policy.require_attestation and policy.attestation_path is None:
        return ["attestation_missing"]
    if policy.require_attestation and policy.attestation_signature_path is None:
        return ["attestation_signature_missing"]
    if policy.require_attestation and policy.trust_store_path is None:
        return ["trust_store_missing"]

    if (
        policy.attestation_path is None
        or policy.attestation_signature_path is None
        or policy.trust_store_path is None
    ):
        return reasons

    attestation = read_attestation(policy.attestation_path)
    attestation_sig = policy.attestation_signature_path.read_bytes()
    issuer_keys = load_trust_store(policy.trust_store_path)
    if not issuer_keys:
        return ["trust_store_empty"]

    if attestation.subject_creator_id != manifest.creator_id:
        reasons.append("attestation_creator_mismatch")
    if manifest.key_id and attestation.subject_key_id != manifest.key_id:
        reasons.append("attestation_key_id_mismatch")

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if pem.decode("utf-8") != attestation.subject_public_key:
        reasons.append("attestation_key_mismatch")

    if attestation.expires_at:
        try:
            expires_at = datetime.fromisoformat(attestation.expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expires_at:
                reasons.append("attestation_expired")
        except ValueError:
            reasons.append("attestation_expired")

    if policy.platform and attestation.platform_binding:
        if attestation.platform_binding != policy.platform:
            reasons.append("attestation_platform_mismatch")

    if policy.region and attestation.region:
        if attestation.region != policy.region:
            reasons.append("attestation_region_mismatch")

    if policy.usage_context and attestation.usage_constraints:
        if policy.usage_context not in attestation.usage_constraints:
            reasons.append("attestation_usage_violation")

    if policy.attestation_purpose and attestation.purpose:
        if attestation.purpose != policy.attestation_purpose:
            reasons.append("attestation_purpose_mismatch")

    if attestation.not_before:
        try:
            not_before = datetime.fromisoformat(attestation.not_before)
            if not_before.tzinfo is None:
                not_before = not_before.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) < not_before:
                reasons.append("attestation_not_yet_valid")
        except ValueError:
            reasons.append("attestation_not_yet_valid")

    candidate_keys = issuer_keys
    if attestation.issuer_key_id:
        candidate_keys = [key for key in issuer_keys if key.key_id == attestation.issuer_key_id]

    verified = any(
        verify_attestation(attestation, attestation_sig, load_public_key_bytes(key.public_key.encode("utf-8")))
        for key in candidate_keys
    )
    if not verified:
        reasons.append("attestation_invalid")

    return reasons


def _load_bundle_public_key(bundle_path: Path, sealed: bool) -> Ed25519PublicKey:
    if sealed:
        with ZipFile(bundle_path, "r") as bundle:
            public_key_bytes = bundle.read("public_key.ed25519")
    else:
        public_key_bytes = (bundle_path / "public_key.ed25519").read_bytes()
    return load_public_key_bytes(public_key_bytes)


def verify_bundle_with_policy(
    bundle_dir: Path,
    policy: VerificationPolicy,
    file_path: Path | None = None,
    public_key: Ed25519PublicKey | None = None,
) -> PolicyResult:
    try:
        ok_sig, manifest = verify_bundle(bundle_dir, public_key=public_key)
    except FileNotFoundError:
        reasons = ("bundle_manifest_missing",)
        placeholder = Manifest(
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
        return PolicyResult(ok=False, reasons=reasons, manifest=placeholder)
    reasons = [] if ok_sig else ["signature_invalid"]

    if policy.require_seal:
        reasons.append("seal_required")

    revocation_entries: tuple[object, ...] = ()
    if policy.require_revocation_check and policy.revocation_list_path is None:
        reasons.append("revocation_list_missing")
    elif policy.revocation_list_path:
        listing = read_revocation_list(policy.revocation_list_path)
        revocation_entries = find_revocations(
            manifest,
            listing,
            platform=policy.platform,
            region=policy.region,
        )
        if revocation_entries:
            reasons.append("revoked")

    if policy.require_key_registry and policy.key_registry_path is None:
        reasons.append("key_registry_missing")
    elif policy.key_registry_path:
        registry = read_registry(policy.key_registry_path)
        bundle_public_key = public_key or _load_bundle_public_key(bundle_dir, sealed=False)
        bundle_key_id = public_key_fingerprint(bundle_public_key)
        if policy.require_key_id_match:
            if manifest.key_id is None:
                reasons.append("key_id_missing")
            elif manifest.key_id != bundle_key_id:
                reasons.append("key_id_mismatch")
        if manifest.key_id is None or manifest.key_id != bundle_key_id:
            reasons.append("key_untrusted")
        else:
            from .registry import is_key_active

            if not is_key_active(registry, manifest.creator_id, manifest.key_id):
                reasons.append("key_untrusted")

    bundle_public_key = public_key or _load_bundle_public_key(bundle_dir, sealed=False)
    reasons.extend(_evaluate_attestation(manifest, policy, bundle_public_key))

    content_hash_verified = False
    reasons.extend(_evaluate_policy(manifest, policy, file_path, content_hash_verified))
    return PolicyResult(
        ok=len(reasons) == 0,
        reasons=tuple(reasons),
        manifest=manifest,
        revocation_entries=revocation_entries,
    )


def verify_sealed_bundle_with_policy(
    bundle_path: Path,
    policy: VerificationPolicy,
    public_key: Ed25519PublicKey | None = None,
) -> PolicyResult:
    try:
        ok, manifest = verify_sealed_bundle(bundle_path, public_key=public_key)
    except FileNotFoundError:
        reasons = ("bundle_missing",)
        placeholder = Manifest(
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
        return PolicyResult(ok=False, reasons=reasons, manifest=placeholder)
    reasons = [] if ok else ["seal_invalid"]

    revocation_entries: tuple[object, ...] = ()
    if policy.require_revocation_check and policy.revocation_list_path is None:
        reasons.append("revocation_list_missing")
    elif policy.revocation_list_path:
        listing = read_revocation_list(policy.revocation_list_path)
        revocation_entries = find_revocations(
            manifest,
            listing,
            platform=policy.platform,
            region=policy.region,
        )
        if revocation_entries:
            reasons.append("revoked")

    if policy.require_key_registry and policy.key_registry_path is None:
        reasons.append("key_registry_missing")
    elif policy.key_registry_path:
        registry = read_registry(policy.key_registry_path)
        bundle_public_key = public_key or _load_bundle_public_key(bundle_path, sealed=True)
        bundle_key_id = public_key_fingerprint(bundle_public_key)
        if policy.require_key_id_match:
            if manifest.key_id is None:
                reasons.append("key_id_missing")
            elif manifest.key_id != bundle_key_id:
                reasons.append("key_id_mismatch")
        if not manifest.key_id or manifest.key_id != bundle_key_id:
            reasons.append("key_untrusted")
        else:
            from .registry import is_key_active

            if not is_key_active(registry, manifest.creator_id, manifest.key_id):
                reasons.append("key_untrusted")

    bundle_public_key = public_key or _load_bundle_public_key(bundle_path, sealed=True)
    reasons.extend(_evaluate_attestation(manifest, policy, bundle_public_key))

    if ok:
        try:
            with ZipFile(bundle_path, "r") as bundle:
                seal_bytes = bundle.read("seal.json")
            seal = seal_from_bytes(seal_bytes)
            if seal.created_at < manifest.created_at:
                reasons.append("seal_timestamp_invalid")
        except Exception:
            pass

    # For sealed bundles, media bytes are inside the bundle and verified via the seal.
    reasons.extend(_evaluate_policy(manifest, policy, file_path=None, content_hash_verified=True))
    return PolicyResult(
        ok=len(reasons) == 0,
        reasons=tuple(reasons),
        manifest=manifest,
        revocation_entries=revocation_entries,
    )
