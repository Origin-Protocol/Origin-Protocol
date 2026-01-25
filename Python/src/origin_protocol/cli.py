from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

from .attestation import (
    build_attestation,
    IssuerKey,
    load_trust_store,
    read_attestation,
    sign_attestation,
    validate_attestation_structure,
    verify_attestation,
    write_attestation,
    write_trust_store,
)
from .bundle import bundle_manifest_from_bytes
from .container import (
    build_sidecar_from_bundle,
    embed_payload,
    extract_origin_payload,
    validate_origin_payload,
    verify_sidecar,
)
from .embed import create_bundle, create_sealed_bundle
from .keys import (
    generate_keypair,
    load_private_key,
    load_public_key,
    load_public_key_bytes,
    public_key_fingerprint,
    save_keypair,
)
from .license import (
    LicenseLedgerEntry,
    add_license_ledger_entry,
    build_license,
    build_license_ledger,
    read_license_file,
    read_license_ledger_file,
    sign_license,
    sign_license_ledger,
    validate_license,
    verify_license,
    verify_license_ledger,
    write_license_file,
    write_license_ledger_file,
)
from .manifest import ORIGIN_VERSION, build_manifest, manifest_from_bytes, read_manifest, validate_manifest
from .policy import apply_policy_profile, VerificationPolicy, verify_bundle_with_policy, verify_sealed_bundle_with_policy
from .sdk import as_dict, verify_sealed, verify_unsealed
from .registry import KeyRecord, add_key_record, build_registry, read_registry, revoke_key, write_registry
from .reasons import REJECTION_REASONS
from .revocation import (
    RevocationEntry,
    add_revocation_entry,
    build_revocation_list,
    read_revocation_list,
    sign_revocation_list,
    verify_revocation_list,
    write_revocation_list,
)
from .verify import verify_bundle, verify_sealed_bundle
from .seal import seal_from_bytes
from . import __version__


def _exit_code_for_severity(severities: tuple[str, ...], threshold: str) -> int:
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold_value = order[threshold]
    for severity in severities:
        if order.get(severity, 0) >= threshold_value:
            return 2
    return 0


def _severity_for_reason(code: str) -> str:
    reason = REJECTION_REASONS.get(code)
    return reason.severity if reason else "low"


def _log(args: argparse.Namespace, message: str) -> None:
    if not getattr(args, "quiet", False):
        print(message)


def _vlog(args: argparse.Namespace, message: str) -> None:
    if not getattr(args, "quiet", False) and getattr(args, "verbose", False):
        print(message)


def _require_file(path: Path, label: str) -> None:
    if not path.exists():
        print(f"{label} not found: {path}")
        raise SystemExit(2)


def _require_output(path: Path, args: argparse.Namespace, label: str = "Output") -> None:
    if path.exists() and not getattr(args, "force", False):
        print(f"{label} exists. Use --force to overwrite.")
        raise SystemExit(2)


def _cmd_init_keys(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    private_path = output_dir / "private_key.ed25519"
    public_path = output_dir / "public_key.ed25519"
    if (private_path.exists() or public_path.exists()) and not args.force:
        print("Output exists. Use --force to overwrite.")
        return 2
    keypair = generate_keypair()
    private_path, public_path = save_keypair(keypair, output_dir)
    _log(args, f"Private key: {private_path}")
    _log(args, f"Public key: {public_path}")
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    file_path = Path(args.file)
    _require_file(file_path, "Media file")
    output_dir = Path(args.output_dir)
    if output_dir.exists() and any(output_dir.iterdir()) and not args.force:
        print("Output exists. Use --force to overwrite.")
        return 2
    _require_file(Path(args.private_key), "Private key")
    _require_file(Path(args.public_key), "Public key")
    _vlog(args, "Loading signing keys")
    private_key = load_private_key(Path(args.private_key))
    public_key = load_public_key(Path(args.public_key))
    key_id = args.key_id or public_key_fingerprint(public_key)
    manifest = build_manifest(
        file_path=file_path,
        creator_id=args.creator_id,
        asset_id=args.asset_id,
        intended_platforms=args.intended_platforms,
        key_id=key_id,
    )
    if args.show_origin_id:
        _log(args, f"Origin ID: {manifest.origin_id or 'missing'}")
    bundle = create_bundle(manifest, private_key, Path(args.public_key), output_dir)
    _log(args, f"Bundle created at: {bundle.directory}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    _require_file(Path(args.bundle_dir), "Bundle directory")
    ok, manifest = verify_bundle(Path(args.bundle_dir))
    if ok:
        _log(args, "Signature verified")
        _log(args, f"Creator: {manifest.creator_id}")
        _log(args, f"Asset: {manifest.asset_id}")
        if args.show_origin_id:
            _log(args, f"Origin ID: {manifest.origin_id or 'missing'}")
        _log(args, f"Hash: {manifest.content_hash}")
        return 0
    _log(args, "Signature verification failed")
    return 2


def _cmd_seal(args: argparse.Namespace) -> int:
    file_path = Path(args.file)
    output_path = Path(args.output)
    _require_file(file_path, "Media file")
    _require_output(output_path, args)
    _require_file(Path(args.private_key), "Private key")
    _require_file(Path(args.public_key), "Public key")
    private_key = load_private_key(Path(args.private_key))
    public_key = load_public_key(Path(args.public_key))
    key_id = args.key_id or public_key_fingerprint(public_key)
    manifest = build_manifest(
        file_path=file_path,
        creator_id=args.creator_id,
        asset_id=args.asset_id,
        intended_platforms=args.intended_platforms,
        key_id=key_id,
    )
    if args.show_origin_id:
        _log(args, f"Origin ID: {manifest.origin_id or 'missing'}")
    bundle_path = create_sealed_bundle(
        file_path=file_path,
        manifest=manifest,
        private_key=private_key,
        public_key_path=Path(args.public_key),
        output_path=output_path,
    )
    _log(args, f"Sealed bundle created at: {bundle_path}")
    return 0


def _cmd_verify_seal(args: argparse.Namespace) -> int:
    _require_file(Path(args.bundle_path), "Sealed bundle")
    ok, manifest = verify_sealed_bundle(Path(args.bundle_path))
    if ok:
        _log(args, "Seal verified")
        _log(args, f"Creator: {manifest.creator_id}")
        _log(args, f"Asset: {manifest.asset_id}")
        if args.show_origin_id:
            _log(args, f"Origin ID: {manifest.origin_id or 'missing'}")
        _log(args, f"Hash: {manifest.content_hash}")
        return 0
    _log(args, "Seal verification failed")
    return 2


def _cmd_policy_verify(args: argparse.Namespace) -> int:
    if args.sealed and args.file:
        print("Cannot use --file with --sealed")
        return 2
    _require_file(Path(args.bundle_path), "Bundle")
    if args.file:
        _require_file(Path(args.file), "Media file")
    if args.revocation_list:
        _require_file(Path(args.revocation_list), "Revocation list")
    if args.key_registry:
        _require_file(Path(args.key_registry), "Key registry")
    if args.attestation:
        _require_file(Path(args.attestation), "Attestation")
    if args.attestation_sig:
        _require_file(Path(args.attestation_sig), "Attestation signature")
    if args.trust_store:
        _require_file(Path(args.trust_store), "Trust store")
    policy = VerificationPolicy(
        platform=args.platform,
        require_platform_match=args.require_platform_match,
        require_creator_id=args.creator_id,
        require_content_hash_match=not args.skip_content_hash,
        require_seal=args.require_seal,
        revocation_list_path=Path(args.revocation_list) if args.revocation_list else None,
        require_revocation_check=args.require_revocation_check,
        key_registry_path=Path(args.key_registry) if args.key_registry else None,
        require_key_registry=args.require_key_registry,
        require_key_id_match=args.require_key_id_match,
        attestation_path=Path(args.attestation) if args.attestation else None,
        attestation_signature_path=Path(args.attestation_sig) if args.attestation_sig else None,
        trust_store_path=Path(args.trust_store) if args.trust_store else None,
        require_attestation=args.require_attestation,
    )

    if args.profile:
        policy = apply_policy_profile(policy, args.profile)

    if args.sealed:
        result = verify_sealed_bundle_with_policy(Path(args.bundle_path), policy)
    else:
        file_path = Path(args.file) if args.file else None
        result = verify_bundle_with_policy(Path(args.bundle_path), policy, file_path=file_path)

    if args.json:
        localization = None
        if args.localization:
            localization = json.loads(Path(args.localization).read_text())
        if args.sealed:
            sdk_result = verify_sealed(Path(args.bundle_path), policy, localization=localization)
        else:
            file_path = Path(args.file) if args.file else None
            sdk_result = verify_unsealed(
                Path(args.bundle_path),
                policy,
                file_path=file_path,
                localization=localization,
            )
        _log(args, json.dumps(as_dict(sdk_result), indent=2))
        if args.dry_run:
            return 0
        if args.exit_on_severity:
            return _exit_code_for_severity(sdk_result.severities, args.exit_on_severity)
        return 0 if sdk_result.ok else 2

    if result.ok:
        _log(args, "Policy verification passed")
        _log(args, f"Creator: {result.manifest.creator_id}")
        _log(args, f"Asset: {result.manifest.asset_id}")
        return 0 if not args.dry_run else 0

    _log(args, "Policy verification failed")
    for reason in result.reasons:
        _log(args, f"- {reason}")
    if args.dry_run:
        return 0
    if args.exit_on_severity:
        severities = tuple(_severity_for_reason(reason) for reason in result.reasons)
        return _exit_code_for_severity(severities, args.exit_on_severity)
    return 2


def _cmd_key_register(args: argparse.Namespace) -> int:
    registry_path = Path(args.registry)
    if registry_path.exists():
        registry = read_registry(registry_path)
    else:
        registry = build_registry()

    _require_file(Path(args.public_key), "Public key")
    public_key_bytes = Path(args.public_key).read_bytes()
    key_id = args.key_id or public_key_fingerprint(load_public_key(Path(args.public_key)))
    valid_from = args.valid_from or datetime.now(timezone.utc).isoformat()
    record = KeyRecord(
        creator_id=args.creator_id,
        key_id=key_id,
        public_key=public_key_bytes.decode("utf-8"),
        status="active",
        valid_from=valid_from,
    )
    registry = add_key_record(registry, record)
    write_registry(registry, registry_path)
    _log(args, f"Key registered: {key_id}")
    return 0


def _cmd_key_revoke(args: argparse.Namespace) -> int:
    registry_path = Path(args.registry)
    _require_file(registry_path, "Registry")
    registry = read_registry(registry_path)
    registry = revoke_key(registry, args.creator_id, args.key_id, superseded_by=args.superseded_by)
    write_registry(registry, registry_path)
    _log(args, f"Key revoked: {args.key_id}")
    return 0


def _cmd_revocation_init(args: argparse.Namespace) -> int:
    listing = build_revocation_list(args.issuer_creator_id)
    output_path = Path(args.output)
    _require_output(output_path, args)
    write_revocation_list(listing, output_path)
    _log(args, f"Revocation list created at: {args.output}")
    return 0


def _cmd_revoke(args: argparse.Namespace) -> int:
    list_path = Path(args.revocation_list)
    _require_file(list_path, "Revocation list")
    listing = read_revocation_list(list_path)
    entry = RevocationEntry(
        creator_id=args.creator_id,
        revoked_at=args.revoked_at,
        asset_id=args.asset_id,
        content_hash=args.content_hash,
        key_id=args.key_id,
        reason=args.reason,
    )
    listing = add_revocation_entry(listing, entry)
    write_revocation_list(listing, list_path)
    _log(args, "Revocation entry added")
    return 0


def _cmd_revocation_sign(args: argparse.Namespace) -> int:
    _require_file(Path(args.revocation_list), "Revocation list")
    _require_file(Path(args.private_key), "Private key")
    output_path = Path(args.signature)
    _require_output(output_path, args)
    listing = read_revocation_list(Path(args.revocation_list))
    signature = sign_revocation_list(listing, load_private_key(Path(args.private_key)))
    output_path.write_bytes(signature)
    _log(args, f"Revocation signature written to: {args.signature}")
    return 0


def _cmd_revocation_verify(args: argparse.Namespace) -> int:
    _require_file(Path(args.revocation_list), "Revocation list")
    _require_file(Path(args.signature), "Signature")
    _require_file(Path(args.public_key), "Public key")
    listing = read_revocation_list(Path(args.revocation_list))
    signature = Path(args.signature).read_bytes()
    public_key = load_public_key(Path(args.public_key))
    ok = verify_revocation_list(listing, signature, public_key)
    _log(args, "Revocation list verified" if ok else "Revocation list invalid")
    return 0 if ok else 2


def _cmd_license_issue(args: argparse.Namespace) -> int:
    _require_file(Path(args.private_key), "Private key")
    _require_file(Path(args.public_key), "Public key")
    output_path = Path(args.output)
    _require_output(output_path, args)
    private_key = load_private_key(Path(args.private_key))
    public_key = load_public_key(Path(args.public_key))
    key_id = args.issuer_key_id or public_key_fingerprint(public_key)
    license_obj = build_license(
        user_id=args.user_id,
        plan=args.plan,
        expires_at=args.expires_at,
        features=args.features,
        device_fingerprint=args.device_fingerprint,
        max_devices=args.max_devices,
        offline_grace_days=args.offline_grace_days,
        issuer_key_id=key_id,
    )
    signature = sign_license(license_obj, private_key)
    write_license_file(license_obj, signature, Path(args.public_key).read_bytes(), output_path)
    _log(args, f"License issued: {output_path}")
    return 0


def _cmd_license_verify(args: argparse.Namespace) -> int:
    _require_file(Path(args.license), "License")
    license_obj, signature, public_key_pem = read_license_file(Path(args.license))
    public_key = load_public_key_bytes(public_key_pem.encode("utf-8"))
    ok = verify_license(license_obj, signature, public_key)
    if not ok:
        _log(args, "License signature invalid")
        return 2
    errors = validate_license(
        license_obj,
        device_fingerprint=args.device_fingerprint,
    )
    if errors:
        for error in errors:
            _log(args, f"- {error}")
        return 2
    _log(args, "License verified")
    _log(args, f"User: {license_obj.user_id}")
    _log(args, f"Plan: {license_obj.plan}")
    _log(args, f"Expires: {license_obj.expires_at}")
    return 0


def _cmd_license_ledger_init(args: argparse.Namespace) -> int:
    _require_file(Path(args.private_key), "Private key")
    _require_file(Path(args.public_key), "Public key")
    output_path = Path(args.output)
    _require_output(output_path, args)
    ledger = build_license_ledger(args.issuer_id)
    signature = sign_license_ledger(ledger, load_private_key(Path(args.private_key)))
    write_license_ledger_file(ledger, signature, Path(args.public_key).read_bytes(), output_path)
    _log(args, f"License ledger created: {output_path}")
    return 0


def _cmd_license_ledger_add(args: argparse.Namespace) -> int:
    _require_file(Path(args.ledger), "License ledger")
    _require_file(Path(args.private_key), "Private key")
    _require_file(Path(args.public_key), "Public key")
    ledger, _, _ = read_license_ledger_file(Path(args.ledger))
    entry = LicenseLedgerEntry(
        license_id=args.license_id,
        revoked_at=args.revoked_at,
        reason=args.reason,
        updated_expires_at=args.updated_expires_at,
        updated_plan=args.updated_plan,
        updated_features=tuple(args.updated_features) if args.updated_features else None,
        updated_device_fingerprint=args.updated_device_fingerprint,
    )
    ledger = add_license_ledger_entry(ledger, entry)
    signature = sign_license_ledger(ledger, load_private_key(Path(args.private_key)))
    output_path = Path(args.output)
    write_license_ledger_file(ledger, signature, Path(args.public_key).read_bytes(), output_path)
    _log(args, f"License ledger updated: {output_path}")
    return 0


def _cmd_license_ledger_verify(args: argparse.Namespace) -> int:
    _require_file(Path(args.ledger), "License ledger")
    ledger, signature, public_key_pem = read_license_ledger_file(Path(args.ledger))
    public_key = load_public_key_bytes(public_key_pem.encode("utf-8"))
    ok = verify_license_ledger(ledger, signature, public_key)
    _log(args, "License ledger verified" if ok else "License ledger invalid")
    return 0 if ok else 2


def _cmd_sidecar_embed(args: argparse.Namespace) -> int:
    output_path = Path(args.output)
    _require_file(Path(args.bundle), "Sealed bundle")
    _require_file(Path(args.media), "Media file")
    _require_output(output_path, args)
    build_sidecar_from_bundle(Path(args.bundle), Path(args.media), output_path)
    _log(args, f"Sidecar written to: {output_path}")
    return 0


def _cmd_sidecar_verify(args: argparse.Namespace) -> int:
    _require_file(Path(args.media), "Media file")
    _require_file(Path(args.sidecar), "Sidecar")
    ok, reason = verify_sidecar(Path(args.media), Path(args.sidecar))
    if ok:
        _log(args, "Sidecar verified")
        return 0
    _log(args, f"Sidecar verification failed: {reason}")
    return 2


def _cmd_container_embed(args: argparse.Namespace) -> int:
    valid_formats = {"sidecar", "mp4", "mov", "mkv"}
    if args.format.lower() not in valid_formats:
        print(f"Unsupported format: {args.format}")
        return 2
    _require_file(Path(args.bundle), "Sealed bundle")
    _require_file(Path(args.media), "Media file")
    if args.payload_signing_key:
        _require_file(Path(args.payload_signing_key), "Payload signing key")
    _require_output(Path(args.output), args)
    try:
        signing_key = load_private_key(Path(args.payload_signing_key)) if args.payload_signing_key else None
        output_path = embed_payload(
            Path(args.bundle),
            Path(args.media),
            Path(args.output),
            args.format,
            signing_key=signing_key,
        )
    except NotImplementedError as exc:
        _log(args, str(exc))
        return 2
    except ValueError as exc:
        _log(args, str(exc))
        return 2
    _log(args, f"Container payload written to: {output_path}")
    if args.format.lower() in {"mp4", "mov"}:
        _log(args, "Payload embedded in MP4/MOV uuid box.")
        return 0
    if args.format.lower() in {"mkv"}:
        _log(args, "Payload embedded in MKV Tags element.")
    return 0


def _cmd_extract_payload(args: argparse.Namespace) -> int:
    media_path = Path(args.media)
    _require_file(media_path, "Media")
    sidecar_path = Path(args.sidecar) if args.sidecar else None
    if sidecar_path is not None:
        _require_file(sidecar_path, "Sidecar")

    payload_bytes = extract_origin_payload(media_path, sidecar_path=sidecar_path)
    if payload_bytes is None:
        _log(args, "No Origin payload found")
        return 2

    if args.validate:
        errors = validate_origin_payload(payload_bytes)
        if errors:
            for error in errors:
                _log(args, f"- {error}")
            return 2

    if args.output:
        output_path = Path(args.output)
        _require_output(output_path, args)
        output_path.write_bytes(payload_bytes)
    else:
        _log(args, payload_bytes.decode("utf-8"))
    return 0


def _cmd_attest_issue(args: argparse.Namespace) -> int:
    _require_file(Path(args.public_key), "Subject public key")
    _require_file(Path(args.issuer_private_key), "Issuer private key")
    if args.issuer_public_key:
        _require_file(Path(args.issuer_public_key), "Issuer public key")
    public_key_pem = Path(args.public_key).read_text()
    attestation = build_attestation(
        issuer_id=args.issuer_id,
        subject_creator_id=args.creator_id,
        subject_key_id=args.key_id,
        subject_public_key_pem=public_key_pem,
        issuer_public_key_pem=Path(args.issuer_public_key).read_text() if args.issuer_public_key else None,
        attestation_type=args.attestation_type,
        attestation_id=args.attestation_id,
        expires_at=args.expires_at,
        not_before=args.not_before,
        platform_binding=args.platform_binding,
        usage_constraints=args.usage_constraints,
        region=args.region,
        expiration_policy=args.expiration_policy,
        purpose=args.purpose,
    )
    output_path = Path(args.output)
    _require_output(output_path, args)
    write_attestation(attestation, output_path)
    signature = sign_attestation(attestation, load_private_key(Path(args.issuer_private_key)))
    signature_path = Path(args.signature)
    _require_output(signature_path, args, label="Signature")
    signature_path.write_bytes(signature)
    _log(args, f"Attestation written to: {args.output}")
    _log(args, f"Attestation signature written to: {args.signature}")
    return 0


def _cmd_attest_verify(args: argparse.Namespace) -> int:
    _require_file(Path(args.attestation), "Attestation")
    _require_file(Path(args.signature), "Signature")
    _require_file(Path(args.issuer_public_key), "Issuer public key")
    attestation = read_attestation(Path(args.attestation))
    signature = Path(args.signature).read_bytes()
    issuer_key = load_public_key(Path(args.issuer_public_key))
    ok = verify_attestation(attestation, signature, issuer_key)
    _log(args, "Attestation verified" if ok else "Attestation invalid")
    return 0 if ok else 2


def _cmd_trust_store_init(args: argparse.Namespace) -> int:
    output_path = Path(args.output)
    _require_output(output_path, args)
    issuer_keys: list[IssuerKey] = []
    for path in args.issuer_public_keys:
        _require_file(Path(path), "Issuer public key")
        public_key = Path(path).read_text()
        key_id = public_key_fingerprint(load_public_key(Path(path)))
        issuer_keys.append(
            IssuerKey(
                issuer_id=args.issuer_id,
                key_id=key_id,
                public_key=public_key,
                valid_from=args.valid_from,
                valid_to=args.valid_to,
            )
        )
    write_trust_store(output_path, issuer_keys)
    _log(args, f"Trust store written to: {args.output}")
    return 0


def _cmd_version(args: argparse.Namespace) -> int:
    _log(args, f"Origin Protocol CLI {__version__}")
    _log(args, f"Origin schema version {ORIGIN_VERSION}")
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.path)
    _require_file(path, "Path")
    kind = args.kind
    errors: list[str] = []
    try:
        if kind == "manifest":
            manifest = read_manifest(path)
            errors = validate_manifest(manifest)
        elif kind == "bundle":
            bundle_manifest_from_bytes(path.read_bytes())
        elif kind == "seal":
            seal_from_bytes(path.read_bytes())
        elif kind == "attestation":
            attestation = read_attestation(path)
            errors = validate_attestation_structure(attestation)
        elif kind == "origin-payload":
            errors = validate_origin_payload(path.read_bytes(), fast_fail=args.fast_fail)
        elif kind == "trust-store":
            load_trust_store(path)
        elif kind == "registry":
            read_registry(path)
        elif kind == "revocation-list":
            read_revocation_list(path)
        else:
            errors.append("unsupported_type")
    except Exception:
        errors.append("invalid_format")

    if errors:
        for error in errors:
            _log(args, f"- {error}")
        return 2
    _log(args, f"{kind} valid")
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    if args.attestation:
        path = Path(args.attestation)
        _require_file(path, "Attestation")
        attestation = read_attestation(path)
        _log(args, f"Attestation: {attestation.attestation_id}")
        _log(args, f"Type: {attestation.attestation_type}")
        _log(args, f"Issuer: {attestation.issuer_id}")
        _log(args, f"Issuer key id: {attestation.issuer_key_id}")
        _log(args, f"Creator: {attestation.subject_creator_id}")
        _log(args, f"Key id: {attestation.subject_key_id}")
        _log(args, f"Issued at: {attestation.issued_at}")
        _log(args, f"Not before: {attestation.not_before}")
        _log(args, f"Expires at: {attestation.expires_at}")
        _log(args, f"Platform binding: {attestation.platform_binding}")
        _log(args, f"Region: {attestation.region}")
        _log(args, f"Usage constraints: {attestation.usage_constraints}")
        _log(args, f"Purpose: {attestation.purpose}")
        return 0

    if args.bundle:
        bundle_path = Path(args.bundle)
        _require_file(bundle_path, "Bundle")
        if args.sealed:
            with ZipFile(bundle_path, "r") as bundle:
                manifest = manifest_from_bytes(bundle.read("manifest.json"))
        else:
            if not bundle_path.is_dir():
                print("Bundle path must be a directory for unsealed bundles")
                return 2
            _require_file(bundle_path / "manifest.json", "Manifest")
            manifest = read_manifest(bundle_path / "manifest.json")
        _log(args, f"Creator: {manifest.creator_id}")
        _log(args, f"Asset: {manifest.asset_id}")
        _log(args, f"Key id: {manifest.key_id}")
        if args.show_origin_id:
            _log(args, f"Origin ID: {manifest.origin_id or 'missing'}")
        _log(args, f"Content hash: {manifest.content_hash}")
        _log(args, f"Platforms: {', '.join(manifest.intended_platforms)}")
        return 0

    print("Nothing to explain")
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="origin", description="Origin Protocol CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    init_keys = sub.add_parser("init-keys", help="Generate Ed25519 keypair")
    init_keys.add_argument("--output-dir", default=".", help="Directory to store keys")
    init_keys.add_argument("--force", action="store_true", help="Overwrite existing keys")
    init_keys.add_argument("--quiet", action="store_true")
    init_keys.add_argument("--verbose", action="store_true")
    init_keys.set_defaults(func=_cmd_init_keys)

    sign = sub.add_parser("sign", help="Create a signed ownership bundle")
    sign.add_argument("file", help="Path to the media file")
    sign.add_argument("--creator-id", required=True, help="Creator identifier")
    sign.add_argument("--asset-id", required=True, help="Asset identifier")
    sign.add_argument("--intended-platforms", nargs="*", default=())
    sign.add_argument("--private-key", required=True, help="Path to private key PEM")
    sign.add_argument("--public-key", required=True, help="Path to public key PEM")
    sign.add_argument("--key-id", help="Optional key identifier")
    sign.add_argument("--show-origin-id", action="store_true", help="Print the derived ORIGIN ID")
    sign.add_argument("--output-dir", default="origin.bundle", help="Output directory")
    sign.add_argument("--force", action="store_true", help="Overwrite existing output")
    sign.add_argument("--quiet", action="store_true")
    sign.add_argument("--verbose", action="store_true")
    sign.set_defaults(func=_cmd_sign)

    verify = sub.add_parser("verify", help="Verify a signed bundle")
    verify.add_argument("bundle_dir", help="Path to bundle directory")
    verify.add_argument("--show-origin-id", action="store_true", help="Print ORIGIN ID if available")
    verify.add_argument("--quiet", action="store_true")
    verify.add_argument("--verbose", action="store_true")
    verify.set_defaults(func=_cmd_verify)

    seal = sub.add_parser("seal", help="Create a sealed media bundle")
    seal.add_argument("file", help="Path to the media file")
    seal.add_argument("--creator-id", required=True, help="Creator identifier")
    seal.add_argument("--asset-id", required=True, help="Asset identifier")
    seal.add_argument("--intended-platforms", nargs="*", default=())
    seal.add_argument("--private-key", required=True, help="Path to private key PEM")
    seal.add_argument("--public-key", required=True, help="Path to public key PEM")
    seal.add_argument("--key-id", help="Optional key identifier")
    seal.add_argument("--show-origin-id", action="store_true", help="Print the derived ORIGIN ID")
    seal.add_argument("--output", default="origin.bundle.zip", help="Output zip path")
    seal.add_argument("--force", action="store_true", help="Overwrite existing output")
    seal.add_argument("--quiet", action="store_true")
    seal.add_argument("--verbose", action="store_true")
    seal.set_defaults(func=_cmd_seal)

    verify_seal = sub.add_parser("verify-seal", help="Verify a sealed media bundle")
    verify_seal.add_argument("bundle_path", help="Path to sealed bundle zip")
    verify_seal.add_argument("--show-origin-id", action="store_true", help="Print ORIGIN ID if available")
    verify_seal.add_argument("--quiet", action="store_true")
    verify_seal.add_argument("--verbose", action="store_true")
    verify_seal.set_defaults(func=_cmd_verify_seal)

    policy_verify = sub.add_parser("policy-verify", help="Verify bundle with platform policy")
    policy_verify.add_argument("bundle_path", help="Path to bundle (dir or zip)")
    policy_group = policy_verify.add_mutually_exclusive_group()
    policy_group.add_argument("--sealed", action="store_true", help="Treat bundle as sealed zip")
    policy_group.add_argument("--file", help="Path to media file (unsealed bundles)")
    policy_verify.add_argument("--platform", help="Platform identifier")
    policy_verify.add_argument("--creator-id", help="Expected creator identifier")
    policy_verify.add_argument("--require-platform-match", action="store_true")
    policy_verify.add_argument("--require-seal", action="store_true")
    policy_verify.add_argument("--require-key-registry", action="store_true")
    policy_verify.add_argument("--require-key-id-match", action="store_true")
    policy_verify.add_argument("--key-registry", help="Path to key registry json")
    policy_verify.add_argument("--require-revocation-check", action="store_true")
    policy_verify.add_argument("--revocation-list", help="Path to revocation list json")
    policy_verify.add_argument("--require-attestation", action="store_true")
    policy_verify.add_argument("--attestation", help="Path to attestation json")
    policy_verify.add_argument("--attestation-sig", help="Path to attestation signature")
    policy_verify.add_argument("--trust-store", help="Path to trust store json")
    policy_verify.add_argument("--profile", choices=["strict", "standard", "permissive"], help="Policy profile")
    policy_verify.add_argument("--skip-content-hash", action="store_true")
    policy_verify.add_argument("--json", action="store_true", help="Output structured JSON result")
    policy_verify.add_argument("--localization", help="Path to localization JSON file")
    policy_verify.add_argument("--dry-run", action="store_true", help="Return success without enforcement")
    policy_verify.add_argument(
        "--exit-on-severity",
        choices=["critical", "high", "medium", "low"],
        help="Exit non-zero when any reason is at or above this severity",
    )
    policy_verify.add_argument("--quiet", action="store_true")
    policy_verify.add_argument("--verbose", action="store_true")
    policy_verify.set_defaults(func=_cmd_policy_verify)

    key_register = sub.add_parser("key-register", help="Register a public key in a registry")
    key_register.add_argument("--registry", required=True, help="Registry JSON path")
    key_register.add_argument("--creator-id", required=True)
    key_register.add_argument("--public-key", required=True)
    key_register.add_argument("--key-id", help="Optional key id override")
    key_register.add_argument("--valid-from", help="ISO8601 timestamp override")
    key_register.add_argument("--quiet", action="store_true")
    key_register.add_argument("--verbose", action="store_true")
    key_register.set_defaults(func=_cmd_key_register)

    key_revoke = sub.add_parser("key-revoke", help="Revoke a public key in a registry")
    key_revoke.add_argument("--registry", required=True, help="Registry JSON path")
    key_revoke.add_argument("--creator-id", required=True)
    key_revoke.add_argument("--key-id", required=True)
    key_revoke.add_argument("--superseded-by", help="New key id")
    key_revoke.add_argument("--quiet", action="store_true")
    key_revoke.add_argument("--verbose", action="store_true")
    key_revoke.set_defaults(func=_cmd_key_revoke)

    rev_init = sub.add_parser("revocation-init", help="Create a revocation list")
    rev_init.add_argument("--issuer-creator-id", required=True)
    rev_init.add_argument("--output", default="revocation_list.json")
    rev_init.add_argument("--force", action="store_true", help="Overwrite existing output")
    rev_init.add_argument("--quiet", action="store_true")
    rev_init.add_argument("--verbose", action="store_true")
    rev_init.set_defaults(func=_cmd_revocation_init)

    revoke = sub.add_parser("revoke", help="Add a revocation entry")
    revoke.add_argument("--revocation-list", required=True)
    revoke.add_argument("--creator-id", required=True)
    revoke.add_argument("--revoked-at", required=True)
    revoke.add_argument("--asset-id")
    revoke.add_argument("--content-hash")
    revoke.add_argument("--key-id")
    revoke.add_argument("--reason")
    revoke.add_argument("--quiet", action="store_true")
    revoke.add_argument("--verbose", action="store_true")
    revoke.set_defaults(func=_cmd_revoke)

    rev_sign = sub.add_parser("revocation-sign", help="Sign a revocation list")
    rev_sign.add_argument("--revocation-list", required=True)
    rev_sign.add_argument("--private-key", required=True)
    rev_sign.add_argument("--signature", default="revocation_list.ed25519")
    rev_sign.add_argument("--force", action="store_true", help="Overwrite existing output")
    rev_sign.add_argument("--quiet", action="store_true")
    rev_sign.add_argument("--verbose", action="store_true")
    rev_sign.set_defaults(func=_cmd_revocation_sign)

    rev_verify = sub.add_parser("revocation-verify", help="Verify a revocation list signature")
    rev_verify.add_argument("--revocation-list", required=True)
    rev_verify.add_argument("--public-key", required=True)
    rev_verify.add_argument("--signature", required=True)
    rev_verify.add_argument("--quiet", action="store_true")
    rev_verify.add_argument("--verbose", action="store_true")
    rev_verify.set_defaults(func=_cmd_revocation_verify)

    license_issue = sub.add_parser("license-issue", help="Issue a signed membership license")
    license_issue.add_argument("--user-id", required=True)
    license_issue.add_argument("--plan", required=True)
    license_issue.add_argument("--expires-at", required=True)
    license_issue.add_argument("--features", nargs="*", default=())
    license_issue.add_argument("--device-fingerprint")
    license_issue.add_argument("--max-devices", type=int)
    license_issue.add_argument("--offline-grace-days", type=int)
    license_issue.add_argument("--issuer-key-id")
    license_issue.add_argument("--private-key", required=True)
    license_issue.add_argument("--public-key", required=True)
    license_issue.add_argument("--output", default="membership.originlicense")
    license_issue.add_argument("--force", action="store_true", help="Overwrite existing output")
    license_issue.add_argument("--quiet", action="store_true")
    license_issue.add_argument("--verbose", action="store_true")
    license_issue.set_defaults(func=_cmd_license_issue)

    license_verify = sub.add_parser("license-verify", help="Verify a membership license")
    license_verify.add_argument("--license", required=True)
    license_verify.add_argument("--device-fingerprint")
    license_verify.add_argument("--quiet", action="store_true")
    license_verify.add_argument("--verbose", action="store_true")
    license_verify.set_defaults(func=_cmd_license_verify)

    ledger_init = sub.add_parser("license-ledger-init", help="Create a signed license revocation ledger")
    ledger_init.add_argument("--issuer-id", required=True)
    ledger_init.add_argument("--private-key", required=True)
    ledger_init.add_argument("--public-key", required=True)
    ledger_init.add_argument("--output", default="license_ledger.json")
    ledger_init.add_argument("--force", action="store_true", help="Overwrite existing output")
    ledger_init.add_argument("--quiet", action="store_true")
    ledger_init.add_argument("--verbose", action="store_true")
    ledger_init.set_defaults(func=_cmd_license_ledger_init)

    ledger_add = sub.add_parser("license-ledger-add", help="Add entry to a license revocation ledger")
    ledger_add.add_argument("--ledger", required=True)
    ledger_add.add_argument("--license-id", required=True)
    ledger_add.add_argument("--revoked-at", required=True)
    ledger_add.add_argument("--reason")
    ledger_add.add_argument("--updated-expires-at")
    ledger_add.add_argument("--updated-plan")
    ledger_add.add_argument("--updated-features", nargs="*")
    ledger_add.add_argument("--updated-device-fingerprint")
    ledger_add.add_argument("--private-key", required=True)
    ledger_add.add_argument("--public-key", required=True)
    ledger_add.add_argument("--output", default="license_ledger.json")
    ledger_add.add_argument("--quiet", action="store_true")
    ledger_add.add_argument("--verbose", action="store_true")
    ledger_add.set_defaults(func=_cmd_license_ledger_add)

    ledger_verify = sub.add_parser("license-ledger-verify", help="Verify a license revocation ledger")
    ledger_verify.add_argument("--ledger", required=True)
    ledger_verify.add_argument("--quiet", action="store_true")
    ledger_verify.add_argument("--verbose", action="store_true")
    ledger_verify.set_defaults(func=_cmd_license_ledger_verify)

    sidecar_embed = sub.add_parser("sidecar-embed", help="Create a sidecar file for media upload")
    sidecar_embed.add_argument("--bundle", required=True, help="Path to sealed bundle zip")
    sidecar_embed.add_argument("--media", required=True, help="Path to media file")
    sidecar_embed.add_argument("--output", default="origin.sidecar.json", help="Sidecar output path")
    sidecar_embed.add_argument("--force", action="store_true", help="Overwrite existing output")
    sidecar_embed.add_argument("--quiet", action="store_true")
    sidecar_embed.add_argument("--verbose", action="store_true")
    sidecar_embed.set_defaults(func=_cmd_sidecar_embed)

    sidecar_verify = sub.add_parser("sidecar-verify", help="Verify a sidecar against media")
    sidecar_verify.add_argument("--sidecar", required=True, help="Sidecar json path")
    sidecar_verify.add_argument("--media", required=True, help="Path to media file")
    sidecar_verify.add_argument("--quiet", action="store_true")
    sidecar_verify.add_argument("--verbose", action="store_true")
    sidecar_verify.set_defaults(func=_cmd_sidecar_verify)

    container_embed = sub.add_parser("container-embed", help="Embed Origin payload into media container")
    container_embed.add_argument("--bundle", required=True, help="Path to sealed bundle zip")
    container_embed.add_argument("--media", required=True, help="Path to media file")
    container_embed.add_argument("--format", default="sidecar", help="sidecar|mp4|mov|mkv")
    container_embed.add_argument("--output", default="origin.sidecar.json", help="Output path")
    container_embed.add_argument("--payload-signing-key", help="Private key PEM for payload signature")
    container_embed.add_argument("--force", action="store_true", help="Overwrite existing output")
    container_embed.add_argument("--quiet", action="store_true")
    container_embed.add_argument("--verbose", action="store_true")
    container_embed.set_defaults(func=_cmd_container_embed)

    extract_payload = sub.add_parser("extract-payload", help="Extract Origin payload from media or sidecar")
    extract_payload.add_argument("--media", required=True, help="Path to media or sidecar JSON")
    extract_payload.add_argument("--sidecar", help="Optional sidecar JSON path")
    extract_payload.add_argument("--output", help="Write payload JSON to file")
    extract_payload.add_argument("--validate", action="store_true", help="Validate payload schema")
    extract_payload.add_argument("--force", action="store_true", help="Overwrite existing output")
    extract_payload.add_argument("--quiet", action="store_true")
    extract_payload.add_argument("--verbose", action="store_true")
    extract_payload.set_defaults(func=_cmd_extract_payload)

    attest_issue = sub.add_parser("attest-issue", help="Issue a creator attestation")
    attest_issue.add_argument("--issuer-id", required=True)
    attest_issue.add_argument("--issuer-private-key", required=True)
    attest_issue.add_argument("--issuer-public-key", help="Issuer public key PEM")
    attest_issue.add_argument("--creator-id", required=True)
    attest_issue.add_argument("--key-id", required=True)
    attest_issue.add_argument("--public-key", required=True, help="Subject public key PEM")
    attest_issue.add_argument("--attestation-type", default="creator_identity")
    attest_issue.add_argument("--attestation-id", help="Override attestation id")
    attest_issue.add_argument("--not-before", help="Optional ISO8601 not-before")
    attest_issue.add_argument("--expires-at", help="Optional ISO8601 expiration")
    attest_issue.add_argument("--platform-binding", help="Optional platform binding")
    attest_issue.add_argument("--usage-constraints", nargs="*", default=None)
    attest_issue.add_argument("--region", help="Optional region")
    attest_issue.add_argument("--expiration-policy", help="Optional expiration policy reference")
    attest_issue.add_argument("--purpose", help="Optional attestation purpose")
    attest_issue.add_argument("--output", default="origin.attestation.json")
    attest_issue.add_argument("--signature", default="attestation.ed25519")
    attest_issue.add_argument("--force", action="store_true", help="Overwrite existing output")
    attest_issue.add_argument("--quiet", action="store_true")
    attest_issue.add_argument("--verbose", action="store_true")
    attest_issue.set_defaults(func=_cmd_attest_issue)

    attest_verify = sub.add_parser("attest-verify", help="Verify a creator attestation")
    attest_verify.add_argument("--attestation", required=True)
    attest_verify.add_argument("--signature", required=True)
    attest_verify.add_argument("--issuer-public-key", required=True)
    attest_verify.add_argument("--quiet", action="store_true")
    attest_verify.add_argument("--verbose", action="store_true")
    attest_verify.set_defaults(func=_cmd_attest_verify)

    trust_store = sub.add_parser("trust-store-init", help="Create a trust store of issuer keys")
    trust_store.add_argument("--issuer-id", required=True)
    trust_store.add_argument("--issuer-public-keys", nargs="+", required=True)
    trust_store.add_argument("--valid-from", default=datetime.now(timezone.utc).isoformat())
    trust_store.add_argument("--valid-to", help="Optional ISO8601 valid-to")
    trust_store.add_argument("--output", default="origin.truststore.json")
    trust_store.add_argument("--force", action="store_true", help="Overwrite existing output")
    trust_store.add_argument("--quiet", action="store_true")
    trust_store.add_argument("--verbose", action="store_true")
    trust_store.set_defaults(func=_cmd_trust_store_init)

    version = sub.add_parser("version", help="Show CLI and schema versions")
    version.add_argument("--quiet", action="store_true")
    version.add_argument("--verbose", action="store_true")
    version.set_defaults(func=_cmd_version)

    validate = sub.add_parser("validate", help="Validate Origin JSON artifacts")
    validate.add_argument("--kind", required=True, choices=[
        "manifest",
        "bundle",
        "seal",
        "attestation",
        "origin-payload",
        "trust-store",
        "registry",
        "revocation-list",
    ])
    validate.add_argument("--path", required=True)
    validate.add_argument("--fast-fail", action="store_true", help="Stop at the first validation error")
    validate.add_argument("--quiet", action="store_true")
    validate.add_argument("--verbose", action="store_true")
    validate.set_defaults(func=_cmd_validate)

    explain = sub.add_parser("explain", help="Explain bundle or attestation")
    explain_group = explain.add_mutually_exclusive_group(required=True)
    explain_group.add_argument("--bundle", help="Path to bundle directory or zip")
    explain_group.add_argument("--attestation", help="Path to attestation JSON")
    explain.add_argument("--sealed", action="store_true", help="Treat bundle as sealed zip")
    explain.add_argument("--show-origin-id", action="store_true", help="Print ORIGIN ID if available")
    explain.add_argument("--quiet", action="store_true")
    explain.add_argument("--verbose", action="store_true")
    explain.set_defaults(func=_cmd_explain)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
