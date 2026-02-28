# ORIGIN Attestation (Draft v0.1)

## Goal
Provide a **trust anchor** that binds a creator identity to a public key.

## Files
- attestation.json
- attestation.ed25519 (signature by issuer)
- trust_store.json (list of issuer public keys)

## Attestation fields
- issuer_id
- subject_creator_id
- subject_key_id
- subject_public_key (PEM)
- issued_at
- expires_at (optional)
- platform_binding (optional)
- usage_constraints (optional)
- region (optional)
- expiration_policy (optional)
- origin_version

## Verification
1. Load trust_store.json issuer public keys.
2. Verify attestation.ed25519 over attestation.json.
3. Ensure subject_creator_id == manifest.creator_id.
4. Ensure subject_key_id == manifest.key_id (if present).
5. Ensure subject_public_key matches the bundle public key.
6. Reject if expired (if expires_at is present).

## Optional semantics
- platform_binding: platform identifier(s) the key is valid for.
- usage_constraints: human-readable usage tags (e.g., "upload", "live", "shorts").
- region: region or jurisdiction scope.
- expiration_policy: issuer policy description or reference.

## CLI
- origin attest-issue
- origin attest-verify
- origin trust-store-init
