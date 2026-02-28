# ORIGIN Security Posture (v1)

This document summarizes the threat model, replay/tamper guidance, and key rotation policy for Origin Protocol.

## Threat model (summary)
- **Tampering:** attacker modifies manifest, seal, bundle, or sidecar.
- **Replay:** attacker re‑uploads a valid proof with altered media or outside intended context.
- **Key compromise:** attacker obtains a creator’s private key.
- **Registry abuse:** untrusted keys appear as trusted without governance.
- **Downgrade:** attacker targets older schemas or weak verification settings.

## Integrity controls
- **Ed25519 signatures** protect manifest, seal, bundle manifests, attestations.
- **SHA‑256 hashes** bind media bytes to the manifest and seal.
- **Deterministic canonicalization** ensures consistent hashes across platforms.
- **ORIGIN ID** (UUIDv5 of key_id + content_hash) provides a stable asset identifier.

## Experimental identity state signatures
- Identity state signatures are **Ed25519** (not HMAC/SHA).
- Signature format: `ed25519:<key_id>:<base64_signature>`.
- `key_id` must match the signing public key fingerprint.
- Verification requires the state payload and the matching public key.

## Replay and tamper guidance
- Always verify:
  - manifest signature
  - seal signature
  - bundle.json signature
  - content hashes against media bytes
- Enforce **intended_platforms** where applicable.
- Use **key registry** and **revocation lists** for trust decisions.
- Reject bundles if any hash or signature fails (see error codes).
- Platforms should bind `asset_id → creator_id` and optionally a binary fingerprint to prevent re‑uploads.

## Key rotation policy
- Creators should rotate keys on compromise or policy requirements.
- Registries SHOULD record:
  - `status: revoked`
  - `superseded_by: <new_key_id>`
- Platforms SHOULD:
  - reject revoked keys
  - accept new keys only after registry update
- Historical proofs remain valid if the key was valid at issue time and not retroactively revoked for fraud.

## Governance and trust anchors
- Trust anchors are defined by the bootstrap file and governance CID.
- Any change to governance inputs requires a new versioned bootstrap + signed checksum.

## Implementation checklist
- Verify all signatures and hashes.
- Enforce registry and revocation checks for standard/strict profiles.
- Require attestation for strict profile.
- Log rejection codes and request IDs for auditability.
