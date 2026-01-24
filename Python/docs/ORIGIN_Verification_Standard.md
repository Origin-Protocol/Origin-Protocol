# ORIGIN Verification Standard (Draft v0.2)

This document defines the **platform-side** verification rules for Origin Protocol bundles.

## 1) Scope
Applies to:
- **Sealed bundle** (zip): bundle.json + bundle.sig + manifest + seal + media
- **Unsealed bundle** (directory): manifest + signature + public key

## 2) Required artifacts
### Sealed bundle (zip)
- bundle.json (hashes of all internal files)
- bundle.sig (signature over bundle.json)
- manifest.json
- signature.ed25519
- public_key.ed25519
- seal.json
- seal.ed25519
- media/<filename>

bundle.json includes:
- bundle_id
- origin_schema
- bundle_type
- bundle_version
- manifest_hash, seal_hash, media_hash (optional but recommended)
- signature_algorithm
- canonicalization

### Unsealed bundle (dir)
- manifest.json
- signature.ed25519
- public_key.ed25519

## 2.1) ORIGIN ID (manifest.origin_id)
ORIGIN ID is a stable, canonical identifier for an asset.

**Definition**
- `origin_id` is a deterministic UUID derived from `content_hash` and the creator key fingerprint (`key_id`).

**Derivation**
- `origin_id = UUIDv5("origin-protocol:origin-id", "<key_id>:<content_hash>")`

**Rules**
- If `origin_id` is present, verifiers MUST recompute and compare.
- If `key_id` is present, creators SHOULD include `origin_id` in the manifest.

## 3) Canonicalization (sealed bundles)
- Deterministic ordering of entries by path.
- Fixed timestamps in zip headers.
- Deterministic compression parameters.
- bundle.json is the canonical file list; bundle.sig authenticates it.

## 4) Verification steps
### Sealed bundle (MUST)
1. Verify bundle.sig over bundle.json using public_key.ed25519.
2. Ensure bundle.json file list equals the zip contents (excluding bundle.json, bundle.sig).
3. Hash each listed file and compare to bundle.json.
4. Verify manifest signature (signature.ed25519) over manifest.json.
5. Verify seal signature (seal.ed25519) over seal.json.
6. If bundle.json includes manifest_hash/seal_hash/media_hash, verify they match manifest.json, seal.json, and media bytes.
6. Verify seal.media_path exists in bundle.
7. Verify seal.content_hash == SHA-256(media bytes).
8. Verify manifest.content_hash == seal.content_hash.
9. If manifest.key_id exists, verify it matches the public key fingerprint.

### Embedded payload verification (MP4/MOV/MKV)
- Validate embedded payload schema and origin_uuid.
- Verify bundle_hash matches hash of sealed bundle.
- Verify manifest_hash matches manifest.json.
- Verify seal_hash matches seal.json.
- Verify media_hash matches the container media bytes.
- Verify key_id matches manifest or public key fingerprint.

### Signature chain logic
- public_key.ed25519 authenticates:
	- bundle.json via bundle.sig
	- manifest.json via signature.ed25519
	- seal.json via seal.ed25519
- bundle.json authenticates the integrity of all bundled artifacts.
- seal.json binds media bytes to manifest.json.

### Unsealed bundle (MUST)
1. Verify manifest signature (signature.ed25519) over manifest.json.
2. If a media file is available, verify manifest.content_hash matches SHA-256(media).
3. If manifest.key_id exists, verify it matches the public key fingerprint.

## 5) Policy layer (platform configurable)
Platforms may enforce:
- **Intended platform match** (manifest.intended_platforms contains platform id).
- **Creator identity match** (manifest.creator_id equals platform account).
- **Key registry** (key_id must be active in registry).
- **Revocation list** (manifest not revoked by asset_id, content_hash, or key_id).
- **Attestation** (creator key must be signed by trusted issuer).

### Policy profiles
- **strict**: require seal, platform match, key registry, key id match, revocation check, attestation.
- **standard**: require seal, platform match, key registry, key id match, revocation check.
- **permissive**: only verify signatures and hashes unless explicitly requested.

## Canonicalization
Follow [ORIGIN_Canonicalization.md](ORIGIN_Canonicalization.md).

## 6) Rejection reasons (recommended)

## 9) Logging and enforcement
- Log rejection codes and severities.
- STRICT: reject any critical/high reason.
- STANDARD: reject critical/high; warn on medium/low.
- PERMISSIVE: reject critical; warn on high/medium/low.

## 7) Trust anchors (future)
- Platform-issued key attestations or certificates.
- Consortium or decentralized trust roots.

## 8) Compatibility
- origin_version is required in all manifests and lists.
- Platforms may support multiple versions in parallel.
