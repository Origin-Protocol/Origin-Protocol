# ORIGIN Container Embedding (Draft v0.2)

## Goal
Embed Origin metadata into **media containers** (MP4/MOV/MKV) so platforms can verify uploads without ZIPs.

## Payload schema (embedded)
Embedded payload JSON includes:
- origin_schema
- origin_uuid
- created_at
- nonce
- bundle_hash (SHA-256 of bundle.json bytes)
- manifest_hash
- seal_hash
- media_hash
- key_id
- bundle.json includes bundle_id, bundle_type, bundle_version, signature_algorithm, canonical_order
- payload (bundle.json, bundle.sig, manifest.json, signature.ed25519, seal.json, seal.ed25519, public_key.ed25519)
- box_signature (MP4/MOV only, optional)
- tag_signature (MKV only, optional)
- attestation_ref (optional)
- registry_ref (optional)
- revocation_ref (optional)

### Container signature semantics
- Container signatures are optional and are verified against the same public key used for the bundle.
- key_id in the signature payload MUST match the manifest key_id.
- Container signatures do not imply a separate authority unless explicitly documented by the platform.

## Interim (Sidecar) Mode
Until native container atoms are implemented, use a sidecar JSON file.

### Sidecar fields
- origin_schema
- origin_uuid
- created_at
- nonce
- media_filename
- bundle_hash (SHA-256 of bundle.json bytes)
- manifest_hash
- seal_hash
- media_hash
- key_id
- payload:
  - bundle.json
  - bundle.sig
  - manifest.json
  - signature.ed25519
  - seal.json
  - seal.ed25519
  - public_key.ed25519
- attestation_ref (optional)
- registry_ref (optional)
- revocation_ref (optional)

### Verification
- Validate payload schema and origin_uuid.
- Verify bundle.sig over bundle.json (bundle.sig may be a JSON envelope).
- Check hashes in bundle.json for all payload files.
- Verify manifest and seal signatures.
- Verify media SHA-256 matches seal.content_hash.
- Verify manifest_hash and seal_hash fields match computed values.
- Verify key_id matches manifest or computed public-key fingerprint.
- Verify media_filename matches the media file and seal media_path.

## MP4/MOV embedding
- Use `udta` or `meta` boxes.
- Store Origin payload as a `uuid` box with a fixed namespace UUID.
- Payload bytes are the canonical JSON of the Origin payload v2.
- Deterministic ordering and canonical JSON are required for reproducibility.

## MP4/MOV implementation (current)
- `origin container-embed --format mp4|mov` inserts a `uuid` box under `moov/udta` when possible.
- Falls back to appending a `uuid` box if no `moov` box is detected.
- UUID namespace: `e1b1c6b2-4d0a-4b40-9a1c-5d1d8f0e9c2a`.

## MKV embedding
- Use Matroska `Tags` element.
- Define a `SimpleTag` with Name="ORIGIN" and Value as payload bytes.

## MKV implementation (current)
- `origin container-embed --format mkv` appends a Tags element with a SimpleTag named `ORIGIN`.

## Implementation status
- Sidecar supported via CLI.
- Native MP4/MOV/MKV embedding is supported via payload appenders.
- Payload validation and extraction helpers are available in the SDK.

## Notes
- The payload is cryptographically sealed via bundle.json + bundle.sig.
- Canonical JSON rules: UTF-8, sorted keys, no whitespace, no comments.
- Platform implementations should not rely on ZIPs once container embedding is finalized.
- JSON schema: docs/origin_payload.schema.json.
