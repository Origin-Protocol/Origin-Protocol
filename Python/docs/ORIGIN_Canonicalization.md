# ORIGIN Canonicalization Rules (Draft v0.2)

## Goal
Ensure deterministic, reproducible bundles and signatures across platforms.

## JSON canonicalization
- UTF-8 encoding
- Sorted keys
- No whitespace: separators (",", ":")
- Omit keys with null/None values

## Origin payload canonicalization
- Same JSON rules as above.
- Payload schema: docs/origin_payload.schema.json.
- Sidecar and container payload bytes MUST be canonical JSON.

## Zip canonicalization (sealed bundles)
- Deterministic file ordering by path
- Fixed timestamps for zip headers
- Deterministic compression (level 9)
- No extra metadata fields

## Bundle manifest (bundle.json)
- Contains SHA-256 hashes for every file in the zip (except bundle.json, bundle.sig)
- Sorted by path

## Sidecar canonicalization
- Payload is base64 encoding of the same files listed in bundle.json
- Verification MUST re-hash payload file bytes and compare with bundle.json
