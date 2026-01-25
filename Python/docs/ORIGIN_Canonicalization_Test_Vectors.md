# ORIGIN Canonicalization Test Vectors (v1)

This document defines deterministic interop vectors for cross‑SDK signature verification.

## Vector file
See [docs/fixtures/canonical_signature_vector.json](docs/fixtures/canonical_signature_vector.json).

It includes:
- `manifest`: the JSON object used for canonicalization
- `canonical_json`: the canonical JSON string (sorted keys, `,`/`:` separators)
- `sha256`: SHA‑256 of `canonical_json`
- `public_key_pem`: Ed25519 public key (PEM)
- `signature_base64`: Ed25519 signature over `canonical_json`

## Verification steps
1) Parse `canonical_json` as UTF‑8 bytes.
2) Compute SHA‑256 and compare with `sha256`.
3) Verify Ed25519 signature using `public_key_pem`.

## Notes
- The canonicalization rules are identical across SDKs: `sort_keys=True`, separators `","` and `":"`.
- The signature is over the canonical JSON bytes, not the pretty‑printed manifest file.
