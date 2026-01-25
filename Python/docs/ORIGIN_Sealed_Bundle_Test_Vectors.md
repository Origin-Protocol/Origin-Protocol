# ORIGIN Sealed Bundle Test Vectors (v1)

This document defines deterministic sealed bundle vectors for cross‑SDK verification.

## Vector files
- [docs/fixtures/sealed_bundle_vector.zip](docs/fixtures/sealed_bundle_vector.zip)
- [docs/fixtures/sealed_bundle_vector.json](docs/fixtures/sealed_bundle_vector.json)

## Contents
The sealed bundle zip includes:
- `bundle.json` and `bundle.sig`
- `manifest.json` and `signature.ed25519`
- `public_key.ed25519`
- `seal.json` and `seal.ed25519`
- `media/vector.mp4`

## Verification steps
1) Read the zip and compute the SHA‑256 hash; compare with `sealed_bundle_vector.json` → `sha256`.
2) Verify `bundle.sig` against `bundle.json` using the included public key.
3) Verify `seal.ed25519` against `seal.json`.
4) Verify `signature.ed25519` against `manifest.json`.
5) Confirm all hashes in `bundle.json` match their respective files.

## Determinism
The vector uses ZIP STORED (no compression), fixed timestamps, and a deterministic Ed25519 key, so the zip hash is stable across SDKs.
