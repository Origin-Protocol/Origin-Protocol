# Origin Protocol (Python)

Creator-controlled metadata + signatures for pre-upload ownership proofs.

Current version: 1.0

## What this is
A minimal Python SDK + CLI that lets creators:
- generate signing keys
- hash a media file
- create an ownership manifest
- sign the manifest
- export a portable bundle for platform-side verification
- seal the media + manifest into a single bundle

This is the **first building block** for a universal, creator-side protection layer.

## Quick start
1) Create a virtual environment and install deps.
2) Generate keys.
3) Sign a file to produce a bundle.
4) Verify the bundle.

## CLI overview
- `origin init-keys` → generate Ed25519 keypair
- `origin sign <file>` → produce a signed bundle
- `origin verify <file>` → verify a bundle
- `origin seal <file>` → produce a sealed media bundle (zip)
- `origin verify-seal <file>` → verify a sealed media bundle
- `origin policy-verify <bundle>` → verify with policy rules

Policy profiles for verification:
- `--profile strict`, `--profile standard`, or `--profile permissive`

Structured output:
- `origin policy-verify ... --json`

Localization and exit codes:
- `--localization docs/locales/en.json`
- `--exit-on-severity critical|high|medium|low`
- `origin key-register` → add a public key to a registry
- `origin key-revoke` → revoke a key in the registry
- `origin revocation-init` → create a revocation list
- `origin revoke` → add a revocation entry
- `origin revocation-sign` → sign a revocation list
- `origin revocation-verify` → verify a revocation list
- `origin sidecar-embed` → create a sidecar for media upload
- `origin sidecar-verify` → verify a sidecar against media
- `origin container-embed` → embed payload into container (sidecar/mp4/mkv)
- `origin attest-issue` → issue a creator attestation
- `origin attest-verify` → verify a creator attestation
- `origin trust-store-init` → create a trust store
- `origin license-issue` → issue a signed membership license
- `origin license-verify` → verify a membership license
- `origin license-ledger-init` → create a signed license revocation ledger
- `origin license-ledger-add` → add entry to a license ledger
- `origin license-ledger-verify` → verify a license ledger

## Bundle format
A bundle is a folder containing:
- `manifest.json` (ownership metadata)
- `signature.ed25519` (signature for the manifest)
- `public_key.ed25519` (public key for verification)

## Sealed bundle format
A sealed bundle is a single zip containing:
- `bundle.json` (hashes of all internal files)
- `bundle.sig` (signature over bundle.json)
- `manifest.json`
- `signature.ed25519`
- `public_key.ed25519`
- `seal.json` (binds media + manifest)
- `seal.ed25519` (signature for the seal)
- `media/<filename>` (the original media file)

## Container embedding
See the draft spec in [docs/ORIGIN_Container_Embedding.md](docs/ORIGIN_Container_Embedding.md).

## Attestation
See the draft spec in [docs/ORIGIN_Attestation.md](docs/ORIGIN_Attestation.md).

## Trust & governance
See [docs/ORIGIN_Trust_Governance.md](docs/ORIGIN_Trust_Governance.md).

## Membership licenses
See [docs/ORIGIN_License.md](docs/ORIGIN_License.md).

## Node network registry
See [docs/ORIGIN_Node_Network.md](docs/ORIGIN_Node_Network.md).

## Node registry reference implementation
See [docs/ORIGIN_Node_Registry_Reference.md](docs/ORIGIN_Node_Registry_Reference.md).

## Canonicalization
See the draft spec in [docs/ORIGIN_Canonicalization.md](docs/ORIGIN_Canonicalization.md).

Canonicalization test vectors:
- [docs/ORIGIN_Canonicalization_Test_Vectors.md](docs/ORIGIN_Canonicalization_Test_Vectors.md)

Sealed bundle test vectors:
- [docs/ORIGIN_Sealed_Bundle_Test_Vectors.md](docs/ORIGIN_Sealed_Bundle_Test_Vectors.md)

## Platform SDKs
- JS sidecar verifier: [sdks/js/README.md](sdks/js/README.md)
- Go sidecar verifier: [sdks/go/README.md](sdks/go/README.md)

## Platform SDK (Python)
See [docs/ORIGIN_Platform_SDK.md](docs/ORIGIN_Platform_SDK.md).

## Billing automation (PayPal IPN)
See [docs/ORIGIN_PayPal_IPN.md](docs/ORIGIN_PayPal_IPN.md) for automated license issuance and revocation using PayPal IPN.

## Error metadata
Rejections include category, subcategory, severity, is_fatal, actions, remediation, and localization/docs links.

## Versioning
This project follows semantic versioning (MAJOR.MINOR.PATCH). See [CHANGELOG.md](CHANGELOG.md).

## Fixtures
Illustrative examples are in [docs/fixtures/README.md](docs/fixtures/README.md).

The manifest includes:
- `creator_id`
- `asset_id`
- `created_at`
- `content_hash` (SHA-256 of the file)
- `intended_platforms`
- `key_id` (public key fingerprint, optional)
- `origin_version`

## Key registry format
A registry is a JSON file containing key records:
- `creator_id`
- `key_id`
- `public_key` (PEM)
- `status` (`active` or `revoked`)
- `valid_from`
- `valid_to` (optional)
- `superseded_by` (optional)

## Revocation list format
A revocation list is a JSON file containing entries:
- `creator_id`
- `revoked_at`
- `asset_id` or `content_hash` or `key_id`
- `reason` (optional)

