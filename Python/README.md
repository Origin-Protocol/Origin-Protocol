## Origin Protocol (Python)

A creator‑controlled authenticity layer for pre‑upload ownership proofs, independent of platforms and file formats.

Creator-controlled metadata + signatures for pre-upload ownership proofs.

## Executive summary
Overall design is solid: layered artifacts (manifest, seal, bundle, container payload), deterministic canonicalization for signing, and multi‑language verifier SDKs are present.

Major gaps that block production‑grade security and scaling:
- Experimental identity state signatures must use asymmetric signing (Ed25519) or explicit HMAC only.
- Large‑file handling and memory use need streaming paths end‑to‑end.
- ZIP/compression determinism requires a reproducible spec or STORED mode.
- Key management/trust discovery needs clear registry and revocation workflows.
- Cross‑SDK canonicalization/interop vectors are incomplete.
- Repo hygiene: LICENSE, CI, packaging metadata, and more tests.

Top findings and risks (by severity):
- **Critical:** experimental identity uses weak authenticity (state_identity.py).
- **High:** key management & trust‑discovery not fully defined.
- **High:** large files/memory usage not fully streaming.
- **High:** ZIP compression determinism risk.
- **Medium:** created_at ordering should parse datetimes.
- **Medium:** canonicalization & cross‑SDK compatibility incomplete.
- **Medium:** per‑signature metadata envelope not always present.
- **Medium:** diagnostic vs fast‑fail error reporting tradeoffs.
- **Low:** docs/CI/LICENSE/packaging/test vectors.

Prioritized action plan (short list):
1) Fix experimental identity signatures (Ed25519 or explicit HMAC) — Critical.
2) Stream bundle/media hashing and zip reads/writes — High.
3) Add STORED/no‑compression option or define deterministic compression — High.
4) Parse created_at to datetimes for payload selection — Medium.
5) Publish canonicalization spec and interop test vectors — Medium.
6) Include per‑signature metadata (key_id, algorithm) in payload/manifest — Medium.
7) Add CI, LICENSE, packaging metadata, signed fixtures — Low.

## Install
- `pip install origin-protocol`
- or `pip install -r requirements.txt`

Current version: 0.2.0

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
	- `python -m venv .venv`
	- `source .venv/bin/activate` (macOS/Linux) or `.venv\Scripts\activate` (Windows)
	- `pip install -r requirements.txt`
2) Generate keys.
	- `origin init-keys --output-dir ./keys`
3) Sign a file to produce a bundle.
	- `origin sign ./media.mp4 --creator-id creator-123 --asset-id asset-123 --public-key ./keys/public_key.ed25519 --private-key ./keys/private_key.ed25519 --output-dir ./origin.bundle`
4) Verify the bundle.
	- `origin verify ./origin.bundle`

## Verification pipeline overview
media → hash → manifest → sign → bundle → seal → verify

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
- `origin registry-sign` → sign a key registry file
- `origin registry-verify` → verify a signed key registry
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

Example CLI output (with ORIGIN ID):
- Creator: creator-123
- Asset: asset-123
- Origin ID: 746fba9f-4c5c-5fcf-8621-0765dd99f750
- Hash: c6f7611b0406f2a66b33f5bb05c8acfa2bd3dc7cd7aef12d0f2d087c6efc8a56

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

`bundle.json` may include `media_summary` (filename, mime_type, size bytes) for quick platform decisions.

## Container embedding
See the draft spec in [docs/ORIGIN_Container_Embedding.md](docs/ORIGIN_Container_Embedding.md).

## Attestation
See the draft spec in [docs/ORIGIN_Attestation.md](docs/ORIGIN_Attestation.md).

## Trust & governance
See [docs/ORIGIN_Trust_Governance.md](docs/ORIGIN_Trust_Governance.md).

## Trust anchor package
See [docs/ORIGIN_Trust_Anchor_Package.md](docs/ORIGIN_Trust_Anchor_Package.md) for bootstrap, governance CID, and checksum flow.

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

Canonicalization rules (implementation reference):
- Bundle entries are ordered by path (ascending).
- ZIP metadata is fixed (timestamp 1980-01-01, zeroed flags/attrs).
- Compression uses DEFLATED with a fixed compresslevel by default; for bit‑for‑bit reproducibility across environments, use STORED (no compression).

## Platform SDKs
- JS sidecar verifier: [sdks/js/README.md](sdks/js/README.md)
- Go sidecar verifier: [sdks/go/README.md](sdks/go/README.md)

## Platform SDK (Python)
See [docs/ORIGIN_Platform_SDK.md](docs/ORIGIN_Platform_SDK.md).

## Reference integrations
See [docs/ORIGIN_Integration_Cookbook.md](docs/ORIGIN_Integration_Cookbook.md) for Python/JS/Go snippets and a cURL cookbook.

## Staging ledger service
See [docs/ORIGIN_Staging_Ledger_Service.md](docs/ORIGIN_Staging_Ledger_Service.md) for base URL, API keys, rate limits, and metrics.

## Platform onboarding kit
See [docs/ORIGIN_Onboarding_Checklist.md](docs/ORIGIN_Onboarding_Checklist.md) and [docs/ORIGIN_SLA_Guidelines.md](docs/ORIGIN_SLA_Guidelines.md).

## Public telemetry
See [docs/ORIGIN_Public_Telemetry.md](docs/ORIGIN_Public_Telemetry.md) for uptime, status, and audit log format.

## License ledger hosting guidance
See [docs/ORIGIN_License_Ledger_Hosting.md](docs/ORIGIN_License_Ledger_Hosting.md).

## Platform integration in 30 seconds
POST /v1/ledger/verify
```
{
	"creator_id": "...",
	"key_id": "...",
	"asset_id": "...",
	"origin_id": "...",
	"content_hash": "...",
	"platform_id": "yt"
}
```

## Error metadata
Rejections include category, subcategory, severity, is_fatal, actions, remediation, and localization/docs links.
See [docs/ORIGIN_Error_Codes_v1.md](docs/ORIGIN_Error_Codes_v1.md) for the frozen v1 list.

## Security posture
See [docs/ORIGIN_Security_Posture.md](docs/ORIGIN_Security_Posture.md) for threat model, replay/tamper guidance, and key rotation policy.

## Versioning
This project follows semantic versioning (MAJOR.MINOR.PATCH). See [CHANGELOG.md](CHANGELOG.md).

## Stability guarantees
- Frozen API contract (v1)
- Frozen OpenAPI schema (v1)
- Frozen error codes (v1)
- Deterministic ORIGIN ID derivation

## Fixtures
Illustrative examples are in [docs/fixtures/README.md](docs/fixtures/README.md).

The manifest includes:
- `creator_id`
- `asset_id`
- `origin_id` (deterministic UUID from `key_id` + `content_hash`)
- `created_at`
- `content_hash` (SHA-256 of the file)
- `intended_platforms`
- `key_id` (public key fingerprint, optional)
- `origin_version`

Notes:
- `origin_version` should be treated as a protocol version and kept consistent across SDKs.
- Signing uses the compact canonical JSON (see canonicalization rules), while the on‑disk manifest may be pretty‑printed for readability.
- `origin_id` is only present when `key_id` is set.

## Why ORIGIN ID exists
ORIGIN ID is the canonical, stable identifier for an asset in the Origin ecosystem.
It is deterministic, portable, and independent of platform, filename, or internal product tooling.

Definition:
- `origin_id = UUIDv5("origin-protocol:origin-id", "<key_id>:<content_hash>")`

## What’s public vs private
Public (standard): protocol specs, schemas, verification logic, trust anchors, governance CIDs, SDKs, and documentation.
Private (product): creator tooling, licensing/billing logic, internal roadmaps, and experimental R&D.

## Security model summary
- Ed25519 signatures for authenticity
- SHA‑256 hashing for integrity
- Deterministic manifests and ORIGIN ID for reproducibility
- Tamper detection via hash and signature verification
- Revocation semantics for key and asset trust

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

