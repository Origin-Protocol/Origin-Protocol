# ORIGIN License Ledger Hosting Guidance (v1)

This guide describes how to host and distribute the signed license revocation ledger used by the Origin license tooling.

## Purpose
The license ledger is a signed, append‑only record of license revocations or updates. Clients download the ledger, verify the signature, and apply revocations locally.

## Artifact format
The CLI writes a single JSON file containing:
- `ledger`: the canonical ledger payload
- `signature`: base64 Ed25519 signature over the canonical ledger JSON
- `public_key`: PEM public key used to verify the signature

The canonical ledger payload includes:
- `ledger_id`, `issuer_id`, `created_at`
- `entries[]` with `license_id`, `revoked_at`, and optional update fields
- `signature_algorithm` (expected: `ed25519`)
- `origin_version`

## Recommended hosting model
Use a simple, immutable file hosting model and provide a stable URL for clients:
- Store the ledger file as a static object (S3, GCS, or a CDN).
- Serve over HTTPS only.
- Set a short cache TTL (e.g., 5–15 minutes) to balance freshness and load.
- Prefer content‑addressed versions for auditability:
  - `/license-ledger/latest.json`
  - `/license-ledger/sha256/<digest>.json`

## Update workflow
1) Initialize a ledger with `origin license-ledger-init`.
2) Add entries with `origin license-ledger-add`.
3) Sign and write with `origin license-ledger-verify` or a signing step in your pipeline.
4) Upload the updated JSON to the hosting location.
5) Update `latest.json` to point to the new signed ledger file.

## Client verification steps
Clients should:
- Fetch the ledger file.
- Verify the Ed25519 signature over the canonical ledger payload.
- Validate `issuer_id`, `origin_version`, and `signature_algorithm`.
- Apply revocations and updates deterministically.

## Key rotation
If the issuer key rotates:
- Publish a new ledger signed by the new key.
- Update your trust store or registry with the new `key_id` → `public_key` mapping.
- Keep the old ledger accessible for auditing.

## Operational guidance
- Back up prior ledgers for auditability.
- Log ledger SHA‑256 digests for each published version.
- Reject ledgers that fail signature verification or that regress `created_at`.

## Example directory layout
```
/license-ledger/
  latest.json
  sha256/
    1a2b...9f.json
    6c4d...aa.json
```

## Related CLI commands
- `origin license-ledger-init`
- `origin license-ledger-add`
- `origin license-ledger-verify`
