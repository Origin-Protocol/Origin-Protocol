# Origin License — Offline Membership Model

## Overview
Origin License treats membership as a signed asset. A license file is a cryptographically signed JSON payload verified locally by the app (no server required).

A lightweight **license revocation ledger** (signed JSON) allows cancellations, upgrades, and device re‑bindings to propagate within 24 hours.

## License payload
A license payload includes:
- `license_id`
- `user_id` (email or hashed identifier)
- `plan`
- `issued_at`
- `expires_at`
- `features` (optional)
- `device_fingerprint` (optional)
- `max_devices` (optional)
- `offline_grace_days` (optional)
- `issuer_key_id` (optional)

The payload is signed with Ed25519 and saved in a `*.originlicense` file.

## License file format
```json
{
  "license": { "...": "..." },
  "signature": "base64-ed25519-signature",
  "public_key": "-----BEGIN PUBLIC KEY-----..."
}
```

## Revocation ledger
A signed ledger is published daily as a static JSON file. It lists revoked licenses and optional updates.

```json
{
  "ledger": { "...": "..." },
  "signature": "base64-ed25519-signature",
  "public_key": "-----BEGIN PUBLIC KEY-----..."
}
```

### Ledger entries
Each entry can include:
- `license_id`
- `revoked_at`
- `reason` (optional)
- `updated_expires_at` (optional)
- `updated_plan` (optional)
- `updated_features` (optional)
- `updated_device_fingerprint` (optional)

## CLI usage
Issue a license:
- `origin license-issue --user-id user@example.com --plan pro --expires-at 2026-12-31T00:00:00Z --private-key private_key.ed25519 --public-key public_key.ed25519 --output membership.originlicense`

Verify a license:
- `origin license-verify --license membership.originlicense --device-fingerprint <fingerprint>`

Create a signed ledger:
- `origin license-ledger-init --issuer-id origin --private-key private_key.ed25519 --public-key public_key.ed25519 --output license_ledger.json`

Add a revocation entry:
- `origin license-ledger-add --ledger license_ledger.json --license-id <id> --revoked-at 2026-01-18T00:00:00Z --private-key private_key.ed25519 --public-key public_key.ed25519 --output license_ledger.json`

Verify a ledger:
- `origin license-ledger-verify --ledger license_ledger.json`

## Client enforcement logic (recommended)
1. Load license file.
2. Verify license signature.
3. Enforce expiry and device binding.
4. Once per day, fetch signed ledger and verify.
5. Apply revocations or updates from ledger.
6. Deny access after offline grace period if ledger cannot be fetched.

## Security properties
- Licenses cannot be forged without the private key.
- Revocation updates are tamper‑evident.
- Device‑bound licenses prevent simple copy‑paste piracy.

## Hosting the ledger
Use any static host:
- GitHub Pages
- Cloudflare R2
- S3
- IPFS
- CDN bucket

No server code required — just publish a signed JSON file.
