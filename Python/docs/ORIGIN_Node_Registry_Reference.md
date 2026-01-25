# ORIGIN Node Registry Reference Implementation (v1)

This reference service exposes a read‑only HTTP API over the signed node governance ledger.
It is designed to be simple, auditable, and easy to deploy.

## What it provides
- Serves the signed node ledger JSON.
- Exposes an authority set derived from ledger entries.
- Health and status endpoint for monitoring.

## Run the service
```
python tools/node_registry_service.py \
  --ledger-path ./node_ledger.json \
  --public-key ./authority_public_key.ed25519 \
  --listen 0.0.0.0:9030 \
  --require-valid
```

## Endpoints
- `GET /health`
  - Returns status, ledger hash, and signature validity.
- `GET /ledger`
  - Returns the raw ledger JSON (signed payload + signature + public key).
- `GET /nodes`
  - Returns the derived authority set and ledger metadata.
- `GET /authority/<node_key>`
  - Returns whether a node key is currently an authority.

## Ledger file format
The ledger JSON file contains:
- `ledger`: canonical ledger payload
- `signature`: base64 Ed25519 signature over the ledger payload
- `public_key`: PEM public key used for signature verification

## Verification behavior
- If `--public-key` is provided, the service verifies the ledger against it.
- If `--require-valid` is set, the service returns 503 when the ledger signature is invalid.

## How to create the ledger
Use the helper tooling:
- `python tools/node_ledger.py init --issuer-id ... --private-key ... --public-key ...`
- `python tools/node_ledger.py add-promotion --ledger ... --certificate ... --private-key ... --public-key ...`
- `python tools/node_ledger.py add-demotion --ledger ... --certificate ... --private-key ... --public-key ...`
- `python tools/node_ledger.py add-revocation --ledger ... --node-key ... --private-key ... --public-key ...`

## Security notes
- Always serve over HTTPS.
- Prefer content‑addressed ledger storage and immutable history.
- Log ledger hashes for auditing.
