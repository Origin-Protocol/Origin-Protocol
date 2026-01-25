# ORIGIN Staging Ledger Service (v1)

This document defines the staging environment for the platform ledger API.

## Base URL
- `https://staging.originprotocol.dev`

## Authentication
- Header: `X-Origin-API-Key: <key>`
- Contact the Origin team to obtain a staging key.

## Rate limits
- Default: 120 requests/minute per key
- Burst: 30 requests/second
- If you need higher limits, request a rate‑limit override for staging.

## Metrics (staging)
- `/v1/metrics` (admin‑only)
- Exposes request counts, latency p50/p95/p99, and error rates.

## Endpoints (v1)
- `POST /v1/ledger/verify`
- `GET /v1/ledger/key-status`
- `GET /v1/ledger/revocation-status`
- `GET /v1/ledger/platform-policy`

See [Platform_API_Contract_v1.md](Platform_API_Contract_v1.md) for payload schemas.

## Response headers
- `X-Origin-Request-Id`: request correlation id
- `X-Origin-RateLimit-Limit`: per‑minute limit
- `X-Origin-RateLimit-Remaining`: remaining quota in the current window
- `X-Origin-RateLimit-Reset`: unix epoch when quota resets

## Staging data
- Staging uses synthetic data and test registries.
- No production data is stored in staging.

## Support
Email: support@originprotocol.dev
