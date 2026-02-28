# ORIGIN Public Telemetry (v1)

This document defines public uptime, status, and audit‑log formats for Origin services.

## Uptime page
- URL: https://status.originprotocol.dev
- Components:
  - Platform Ledger API
  - Governance Bootstrap
  - Trust Store
  - Staging API

## Status endpoint
- URL: https://<host>/v1/status
- Method: GET

Example response:
```json
{
  "ok": true,
  "service": "origin-ledger",
  "version": "1.0.0",
  "region": "us-east-1",
  "timestamp": "2026-01-24T00:00:00Z",
  "uptime_seconds": 86400,
  "request_id": "req_01HX..."
}
```

## Audit log format (platform‑side)
Platforms should log the following fields for every verification request:
- request_id
- creator_id
- key_id
- asset_id
- origin_id
- content_hash
- platform_id
- policy_profile
- decision (allow/reject/review)
- reasons (codes)
- timestamp
- latency_ms

Example log entry:
```json
{
  "request_id": "req_01HX...",
  "creator_id": "creator-123",
  "key_id": "key-abc",
  "asset_id": "asset-123",
  "origin_id": "746fba9f-4c5c-5fcf-8621-0765dd99f750",
  "content_hash": "<sha256>",
  "platform_id": "yt",
  "policy_profile": "standard",
  "decision": "allow",
  "reasons": [],
  "timestamp": "2026-01-24T00:00:00Z",
  "latency_ms": 120
}
```
