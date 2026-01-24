# Origin Protocol Platform Onboarding Guide (MVP)

## 1) Install the SDK

- Python: install from this repository or your package registry.
- Required runtime: Python 3.10+

## 2) Start the Platform Ledger API

The platform ledger API provides verification and policy endpoints.

Recommended environment variables:
- ORIGIN_PLATFORM_LEDGER_PATH
- ORIGIN_KEY_REGISTRY_PATH
- ORIGIN_REVOCATION_LIST_PATH
- ORIGIN_PLATFORM_POLICY_PATH
- ORIGIN_PLATFORM_POLICY_DIR
- ORIGIN_BOOTSTRAP_PATH (optional)
- ORIGIN_API_KEYS or ORIGIN_API_KEYS_PATH (optional, enables API key auth)
- ORIGIN_RATE_LIMIT_PER_MIN (optional, default 120)

## 3) Call the Ledger API

### POST /v1/ledger/verify

Request:
- creator_id
- key_id
- asset_id
- origin_id
- content_hash
- platform_id

Response:
- ok: true/false
- reasons: list of rejection codes and metadata

If API keys are enabled, send:
- X-Origin-API-Key: <key>

### GET /v1/ledger/key-status

Query:
- creator_id
- key_id

### GET /v1/ledger/revocation-status

Query:
- creator_id
- key_id
- asset_id
- origin_id
- content_hash
- platform_id

### GET /v1/ledger/platform-policy

Query:
- platform_id (optional)

## 4) Enforce Policy

Use `platform_policy` to choose the policy profile:
- permissive
- standard
- strict

Then enforce rejection codes based on `platform_action` and `severity`.

## 5) Interpret Rejection Codes

See the canonical mapping in:
- src/origin_protocol/reasons.py

## 6) Log Results

Capture:
- request payload
- policy profile
- ok status
- rejection codes

## 7) Integration Testing

Use:
- platform_tests/fixtures
- platform_tests/cases.json

## 8) Bootstrap & Governance

Use the platform bootstrap file to anchor governance:
- platform/bootstrap_v1.json

This includes:
- governance_ledger_cid
- governance_node_endpoints
- governance_ipfs_gateways
