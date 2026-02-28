# Platform Ledger API Test Suite (MVP)

This folder contains minimal fixtures and request cases for platform-side integration testing.

## Fixtures

- fixtures/platform_ledger.json
- fixtures/key_registry.json
- fixtures/revocation_list.json

## Sample Requests

See cases.json for expected responses.

## Running Against the API

Set these environment variables before starting the service:

- ORIGIN_PLATFORM_LEDGER_PATH=platform_tests/fixtures/platform_ledger.json
- ORIGIN_KEY_REGISTRY_PATH=platform_tests/fixtures/key_registry.json
- ORIGIN_REVOCATION_LIST_PATH=platform_tests/fixtures/revocation_list.json
- ORIGIN_PLATFORM_POLICY_PATH=platform/platform_policies.json
- ORIGIN_PLATFORM_POLICY_DIR=platform/policies
- ORIGIN_API_KEY=<key> (optional if API keys are enabled on the server)

Then POST each request to /v1/ledger/verify and compare the `ok` flag and `reasons[].code`.
