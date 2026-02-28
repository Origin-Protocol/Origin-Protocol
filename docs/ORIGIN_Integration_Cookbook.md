# ORIGIN Integration Cookbook (v1)

Minimal, copy‑paste integrations for platform teams.

## Python (platform verification)
```python
from pathlib import Path

from origin_protocol.policy import VerificationPolicy
from origin_protocol.sdk import verify_sealed

policy = VerificationPolicy(
    require_seal=True,
    require_key_registry=True,
    require_revocation_check=True,
)

result = verify_sealed(Path("/uploads/asset.origin.zip"), policy)
if result.ok:
    print("verified")
else:
    print("rejected", result.reasons)
```

## JS (sidecar verification)
```bash
node sdks/js/sidecarVerifier.js /path/to/media.mp4 /path/to/media.mp4.origin.json
```

## Go (sidecar verification)
```bash
go run sdks/go/sidecar_verifier.go /path/to/media.mp4 /path/to/media.mp4.origin.json
```

## cURL cookbook (Platform Ledger API)

### POST /v1/ledger/verify
```bash
curl -X POST "https://<host>/v1/ledger/verify" \
  -H "Content-Type: application/json" \
  -H "X-Origin-API-Key: <key>" \
  -d '{
    "creator_id": "creator-123",
    "key_id": "<key-id>",
    "asset_id": "asset-123",
    "origin_id": "<origin-id>",
    "content_hash": "<sha256>",
    "platform_id": "yt"
  }'
```

### GET /v1/ledger/key-status
```bash
curl -X GET "https://<host>/v1/ledger/key-status?creator_id=creator-123&key_id=<key-id>" \
  -H "X-Origin-API-Key: <key>"
```

### GET /v1/ledger/revocation-status
```bash
curl -X GET "https://<host>/v1/ledger/revocation-status?creator_id=creator-123&key_id=<key-id>&asset_id=asset-123&origin_id=<origin-id>&content_hash=<sha256>&platform_id=yt" \
  -H "X-Origin-API-Key: <key>"
```

### GET /v1/ledger/platform-policy
```bash
curl -X GET "https://<host>/v1/ledger/platform-policy?platform_id=yt" \
  -H "X-Origin-API-Key: <key>"
```
