# Origin Platform Ledger API v1.0 (Frozen)

## Base
- Base URL: https://<host>
- Content-Type: application/json
- API key header: X-Origin-API-Key: <key> (required when server is configured with keys)

## Endpoints

### POST /v1/ledger/verify
**Request**
```
{
  "creator_id": "...",
  "key_id": "...",
  "asset_id": "...",
  "content_hash": "...",
  "platform_id": "tiktok"
}
```

**Response**
```
{
  "ok": true,
  "reasons": []
}
```

**Error Response**
```
{
  "ok": false,
  "reasons": [
    {
      "code": "revoked",
      "severity": "critical",
      "message": "Asset or key revoked",
      "platform_action": "reject_upload",
      "creator_action": "This asset or key has been revoked. Use a different key or re-issue the asset with a new manifest."
    }
  ]
}
```

### GET /v1/ledger/key-status
Query params: creator_id, key_id

**Response**
```
{
  "ok": true,
  "reasons": [],
  "key_status": "active"
}
```

### GET /v1/ledger/revocation-status
Query params: creator_id, key_id, asset_id, content_hash, platform_id

**Response**
```
{
  "ok": false,
  "reasons": [{"code": "revoked", "severity": "critical", "message": "Asset or key revoked", "platform_action": "reject_upload", "creator_action": "..."}],
  "revoked": true
}
```

### GET /v1/ledger/platform-policy
Query param: platform_id (optional)

**Response**
```
{
  "ok": true,
  "policy": {
    "profile": "standard",
    "require_key_registry": true,
    "require_revocation_check": true,
    "require_platform_match": true,
    "require_key_id_match": true,
    "require_asset_record": true
  },
  "governance": {
    "ledger_cid": "sha256:...",
    "node_endpoints": [],
    "ipfs_gateways": []
  }
}
```

## Frozen items
- Endpoint names
- Request/response schemas
- Canonical OpenAPI: docs/platform_api_v1_openapi.yaml
- Policy profile names: permissive, standard, strict
- Bootstrap schema: platform/bootstrap_v1.json
- Governance CID file: platform/governance_v1.cid
