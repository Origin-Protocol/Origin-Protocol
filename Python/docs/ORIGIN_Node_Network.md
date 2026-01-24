# Origin Node Network — Registry v1

## Goal
Maintain a decentralized registry of attestations:
- which assets exist
- who sealed them
- when they were sealed
- hashes and lineage

Nodes store **metadata + signatures only**, not media files.

## Node types

### Light nodes (EXE instances)
- Seal content locally
- Verify bundles locally
- Optionally submit attestations to a full node
- Optionally query registry for global checks
- Cache recent entries

### Full nodes (registry backbone)
- Store full append‑only attestation log
- Validate submissions (signatures + schema)
- Serve queries by `asset_id` or `media_hash`
- Replicate log to other full nodes

### Authority nodes (protocol stewards)
- Publish protocol versions and schemas
- Sign official specs and schema updates
- Do **not** modify registry history

## Attestation entry (conceptual)
```json
{
  "asset_id": "origin:video:123456",
  "media_hash": "sha256-...",
  "manifest_hash": "sha256-...",
  "creator_public_key": "ed25519:...",
  "sealed_at": 1737244800,
  "lineage": {
    "type": "original",
    "parents": []
  },
  "signature": "creator-signature-over-all-fields"
}
```

## v1 HTTP interface (simple)

### Light → Full
- `POST /attestations` — submit attestation
- `GET /attestations?media_hash=...`
- `GET /attestations?asset_id=...`

### Full ↔ Full
- `GET /log?since=<index>` — append‑only replication

### Authority → Everyone
- Publish signed schemas and protocol versions at a known URL

## Client behavior (EXE / light node)
- On sealing: optionally submit attestation to full node
- On verify: optionally query full node for global confirmation
- Offline mode: verify signatures + hashes locally

## Roadmap (non‑breaking)
- v1: single full node + light nodes
- v2: multiple full nodes + replication
- v3: discovery + multi‑registry trust anchors

---

# License Ledger Distribution (Decentralized)

## Model
- Authority nodes sign and publish the license ledger as a content‑addressed object (CID/hash).
- Full nodes mirror and serve the ledger by CID.
- Light nodes fetch the ledger from any available full node.
- Optional IPFS gateways can be used for content retrieval by CID.
- All ledgers are signature‑verified after retrieval.

## Retrieval (Light nodes)
1. Obtain the ledger CID (content hash identifier).
2. Try a rotating list of full node endpoints.
3. Optionally try IPFS gateways.
4. Verify the ledger signature before use.

## Notes
- No centralized URLs or hosting.
- No platform dependency.
- Content‑addressed storage prevents tampering.
- Signature verification is required after every fetch.

---

# Origin Node Ecosystem — End‑Game Design

## Overview
Origin’s node network grows organically without central coordination.
Every user begins as a Light Node and can promote to Full Node via measurable contribution.
Authority Nodes emerge by decentralized consensus.

Principles:
- Contribution earns responsibility
- Cryptographic truth replaces trust
- The network governs itself

## Node types

### Light Node (default)
Capabilities:
- Seal content
- Verify content
- Fetch ledger updates
- Maintain local state
- Participate in provenance

Light Nodes do not serve data to others and do not sign ledger updates.

### Full Node (self‑promotion, no approval)
A Light Node becomes a Full Node when it meets any usage threshold and opts‑in to serve.

Usage‑based criteria (any one):
- Sealed ≥ 50 items
- Verified ≥ 200 items
- Weekly use for ≥ 90 days
- Active membership ≥ 6 months
- Lifetime membership

Node‑behavior criteria:
- Opt‑in to run full‑node service
- Mirrors the ledger
- Serves the correct CID
- Responds to health checks
- ≥ 80% uptime over 30 days

Full Nodes:
- Mirror the ledger
- Serve ledger data to other nodes
- Pin ledger CIDs to IPFS
- Provide redundancy and resilience

### Authority Node (promotion by consensus)
Authority Nodes sign ledger updates and enforce protocol rules.

Eligibility:
- Meets Full Node requirements
- Mirrors ledger correctly for ≥ 60 days
- Zero protocol violations
- ≥ 90% uptime
- Correct CID history
- Correct signature verification behavior

Promotion request (signed):
```json
{
  "node_key": "...",
  "uptime_score": 0.93,
  "ledger_hash": "...",
  "cid_history": ["..."],
  "pinned_cids": ["..."],
  "request_timestamp": "...",
  "signature": "..."
}
```

Authority nodes evaluate automatically. If M‑of‑N signatures approve, the ledger records:
```
authority_nodes += node_key
```

## Demotion and revocation

### Automatic demotion
Demote when a node:
- Serves incorrect ledger data
- Fails uptime thresholds
- Stops mirroring
- Violates protocol rules
- Is flagged by multiple nodes

Ledger update:
```
authority_nodes -= node_key
```

### Revocation
For malicious behavior:
- Authority Nodes publish a Revocation Certificate
- Ledger reflects removal
- Clients automatically distrust the key

## Ledger governance
- Authority Node signatures
- Promotion and demotion certificates
- Revocation entries
- CID‑based integrity
- IPFS pinning
- Node‑served endpoints

No single party controls the ledger. Authority Nodes collectively maintain it.

## Why this works
- Self‑expanding: heavy users become infrastructure
- Self‑maintaining: nodes promote/demote automatically
- Self‑governing: authority emerges from contribution
- Creator‑first: the people who rely on Origin most become its backbone
- Minimal burden: no manual node lists, approvals, or infra coordination

---

# Implementation order (recommended)

1) **Data contracts (done)**
  - Promotion request + certificate
  - Demotion certificate
  - Deterministic signing and verification

  Reference module: [Python/src/origin_protocol/nodes.py](Python/src/origin_protocol/nodes.py)

2) **Local node metrics (next)**
  - Track usage counts (sealed, verified, checks, exports)
  - Track app “active days” and last‑seen timestamps
  - Emit a local node metrics record for eligibility checks

3) **Full node opt‑in service**
  - Ledger mirror + serve endpoints
  - Health check responder
  - Automatic CID pinning hooks

   Tool: [Python/tools/full_node_service.py](Python/tools/full_node_service.py)

   Example usage:
   - Listen on port 9020 and mirror from upstream:
     - `python full_node_service.py --listen 0.0.0.0:9020 --ledger-cid sha256:<hash> --upstream https://gateway/ipfs/{cid}`
   - Health check:
     - `GET /health`
   - Serve ledger by CID:
     - `GET /ledger/<cid>` or `GET /ipfs/<cid>`

4) **Promotion request workflow**
  - Full node generates signed request
  - Sends to authority nodes
  - Collects M‑of‑N signatures

   Tool: [Python/tools/node_promotion.py](Python/tools/node_promotion.py)

   Example flow:
   - Build + sign request:
     - `python node_promotion.py build-request --node-key <key> --uptime-score 0.92 --ledger-path <ledger> --private-key <priv> --public-key <pub> --output promotion_request.json`
   - Compute request hash:
     - `sha256(request)` (use the request JSON payload)
   - Create certificate shell:
     - `python node_promotion.py build-certificate --node-key <key> --request-hash <hash> --approvals-required 3 --output promotion_certificate.json`
   - Authority adds approval:
     - `python node_promotion.py add-approval --certificate promotion_certificate.json --private-key <authority-priv> --public-key <authority-pub> --output promotion_certificate.signed.json`

5) **Ledger integration**
  - Promotion / demotion / revocation entries in ledger
  - Clients consume and enforce authority set updates

   Tool: [Python/tools/node_ledger.py](Python/tools/node_ledger.py)

   Example flow:
   - Init ledger:
     - `python node_ledger.py init --issuer-id origin --private-key private_key.ed25519 --public-key public_key.ed25519 --output node_ledger.json`
   - Add promotion certificate:
     - `python node_ledger.py add-promotion --ledger node_ledger.json --certificate promotion_certificate.signed.json --private-key private_key.ed25519 --public-key public_key.ed25519 --output node_ledger.json`
   - Add demotion certificate:
     - `python node_ledger.py add-demotion --ledger node_ledger.json --certificate demotion_certificate.signed.json --private-key private_key.ed25519 --public-key public_key.ed25519 --output node_ledger.json`
   - Add revocation:
     - `python node_ledger.py add-revocation --ledger node_ledger.json --node-key <key> --reason "malicious" --private-key private_key.ed25519 --public-key public_key.ed25519 --output node_ledger.json`
   - Verify ledger:
     - `python node_ledger.py verify --ledger node_ledger.json`

6) **Demotion + revocation automation**
  - Health‑check based demotion
  - Signature‑verified revocation certificates

   Tool: [Python/tools/node_health_monitor.py](Python/tools/node_health_monitor.py)

   Config example:
   ```json
   {
     "expected_ledger_cid": "sha256:<hash>",
     "nodes": [
       {
         "node_key": "<node-key>",
         "health_url": "http://node-a:9020/health",
         "ledger_url": "http://node-a:9020/ledger/{cid}"
       }
     ],
     "failure_threshold": 3,
     "demotion_reason": "health_check_failed",
     "approvals_required": 3,
     "authority_private_key": "private_key.ed25519",
     "authority_public_key": "public_key.ed25519",
     "node_ledger_path": "node_ledger.json",
     "apply_demotion": false,
     "state_path": "~/.origin_protocol/node_health.json"
   }
   ```

   Run:
   - `python node_health_monitor.py --config node_health.json`
