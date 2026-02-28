# ORIGIN Trust Anchor Package (v1)

This package defines the authoritative bootstrap inputs that anchor governance and policy.

## Contents
- bootstrap: platform/bootstrap_v1.json
- governance CID: platform/governance_v1.cid
- governance ledger: platform/governance_v1.json
- checksum: platform/governance_v1.sha256 (signed)

## Bootstrap file
- stable URL: https://originprotocol.dev/bootstrap/platform_v1.json
- version: 1.0
- governance CID: sha256:f720f80b5ab754f6e2606877eebd37174f9d1e86556b6b37897767377f4a35f8

## Governance CID
The governance CID is the canonical reference to the governance ledger content.

## Signed checksum (recommended)
Publish a signed checksum alongside the governance ledger:
- file: platform/governance_v1.sha256
- signature: platform/governance_v1.sha256.ed25519

Example checksum file:
```
sha256:<hash>  governance_v1.json
```

Verification steps:
1. Download bootstrap file from stable URL.
2. Read governance CID.
3. Fetch governance ledger by CID.
4. Verify governance_v1.sha256 signature using trusted issuer key.
5. Validate governance_v1.json hash matches the checksum.

## Rotation
- Any updates require a new versioned bootstrap file and governance CID.
- Clients should pin to versioned stable URLs and verify signatures.
