Origin Protocol (Python SDK + CLI)
Creator-controlled metadata + signatures for pre-upload ownership proofs.
Version: 1.0 (Frozen)

https://medium.com/@bkelleytms/origin-protocol-a-new-open-standard-for-creator-authenticity-527074b14c0c

What this is
A minimal, standards-compliant Python SDK and CLI for:
- generating Ed25519 signing keys
- hashing media files
- creating and signing ownership manifests
- producing portable bundles
- sealing media + metadata into a single verifiable archive
- verifying bundles and sealed bundles
This SDK implements the Origin Protocol v1.0 specification.

Installation
pip install origin-protocol



Quick Start
Minimal example:
origin init-keys
origin sign myvideo.mp4
origin verify myvideo.originbundle




Bundle Formats
Short, clean descriptions of:
- bundle
- sealed bundle
- container embedding

Specifications
Link to:
- Canonicalization
- Attestation
- Trust & Governance
- Registry
- License
- Node Network
- Test Vectors

Platform SDKs
Link to JS and Go verifiers.

Versioning
Origin Protocol follows semantic versioning.
v1.0 is frozen and immutable.
