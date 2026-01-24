# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-01-16
### Added
- Sealed bundle integrity (bundle.json + bundle.sig)
- Policy verification layer with revocation, key registry, and attestation
- Container embedding: MP4/MOV uuid box, MKV tag embedding, sidecar support
- Platform SDK stubs (JS/Go)
- Canonicalization spec and fixtures

### Changed
- Manifest supports optional `key_id`

## [0.1.0] - 2026-01-15
### Added
- Initial manifest + signature bundle
- CLI for keygen, sign, verify
