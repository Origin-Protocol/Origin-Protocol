# Security Policy

## Supported Versions

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 0.2.x   | :white_check_mark: | Development (NOT production-ready) |
| 0.1.x   | :x:                | Deprecated |

**⚠️ IMPORTANT**: Version 0.2.x is NOT production-ready. See [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) for details.

## Reporting a Vulnerability

If you discover a security vulnerability in Origin Protocol, please report it by:

1. **DO NOT** open a public GitHub issue
2. Email security@origin-protocol.com with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and provide updates as we investigate.

## Security Features

### Cryptographic Primitives

- **Signing**: Ed25519 (via cryptography library)
- **Hashing**: SHA-256
- **Key size**: 256-bit Ed25519 keys

### Threat Model

See [docs/ORIGIN_Security_Posture.md](docs/ORIGIN_Security_Posture.md) for the full threat model.

**Protected Against**:
- ✅ Signature forgery (Ed25519 provides 128-bit security)
- ✅ Content tampering (SHA-256 collision resistance)
- ✅ Replay attacks (via timestamps and nonces)
- ✅ Key compromise (via revocation lists)

**NOT Protected Against**:
- ❌ Timing attacks (constant-time not guaranteed)
- ❌ Side-channel attacks on key material
- ❌ Quantum attacks (Ed25519 is not post-quantum secure)
- ❌ Social engineering attacks

## Known Security Issues

### Critical Issues (DO NOT USE IN PRODUCTION)

1. **Experimental Identity Module (state_identity.py)**
   - Uses HMAC with string secrets instead of Ed25519
   - No non-repudiation
   - Secret compromise allows forgery
   - **Mitigation**: Use `state_identity_sig.py` instead
   - **Status**: Deprecated in 0.2.0, will be removed in 1.0.0

2. **Broad Exception Handling**
   - 36+ bare `except Exception` blocks may mask security errors
   - **Mitigation**: Being refactored to specific exception types
   - **Status**: In progress

### Dependency Vulnerabilities

Last checked: 2026-01-25

- **wheel 0.42.0**: CVE-2026-24049 (Path Traversal)
  - **Impact**: HIGH
  - **Fixed in**: wheel 0.46.2+
  - **Status**: ✅ Fixed in requirements.txt

## Security Best Practices

### Key Management

**DO**:
- Generate keys in a secure environment
- Store private keys encrypted at rest
- Use hardware security modules (HSM) for production keys
- Rotate keys regularly (every 90 days recommended)
- Use separate keys for development, staging, and production

**DON'T**:
- Commit private keys to version control
- Share keys via email or chat
- Use the same key across multiple creators
- Store keys in plaintext

### Manifest Creation

**DO**:
- Validate all input fields before signing
- Use ISO8601 timestamps with timezone
- Include all relevant metadata (creator_id, asset_id, content_hash)
- Sign manifests immediately after creation

**DON'T**:
- Sign manifests with missing fields
- Use relative timestamps or assume local timezone
- Reuse signatures across different manifests

### Verification

**DO**:
- Verify signatures before trusting any manifest
- Check revocation lists before accepting signatures
- Validate all timestamps and ensure they're not in the future
- Use policy-based verification with appropriate profiles

**DON'T**:
- Trust manifests without signature verification
- Skip revocation checks for performance
- Accept manifests with timestamps in the future
- Use permissive policies in production

## Security Checklist for Production

Before deploying to production:

- [ ] All critical security issues resolved
- [ ] All high-priority security issues resolved
- [ ] Dependencies scanned for vulnerabilities (pip-audit clean)
- [ ] Static code analysis completed (bandit clean)
- [ ] Penetration testing completed
- [ ] Security audit by external firm
- [ ] Incident response plan documented
- [ ] Key rotation procedures tested
- [ ] Backup/recovery procedures tested
- [ ] Monitoring and alerting configured
- [ ] Rate limiting implemented
- [ ] DDoS protection configured

## Security Testing

### Static Analysis

```bash
# Run Bandit security scanner
bandit -r src/ -ll

# Check for dependency vulnerabilities
pip-audit --desc

# Run linting
ruff check src/
```

### Dynamic Analysis

```bash
# Run fuzz testing
python tests/eval/fuzz_verifiers.py

# Run performance benchmarks
python tests/eval/perf_bench.py
```

## Security Contacts

- **Security Team**: security@origin-protocol.com
- **Bug Bounty**: bounty@origin-protocol.com (program TBD)

## Security Updates

Subscribe to security updates:
- GitHub Security Advisories: https://github.com/Origin-Protocol/Origin-Protocol/security/advisories
- Email list: security-announce@origin-protocol.com

## Acknowledgments

We thank the following researchers for responsible disclosure:

(None yet - this is a new project)

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Python Security](https://python.readthedocs.io/en/stable/library/security_warnings.html)
- [Cryptography Best Practices](https://github.com/pyca/cryptography)
