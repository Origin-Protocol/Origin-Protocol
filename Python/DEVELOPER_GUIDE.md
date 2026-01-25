# Developer Quick Reference

## Setup (30 seconds)
```bash
cd Python
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install -e .
```

## Run Tests
```bash
pytest                           # Run all tests
pytest -v                        # Verbose output
pytest --cov=src                 # With coverage
pytest -m "not slow"             # Skip slow tests
pytest tests/test_verify.py      # Single file
```

## Code Quality
```bash
ruff check src/                  # Lint
ruff check --fix src/            # Auto-fix
mypy src/                        # Type check
bandit -r src/ -ll               # Security scan
pip-audit                        # Dependency scan
```

## Coverage
```bash
pytest --cov=src --cov-report=html  # HTML report
open htmlcov/index.html             # View in browser
```

## CLI Commands
```bash
# Generate keys
origin init-keys --output-dir ./keys

# Sign file
origin sign media.mp4 \
  --creator-id creator-123 \
  --asset-id asset-123 \
  --public-key ./keys/public_key.ed25519 \
  --private-key ./keys/private_key.ed25519 \
  --output-dir ./bundle

# Verify bundle
origin verify ./bundle

# Policy verification
origin policy-verify ./bundle --profile strict --json
```

## File Structure
```
Python/
├── src/origin_protocol/        # Source code
│   ├── manifest.py            # Core manifest logic
│   ├── keys.py                # Ed25519 key management
│   ├── verify.py              # Verification logic
│   ├── seal.py                # Sealed bundle creation
│   ├── bundle.py              # Bundle operations
│   ├── policy.py              # Policy-based verification
│   ├── registry.py            # Key registry
│   ├── attestation.py         # Attestations
│   ├── container.py           # Sidecar support
│   ├── mp4.py / mkv.py        # Container embedding
│   └── experimental/          # Experimental features
├── tests/                      # Test suite
├── docs/                       # Documentation
├── platform/                   # Platform SDK
├── tools/                      # Utility scripts
└── pyproject.toml             # Project config
```

## Common Tasks

### Add a new dependency
```bash
pip install package-name
pip freeze | grep package-name >> requirements.txt
pip freeze > requirements.lock  # Update lock file
```

### Run specific test
```bash
pytest tests/test_origin_protocol.py::OriginProtocolTests::test_sealed_bundle_verification -v
```

### Debug test
```bash
pytest tests/test_verify.py -v -s --pdb  # Drop into debugger on failure
```

### Profile performance
```bash
python -m cProfile -o profile.stats tests/eval/perf_bench.py
python -m pstats profile.stats
```

## Git Workflow
```bash
git checkout -b feature/your-feature
# Make changes
pytest  # Ensure tests pass
ruff check --fix src/  # Fix linting
git add .
git commit -m "feat: your change"
git push origin feature/your-feature
# Open PR on GitHub
```

## Production Readiness Checklist
- [ ] All tests pass (`pytest`)
- [ ] Coverage >75% (`pytest --cov=src`)
- [ ] Linting clean (`ruff check src/`)
- [ ] Security scan clean (`bandit -r src/ -ll`)
- [ ] Dependencies safe (`pip-audit`)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped (pyproject.toml)

## Debugging Tips

### Enable verbose logging
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Inspect bundle contents
```bash
unzip -l bundle.zip              # List contents
unzip bundle.zip                 # Extract
jq . bundle/manifest.json        # Pretty-print JSON
```

### Check signature manually
```python
from origin_protocol.keys import load_public_key_from_pem
from origin_protocol.verify import verify_signature

public_key = load_public_key_from_pem("public_key.ed25519")
with open("signature.ed25519", "rb") as f:
    signature = f.read()
with open("manifest.json", "rb") as f:
    message = f.read()
    
is_valid = public_key.verify(signature, message)  # Raises on invalid
```

## Performance Tips
- Use streaming for large files (already implemented in `hash_file()`)
- Cache public keys (avoid repeated PEM parsing)
- Use `--profile standard` for faster verification
- Batch verify multiple bundles

## Security Best Practices
- Never commit keys to git
- Use `.gitignore` for `*.pem`, `*.key` files
- Rotate keys every 90 days
- Use HSM for production keys
- Always verify signatures before trusting data

## Common Errors

### `InvalidSignature`
- Check public key matches private key used for signing
- Verify manifest hasn't been modified
- Check signature file format

### `FileNotFoundError`
- Check file paths are correct
- Use absolute paths when possible
- Verify working directory

### `JSONDecodeError`
- Validate JSON syntax (use `jq` or `python -m json.tool`)
- Check for trailing commas
- Verify encoding is UTF-8

## Resources
- [Production Readiness Guide](PRODUCTION_READINESS.md)
- [Security Policy](SECURITY.md)
- [Migration Guide](MIGRATION_GUIDE.md)
- [Implementation Roadmap](ROADMAP.md)
- [Main README](README.md)

## Support
- GitHub Issues: https://github.com/Origin-Protocol/Origin-Protocol/issues
- Email: dev@origin-protocol.com
