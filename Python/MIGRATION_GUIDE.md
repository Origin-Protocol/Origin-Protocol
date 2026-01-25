# Migration Guide: state_identity.py → state_identity_sig.py

## Overview

The `state_identity.py` module uses HMAC-based authentication which provides weaker security than asymmetric Ed25519 signatures. Starting from version 0.2.0, this module is **deprecated** and will be removed in version 1.0.0.

**All users should migrate to `state_identity_sig.py` which provides Ed25519 signatures.**

## Security Comparison

| Feature | state_identity.py (HMAC) | state_identity_sig.py (Ed25519) |
|---------|--------------------------|----------------------------------|
| Authentication | ✅ Symmetric | ✅ Asymmetric |
| Non-repudiation | ❌ No | ✅ Yes |
| Key compromise impact | 🔴 Critical (forgery) | 🟡 Moderate (revoke key) |
| Secret management | 🔴 Requires secure storage | 🟢 Public key can be shared |
| Signature size | 64 chars (hex) | ~100 chars (base64 + metadata) |
| Production ready | ❌ No | ✅ Yes |

## Breaking Changes

### 1. Function Signatures

**Old (state_identity.py)**:
```python
from origin_protocol.experimental.state_identity import (
    initialize_state,
    evolve_state,
    compute_state_signature,
)

state = initialize_state(
    seed="creator-123",
    secret="my-secret-key"  # ❌ String secret
)
```

**New (state_identity_sig.py)**:
```python
from origin_protocol.experimental.state_identity_sig import (
    initialize_state_signed,
    evolve_state_signed,
    sign_state,
    verify_state_signature,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

private_key = Ed25519PrivateKey.generate()  # ✅ Ed25519 key

state = initialize_state_signed(
    seed="creator-123",
    private_key=private_key,  # ✅ Ed25519 private key
    key_id="key-fingerprint"  # Optional
)
```

### 2. Signature Format

**Old**: Hex-encoded HMAC-SHA256 (64 characters)
```
c6f7611b0406f2a66b33f5bb05c8acfa2bd3dc7cd7aef12d0f2d087c6efc8a56
```

**New**: Base64-encoded signature with metadata (algorithm:key_id:signature)
```
ed25519:sha256-abc123:IGfJ5P7Xb4zD9EM+YzPXwvKj2sL5T8+Hk6N/Q1mR3gA=
```

### 3. Verification

**Old**:
```python
# No verification function - just recompute and compare
expected = compute_state_signature(state, secret="my-secret-key")
valid = state.signature == expected  # ❌ String comparison
```

**New**:
```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

public_key = private_key.public_key()  # Or load from PEM

valid = verify_state_signature(
    state,
    public_key,
    expected_key_id="key-fingerprint"  # Optional
)
```

## Step-by-Step Migration

### Step 1: Generate Ed25519 Keys

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Generate new key pair
private_key = Ed25519PrivateKey.generate()

# Serialize for storage
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()  # Or use BestAvailableEncryption()
)

public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save to files
with open("private_key.pem", "wb") as f:
    f.write(private_pem)
    
with open("public_key.pem", "wb") as f:
    f.write(public_pem)
```

### Step 2: Update State Initialization

**Before**:
```python
from origin_protocol.experimental.state_identity import initialize_state

state = initialize_state(
    seed="user-123",
    coherence=0.8,
    entropy_level=0.2,
    harmonics=(1.0, 0.5, 0.25),
    secret="my-hmac-secret"
)
```

**After**:
```python
from origin_protocol.experimental.state_identity_sig import initialize_state_signed
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Load private key
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

state = initialize_state_signed(
    seed="user-123",
    private_key=private_key,
    coherence=0.8,
    entropy_level=0.2,
    harmonics=(1.0, 0.5, 0.25),
    key_id="optional-key-id"  # Optional, auto-derived if not provided
)
```

### Step 3: Update State Evolution

**Before**:
```python
from origin_protocol.experimental.state_identity import evolve_state

new_state = evolve_state(
    state,
    coherence_drift=-0.01,
    entropy_drift=0.01,
    harmonics_delta=(0.1, -0.05, 0.02),
    secret="my-hmac-secret"
)
```

**After**:
```python
from origin_protocol.experimental.state_identity_sig import evolve_state_signed

new_state = evolve_state_signed(
    state,
    private_key=private_key,
    coherence_drift=-0.01,
    entropy_drift=0.01,
    harmonics_delta=(0.1, -0.05, 0.02),
    key_id="optional-key-id"  # Optional
)
```

### Step 4: Update Verification

**Before**:
```python
from origin_protocol.experimental.state_identity import compute_state_signature

# Recompute signature to verify
expected = compute_state_signature(state, secret="my-hmac-secret")
is_valid = state.signature == expected
```

**After**:
```python
from origin_protocol.experimental.state_identity_sig import verify_state_signature
from cryptography.hazmat.primitives import serialization

# Load public key
with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

is_valid = verify_state_signature(
    state,
    public_key,
    expected_key_id="optional-key-id"  # Optional
)
```

## Data Migration

If you have existing states signed with HMAC, you'll need to re-sign them:

```python
from origin_protocol.experimental.state_identity import initialize_state
from origin_protocol.experimental.state_identity_sig import sign_state
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Load existing state (HMAC-signed)
old_state = initialize_state(seed="user-123", secret="old-secret")

# Create new state with same data but Ed25519 signature
private_key = Ed25519PrivateKey.generate()

# Create base state without signature
from origin_protocol.experimental.state_identity import IdentityState
base_state = IdentityState(
    state_id=old_state.state_id,
    created_at=old_state.created_at,
    coherence=old_state.coherence,
    entropy_level=old_state.entropy_level,
    harmonics=old_state.harmonics,
    signature=""  # Will be replaced
)

# Sign with Ed25519
new_state = sign_state(base_state, private_key)

# Store new state
print(f"Migrated state: {new_state.state_id}")
```

## Compatibility Layer (Temporary)

If you need to support both formats during migration:

```python
def verify_state_flexible(state, secret=None, public_key=None):
    """Verify state with either HMAC or Ed25519."""
    if public_key:
        # Try Ed25519 verification
        from origin_protocol.experimental.state_identity_sig import verify_state_signature
        return verify_state_signature(state, public_key)
    elif secret:
        # Fall back to HMAC (deprecated)
        from origin_protocol.experimental.state_identity import compute_state_signature
        expected = compute_state_signature(state, secret=secret)
        return state.signature == expected
    else:
        raise ValueError("Must provide either public_key or secret")
```

## Timeline

- **v0.2.0** (Current): Deprecation warnings added
- **v0.3.0** (2026-Q2): HMAC functions marked as errors
- **v1.0.0** (2026-Q3): HMAC module removed entirely

## Testing

After migration, verify your changes:

```python
import unittest
from origin_protocol.experimental.state_identity_sig import (
    initialize_state_signed,
    evolve_state_signed,
    verify_state_signature,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

class TestMigration(unittest.TestCase):
    def test_ed25519_state_lifecycle(self):
        # Generate key
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Initialize
        state = initialize_state_signed(
            seed="test-user",
            private_key=private_key
        )
        
        # Verify
        self.assertTrue(verify_state_signature(state, public_key))
        
        # Evolve
        new_state = evolve_state_signed(state, private_key=private_key)
        
        # Verify evolved state
        self.assertTrue(verify_state_signature(new_state, public_key))

if __name__ == "__main__":
    unittest.main()
```

## FAQ

### Q: Why is HMAC deprecated?

A: HMAC provides symmetric authentication, meaning anyone with the secret can create valid signatures. This doesn't provide non-repudiation and creates a single point of failure. Ed25519 uses asymmetric keys, so only the private key holder can sign, but anyone can verify with the public key.

### Q: Can I continue using HMAC?

A: Not recommended. HMAC support will be removed in v1.0.0. Start migrating now.

### Q: Do I need to migrate existing states?

A: Yes, if you want to verify them with the new system. You'll need to re-sign them with Ed25519 keys.

### Q: What happens if I ignore the deprecation warning?

A: Your code will work in v0.2.x but will break in v1.0.0 when HMAC support is removed.

### Q: Can I verify both signature types during migration?

A: Yes, use the compatibility layer shown above, but remove it before v1.0.0.

## Support

If you have questions about migration:
- Open an issue: https://github.com/Origin-Protocol/Origin-Protocol/issues
- Email: support@origin-protocol.com
- Discord: https://discord.gg/origin-protocol (TBD)
