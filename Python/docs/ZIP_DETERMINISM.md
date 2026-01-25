# ZIP Compression Determinism - Technical Decision

**Date**: 2026-01-25  
**Status**: ✅ **RESOLVED**  
**Decision**: Use `ZIP_STORED` (no compression) by default for sealed bundles

---

## Problem Statement

The Origin Protocol uses ZIP files for sealed bundles, which contain media files and cryptographic artifacts (manifests, signatures, seals). For cross-platform verification to work reliably, these ZIP files must be **bit-for-bit reproducible** - the same input files should always produce the same ZIP output, regardless of:

- Operating system (Windows, macOS, Linux)
- Python version (3.10, 3.11, 3.12)
- zlib library version
- Compression implementation

### Issue with DEFLATE Compression

The `ZIP_DEFLATED` compression method (standard ZIP compression) uses the DEFLATE algorithm, which:

1. **Varies by zlib version** - Different zlib versions may produce different compressed output for the same input
2. **Has implementation-specific optimizations** - Different platforms may use different DEFLATE implementations
3. **Depends on compression level** - Even with the same level (0-9), output can vary
4. **May use OS-specific features** - Platform-specific optimizations affect output

**Result**: A sealed bundle created on macOS with Python 3.11 may have a different hash than the same bundle created on Linux with Python 3.12, even if the contents are identical.

**Impact**: 
- Cross-platform verification fails (hash mismatch)
- Reproducible builds impossible
- Supply chain security compromised
- Platform integration reliability reduced

---

## Solution: ZIP_STORED (No Compression)

### Decision

**Change the default compression method from `ZIP_DEFLATED` to `ZIP_STORED`** in `create_sealed_bundle()`.

```python
# BEFORE (non-deterministic)
compression: int = ZIP_DEFLATED  # ❌ Platform-dependent output

# AFTER (deterministic)
compression: int = ZIP_STORED    # ✅ Bit-for-bit reproducible
```

### Rationale

| Factor | ZIP_STORED | ZIP_DEFLATED |
|--------|------------|--------------|
| **Determinism** | ✅ Guaranteed | ❌ Not guaranteed |
| **Cross-platform** | ✅ Identical output | ❌ May vary |
| **Reproducible builds** | ✅ Yes | ❌ No |
| **File size** | 🟡 Larger (uncompressed) | ✅ Smaller (compressed) |
| **Speed** | ✅ Faster (no compression) | 🟡 Slower (compression overhead) |
| **Complexity** | ✅ Simple | 🟡 Complex |

### Trade-offs

**Pros**:
- ✅ **Guaranteed determinism** - Same input always produces same output
- ✅ **Cross-platform compatible** - Works identically on all platforms
- ✅ **Reproducible builds** - Critical for supply chain security
- ✅ **Faster creation** - No compression overhead
- ✅ **Simpler implementation** - No compression level tuning needed
- ✅ **Easier debugging** - Uncompressed files easier to inspect

**Cons**:
- ❌ **Larger file sizes** - No compression means bigger bundles
- ❌ **Higher bandwidth** - Larger files to upload/download
- ❌ **More storage** - Uncompressed files use more disk space

### File Size Impact

Example media file sizes (uncompressed vs compressed):

| Media Type | Original | ZIP_STORED | ZIP_DEFLATED (level 9) | Difference |
|------------|----------|------------|------------------------|------------|
| MP4 video (1GB) | 1.0 GB | 1.0 GB | 1.0 GB | ~0% (already compressed) |
| MP3 audio (10MB) | 10 MB | 10 MB | 10 MB | ~0% (already compressed) |
| PNG image (5MB) | 5 MB | 5 MB | 4.5 MB | ~10% |
| JSON manifest (10KB) | 10 KB | 10 KB | 2 KB | ~80% |

**Key insight**: Most media files (MP4, MP3, JPEG, PNG) are **already compressed**, so ZIP compression provides minimal benefit (~0-10% reduction). The manifest/signature files are small (<100KB), so compression savings are negligible in absolute terms.

**Conclusion**: The file size penalty is minimal for media bundles, and the determinism benefit is critical.

---

## Implementation

### Code Changes

**File**: `src/origin_protocol/embed.py`

```python
def create_sealed_bundle(
    file_path: Path,
    manifest: Manifest,
    private_key: Ed25519PrivateKey,
    public_key_path: Path,
    output_path: Path,
    *,
    compression: int = ZIP_STORED,  # Changed from ZIP_DEFLATED
    compresslevel: int = 9,
    allow_zip64: bool = True,
) -> Path:
    """Create sealed bundle with deterministic output.
    
    Note:
        By default, ZIP_STORED (no compression) is used to ensure bit-for-bit
        reproducibility across platforms and Python versions. DEFLATE compression
        can vary by zlib version, which breaks deterministic verification.
        
        For compressed bundles, explicitly pass compression=ZIP_DEFLATED, but be
        aware this may cause cross-platform verification failures.
    """
    # ... implementation
```

### Backward Compatibility

**Breaking Change**: Yes, but acceptable because:
1. Version 0.2.0 is **not production-ready** (documented in PRODUCTION_READINESS.md)
2. This is a **security-critical fix** for cross-platform reliability
3. Users can opt-in to compression if needed by passing `compression=ZIP_DEFLATED`

### Migration Path

For users who need compressed bundles (e.g., bandwidth-constrained environments):

```python
# Explicitly request compression (non-deterministic)
create_sealed_bundle(
    file_path=media_path,
    manifest=manifest,
    private_key=private_key,
    public_key_path=public_key_path,
    output_path=output_path,
    compression=zipfile.ZIP_DEFLATED,  # Opt-in to compression
    compresslevel=9
)
```

**Warning**: Compressed bundles may fail cross-platform verification. Only use if:
- Bundle is verified on the same platform it was created
- File size is critical (e.g., limited bandwidth)
- Reproducibility is not required

---

## Testing

### Determinism Test

```python
import hashlib
from pathlib import Path
from origin_protocol.embed import create_sealed_bundle

def test_sealed_bundle_determinism():
    """Verify that sealed bundles are bit-for-bit reproducible."""
    # Create bundle twice
    bundle1 = create_sealed_bundle(...)
    bundle2 = create_sealed_bundle(...)
    
    # Compute hashes
    hash1 = hashlib.sha256(Path(bundle1).read_bytes()).hexdigest()
    hash2 = hashlib.sha256(Path(bundle2).read_bytes()).hexdigest()
    
    # Must be identical
    assert hash1 == hash2, "Bundles are not deterministic!"
```

### Cross-Platform Test

```bash
# Create bundle on Linux
python create_bundle.py --output linux-bundle.zip

# Create same bundle on macOS
python create_bundle.py --output macos-bundle.zip

# Verify hashes match
sha256sum linux-bundle.zip macos-bundle.zip
# Should output identical hashes
```

---

## Alternatives Considered

### Option 1: Fixed DEFLATE Parameters (Rejected)

**Approach**: Document exact zlib version and compression parameters required.

**Pros**:
- Compression benefit retained

**Cons**:
- ❌ Requires pinning zlib version (difficult across platforms)
- ❌ Breaks on Python version upgrades
- ❌ Requires custom zlib builds on some platforms
- ❌ High maintenance burden
- ❌ Still not guaranteed across all environments

**Verdict**: ❌ **Rejected** - Too fragile, high maintenance, not truly deterministic

### Option 2: Custom DEFLATE Implementation (Rejected)

**Approach**: Implement deterministic DEFLATE compression in pure Python.

**Pros**:
- True determinism
- Compression benefit retained

**Cons**:
- ❌ High implementation complexity
- ❌ Performance overhead (pure Python vs C extension)
- ❌ Security audit burden (custom crypto-adjacent code)
- ❌ Maintenance burden
- ❌ Not needed for v1.0 (media already compressed)

**Verdict**: ❌ **Rejected** for v1.0 - Consider for v2.0 if compression proves critical

### Option 3: ZIP_STORED (Selected)

**Approach**: No compression, store files as-is.

**Pros**:
- ✅ Guaranteed determinism
- ✅ Simple implementation
- ✅ Cross-platform compatible
- ✅ Zero maintenance
- ✅ Faster creation
- ✅ Minimal file size penalty for media

**Cons**:
- 🟡 Larger bundles (but minimal for compressed media)

**Verdict**: ✅ **SELECTED** - Best balance of simplicity, reliability, and security

---

## Documentation Updates

### README.md

Added note in Canonicalization section:

```markdown
Canonicalization rules (implementation reference):
- Bundle entries are ordered by path (ascending).
- ZIP metadata is fixed (timestamp 1980-01-01, zeroed flags/attrs).
- **Compression uses ZIP_STORED (no compression) by default for bit-for-bit
  reproducibility across environments.** For compressed bundles, use
  compression=ZIP_DEFLATED, but note this may cause cross-platform
  verification failures.
```

### PRODUCTION_READINESS.md

Updated status:

```markdown
### 3.3 ZIP Compression Determinism ✅
- **Issue**: DEFLATE compression may vary across platforms
- **Decision**: Use ZIP_STORED (no compression) by default
- **Status**: ✅ RESOLVED
- **Rationale**: See docs/ZIP_DETERMINISM.md
```

---

## Impact Assessment

### For Developers

- ✅ **No code changes required** - Default behavior is now deterministic
- ✅ **Can opt-in to compression** if needed via parameter
- ✅ **Tests unchanged** - Existing tests still pass

### For Platforms

- ✅ **Cross-platform verification now reliable** - Same bundle hash on all platforms
- ✅ **Reproducible builds enabled** - Critical for supply chain security
- 🟡 **Slightly larger bundles** - ~10% larger for metadata-heavy bundles, ~0% for media

### For End Users

- ✅ **More reliable verification** - No more false negatives due to compression differences
- 🟡 **Slightly larger uploads** - Minimal impact for media files

---

## Monitoring & Validation

### Metrics to Track

1. **Bundle size distribution** - Monitor impact of no compression
2. **Verification success rate** - Should improve with deterministic bundles
3. **Cross-platform verification** - Test on Windows/macOS/Linux
4. **Build reproducibility** - Same commit should produce same bundle

### Success Criteria

- ✅ 100% deterministic bundles (same input → same output)
- ✅ 100% cross-platform verification success
- ✅ <10% average file size increase for media bundles
- ✅ Faster bundle creation (no compression overhead)

---

## Future Considerations

### For v2.0

If file size becomes a critical issue, consider:

1. **Content-aware compression** - Only compress JSON/text files, store media as-is
2. **Custom deterministic DEFLATE** - Pure Python implementation
3. **Alternative formats** - tar.gz with reproducible tar
4. **Streaming compression** - For large files

### Feedback Loop

Monitor these signals:
- User complaints about file size
- Bandwidth cost increases
- Storage cost increases
- Platform feedback on bundle size limits

If file size becomes a blocker, revisit compression strategy in v2.0.

---

## References

- [ZIP File Format Specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Reproducible Builds](https://reproducible-builds.org/)
- [Python zipfile documentation](https://docs.python.org/3/library/zipfile.html)
- [zlib compression library](https://www.zlib.net/)

---

## Approval & Sign-off

- **Technical Decision**: Approved
- **Security Impact**: Positive (enables reproducible builds)
- **Performance Impact**: Positive (faster creation, minimal size impact)
- **User Impact**: Positive (more reliable verification)

**Status**: ✅ **APPROVED & IMPLEMENTED**

---

**Last Updated**: 2026-01-25  
**Version**: 0.2.0 → 1.0.0
