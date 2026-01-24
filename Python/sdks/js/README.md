# Origin Protocol JS SDK (Sidecar Verifier)

This is a minimal Node.js verifier for Origin sidecar payloads (platform-side).

## Usage

```
node sidecarVerifier.js <mediaPath> <sidecarPath>
```

### MP4 verifier

```
node mp4Verifier.js <mp4Path>
```

### MKV verifier

```
node mkvVerifier.js <mkvPath>
```

## What it checks
- bundle.sig over bundle.json
- bundle.json file hashes
- manifest signature
- seal signature
- media hash matches seal and manifest

## Notes
- Uses only Node's built-in `crypto` module.
- Intended as a reference implementation for platform integration.
