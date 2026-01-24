# Origin Protocol Go SDK (Sidecar Verifier)

Minimal Go reference verifier for Origin sidecar payloads.

## Usage

```
go run sidecar_verifier.go <mediaPath> <sidecarPath>
```

## MP4 verifier

```
go run ./cmd/mp4_verifier <mp4Path>
```

## MKV verifier

```
go run ./cmd/mkv_verifier <mkvPath>
```

## Sealed bundle verifier

```
go run ./cmd/sealed_bundle_verifier <bundlePath>
```

## Checks
- bundle.sig over bundle.json
- bundle.json file hashes
- manifest signature
- seal signature
- media hash matches seal + manifest
