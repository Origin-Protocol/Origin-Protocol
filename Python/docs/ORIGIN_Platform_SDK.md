# ORIGIN Platform SDK (Draft v0.2)

## Goal
Provide a simple platform‑side API for verification, returning **standardized rejection codes**.

## Python API

```
from origin_protocol.policy import VerificationPolicy
from origin_protocol.sdk import verify_sealed, as_dict, load_localization

policy = VerificationPolicy(require_seal=True)
localization = load_localization(Path("docs/locales/en.json"))
result = verify_sealed(Path("bundle.zip"), policy, localization=localization)
if not result.ok:
    for code, message in result.reason_details:
        print(code, message)

print(as_dict(result))
```

## Container payload helpers
```
from origin_protocol.container import extract_origin_payload, validate_origin_payload

payload = extract_origin_payload(Path("video.mp4"), sidecar_path=Path("origin.sidecar.json"))
if payload is None:
    raise ValueError("Missing Origin payload")

errors = validate_origin_payload(payload, fast_fail=True)
if errors:
    raise ValueError(errors)
```

## Rejection codes
See [ORIGIN_Verification_Standard.md](ORIGIN_Verification_Standard.md) and [reasons.py](../src/origin_protocol/reasons.py).

## Error metadata
Each reason includes:
- category
- subcategory
- severity
- is_fatal
- creator_action
- platform_action
- remediation
- localization_key
- docs_url

## Localization
Load localization strings from [docs/locales/en.json](locales/en.json) and pass them to SDK helpers.

## Canonicalization test vectors
Use the canonical manifest vector in [docs/fixtures/canonical_manifest_vector.json](fixtures/canonical_manifest_vector.json) to confirm cross‑SDK JSON bytes match.

## CLI integration
`origin policy-verify --json --localization docs/locales/en.json --exit-on-severity high`
