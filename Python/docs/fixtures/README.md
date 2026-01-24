# ORIGIN Fixtures (Illustrative)

These files are **illustrative examples** of Origin Protocol artifacts for documentation and interoperability testing.

They are not signed and should not be used for real verification.

Embedded container fixtures are base64-encoded minimal files with an empty Origin payload.

## Decode fixtures
Run the decoder to materialize MP4/MKV files:

- `python decode_fixtures.py`

## Verify fixtures
After decoding, verify embedded payloads:

- `python verify_fixtures.py`

## Signed interop vectors
Generate signed vectors (manifest/signature/seal/bundle) with:

- `python generate_signed_vectors.py`

## Included
- manifest_example.json
- bundle_example.json
- payload_example.json
- mp4_embedded_base64.txt
- mkv_embedded_base64.txt
