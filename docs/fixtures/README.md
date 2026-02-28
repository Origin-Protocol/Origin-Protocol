# ORIGIN Fixtures (Illustrative)

These files are **illustrative examples** of Origin Protocol artifacts for documentation and interoperability testing.

Most fixtures are not signed and should not be used for real verification. Signed vectors are explicitly labeled.

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
- `python generate_sealed_bundle_vector.py`

## Included
- manifest_example.json
- bundle_example.json
- payload_example.json
- canonical_manifest_vector.json
- canonical_signature_vector.json (signed interop vector)
- sealed_bundle_vector.zip (signed sealed bundle vector)
- sealed_bundle_vector.json (hash/index)
- mp4_embedded_base64.txt
- mkv_embedded_base64.txt
