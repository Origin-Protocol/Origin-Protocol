# ORIGIN Error Codes v1 (Frozen)

**Version:** 1.0.0

This document defines the frozen v1 rejection codes used by the platform ledger API and SDKs.
The canonical mapping (messages, severity, actions) is implemented in src/origin_protocol/reasons.py.
Any changes require a new version of this document and a versioned API update.

## Fields
- code
- category
- severity
- platform_action
- message

## Codes

| code | category | severity | platform_action | message |
|---|---|---|---|---|
| sidecar_read_error | transport | medium | reject_upload | Sidecar file could not be read |
| bundle_manifest_missing | transport | high | reject_upload | bundle.json missing from payload |
| bundle_signature_missing | transport | high | reject_upload | bundle.sig missing from payload |
| media_read_error | transport | medium | reject_upload | Media file could not be read |
| manifest_invalid | integrity | high | reject_upload | Manifest JSON invalid |
| public_key_invalid | crypto | critical | reject_upload | Public key PEM invalid or not Ed25519 |
| payload_invalid_json | transport | high | reject_upload | Embedded Origin payload is not valid JSON |
| payload_missing_keys | transport | high | reject_upload | Embedded Origin payload missing required keys |
| bundle_manifest_missing_entry | integrity | high | reject_upload | Bundle manifest missing required entry |
| bundle_manifest_hash_mismatch | integrity | high | reject_upload | Bundle manifest hash mismatch for embedded payload |
| signature_invalid | crypto | critical | reject_upload | Manifest signature invalid |
| seal_invalid | crypto | critical | reject_upload | Seal signature invalid |
| bundle_manifest_invalid | crypto | critical | reject_upload | Bundle manifest signature invalid |
| bundle_contents_mismatch | integrity | high | reject_upload | Bundle contents do not match bundle.json |
| bundle_hash_mismatch | integrity | high | reject_upload | Bundle manifest hash mismatch |
| asset_record_missing | policy | high | require_manual_review | Asset record missing from platform ledger |
| content_hash_mismatch | integrity | critical | reject_upload | Content hash mismatch |
| platform_mismatch | policy | medium | reject_upload | Upload platform not in intended_platforms |
| platform_missing | policy | low | warn_creator | Platform not specified |
| creator_mismatch | identity | high | reject_upload | Creator id mismatch |
| key_id_missing | identity | medium | warn_creator | Key id missing |
| key_id_mismatch | identity | high | reject_upload | Key id mismatch |
| key_untrusted | trust | critical | reject_upload | Key not trusted or inactive |
| revoked | governance | critical | reject_upload | Asset or key revoked |
| revocation_list_missing | governance | high | require_manual_review | Revocation list missing |
| revocation_signature_invalid | governance | critical | reject_upload | Revocation list signature invalid |
| revocation_entry_invalid | governance | high | require_manual_review | Revocation entry invalid |
| revocation_scope_unsupported | policy | medium | require_manual_review | Revocation scope unsupported |
| revocation_issuer_untrusted | trust | high | defer_to_trust_store | Revocation issuer untrusted |
| revocation_conflict | governance | high | require_manual_review | Revocation conflict detected |
| seal_timestamp_invalid | integrity | high | reject_upload | Seal timestamp predates manifest |
| key_registry_missing | trust | medium | require_manual_review | Key registry missing |
| seal_required | policy | high | reject_upload | Seal required by policy |
| content_hash_unchecked | policy | low | log_only | Content hash not verified |
| attestation_missing | trust | high | reject_upload | Attestation missing |
| attestation_signature_missing | trust | high | reject_upload | Attestation signature missing |
| trust_store_missing | trust | high | require_manual_review | Trust store missing |
| trust_store_empty | trust | high | require_manual_review | Trust store empty |
| attestation_creator_mismatch | trust | high | reject_upload | Attestation creator mismatch |
| attestation_key_id_mismatch | trust | high | reject_upload | Attestation key id mismatch |
| attestation_key_mismatch | trust | high | reject_upload | Attestation public key mismatch |
| attestation_expired | trust | high | require_manual_review | Attestation expired or invalid |
| attestation_invalid | trust | critical | reject_upload | Attestation signature invalid |
| attestation_platform_mismatch | trust | high | reject_upload | Attestation platform binding mismatch |
| attestation_region_mismatch | trust | high | reject_upload | Attestation region mismatch |
| attestation_usage_violation | trust | high | reject_upload | Attestation usage constraints violated |
| attestation_not_yet_valid | trust | high | require_manual_review | Attestation not yet valid |
| attestation_purpose_mismatch | trust | high | reject_upload | Attestation purpose mismatch |
| container_payload_missing | integrity | high | require_manual_review | Container payload missing |
| container_payload_invalid | integrity | high | reject_upload | Container payload invalid |
| container_signature_invalid | crypto | critical | quarantine_upload | Container payload signature invalid |
| container_format_unsupported | policy | medium | require_manual_review | Container format unsupported |
| container_payload_mismatch | integrity | high | reject_upload | Container payload mismatch |
| bundle_missing_file | integrity | high | reject_upload | Bundle missing required file |
| bundle_unreadable | integrity | high | reject_upload | Bundle unreadable or corrupted |
| bundle_media_missing | integrity | high | reject_upload | Bundle media missing |
| bundle_media_path_invalid | integrity | high | reject_upload | Bundle media path invalid |
| policy_violation | policy | high | reject_upload | Policy violation |
| policy_unsupported | policy | medium | require_manual_review | Policy feature unsupported |
| policy_input_missing | policy | high | defer_to_trust_store | Policy input missing |
