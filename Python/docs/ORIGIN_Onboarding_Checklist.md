# ORIGIN Platform Onboarding Checklist (v1)

Use this checklist to validate a production‑ready integration.

## Integration readiness
- [ ] SDK installed and pinned to a released version
- [ ] Platform ledger API base URL configured
- [ ] API key configured and rotated in secrets manager
- [ ] Request signing and transport security reviewed

## Verification pipeline
- [ ] Verify bundle signatures and hashes
- [ ] Enforce intended_platforms where applicable
- [ ] Validate key registry and revocation list
- [ ] Enforce attestation for strict profile
- [ ] Log rejection codes and reason metadata

## Platform policy
- [ ] Profile selected (permissive/standard/strict)
- [ ] Platform policy endpoint integrated
- [ ] Rejection codes mapped to moderation actions

## Testing
- [ ] Test fixtures validated (platform_tests/fixtures)
- [ ] Golden cases pass (platform_tests/cases.json)
- [ ] Failure modes validated (tampered manifest, revoked key)

## Observability
- [ ] Request IDs logged
- [ ] Error rate dashboards configured
- [ ] Latency SLOs defined

## Launch
- [ ] Governance bootstrap pinned
- [ ] Trust anchor checksum verified
- [ ] Production API key issued
