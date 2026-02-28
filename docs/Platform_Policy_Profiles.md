# Platform Policy Profiles

Profiles are JSON configurations that the platform ledger API loads from platform/policies.

## permissive
- Minimal checks
- No registry or revocation enforcement

## standard
- Requires key registry
- Requires revocation checks
- Requires platform match
- Requires asset record

## strict
- Same as standard (MVP)
- Reserved for additional governance requirements

Files:
- platform/policies/permissive.json
- platform/policies/standard.json
- platform/policies/strict.json

Platform mapping:
- platform/platform_policies.json
