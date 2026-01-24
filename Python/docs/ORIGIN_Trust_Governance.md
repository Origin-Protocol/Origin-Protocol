# ORIGIN Trust & Governance (Draft v0.1)

## Roles
- **Creator**: produces content and holds a signing key.
- **Issuer**: validates creators and signs attestations.
- **Registry operator**: maintains key registry entries.
- **Revocation authority**: publishes revocation lists.
- **Platform verifier**: enforces verification policy.

## Trust store semantics
- Trust stores are **explicit allowlists** of issuer public keys.
- Platforms SHOULD distribute trust stores via secure channels.
- Platforms SHOULD version and rotate trust stores.
- Compromised issuers MUST be removed and their attestations invalidated.

## Update strategy
- Trust store updates should be **atomic** and **audited**.
- Prefer short-lived attestations to limit blast radius.
- Platforms may cache trust store snapshots with TTL.

## Governance model options
- Consortium governed issuer list.
- Platform-specific issuer lists.
- Hybrid (consortium + platform overrides).
