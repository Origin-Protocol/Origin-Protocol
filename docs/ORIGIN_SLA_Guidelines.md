# ORIGIN SLA Guidelines (Draft)

These guidelines describe recommended service‑level targets for platform integrations.

## Availability
- **Staging:** 99.0% monthly uptime
- **Production:** 99.9% monthly uptime

## Latency targets (p95)
- **Verify endpoint:** < 250 ms
- **Policy endpoint:** < 150 ms
- **Key status / revocation status:** < 150 ms

## Error rates
- 5xx error rate < 0.1% monthly
- 4xx errors are treated as client misuse and excluded from SLOs

## Incident response
- P1 (service down): initial response < 30 minutes
- P2 (degraded): initial response < 2 hours

## Maintenance windows
- Published at least 72 hours in advance
- Max 2 hours per window

## Contact
support@originprotocol.dev
