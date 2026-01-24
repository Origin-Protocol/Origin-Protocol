# PayPal IPN → Origin License Automation

This guide shows how to automate Origin membership licenses using PayPal IPN (no full backend required).

## Overview
1. User pays via PayPal
2. PayPal sends IPN to your listener
3. Listener validates IPN
4. Listener issues a signed `.originlicense`
5. License is emailed to the buyer
6. Cancellation events update the license ledger

## Minimal IPN listener
A reference implementation is included:
- `tools/paypal_ipn_listener.py`

It uses only the Python standard library and the Origin CLI.

## Required environment variables
```
ORIGIN_LICENSE_PRIVATE_KEY=issuer_private.pem
ORIGIN_LICENSE_PUBLIC_KEY=issuer_public.pem
ORIGIN_LICENSE_OUTPUT=./licenses
ORIGIN_LICENSE_INDEX=./license_index.jsonl
ORIGIN_LICENSE_LEDGER=./license_ledger.json
ORIGIN_LEDGER_PRIVATE_KEY=issuer_private.pem
ORIGIN_LEDGER_PUBLIC_KEY=issuer_public.pem
ORIGIN_PLAN_NAME=pro
ORIGIN_PLAN_DAYS=30

# IPN listener
ORIGIN_IPN_HOST=0.0.0.0
ORIGIN_IPN_PORT=8080
PAYPAL_VERIFY_URL=https://ipnpb.paypal.com/cgi-bin/webscr

# SMTP (optional email delivery)
ORIGIN_SMTP_HOST=smtp.gmail.com
ORIGIN_SMTP_PORT=587
ORIGIN_SMTP_USER=you@gmail.com
ORIGIN_SMTP_PASS=app_password
ORIGIN_SMTP_FROM=you@gmail.com
```

## Run locally
```
python tools/paypal_ipn_listener.py
```

## PayPal configuration
- Use PayPal IPN or Webhooks
- Set the notification URL to your listener (public URL)
- Pass a stable user ID in the `custom` field (recommended)

## License issuance
The listener executes:
```
origin license-issue --user-id <id> --plan pro --expires-at <timestamp>
```

## Revocation / cancellation
Cancellation events trigger:
```
origin license-ledger-add --ledger license_ledger.json --license-id <id> --revoked-at <now>
```

## Notes
- This is a single-file listener. For production use, place it behind HTTPS (reverse proxy or serverless adapter).
- IPN validation is mandatory and implemented in the listener.
- The license ledger can be hosted as a static file (CDN, GitHub Pages, etc.).
