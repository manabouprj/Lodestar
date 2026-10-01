# Security of LODESTAR

LODESTAR aggregates the most sensitive view an organisation has of itself: where it is weak.
It is designed and should be operated as a tier-0 security system.

## Threat model (summary)

| Threat | Control in v1.0 | Operator action |
|---|---|---|
| Stolen connector credentials used to change security tools | All adapters are read-only; least-privilege scopes documented per connector | Create dedicated read-only service identities; review quarterly |
| Secrets leaked via Git | Config loader refuses literal secrets for any key containing secret/password/token/api_key/access_key; `.env` git-ignored | Use a secret store (Key Vault, Vault) to populate env vars |
| Unauthorised access to the dashboard / API | API keys per role (exec / analyst / ciso), constant-time comparison, enforced in live mode; HttpOnly SameSite=Strict cookie for browser | Front with SSO-aware proxy and MFA; rotate keys |
| Forged findings pushed to the webhook | HMAC-SHA256 signature, 5 MB body cap, schema validation | Rotate `LODESTAR_WEBHOOK_SECRET`; restrict source IPs at the proxy |
| Automated, wrong remediation | No write actions to controls; ITSM tickets require human approval and default to dry-run | Keep dry-run until change-board sign-off |
| LLM leaking data or inventing numbers | Off by default; sends only aggregated facts; output discarded if it contains numbers not present in the facts | Use an enterprise LLM agreement with no training on inputs |
| Container compromise | Non-root user, read-only filesystem, `no-new-privileges`, all capabilities dropped, bound to 127.0.0.1 | Scan image in CI; patch base image monthly |
| Tampering / repudiation | Audit table for every agent run, approval, pipeline run and ingest | Ship audit to SIEM |
| Spoofed Slack / Teams requests | Slack v0 signing-secret verification with 5-minute replay window; Teams outgoing-webhook HMAC; unmapped chat users are read-only | Publish only `/api/chat/*` externally; private channels only |
| A decision taken by the wrong person | Role check per decision type (regulatory, risk acceptance and safety-critical need decision authority); verdict audit with channel and user | Keep chat role mappings in change control |
| Web attacks on the dashboard | Strict CSP, `X-Frame-Options: DENY`, `nosniff`, all dynamic text HTML-escaped | — |

## Data handled

Finding metadata (hostnames, user principal names, CVEs, titles). No payload content, no
email bodies, no file contents. Retention: last 30 runs, 400 days of daily snapshots,
webhook items 30 days (configurable).

## Known gaps (tracked in PEER_REVIEW.md)

* no native OIDC/SAML in-app (use the proxy)
* webhook has no timestamp-based replay window yet
* SQLite file should sit on an encrypted volume
* Teams decisions are text commands until a Bot Framework app with card actions is added
