# Security of LODESTAR

LODESTAR aggregates the most sensitive view an organisation has of itself: where it is weak.
It is designed and should be operated as a tier-0 security system.

## Threat model (summary)

| Threat | Control (v2.0) | Operator action |
|---|---|---|
| Stolen connector credentials used to change security tools | All adapters are read-only; least-privilege scopes documented per connector | Create dedicated read-only service identities; review quarterly |
| Secrets leaked via Git | Config loader refuses literal secrets for any key containing secret/password/token/api_key/access_key; `.env` git-ignored | Use a secret store (Key Vault, Vault) to populate env vars |
| Unauthorised access to the dashboard / API | In-app OIDC SSO (code + PKCE, ID token verified against JWKS; groups mapped to role and organisation); bearer JWTs for services; API keys per role, optionally per organisation, constant-time comparison; enforced in live mode | Enforce MFA in the IdP; keep `role_map` in change control; rotate keys |
| Session theft / CSRF | HMAC-signed session cookie (HttpOnly, Secure, SameSite=Lax, 8 h); double-submit CSRF token on every cookie-authenticated POST; HSTS | Keep `secure_cookies: true` behind TLS |
| One organisation seeing another's data (group / MSSP) | Every table org-scoped; principals carry their organisations; unknown or foreign orgs return 404; webhooks need `?org=` and can use a per-org secret | Separate deployments where regulation requires physical separation |
| Forged or replayed findings pushed to the webhook | HMAC-SHA256 signature, optional signed timestamp with a 5-minute window (`security.webhook_require_timestamp`), 5 MB body cap, schema validation | Rotate the webhook secrets; restrict source IPs at the proxy |
| A broken tool hiding risk | Lifecycle rules: a failed / skipped / empty source never resolves findings. The IngestionMonitorAgent turns repeated failures, staleness, silence and volume drops into findings and alerts ([INGESTION_OPERATIONS.md](INGESTION_OPERATIONS.md)) | Route `ingestion.alerts` to the on-call channel; alert on `lodestar_source_state{state=~"failing\|stale"}` |
| An AI assistant misusing access, or prompt injection through tool output | MCP server is read-only (no tool changes anything), uses the API's principals, roles and org scope, redacts TLP:RED, audit-logs every call and tells the client that tool output is data, not instructions. The `mcp` adapter refuses vendor tools not annotated read-only ([MCP.md](MCP.md)) | One API key per assistant, analyst role or lower; keep human approval on for any other agent tool that can act |
| Automated, wrong remediation | No write actions to controls; ITSM tickets require human approval and default to dry-run | Keep dry-run until change-board sign-off |
| LLM leaking data or inventing numbers | Off by default; sends only aggregated facts; output discarded if it contains numbers not present in the facts | Use an enterprise LLM agreement with no training on inputs |
| Container compromise | Non-root user, read-only filesystem, `no-new-privileges`, all capabilities dropped, bound to 127.0.0.1 | Scan image in CI; patch base image monthly |
| Tampering / repudiation | Audit table for every agent run, approval, pipeline run and ingest | Ship audit to SIEM |
| Spoofed Slack / Teams requests | Slack v0 signing-secret verification with 5-minute replay window; Teams outgoing-webhook HMAC; unmapped chat users are read-only | Publish only `/api/chat/*` externally; private channels only |
| A decision taken by the wrong person | Role check per decision type (regulatory, risk acceptance and safety-critical need decision authority); verdict audit with channel and user | Keep chat role mappings in change control |
| Spoofed advisory / researcher e-mails | Sender allow-list; DKIM/SPF check (unverified mail capped at medium); no link following; deterministic parsing (prompt-injection text has no effect) | Dedicated mailbox with Mail.Read scoped by ApplicationAccessPolicy or read-only IMAP |
| Leaking TLP-restricted intelligence | TLP carried on every finding; TLP:RED titles never sent to chat, notifications or reports; LLM receives aggregates only | Keep chat channels private; review TLP handling with the CERT / ISAC |
| Storing exploit details from researchers | HackerOne proof-of-concept text is not copied; only title, severity, CWE, asset and link | Restrict HackerOne access to the AppSec team |
| Web attacks on the dashboard | Strict CSP, `X-Frame-Options: DENY`, `nosniff`, all dynamic text HTML-escaped | — |

## Data handled

Finding metadata (hostnames, user principal names, CVEs, titles). No payload content, no
email bodies, no file contents. Retention: last `storage.keep_runs` full runs (5), closed findings 400 days, snapshots 800 days, audit 400 days,
webhook items 60 days, per-fetch ingestion history 30 days (all configurable under `ops.retention`).

## Known gaps (tracked in PEER_REVIEW.md)

* SAML is not supported in-app (OIDC is); use the IdP's OIDC endpoint
* webhook timestamps are optional by default - set `security.webhook_require_timestamp: true` once every sender signs them
* SQLite file should sit on an encrypted volume
* Teams decisions are text commands until a Bot Framework app with card actions is added
