# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub: **Security → Report a vulnerability** on
this repository (private vulnerability reporting). Do not open a public issue.

Include the affected version (`python -m lodestar --version` or the tag), the component (API, MCP
server, an adapter, the dashboard ...), steps to reproduce and the impact you expect. You will get an
acknowledgement within 5 working days and a fix or mitigation plan within 30 days for confirmed issues.
Credit is given in the CHANGELOG unless you prefer otherwise.

## Supported versions

Security fixes go into the latest minor release (currently 2.3.x). Upgrade by following
[docs/PRODUCTION.md](../docs/PRODUCTION.md#upgrades).

## Scope

LODESTAR's own code and default configuration. Vulnerabilities in dependencies should be reported to
those projects; Dependabot raises updates here. The threat model and hardening guidance are in
[docs/SECURITY.md](../docs/SECURITY.md).
