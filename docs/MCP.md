# MCP: LODESTAR as the central integration point for AI assistants

LODESTAR speaks the **Model Context Protocol (MCP)** in both directions:

* **As a server:** one governed MCP endpoint through which AI assistants and agents (Claude, Microsoft
  Copilot Studio, Azure AI Foundry Agent Service, Amazon Bedrock AgentCore, IDEs) get the organisation's
  prioritised security picture.
* **As a client:** the `mcp` adapter ingests from a security vendor's MCP server like any other source.

```
  Claude / Copilot / Foundry / Bedrock / IDE                     vendor MCP servers (EDR, CSPM, ...)
            |  one credential, read-only tools                               ^  one read-only tool each
            v                                                                |
   +-------------------  LODESTAR  ---------------------------------------------------------+
   |  /mcp/  (streamable HTTP, API key / OIDC bearer, roles, org scope, audit)  |  mcp adapter |
   |  priorities . findings . attack paths . KRIs . decisions . controls . ingestion health  |
   |  <- collected, de-duplicated, entity-resolved, correlated and scored from 21 domains ->  |
   +------------------------------------------------------------------------------------------+
            ^ SIEM-first queries, native APIs, http_json, file drop, signed webhooks
```

## Why a central server

Without a hub, every assistant needs its own credentials and tool definitions for every console: EDR,
SIEM, scanner, IdP, CSPM and the rest. That is many standing credentials to secure, rotate and audit, and
the assistant still has to work out what matters. With LODESTAR in the middle:

| | Assistant wired to each tool | Assistant wired to LODESTAR |
|---|---|---|
| Credentials | One per tool per assistant | One API key or SSO token, org-scoped, revocable in one place |
| Blast radius | Write-capable vendor APIs exposed to the model | Read-only tools only. Nothing can isolate, close, approve or change |
| Answers | Raw alerts the model must de-duplicate and rank | Prioritised, correlated items with "why", owner and due date |
| Governance | Per-tool logs, if any | Every tool call audit-logged with the actor. Roles and organisations enforced server-side |
| Sensitive data | Whatever the tool returns | TLP:RED redacted, internal evidence keys stripped |

## Connecting

### Over the network (recommended)

The MCP server is mounted on the LODESTAR API at **`https://<lodestar-host>/mcp/`** (streamable HTTP,
stateless, JSON responses). Keep the trailing slash. It is on by default. Set `mcp.enabled: false` in
`lodestar.yaml` to switch it off.

Authentication is the same as the REST API:

* **API key:** `Authorization: Bearer <key>` or `X-API-Key: <key>`, from `LODESTAR_API_KEYS`
  (`analyst@acme-bank:<key>` limits it to one organisation). Create a dedicated key per assistant.
* **OIDC bearer JWT** from your identity provider: for example an Entra ID app-role or managed-identity
  token for a Foundry agent. Roles and organisations come from `security.oidc.role_map` / `org_map`. The
  audience is `security.oidc.mcp_audience`, else `audience`, else `client_id`.
* In demo mode (or `security.require_auth: false`) the endpoint is open, as the dashboard is.

Unauthenticated calls get `401` and are audit-logged as `mcp_denied`.

Client configuration (any client that supports remote MCP servers with headers), for example:

```json
{
  "mcpServers": {
    "lodestar": {
      "type": "http",
      "url": "https://lodestar.acme.example/mcp/",
      "headers": { "Authorization": "Bearer ${LODESTAR_MCP_KEY}" }
    }
  }
}
```

* **Azure AI Foundry Agent Service:** add an MCP tool with `server_url` `https://lodestar.../mcp/` and the
  key or token in the headers. Allow the read-only tools you want (all of them are read-only).
* **Amazon Bedrock AgentCore Gateway:** register LODESTAR as an MCP server target, with outbound auth set
  to an API key or OAuth.
* **Copilot Studio:** add an MCP connector pointing at the URL, using API key authentication.

### On the LODESTAR host (stdio)

For a desktop client running on the LODESTAR host itself:

```json
{
  "mcpServers": {
    "lodestar": {
      "command": "C:\\Projects\\lodestar\\.venv\\Scripts\\python.exe",
      "args": ["-m", "lodestar", "mcp", "--role", "analyst"],
      "cwd": "C:\\Projects\\lodestar"
    }
  }
}
```

`--role exec|analyst|ciso` (default `analyst`) and `--org <key>` scope the session. Anyone who can run
this command can already read the store, so stdio adds no access. It only gives a desktop client a
convenient way in.

## Tools

All tools are annotated `readOnlyHint: true, destructiveHint: false`. Most also take `org` (from
`list_organisations`); without it, the first organisation you may see is used.

| Tool | Role | Returns |
|---|---|---|
| `whoami` | exec | Your actor, role and organisations |
| `list_organisations` | exec | Organisations you may see, with industry, last run and posture |
| `get_overview` | exec | Posture score, open items per horizon, SLA breaches, attack paths, decisions waiting, data confidence, ingestion health. **Start here** |
| `get_kris` | exec | Key risk indicators with provenance (connector, computed, manual) and the ones not measured |
| `list_decisions` | exec | Decisions waiting for (or taken by) a named human. Read-only: deciding stays in the dashboard or chat |
| `get_priorities` | analyst | The work list for `today`, `week`, `month` or `backlog`: score, why, owner team, due date. Filter by `domain` or `team` |
| `search_findings` | analyst | By text, domain, minimum severity, asset, CVE and status |
| `get_finding` | analyst | One finding in full: description, remediation, score factors, evidence, frameworks |
| `get_attack_paths` | analyst | Correlated attack paths with narrative, MITRE techniques and the recommended action |
| `get_controls` | analyst | Effectiveness, coverage, data age, drift and issues per control |
| `get_ingestion_health` | analyst | Per-source ingestion state and checks ([INGESTION_OPERATIONS.md](INGESTION_OPERATIONS.md)) |
| `check_ingestion` | ciso | Runs the ingestion sanity test **now** (a live, read-only fetch from the vendor APIs). At most once per 5 minutes per organisation |

A call above your role returns a tool error such as `this tool requires role 'analyst' (you are 'exec')`.
A call for an organisation you are not mapped to returns `unknown or not permitted org`.

Example prompts an assistant can answer:

* "What must the infrastructure team fix today at Acme Bank, and why?"
* "Is there an attack path through the internet-facing portal?"
* "Which decisions are overdue and who has to take them?"
* "Our EDR numbers look low. Is the ingestion healthy?"

## Safety model

* **Read-only.** There is no tool that changes LODESTAR, a security control or a ticket. Action approval
  and decisions require a named human in the dashboard or chat, with role checks and audit. The MCP
  server cannot reach them.
* **Untrusted content.** Finding titles, descriptions and evidence come from security tools and can carry
  attacker-controlled text (a phishing subject line, a crafted hostname). The server instructions tell the
  client to treat every result as data and never as instructions. Keep human approval on in your agent
  framework for any tool **outside** LODESTAR that can act.
* **Scope.** Every call runs with the caller's role and organisations. Results are filtered server-side.
* **Redaction.** TLP:RED items show `[TLP:RED item - open the dashboard]` with no description, user or
  evidence. Internal keys (`_src`, `_sync` ...) are stripped.
* **Audit.** Each data tool call is written to the audit log (`mcp_tool`, with actor, tool and org), as
  are denied connections.
* **Cost control.** `check_ingestion` is rate-limited, and the other tools read the latest stored run, so
  they never trigger collection.

## The `mcp` adapter: ingesting from a vendor's MCP server

```yaml
connectors:
  cloud:
    adapter: mcp
    product: Example CNAPP
    interval_minutes: 240
    settings:
      url: https://mcp.cnapp.example/mcp
      auth: {type: bearer, token: "${CNAPP_MCP_TOKEN}"}     # or header / basic / oauth2, as for http_json
      tool: list_findings
      arguments: {since: "{since}", severity: [critical, high], limit: 1000}
      records: findings                                    # dotted path in the tool's structured result
      cursor_column: updated_at                            # incremental because {since} is used
      field_map: {finding_id: id, title: title, severity: severity, asset_id: resource.name,
                  first_seen: created_at, cve: cve}
      finding_type: misconfiguration
      health: {coverage_pct: 98}
```

* LODESTAR lists the server's tools, checks that `tool` exists, and **refuses** to call it if it is
  annotated `destructiveHint: true` or `readOnlyHint: false`, whatever the configuration says. A tool
  without annotations is called with a warning. Set `require_read_only_annotation: true` to refuse those
  too.
* Only the one named tool is ever called, only with the configured arguments. The model is not
  involved: this is deterministic ingestion.
* The result is read from the tool's structured content, or from JSON text content. Nested objects are
  flattened to dotted keys (`resource.name`). Mapping, sync modes, health, expectations and continuous
  validation work exactly as for `http_json`.
* TLS verification stays on (`ca_bundle` for a private CA). Credentials come only from environment
  references.
* Remote (streamable HTTP) servers only. LODESTAR does not launch local stdio server processes from
  configuration.

Test it with `lodestar test-connector cloud` and `lodestar check-ingestion --domain cloud`.

## Operations

* The endpoint shares the API's TLS termination, reverse proxy and rate limits. Expose `/mcp/` only to
  the networks your agent platforms come from.
* Watch `lodestar_http_requests_total` and the `mcp_tool` / `mcp_denied` audit events.
* Revoke an assistant by removing its key from `LODESTAR_API_KEYS` (or its app role in the IdP) and
  restarting the API.
