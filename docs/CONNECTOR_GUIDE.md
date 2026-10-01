# Connector guide

There are three ways to bring a product into LODESTAR. Pick the lightest one that works.

## 1. File drop (no code)

Any scheduled export (CSV or JSON) or SIEM saved-search export can be read.

```yaml
connectors:
  pam:
    enabled: true
    adapter: file_drop
    product: CyberArk PAM
    settings:
      path: data/drop/pam              # folder the export lands in (SFTP, SMB, blob sync)
      finding_type: policy_violation   # default type when the file has no type column
      field_map:                       # LODESTAR field: vendor column
        title: EventName
        severity: Risk
        user_id: TargetUser
        asset_id: TargetMachine
        first_seen: Timestamp
      severity_map: {"5": critical, "4": high, "3": medium}
      health: {coverage_pct: 88, kpis: {vaulted_pct: 88, standing_admins: 9}}
```

Fields: `finding_id, title, description, severity, asset_id, user_id, app_id, cve, first_seen,
last_seen, remediation, finding_type`. Missing `finding_id` is derived from a stable hash.

## 2. Signed webhook (push)

Send LODESTAR-shaped findings from the product, a SOAR playbook or a Logic App:

```bash
BODY='[{"finding_id":"waf-123","source":"cloudflare","finding_type":"detection","title":"SQLi burst","severity":"high","asset_id":"web-01"}]'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$LODESTAR_WEBHOOK_SECRET" -hex | sed 's/^.* //')
curl -X POST https://lodestar.example/api/ingest/waf -H "X-Lodestar-Signature: sha256=$SIG" \
     -H "Content-Type: application/json" --data "$BODY"
```

PowerShell:

```powershell
$body = '[{"finding_id":"waf-123","source":"cloudflare","finding_type":"detection","title":"SQLi burst","severity":"high"}]'
$hmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($env:LODESTAR_WEBHOOK_SECRET))
$sig  = -join ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($body)) | ForEach-Object { $_.ToString("x2") })
Invoke-RestMethod -Method Post -Uri https://lodestar.example/api/ingest/waf -Body $body `
  -ContentType "application/json" -Headers @{ "X-Lodestar-Signature" = "sha256=$sig" }
```

Items are upserted by `finding_id` (re-sending updates, never duplicates) and kept for
`retention_days` (default 30).

## 3. Native adapter (code)

```python
# lodestar/agents/connectors/adapters/my_product.py
from ....models import ControlHealth, Domain, Finding, FindingType, Severity
from .base import Adapter, AdapterResult, http_client, request_with_retry

class MyProductAdapter(Adapter):
    name = "my_product"
    supported_domains = (Domain.EDR,)

    def fetch(self, ctx) -> AdapterResult:
        self.require("base_url", "api_token")
        with http_client() as c:
            rows = request_with_retry(c, "GET", f"{self.settings['base_url']}/alerts",
                                      headers={"Authorization": f"Bearer {self.settings['api_token']}"}).json()
        findings = [Finding(finding_id=f"edr-mp-{r['id']}", domain=Domain.EDR, source="my_product",
                            finding_type=FindingType.DETECTION, title=r["name"],
                            severity=Severity(r["severity"].lower()), asset_id=r["hostname"]) for r in rows]
        return AdapterResult(findings=findings,
                             health=ControlHealth(domain=Domain.EDR, product="My Product", coverage_pct=97.0))
```

Register it in `adapters/__init__.py` (`REGISTRY`), add a unit test with a recorded response,
and reference it in `config/lodestar.yaml`. Rules for adapters:

* read-only scopes only; document the permission in `domains.py` (`least_privilege`)
* secrets only through `settings` populated from `${ENV}` references
* always return `ControlHealth` (coverage and freshness feed the posture score)
* use `request_with_retry` (honours `Retry-After`, backs off on 429/5xx)

## Validating a native adapter

The three shipped native adapters (Microsoft Graph Security, Entra ID Protection, Tenable) follow
the vendors' published APIs but must be validated against your tenant in Phase 1: run with
`LODESTAR_LOG=INFO python -m lodestar run --phase 1`, check the counts per connector in the data
quality panel against the vendor console, and spot-check ten findings.

## Adding a correlation rule

```python
Rule("LDS-011", "Stale admin with leaked credentials", "user",
     (all_of(d(Domain.BRAND), ftype(FindingType.EXPOSURE)),            # infostealer / leak
      all_of(d(Domain.IDENTITY), ftype(FindingType.MISCONFIGURATION))), # dormant admin
     Severity.HIGH, "…narrative…", "…action…", ("T1078",))
```
