# LODESTAR Risk Score (LRS)

The score decides what a CISO sees first, so it has to be explainable, deterministic and
tunable. There is no machine-learning model in the ranking path. Every factor is stored on the
finding (`score_factors`) together with plain-English reasons (`why`).

## Formula

```
raw = 0.30 × Severity + 0.25 × Exploitability + 0.20 × AssetCriticality
    + 0.15 × Exposure + 0.10 × TimePressure                     (each 0..1)

LRS = min(100, 100 × raw × VerticalWeight × Compensating × AttackPath)
```

| Factor | How it is derived |
|---|---|
| Severity | critical 1.0 · high 0.75 · medium 0.45 · low 0.2 · info 0.05 (vendor severity, normalised) |
| Exploitability | max(EPSS, type baseline). KEV → ≥0.95. Active exploitation in our environment (a detection referencing the same CVE on the same asset) → 1.0. Baselines: incident 1.0, detection 0.8, exposure 0.7, policy violation 0.55, coverage gap 0.5, misconfiguration 0.45, vulnerability 0.2 |
| Asset criticality | 0.2 + 0.8 × (criticality − 1) / 4, from the CMDB / crown-jewel register (1-5). Unknown assets default to 3 and are reported in data quality |
| Exposure | internet 1.0 · partner 0.65 · internal 0.35 · isolated 0.1 |
| Time pressure | share of the industry SLA consumed; 1.0 once overdue |
| Vertical weight | `1 + (w − 1) × 0.6` where `w` is the profile's weight for the control domain (e.g. OT ×1.45 for power utilities → ×1.27 effective) |
| Compensating | ×0.85 when a compensating control is recorded (virtual patch, segmentation) |
| Attack path | ×1.20 when the finding is part of a correlated toxic combination |

## Focus horizons

| Horizon | Rule |
|---|---|
| **Today** | LRS ≥ 75 **and** (severity high/critical **or** KEV **or** attack path **or** active exploitation); or active exploitation on a criticality ≥ 4 asset. Capped at `today_capacity` (25): attack-path, KEV and actively-exploited items are always kept; the lowest-scoring others roll to This week with a reason |
| **This week** | LRS ≥ 55 |
| **This month** | LRS ≥ 35 |
| **Backlog** | everything else (tracked and reported, not pushed to people) |

The capacity cap exists because a Today list nobody can finish is not a priority list.

## Posture score (0-100)

```
posture = 0.45 × mean(control effectiveness)
        + 0.40 × KRI attainment vs appetite   (within 1.0 · near 0.6 · breach 0.15)
        + 0.15 × acute exposure               (100 − min(60, 1.5 × Today) − min(40, 3 × attack paths))
```

Control effectiveness = 55% coverage + 20% data freshness + 15% policy drift + 10% health issues.
A data-trust score (mandatory feeds missing, stale feeds, CMDB match rate) is shown next to the
posture score, and the dashboard flags **medium/low confidence** when the posture is built on gaps.

## Tuning

All thresholds and weights live in `config/lodestar.yaml → scoring` and the industry profile.
Recommended calibration after 60 days in production: export analyst overrides (items manually
promoted or demoted), compare to LRS, adjust weights in steps of 0.05, re-run the test suite.
Weights must sum to 1.0 (enforced at start-up).

## Worked example (Sandline Bank demo)

`CVE-2023-4966` on the internet banking Citrix gateway:

| Factor | Value | Why |
|---|---:|---|
| Severity | 1.00 | critical |
| Exploitability | 1.00 | on CISA KEV, and WAF shows exploit attempts against the same asset |
| Asset criticality | 1.00 | crown jewel (Core banking) |
| Exposure | 1.00 | internet-facing |
| Time pressure | 1.00 | banking SLA for critical is 7 days; first seen 10 days ago |
| Attack path | ×1.2 | LDS-001 |
| **LRS** | **100 → Today** | |

Compare a medium "PAM session not recorded" finding 90 days old on a crown-jewel system: it can
score above 75 but is held to **This week**, because nothing about it is urgent today.
