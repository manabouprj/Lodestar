# Fraud management for financial institutions

In most banks, fraud and cyber run as separate teams with separate tools. Attackers don't
separate them: a lookalike domain harvests credentials (a brand-protection signal), bots stuff
them into the mobile app (a WAF signal), and accounts are taken over and drained (a fraud-engine
signal). LODESTAR joins these signals.

## FraudSentinelAgent (phase 2)

Connects to the fraud engine or case manager (Feedzai, NICE Actimize, SAS Fraud Management,
FICO Falcon, BioCatch, LexisNexis ThreatMetrix, Featurespace) through a read-only reporting API,
an analytics export (`file_drop`) or a signed webhook.

It reports two things:

* **Fraud signals:** account takeover clusters, mule-account networks, authorised-push-payment
  scam clusters, anomalous employee payment approvals, card / gift-card / loyalty fraud.
* **Fraud-control health:** real-time scoring coverage per payment channel, alert backlog,
  disabled rules, model drift, detection-before-loss rate, false-positive rate.

A fraud control with gaps is treated like any other degraded control. An instant-payments
channel without real-time scoring is a coverage gap and appears in the Today list.

## Cyber-enabled fraud correlation

| Rule | Signals joined | Decision raised |
|---|---|---|
| LDS-011 Lookalike phishing driving account takeover | Brand lookalike domain + fraud ATO sessions referred from it | Joint cyber-fraud response: step-up auth, payment holds, customer notice (Head of Fraud, CISO, Customer Ops, 2 h) |
| LDS-012 Compromised employee credentials + anomalous payment | Infostealer / identity risk on an employee + fraud alert on a payment they approved | Hold/recall payment, suspend payment rights (Head of Fraud, Payments Ops, HR/Legal, 1 h, regulatory) |
| LDS-013 Bot-driven account takeover | WAF credential stuffing on a customer app + fraud ATO on the same app | Bot mitigation and step-up on login (channel owner, Head of Fraud, 4 h) |
| Mule network (no correlation needed) | Fraud engine mule detection | Suspicious transaction report decision (MLRO, 24 h, regulatory), banking and fintech profiles only |

## KRIs (banking and fintech profiles)

| KRI | Default appetite |
|---|---|
| Fraud detected before loss (by value) | ≥ 95 % |
| Fraud alert backlog (oldest untriaged) | ≤ 24 h |
| Payment channels under real-time fraud scoring | 100 % |

Retail (card, gift-card and loyalty fraud) and telecom (SIM-swap, subscription fraud) carry a
fraud detection KRI. Aviation weights loyalty-programme fraud.

## What LODESTAR will not do

It does not block or restrict customer accounts, hold, recall or release payments, freeze
accounts, file SAR/STR reports or contact customers. Avoiding tipping-off is a legal obligation,
so customer contact for mule cases is never automated. All of these are Decision-desk items for
the Head of Fraud, MLRO or Payments Operations.

## Data handling

Send aggregates and case references, not full PAN or account numbers. Map customers to
pseudonymous IDs in the export. The fraud engine stays the system of record for cases.
