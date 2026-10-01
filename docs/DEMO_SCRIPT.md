# Presentation demo script (22 minutes)

**Setup:** `python -m lodestar demo`, then open `dist/lodestar-dashboard.html` (works offline) or
`python -m lodestar serve`. The dashboard opens in the dark operations-centre theme (Light button top right). Start on **Sandline Bank (Demo) · Banking**. All organisations are
fictional; say so up front.

## 1. The problem (1 min)

"A bank like this runs 18 security and fraud tools, a HackerOne programme and several intelligence feeds. Between them they raised **1,554 signals**. Every tool
calls some of its findings critical. Where does the CISO start on Monday morning?"

## 2. From noise to focus (2 min) - hero panel

Point at the funnel: **1,554 signals → 942 open → 203 this week → 28 today → 20 attack paths**.
Today's list is under 3 % of open signals, and it is capped so the team can finish it.

## 2b. What needs a human now (2 min) - Decision desk

"Agents did the investigation. These **25 decisions** need a person, and **10 of them are needed now**."
Open *Approve emergency patch or isolation of Internet banking gateway*: who decides (CISO + Head of
IT Operations), the 4-hour deadline, what the agents prepared, and what they **will not** do.
Click *Approve emergency patch now* to show how a verdict is recorded. Filter **Decider → MLRO** to
show the suspicious-transaction decision.

## 3. Why is this on my list? (3 min) - Focus queue, Today tab

Open the top item, **Citrix NetScaler ADC session token leak (CVE-2023-4966)** on the internet
banking gateway. Read the reasons aloud:
on CISA KEV · active exploitation in our environment · crown-jewel asset · internet-facing ·
SLA breached under the 7-day banking SLA · part of an attack path.
"No black box. Your auditors can read this."

Filter **Owner → Identity & Access** to show how each team gets its own list.

## 4. What no single tool sees (3 min) - Attack paths

Walk through three real-world CISO scenarios:

| Attack path | Tools that each saw part of it |
|---|---|
| KEV vulnerability under active attack on the internet banking gateway | VMDR + WAF |
| Privileged account takeover risk: MFA-fatigue sign-ins on a domain admin that is not vaulted | Identity + PAM |
| Customer ID documents in a publicly readable storage bucket | Cloud (CNAPP) + DLP |
| Employee pasting customer data into an unsanctioned GenAI tool | Web proxy + DLP |
| Ransomware precursor on Core banking, and no immutable backup | EDR + Backup |

## 4b. Cyber-enabled fraud (2 min) - Fraud & financial crime

The lookalike domain the brand tool found is the same one referring sessions in **214 customer
account takeovers** in the fraud engine (LDS-011). An employee whose credentials appeared in
infostealer logs approved a **USD 640K** payment to a one-day-old beneficiary (LDS-012). Fraud
KPIs: USD 412K confirmed loss and USD 9.8M prevented in 30 days, a 31-hour alert backlog, and the
instant-payments channel not scored in real time.

## 4b2. Outside warnings (2 min) - External reports & intelligence

"The national CERT e-mailed an advisory this morning: CVE-2023-4966 is being exploited against
banks." LODESTAR read the mailbox, matched it to our internet banking gateway and raised its
priority. The sector ISAC's indicator `update-sync-cdn.example` was **seen in our own proxy and EDR
logs**, which raised an incident decision and, because banking is critical infrastructure, a
**mandatory notification decision** with its deadline. HackerOne: an SSRF report on the partner
API is already being probed by attackers (LDS-014), and a researcher found a staging host that
isn't in the CMDB. Point at *20 ingested → 2 relevant → 1 sighted*: everything else was filtered out.
Switch to **Helionyx Power & Water** to show a CSAF ICS advisory matched to 20 PLCs, HMIs and RTUs.

## 4c. Ask it in Slack or Teams (1 min) - Ask LODESTAR

Click `decisions`, then `intel`, `bounty` and `fraud`. "Every morning at 07:00 the same brief lands in the leadership
channel. Anyone can ask `/lodestar why DEC-…`, and a mapped CISO can approve from Slack. LODESTAR
still changes nothing itself."

## 5. Are our controls working? (2 min) - Control assurance

Show **DLP: stale** (feed 61 h old), **AI security: degraded** (inventory incomplete),
**DAST: degraded** (APIs not covered), **EDR 95.5 % coverage** vs 98 % appetite, **fraud scoring covers 86.4 % of payment channels**.
"A control that silently stops working is a risk, so it becomes a finding."

## 6. Same platform, different industry (2 min)

Switch to **Helionyx Power & Water**: OT is weighted ×1.45, unmanaged vendor remote access to
SCADA appears as an attack path (LDS-009), NERC CIP and IEC 62443 appear in the frameworks.
Switch to **Aerolume Airways**: ICAO / EASA Part-IS, baggage OT, fake booking sites.
"No code change. Each industry is a configuration file."

## 7. The board conversation (2 min) - reports

Open `reports/sandline-bank-demo/<date>_quarterly.html`:
posture **60.3 / 100** vs appetite 75 (up from about 47 six months ago), KRIs vs appetite,
**five decisions requested from the board**, indicative exposure **USD 19.5M - 85.6M** across open attack paths, the "Waiting on people" table,
the fraud section and framework readiness for NIST CSF 2.0, ISO 27001 and PCI DSS.
Then the weekly report: the same data, written for technical leads with owners and due dates.

## 8. How we get there (1 min) - docs/DEPLOYMENT_PHASES.md

Phase 1 in six weeks with five connectors gives the Today list and the weekly report. Each
later phase adds controls without disturbing what is live. Every write action needs a human.

## Likely questions

* **Does it replace the SIEM / tools?** No. It reads from them (read-only) and decides what matters across them.
* **Does it use AI to decide priorities?** No, the score is a transparent formula. AI is optional, writes narrative only, and every number it writes is checked against the data.
* **How long to add a product we use?** A CSV/JSON export works the same day via `file_drop`; a native adapter is about 60 lines of code.
* **Where does the data live?** In your environment: one container and a database you control.
