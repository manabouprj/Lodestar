"""Generate the README architecture diagram (docs/images/architecture-{dark,light}.svg).

Run after changing the pipeline:  python scripts/make_architecture_svg.py
The README shows the dark or light variant to match the reader's GitHub theme (<picture>).
"""
from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).resolve().parent.parent / "docs" / "images"
W, H = 1200, 972
FONT = "-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"

THEMES = {
    "dark": dict(bg="#0d1117", panel="#161b22", panel2="#1c2128", line="#30363d", ink="#e6edf3", ink2="#9198a1",
                 src="#4493f8", ing="#3fb950", pipe="#d29922", out="#ab7df8", ppl="#f47067", arrow="#6e7681"),
    "light": dict(bg="#ffffff", panel="#f6f8fa", panel2="#eef1f4", line="#d1d9e0", ink="#1f2328", ink2="#59636e",
                  src="#0969da", ing="#1a7f37", pipe="#9a6700", out="#8250df", ppl="#cf222e", arrow="#818b98"),
}

SOURCES = [
    ("Endpoint & identity", ["EDR", "Identity / IdP", "PAM", "ZTNA"]),
    ("Network & web", ["Firewall", "Web proxy", "WAF", "Email security"]),
    ("Exposure & code", ["VMDR", "Cloud / CNAPP", "SAST", "DAST"]),
    ("Detect & respond", ["SIEM / SOC", "OT / ICS", "Backup"]),
    ("Business risk", ["Fraud engine", "Brand / DRP", "AI security", "DLP"]),
]
EXTERNAL = ["HackerOne bug bounty", "CERT / ISAC (TAXII)", "MISP", "PSIRT / CISA CSAF", "Advisory mailbox"]
PATHS = ["SIEM-first query · 6 SIEMs", "Native API · REST / MCP", "File drop · CSV / JSON", "Signed webhook", "Feeds & mailbox"]
ROW1 = [("1", "Asset & identity", "CMDB, crown jewels,|people directory"), ("2", "Threat hunt", "intel IOCs searched|in SIEM telemetry"),
        ("3", "Data quality", "entity resolution,|ingestion checks"), ("4", "Lifecycle", "first seen, resolve,|carry forward"),
        ("5", "Threat intel", "KEV, EPSS,|relevance filter"), ("6", "Control assurance", "coverage, freshness,|policy drift")]
ROW2 = [("7", "Correlation", "attack paths|across tools"), ("8", "Prioritisation", "risk score →|Today / Week / Month"),
        ("9", "Compliance", "framework|readiness"), ("10", "Action drafts", "tickets and|playbooks"),
        ("11", "Decision agent", "what only a|human may do")]
OUTPUTS = [("Dashboard", "CISO + technical teams"), ("Business reports", "weekly · monthly · quarterly"),
           ("Slack / Teams", "ask, brief, decide"), ("REST API · MCP", "SSO, RBAC, AI assistants"),
           ("ITSM", "ServiceNow / Jira, approved only"), ("Metrics & alerts", "Prometheus, ingestion alerts")]


class Svg:
    def __init__(self, t: dict[str, str]):
        self.t, self.parts = t, []

    def add(self, s: str) -> None:
        self.parts.append(s)

    def rect(self, x, y, w, h, fill, stroke=None, r=8, sw=1, dash=None):
        st = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
        da = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}"{st}{da}/>')

    def text(self, x, y, s, size=13, fill=None, weight=400, anchor="start", italic=False):
        it = ' font-style="italic"' if italic else ""
        self.add(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill or self.t["ink"]}" '
                 f'text-anchor="{anchor}"{it}>{escape(s)}</text>')

    def arrow(self, x1, y1, x2, y2, color=None, dash=None, width=1.6):
        da = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color or self.t["arrow"]}" '
                 f'stroke-width="{width}"{da} marker-end="url(#ah)"/>')

    def band(self, x, y, w, h, accent, title, subtitle=""):
        self.rect(x, y, w, h, self.t["panel"], self.t["line"])
        self.add(f'<rect x="{x}" y="{y + 10}" width="4" height="{h - 20}" rx="2" fill="{accent}"/>')
        self.text(x + 18, y + 26, title, 14, weight=650)
        if subtitle:
            self.text(x + 18 + len(title) * 7.9 + 10, y + 26, subtitle, 12, self.t["ink2"])

    def chip(self, x, y, w, label, accent=None, h=24):
        self.rect(x, y, w, h, self.t["panel2"], self.t["line"], r=5)
        if accent:
            self.add(f'<circle cx="{x + 11}" cy="{y + h / 2}" r="3" fill="{accent}"/>')
        self.text(x + (20 if accent else w / 2), y + h / 2 + 4.5, label, 12, anchor="start" if accent else "middle")


def build(theme: str) -> str:
    t = THEMES[theme]
    s = Svg(t)
    s.add(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
          f'font-family="{FONT}" role="img" aria-labelledby="t d">')
    s.add('<title id="t">LODESTAR architecture</title>')
    s.add('<desc id="d">Security controls and external intelligence are collected read-only through five integration '
          'paths into 21 connector agents, processed by an eleven-stage agent pipeline backed by a SQLite store and an '
          'industry profile, and delivered to a dashboard, reports, chat, API, ITSM and metrics. People make every '
          'decision; approved actions only then reach ITSM.</desc>')
    s.add(f'<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
          f'<path d="M0,0 L10,5 L0,10 z" fill="{t["arrow"]}"/></marker></defs>')
    s.rect(0, 0, W, H, t["bg"], r=0)
    s.text(32, 42, "LODESTAR", 22, weight=750)
    s.text(172, 42, "read-only collection  →  agent pipeline  →  people decide", 15, t["ink2"])

    # 1. sources -----------------------------------------------------------
    y0 = 62
    s.band(24, y0, 820, 178, t["src"], "Your security controls", "read-only scopes, 21 domains")
    cx = 42
    for title, items in SOURCES:
        s.text(cx, y0 + 54, title, 11.5, t["ink2"], weight=600)
        for i, it in enumerate(items):
            s.chip(cx, y0 + 64 + i * 27, 146, it, t["src"])
        cx += 158
    s.band(860, y0, 316, 178, t["src"], "External reports & intel")
    for i, it in enumerate(EXTERNAL):
        s.chip(878, y0 + 42 + i * 26, 280, it, t["src"], h=22)

    # 2. integration paths -------------------------------------------------
    y1 = 262
    for x in (240, 434, 628, 822, 1016):
        s.arrow(x - 60 if x < 900 else x, y0 + 178, x - 60 if x < 900 else x, y1 - 2)
    s.band(24, y1, 1152, 106, t["ing"], "Integration paths", "pick the lightest per control - most teams start SIEM-first")
    px, pw = 42, 214
    for p in PATHS:
        s.chip(px, y1 + 40, pw, p, t["ing"], h=26)
        px += pw + 12
    s.text(42, y1 + 92, "21 connector agents  ·  one per control domain  ·  failure-isolated (a failed source never closes findings)"
           "  ·  per-source cadence 15 min - 24 h  ·  validated every run", 12, t["ink2"])

    # 3. pipeline ---------------------------------------------------------
    y2 = 392
    s.arrow(113, y1 + 106, 113, y2 - 2)
    s.band(24, y2, 920, 270, t["pipe"], "Agent pipeline", "phase-gated 0 → 4, 15-minute scheduler tick")
    bw, bh, gap = 140, 76, 10

    def step(x, y, n, name, sub):
        s.rect(x, y, bw, bh, t["panel2"], t["line"], r=7)
        s.add(f'<circle cx="{x + 15}" cy="{y + 18}" r="10" fill="none" stroke="{t["pipe"]}" stroke-width="1.5"/>')
        s.text(x + 15, y + 22, n, 10.5, t["pipe"], weight=700, anchor="middle")
        s.text(x + 30, y + 23, name, 12, weight=650)
        for j, line in enumerate(sub.split("|")):
            s.text(x + 10, y + 45 + j * 15, line, 11, t["ink2"])

    col = [42 + i * (bw + gap) for i in range(6)]
    r1y, r2y = y2 + 46, y2 + 46 + bh + 30
    for i, (n, name, sub) in enumerate(ROW1):
        step(col[i], r1y, n, name, sub)
        if i:
            s.arrow(col[i] - gap + 1, r1y + bh / 2, col[i] - 1, r1y + bh / 2)
    s.arrow(col[5] + bw / 2, r1y + bh + 1, col[5] + bw / 2, r2y - 1)          # turn down
    for i, (n, name, sub) in enumerate(ROW2):                              # row 2 runs right -> left
        c = 5 - i
        step(col[c], r2y, n, name, sub)
        if i:
            s.arrow(col[c + 1] - 1, r2y + bh / 2, col[c] + bw + 1, r2y + bh / 2)
    s.text(col[0], r2y + 22, "On demand:", 11.5, t["ink2"], weight=600)
    for j, line in enumerate(["Reporting, Narrative", "and ChatOps agents", "read the same results"]):
        s.text(col[0], r2y + 40 + j * 15, line, 11, t["ink2"])

    # side rail: store + industry profile -----------------------------------
    s.band(956, y2, 220, 128, t["pipe"], "Store")
    s.add(f'<ellipse cx="988" cy="{y2 + 58}" rx="15" ry="5" fill="none" stroke="{t["ink2"]}" stroke-width="1.3"/>'
          f'<path d="M973,{y2 + 58} v26 a15,5 0 0 0 30,0 v-26" fill="none" stroke="{t["ink2"]}" stroke-width="1.3"/>')
    for i, line in enumerate(["SQLite (WAL), per org", "finding history, cursors", "decisions, tickets, audit"]):
        s.text(1012, y2 + 56 + i * 18, line, 11.5, t["ink2"])
    s.band(956, y2 + 142, 220, 128, t["pipe"], "Industry profile")
    for i, line in enumerate(["aviation · banking · fintech", "retail · energy · power", "telecom · ports & logistics",
                              "weights, KRIs, frameworks"]):
        s.text(974, y2 + 142 + 50 + i * 18, line, 11.5, t["ink2"])
    s.arrow(956, y2 + 206, 946, y2 + 206, dash="4 3")
    s.arrow(944, y2 + 64, 954, y2 + 64)

    # 4. delivery ---------------------------------------------------------
    y3 = 688
    s.arrow(col[1] + bw / 2, r2y + bh + 1, col[1] + bw / 2, y3 - 2)
    s.band(24, y3, 1152, 104, t["out"], "Delivery", "same facts everywhere - no number differs between dashboard, report and chat")
    ox, ow = 42, 180
    for name, sub in OUTPUTS:
        s.rect(ox, y3 + 40, ow, 48, t["panel2"], t["line"], r=6)
        s.text(ox + 12, y3 + 60, name, 12.5, weight=650)
        s.text(ox + 12, y3 + 78, sub, 11, t["ink2"])
        ox += ow + 9

    # 5. people -------------------------------------------------------------
    y4 = 818
    s.rect(24, y4, 1152, 112, t["panel"], t["ppl"], r=8, sw=1.4, dash="6 4")
    s.add(f'<rect x="24" y="{y4 + 10}" width="4" height="92" rx="2" fill="{t["ppl"]}"/>')
    s.text(42, y4 + 28, "People decide", 14, weight=650)
    s.text(162, y4 + 28, "agents inform and prepare; they never change a production system", 12, t["ink2"])
    roles = ["CISO / risk owner", "SOC & IT owners", "Fraud / MLRO", "Plant / OT manager"]
    rx = 42
    for r in roles:
        s.chip(rx, y4 + 44, 172, r, t["ppl"], h=26)
        rx += 182
    s.text(42, y4 + 94, "Decisions recorded in the Decision desk, Slack or Teams by role · escalated when waiting · every verdict "
           "audit-logged", 12, t["ink2"])
    # requests flow down from the decision surfaces; approved verdicts flow up to ITSM only
    s.arrow(42 + 2 * (ow + 9) + ow / 2, y3 + 89, 42 + 2 * (ow + 9) + ow / 2, y4 - 2)
    s.text(42 + 2 * (ow + 9) + ow / 2 + 8, y4 - 6, "decisions requested", 11, t["ink2"])
    ix = 42 + 4 * (ow + 9) + ow / 2
    s.add(f'<path d="M{ix},{y4 + 40} L{ix},{y3 + 90}" fill="none" stroke="{t["ppl"]}" stroke-width="1.8" marker-end="url(#ah)"/>')
    s.text(ix + 8, y4 - 6, "approved verdict only", 11, t["ppl"])
    s.text(W - 24, H - 12, "github.com/manabouprj/Lodestar", 11, t["ink2"], anchor="end")
    s.add("</svg>")
    return "\n".join(s.parts)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for th in THEMES:
        (OUT / f"architecture-{th}.svg").write_text(build(th), encoding="utf-8")
        print("wrote", OUT / f"architecture-{th}.svg")
