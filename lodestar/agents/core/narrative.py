"""NarrativeAgent (Phase 4) - business-language summaries for executives.

Two engines:
  * deterministic templates (default, no external calls, always available)
  * LLM (Anthropic Messages API) when llm.provider=anthropic and ANTHROPIC_API_KEY is set

Guardrails for the LLM path:
  1. only aggregated facts are sent (no raw findings, hostnames or user IDs)
  2. numeric hallucination check: every number in the output must exist in the
     facts; otherwise the text is discarded and the template is used
  3. output length capped; failures fall back silently to templates
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

NUM_RE = re.compile(r"(?<![A-Za-z])\d+(?:\.\d+)?")


def _numbers_in(obj: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(obj, dict):
        for v in obj.values():
            found |= _numbers_in(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            found |= _numbers_in(v)
    elif isinstance(obj, bool):
        pass
    elif isinstance(obj, (int, float)):
        found |= {_norm(str(obj))}
        found.add(_norm(str(round(obj))))
        found.add(_norm(f"{obj:.1f}"))
    elif isinstance(obj, str):
        found |= {_norm(n) for n in NUM_RE.findall(obj)}
    return found


def _norm(n: str) -> str:
    try:
        f = float(n)
    except ValueError:
        return n
    return str(int(f)) if f == int(f) else f"{f:.1f}".rstrip("0").rstrip(".")


def numbers_grounded(text: str, facts: dict) -> tuple[bool, list[str]]:
    allowed = _numbers_in(facts) | {str(i) for i in range(0, 11)} | {"2024", "2025", "2026", "2027", "100"}
    bad = [n for n in NUM_RE.findall(text) if _norm(n) not in allowed]
    return (not bad, bad)


def template_summary(facts: dict, audience: str) -> str:
    p, prev = facts["posture_score"], facts.get("posture_prev")
    trend = ""
    if prev is not None:
        delta = round(p - prev, 1)
        trend = f" ({'up' if delta >= 0 else 'down'} {abs(delta)} points vs previous period)"
    breaches = [k for k in facts.get("kris", []) if k["status"] == "breach"]
    lines = [f"Security posture stands at {p}/100{trend}."]
    if facts.get("attack_paths"):
        lines.append(f"{facts['attack_paths']} correlated attack path(s) require immediate action; "
                     f"the most significant is: {facts['top_attack_path']}.")
    lines.append(f"{facts['today']} item(s) need action today and {facts['week']} this week, "
                 f"distilled from {facts['total_open']} open signals across {facts['controls']} security controls.")
    if breaches:
        lines.append("Risk appetite is exceeded for: " + ", ".join(k["label"] for k in breaches[:4]) + ".")
    else:
        lines.append("All key risk indicators are within the agreed risk appetite.")
    if audience in ("monthly", "quarterly") and facts.get("exposure_estimate"):
        lines.append(f"Estimated financial exposure from open critical attack paths: {facts['exposure_estimate']}.")
    if facts.get("decisions") and audience in ("monthly", "quarterly"):
        lines.append(f"{len(facts['decisions'])} decision(s) are requested from leadership below.")
    return " ".join(lines)


def llm_summary(facts: dict, audience: str, llm_cfg: dict) -> str | None:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if llm_cfg.get("provider") != "anthropic" or not key:
        return None
    import httpx
    system = ("You are a CISO's chief of staff. Write a concise executive summary (max 150 words) for a "
              f"{audience} security report for business leaders. Use ONLY the facts provided in JSON. Do not "
              "invent numbers, names or events. Plain business English, no jargon, no markdown headings.")
    body = {"model": llm_cfg.get("model", "claude-sonnet-4-5"), "max_tokens": int(llm_cfg.get("max_tokens", 400)),
            "system": system, "messages": [{"role": "user", "content": json.dumps(facts, default=str)}]}
    try:
        r = httpx.post("https://api.anthropic.com/v1/messages", json=body, timeout=60, trust_env=True,
                       headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        r.raise_for_status()
        text = "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text").strip()
    except Exception:
        return None
    ok, _ = numbers_grounded(text, facts)
    return text[:2000] if ok and text else None


def summarise(facts: dict, audience: str, llm_cfg: dict | None = None) -> tuple[str, str]:
    """Returns (text, engine) where engine is 'llm' or 'template'."""
    text = llm_summary(facts, audience, llm_cfg or {})
    if text:
        return text, "llm"
    return template_summary(facts, audience), "template"
