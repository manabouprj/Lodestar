"""Dashboard rendering (served by the API or exported as a single static file)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

TEMPLATE = Path(__file__).resolve().parent / "templates" / "dashboard.html"
SKELETON = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
</head><body>
{body}
</body></html>"""


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def render_dashboard(payloads: list[dict[str, Any]], *, demo: bool = False, api: bool = False,
                     default: str | None = None, full_document: bool = True) -> str:
    orgs = {slug(p["org"]): p for p in payloads}
    data = {"orgs": orgs, "order": list(orgs), "default": default or (next(iter(orgs)) if orgs else None),
            "demo": demo, "api": api}
    blob = json.dumps(data, separators=(",", ":"), default=str).replace("</", "<\\/")
    body = TEMPLATE.read_text(encoding="utf-8").replace("/*__LODESTAR_DATA__*/null", blob)
    return SKELETON.format(body=body) if full_document else body
