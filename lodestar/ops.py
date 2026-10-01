"""Operability: Prometheus metrics and structured (JSON) logging.

Metrics (GET /metrics, bearer LODESTAR_METRICS_TOKEN) - alert on these, not on log lines:
  lodestar_last_run_timestamp_seconds{org}                 run freshness (alert if > 2x schedule)
  lodestar_posture_score{org} / lodestar_kri_coverage_pct{org}
  lodestar_findings_open{org,horizon}                      today / week / month / backlog
  lodestar_decisions_pending{org}
  lodestar_connector_up{org,source}                        1 = last attempt succeeded
  lodestar_connector_last_success_timestamp_seconds{org,source}
  lodestar_connector_items{org,source}
  lodestar_http_requests_total{method,code}
Logs: LODESTAR_LOG_FORMAT=json -> one JSON object per line (ship to the SIEM); LODESTAR_LOG=INFO|DEBUG.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any


def _esc(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _ts(v) -> float | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.timestamp()
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def prometheus(store, orgs: dict[str, str], reqs: dict[tuple[str, int], int], lat: list) -> str:
    lines: list[str] = []

    def metric(name: str, help_: str, kind: str, samples: list[tuple[dict[str, Any], float]]) -> None:
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items())
            lines.append(f"{name}{{{lab}}} {value}" if lab else f"{name} {value}")

    from . import __version__
    metric("lodestar_build_info", "LODESTAR version", "gauge", [({"version": __version__}, 1)])
    last_run, posture, kcov, open_, pending, up, last_ok, items = [], [], [], [], [], [], [], []
    for key, org_name in orgs.items():
        org = {"org": key}
        info = store.latest_run_info(org_name)
        if info and _ts(info.get("generated_at")):
            last_run.append((org, _ts(info["generated_at"])))
        res = store.latest_result(org_name)
        if res:
            snap = res.snapshot
            posture.append((org, snap.posture_score))
            if snap.kri_coverage_pct is not None:
                kcov.append((org, snap.kri_coverage_pct))
            for h, n in snap.open_by_horizon.items():
                open_.append(({**org, "horizon": h}, n))
            decided = {k for k, v in store.decision_state(org_name).items() if v["status"] != "pending"}
            pending.append((org, sum(1 for d in res.decisions if d.get("status") == "pending" and d["decision_id"] not in decided)))
        for src, st in store.all_connector_state(org_name).items():
            lab = {**org, "source": src}
            ok = st.get("last_success") is not None and (st.get("last_attempt") is None or st.get("last_error") in (None, ""))
            up.append((lab, 1 if ok else 0))
            if st.get("last_success"):
                last_ok.append((lab, _ts(st["last_success"])))
            if st.get("items") is not None:
                items.append((lab, st["items"]))
    metric("lodestar_last_run_timestamp_seconds", "Unix time of the last pipeline run", "gauge", last_run)
    metric("lodestar_posture_score", "Posture score 0-100", "gauge", posture)
    metric("lodestar_kri_coverage_pct", "Share of the industry profile KRIs that are measured", "gauge", kcov)
    metric("lodestar_findings_open", "Open findings by horizon", "gauge", open_)
    metric("lodestar_decisions_pending", "Human decisions waiting", "gauge", pending)
    metric("lodestar_connector_up", "1 if the last fetch of the source succeeded", "gauge", up)
    metric("lodestar_connector_last_success_timestamp_seconds", "Unix time of the last successful fetch", "gauge", last_ok)
    metric("lodestar_connector_items", "Items returned by the last successful fetch", "gauge", items)
    metric("lodestar_http_requests_total", "HTTP requests served", "counter",
           [({"method": m, "code": f"{c}xx"}, n) for (m, c), n in sorted(reqs.items())])
    metric("lodestar_http_request_seconds_sum", "Total request time", "counter", [({}, round(lat[0], 4))])
    metric("lodestar_http_request_seconds_count", "Requests timed", "counter", [({}, lat[1])])
    return "\n".join(lines) + "\n"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {"ts": datetime.fromtimestamp(record.created).astimezone().isoformat(timespec="milliseconds"),
               "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def configure_logging() -> None:
    level = os.environ.get("LODESTAR_LOG", "WARNING").upper()
    handler = logging.StreamHandler()
    if os.environ.get("LODESTAR_LOG_FORMAT", "").lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
