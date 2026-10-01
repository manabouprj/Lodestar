"""Persistence (SQLite by default - zero infrastructure for Phase 0/1).

Tables
  runs        - one row per pipeline execution (full result JSON)
  snapshots   - one row per day (trend source for dashboards & reports)
  findings    - latest state of every finding (status tracking, MTTR)
  webhook     - findings pushed by products via /api/ingest/{domain}
  audit       - agent + API audit trail (append-only)

The interface is intentionally small so a PostgreSQL implementation can be
dropped in for multi-tenant scale (see docs/ARCHITECTURE.md §Scale).
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from .models import DailySnapshot, PipelineResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY AUTOINCREMENT, org TEXT, generated_at TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS snapshots (org TEXT, date TEXT, data TEXT, PRIMARY KEY (org, date));
CREATE TABLE IF NOT EXISTS findings (org TEXT, finding_id TEXT, domain TEXT, status TEXT, score REAL,
    horizon TEXT, first_seen TEXT, resolved_at TEXT, data TEXT, PRIMARY KEY (org, finding_id));
CREATE TABLE IF NOT EXISTS webhook (domain TEXT, finding_id TEXT, received_at TEXT, data TEXT,
    PRIMARY KEY (domain, finding_id));
CREATE TABLE IF NOT EXISTS decisions (org TEXT, decision_id TEXT, first_raised TEXT, status TEXT DEFAULT 'pending',
    choice TEXT, role TEXT, note TEXT, decided_at TEXT, PRIMARY KEY (org, decision_id));
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, event TEXT, details TEXT);
"""


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    # ---- pipeline results -------------------------------------------------
    def save_result(self, result: PipelineResult) -> int:
        payload = result.model_dump_json()
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as c:
            cur = c.execute("INSERT INTO runs (org, generated_at, result) VALUES (?,?,?)",
                            (result.org_name, result.generated_at.isoformat(), payload))
            c.execute("INSERT OR REPLACE INTO snapshots (org, date, data) VALUES (?,?,?)",
                      (result.org_name, result.snapshot.date, result.snapshot.model_dump_json()))
            current = {f.finding_id for f in result.findings}
            for f in result.findings:
                c.execute(
                    """INSERT INTO findings (org, finding_id, domain, status, score, horizon, first_seen, resolved_at, data)
                       VALUES (?,?,?,?,?,?,?,NULL,?)
                       ON CONFLICT(org, finding_id) DO UPDATE SET status=excluded.status, score=excluded.score,
                       horizon=excluded.horizon, data=excluded.data, resolved_at=NULL""",
                    (result.org_name, f.finding_id, f.domain.value, f.status.value, f.score,
                     f.horizon.value if f.horizon else None, f.first_seen.isoformat(), f.model_dump_json()))
            # anything previously open that no longer appears is considered resolved at source
            rows = c.execute("SELECT finding_id FROM findings WHERE org=? AND resolved_at IS NULL",
                             (result.org_name,)).fetchall()
            for (fid,) in rows:
                if fid not in current:
                    c.execute("UPDATE findings SET status='resolved', resolved_at=? WHERE org=? AND finding_id=?",
                              (now, result.org_name, fid))
            c.execute("DELETE FROM runs WHERE org=? AND id NOT IN (SELECT id FROM runs WHERE org=? ORDER BY id DESC LIMIT 30)",
                      (result.org_name, result.org_name))
            return int(cur.lastrowid)

    def latest_result(self, org: Optional[str] = None) -> Optional[PipelineResult]:
        q = "SELECT result FROM runs" + (" WHERE org=?" if org else "") + " ORDER BY id DESC LIMIT 1"
        with self._conn() as c:
            row = c.execute(q, (org,) if org else ()).fetchone()
        return PipelineResult.model_validate_json(row[0]) if row else None

    def list_orgs(self) -> list[str]:
        with self._conn() as c:
            return [r[0] for r in c.execute("SELECT DISTINCT org FROM runs ORDER BY org")]

    def history(self, org: str, days: int = 400) -> list[DailySnapshot]:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
        with self._conn() as c:
            rows = c.execute("SELECT data FROM snapshots WHERE org=? AND date>=? ORDER BY date", (org, since)).fetchall()
        return [DailySnapshot.model_validate_json(r[0]) for r in rows]

    def save_snapshots(self, org: str, snaps: list[DailySnapshot]) -> None:
        with self._lock, self._conn() as c:
            c.executemany("INSERT OR IGNORE INTO snapshots (org, date, data) VALUES (?,?,?)",
                          [(org, s.date, s.model_dump_json()) for s in snaps])

    # ---- webhook ingestion ------------------------------------------------
    def upsert_webhook(self, domain: str, items: list[dict[str, Any]]) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as c:
            for it in items:
                c.execute("INSERT OR REPLACE INTO webhook (domain, finding_id, received_at, data) VALUES (?,?,?,?)",
                          (domain, it["finding_id"], now, json.dumps(it, default=str)))
        return len(items)

    def webhook_findings(self, domain: str, retention_days: int = 30) -> list[dict[str, Any]]:
        since = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self._conn() as c:
            rows = c.execute("SELECT data FROM webhook WHERE domain=? AND received_at>=?", (domain, since)).fetchall()
        return [json.loads(r[0]) for r in rows]

    # ---- human decisions (decision desk) ------------------------------------
    def decision_state(self, org: str) -> dict[str, dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT decision_id, first_raised, status, choice, role, note, decided_at FROM decisions "
                             "WHERE org=?", (org,)).fetchall()
        return {r[0]: {"first_raised": datetime.fromisoformat(r[1]), "status": r[2], "choice": r[3], "role": r[4],
                       "note": r[5], "decided_at": r[6]} for r in rows}

    def register_decisions(self, org: str, ids: list[str], when: datetime) -> None:
        with self._lock, self._conn() as c:
            c.executemany("INSERT OR IGNORE INTO decisions (org, decision_id, first_raised) VALUES (?,?,?)",
                          [(org, i, when.isoformat()) for i in ids])

    def record_decision(self, org: str, decision_id: str, status: str, choice: str, role: str, note: str = "") -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO decisions (org, decision_id, first_raised, status, choice, role, note, decided_at) "
                      "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(org, decision_id) DO UPDATE SET status=excluded.status, "
                      "choice=excluded.choice, role=excluded.role, note=excluded.note, decided_at=excluded.decided_at",
                      (org, decision_id, datetime.now(timezone.utc).isoformat(), status, choice, role, note,
                       datetime.now(timezone.utc).isoformat()))

    # ---- audit ------------------------------------------------------------
    def audit(self, actor: str, event: str, details: dict[str, Any] | None = None) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO audit (ts, actor, event, details) VALUES (?,?,?,?)",
                      (datetime.now(timezone.utc).isoformat(), actor, event, json.dumps(details or {}, default=str)))

    def audit_many(self, entries: list[dict[str, Any]]) -> None:
        with self._lock, self._conn() as c:
            c.executemany("INSERT INTO audit (ts, actor, event, details) VALUES (?,?,?,?)",
                          [(e.get("ts"), e.get("agent"), e.get("event"),
                            json.dumps({k: v for k, v in e.items() if k not in ("ts", "agent", "event")}, default=str))
                           for e in entries])

    def recent_audit(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT ts, actor, event, details FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"ts": r[0], "actor": r[1], "event": r[2], "details": json.loads(r[3])} for r in rows]
