"""Persistence - SQLite (WAL) with versioned schema migrations.

SQLite is the supported production store for single-node deployments (one
server, any number of tenants with a few thousand open findings each). All
writes go through short transactions; cross-process runs are serialised with
lease locks in the `locks` table, so the API, scheduler and CLI can share a DB.

Tables
  runs             last N pipeline results per org (dashboard / API source)
  snapshots        one row per org per day (trends, reports)
  findings         lifecycle state of every finding (first seen, last seen, missed pulls, resolution)
  connector_state  per org + source: sync cursor, last success / attempt / error
  webhook_items    findings pushed via /api/ingest/{domain}, per org
  webhook_health   health blocks pushed via webhook, per org + domain
  decisions        Decision-desk clocks and human verdicts
  escalations      chat escalations already sent (no repeats)
  itsm_tickets     tickets created per action (no duplicates)
  locks            lease locks (one pipeline run per org at a time)
  audit            append-only audit trail
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from .models import DailySnapshot, PipelineResult

MIGRATIONS: list[str] = [
    # 1 - v1.x baseline
    """
    CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY AUTOINCREMENT, org TEXT, generated_at TEXT, result TEXT);
    CREATE TABLE IF NOT EXISTS snapshots (org TEXT, date TEXT, data TEXT, PRIMARY KEY (org, date));
    CREATE TABLE IF NOT EXISTS findings (org TEXT, finding_id TEXT, domain TEXT, status TEXT, score REAL,
        horizon TEXT, first_seen TEXT, resolved_at TEXT, data TEXT, PRIMARY KEY (org, finding_id));
    CREATE TABLE IF NOT EXISTS webhook (domain TEXT, finding_id TEXT, received_at TEXT, data TEXT, PRIMARY KEY (domain, finding_id));
    CREATE TABLE IF NOT EXISTS decisions (org TEXT, decision_id TEXT, first_raised TEXT, status TEXT DEFAULT 'pending',
        choice TEXT, role TEXT, note TEXT, decided_at TEXT, PRIMARY KEY (org, decision_id));
    CREATE TABLE IF NOT EXISTS webhook_health (domain TEXT PRIMARY KEY, received_at TEXT, data TEXT);
    CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, event TEXT, details TEXT);
    """,
    # 2 - v2.0: lifecycle, connector state, tenancy-aware webhooks, locks, escalations, ITSM de-duplication
    """
    ALTER TABLE findings ADD COLUMN last_seen TEXT;
    ALTER TABLE findings ADD COLUMN missed_runs INTEGER DEFAULT 0;
    ALTER TABLE findings ADD COLUMN resolution TEXT;
    CREATE INDEX IF NOT EXISTS ix_findings_open ON findings (org, resolved_at);
    CREATE TABLE IF NOT EXISTS connector_state (org TEXT, source_key TEXT, cursor TEXT, last_success TEXT,
        last_attempt TEXT, last_error TEXT, items INTEGER, PRIMARY KEY (org, source_key));
    CREATE TABLE IF NOT EXISTS webhook_items (org TEXT, domain TEXT, finding_id TEXT, received_at TEXT, data TEXT,
        PRIMARY KEY (org, domain, finding_id));
    INSERT OR IGNORE INTO webhook_items (org, domain, finding_id, received_at, data)
        SELECT '', domain, finding_id, received_at, data FROM webhook;
    CREATE TABLE IF NOT EXISTS webhook_health2 (org TEXT, domain TEXT, received_at TEXT, data TEXT, PRIMARY KEY (org, domain));
    INSERT OR IGNORE INTO webhook_health2 (org, domain, received_at, data) SELECT '', domain, received_at, data FROM webhook_health;
    CREATE TABLE IF NOT EXISTS escalations (org TEXT, decision_id TEXT, stage TEXT, sent_at TEXT, PRIMARY KEY (org, decision_id, stage));
    CREATE TABLE IF NOT EXISTS itsm_tickets (org TEXT, action_id TEXT, ref TEXT, url TEXT, created TEXT, PRIMARY KEY (org, action_id));
    CREATE TABLE IF NOT EXISTS locks (name TEXT PRIMARY KEY, holder TEXT, expires REAL);
    CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit (ts);
    """,
    # 3 - v2.2: continuous ingestion validation (consecutive failures, last good health, monitor/alert state,
    #     per-fetch history for volume baselines)
    """
    ALTER TABLE connector_state ADD COLUMN failures INTEGER DEFAULT 0;
    ALTER TABLE connector_state ADD COLUMN health TEXT;
    ALTER TABLE connector_state ADD COLUMN monitor TEXT;
    CREATE TABLE IF NOT EXISTS source_runs (org TEXT, source_key TEXT, at TEXT, status TEXT, items INTEGER,
        warnings INTEGER);
    CREATE INDEX IF NOT EXISTS ix_source_runs ON source_runs (org, source_key, at);
    """,
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


class LockBusy(RuntimeError):
    pass


class Store:
    def __init__(self, path: Path | str, keep_runs: int = 5):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.keep_runs = max(1, int(keep_runs))
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[int, PipelineResult]] = {}
        self._migrate()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    # ---- schema -------------------------------------------------------------
    def _migrate(self) -> None:
        with self._lock, self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER)")
            row = c.execute("SELECT MAX(version) FROM schema_version").fetchone()
            current = row[0] or 0
            if current == 0 and c.execute("SELECT name FROM sqlite_master WHERE name='runs'").fetchone():
                current = 1                                  # v1.x database without a version table
                c.execute("INSERT INTO schema_version VALUES (1)")
            for stmt in [s.strip() for s in MIGRATIONS[0].split(";") if s.strip()]:
                c.execute(stmt)                              # baseline is idempotent: repairs partial v1 schemas
            for version, script in enumerate(MIGRATIONS, start=1):
                if version <= current:
                    continue
                for stmt in [s.strip() for s in script.split(";") if s.strip()]:
                    try:
                        c.execute(stmt)
                    except sqlite3.OperationalError as exc:  # idempotent re-run (column already exists)
                        if "duplicate column" not in str(exc):
                            raise
                c.execute("INSERT INTO schema_version VALUES (?)", (version,))

    def schema_version(self) -> int:
        with self._conn() as c:
            return int(c.execute("SELECT MAX(version) FROM schema_version").fetchone()[0])

    # ---- locks --------------------------------------------------------------
    @contextmanager
    def lease(self, name: str, ttl_seconds: int = 3600, wait_seconds: float = 0) -> Iterator[None]:
        """Cross-process lease lock. Raises LockBusy if another holder has it (after waiting)."""
        holder = f"{socket.gethostname()}:{os.getpid()}:{threading.get_ident()}"
        deadline = time.time() + wait_seconds
        while True:
            with self._lock, self._conn() as c:
                now = time.time()
                c.execute("INSERT INTO locks (name, holder, expires) VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET "
                          "holder=excluded.holder, expires=excluded.expires WHERE locks.expires < ?",
                          (name, holder, now + ttl_seconds, now))
                got = c.execute("SELECT holder FROM locks WHERE name=?", (name,)).fetchone()[0] == holder
            if got:
                break
            if time.time() >= deadline:
                raise LockBusy(f"'{name}' is locked by another process")
            time.sleep(1)
        try:
            yield
        finally:
            with self._lock, self._conn() as c:
                c.execute("DELETE FROM locks WHERE name=? AND holder=?", (name, holder))

    # ---- pipeline results ---------------------------------------------------
    def save_result(self, result: PipelineResult, lifecycle: dict[str, Any] | None = None) -> int:
        """Persist a run. Absent findings are NOT auto-resolved here: the LifecycleAgent decides
        (see `lifecycle` = {"resolve": {id: reason}, "missed": {id: n}})."""
        lifecycle = lifecycle or {}
        payload = result.model_dump_json()
        now = _now().isoformat()
        org = result.org_name
        with self._lock, self._conn() as c:
            cur = c.execute("INSERT INTO runs (org, generated_at, result) VALUES (?,?,?)",
                            (org, result.generated_at.isoformat(), payload))
            c.execute("INSERT OR REPLACE INTO snapshots (org, date, data) VALUES (?,?,?)",
                      (org, result.snapshot.date, result.snapshot.model_dump_json()))
            missed = lifecycle.get("missed", {})
            for f in result.findings:
                closed = f.status.value in ("resolved", "false_positive")
                resolved_at = _iso(f.last_seen) if closed else None
                c.execute(
                    """INSERT INTO findings (org, finding_id, domain, status, score, horizon, first_seen, resolved_at, data,
                                             last_seen, missed_runs, resolution)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(org, finding_id) DO UPDATE SET status=excluded.status, score=excluded.score,
                         horizon=excluded.horizon, data=excluded.data, last_seen=excluded.last_seen,
                         missed_runs=excluded.missed_runs,
                         first_seen=MIN(findings.first_seen, excluded.first_seen),
                         resolved_at=CASE WHEN excluded.resolved_at IS NULL THEN NULL
                                          ELSE COALESCE(findings.resolved_at, excluded.resolved_at) END,
                         resolution=CASE WHEN excluded.resolved_at IS NULL THEN NULL ELSE excluded.resolution END""",
                    (org, f.finding_id, f.domain.value, f.status.value, f.score, f.horizon.value if f.horizon else None,
                     _iso(f.first_seen), resolved_at, f.model_dump_json(), _iso(f.last_seen),
                     int(missed.get(f.finding_id, 0)), "closed at source" if closed else None))
            # LODESTAR-generated findings (control health, ingestion monitor) raised after the LifecycleAgent ran
            raised = {f.finding_id for f in result.findings if f.source.startswith("lodestar.")
                      and f.status.value not in ("resolved", "false_positive")}
            for fid, reason in (lifecycle.get("resolve") or {}).items():
                if fid in raised:
                    continue
                c.execute("UPDATE findings SET status='resolved', resolved_at=COALESCE(resolved_at, ?), resolution=? "
                          "WHERE org=? AND finding_id=?", (now, reason, org, fid))
            c.execute("DELETE FROM runs WHERE org=? AND id NOT IN (SELECT id FROM runs WHERE org=? ORDER BY id DESC LIMIT ?)",
                      (org, org, self.keep_runs))
            run_id = int(cur.lastrowid)
        self._cache[org] = (run_id, result)
        return run_id

    def latest_result(self, org: Optional[str] = None) -> Optional[PipelineResult]:
        q = "SELECT id, org FROM runs" + (" WHERE org=?" if org else "") + " ORDER BY id DESC LIMIT 1"
        with self._conn() as c:
            row = c.execute(q, (org,) if org else ()).fetchone()
            if not row:
                return None
            cached = self._cache.get(row[1])
            if cached and cached[0] == row[0]:
                return cached[1].model_copy(deep=True)
            data = c.execute("SELECT result FROM runs WHERE id=?", (row[0],)).fetchone()[0]
        res = PipelineResult.model_validate_json(data)
        self._cache[row[1]] = (row[0], res)
        return res.model_copy(deep=True)

    def latest_run_info(self, org: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute("SELECT id, generated_at FROM runs WHERE org=? ORDER BY id DESC LIMIT 1", (org,)).fetchone()
        return {"run_id": row[0], "generated_at": row[1]} if row else None

    def list_orgs(self) -> list[str]:
        with self._conn() as c:
            return [r[0] for r in c.execute("SELECT DISTINCT org FROM runs ORDER BY org")]

    def history(self, org: str, days: int = 400) -> list[DailySnapshot]:
        since = (_now() - timedelta(days=days)).date().isoformat()
        with self._conn() as c:
            rows = c.execute("SELECT data FROM snapshots WHERE org=? AND date>=? ORDER BY date", (org, since)).fetchall()
        return [DailySnapshot.model_validate_json(r[0]) for r in rows]

    def save_snapshots(self, org: str, snaps: list[DailySnapshot]) -> None:
        with self._lock, self._conn() as c:
            c.executemany("INSERT OR IGNORE INTO snapshots (org, date, data) VALUES (?,?,?)",
                          [(org, s.date, s.model_dump_json()) for s in snaps])

    # ---- lifecycle ----------------------------------------------------------
    def open_findings(self, org: str) -> dict[str, dict[str, Any]]:
        """Findings LODESTAR still considers open, with their stored state."""
        with self._conn() as c:
            rows = c.execute("SELECT finding_id, data, missed_runs, first_seen FROM findings "
                             "WHERE org=? AND resolved_at IS NULL", (org,)).fetchall()
        return {r[0]: {"data": r[1], "missed_runs": r[2] or 0, "first_seen": _dt(r[3])} for r in rows}

    def first_seen_map(self, org: str, ids: list[str]) -> dict[str, datetime]:
        out: dict[str, datetime] = {}
        with self._conn() as c:
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                q = f"SELECT finding_id, first_seen FROM findings WHERE org=? AND finding_id IN ({','.join('?' * len(chunk))})"
                for fid, fs in c.execute(q, (org, *chunk)).fetchall():
                    if fs:
                        out[fid] = _dt(fs)
        return out

    def resolution_stats(self, org: str, days: int = 90) -> list[dict[str, Any]]:
        """Findings closed in the window: first_seen, resolved_at, severity, domain, due date (for MTTR / SLA KPIs)."""
        since = (_now() - timedelta(days=days)).isoformat()
        with self._conn() as c:
            # administrative closures (connector removed, alert expired) are not remediation and must not improve MTTR / SLA
            rows = c.execute("SELECT first_seen, resolved_at, data FROM findings WHERE org=? AND resolved_at >= ? "
                             "AND status='resolved' AND COALESCE(resolution, '') NOT LIKE 'source no longer%' "
                             "AND COALESCE(resolution, '') NOT LIKE 'expired%'", (org, since)).fetchall()
        out = []
        for fs, ra, data in rows:
            d = json.loads(data)
            out.append({"first_seen": _dt(fs), "resolved_at": _dt(ra), "severity": d.get("severity"),
                        "domain": d.get("domain"), "due_date": _dt(d.get("due_date")), "type": d.get("finding_type")})
        return out

    # ---- connector state ----------------------------------------------------
    def connector_state(self, org: str, source_key: str) -> dict[str, Any]:
        with self._conn() as c:
            row = c.execute("SELECT cursor, last_success, last_attempt, last_error, items, failures, health, monitor "
                            "FROM connector_state WHERE org=? AND source_key=?", (org, source_key)).fetchone()
        if not row:
            return {}
        return {"cursor": row[0], "last_success": _dt(row[1]), "last_attempt": _dt(row[2]), "last_error": row[3],
                "items": row[4], "failures": int(row[5] or 0), "health": json.loads(row[6]) if row[6] else None,
                "monitor": json.loads(row[7]) if row[7] else {}}

    def all_connector_state(self, org: str) -> dict[str, dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT source_key FROM connector_state WHERE org=?", (org,)).fetchall()
        return {r[0]: self.connector_state(org, r[0]) for r in rows}

    def set_connector_state(self, org: str, source_key: str, *, ok: bool, cursor: str | None = None,
                            error: str | None = None, items: int | None = None, health: str | None = None,
                            at: datetime | None = None) -> None:
        """Record a fetch. `at` is the pipeline's clock (run start) so intervals line up with scheduler ticks;
        `health` is the source's ControlHealth JSON, kept as the last good telemetry for carry-forward."""
        now = _iso(at) if at else _now().isoformat()
        with self._lock, self._conn() as c:
            c.execute("INSERT OR IGNORE INTO connector_state (org, source_key) VALUES (?,?)", (org, source_key))
            if ok:
                c.execute("UPDATE connector_state SET last_success=?, last_attempt=?, last_error=NULL, items=?, failures=0, "
                          "cursor=COALESCE(?, cursor), health=COALESCE(?, health) WHERE org=? AND source_key=?",
                          (now, now, items, cursor, health, org, source_key))
            else:
                c.execute("UPDATE connector_state SET last_attempt=?, last_error=?, failures=COALESCE(failures, 0) + 1 "
                          "WHERE org=? AND source_key=?", (now, (error or "")[:1000], org, source_key))

    def set_monitor_state(self, org: str, source_key: str, monitor: dict[str, Any]) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT OR IGNORE INTO connector_state (org, source_key) VALUES (?,?)", (org, source_key))
            c.execute("UPDATE connector_state SET monitor=? WHERE org=? AND source_key=?",
                      (json.dumps(monitor, default=str), org, source_key))

    def record_source_run(self, org: str, source_key: str, status: str, items: int | None = None, warnings: int = 0,
                          at: datetime | None = None) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO source_runs (org, source_key, at, status, items, warnings) VALUES (?,?,?,?,?,?)",
                      (org, source_key, _iso(at) if at else _now().isoformat(), status, items, warnings))

    def last_items_at(self, org: str, source_key: str) -> datetime | None:
        """When the source last returned at least one item (silence detection)."""
        with self._conn() as c:
            row = c.execute("SELECT MAX(at) FROM source_runs WHERE org=? AND source_key=? AND items > 0",
                            (org, source_key)).fetchone()
        return _dt(row[0]) if row and row[0] else None

    def source_history(self, org: str, source_key: str, limit: int = 14) -> list[dict[str, Any]]:
        """Most recent fetches of a source, newest first (status ok / failed / no_data)."""
        with self._conn() as c:
            rows = c.execute("SELECT at, status, items, warnings FROM source_runs WHERE org=? AND source_key=? "
                             "ORDER BY at DESC, rowid DESC LIMIT ?", (org, source_key, limit)).fetchall()
        return [{"at": _dt(r[0]), "status": r[1], "items": r[2], "warnings": r[3]} for r in rows]

    # ---- webhook ingestion --------------------------------------------------
    def upsert_webhook(self, domain: str, items: list[dict[str, Any]], org: str = "") -> int:
        now = _now().isoformat()
        with self._lock, self._conn() as c:
            c.executemany("INSERT OR REPLACE INTO webhook_items (org, domain, finding_id, received_at, data) VALUES (?,?,?,?,?)",
                          [(org, domain, it["finding_id"], now, json.dumps(it, default=str)) for it in items])
        return len(items)

    def set_webhook_health(self, domain: str, health: dict[str, Any] | None, org: str = "") -> None:
        now = _now().isoformat()
        with self._lock, self._conn() as c:
            row = c.execute("SELECT data FROM webhook_health2 WHERE org=? AND domain=?", (org, domain)).fetchone()
            data = json.loads(row[0]) if row and row[0] else {}
            if health:
                data.update(health)
            c.execute("INSERT OR REPLACE INTO webhook_health2 (org, domain, received_at, data) VALUES (?,?,?,?)",
                      (org, domain, now, json.dumps(data, default=str)))

    def webhook_health(self, domain: str, org: str = "", include_unscoped: bool = True) -> tuple[datetime | None, dict[str, Any]]:
        """include_unscoped: also read items pushed without an org (single-organisation deployments only)."""
        with self._conn() as c:
            row = c.execute("SELECT received_at, data FROM webhook_health2 WHERE domain=? AND org IN (?, ?) "
                            "ORDER BY received_at DESC LIMIT 1", (domain, org, "" if include_unscoped else org)).fetchone()
        return (_dt(row[0]), json.loads(row[1] or "{}")) if row else (None, {})

    def webhook_findings(self, domain: str, retention_days: int = 30, org: str = "",
                         include_unscoped: bool = True) -> list[dict[str, Any]]:
        since = (_now() - timedelta(days=retention_days)).isoformat()
        with self._conn() as c:
            rows = c.execute("SELECT data FROM webhook_items WHERE domain=? AND org IN (?, ?) AND received_at>=?",
                             (domain, org, "" if include_unscoped else org, since)).fetchall()
        return [json.loads(r[0]) for r in rows]

    # ---- human decisions ----------------------------------------------------
    def decision_state(self, org: str) -> dict[str, dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT decision_id, first_raised, status, choice, role, note, decided_at FROM decisions "
                             "WHERE org=?", (org,)).fetchall()
        return {r[0]: {"first_raised": _dt(r[1]), "status": r[2], "choice": r[3], "role": r[4],
                       "note": r[5], "decided_at": r[6]} for r in rows}

    def register_decisions(self, org: str, ids: list[str], when: datetime) -> None:
        with self._lock, self._conn() as c:
            c.executemany("INSERT OR IGNORE INTO decisions (org, decision_id, first_raised) VALUES (?,?,?)",
                          [(org, i, _iso(when)) for i in ids])

    def record_decision(self, org: str, decision_id: str, status: str, choice: str, role: str, note: str = "") -> None:
        now = _now().isoformat()
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO decisions (org, decision_id, first_raised, status, choice, role, note, decided_at) "
                      "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(org, decision_id) DO UPDATE SET status=excluded.status, "
                      "choice=excluded.choice, role=excluded.role, note=excluded.note, decided_at=excluded.decided_at",
                      (org, decision_id, now, status, choice, role, note, now))

    def escalation_sent(self, org: str, decision_id: str, stage: str) -> bool:
        with self._lock, self._conn() as c:
            cur = c.execute("INSERT OR IGNORE INTO escalations (org, decision_id, stage, sent_at) VALUES (?,?,?,?)",
                            (org, decision_id, stage, _now().isoformat()))
            return cur.rowcount == 0     # True = already sent before

    def escalation_pending(self, org: str, decision_id: str, stage: str) -> bool:
        with self._conn() as c:
            return c.execute("SELECT 1 FROM escalations WHERE org=? AND decision_id=? AND stage=?",
                             (org, decision_id, stage)).fetchone() is None

    # ---- ITSM de-duplication ------------------------------------------------
    def ticket_for(self, org: str, action_id: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute("SELECT ref, url, created FROM itsm_tickets WHERE org=? AND action_id=?", (org, action_id)).fetchone()
        return {"ref": row[0], "url": row[1], "created": row[2]} if row else None

    def save_ticket(self, org: str, action_id: str, ref: str, url: str = "") -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT OR IGNORE INTO itsm_tickets (org, action_id, ref, url, created) VALUES (?,?,?,?,?)",
                      (org, action_id, ref, url, _now().isoformat()))

    # ---- audit --------------------------------------------------------------
    def audit(self, actor: str, event: str, details: dict[str, Any] | None = None) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO audit (ts, actor, event, details) VALUES (?,?,?,?)",
                      (_now().isoformat(), actor, event, json.dumps(details or {}, default=str)))

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

    # ---- maintenance --------------------------------------------------------
    def prune(self, *, closed_findings_days: int = 400, webhook_days: int = 60, audit_days: int = 400,
              snapshot_days: int = 800, source_runs_days: int = 30) -> dict[str, int]:
        now = _now()
        out = {}
        with self._lock, self._conn() as c:
            out["findings"] = c.execute("DELETE FROM findings WHERE resolved_at IS NOT NULL AND resolved_at < ?",
                                        ((now - timedelta(days=closed_findings_days)).isoformat(),)).rowcount
            out["webhook_items"] = c.execute("DELETE FROM webhook_items WHERE received_at < ?",
                                             ((now - timedelta(days=webhook_days)).isoformat(),)).rowcount
            out["audit"] = c.execute("DELETE FROM audit WHERE ts < ?", ((now - timedelta(days=audit_days)).isoformat(),)).rowcount
            out["snapshots"] = c.execute("DELETE FROM snapshots WHERE date < ?",
                                         ((now - timedelta(days=snapshot_days)).date().isoformat(),)).rowcount
            out["source_runs"] = c.execute("DELETE FROM source_runs WHERE at < ?",
                                           ((now - timedelta(days=source_runs_days)).isoformat(),)).rowcount
        return out

    def backup(self, dest: Path | str) -> Path:
        """Consistent online backup (safe while the API and scheduler are running)."""
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as src, sqlite3.connect(dest) as dst:
            src.backup(dst)
        return dest

    def ping(self) -> bool:
        with self._conn() as c:
            return c.execute("SELECT 1").fetchone()[0] == 1
