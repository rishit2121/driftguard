"""ClickHouse access. Every query that matters to the demo is timed from ClickHouse's own summary."""
import json
import threading
import time
from datetime import datetime, timezone

import clickhouse_connect

from . import config

_local = threading.local()
_schema_ready = False
_schema_lock = threading.Lock()


def _connect(database=None):
    # Sessions are disabled so the client can be used safely across FastAPI's worker threads.
    return clickhouse_connect.get_client(
        host=config.CLICKHOUSE_HOST, port=config.CLICKHOUSE_PORT, username=config.CLICKHOUSE_USER,
        password=config.CLICKHOUSE_PASSWORD, secure=config.CLICKHOUSE_SECURE, database=database,
        autogenerate_session_id=False,
    )


def client():
    """One ClickHouse client per thread; schema is created once per process."""
    global _schema_ready
    if getattr(_local, "client", None) is None:
        with _schema_lock:
            if not _schema_ready:
                _connect().command(f"CREATE DATABASE IF NOT EXISTS {config.CLICKHOUSE_DATABASE}")
                c = _connect(config.CLICKHOUSE_DATABASE)
                for stmt in config.SCHEMA_PATH.read_text().split(";"):
                    body = "\n".join(l for l in stmt.splitlines() if not l.strip().startswith("--")).strip()
                    if body:
                        c.command(body)
                _schema_ready = True
        _local.client = _connect(config.CLICKHOUSE_DATABASE)
    return _local.client


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def insert(table: str, rows: list[dict]):
    if not rows:
        return
    cols = list(rows[0].keys())
    client().insert(table, [[r[c] for c in cols] for r in rows], column_names=cols)


def timed_query(name: str, sql: str, parameters: dict | None = None, run_id: str = "") -> dict:
    """Run a query and return rows plus ClickHouse-reported elapsed time and rows read."""
    t0 = time.perf_counter()
    res = client().query(sql, parameters=parameters or {})
    wall_ms = (time.perf_counter() - t0) * 1000
    summary = res.summary or {}
    elapsed_ms = int(summary.get("elapsed_ns", 0)) / 1e6 if summary.get("elapsed_ns") else wall_ms
    stats = {
        "query_name": name,
        "elapsed_ms": round(elapsed_ms, 3),
        "client_wall_ms": round(wall_ms, 3),
        "rows_read": int(summary.get("read_rows", 0)),
        "bytes_read": int(summary.get("read_bytes", 0)),
        "result_rows": len(res.result_rows),
    }
    insert("query_latency", [{
        "measured_at": now(), "query_name": name, "elapsed_ms": stats["elapsed_ms"],
        "rows_read": stats["rows_read"], "bytes_read": stats["bytes_read"],
        "result_rows": stats["result_rows"], "run_id": run_id,
    }])
    return {"columns": list(res.column_names), "rows": [list(r) for r in res.result_rows], "stats": stats, "sql": sql}


def rows_as_dicts(result: dict) -> list[dict]:
    return [dict(zip(result["columns"], r)) for r in result["rows"]]


class RunLog:
    """Writes the investigation timeline to run_events (Page D) and keeps it in memory for the API."""

    def __init__(self, run_id: str):
        self.run_id = run_id
        self.events: list[dict] = []

    def event(self, stage: str, provider: str, duration_ms: float, result: str, details: dict | str):
        row = {
            "event_at": now(), "run_id": self.run_id, "stage": stage, "provider": provider,
            "duration_ms": int(max(0, duration_ms)), "result": result,
            "details": details if isinstance(details, str) else json.dumps(details, default=str),
        }
        insert("run_events", [row])
        self.events.append(row)
        return row

    def stage(self, stage: str, provider: str):
        return _Stage(self, stage, provider)


class _Stage:
    def __init__(self, log: RunLog, stage: str, provider: str):
        self.log, self.stage, self.provider = log, stage, provider
        self.details: dict = {}
        self.result = "ok"

    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc is not None:
            self.result = "error"
            self.details["error"] = f"{exc_type.__name__}: {exc}"
        self.log.event(self.stage, self.provider, (time.perf_counter() - self.t0) * 1000, self.result, self.details)
        return False
