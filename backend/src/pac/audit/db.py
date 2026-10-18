from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DB_PATH = Path(__file__).resolve().parents[3] / "data" / "pac.sqlite3"
SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path: Path | None = None) -> None:
    """Create or upgrade the local audit database schema."""
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(path, timeout=5) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS task_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK (status IN ('succeeded', 'failed')),
                returncode INTEGER,
                error_code TEXT
            )
            """
        )
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError("Database schema is newer than this application")

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                schema_version INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK (status IN ('succeeded', 'partial', 'failed')),
                snapshot_json TEXT NOT NULL
            )
            """
        )
        connection.execute("PRAGMA user_version = 1")


def record_audit_run(
    *,
    started_at: str,
    finished_at: str,
    status: str,
    snapshot: dict[str, Any],
    schema_version: int = SCHEMA_VERSION,
    db_path: Path | None = None,
) -> int:
    """Persist one immutable, versioned audit snapshot."""
    if status not in {"succeeded", "partial", "failed"}:
        raise ValueError("Invalid audit status")
    if schema_version != SCHEMA_VERSION:
        raise ValueError("Unsupported audit schema version")

    snapshot_json = json.dumps(
        snapshot,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    path = db_path or DB_PATH
    init_db(path)

    with sqlite3.connect(path, timeout=5) as connection:
        cursor = connection.execute(
            """
            INSERT INTO audit_runs
                (schema_version, started_at, finished_at, status, snapshot_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (schema_version, started_at, finished_at, status, snapshot_json),
        )
        return int(cursor.lastrowid)


def get_audit_run(
    audit_id: int,
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """Return one saved snapshot, or None when it does not exist."""
    path = db_path or DB_PATH
    init_db(path)

    with sqlite3.connect(path, timeout=5) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT id, schema_version, started_at, finished_at, status,
                   snapshot_json
            FROM audit_runs WHERE id = ?
            """,
            (audit_id,),
        ).fetchone()

    if row is None:
        return None
    result = dict(row)
    result["snapshot"] = json.loads(result.pop("snapshot_json"))
    return result


def list_audit_runs(
    limit: int = 20,
    offset: int = 0,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """List recent audit metadata without loading sensitive snapshots."""
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if offset < 0:
        raise ValueError("offset must not be negative")

    path = db_path or DB_PATH
    init_db(path)
    with sqlite3.connect(path, timeout=5) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, schema_version, started_at, finished_at, status
            FROM audit_runs ORDER BY id DESC LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    return [dict(row) for row in rows]


def delete_audit_run(audit_id: int, db_path: Path | None = None) -> bool:
    """Delete a saved audit snapshot by its local database identifier."""
    path = db_path or DB_PATH
    init_db(path)
    with sqlite3.connect(path, timeout=5) as connection:
        cursor = connection.execute("DELETE FROM audit_runs WHERE id = ?", (audit_id,))
        return cursor.rowcount == 1


def record_execution(
    *,
    task_id: str,
    started_at: str,
    finished_at: str,
    status: str,
    returncode: int | None = None,
    error_code: str | None = None,
    db_path: Path | None = None,
) -> int:
    """Record execution metadata, never command output."""
    if status not in {"succeeded", "failed"}:
        raise ValueError("Invalid task status")

    path = db_path or DB_PATH
    init_db(path)

    with sqlite3.connect(path, timeout=5) as connection:
        cursor = connection.execute(
            """
            INSERT INTO task_history
                (task_id, started_at, finished_at, status,
                 returncode, error_code)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                started_at,
                finished_at,
                status,
                returncode,
                error_code,
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)


def list_history(
    limit: int = 20,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Return recent task metadata, with a bounded result count."""
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")

    path = db_path or DB_PATH
    init_db(path)

    with sqlite3.connect(path, timeout=5) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, task_id, started_at, finished_at,
                   status, returncode, error_code
            FROM task_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]