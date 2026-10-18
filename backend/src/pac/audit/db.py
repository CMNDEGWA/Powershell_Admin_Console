from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DB_PATH = Path(__file__).resolve().parents[3] / "data" / "pac.sqlite3"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path: Path | None = None) -> None:
    """Create the database and audit table if they do not exist."""
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
        connection.commit()


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