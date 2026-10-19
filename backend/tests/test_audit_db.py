from pathlib import Path

import pytest

from pac.audit.db import (
    delete_audit_run,
    get_audit_run,
    init_db,
    get_storage_usage,
    list_audit_runs,
    list_history,
    record_audit_run,
    record_execution,
)


def test_database_initializes(tmp_path: Path) -> None:
    database = tmp_path / "test.sqlite3"

    init_db(database)

    assert database.exists()
    assert list_history(db_path=database) == []


def test_record_and_retrieve_execution(tmp_path: Path) -> None:
    database = tmp_path / "test.sqlite3"

    record_id = record_execution(
        task_id="hello",
        started_at="2026-10-18T10:00:00+00:00",
        finished_at="2026-10-18T10:00:01+00:00",
        status="succeeded",
        returncode=0,
        db_path=database,
    )

    history = list_history(db_path=database)

    assert len(history) == 1
    assert history[0]["id"] == record_id
    assert history[0]["task_id"] == "hello"
    assert history[0]["status"] == "succeeded"
    assert history[0]["returncode"] == 0
    assert "stdout" not in history[0]
    assert "stderr" not in history[0]


def test_invalid_status_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Invalid task status"):
        record_execution(
            task_id="hello",
            started_at="start",
            finished_at="finish",
            status="unknown",
            db_path=tmp_path / "test.sqlite3",
        )


def test_history_limit_is_bounded(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="between 1 and 100"):
        list_history(limit=101, db_path=tmp_path / "test.sqlite3")


def test_audit_snapshot_round_trip_and_delete(tmp_path: Path) -> None:
    database = tmp_path / "test.sqlite3"
    snapshot = {
        "machine": {"hostname": "WORKSTATION", "adapters": []},
        "findings": [{"id": "firewall-profile", "severity": "high"}],
    }
    audit_id = record_audit_run(
        started_at="2026-10-18T10:00:00+00:00",
        finished_at="2026-10-18T10:00:02+00:00",
        status="partial",
        snapshot=snapshot,
        db_path=database,
    )

    assert get_audit_run(audit_id, db_path=database) == {
        "id": audit_id,
        "schema_version": 2,
        "started_at": "2026-10-18T10:00:00+00:00",
        "finished_at": "2026-10-18T10:00:02+00:00",
        "status": "partial",
        "snapshot": snapshot,
    }
    assert list_audit_runs(db_path=database) == [
        {
            "id": audit_id,
            "schema_version": 2,
            "started_at": "2026-10-18T10:00:00+00:00",
            "finished_at": "2026-10-18T10:00:02+00:00",
            "status": "partial",
        }
    ]
    storage = get_storage_usage(db_path=database)
    assert storage["audit_count"] == 1
    assert storage["database_bytes"] == database.stat().st_size
    assert delete_audit_run(audit_id, db_path=database)
    assert get_audit_run(audit_id, db_path=database) is None
    assert get_storage_usage(db_path=database)["audit_count"] == 0


def test_schema_upgrade_redacts_existing_snapshots_without_deleting_them(tmp_path: Path) -> None:
    import json
    import sqlite3

    database = tmp_path / "legacy.sqlite3"
    snapshot = {
        "schema_version": 1,
        "machine": {"networkAdapters": [{"macAddress": "00-11-22-33-44-55"}]},
        "collectors": {"eventLogs": {"data": [{"events": [{"message": "private event"}]}]}},
        "recommendations": [],
    }
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE audit_runs (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL, "
            "started_at TEXT NOT NULL, finished_at TEXT NOT NULL, status TEXT NOT NULL, snapshot_json TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO audit_runs VALUES (1, 1, 'start', 'finish', 'succeeded', ?)",
            (json.dumps(snapshot),),
        )
        connection.execute("PRAGMA user_version = 1")

    upgraded = get_audit_run(1, db_path=database)

    assert upgraded is not None
    assert upgraded["schema_version"] == 2
    assert upgraded["snapshot"]["schema_version"] == 2
    assert upgraded["snapshot"]["machine"]["networkAdapters"][0] == {}
    assert "message" not in upgraded["snapshot"]["collectors"]["eventLogs"]["data"][0]["events"][0]
    assert get_storage_usage(db_path=database)["audit_count"] == 1


def test_audit_schema_does_not_break_legacy_history(tmp_path: Path) -> None:
    database = tmp_path / "test.sqlite3"
    record_id = record_execution(
        task_id="hello",
        started_at="start",
        finished_at="finish",
        status="succeeded",
        db_path=database,
    )

    assert list_history(db_path=database)[0]["id"] == record_id
    assert list_audit_runs(db_path=database) == []