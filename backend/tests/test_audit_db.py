from pathlib import Path

import pytest

from pac.audit.db import init_db, list_history, record_execution


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