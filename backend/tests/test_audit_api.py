from pathlib import Path

from fastapi.testclient import TestClient

import pac.audit.db as audit_db
import pac.main as main
from pac.powershell.runner import (
    PowerShellExecutionError,
    TaskResult,
)

client = TestClient(main.app)


def test_successful_task_is_recorded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        audit_db,
        "DB_PATH",
        tmp_path / "history.sqlite3",
    )
    monkeypatch.setattr(
        main,
        "run_hello_task",
        lambda: TaskResult(
            returncode=0,
            stdout='{"message":"PowerShell task completed"}',
            stderr="",
        ),
    )

    response = client.post("/api/tasks/hello/run")

    assert response.status_code == 200
    history = client.get("/api/history").json()["history"]

    assert len(history) == 1
    assert history[0]["task_id"] == "hello"
    assert history[0]["status"] == "succeeded"
    assert history[0]["returncode"] == 0
    assert "stdout" not in history[0]


def test_failed_task_is_recorded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        audit_db,
        "DB_PATH",
        tmp_path / "history.sqlite3",
    )

    def fail_task():
        raise PowerShellExecutionError("Internal test error")

    monkeypatch.setattr(main, "run_hello_task", fail_task)

    response = client.post("/api/tasks/hello/run")

    assert response.status_code == 503
    assert "Internal test error" not in response.text

    history = client.get("/api/history").json()["history"]
    assert len(history) == 1
    assert history[0]["status"] == "failed"
    assert history[0]["error_code"] == "execution_error"


def test_history_rejects_invalid_limit() -> None:
    response = client.get("/api/history?limit=101")

    assert response.status_code == 422