import json
import shutil

import pytest
from fastapi.testclient import TestClient

from pac.main import app

client = TestClient(app)
client = TestClient(app, base_url="http://127.0.0.1")


def test_list_approved_tasks() -> None:
    response = client.get("/api/tasks")

    assert response.status_code == 200
    tasks = response.json()["tasks"]
    assert [task["id"] for task in tasks] == ["hello"]


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is not installed")
def test_run_approved_task() -> None:
    response = client.post("/api/tasks/hello/run")

    assert response.status_code == 200
    data = response.json()
    assert data["task_id"] == "hello"
    assert data["returncode"] == 0

    output = json.loads(data["stdout"])
    assert output["message"] == "PowerShell task completed"


def test_reject_unknown_task() -> None:
    response = client.post("/api/tasks/not-approved/run")

    assert response.status_code == 404