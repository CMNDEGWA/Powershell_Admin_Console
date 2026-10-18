from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException

from pac.audit.db import list_history, record_execution
from pac.powershell.runner import (
    PowerShellExecutionError,
    run_hello_task,
)

app = FastAPI(
    title="PowerShell Administration Console",
    version="0.1.0",
)


def current_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.get("/api/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "app": "PAC"}


@app.get("/api/tasks")
def list_tasks() -> dict:
    return {
        "tasks": [
            {
                "id": "hello",
                "name": "PowerShell diagnostic",
                "description": (
                    "Reports the PowerShell version and platform."
                ),
            }
        ]
    }


@app.post("/api/tasks/{task_id}/run")
def execute_task(task_id: str) -> dict:
    if task_id != "hello":
        raise HTTPException(
            status_code=404,
            detail="Task not found",
        )

    started_at = current_timestamp()

    try:
        result = run_hello_task()
    except PowerShellExecutionError as exc:
        finished_at = current_timestamp()

        record_execution(
            task_id=task_id,
            started_at=started_at,
            finished_at=finished_at,
            status="failed",
            error_code="execution_error",
        )

        raise HTTPException(
            status_code=503,
            detail="The approved PowerShell task could not be completed.",
        ) from exc

    finished_at = current_timestamp()

    record_execution(
        task_id=task_id,
        started_at=started_at,
        finished_at=finished_at,
        status="succeeded",
        returncode=result.returncode,
    )

    return {
        "task_id": task_id,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


@app.get("/api/history")
def get_history(limit: int = 20) -> dict:
    if not 1 <= limit <= 100:
        raise HTTPException(
            status_code=422,
            detail="limit must be between 1 and 100",
        )

    return {"history": list_history(limit=limit)}