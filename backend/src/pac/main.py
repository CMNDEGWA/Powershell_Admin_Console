from fastapi import FastAPI, HTTPException

from pac.powershell.runner import (
    PowerShellExecutionError,
    run_hello_task,
)

app = FastAPI(
    title="PowerShell Administration Console",
    version="0.1.0",
)


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

    try:
        result = run_hello_task()
    except PowerShellExecutionError as exc:
        raise HTTPException(
            status_code=503,
            detail="The approved PowerShell task could not be completed.",
        ) from exc

    return {
        "task_id": task_id,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }