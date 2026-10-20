from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query, Request, Response
from starlette.responses import JSONResponse

from pac.approval import approval_status, request_native_approval
from pac.audit.collectors import (
    InsufficientAuditPrivileges,
    UnsupportedAuditPlatform,
    audit_status,
    collect_machine_summary,
    collect_system_audit,
)
from pac.audit.db import (
    delete_audit_run,
    get_audit_run,
    get_storage_usage,
    list_audit_runs,
    list_history,
    record_audit_run,
    record_execution,
)
from pac.audit.pdf import build_audit_pdf
from pac.audit.privacy import sanitize_snapshot
from pac.audit.recommendations import generate_recommendations
from pac.powershell.runner import (
    PowerShellExecutionError,
    run_hello_task,
)


_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "testserver"}
_ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
_ALLOWED_ORIGINS = {
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
}

app = FastAPI(
    title="PowerShell Administration Console",
    version="0.1.0",
)


@app.middleware("http")
async def protect_local_admin_api(request: Request, call_next):
    """Reject unexpected host headers and cross-origin state-changing requests."""
    if request.url.path.startswith("/api/"):
        host = request.headers.get("host", "").split(":", 1)[0].lower()
        if host not in _ALLOWED_HOSTS:
            return JSONResponse(status_code=400, content={"detail": "Invalid host"})

        origin = request.headers.get("origin")
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if origin is not None and origin not in _ALLOWED_ORIGINS:
                return JSONResponse(status_code=403, content={"detail": "Origin not allowed"})

    return await call_next(request)


def current_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.get("/api/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "app": "PAC"}


@app.get("/api/approval")
def get_approval_status() -> dict:
    return approval_status()


@app.post("/api/approval/request")
def request_approval() -> dict:
    return request_native_approval()


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


@app.get("/api/storage")
def get_local_storage_usage() -> dict[str, int]:
    return get_storage_usage()


@app.get("/api/system/summary")
def get_system_summary() -> dict:
    try:
        return {"machine": collect_machine_summary()}
    except PowerShellExecutionError as exc:
        raise HTTPException(
            status_code=503,
            detail="System information could not be collected for this operating system.",
        ) from exc


@app.post("/api/audits", status_code=201)
def create_audit() -> dict:
    started_at = current_timestamp()
    try:
        snapshot = collect_system_audit()
    except InsufficientAuditPrivileges as exc:
        raise HTTPException(
            status_code=403,
            detail="Run the backend as administrator to perform a full system audit.",
        ) from exc
    except UnsupportedAuditPlatform as exc:
        raise HTTPException(
            status_code=409,
            detail="Auditing requires a Windows system and PowerShell 7.",
        ) from exc
    except PowerShellExecutionError:
        snapshot = {
            "schema_version": 1,
            "collected_at": current_timestamp(),
            "machine": {},
            "collectors": {},
            "recommendations": [],
            "error_code": "collection_error",
        }

    if "error_code" not in snapshot:
        snapshot["recommendations"] = generate_recommendations(snapshot)
    snapshot = sanitize_snapshot(snapshot)
    snapshot["schema_version"] = 2
    status = audit_status(snapshot)
    finished_at = current_timestamp()
    audit_id = record_audit_run(
        started_at=started_at,
        finished_at=finished_at,
        status=status,
        snapshot=snapshot,
    )
    saved = get_audit_run(audit_id)
    assert saved is not None
    return saved


@app.get("/api/audits")
def get_audits(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> dict:
    return {"audits": list_audit_runs(limit=limit, offset=offset)}


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: int) -> dict:
    audit = get_audit_run(audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit not found")
    return audit


@app.delete("/api/audits/{audit_id}", status_code=204)
def remove_audit(audit_id: int) -> Response:
    if not delete_audit_run(audit_id):
        raise HTTPException(status_code=404, detail="Audit not found")
    return Response(status_code=204)


@app.get("/api/audits/{audit_id}/pdf")
def export_audit_pdf(audit_id: int) -> Response:
    audit = get_audit_run(audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit not found")
    return Response(
        content=build_audit_pdf(audit),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="pac-audit-{audit_id}.pdf"'},
    )