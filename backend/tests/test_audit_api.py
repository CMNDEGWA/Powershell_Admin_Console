from pathlib import Path

from fastapi.testclient import TestClient

import pac.audit.db as audit_db
import pac.main as main
from pac.powershell.runner import (
    PowerShellExecutionError,
    TaskResult,
)
from pac.audit.collectors import UnsupportedAuditPlatform

client = TestClient(main.app)
client = TestClient(main.app, base_url="http://127.0.0.1")


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


def test_system_summary_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(
        main,
        "collect_machine_summary",
        lambda: {"hostname": "TEST-PC", "networkAdapters": []},
    )

    response = client.get("/api/system/summary")

    assert response.status_code == 200
    assert response.json()["machine"]["hostname"] == "TEST-PC"


def test_audit_snapshot_can_be_exported_and_deleted(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(audit_db, "DB_PATH", tmp_path / "audit.sqlite3")
    monkeypatch.setattr(
        main,
        "collect_system_audit",
        lambda: {
            "schema_version": 1,
            "collected_at": "2026-10-18T10:00:00+00:00",
            "machine": {
                "hostname": "TEST-PC",
                "operatingSystem": {"caption": "Windows 11 Pro", "build": "26100", "powershellVersion": "7.5.3"},
                "hardware": {"manufacturer": "Example", "model": "Model"},
                "networkAdapters": [{
                    "name": "Ethernet",
                    "status": "Up",
                    "macAddress": "00-11-22-33-44-55",
                    "addresses": [{"address": "192.0.2.10"}],
                }],
                "remoteDesktop": {
                    "configuredEnabled": False,
                    "serviceState": "Stopped",
                    "firewallRules": [],
                },
            },
            "collectors": {
                "accountsAndGroups": {
                    "status": "succeeded",
                    "data": {
                        "users": [{
                            "Name": "audit-user",
                            "Enabled": True,
                            "LastLogon": "2026-10-18T09:00:00Z",
                            "PasswordRequired": True,
                            "PrincipalSource": "Local",
                        }],
                        "groups": [{
                            "name": "Administrators",
                            "description": "Administrators",
                            "members": [{"name": "TEST-PC\\audit-user"}],
                        }],
                    },
                },
                "services": {
                    "status": "succeeded",
                    "data": [{
                        "Name": "ExampleService",
                        "DisplayName": "Example service",
                        "State": "Running",
                        "StartMode": "Auto",
                        "StartName": "LocalSystem",
                        "PathName": "C:\\Example\\service.exe",
                    }],
                },
                "installedSoftware": {
                    "status": "succeeded",
                    "data": [{"name": "Example App", "version": "1.2", "publisher": "Example", "scope": "machine"}],
                },
                "updates": {
                    "status": "succeeded",
                    "data": {
                        "installedHotfixes": [{"HotFixID": "KB123", "Description": "Security", "InstalledBy": "SYSTEM", "InstalledOn": "2026-01-01"}],
                        "updateHistory": [{"Date": "2026-10-01", "Title": "Cumulative update", "Operation": 1, "ResultCode": 2, "HResult": 0}],
                        "pendingUpdates": [{"title": "Pending update", "downloaded": False}],
                    },
                },
                "firewall": {
                    "status": "succeeded",
                    "data": {
                        "profiles": [{"Name": "Public", "Enabled": True}],
                        "rules": [{"Name": "ExampleRule", "DisplayName": "Example rule", "Enabled": True, "Direction": "Inbound", "Action": "Allow", "Profile": "Public", "Protocol": "TCP", "LocalPort": "443"}],
                    },
                },
                "security": {
                    "status": "succeeded",
                    "data": {"defender": {"RealTimeProtectionEnabled": True}, "uacEnabled": True, "secureBootEnabled": True},
                },
                "scheduledTasks": {
                    "status": "succeeded",
                    "data": [{"taskPath": "\\Example\\", "taskName": "Audit", "state": "Ready", "principal": "SYSTEM", "runLevel": "Highest", "actions": [{"execute": "audit.exe", "arguments": "--check"}]}],
                },
                "eventLogs": {
                    "status": "succeeded",
                    "data": [{
                        "channel": "System",
                        "status": "succeeded",
                        "enabled": True,
                        "recordCount": 1,
                        "collectedCount": 1,
                        "truncated": False,
                        "events": [{"timeCreated": "2026-10-18T09:00:00Z", "eventId": 1001, "level": "Warning", "provider": "Example", "message": "Example warning"}],
                    }],
                },
            },
            "recommendations": [],
        },
    )

    created = client.post("/api/audits")

    assert created.status_code == 201
    audit_id = created.json()["id"]
    assert created.json()["status"] == "succeeded"
    assert [finding["id"] for finding in created.json()["snapshot"]["recommendations"]] == [
        "pending-updates"
    ]
    assert client.get(f"/api/audits/{audit_id}").json()["snapshot"]["machine"]["hostname"] == "TEST-PC"
    assert client.get("/api/audits").json()["audits"][0]["id"] == audit_id

    pdf = client.get(f"/api/audits/{audit_id}/pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF-")

    deleted = client.delete(f"/api/audits/{audit_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/audits/{audit_id}").status_code == 404


def test_audit_reports_unsupported_target(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(audit_db, "DB_PATH", tmp_path / "audit.sqlite3")

    def unsupported():
        raise UnsupportedAuditPlatform("internal detail")

    monkeypatch.setattr(main, "collect_system_audit", unsupported)

    response = client.post("/api/audits")

    assert response.status_code == 409
    assert "internal detail" not in response.text


def test_audit_requires_administrator(monkeypatch) -> None:
    def not_elevated():
        from pac.audit.collectors import InsufficientAuditPrivileges

        raise InsufficientAuditPrivileges("internal detail")

    monkeypatch.setattr(main, "collect_system_audit", not_elevated)

    response = client.post("/api/audits")

    assert response.status_code == 403
    assert "internal detail" not in response.text


def test_privileged_mutation_rejects_untrusted_origin() -> None:
    response = client.delete(
        "/api/audits/1",
        headers={"Origin": "https://untrusted.example"},
    )

    assert response.status_code == 403