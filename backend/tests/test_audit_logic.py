import json

import pytest

import pac.audit.collectors as collectors
from pac.audit.collectors import UnsupportedAuditPlatform
from pac.audit.recommendations import generate_recommendations
from pac.powershell.runner import PowerShellExecutionError, TaskResult


def _result(payload: dict) -> TaskResult:
    return TaskResult(0, json.dumps(payload), "")


def test_machine_summary_is_validated_and_tagged(monkeypatch) -> None:
    monkeypatch.setattr(
        collectors,
        "run_audit_script",
        lambda mode: _result({
            "schemaVersion": 1,
            "mode": mode,
            "collectedAt": "2026-10-18T10:00:00Z",
            "supportedTarget": True,
            "machine": {"hostname": "TEST-PC", "networkAdapters": []},
            "sections": {},
        }),
    )

    summary = collectors.collect_machine_summary()

    assert summary["hostname"] == "TEST-PC"
    assert summary["supportedTarget"] is True
    assert summary["collectedAt"] == "2026-10-18T10:00:00Z"


def test_full_audit_rejects_unsupported_target(monkeypatch) -> None:
    monkeypatch.setattr(
        collectors,
        "run_audit_script",
        lambda mode: _result({
            "schemaVersion": 1,
            "mode": mode,
            "supportedTarget": False,
            "machine": {"administrator": True},
            "sections": {},
        }),
    )

    with pytest.raises(UnsupportedAuditPlatform):
        collectors.collect_system_audit()


@pytest.mark.parametrize(
    "caption",
    ["Microsoft Windows 11 Pro", "Microsoft Windows Server 2022 Datacenter"],
)
def test_full_audit_accepts_windows_releases(monkeypatch, caption: str) -> None:
    monkeypatch.setattr(
        collectors,
        "run_audit_script",
        lambda mode: _result({
            "schemaVersion": 1,
            "mode": mode,
            "supportedTarget": True,
            "machine": {
                "administrator": True,
                "operatingSystem": {"caption": caption, "build": "20348"},
            },
            "sections": {"services": {"status": "succeeded", "data": []}},
        }),
    )

    snapshot = collectors.collect_system_audit()

    assert snapshot["machine"]["operatingSystem"]["caption"] == caption


def test_full_audit_requires_administrator(monkeypatch) -> None:
    monkeypatch.setattr(
        collectors,
        "run_audit_script",
        lambda mode: _result({
            "schemaVersion": 1,
            "mode": mode,
            "supportedTarget": True,
            "machine": {"administrator": False},
            "sections": {},
        }),
    )

    with pytest.raises(collectors.InsufficientAuditPrivileges):
        collectors.collect_system_audit()


def test_full_audit_rejects_invalid_collector_status(monkeypatch) -> None:
    monkeypatch.setattr(
        collectors,
        "run_audit_script",
        lambda mode: _result({
            "schemaVersion": 1,
            "mode": mode,
            "supportedTarget": True,
            "machine": {"administrator": True},
            "sections": {"services": {"status": "unknown"}},
        }),
    )

    with pytest.raises(PowerShellExecutionError, match="invalid collector status"):
        collectors.collect_system_audit()


def test_recommendations_are_evidence_backed_and_sorted() -> None:
    snapshot = {
        "machine": {
            "remoteDesktop": {
                "configuredEnabled": True,
                "serviceState": "Running",
                "enabledInboundFirewallRule": True,
            }
        },
        "collectors": {
            "firewall": {
                "status": "succeeded",
                "data": {"profiles": [{"Name": "Public", "Enabled": False}]},
            },
            "security": {
                "status": "succeeded",
                "data": {
                    "defender": {"RealTimeProtectionEnabled": False},
                    "uacEnabled": False,
                },
            },
            "updates": {
                "status": "succeeded",
                "data": {"pendingUpdates": [{"title": "Security update"}]},
            },
        },
    }

    findings = generate_recommendations(snapshot)

    assert [finding["severity"] for finding in findings] == [
        "high",
        "high",
        "high",
        "medium",
        "medium",
    ]
    assert all(finding["evidence"] for finding in findings)
    assert all(finding["rule_version"] for finding in findings)