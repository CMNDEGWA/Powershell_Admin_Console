import json
import platform

import pytest

import pac.audit.collectors as collectors
import pac.audit.platforms as platform_collectors
from pac.audit.collectors import UnsupportedAuditPlatform
from pac.audit.recommendations import generate_recommendations
from pac.powershell.runner import PowerShellExecutionError, TaskResult


def _result(payload: dict) -> TaskResult:
    return TaskResult(0, json.dumps(payload), "")


def _mock_windows(monkeypatch) -> None:
    monkeypatch.setattr(collectors, "detect_platform", lambda: "windows")


@pytest.mark.parametrize(
    ("system_name", "expected"),
    [("Windows", "windows"), ("Linux", "linux"), ("Darwin", "macos"), ("FreeBSD", "unsupported")],
)
def test_detect_platform(system_name: str, expected: str) -> None:
    assert platform_collectors.detect_platform(system_name) == expected


@pytest.mark.parametrize("target", ["linux", "macos"])
@pytest.mark.skipif(platform.system() == "Windows", reason="POSIX summary uses POSIX-only process APIs")
def test_posix_summary_has_normalized_platform_fields(target: str) -> None:
    summary = platform_collectors.collect_posix_summary(target)

    assert summary["platform"] == target
    assert summary["supportedTarget"] is True
    assert "operatingSystem" in summary
    assert "networkAdapters" in summary
    assert summary["remoteAccess"]["configuredEnabled"] is None


def test_machine_summary_is_validated_and_tagged(monkeypatch) -> None:
    _mock_windows(monkeypatch)
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
    _mock_windows(monkeypatch)
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
    _mock_windows(monkeypatch)
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
                "remoteDesktop": {
                    "configuredEnabled": False,
                    "serviceState": "Stopped",
                    "firewallRules": [],
                    "enabledInboundFirewallRule": False,
                },
            },
            "sections": {"services": {"status": "succeeded", "data": []}},
        }),
    )

    snapshot = collectors.collect_system_audit()

    assert snapshot["machine"]["operatingSystem"]["caption"] == caption
    assert snapshot["machine"]["platform"] == "windows"
    assert snapshot["machine"]["remoteAccess"]["name"] == "Remote Desktop"


def test_full_audit_dispatches_to_native_linux_collector(monkeypatch) -> None:
    monkeypatch.setattr(collectors, "detect_platform", lambda: "linux")
    summary = {"platform": "linux", "administrator": True}
    monkeypatch.setattr(collectors, "collect_posix_summary", lambda target: summary)
    monkeypatch.setattr(
        collectors,
        "collect_posix_audit",
        lambda target, machine: {"machine": machine, "collectors": {}, "recommendations": []},
    )

    snapshot = collectors.collect_system_audit()

    assert snapshot["machine"]["platform"] == "linux"


def test_full_posix_audit_requires_root(monkeypatch) -> None:
    monkeypatch.setattr(collectors, "detect_platform", lambda: "macos")
    monkeypatch.setattr(
        collectors,
        "collect_posix_summary",
        lambda target: {"platform": target, "administrator": False},
    )

    with pytest.raises(collectors.InsufficientAuditPrivileges):
        collectors.collect_system_audit()


def test_full_audit_requires_administrator(monkeypatch) -> None:
    _mock_windows(monkeypatch)
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
    _mock_windows(monkeypatch)
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
    assert all(finding["severity_rationale"] for finding in findings)
    assert all(finding["applicability"] for finding in findings)
    assert all(finding["confidence"] in {"high", "medium", "limited"} for finding in findings)


def test_posix_active_remote_login_gets_a_recommendation() -> None:
    findings = generate_recommendations({
        "machine": {
            "platform": "linux",
            "remoteAccess": {"name": "SSH", "serviceState": "Active"},
        },
        "collectors": {},
    })

    assert findings[0]["id"] == "ssh-service-active"


def test_remote_desktop_unknown_firewall_state_is_not_reported_as_closed() -> None:
    finding = generate_recommendations({
        "machine": {
            "platform": "windows",
            "remoteDesktop": {
                "configuredEnabled": True,
                "enabledInboundFirewallRule": None,
            },
        },
        "collectors": {},
    })[0]

    assert "not collected" in finding["summary"]
    assert finding["confidence"] == "limited"
    assert finding["evidence"]["enabledInboundFirewallRule"] is None