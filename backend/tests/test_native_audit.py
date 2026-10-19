import sys
import platform
import shutil

import pytest

import pac.audit.native_audit as native_audit
from pac.audit.collectors import audit_status
from pac.audit.pdf import build_audit_pdf


@pytest.mark.skipif(platform.system() == "Windows", reason="selectors cannot monitor subprocess pipes on Windows")
def test_fixed_command_does_not_use_a_shell(monkeypatch) -> None:
    captured = {}
    monkeypatch.setattr(native_audit.shutil, "which", lambda _: sys.executable)
    original_popen = native_audit.subprocess.Popen

    def popen(arguments, **options):
        captured["arguments"] = arguments
        captured.update(options)
        return original_popen(arguments, **options)

    monkeypatch.setattr(native_audit.subprocess, "Popen", popen)

    result = native_audit._run_command([sys.executable, "-c", "print('active')"])

    assert result.strip() == "active"
    assert captured["shell"] is False
    assert captured["arguments"] == [sys.executable, "-c", "print('active')"]


def test_missing_command_is_reported_as_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(native_audit.shutil, "which", lambda _: None)

    result = native_audit._capture(lambda: native_audit._run_command(["missing-tool"]))

    assert result == {"status": "unavailable", "data": None, "errorCode": "tool_unavailable"}


@pytest.mark.skipif(platform.system() == "Windows", reason="selectors cannot monitor subprocess pipes on Windows")
def test_native_command_output_is_bounded(monkeypatch) -> None:
    monkeypatch.setattr(native_audit.shutil, "which", lambda _: sys.executable)
    monkeypatch.setattr(native_audit, "MAX_COMMAND_OUTPUT", 16)

    try:
        native_audit._run_command([sys.executable, "-c", "print('x' * 100)"])
    except RuntimeError as error:
        assert "output exceeded limit" in str(error)
    else:
        raise AssertionError("oversized command output was accepted")


def test_linux_service_output_is_normalized(monkeypatch) -> None:
    monkeypatch.setattr(native_audit.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        native_audit,
        "_run_command",
        lambda _: "ssh.service loaded active running OpenSSH server daemon\n",
    )

    services = native_audit._collect_linux_services()

    assert services == [{
        "Name": "ssh.service",
        "DisplayName": "OpenSSH server daemon",
        "State": "active",
        "StartMode": "systemd",
        "StartName": None,
        "PathName": None,
    }]


@pytest.mark.parametrize("target", ["linux", "macos"])
def test_posix_audit_uses_shared_snapshot_shape(monkeypatch, target: str) -> None:
    collectors = {
        "_collect_accounts": {"users": [], "groups": []},
        f"_collect_{target}_services": [],
        f"_collect_{target}_software": [],
        f"_collect_{target}_firewall": {"profiles": [], "rules": []},
        f"_collect_{target}_security": {},
        f"_collect_{target}_tasks": [],
        f"_collect_{target}_events": [],
    }
    if target == "linux":
        collectors["_collect_linux_updates"] = {"pendingUpdates": []}
    for function_name, result in collectors.items():
        monkeypatch.setattr(native_audit, function_name, lambda result=result: result)
    summary = {
        "platform": target,
        "collectedAt": "2026-10-18T10:00:00+00:00",
        "remoteAccess": {},
    }

    snapshot = native_audit.collect_posix_audit(target, summary)

    assert snapshot["machine"]["platform"] == target
    assert snapshot["collectors"]["accountsAndGroups"]["status"] == "succeeded"
    assert snapshot["collectors"]["eventLogs"]["data"][0]["channel"] == "system"
    expected_status = "partial" if target == "macos" else "succeeded"
    assert audit_status(snapshot) == expected_status


def test_denied_collectors_never_produce_a_clean_audit() -> None:
    assert audit_status({
        "collectors": {
            "services": {"status": "succeeded"},
            "firewall": {"status": "denied"},
        },
    }) == "partial"
    assert audit_status({
        "collectors": {"firewall": {"status": "unavailable"}},
    }) == "failed"


def test_posix_snapshot_exports_to_pdf() -> None:
    audit = {
        "id": 1,
        "status": "partial",
        "snapshot": {
            "collected_at": "2026-10-18T10:00:00+00:00",
            "machine": {
                "platform": "linux",
                "hostname": "linux-host",
                "operatingSystem": {"caption": "Linux", "version": "1", "build": "kernel"},
                "remoteAccess": {
                    "name": "SSH",
                    "serviceState": "Not assessed",
                    "configuredEnabled": None,
                    "enabledInboundFirewallRule": None,
                },
                "networkAdapters": [],
            },
            "collectors": {"firewall": {"status": "unavailable", "data": None}},
            "recommendations": [],
        },
    }

    document = build_audit_pdf(audit)

    assert document.startswith(b"%PDF-")