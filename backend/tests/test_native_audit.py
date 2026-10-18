import sys

import pac.audit.native_audit as native_audit
from pac.audit.pdf import build_audit_pdf


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


def test_posix_audit_uses_shared_snapshot_shape(monkeypatch) -> None:
    monkeypatch.setattr(native_audit, "_collect_accounts", lambda: {"users": [], "groups": []})
    monkeypatch.setattr(native_audit, "_collect_linux_services", lambda: [])
    monkeypatch.setattr(native_audit, "_collect_linux_software", lambda: [])
    monkeypatch.setattr(native_audit, "_collect_linux_updates", lambda: {"pendingUpdates": []})
    monkeypatch.setattr(native_audit, "_collect_linux_firewall", lambda: {"profiles": [], "rules": []})
    monkeypatch.setattr(native_audit, "_collect_linux_security", lambda: {})
    monkeypatch.setattr(native_audit, "_collect_linux_tasks", lambda: [])
    monkeypatch.setattr(native_audit, "_collect_linux_events", lambda: [])
    summary = {
        "platform": "linux",
        "collectedAt": "2026-10-18T10:00:00+00:00",
        "remoteAccess": {},
    }

    snapshot = native_audit.collect_posix_audit("linux", summary)

    assert snapshot["machine"]["platform"] == "linux"
    assert snapshot["collectors"]["accountsAndGroups"]["status"] == "succeeded"
    assert snapshot["collectors"]["eventLogs"]["data"][0]["channel"] == "system"


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