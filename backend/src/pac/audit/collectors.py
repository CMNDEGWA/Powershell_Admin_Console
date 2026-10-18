from __future__ import annotations

import json
from typing import Any

from pac.powershell.runner import PowerShellExecutionError, run_audit_script


class UnsupportedAuditPlatform(PowerShellExecutionError):
    """Raised when the audit target is outside the supported Windows baseline."""

class InsufficientAuditPrivileges(PowerShellExecutionError):
    """Raised when a full audit is requested without an elevated process."""



def _read_payload(mode: str) -> dict[str, Any]:
    result = run_audit_script(mode)
    try:
        payload = json.loads(result.stdout.lstrip("\ufeff"))
    except (json.JSONDecodeError, TypeError) as exc:
        raise PowerShellExecutionError("PowerShell returned invalid audit JSON") from exc

    if not isinstance(payload, dict) or payload.get("schemaVersion") != 1:
        raise PowerShellExecutionError("PowerShell returned an unsupported audit schema")
    if payload.get("mode") != mode or not isinstance(payload.get("machine"), dict):
        raise PowerShellExecutionError("PowerShell returned an incomplete audit payload")
    return payload


def collect_machine_summary() -> dict[str, Any]:
    """Collect the overview independently from the full audit."""
    payload = _read_payload("summary")
    machine = payload["machine"]
    machine["supportedTarget"] = bool(payload.get("supportedTarget"))
    machine["collectedAt"] = payload.get("collectedAt")
    return machine


def collect_system_audit() -> dict[str, Any]:
    """Collect and validate the complete fixed audit snapshot."""
    payload = _read_payload("audit")
    if payload.get("supportedTarget") is not True:
        raise UnsupportedAuditPlatform(
            "Auditing requires a Windows system and PowerShell 7"
        )
    if payload["machine"].get("administrator") is not True:
        raise InsufficientAuditPrivileges("The full audit must run as administrator")

    sections = payload.get("sections")
    if not isinstance(sections, dict):
        raise PowerShellExecutionError("PowerShell returned invalid collector results")

    allowed_statuses = {"succeeded", "failed", "denied"}
    for name, section in sections.items():
        if (
            not isinstance(name, str)
            or not isinstance(section, dict)
            or section.get("status") not in allowed_statuses
        ):
            raise PowerShellExecutionError("PowerShell returned an invalid collector status")

    return {
        "schema_version": 1,
        "collected_at": payload.get("collectedAt"),
        "machine": payload["machine"],
        "collectors": sections,
        "recommendations": [],
    }


def audit_status(snapshot: dict[str, Any]) -> str:
    """Return succeeded only when all collectors and selected logs completed."""
    collector_results = list(snapshot.get("collectors", {}).values())
    if not collector_results:
        return "failed"

    incomplete = any(item.get("status") != "succeeded" for item in collector_results)
    event_logs = snapshot.get("collectors", {}).get("eventLogs", {})
    event_data = event_logs.get("data")
    if isinstance(event_data, list):
        incomplete = incomplete or any(log.get("status") != "succeeded" for log in event_data)
    if all(item.get("status") != "succeeded" for item in collector_results):
        return "failed"
    return "partial" if incomplete else "succeeded"