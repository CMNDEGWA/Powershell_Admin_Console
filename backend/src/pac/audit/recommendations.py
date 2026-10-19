from __future__ import annotations

from typing import Any


RULE_VERSION = "2026.1"


def _data(snapshot: dict[str, Any], collector: str) -> Any:
    result = snapshot.get("collectors", {}).get(collector, {})
    if result.get("status") != "succeeded":
        return None
    return result.get("data")


def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _finding(
    *,
    rule_id: str,
    title: str,
    severity: str,
    summary: str,
    recommendation: str,
    evidence: Any,
    severity_rationale: str,
    applicability: str,
    confidence: str = "high",
) -> dict[str, Any]:
    return {
        "id": rule_id,
        "rule_version": RULE_VERSION,
        "title": title,
        "severity": severity,
        "summary": summary,
        "recommendation": recommendation,
        "evidence": evidence,
        "severity_rationale": severity_rationale,
        "applicability": applicability,
        "confidence": confidence,
    }


def generate_recommendations(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Apply explicit, deterministic checks to collected evidence."""
    findings: list[dict[str, Any]] = []
    firewall = _data(snapshot, "firewall")
    if isinstance(firewall, dict):
        for profile in _items(firewall.get("profiles")):
            if isinstance(profile, dict) and profile.get("Enabled") is False:
                findings.append(_finding(
                    rule_id=f"firewall-disabled-{str(profile.get('Name', 'unknown')).lower()}",
                    title=f"{profile.get('Name', 'A firewall')} profile is disabled",
                    severity="high",
                    summary=f"The {profile.get('Name', 'system firewall')} profile is disabled.",
                    recommendation="Enable a host firewall unless a documented security control provides equivalent protection.",
                    evidence=profile,
                    severity_rationale="A disabled host firewall profile can remove a layer of inbound and outbound traffic filtering.",
                    applicability="Applies to firewall profiles returned by the platform collector.",
                ))

    security = _data(snapshot, "security")
    if isinstance(security, dict):
        defender = security.get("defender")
        if isinstance(defender, dict) and defender.get("RealTimeProtectionEnabled") is False:
            findings.append(_finding(
                rule_id="defender-realtime-disabled",
                title="Microsoft Defender real-time protection is disabled",
                severity="high",
                summary="The collected Defender status reports real-time protection disabled.",
                recommendation="Confirm that another approved endpoint-protection product is active, or enable Microsoft Defender real-time protection.",
                evidence=defender,
                severity_rationale="Real-time malware protection is explicitly reported as disabled; alternative endpoint protection is not assessed.",
                applicability="Applies to Windows systems where the Defender collector returns this setting.",
            ))
        if security.get("uacEnabled") is False:
            findings.append(_finding(
                rule_id="uac-disabled",
                title="User Account Control is disabled",
                severity="high",
                summary="The EnableLUA policy is disabled.",
                recommendation="Enable User Account Control and verify that administrative workflows continue to operate as intended.",
                evidence={"uacEnabled": False},
                severity_rationale="Disabling UAC removes a Windows privilege-prompting control.",
                applicability="Applies to Windows systems where the UAC policy was collected.",
            ))

    machine = snapshot.get("machine") or {}
    remote_desktop = machine.get("remoteDesktop", {}) if isinstance(machine, dict) else {}
    if remote_desktop.get("configuredEnabled") is True:
        firewall_state = remote_desktop.get("enabledInboundFirewallRule")
        firewall_open = firewall_state is True
        if firewall_open:
            remote_summary = "Remote Desktop is configured and an enabled inbound firewall rule was found."
            severity_rationale = "An enabled inbound firewall rule was detected for a configured remote-access service."
            confidence = "high"
        elif firewall_state is False:
            remote_summary = "Remote Desktop is configured, but no enabled inbound firewall rule was found."
            severity_rationale = "Remote Desktop is configured, although the collected firewall data did not show an enabled inbound rule."
            confidence = "high"
        else:
            remote_summary = "Remote Desktop is configured, but inbound firewall state was not collected."
            severity_rationale = "Remote Desktop is configured; exposure cannot be determined because firewall state is unknown."
            confidence = "limited"
        findings.append(_finding(
            rule_id="remote-desktop-enabled",
            title="Remote Desktop is configured",
            severity="medium" if firewall_open else "low",
            summary=remote_summary,
            recommendation="If remote access is not required, disable Remote Desktop. If it is required, restrict access to approved users and trusted networks.",
            evidence={
                "configuredEnabled": True,
                "serviceState": remote_desktop.get("serviceState"),
                "serviceStartMode": remote_desktop.get("serviceStartMode"),
                "enabledInboundFirewallRule": firewall_state,
            },
            severity_rationale=severity_rationale,
            applicability="Applies to Windows systems where Remote Desktop configuration was collected.",
            confidence=confidence,
        ))

    remote_access = machine.get("remoteAccess", {}) if isinstance(machine, dict) else {}
    if (
        machine.get("platform") in {"linux", "macos"}
        and str(remote_access.get("serviceState", "")).lower() in {"active", "running"}
    ):
        findings.append(_finding(
            rule_id="ssh-service-active",
            title=f"{remote_access.get('name', 'SSH')} service is active",
            severity="low",
            summary="A remote-login service is active on this system.",
            recommendation="Confirm remote login is required and restrict it to approved users and trusted networks.",
            evidence={"serviceState": remote_access.get("serviceState")},
            severity_rationale="An active remote-login service increases the machine's remotely reachable administration surface.",
            applicability="Applies to Linux and macOS when a known remote-login service is detected.",
        ))

    accounts = _data(snapshot, "accountsAndGroups")
    if isinstance(accounts, dict) and machine.get("platform") in {None, "windows"}:
        for user in _items(accounts.get("users")):
            if (
                isinstance(user, dict)
                and isinstance(user.get("Name"), str)
                and user["Name"].lower() == "guest"
                and user.get("Enabled") is True
            ):
                findings.append(_finding(
                    rule_id="guest-account-enabled",
                    title="The built-in Guest account is enabled",
                    severity="medium",
                    summary="The local Guest account is enabled.",
                    recommendation="Disable the Guest account unless there is an approved, documented need for it.",
                    evidence=user,
                    severity_rationale="An enabled built-in Guest account may permit access with reduced accountability.",
                    applicability="Applies to Windows local accounts when the accounts collector succeeds.",
                ))

    updates = _data(snapshot, "updates")
    if isinstance(updates, dict):
        pending = _items(updates.get("pendingUpdates"))
        if pending:
            findings.append(_finding(
                rule_id="pending-updates",
                title=f"{len(pending)} updates are available",
                severity="medium",
                summary="The platform update inventory reported updates that are not installed.",
                recommendation="Review the available updates and install approved security and quality updates during a suitable maintenance window.",
                evidence={"count": len(pending), "updates": pending[:20]},
                severity_rationale="The configured package/update source reports pending updates; applicability and urgency depend on update metadata.",
                applicability="Applies only where the platform update collector completed successfully.",
                confidence="medium",
            ))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda item: (severity_order[item["severity"]], item["title"]))