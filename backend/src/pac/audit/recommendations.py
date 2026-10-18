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
) -> dict[str, Any]:
    return {
        "id": rule_id,
        "rule_version": RULE_VERSION,
        "title": title,
        "severity": severity,
        "summary": summary,
        "recommendation": recommendation,
        "evidence": evidence,
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
                    summary="Windows Firewall is disabled for this network profile.",
                    recommendation="Enable the firewall profile unless a documented security control provides equivalent protection.",
                    evidence=profile,
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
            ))
        if security.get("uacEnabled") is False:
            findings.append(_finding(
                rule_id="uac-disabled",
                title="User Account Control is disabled",
                severity="high",
                summary="The EnableLUA policy is disabled.",
                recommendation="Enable User Account Control and verify that administrative workflows continue to operate as intended.",
                evidence={"uacEnabled": False},
            ))

    machine = snapshot.get("machine", {})
    remote_desktop = machine.get("remoteDesktop", {}) if isinstance(machine, dict) else {}
    if remote_desktop.get("configuredEnabled") is True:
        firewall_open = remote_desktop.get("enabledInboundFirewallRule") is True
        findings.append(_finding(
            rule_id="remote-desktop-enabled",
            title="Remote Desktop is configured",
            severity="medium" if firewall_open else "low",
            summary=(
                "Remote Desktop is configured and an enabled inbound firewall rule was found."
                if firewall_open
                else "Remote Desktop is configured, but no enabled inbound firewall rule was found."
            ),
            recommendation="If remote access is not required, disable Remote Desktop. If it is required, restrict access to approved users and trusted networks.",
            evidence={
                "configuredEnabled": True,
                "serviceState": remote_desktop.get("serviceState"),
                "serviceStartMode": remote_desktop.get("serviceStartMode"),
                "enabledInboundFirewallRule": firewall_open,
            },
        ))

    accounts = _data(snapshot, "accountsAndGroups")
    if isinstance(accounts, dict):
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
                ))

    updates = _data(snapshot, "updates")
    if isinstance(updates, dict):
        pending = _items(updates.get("pendingUpdates"))
        if pending:
            findings.append(_finding(
                rule_id="pending-updates",
                title=f"{len(pending)} updates are available",
                severity="medium",
                summary="Windows Update reported updates that are not installed.",
                recommendation="Review the available updates and install approved security and quality updates during a suitable maintenance window.",
                evidence={"count": len(pending), "updates": pending[:20]},
            ))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda item: (severity_order[item["severity"]], item["title"]))