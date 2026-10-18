from __future__ import annotations

import json
import os
import plistlib
import re
import selectors
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable
from datetime import datetime, timezone

from pac.audit.platforms import collect_posix_summary


MAX_COMMAND_OUTPUT = 4 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 30


def _run_command(arguments: list[str], *, allow_nonzero: bool = False) -> str:
    """Run one fixed, read-only command with bounded time and output."""
    executable = shutil.which(arguments[0])
    if executable is None:
        raise FileNotFoundError(arguments[0])
    process = subprocess.Popen(
        [executable, *arguments[1:]],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    assert process.stdout is not None
    assert process.stderr is not None

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            ready_streams = selector.select(remaining) if remaining > 0 else []
            if not ready_streams:
                process.kill()
                process.wait()
                raise subprocess.TimeoutExpired(arguments, COMMAND_TIMEOUT_SECONDS)

            for key, _ in ready_streams:
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffer = buffers[key.data]
                if sum(map(len, buffers.values())) + len(chunk) > MAX_COMMAND_OUTPUT:
                    process.kill()
                    process.wait()
                    raise RuntimeError("command output exceeded limit")
                buffer.extend(chunk)
        return_code = process.wait(timeout=max(0, deadline - time.monotonic()))
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()

    stdout = buffers["stdout"].decode("utf-8", errors="replace")
    stderr = buffers["stderr"].decode("utf-8", errors="replace")
    if return_code and ("permission denied" in stderr.lower() or "operation not permitted" in stderr.lower()):
        raise PermissionError(arguments[0])
    if return_code and not allow_nonzero:
        raise RuntimeError(arguments[0])
    return stdout


def _capture(action: Callable[[], Any]) -> dict[str, Any]:
    try:
        return {"status": "succeeded", "data": action(), "errorCode": None}
    except PermissionError:
        return {"status": "denied", "data": None, "errorCode": "access_denied"}
    except FileNotFoundError:
        return {"status": "unavailable", "data": None, "errorCode": "tool_unavailable"}
    except subprocess.TimeoutExpired:
        return {"status": "failed", "data": None, "errorCode": "collection_timeout"}
    except Exception:
        return {"status": "failed", "data": None, "errorCode": "collection_error"}


def _collect_accounts() -> dict[str, Any]:
    """Read local POSIX users and group membership without password data."""
    import grp
    import pwd

    users = [
        {
            "Name": account.pw_name,
            "Enabled": None,
            "LastLogon": None,
            "PasswordRequired": None,
            "PrincipalSource": "Local",
            "uid": account.pw_uid,
            "home": account.pw_dir,
            "shell": account.pw_shell,
        }
        for account in pwd.getpwall()
    ]
    groups = [
        {
            "name": group.gr_name,
            "description": None,
            "members": [{"name": member} for member in group.gr_mem],
        }
        for group in grp.getgrall()
    ]
    return {"users": users, "groups": groups}


def _collect_linux_services() -> list[dict[str, Any]]:
    """Read systemd service state from the local service manager."""
    output = _run_command([
        "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager",
    ])
    services = []
    for line in output.splitlines():
        columns = line.split(None, 4)
        if len(columns) >= 4:
            services.append({
                "Name": columns[0],
                "DisplayName": columns[4] if len(columns) > 4 else columns[0],
                "State": columns[2],
                "StartMode": "systemd",
                "StartName": None,
                "PathName": None,
            })
    return services


def _collect_macos_services() -> list[dict[str, Any]]:
    """Read loaded launchd services from the local service manager."""
    output = _run_command(["launchctl", "list"])
    services = []
    for line in output.splitlines()[1:]:
        columns = line.split(None, 2)
        if len(columns) == 3:
            services.append({
                "Name": columns[2],
                "DisplayName": columns[2],
                "State": "Running" if columns[0] != "-" else "Loaded",
                "StartMode": "launchd",
                "StartName": None,
                "PathName": None,
            })
    return services


def _collect_linux_software() -> list[dict[str, Any]]:
    """Read package inventory from the installed dpkg or RPM database."""
    if shutil.which("dpkg-query"):
        output = _run_command([
            "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Maintainer}\n",
        ])
        return [
            {"name": parts[0], "version": parts[1], "publisher": parts[2] if len(parts) > 2 else None, "scope": "system"}
            for line in output.splitlines()
            if len(parts := line.split("\t", 2)) >= 2
        ]
    if shutil.which("rpm"):
        output = _run_command(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"])
        return [
            {"name": parts[0], "version": parts[1], "publisher": parts[2] if len(parts) > 2 else None, "scope": "system"}
            for line in output.splitlines()
            if len(parts := line.split("\t", 2)) >= 2
        ]
    raise FileNotFoundError("dpkg-query or rpm")


def _collect_macos_software() -> list[dict[str, Any]]:
    """Read app names and versions from local application bundles."""
    applications = []
    roots = [Path("/Applications"), Path.home() / "Applications"]
    for root in roots:
        if not root.exists():
            continue
        for app_bundle in root.glob("*.app"):
            info_path = app_bundle / "Contents" / "Info.plist"
            try:
                with info_path.open("rb") as info_file:
                    metadata = plistlib.load(info_file)
            except (OSError, plistlib.InvalidFileException):
                continue
            applications.append({
                "name": metadata.get("CFBundleDisplayName") or metadata.get("CFBundleName") or app_bundle.stem,
                "version": metadata.get("CFBundleShortVersionString") or metadata.get("CFBundleVersion"),
                "publisher": metadata.get("NSHumanReadableCopyright"),
                "scope": "user" if root == Path.home() / "Applications" else "system",
            })
    return applications


def _collect_linux_updates() -> dict[str, Any]:
    """Read cached apt upgrade candidates without refreshing repositories."""
    if not shutil.which("apt"):
        raise FileNotFoundError("apt update inventory")
    output = _run_command(["apt", "list", "--upgradable"], allow_nonzero=True)
    pending = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            pending.append({"title": parts[0], "version": parts[1], "downloaded": None})
    return {"installedHotfixes": [], "updateHistory": [], "pendingUpdates": pending}


def _collect_linux_firewall() -> dict[str, Any]:
    """Inspect the first available UFW, firewalld, or nftables state."""
    if shutil.which("ufw"):
        output = _run_command(["ufw", "status", "verbose"], allow_nonzero=True)
        enabled = output.lower().startswith("status: active")
        rules = [{"Name": line.strip(), "DisplayName": line.strip(), "Enabled": True, "Direction": None, "Action": None, "Profile": "UFW"} for line in output.splitlines() if "ALLOW" in line.upper() or "DENY" in line.upper()]
        return {"profiles": [{"Name": "UFW", "Enabled": enabled}], "rules": rules}
    if shutil.which("firewall-cmd"):
        state = _run_command(["firewall-cmd", "--state"], allow_nonzero=True).strip()
        enabled = state == "running"
        rules = [{"Name": line, "DisplayName": line, "Enabled": True, "Direction": None, "Action": None, "Profile": "firewalld"} for line in _run_command(["firewall-cmd", "--list-all"], allow_nonzero=True).splitlines()]
        return {"profiles": [{"Name": "firewalld", "Enabled": enabled}], "rules": rules}
    if shutil.which("nft"):
        rules = [{"Name": line, "DisplayName": line, "Enabled": True, "Direction": None, "Action": None, "Profile": "nftables"} for line in _run_command(["nft", "list", "ruleset"], allow_nonzero=True).splitlines()]
        return {"profiles": [{"Name": "nftables", "Enabled": bool(rules)}], "rules": rules}
    raise FileNotFoundError("supported firewall utility")


def _collect_macos_firewall() -> dict[str, Any]:
    """Inspect macOS Application Firewall state and listed applications."""
    command = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    if not Path(command).is_file():
        raise FileNotFoundError("Application Firewall")
    state = _run_command([command, "--getglobalstate"], allow_nonzero=True).strip()
    enabled = "enabled" in state.lower()
    rules = [{"Name": line, "DisplayName": line, "Enabled": True, "Direction": None, "Action": None, "Profile": "Application Firewall"} for line in _run_command([command, "--listapps"], allow_nonzero=True).splitlines()]
    return {"profiles": [{"Name": "Application Firewall", "Enabled": enabled}], "rules": rules}


def _collect_linux_security() -> dict[str, Any]:
    """Read Linux SELinux and AppArmor state when their tools are present."""
    controls = {}
    if shutil.which("getenforce"):
        controls["selinux"] = _run_command(["getenforce"], allow_nonzero=True).strip()
    if shutil.which("aa-status"):
        controls["apparmor"] = _run_command(["aa-status", "--enabled"], allow_nonzero=True).strip()
    return controls


def _collect_macos_security() -> dict[str, Any]:
    """Read local Gatekeeper and FileVault status when available."""
    controls = {}
    if shutil.which("spctl"):
        controls["gatekeeper"] = _run_command(["spctl", "--status"], allow_nonzero=True).strip()
    if shutil.which("fdesetup"):
        controls["fileVault"] = _run_command(["fdesetup", "status"], allow_nonzero=True).strip()
    return controls


def _collect_linux_tasks() -> list[dict[str, Any]]:
    """Read systemd timers and system-wide cron entries."""
    tasks = []
    if shutil.which("systemctl"):
        output = _run_command(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"])
        for line in output.splitlines():
            columns = line.split()
            if columns:
                tasks.append({"taskPath": "systemd", "taskName": columns[-1], "state": "Scheduled", "principal": None, "runLevel": None, "actions": []})
    cron_paths = [Path("/etc/crontab"), Path("/etc/cron.d")]
    cron_lines = []
    for path in cron_paths:
        candidates = [path] if path.is_file() else list(path.glob("*")) if path.is_dir() else []
        for candidate in candidates:
            try:
                cron_lines.extend(line.strip() for line in candidate.read_text(errors="replace").splitlines() if line.strip() and not line.lstrip().startswith("#"))
            except PermissionError:
                raise
    tasks.extend({"taskPath": "/etc/cron", "taskName": line, "state": "Configured", "principal": None, "runLevel": None, "actions": []} for line in cron_lines)
    return tasks


def _collect_macos_tasks() -> list[dict[str, Any]]:
    """Read configured launchd jobs from standard system and user folders."""
    task_roots = [
        Path("/System/Library/LaunchDaemons"),
        Path("/Library/LaunchDaemons"),
        Path("/Library/LaunchAgents"),
        Path.home() / "Library/LaunchAgents",
    ]
    tasks = []
    for root in task_roots:
        if not root.exists():
            continue
        for plist_path in root.glob("*.plist"):
            try:
                with plist_path.open("rb") as plist_file:
                    item = plistlib.load(plist_file)
            except (OSError, plistlib.InvalidFileException):
                continue
            tasks.append({
                "taskPath": str(root),
                "taskName": item.get("Label", plist_path.stem),
                "state": "Configured",
                "principal": item.get("UserName"),
                "runLevel": None,
                "actions": item.get("ProgramArguments") or [item.get("Program")],
            })
    return tasks


def _collect_linux_events() -> list[dict[str, Any]]:
    """Read a bounded selection of recent local journal entries."""
    output = _run_command(["journalctl", "--no-pager", "-n", "1000", "-o", "json"])
    events = []
    for index, line in enumerate(output.splitlines()):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        priority = entry.get("PRIORITY")
        level = {"0": "Critical", "1": "Critical", "2": "Critical", "3": "Error", "4": "Warning"}.get(str(priority), "Information")
        timestamp = entry.get("__REALTIME_TIMESTAMP")
        try:
            collected_time = datetime.fromtimestamp(int(timestamp) / 1_000_000, timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            collected_time = None
        events.append({
            "timeCreated": collected_time,
            "eventId": entry.get("MESSAGE_ID"),
            "level": level,
            "provider": entry.get("SYSLOG_IDENTIFIER"),
            "recordId": index,
            "message": str(entry.get("MESSAGE", ""))[:600],
        })
    return events


def _collect_macos_events() -> list[dict[str, Any]]:
    """Read up to 1,000 recent fault, error, and default unified-log lines."""
    output = _run_command([
        "log", "show", "--last", "24h", "--style", "syslog", "--limit", "1000",
        "--predicate", "messageType == fault OR messageType == error OR messageType == default",
    ])
    return [
        {"timeCreated": None, "eventId": None, "level": "Error" if re.search(r"\b(error|fault)\b", line, re.IGNORECASE) else "Information", "provider": "Unified Log", "recordId": index, "message": line[:600]}
        for index, line in enumerate(output.splitlines())
        if line.strip()
    ]


def collect_posix_audit(
    target_platform: str,
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect platform-specific inventories without accepting shell input."""
    if target_platform not in {"linux", "macos"}:
        raise ValueError("POSIX audit requested for unsupported platform")

    service_collector = _collect_linux_services if target_platform == "linux" else _collect_macos_services
    software_collector = _collect_linux_software if target_platform == "linux" else _collect_macos_software
    firewall_collector = _collect_linux_firewall if target_platform == "linux" else _collect_macos_firewall
    security_collector = _collect_linux_security if target_platform == "linux" else _collect_macos_security
    task_collector = _collect_linux_tasks if target_platform == "linux" else _collect_macos_tasks
    event_collector = _collect_linux_events if target_platform == "linux" else _collect_macos_events

    def unavailable_updates() -> None:
        raise FileNotFoundError("local update inventory")

    update_collector = _collect_linux_updates if target_platform == "linux" else unavailable_updates
    event_collector = _collect_linux_events if target_platform == "linux" else _collect_macos_events
    machine_summary = summary or collect_posix_summary(target_platform)
    sections = {
        "accountsAndGroups": _capture(_collect_accounts),
        "services": _capture(service_collector),
        "installedSoftware": _capture(software_collector),
        "updates": _capture(update_collector),
        "firewall": _capture(firewall_collector),
        "security": _capture(security_collector),
        "scheduledTasks": _capture(task_collector),
        "eventLogs": _capture(lambda: [{"channel": "system", "status": "succeeded", "recordCount": None, "collectedCount": len(events), "truncated": False, "events": events} for events in [event_collector()]]),
    }
    machine_summary["remoteAccess"].update({
        "serviceState": "Not detected",
        "configuredEnabled": None,
    })
    services = sections["services"].get("data") or []
    ssh_services = [
        service for service in services
        if "ssh" in str(service.get("Name", "")).lower()
        or "remote-login" in str(service.get("Name", "")).lower()
    ]
    if ssh_services:
        active_services = [
            service for service in ssh_services
            if str(service.get("State", "")).lower() in {"active", "running"}
        ]
        machine_summary["remoteAccess"]["serviceState"] = (
            "Active" if active_services else "Inactive or loaded"
        )
    return {
        "schema_version": 1,
        "collected_at": machine_summary["collectedAt"],
        "machine": machine_summary,
        "collectors": sections,
        "recommendations": [],
    }