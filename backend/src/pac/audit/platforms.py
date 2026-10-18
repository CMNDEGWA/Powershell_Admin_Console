from __future__ import annotations

import os
import platform as platform_info
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil


def detect_platform(system_name: str | None = None) -> str:
    """Normalize the host operating system for collector selection."""
    system = (system_name or platform_info.system()).lower()
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    if system == "darwin":
        return "macos"
    return "unsupported"


def _processor_name(target: str) -> str | None:
    """Read a descriptive CPU label when Python does not provide one."""
    if platform_info.processor():
        return platform_info.processor()
    if target == "linux":
        try:
            cpu_information = Path("/proc/cpuinfo").read_text(errors="replace")
        except OSError:
            return None
        match = re.search(r"^(?:model name|Hardware|Processor)\s*:\s*(.+)$", cpu_information, re.MULTILINE)
        return match.group(1).strip() if match else None
    return None


def collect_posix_summary(target_platform: str | None = None) -> dict[str, Any]:
    """Collect the shared machine overview on Linux or macOS."""
    target = target_platform or detect_platform()
    if target not in {"linux", "macos"}:
        raise ValueError("POSIX summary requested for unsupported platform")

    release = {}
    if target == "linux":
        try:
            release = platform_info.freedesktop_os_release()
        except OSError:
            release = {}
        caption = release.get("PRETTY_NAME") or release.get("NAME") or "Linux"
        version = release.get("VERSION_ID") or release.get("VERSION") or "Rolling release"
    else:
        mac_version = platform_info.mac_ver()[0]
        caption = "macOS"
        version = mac_version or platform_info.release()

    interfaces = psutil.net_if_addrs()
    interface_stats = psutil.net_if_stats()
    adapters = []
    link_family = getattr(psutil, "AF_LINK", getattr(psutil, "AF_PACKET", object()))
    for name, addresses in interfaces.items():
        ip_addresses = [
            {
                "address": address.address.split("%", 1)[0],
                "family": "IPv6" if address.family == socket.AF_INET6 else "IPv4",
                "prefixLength": None,
            }
            for address in addresses
            if address.family in {
                socket.AF_INET,
                socket.AF_INET6,
            }
        ]
        mac_address = next(
            (address.address for address in addresses if address.family == link_family),
            None,
        )
        stats = interface_stats.get(name)
        adapters.append({
            "name": name,
            "description": name,
            "status": "Up" if stats and stats.isup else "Down",
            "macAddress": mac_address,
            "linkSpeed": stats.speed if stats else None,
            "addresses": ip_addresses,
        })

    memory_bytes = psutil.virtual_memory().total
    boot_time = datetime.fromtimestamp(psutil.boot_time(), timezone.utc)
    now = datetime.now(timezone.utc)
    remote_name = "SSH" if target == "linux" else "Remote Login (SSH)"
    return {
        "platform": target,
        "supportedTarget": True,
        "collectedAt": now.isoformat(),
        "hostname": platform_info.node(),
        "operatingSystem": {
            "caption": caption,
            "edition": release.get("ID") if target == "linux" else "macOS",
            "version": version,
            "build": platform_info.release(),
            "architecture": platform_info.machine(),
            "powershellProcess64Bit": sys.maxsize > 2**32,
            "powershellVersion": None,
            "lastBootTime": boot_time.isoformat(),
            "uptimeSeconds": max(0, int((now - boot_time).total_seconds())),
        },
        "hardware": {
            "manufacturer": None,
            "model": platform_info.machine(),
            "processorNames": [name for name in [_processor_name(target)] if name],
            "logicalProcessors": psutil.cpu_count(logical=True),
            "memoryBytes": memory_bytes,
        },
        "networkAdapters": adapters,
        "remoteDesktop": None,
        "remoteAccess": {
            "name": remote_name,
            "configuredEnabled": None,
            "serviceState": "Not assessed in summary",
            "serviceStartMode": None,
            "enabledInboundFirewallRule": None,
            "firewallRules": None,
        },
        "administrator": os.geteuid() == 0,
    }