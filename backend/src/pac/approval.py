from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def is_privileged_context() -> bool:
    """Return True when the current process already has the operating-system privilege needed for audit collection."""
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.run(
                ["whoami", "/groups"],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            return False
        output = (result.stdout or "") + (result.stderr or "")
        return (
            "S-1-5-32-544" in output
            or "Administrators" in output
            or "Builtin\\Administrators" in output
        )

    return os.geteuid() == 0


def native_approval_method() -> str:
    system = platform.system()
    if system == "Windows":
        return "uac"
    if system in {"Linux", "Darwin"}:
        return "sudo"
    return "unsupported"


def helper_command() -> str:
    system = platform.system()
    project_root = _project_root()
    if system == "Windows":
        script = project_root / "powershell" / "scripts" / "pac-approval.ps1"
        return (
            'powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File '
            f'"{script}"'
        )
    if system in {"Linux", "Darwin"}:
        return "sudo -n true"
    return "No native approval helper is available on this platform."


def approval_status() -> dict[str, object]:
    approved = is_privileged_context()
    return {
        "approved": approved,
        "requiresApproval": not approved,
        "platform": platform.system(),
        "method": native_approval_method(),
        "helperCommand": helper_command(),
        "explanation": (
            "PAC requires a local OS approval step before it can collect privileged system data. "
            "The helper must be launched on the host and approved by the user."
        ),
    }


def request_native_approval() -> dict[str, object]:
    """Attempt the OS-native approval step without altering the audit workflow when it is unavailable."""
    status = approval_status()
    if status["approved"]:
        return {**status, "attempted": False, "result": "already-approved"}

    system = platform.system()
    if system == "Windows":
        script = _project_root() / "powershell" / "scripts" / "pac-approval.ps1"
        command = [
            "powershell",
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            (
                "Start-Process powershell -Verb RunAs -ArgumentList @('-NoLogo','-NoProfile',"
                "'-ExecutionPolicy','Bypass','-File','"
                f"{script}'"
                ")"
            ),
        ]
    elif system in {"Linux", "Darwin"}:
        if shutil.which("sudo") is None:
            return {
                **status,
                "attempted": False,
                "result": "unavailable",
                "message": "A sudo-based native helper is unavailable on this host.",
            }
        command = ["sudo", "-n", "true"]
    else:
        return {
            **status,
            "attempted": False,
            "result": "unsupported",
            "message": "No native approval helper is available for this platform.",
        }

    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        return {
            **status,
            "attempted": True,
            "result": "unavailable",
            "message": str(exc),
        }

    if completed.returncode == 0:
        return {
            **status,
            "attempted": True,
            "result": "approved",
            "message": "The local operating system accepted the approval helper request.",
        }

    return {
        **status,
        "attempted": True,
        "result": "pending",
        "message": (
            "The approval helper is available but was not granted privileges in this session. "
            "Run the helper from the host desktop or use the system's native elevation prompt."
        ),
    }
