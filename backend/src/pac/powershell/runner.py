
from __future__ import annotations

import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path


MAX_OUTPUT_BYTES = 16 * 1024
DEFAULT_TIMEOUT_SECONDS = 10


class PowerShellExecutionError(RuntimeError):
    """Raised when a PowerShell task cannot run safely."""


@dataclass(frozen=True)
class TaskResult:
    returncode: int
    stdout: str
    stderr: str


def run_hello_task(
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
) -> TaskResult:
    """Run the one approved diagnostic script with bounded output."""

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be greater than zero")

    executable = shutil.which("pwsh")
    if executable is None:
        raise PowerShellExecutionError(
            "PowerShell 7 (pwsh) was not found on PATH"
        )

    # Resolve a fixed, application-owned script; never accept a path from a caller.
    project_root = Path(__file__).resolve().parents[4]
    script = project_root / "powershell" / "scripts" / "hello.ps1"

    if not script.is_file():
        raise PowerShellExecutionError(
            f"Approved script is missing: {script}"
        )

    command = [
        executable,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(script),
    ]

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except OSError as exc:
        raise PowerShellExecutionError(
            "Could not start PowerShell"
        ) from exc

    assert process.stdout is not None
    assert process.stderr is not None

    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    output_limit_exceeded = threading.Event()

    def collect_output(stream, buffer: bytearray) -> None:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return

            remaining = max_output_bytes - len(buffer)
            if len(chunk) > remaining:
                buffer.extend(chunk[:remaining])
                output_limit_exceeded.set()
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                return

            buffer.extend(chunk)

    stdout_thread = threading.Thread(
        target=collect_output,
        args=(process.stdout, stdout_buffer),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=collect_output,
        args=(process.stderr, stderr_buffer),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()

    stdout_thread.join()
    stderr_thread.join()

    if timed_out:
        raise PowerShellExecutionError(
            f"PowerShell task exceeded {timeout_seconds} seconds"
        )

    if output_limit_exceeded.is_set():
        raise PowerShellExecutionError(
            f"PowerShell output exceeded {max_output_bytes} bytes"
        )
    
    if process.returncode != 0:
        raise PowerShellExecutionError(
            f"PowerShell task exited with code {process.returncode}"
    )

    return TaskResult(
        returncode=process.returncode,
        stdout=stdout_buffer.decode("utf-8", errors="replace"),
        stderr=stderr_buffer.decode("utf-8", errors="replace"),
    )