
import io
import subprocess

import pytest

import pac.powershell.runner as runner


class FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", timeout=False):
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = 0
        self.killed = False
        self.timeout = timeout
        self.wait_calls = 0

    def wait(self, timeout=None):
        self.wait_calls += 1

        if self.timeout and self.wait_calls == 1:
            raise subprocess.TimeoutExpired("pwsh", timeout)

        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


def test_rejects_non_positive_timeout():
    with pytest.raises(ValueError, match="timeout_seconds"):
        runner.run_hello_task(timeout_seconds=0)


def test_rejects_non_positive_output_limit():
    with pytest.raises(ValueError, match="max_output_bytes"):
        runner.run_hello_task(max_output_bytes=0)


def test_missing_powershell_is_reported(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)

    with pytest.raises(runner.PowerShellExecutionError, match="not found"):
        runner.run_hello_task()


def test_timeout_kills_process(monkeypatch):
    fake = FakeProcess(timeout=True)
    monkeypatch.setattr(runner.shutil, "which", lambda _: "/usr/bin/pwsh")
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **kw: fake)

    with pytest.raises(runner.PowerShellExecutionError, match="exceeded"):
        runner.run_hello_task(timeout_seconds=0.01)

    assert fake.killed


def test_output_limit_kills_process(monkeypatch):
    fake = FakeProcess(stdout=b"x" * 100)
    monkeypatch.setattr(runner.shutil, "which", lambda _: "/usr/bin/pwsh")
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **kw: fake)

    with pytest.raises(runner.PowerShellExecutionError, match="output exceeded"):
        runner.run_hello_task(max_output_bytes=8)

    assert fake.killed


def test_nonzero_exit_is_failure(monkeypatch):
    fake = FakeProcess(stderr=b"task failed")
    fake.returncode = 7

    monkeypatch.setattr(runner.shutil, "which", lambda _: "/usr/bin/pwsh")
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **kw: fake)

    with pytest.raises(runner.PowerShellExecutionError, match="code 7"):
        runner.run_hello_task()