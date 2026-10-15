
import json

from pac.powershell.runner import run_hello_task


def test_hello_task_returns_diagnostic_json() -> None:
    result = run_hello_task()

    assert result.returncode == 0, result.stderr

    payload = json.loads(result.stdout)
    assert payload["message"] == "PowerShell task completed"
    assert payload["powershellVersion"]
    assert payload["platform"]