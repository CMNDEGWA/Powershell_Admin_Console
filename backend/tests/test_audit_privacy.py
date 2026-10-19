import json

from pac.audit.privacy import sanitize_snapshot


def test_sanitize_snapshot_removes_sensitive_fields_and_preserves_findings() -> None:
    snapshot = {
        "machine": {
            "networkAdapters": [{
                "name": "Ethernet",
                "macAddress": "00-11-22-33-44-55",
                "addresses": [{"address": "192.0.2.10"}],
            }],
        },
        "collectors": {
            "accountsAndGroups": {
                "status": "succeeded",
                "data": {
                    "users": [{"Name": "alice", "Enabled": True, "LastLogon": "recent"}],
                    "groups": [{"name": "Administrators", "members": [{"name": "alice"}]}],
                },
            },
            "services": {
                "status": "succeeded",
                "data": [{"Name": "Example", "StartName": "alice", "PathName": "/opt/private/service"}],
            },
            "scheduledTasks": {
                "status": "succeeded",
                "data": [{"taskName": "nightly /home/alice/job --token x", "actions": [{"arguments": "--token x"}]}],
            },
            "eventLogs": {
                "status": "succeeded",
                "data": [{"events": [{"eventId": 42, "message": "alice logged in"}]}],
            },
        },
        "recommendations": [{"id": "example", "summary": "alice logged in", "evidence": {"Name": "alice"}}],
    }

    cleaned = sanitize_snapshot(snapshot)
    serialized = json.dumps(cleaned)

    assert "00-11-22-33-44-55" not in serialized
    assert "192.0.2.10" not in serialized
    assert "alice" not in serialized
    assert "/opt/private/service" not in serialized
    assert "--token x" not in serialized
    assert "message" not in cleaned["collectors"]["eventLogs"]["data"][0]["events"][0]
    assert cleaned["collectors"]["accountsAndGroups"]["status"] == "succeeded"
    assert cleaned["collectors"]["accountsAndGroups"]["data"]["users"][0]["Name"] == "Local account 1"
    assert cleaned["recommendations"][0]["id"] == "example"
    assert cleaned["recommendations"][0]["summary"] == "Local account 1 logged in"