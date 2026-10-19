from __future__ import annotations

import re
from typing import Any


_SENSITIVE_FIELDS = {
    "address",
    "addresses",
    "arguments",
    "execute",
    "home",
    "ipaddress",
    "lastlogon",
    "localaddress",
    "macaddress",
    "message",
    "path",
    "pathname",
    "program",
    "principal",
    "remoteaddress",
    "shell",
    "startname",
    "taskpath",
    "uid",
    "username",
    "workingdirectory",
}


def _account_aliases(snapshot: dict[str, Any]) -> dict[str, str]:
    accounts = (
        snapshot.get("collectors", {})
        .get("accountsAndGroups", {})
        .get("data", {})
        .get("users", [])
    )
    aliases: dict[str, str] = {}
    for index, account in enumerate(accounts, start=1):
        if not isinstance(account, dict) or not isinstance(account.get("Name"), str):
            continue
        label = f"Local account {index}"
        name = account["Name"]
        aliases[name.casefold()] = label
        aliases[name.rsplit("\\", 1)[-1].casefold()] = label
    return aliases


def sanitize_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Remove sensitive inventory values and pseudonymize account references.

    Account aliases are applied throughout the snapshot so collector data and
    recommendation evidence remain correlatable without storing real names.
    """
    aliases = _account_aliases(snapshot)

    def sanitize(value: Any, context: tuple[str, ...] = ()) -> Any:
        if isinstance(value, dict):
            cleaned = {}
            for key, item in value.items():
                normalized = "".join(character for character in key.casefold() if character.isalnum())
                if normalized in _SENSITIVE_FIELDS:
                    continue
                if normalized == "taskname" and "scheduledtasks" in context:
                    cleaned[key] = "Scheduled task"
                    continue
                if normalized in {"name", "username"} and ("users" in context or "members" in context):
                    if isinstance(item, str):
                        cleaned[key] = aliases.get(item.casefold(), "Local account")
                    continue
                cleaned[key] = sanitize(item, (*context, normalized))
            return cleaned
        if isinstance(value, list):
            return [sanitize(item, context) for item in value]
        if isinstance(value, str):
            cleaned = value
            for account_name, label in sorted(aliases.items(), key=lambda item: len(item[0]), reverse=True):
                cleaned = re.sub(
                    rf"(?<![\w.-]){re.escape(account_name)}(?![\w.-])",
                    label,
                    cleaned,
                    flags=re.IGNORECASE,
                )
            return cleaned
        return value

    return sanitize(snapshot)