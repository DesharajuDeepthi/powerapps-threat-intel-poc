from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


FIELD_PATTERN = re.compile(r"^\s*[-*•]?\s*\*?(?P<key>[A-Za-z][A-Za-z0-9 /_-]*?)\*?\s*:\s*(?P<value>.+?)\s*$")
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


@dataclass(frozen=True)
class ThreatIntelRecord:
    slack_message_ts: str
    document: str
    threat: str
    impacted_technology: str
    cve_count: int
    cves: list[str]
    slack_user_id: str = ""
    analyst_name: str = ""
    analyst_email: str = ""


def parse_threat_intel_messages(messages: list[dict[str, Any]]) -> list[ThreatIntelRecord]:
    records: list[ThreatIntelRecord] = []
    for message in messages:
        record = parse_threat_intel_message(message)
        if record is not None:
            records.append(record)
    return records


def parse_threat_intel_message(message: dict[str, Any]) -> ThreatIntelRecord | None:
    text = message.get("text")
    if not isinstance(text, str) or not text.strip():
        return None

    fields = _parse_fields(text)
    document = fields.get("document", "").strip()
    if not document:
        return None

    cves = _extract_cves(fields.get("cve", ""))
    cve_count = _parse_cve_count(fields.get("cve count"), len(cves))

    return ThreatIntelRecord(
        slack_message_ts=str(message.get("ts", "")).strip(),
        document=document,
        threat=fields.get("threat", "").strip(),
        impacted_technology=fields.get("impacted technology", "").strip(),
        cve_count=cve_count,
        cves=cves,
        slack_user_id=_slack_user_id(message),
        analyst_name=_analyst_name(message),
        analyst_email=_analyst_email(message),
    )


def _parse_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = FIELD_PATTERN.match(line)
        if not match:
            continue

        key = _normalize_key(match.group("key"))
        value = match.group("value").strip().strip("*").strip()
        if key == "cves":
            key = "cve"
        elif key == "impacted technologies":
            key = "impacted technology"

        fields[key] = value
    return fields


def _normalize_key(key: str) -> str:
    return re.sub(r"\s+", " ", key.strip().lower())


def _extract_cves(value: str) -> list[str]:
    return sorted({match.group(0).upper() for match in CVE_PATTERN.finditer(value)})


def _parse_cve_count(value: str | None, fallback: int) -> int:
    if value is None:
        return fallback

    match = re.search(r"\d+", value)
    if not match:
        return fallback
    return int(match.group(0))


def _slack_user_id(message: dict[str, Any]) -> str:
    for key in ("user", "bot_id", "app_id"):
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _analyst_name(message: dict[str, Any]) -> str:
    profile = message.get("user_profile")
    if isinstance(profile, dict):
        for key in ("real_name", "display_name", "name"):
            value = profile.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    bot_profile = message.get("bot_profile")
    if isinstance(bot_profile, dict):
        value = bot_profile.get("name")
        if isinstance(value, str) and value.strip():
            return value.strip()

    username = message.get("username")
    if isinstance(username, str) and username.strip():
        return username.strip()

    return _slack_user_id(message)


def _analyst_email(message: dict[str, Any]) -> str:
    profile = message.get("user_profile")
    if isinstance(profile, dict):
        value = profile.get("email")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""
