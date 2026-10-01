from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from src.slack_client import SlackClient, SlackClientError

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class SlackPdfFile:
    file_id: str
    name: str
    url_private_download: str
    message_ts: str


@dataclass(frozen=True)
class SlackPdfDuplicateSighting:
    file_id: str
    name: str
    first_message_ts: str
    duplicate_message_ts: str
    match_reason: str


def validate_slack_auth(slack_client: SlackClient) -> dict[str, Any]:
    auth_info = slack_client.get("auth.test")
    LOGGER.info("Slack bot authentication succeeded")
    return auth_info


def get_channels(slack_client: SlackClient) -> list[dict[str, Any]]:
    channels = slack_client.get_cursor_paginated(
        "conversations.list",
        collection_key="channels",
        params={
            "types": "public_channel,private_channel",
            "exclude_archived": "true",
            "limit": 200,
        },
    )
    LOGGER.info("%s Slack channels retrieved", len(channels))
    return channels


def get_channel_messages(slack_client: SlackClient, channel_id: str) -> list[dict[str, Any]]:
    messages = slack_client.get_cursor_paginated(
        "conversations.history",
        collection_key="messages",
        params={
            "channel": channel_id,
            "limit": 200,
        },
    )
    LOGGER.info("%s Slack channel messages retrieved", len(messages))
    return messages


def enrich_message_sender_details(
    slack_client: SlackClient,
    messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    user_ids = sorted(
        {
            user_id
            for message in messages
            if isinstance((user_id := message.get("user")), str)
            and user_id.strip()
            and user_id.startswith(("U", "W"))
            and not isinstance(message.get("user_profile"), dict)
        }
    )
    if not user_ids:
        return messages

    profiles: dict[str, dict[str, str]] = {}
    for user_id in user_ids:
        try:
            payload = slack_client.get("users.info", params={"user": user_id})
        except SlackClientError as exc:
            LOGGER.warning("Could not resolve Slack sender names; keeping Slack user ids: %s", exc)
            return messages

        user = payload.get("user", {})
        if not isinstance(user, dict):
            continue
        profile = user.get("profile", {})
        if not isinstance(profile, dict):
            profile = {}
        profiles[user_id] = {
            "real_name": _first_text(user.get("real_name"), profile.get("real_name")),
            "display_name": _first_text(profile.get("display_name"), user.get("name")),
            "email": _first_text(profile.get("email")),
        }

    enriched: list[dict[str, Any]] = []
    for message in messages:
        user_id = message.get("user")
        if isinstance(user_id, str) and user_id in profiles:
            updated = dict(message)
            updated["user_profile"] = profiles[user_id]
            enriched.append(updated)
        else:
            enriched.append(message)
    return enriched


def extract_pdf_files(messages: list[dict[str, Any]]) -> list[SlackPdfFile]:
    pdf_files: list[SlackPdfFile] = []
    seen_file_ids: set[str] = set()

    for message in messages:
        message_ts = str(message.get("ts", ""))
        files = message.get("files", [])
        if not isinstance(files, list):
            continue

        for file_info in files:
            if not isinstance(file_info, dict) or not _is_pdf_file(file_info):
                continue

            file_id = str(file_info.get("id", "")).strip()
            if not file_id or file_id in seen_file_ids:
                continue

            download_url = _download_url(file_info)
            if not download_url:
                LOGGER.warning("Skipping PDF file %s because Slack did not provide a download URL", file_id)
                continue

            pdf_files.append(
                SlackPdfFile(
                    file_id=file_id,
                    name=_file_name(file_info, file_id),
                    url_private_download=download_url,
                    message_ts=message_ts,
                )
            )
            seen_file_ids.add(file_id)

    LOGGER.info("%s Slack PDF files discovered", len(pdf_files))
    return pdf_files


def extract_pdf_duplicate_sightings(messages: list[dict[str, Any]]) -> list[SlackPdfDuplicateSighting]:
    sightings: list[SlackPdfDuplicateSighting] = []
    first_by_file_id: dict[str, SlackPdfFile] = {}
    first_by_name: dict[str, SlackPdfFile] = {}
    seen_events: set[tuple[str, str, str]] = set()

    for message in sorted(messages, key=_message_sort_key):
        message_ts = str(message.get("ts", "")).strip()
        files = message.get("files", [])
        if not isinstance(files, list):
            continue

        for file_info in files:
            if not isinstance(file_info, dict) or not _is_pdf_file(file_info):
                continue

            file_id = str(file_info.get("id", "")).strip()
            if not file_id:
                continue

            name = _file_name(file_info, file_id)
            normalized_name = _normalize_file_name(name)
            first_file = first_by_file_id.get(file_id)
            match_reason = "same Slack file id"

            if first_file is None and normalized_name:
                first_file = first_by_name.get(normalized_name)
                match_reason = "same PDF file name"

            if first_file is not None:
                if message_ts and message_ts != first_file.message_ts:
                    event_key = (first_file.file_id, file_id, message_ts)
                    if event_key not in seen_events:
                        sightings.append(
                            SlackPdfDuplicateSighting(
                                file_id=file_id,
                                name=name,
                                first_message_ts=first_file.message_ts,
                                duplicate_message_ts=message_ts,
                                match_reason=match_reason,
                            )
                        )
                        seen_events.add(event_key)
                continue

            download_url = _download_url(file_info)
            if not download_url:
                continue

            pdf_file = SlackPdfFile(
                file_id=file_id,
                name=name,
                url_private_download=download_url,
                message_ts=message_ts,
            )
            first_by_file_id[file_id] = pdf_file
            if normalized_name:
                first_by_name.setdefault(normalized_name, pdf_file)

    LOGGER.info("%s duplicate Slack PDF sightings discovered", len(sightings))
    return sightings


def find_channel_by_name(channels: list[dict[str, Any]], channel_name: str) -> dict[str, Any] | None:
    normalized_target = normalize_channel_name(channel_name)
    for channel in channels:
        name = channel.get("name")
        if isinstance(name, str) and normalize_channel_name(name) == normalized_target:
            return channel
    return None


def channel_display_name(channel: dict[str, Any]) -> str:
    name = channel.get("name")
    if isinstance(name, str) and name.strip():
        return f"#{name.strip()}"
    return "#<unnamed-channel>"


def normalize_channel_name(channel_name: str) -> str:
    return channel_name.strip().lstrip("#").lower()


def channel_id(channel: dict[str, Any]) -> str | None:
    value = channel.get("id")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _is_pdf_file(file_info: dict[str, Any]) -> bool:
    mimetype = str(file_info.get("mimetype", "")).lower()
    filetype = str(file_info.get("filetype", "")).lower()
    name = str(file_info.get("name", "")).lower()
    title = str(file_info.get("title", "")).lower()
    return (
        mimetype == "application/pdf"
        or filetype == "pdf"
        or name.endswith(".pdf")
        or title.endswith(".pdf")
    )


def _download_url(file_info: dict[str, Any]) -> str | None:
    for key in ("url_private_download", "url_private"):
        value = file_info.get(key)
        if isinstance(value, str) and value.startswith("https://"):
            return value
    return None


def _file_name(file_info: dict[str, Any], file_id: str) -> str:
    for key in ("name", "title"):
        value = file_info.get(key)
        if isinstance(value, str) and value.strip():
            name = value.strip()
            return name if name.lower().endswith(".pdf") else f"{name}.pdf"
    return f"{file_id}.pdf"


def _normalize_file_name(name: str) -> str:
    return " ".join(name.strip().lower().split())


def _message_sort_key(message: dict[str, Any]) -> tuple[float, str]:
    message_ts = str(message.get("ts", "")).strip()
    try:
        return (float(message_ts), message_ts)
    except ValueError:
        return (0.0, message_ts)


def _first_text(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""
