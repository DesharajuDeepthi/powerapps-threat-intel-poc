from __future__ import annotations

from src.slack_service import (
    channel_id,
    enrich_message_sender_details,
    extract_pdf_duplicate_sightings,
    extract_pdf_files,
    find_channel_by_name,
    get_channel_messages,
    get_channels,
    normalize_channel_name,
)
from src.slack_client import SlackClientError


class FakeSlackClient:
    def __init__(self) -> None:
        self.method: str | None = None
        self.collection_key: str | None = None
        self.params: dict[str, object] | None = None

    def get_cursor_paginated(
        self, method: str, *, collection_key: str, params: dict[str, object] | None = None
    ) -> list[dict[str, object]]:
        self.method = method
        self.collection_key = collection_key
        self.params = params
        if collection_key == "messages":
            return [{"ts": "123.456", "files": []}]
        return [{"name": "feedly-threat-intel", "id": "C123"}]


class FakeUserInfoSlackClient:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def get(self, method: str, *, params: dict[str, object] | None = None) -> dict[str, object]:
        if self.fail:
            raise SlackClientError("Slack API returned error: missing_scope")
        assert method == "users.info"
        assert params == {"user": "U123"}
        return {
            "ok": True,
            "user": {
                "id": "U123",
                "real_name": "On Call Analyst",
                "profile": {
                    "display_name": "oncall",
                    "email": "analyst@example.com",
                },
            },
        }


def test_get_channels_uses_conversations_list() -> None:
    slack_client = FakeSlackClient()

    channels = get_channels(slack_client)  # type: ignore[arg-type]

    assert slack_client.method == "conversations.list"
    assert slack_client.collection_key == "channels"
    assert channels == [{"name": "feedly-threat-intel", "id": "C123"}]


def test_find_channel_by_name_accepts_hash_prefix_and_case() -> None:
    channels = [{"name": "feedly-threat-intel", "id": "C123"}]

    channel = find_channel_by_name(channels, "#Feedly-Threat-Intel")

    assert channel == {"name": "feedly-threat-intel", "id": "C123"}


def test_normalize_channel_name_strips_hash() -> None:
    assert normalize_channel_name(" #Feedly-Threat-Intel ") == "feedly-threat-intel"


def test_get_channel_messages_uses_conversations_history() -> None:
    slack_client = FakeSlackClient()

    messages = get_channel_messages(slack_client, "C123")  # type: ignore[arg-type]

    assert slack_client.method == "conversations.history"
    assert slack_client.collection_key == "messages"
    assert slack_client.params is not None
    assert slack_client.params["channel"] == "C123"
    assert messages == [{"ts": "123.456", "files": []}]


def test_enrich_message_sender_details_adds_user_profile() -> None:
    messages = [{"ts": "123.456", "user": "U123", "text": "Document: report.pdf"}]

    enriched = enrich_message_sender_details(FakeUserInfoSlackClient(), messages)  # type: ignore[arg-type]

    assert enriched[0]["user_profile"] == {
        "real_name": "On Call Analyst",
        "display_name": "oncall",
        "email": "analyst@example.com",
    }


def test_enrich_message_sender_details_falls_back_when_scope_missing() -> None:
    messages = [{"ts": "123.456", "user": "U123", "text": "Document: report.pdf"}]

    enriched = enrich_message_sender_details(FakeUserInfoSlackClient(fail=True), messages)  # type: ignore[arg-type]

    assert enriched == messages


def test_extract_pdf_files_deduplicates_and_uses_download_url() -> None:
    messages = [
        {
            "ts": "123.456",
            "files": [
                {
                    "id": "F123",
                    "name": "report.pdf",
                    "mimetype": "application/pdf",
                    "url_private_download": "https://files.slack.com/report.pdf",
                },
                {
                    "id": "F123",
                    "name": "report.pdf",
                    "mimetype": "application/pdf",
                    "url_private_download": "https://files.slack.com/report.pdf",
                },
                {
                    "id": "F456",
                    "name": "notes.txt",
                    "mimetype": "text/plain",
                    "url_private_download": "https://files.slack.com/notes.txt",
                },
            ],
        }
    ]

    pdf_files = extract_pdf_files(messages)

    assert len(pdf_files) == 1
    assert pdf_files[0].file_id == "F123"
    assert pdf_files[0].name == "report.pdf"
    assert pdf_files[0].url_private_download == "https://files.slack.com/report.pdf"
    assert pdf_files[0].message_ts == "123.456"


def test_extract_pdf_duplicate_sightings_finds_second_slack_message_for_same_pdf() -> None:
    messages = [
        {
            "ts": "200.000",
            "files": [
                {
                    "id": "F123",
                    "name": "report.pdf",
                    "mimetype": "application/pdf",
                    "url_private_download": "https://files.slack.com/report.pdf",
                }
            ],
        },
        {
            "ts": "100.000",
            "files": [
                {
                    "id": "F123",
                    "name": "report.pdf",
                    "mimetype": "application/pdf",
                    "url_private_download": "https://files.slack.com/report.pdf",
                }
            ],
        },
    ]

    sightings = extract_pdf_duplicate_sightings(messages)

    assert len(sightings) == 1
    assert sightings[0].file_id == "F123"
    assert sightings[0].first_message_ts == "100.000"
    assert sightings[0].duplicate_message_ts == "200.000"
    assert sightings[0].match_reason == "same Slack file id"


def test_extract_pdf_duplicate_sightings_finds_second_upload_with_same_pdf_name() -> None:
    messages = [
        {
            "ts": "100.000",
            "files": [
                {
                    "id": "F123",
                    "name": "report.pdf",
                    "mimetype": "application/pdf",
                    "url_private_download": "https://files.slack.com/report.pdf",
                }
            ],
        },
        {
            "ts": "200.000",
            "files": [
                {
                    "id": "F456",
                    "name": "report.pdf",
                    "mimetype": "application/pdf",
                    "url_private_download": "https://files.slack.com/report-copy.pdf",
                }
            ],
        },
    ]

    sightings = extract_pdf_duplicate_sightings(messages)

    assert len(sightings) == 1
    assert sightings[0].file_id == "F456"
    assert sightings[0].first_message_ts == "100.000"
    assert sightings[0].duplicate_message_ts == "200.000"
    assert sightings[0].match_reason == "same PDF file name"


def test_channel_id_returns_string_id() -> None:
    assert channel_id({"id": "C123"}) == "C123"
    assert channel_id({}) is None
