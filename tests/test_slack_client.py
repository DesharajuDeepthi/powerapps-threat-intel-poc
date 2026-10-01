from __future__ import annotations

from typing import Any

import pytest
import requests

from src.slack_client import SlackClient, SlackClientError


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        payload: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
        text: str = "",
        content: bytes = b"",
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = text
        self.content = content

    def json(self) -> dict[str, Any]:
        if self._payload is None:
            raise ValueError("invalid json")
        return self._payload


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.headers: dict[str, str] = {}
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    def get(
        self, url: str, *, params: dict[str, Any] | None = None, timeout: int | None = None
    ) -> FakeResponse:
        self.calls.append({"url": url, "params": params, "timeout": timeout})
        return self.responses.pop(0)


def test_get_cursor_paginated_follows_next_cursor() -> None:
    session = FakeSession(
        [
            FakeResponse(
                200,
                {
                    "ok": True,
                    "channels": [{"name": "feedly-threat-intel"}],
                    "response_metadata": {"next_cursor": "next-page"},
                },
            ),
            FakeResponse(200, {"ok": True, "channels": [{"name": "security"}]}),
        ]
    )
    client = SlackClient("xoxb-secret-token", session=session)  # type: ignore[arg-type]

    channels = client.get_cursor_paginated("conversations.list", collection_key="channels")

    assert channels == [{"name": "feedly-threat-intel"}, {"name": "security"}]
    assert session.calls[0]["url"] == "https://slack.com/api/conversations.list"
    assert session.calls[1]["params"]["cursor"] == "next-page"
    assert session.headers["Authorization"] == "Bearer xoxb-secret-token"


def test_slack_error_raises_sanitized_message() -> None:
    session = FakeSession(
        [
            FakeResponse(
                200,
                {
                    "ok": False,
                    "error": "missing_scope",
                    "needed": "channels:read",
                    "provided": "files:read",
                },
            )
        ]
    )
    client = SlackClient("xoxb-secret-token", session=session)  # type: ignore[arg-type]

    with pytest.raises(SlackClientError) as exc_info:
        client.get("conversations.list")

    message = str(exc_info.value)
    assert "missing_scope" in message
    assert "channels:read" in message
    assert "xoxb-secret-token" not in message
    assert "Authorization" not in message


def test_429_retry_after_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    session = FakeSession(
        [
            FakeResponse(429, {"ok": False, "error": "ratelimited"}, headers={"Retry-After": "0"}),
            FakeResponse(200, {"ok": True}),
        ]
    )
    client = SlackClient("xoxb-secret-token", session=session)  # type: ignore[arg-type]
    monkeypatch.setattr("src.slack_client.time.sleep", sleeps.append)

    payload = client.get("auth.test")

    assert payload == {"ok": True}
    assert len(session.calls) == 2
    assert sleeps == [0.0]


def test_network_error_is_wrapped_without_token() -> None:
    class FailingSession(FakeSession):
        def get(
            self, url: str, *, params: dict[str, Any] | None = None, timeout: int | None = None
        ) -> FakeResponse:
            raise requests.Timeout("timed out")

    client = SlackClient("xoxb-secret-token", session=FailingSession([]), max_retries=0)  # type: ignore[arg-type]

    with pytest.raises(SlackClientError) as exc_info:
        client.get("auth.test")

    assert "timed out" in str(exc_info.value)
    assert "xoxb-secret-token" not in str(exc_info.value)


def test_download_file_returns_bytes() -> None:
    session = FakeSession([FakeResponse(200, content=b"%PDF-test")])
    client = SlackClient("xoxb-secret-token", session=session)  # type: ignore[arg-type]

    content = client.download_file("https://files.slack.com/files-pri/example.pdf")

    assert content == b"%PDF-test"
    assert session.calls[0]["url"] == "https://files.slack.com/files-pri/example.pdf"
