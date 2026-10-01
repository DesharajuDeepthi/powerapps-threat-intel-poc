from __future__ import annotations

import logging
import time
from typing import Any

import requests

LOGGER = logging.getLogger(__name__)

SLACK_BASE_URL = "https://slack.com/api"
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_RETRIES = 3


class SlackClientError(RuntimeError):
    """Raised when Slack API calls fail."""


class SlackClient:
    def __init__(
        self,
        bot_token: str,
        *,
        base_url: str = SLACK_BASE_URL,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        session: requests.Session | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._session = session or requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {bot_token}",
                "Accept": "application/json",
            }
        )

    def get(self, method: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self._method_url(method)
        response = self._request_with_retries(url, params=params)
        payload = _response_json(response)

        if payload.get("ok") is not True:
            raise SlackClientError(_format_slack_error(payload))

        return payload

    def get_cursor_paginated(
        self,
        method: str,
        *,
        collection_key: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor = ""

        while True:
            request_params = dict(params or {})
            if cursor:
                request_params["cursor"] = cursor

            payload = self.get(method, params=request_params)
            values = payload.get(collection_key, [])
            if not isinstance(values, list):
                raise SlackClientError(f"Slack response did not contain list field {collection_key}.")

            items.extend(item for item in values if isinstance(item, dict))

            metadata = payload.get("response_metadata", {})
            cursor = ""
            if isinstance(metadata, dict):
                cursor_value = metadata.get("next_cursor", "")
                if isinstance(cursor_value, str):
                    cursor = cursor_value

            if not cursor:
                return items

    def download_file(self, url: str) -> bytes:
        response = self._request_with_retries(url)
        return response.content

    def _request_with_retries(
        self, url: str, *, params: dict[str, Any] | None = None
    ) -> requests.Response:
        for attempt in range(self._max_retries + 1):
            try:
                response = self._session.get(url, params=params, timeout=self._timeout_seconds)
            except requests.RequestException as exc:
                if attempt >= self._max_retries:
                    raise SlackClientError(f"Slack API request failed: {exc}") from exc
                LOGGER.warning("Slack API request failed; retrying")
                time.sleep(_retry_backoff_seconds(attempt))
                continue

            if response.status_code == 429 and attempt < self._max_retries:
                wait_seconds = _retry_after_seconds(response.headers.get("Retry-After"), attempt)
                LOGGER.warning("Slack API returned 429 Too Many Requests; retrying")
                time.sleep(wait_seconds)
                continue

            if response.status_code >= 400:
                raise SlackClientError(_format_http_error(response))

            return response

        raise SlackClientError("Slack API request failed after retries.")

    def _method_url(self, method: str) -> str:
        return f"{self._base_url}/{method.lstrip('/')}"


def _response_json(response: requests.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:
        raise SlackClientError("Slack API returned invalid JSON.") from exc

    if not isinstance(payload, dict):
        raise SlackClientError("Slack API returned an unexpected JSON payload.")
    return payload


def _format_slack_error(payload: dict[str, Any]) -> str:
    error = payload.get("error", "unknown_error")
    needed = payload.get("needed")
    provided = payload.get("provided")
    parts = [f"Slack API returned error: {error}"]

    if needed:
        parts.append(f"needed={needed}")
    if provided:
        parts.append(f"provided={provided}")

    return " | ".join(str(part) for part in parts)


def _format_http_error(response: requests.Response) -> str:
    detail = response.text[:300].strip()
    status = f"Slack API returned HTTP {response.status_code}"
    return f"{status}: {detail}" if detail else status


def _retry_after_seconds(header_value: str | None, attempt: int) -> float:
    if header_value:
        try:
            return max(float(header_value), 0)
        except ValueError:
            pass
    return _retry_backoff_seconds(attempt)


def _retry_backoff_seconds(attempt: int) -> float:
    return min(2**attempt, 10)
