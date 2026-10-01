from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from src.config import load_config
from src.repository_models import AnalystFeedbackRecord
from src.sharepoint_repository import SharePointThreatIntelRepository
from tests.test_repository_payloads import sample_analysis


class FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = str(self._payload)

    def json(self) -> dict[str, Any]:
        return self._payload


class FakeSession:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        self.get_calls: list[dict[str, Any]] = []
        self.put_calls: list[dict[str, Any]] = []
        self.post_calls: list[dict[str, Any]] = []
        self.patch_calls: list[dict[str, Any]] = []
        self.get_payload: dict[str, Any] = {"value": []}

    def get(self, url: str, *, params: dict[str, Any], timeout: int) -> FakeResponse:
        self.get_calls.append({"url": url, "params": params, "timeout": timeout})
        return FakeResponse(200, self.get_payload)

    def put(self, url: str, *, data: bytes, timeout: int) -> FakeResponse:
        self.put_calls.append({"url": url, "data": data, "timeout": timeout})
        return FakeResponse(200, {"webUrl": "https://sharepoint/doc.pdf"})

    def post(self, url: str, *, json: dict[str, Any], timeout: int) -> FakeResponse:
        self.post_calls.append({"url": url, "json": json, "timeout": timeout})
        return FakeResponse(201, {"id": "1"})

    def patch(self, url: str, *, json: dict[str, Any], timeout: int) -> FakeResponse:
        self.patch_calls.append({"url": url, "json": json, "timeout": timeout})
        return FakeResponse(200, {"id": "1"})

    def close(self) -> None:
        pass


def test_sharepoint_repository_uses_graph_payloads(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pdf_path = tmp_path / "advisory.pdf"
    pdf_path.write_bytes(b"%PDF")
    analysis = sample_analysis()
    analysis = analysis.__class__(**{**analysis.__dict__, "local_file_path": str(pdf_path)})

    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-valid-token")
    monkeypatch.setenv("SLACK_CHANNEL_NAME", "feedly-threat-intel")
    monkeypatch.setenv("STORAGE_BACKEND", "sharepoint")
    monkeypatch.setenv("MS_TENANT_ID", "tenant")
    monkeypatch.setenv("MS_CLIENT_ID", "client")
    monkeypatch.setenv("MS_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SHAREPOINT_SITE_ID", "site")
    monkeypatch.setenv("SHAREPOINT_DOCUMENT_LIBRARY_ID", "drive")
    monkeypatch.setenv("SP_DOCUMENTS_LIST_ID", "documents")
    monkeypatch.setenv("SP_FINDINGS_LIST_ID", "findings")
    monkeypatch.setenv("SP_INDICATORS_LIST_ID", "indicators")
    monkeypatch.setenv("SP_MEMORY_LIST_ID", "memory")
    monkeypatch.setenv("SP_FEEDBACK_LIST_ID", "feedback")
    monkeypatch.setenv("DOWNLOAD_DIR", str(tmp_path / "downloads"))
    monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "output" / "findings.xlsx"))
    monkeypatch.setenv("PROCESSED_FILES_PATH", str(tmp_path / "data" / "processed_files.json"))
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("ANALYSIS_RESULTS_DIR", str(tmp_path / "data" / "results"))
    config = load_config(env_file=None)
    monkeypatch.setattr(SharePointThreatIntelRepository, "_access_token", lambda self: "token")
    session = FakeSession()
    repository = SharePointThreatIntelRepository(config, session=session)  # type: ignore[arg-type]

    result = repository.publish_analysis(analysis)

    assert result.backend == "sharepoint"
    assert session.put_calls[0]["url"].endswith("/root:/doc-1_advisory.pdf:/content")
    assert len(session.post_calls) >= 4
    assert session.post_calls[0]["json"]["fields"]["DocumentID"] == "doc-1"
    assert any(call["json"]["fields"].get("MemoryKey") == "CVE-2021-34473" for call in session.post_calls)
    assert session.headers["Authorization"] == "Bearer token"
    assert session.headers["Prefer"] == "HonorNonIndexedQueriesWarningMayFailRandomly"


def test_sharepoint_repository_records_feedback_and_updates_memory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-valid-token")
    monkeypatch.setenv("SLACK_CHANNEL_NAME", "feedly-threat-intel")
    monkeypatch.setenv("STORAGE_BACKEND", "sharepoint")
    monkeypatch.setenv("MS_TENANT_ID", "tenant")
    monkeypatch.setenv("MS_CLIENT_ID", "client")
    monkeypatch.setenv("MS_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SHAREPOINT_SITE_ID", "site")
    monkeypatch.setenv("SHAREPOINT_DOCUMENT_LIBRARY_ID", "drive")
    monkeypatch.setenv("SP_DOCUMENTS_LIST_ID", "documents")
    monkeypatch.setenv("SP_FINDINGS_LIST_ID", "findings")
    monkeypatch.setenv("SP_INDICATORS_LIST_ID", "indicators")
    monkeypatch.setenv("SP_MEMORY_LIST_ID", "memory")
    monkeypatch.setenv("SP_FEEDBACK_LIST_ID", "feedback")
    monkeypatch.setenv("DOWNLOAD_DIR", str(tmp_path / "downloads"))
    monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "output" / "findings.xlsx"))
    monkeypatch.setenv("PROCESSED_FILES_PATH", str(tmp_path / "data" / "processed_files.json"))
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("ANALYSIS_RESULTS_DIR", str(tmp_path / "data" / "results"))
    config = load_config(env_file=None)
    monkeypatch.setattr(SharePointThreatIntelRepository, "_access_token", lambda self: "token")
    session = FakeSession()
    session.get_payload = {
        "value": [
            {
                "id": "memory-item-1",
                "fields": {
                    "MemoryID": "CVE-2021-34473",
                    "MemoryType": "CVE",
                    "MemoryKey": "CVE-2021-34473",
                    "CVE": "CVE-2021-34473",
                    "FirstSeenDate": "2026-09-01T00:00:00+00:00",
                    "LastSeenDate": "2026-09-23T00:00:00+00:00",
                    "TimesSeen": 2,
                    "LastDocumentID": "doc-1",
                },
            }
        ]
    }
    repository = SharePointThreatIntelRepository(config, session=session)  # type: ignore[arg-type]

    repository.record_feedback(
        AnalystFeedbackRecord(
            feedback_id="fb-1",
            finding_id="finding-1",
            document_id="doc-1",
            cve="CVE-2021-34473",
            analyst_email="analyst@example.com",
            analyst_name="Analyst",
            previous_status="Review Required",
            new_status="Action Required",
            system_relevance="HIGH",
            analyst_relevance="HIGH",
            comment="Exchange team is remediating.",
            decision="Action Required",
            created_date="2026-09-23T02:00:00+00:00",
        )
    )

    assert session.post_calls[0]["url"].endswith("/lists/feedback/items")
    assert session.post_calls[0]["json"]["fields"]["FeedbackID"] == "fb-1"
    assert session.patch_calls[0]["url"].endswith("/lists/memory/items/memory-item-1/fields")
    assert session.patch_calls[0]["json"]["LastAnalystDecision"] == "Action Required"
