from __future__ import annotations

from pathlib import Path

from src.file_service import download_slack_pdf, safe_filename
from src.slack_service import SlackPdfFile


class FakeSlackClient:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def download_file(self, url: str) -> bytes:
        self.urls.append(url)
        return b"%PDF-test"


def test_safe_filename_replaces_unsafe_characters() -> None:
    assert safe_filename("bad report / final?.pdf") == "bad_report_final_.pdf"
    assert safe_filename("...") == "download.pdf"


def test_download_slack_pdf_writes_pdf(tmp_path: Path) -> None:
    slack_client = FakeSlackClient()
    pdf_file = SlackPdfFile(
        file_id="F123",
        name="report.pdf",
        url_private_download="https://files.slack.com/report.pdf",
        message_ts="123.456",
    )

    result = download_slack_pdf(slack_client, pdf_file, tmp_path)  # type: ignore[arg-type]

    assert result.downloaded is True
    assert result.path == tmp_path / "F123_report.pdf"
    assert result.path.read_bytes() == b"%PDF-test"
    assert slack_client.urls == ["https://files.slack.com/report.pdf"]


def test_download_slack_pdf_skips_existing_file(tmp_path: Path) -> None:
    slack_client = FakeSlackClient()
    destination = tmp_path / "F123_report.pdf"
    destination.write_bytes(b"existing")
    pdf_file = SlackPdfFile(
        file_id="F123",
        name="report.pdf",
        url_private_download="https://files.slack.com/report.pdf",
        message_ts="123.456",
    )

    result = download_slack_pdf(slack_client, pdf_file, tmp_path)  # type: ignore[arg-type]

    assert result.downloaded is False
    assert destination.read_bytes() == b"existing"
    assert slack_client.urls == []
