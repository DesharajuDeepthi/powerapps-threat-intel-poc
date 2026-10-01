from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from src.slack_client import SlackClient
from src.slack_service import SlackPdfFile

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class DownloadResult:
    file_id: str
    name: str
    path: Path
    downloaded: bool


def download_slack_pdf(
    slack_client: SlackClient,
    pdf_file: SlackPdfFile,
    download_dir: Path,
) -> DownloadResult:
    download_dir.mkdir(parents=True, exist_ok=True)
    destination = download_dir / f"{pdf_file.file_id}_{safe_filename(pdf_file.name)}"

    if destination.exists():
        LOGGER.info("Skipping already downloaded Slack PDF: %s", destination.name)
        return DownloadResult(
            file_id=pdf_file.file_id,
            name=pdf_file.name,
            path=destination,
            downloaded=False,
        )

    content = slack_client.download_file(pdf_file.url_private_download)
    destination.write_bytes(content)
    LOGGER.info("Downloaded Slack PDF %s to %s", pdf_file.name, destination)

    return DownloadResult(
        file_id=pdf_file.file_id,
        name=pdf_file.name,
        path=destination,
        downloaded=True,
    )


def safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    cleaned = cleaned.strip("._")
    return cleaned or "download.pdf"
