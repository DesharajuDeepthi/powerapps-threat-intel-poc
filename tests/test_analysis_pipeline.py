from __future__ import annotations

from pathlib import Path

import pymupdf as fitz
import pytest

from src.analysis_pipeline import process_document
from src.config import load_config
from src.models import DocumentMetadata


def test_process_document_persists_analysis_and_skips_duplicate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pdf_path = tmp_path / "hive.pdf"
    document = fitz.open()
    page = document.new_page()
    page.insert_text(
        (72, 72),
        "Hive Ransomware actors gained initial access to Microsoft Exchange Server by exploiting CVE-2021-34473.",
    )
    document.save(pdf_path)
    document.close()

    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-valid-token")
    monkeypatch.setenv("SLACK_CHANNEL_NAME", "feedly-threat-intel")
    monkeypatch.setenv("DOWNLOAD_DIR", str(tmp_path / "downloads"))
    monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "output" / "findings.xlsx"))
    monkeypatch.setenv("PROCESSED_FILES_PATH", str(tmp_path / "data" / "processed_files.json"))
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("ANALYSIS_RESULTS_DIR", str(tmp_path / "data" / "results"))
    monkeypatch.setenv("ENABLE_SENTENCE_TRANSFORMER", "false")
    monkeypatch.setenv("SEMANTIC_HIGH_THRESHOLD", "0.55")
    monkeypatch.setenv("SEMANTIC_REVIEW_THRESHOLD", "0.35")
    config = load_config(env_file=None)

    metadata = DocumentMetadata(
        document_id="test-doc",
        document_name="hive.pdf",
        local_file_path=str(pdf_path),
        source="test",
    )

    first = process_document(metadata, pdf_path, config)
    second = process_document(metadata, pdf_path, config)

    assert first.document_id == "test-doc"
    assert second.pdf_sha256 == first.pdf_sha256
    assert (tmp_path / "data" / "results" / "test-doc.json").exists()
    assert first.cves[0].cve == "CVE-2021-34473"
    assert first.cves[0].technology == "Microsoft Exchange Server"
    assert "Microsoft Exchange Server" in first.cves[0].technology_evidence
    assert first.threat_name == "Hive Ransomware"
    assert "Hive Ransomware" in first.threat_evidence
    assert first.threat_evidence_page_number == 1
