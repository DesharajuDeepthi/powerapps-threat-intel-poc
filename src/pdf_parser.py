from __future__ import annotations

import logging
from pathlib import Path

import pymupdf as fitz

from src.models import PdfExtractionResult, PdfPageText

LOGGER = logging.getLogger(__name__)

STATUS_SUCCESS = "SUCCESS"
STATUS_NO_TEXT = "NO_EXTRACTABLE_TEXT"
STATUS_ENCRYPTED = "ENCRYPTED"
STATUS_ERROR = "ERROR"


def extract_pdf_text(file_path: str | Path) -> PdfExtractionResult:
    path = Path(file_path)
    LOGGER.info("PDF processing started: %s", path.name)

    try:
        document = fitz.open(path)
    except Exception as exc:
        LOGGER.warning("Could not open PDF %s: %s", path, exc)
        return PdfExtractionResult(
            pages=[],
            page_count=0,
            character_count=0,
            extraction_status=STATUS_ERROR,
            error=str(exc),
        )

    try:
        if document.needs_pass:
            return PdfExtractionResult(
                pages=[],
                page_count=document.page_count,
                character_count=0,
                extraction_status=STATUS_ENCRYPTED,
                error="PDF is encrypted or password protected.",
            )

        pages: list[PdfPageText] = []
        for index, page in enumerate(document, start=1):
            text = page.get_text("text") or ""
            pages.append(PdfPageText(page_number=index, text=text))

        character_count = sum(len(page.text) for page in pages)
        status = STATUS_SUCCESS if character_count else STATUS_NO_TEXT
        LOGGER.info(
            "Text extraction completed for %s: %s pages, %s characters, status=%s",
            path.name,
            len(pages),
            character_count,
            status,
        )
        return PdfExtractionResult(
            pages=pages,
            page_count=document.page_count,
            character_count=character_count,
            extraction_status=status,
        )
    finally:
        document.close()
