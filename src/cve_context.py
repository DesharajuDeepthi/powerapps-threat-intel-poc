from __future__ import annotations

import re

from src.indicator_extractor import CVE_PATTERN
from src.models import CveContext, PdfPageText

SENTENCE_SPLIT_PATTERN = re.compile(r"(?<=[.!?])\s+")


def extract_cve_contexts(pages: list[PdfPageText], max_contexts_per_cve: int = 3) -> list[CveContext]:
    contexts: list[CveContext] = []
    seen: set[tuple[str, str]] = set()
    per_cve_count: dict[str, int] = {}

    for page in pages:
        sentences = _split_sentences(page.text)
        for index, sentence in enumerate(sentences):
            cves = {match.group(0).upper() for match in CVE_PATTERN.finditer(sentence)}
            for cve in cves:
                if per_cve_count.get(cve, 0) >= max_contexts_per_cve:
                    continue

                window = _context_window(sentences, index)
                normalized_window = re.sub(r"\s+", " ", window).strip()
                key = (cve, normalized_window.lower())
                if key in seen:
                    continue

                contexts.append(
                    CveContext(
                        cve=cve,
                        page_number=page.page_number,
                        context=normalized_window,
                    )
                )
                seen.add(key)
                per_cve_count[cve] = per_cve_count.get(cve, 0) + 1

    return contexts


def _split_sentences(text: str) -> list[str]:
    compact = re.sub(r"\s+", " ", text).strip()
    if not compact:
        return []
    return [sentence.strip() for sentence in SENTENCE_SPLIT_PATTERN.split(compact) if sentence.strip()]


def _context_window(sentences: list[str], index: int) -> str:
    start = max(index - 1, 0)
    end = min(index + 3, len(sentences))
    return " ".join(sentences[start:end])
