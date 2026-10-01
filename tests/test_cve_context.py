from __future__ import annotations

from src.cve_context import extract_cve_contexts
from src.models import PdfPageText


def test_extract_cve_contexts_captures_surrounding_sentences_and_page() -> None:
    pages = [
        PdfPageText(
            page_number=2,
            text=(
                "Before sentence. Hive actors gained initial access to Microsoft Exchange "
                "by exploiting CVE-2021-34473. After sentence one. After sentence two."
            ),
        )
    ]

    contexts = extract_cve_contexts(pages)

    assert len(contexts) == 1
    assert contexts[0].cve == "CVE-2021-34473"
    assert contexts[0].page_number == 2
    assert "Before sentence" in contexts[0].context
    assert "After sentence one" in contexts[0].context
