from __future__ import annotations

from src.comment_generator import generate_analyst_comment
from src.semantic_analyzer import SemanticAnalyzer
from src.technology_extractor import associate_technology


def test_semantic_analyzer_classifies_initial_access_with_keyword_fallback() -> None:
    analyzer = SemanticAnalyzer(
        high_threshold=0.55,
        review_threshold=0.35,
        model_name="unused",
        enable_sentence_transformer=False,
    )

    result = analyzer.analyze(
        "Hive actors gained initial access by exploiting CVE-2021-34473 against Microsoft Exchange."
    )

    assert result.semantic_category in {"initial_access", "active_exploitation"}
    assert result.document_relevance == "HIGH"
    assert "initial_access" in result.semantic_scores


def test_technology_association_uses_context_evidence() -> None:
    association = associate_technology(
        "Hive actors exploited CVE-2021-34473 against Microsoft Exchange Server."
    )

    assert association.technology == "Microsoft Exchange Server"
    assert association.vendor == "Microsoft"
    assert "Microsoft Exchange" in association.association_evidence


def test_analyst_comment_is_rule_based() -> None:
    comment = generate_analyst_comment(
        cve="CVE-2021-34473",
        technology="Microsoft Exchange Server",
        semantic_category="initial_access",
        relevance="HIGH",
    )

    assert "CVE-2021-34473" in comment
    assert "Microsoft Exchange Server" in comment
    assert "Document relevance is HIGH" in comment
