from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from src.analysis_store import load_analysis, save_analysis
from src.comment_generator import generate_analyst_comment
from src.config import AppConfig
from src.cve_context import extract_cve_contexts
from src.indicator_extractor import extract_indicators
from src.models import (
    CVEAnalysis,
    CveContext,
    DocumentAnalysis,
    DocumentMetadata,
    IndicatorSet,
    PdfPageText,
)
from src.pdf_parser import extract_pdf_text
from src.semantic_analyzer import HIGH_INTENTS, SemanticAnalyzer
from src.technology_extractor import associate_technology

LOGGER = logging.getLogger(__name__)

RELEVANCE_RANK = {"HIGH": 3, "REVIEW": 2, "INFORMATIONAL": 1}
RANSOMWARE_PATTERN = re.compile(r"\b([A-Z][A-Za-z0-9_-]+(?:\s+[A-Z][A-Za-z0-9_-]+)?)\s+Ransomware\b")


def process_document(
    metadata: DocumentMetadata,
    file_path: str | Path,
    config: AppConfig,
    *,
    force: bool = False,
) -> DocumentAnalysis:
    path = Path(file_path)
    pdf_sha256 = _sha256_file(path)
    existing = load_analysis(config.analysis_results_dir, metadata.document_id)
    if (
        existing is not None
        and existing.pdf_sha256 == pdf_sha256
        and _has_evidence_provenance(existing)
        and not force
    ):
        LOGGER.info("Skipping unchanged document analysis: %s", metadata.document_name)
        return existing

    processed_at = _utc_now()
    analyzer = SemanticAnalyzer(
        high_threshold=config.semantic_high_threshold,
        review_threshold=config.semantic_review_threshold,
        model_name=config.embedding_model_name,
        enable_sentence_transformer=config.enable_sentence_transformer,
    )

    try:
        extraction = extract_pdf_text(path)
        indicators = extract_indicators(extraction.full_text)
        cve_contexts = extract_cve_contexts(extraction.pages)
        cve_contexts = _ensure_contexts_for_all_cves(indicators.cves, cve_contexts)
        cve_analyses = _analyze_cves(cve_contexts, analyzer)
        threat_name, threat_evidence, threat_evidence_page_number = _extract_threat_details(
            extraction.pages,
            metadata.document_name,
        )

        analysis = DocumentAnalysis(
            document_id=metadata.document_id,
            document_name=metadata.document_name,
            local_file_path=str(path),
            source=metadata.source,
            slack_channel_id=metadata.slack_channel_id,
            slack_message_id=metadata.slack_message_id,
            slack_message_timestamp=metadata.slack_message_timestamp,
            slack_file_id=metadata.slack_file_id,
            slack_file_url=metadata.slack_file_url,
            downloaded_at=metadata.downloaded_at,
            processed_at=processed_at,
            pdf_sha256=pdf_sha256,
            extraction_status=extraction.extraction_status,
            page_count=extraction.page_count,
            character_count=extraction.character_count,
            threat_name=threat_name,
            indicators=indicators,
            cves=cve_analyses,
            threat_evidence=threat_evidence,
            threat_evidence_page_number=threat_evidence_page_number,
        )
        save_analysis(analysis, config.analysis_results_dir)
        _log_analysis_counts(analysis)
        return analysis
    except Exception as exc:
        LOGGER.exception("Document analysis failed for %s", metadata.document_name)
        analysis = DocumentAnalysis(
            document_id=metadata.document_id,
            document_name=metadata.document_name,
            local_file_path=str(path),
            source=metadata.source,
            slack_channel_id=metadata.slack_channel_id,
            slack_message_id=metadata.slack_message_id,
            slack_message_timestamp=metadata.slack_message_timestamp,
            slack_file_id=metadata.slack_file_id,
            slack_file_url=metadata.slack_file_url,
            downloaded_at=metadata.downloaded_at,
            processed_at=processed_at,
            pdf_sha256=pdf_sha256,
            extraction_status="ERROR",
            page_count=0,
            character_count=0,
            threat_name=None,
            indicators=IndicatorSet(),
            cves=[],
            processing_error=str(exc),
        )
        save_analysis(analysis, config.analysis_results_dir)
        return analysis


def _analyze_cves(contexts: list[CveContext], analyzer: SemanticAnalyzer) -> list[CVEAnalysis]:
    best_by_cve: dict[str, CVEAnalysis] = {}

    for context in contexts:
        semantic = analyzer.analyze(context.context)
        technology = associate_technology(context.context)
        comment = generate_analyst_comment(
            cve=context.cve,
            technology=technology.technology,
            semantic_category=semantic.semantic_category,
            relevance=semantic.document_relevance,
        )
        analysis = CVEAnalysis(
            cve=context.cve,
            technology=technology.technology,
            vendor=technology.vendor,
            page_number=context.page_number,
            evidence_text=context.context,
            semantic_scores=semantic.semantic_scores,
            semantic_category=semantic.semantic_category,
            document_relevance=semantic.document_relevance,
            analyst_comment=comment,
            technology_evidence=technology.association_evidence,
        )

        existing = best_by_cve.get(context.cve)
        if existing is None or _score_rank(analysis) > _score_rank(existing):
            best_by_cve[context.cve] = analysis

    return [best_by_cve[cve] for cve in sorted(best_by_cve)]


def _score_rank(analysis: CVEAnalysis) -> tuple[int, float]:
    high_score = max(analysis.semantic_scores.get(label, 0.0) for label in HIGH_INTENTS)
    return (RELEVANCE_RANK.get(analysis.document_relevance, 0), high_score)


def _ensure_contexts_for_all_cves(cves: list[str], contexts: list[CveContext]) -> list[CveContext]:
    existing = {context.cve for context in contexts}
    missing = [cve for cve in cves if cve not in existing]
    return [*contexts, *[CveContext(cve=cve, page_number=None, context=cve) for cve in missing]]


def _extract_threat_details(
    pages: list[PdfPageText],
    document_name: str,
) -> tuple[str | None, str, int | None]:
    for page in pages:
        match = RANSOMWARE_PATTERN.search(page.text)
        if match:
            return (
                f"{match.group(1).strip()} Ransomware",
                _evidence_sentence(page.text, match.group(0)),
                page.page_number,
            )

    document_match = RANSOMWARE_PATTERN.search(document_name.replace("_", " "))
    if document_match:
        return (
            f"{document_match.group(1).strip()} Ransomware",
            f"Detected from document filename: {document_name}",
            None,
        )
    return None, "", None


def _evidence_sentence(text: str, matched_text: str) -> str:
    normalized = re.sub(r"\s+", " ", text).strip()
    sentences = re.split(r"(?<=[.!?])\s+", normalized)
    for sentence in sentences:
        if matched_text.lower() in sentence.lower():
            return sentence.strip()
    return normalized


def _has_evidence_provenance(analysis: DocumentAnalysis) -> bool:
    if analysis.threat_name and not analysis.threat_evidence:
        return False
    return all(bool(cve.technology_evidence) for cve in analysis.cves)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_analysis_counts(analysis: DocumentAnalysis) -> None:
    high = sum(1 for cve in analysis.cves if cve.document_relevance == "HIGH")
    review = sum(1 for cve in analysis.cves if cve.document_relevance == "REVIEW")
    informational = sum(1 for cve in analysis.cves if cve.document_relevance == "INFORMATIONAL")
    LOGGER.info("%s CVEs detected", len(analysis.cves))
    LOGGER.info("%s high-relevance CVEs", high)
    LOGGER.info("%s review CVEs", review)
    LOGGER.info("%s informational CVEs", informational)
    LOGGER.info("%s IPs detected", len(analysis.indicators.ipv4))
