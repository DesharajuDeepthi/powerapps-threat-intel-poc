from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.models import CVEAnalysis, DocumentAnalysis
from src.repository_models import AnalystFeedbackRecord, MemoryRecord, SimilarDocumentRecord

RELEVANCE_RANK = {"INFORMATIONAL": 1, "REVIEW": 2, "HIGH": 3}


def document_payload(analysis: DocumentAnalysis, pdf_url: str | None = None) -> dict[str, Any]:
    high_count = sum(1 for cve in analysis.cves if cve.document_relevance == "HIGH")
    review_count = sum(1 for cve in analysis.cves if cve.document_relevance == "REVIEW")
    informational_count = sum(1 for cve in analysis.cves if cve.document_relevance == "INFORMATIONAL")
    return {
        "DocumentID": analysis.document_id,
        "DocumentName": analysis.document_name,
        "SlackFileID": analysis.slack_file_id or "",
        "SlackMessageID": analysis.slack_message_id or "",
        "SlackMessageDate": _slack_ts_to_iso(analysis.slack_message_timestamp),
        "ThreatName": analysis.threat_name or "",
        "ThreatEvidence": analysis.threat_evidence,
        "ThreatEvidencePageNumber": analysis.threat_evidence_page_number or "",
        "Source": analysis.source,
        "ReceivedDate": analysis.downloaded_at or "",
        "ProcessedDate": analysis.processed_at,
        "ProcessingStatus": analysis.extraction_status,
        "DocumentRelevance": highest_relevance(analysis),
        "HighFindingCount": high_count,
        "ReviewFindingCount": review_count,
        "InformationalFindingCount": informational_count,
        "CVECount": len(analysis.cves),
        "IPCount": len(analysis.indicators.ipv4),
        "DomainCount": len(analysis.indicators.domains),
        "HashCount": len(analysis.indicators.sha256) + len(analysis.indicators.sha1) + len(analysis.indicators.md5),
        "PDFUrl": pdf_url or "",
        "LocalFileName": Path(analysis.local_file_path).name,
        "FileHash": analysis.pdf_sha256,
        "CreatedByPipeline": True,
    }


def finding_payload(analysis: DocumentAnalysis, cve: CVEAnalysis) -> dict[str, Any]:
    return {
        "FindingID": finding_id(analysis.document_id, cve.cve),
        "DocumentID": analysis.document_id,
        "CVE": cve.cve,
        "Technology": cve.technology,
        "Vendor": cve.vendor,
        "TechnologyEvidence": cve.technology_evidence,
        "PageNumber": cve.page_number or "",
        "SemanticCategory": cve.semantic_category,
        "DocumentRelevance": cve.document_relevance,
        "ActiveExploitationScore": cve.semantic_scores.get("active_exploitation", 0.0),
        "InitialAccessScore": cve.semantic_scores.get("initial_access", 0.0),
        "RemoteCodeExecutionScore": cve.semantic_scores.get("remote_code_execution", 0.0),
        "PrivilegeEscalationScore": cve.semantic_scores.get("privilege_escalation", 0.0),
        "AuthenticationBypassScore": cve.semantic_scores.get("authentication_bypass", 0.0),
        "BackgroundReferenceScore": cve.semantic_scores.get("background_reference", 0.0),
        "EvidenceText": cve.evidence_text,
        "SuggestedAnalystComment": cve.analyst_comment,
        "Status": _default_status(cve.document_relevance),
        "AssignedTo": "",
        "CreatedDate": analysis.processed_at,
        "UpdatedDate": analysis.processed_at,
    }


def indicator_payloads(analysis: DocumentAnalysis) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for indicator_type, values in [
        ("IP", analysis.indicators.ipv4),
        ("Domain", analysis.indicators.domains),
        ("URL", analysis.indicators.urls),
        ("SHA256", analysis.indicators.sha256),
        ("SHA1", analysis.indicators.sha1),
        ("MD5", analysis.indicators.md5),
        ("MITRE", analysis.indicators.mitre_techniques),
        ("ContainerImage", analysis.indicators.container_indicators),
    ]:
        for value in values:
            rows.append(
                {
                    "IndicatorID": _stable_id(analysis.document_id, indicator_type, value),
                    "DocumentID": analysis.document_id,
                    "IndicatorType": indicator_type,
                    "IndicatorValue": value,
                    "NormalizedValue": value,
                    "PageNumber": "",
                    "EvidenceText": "",
                    "FirstSeenDate": analysis.processed_at,
                    "LastSeenDate": analysis.processed_at,
                }
            )
    return rows


def memory_payload(
    analysis: DocumentAnalysis,
    cve: CVEAnalysis,
    existing: MemoryRecord | None = None,
) -> dict[str, Any]:
    times_seen = 1
    first_seen_date = analysis.processed_at
    previous_highest_relevance = cve.document_relevance
    if existing is not None:
        first_seen_date = existing.first_seen_date
        times_seen = existing.times_seen
        if existing.last_document_id != analysis.document_id:
            times_seen += 1
        previous_highest_relevance = _higher_relevance(
            existing.previous_highest_relevance,
            cve.document_relevance,
        )

    return {
        "MemoryID": memory_key_for_cve(cve.cve),
        "MemoryType": "CVE",
        "MemoryKey": memory_key_for_cve(cve.cve),
        "CVE": cve.cve,
        "Technology": cve.technology,
        "Vendor": cve.vendor,
        "ThreatName": analysis.threat_name or "",
        "FirstSeenDate": first_seen_date,
        "LastSeenDate": analysis.processed_at,
        "TimesSeen": times_seen,
        "PreviousHighestRelevance": previous_highest_relevance,
        "PreviousSemanticCategory": cve.semantic_category,
        "LastDocumentID": analysis.document_id,
        "LastAnalystStatus": existing.last_analyst_status if existing else "",
        "LastAnalystDecision": existing.last_analyst_decision if existing else "",
        "LastAnalystComment": existing.last_analyst_comment if existing else "",
        "LastReviewedDate": existing.last_reviewed_date if existing else "",
        "InternalMatch": existing.internal_match if existing else "",
        "AffectedAssetCount": existing.affected_asset_count if existing else None,
        "UpdatedDate": analysis.processed_at,
    }


def feedback_payload(feedback: AnalystFeedbackRecord) -> dict[str, Any]:
    return {
        "FeedbackID": feedback.feedback_id,
        "FindingID": feedback.finding_id,
        "DocumentID": feedback.document_id,
        "CVE": feedback.cve or "",
        "AnalystEmail": feedback.analyst_email or "",
        "AnalystName": feedback.analyst_name or "",
        "PreviousStatus": feedback.previous_status or "",
        "NewStatus": feedback.new_status or "",
        "SystemRelevance": feedback.system_relevance or "",
        "AnalystRelevance": feedback.analyst_relevance or "",
        "Comment": feedback.comment or "",
        "Decision": feedback.decision or "",
        "CreatedDate": feedback.created_date,
    }


def similar_document_payload(record: SimilarDocumentRecord) -> dict[str, Any]:
    return {
        "SimilarityID": _stable_id(record.current_document_id, record.similar_document_id),
        "CurrentDocumentID": record.current_document_id,
        "SimilarDocumentID": record.similar_document_id,
        "SimilarityScore": record.similarity_score,
        "MatchReason": record.match_reason,
        "CreatedDate": record.created_date,
    }


def memory_key_for_cve(cve: str) -> str:
    return cve.upper()


def finding_id(document_id: str, cve: str) -> str:
    return _stable_id(document_id, cve.upper())


def highest_relevance(analysis: DocumentAnalysis) -> str:
    if not analysis.cves:
        return "INFORMATIONAL"
    return max((cve.document_relevance for cve in analysis.cves), key=lambda value: RELEVANCE_RANK.get(value, 0))


def _default_status(relevance: str) -> str:
    if relevance == "HIGH":
        return "Review Required"
    if relevance == "REVIEW":
        return "Review Required"
    return "Informational"


def _higher_relevance(existing: str | None, current: str) -> str:
    if existing is None:
        return current
    return current if RELEVANCE_RANK.get(current, 0) > RELEVANCE_RANK.get(existing, 0) else existing


def _stable_id(*parts: str) -> str:
    digest = hashlib.sha256("::".join(parts).encode("utf-8")).hexdigest()
    return digest[:32]


def _slack_ts_to_iso(value: str | None) -> str:
    if not value:
        return ""
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    except ValueError:
        return value
