from __future__ import annotations

from src.models import CVEAnalysis, DocumentAnalysis, IndicatorSet
from src.repository_models import AnalystFeedbackRecord, SimilarDocumentRecord
from src.repository_payloads import (
    document_payload,
    feedback_payload,
    finding_payload,
    indicator_payloads,
    memory_payload,
    similar_document_payload,
)


def sample_analysis(document_id: str = "doc-1", relevance: str = "HIGH") -> DocumentAnalysis:
    return DocumentAnalysis(
        document_id=document_id,
        document_name="advisory.pdf",
        local_file_path="/app/downloads/advisory.pdf",
        source="slack",
        slack_channel_id="C123",
        slack_message_id="123.456",
        slack_message_timestamp="123.456",
        slack_file_id="F123",
        slack_file_url="https://files.slack.com/advisory.pdf",
        downloaded_at="2026-09-22T00:00:00+00:00",
        processed_at="2026-09-23T00:00:00+00:00",
        pdf_sha256="a" * 64,
        extraction_status="SUCCESS",
        page_count=2,
        character_count=100,
        threat_name="Hive Ransomware",
        threat_evidence="Hive Ransomware actors targeted Microsoft Exchange Server.",
        threat_evidence_page_number=1,
        indicators=IndicatorSet(
            cves=["CVE-2021-34473"],
            ipv4=["8.8.8.8"],
            domains=["example.com"],
            urls=["https://example.com"],
            sha256=["b" * 64],
            mitre_techniques=["T1059"],
        ),
        cves=[
            CVEAnalysis(
                cve="CVE-2021-34473",
                technology="Microsoft Exchange Server",
                vendor="Microsoft",
                page_number=1,
                evidence_text="Hive actors exploited CVE-2021-34473 against Exchange.",
                semantic_scores={
                    "active_exploitation": 0.9,
                    "initial_access": 0.8,
                    "remote_code_execution": 0.7,
                    "privilege_escalation": 0.1,
                    "authentication_bypass": 0.2,
                    "background_reference": 0.1,
                },
                semantic_category="active_exploitation",
                document_relevance=relevance,
                analyst_comment="Review this CVE.",
                technology_evidence="Hive actors exploited Microsoft Exchange Server.",
            )
        ],
    )


def test_document_payload_contains_power_apps_fields() -> None:
    payload = document_payload(sample_analysis(), pdf_url="https://sharepoint/pdf")

    assert payload["DocumentID"] == "doc-1"
    assert payload["PDFUrl"] == "https://sharepoint/pdf"
    assert payload["HighFindingCount"] == 1
    assert payload["IPCount"] == 1
    assert payload["CreatedByPipeline"] is True
    assert payload["ThreatEvidence"] == "Hive Ransomware actors targeted Microsoft Exchange Server."
    assert payload["ThreatEvidencePageNumber"] == 1


def test_finding_payload_contains_scores_and_default_status() -> None:
    analysis = sample_analysis(relevance="HIGH")
    payload = finding_payload(analysis, analysis.cves[0])

    assert payload["FindingID"]
    assert payload["DocumentID"] == "doc-1"
    assert payload["CVE"] == "CVE-2021-34473"
    assert payload["Status"] == "Review Required"
    assert payload["ActiveExploitationScore"] == 0.9
    assert payload["TechnologyEvidence"] == "Hive actors exploited Microsoft Exchange Server."


def test_indicator_payloads_split_iocs() -> None:
    payloads = indicator_payloads(sample_analysis())

    assert {payload["IndicatorType"] for payload in payloads} >= {"IP", "Domain", "URL", "SHA256", "MITRE"}
    assert any(payload["NormalizedValue"] == "8.8.8.8" for payload in payloads)


def test_memory_payload_keeps_current_evidence_separate_from_history() -> None:
    current = sample_analysis(document_id="doc-2", relevance="INFORMATIONAL")
    previous = sample_analysis(document_id="doc-1", relevance="HIGH")
    previous_payload = memory_payload(previous, previous.cves[0])
    existing = previous_payload | {
        "FirstSeenDate": "2026-09-01T00:00:00+00:00",
        "TimesSeen": 1,
        "LastDocumentID": "doc-1",
    }

    from src.repository_models import MemoryRecord

    payload = memory_payload(
        current,
        current.cves[0],
        MemoryRecord(
            memory_id=existing["MemoryID"],
            memory_type=existing["MemoryType"],
            memory_key=existing["MemoryKey"],
            cve=existing["CVE"],
            technology=existing["Technology"],
            vendor=existing["Vendor"],
            threat_name=existing["ThreatName"],
            first_seen_date=existing["FirstSeenDate"],
            last_seen_date=existing["LastSeenDate"],
            times_seen=existing["TimesSeen"],
            previous_highest_relevance=existing["PreviousHighestRelevance"],
            previous_semantic_category=existing["PreviousSemanticCategory"],
            last_document_id=existing["LastDocumentID"],
        ),
    )

    assert current.cves[0].document_relevance == "INFORMATIONAL"
    assert payload["PreviousHighestRelevance"] == "HIGH"
    assert payload["TimesSeen"] == 2
    assert payload["FirstSeenDate"] == "2026-09-01T00:00:00+00:00"


def test_feedback_and_similarity_payloads_are_power_apps_ready() -> None:
    feedback = AnalystFeedbackRecord(
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
        comment="Exchange owners notified.",
        decision="Action Required",
        created_date="2026-09-23T00:00:00+00:00",
    )
    similar = SimilarDocumentRecord(
        current_document_id="doc-2",
        similar_document_id="doc-1",
        similarity_score=0.82,
        match_reason="Shared CVE and Exchange exploitation context",
        created_date="2026-09-23T00:00:00+00:00",
    )

    assert feedback_payload(feedback)["Decision"] == "Action Required"
    assert similar_document_payload(similar)["SimilarityID"]
    assert similar_document_payload(similar)["SimilarityScore"] == 0.82
