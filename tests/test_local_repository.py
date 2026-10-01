from __future__ import annotations

import json

from src.local_repository import LocalThreatIntelRepository
from src.repository_models import AnalystFeedbackRecord
from tests.test_repository_payloads import sample_analysis


def test_local_repository_creates_and_updates_memory(tmp_path) -> None:
    repository = LocalThreatIntelRepository(
        db_path=tmp_path / "threat_intel.db",
        repository_dir=tmp_path / "repo",
    )

    first = sample_analysis(document_id="doc-1", relevance="REVIEW")
    second = sample_analysis(document_id="doc-2", relevance="HIGH")
    repository.publish_analysis(first)
    repository.publish_analysis(second)

    memory = repository.get_memory("CVE-2021-34473")

    assert memory is not None
    assert memory.first_seen_date == "2026-09-23T00:00:00+00:00"
    assert memory.last_seen_date == "2026-09-23T00:00:00+00:00"
    assert memory.times_seen == 2
    assert memory.previous_highest_relevance == "HIGH"
    assert memory.last_document_id == "doc-2"
    repository.close()


def test_local_repository_does_not_increment_same_document_twice(tmp_path) -> None:
    repository = LocalThreatIntelRepository(
        db_path=tmp_path / "threat_intel.db",
        repository_dir=tmp_path / "repo",
    )
    analysis = sample_analysis(document_id="doc-1", relevance="HIGH")

    repository.publish_analysis(analysis)
    repository.publish_analysis(analysis)
    memory = repository.get_memory("CVE-2021-34473")

    assert memory is not None
    assert memory.times_seen == 1
    repository.close()


def test_local_repository_stores_similar_documents(tmp_path) -> None:
    repository = LocalThreatIntelRepository(
        db_path=tmp_path / "threat_intel.db",
        repository_dir=tmp_path / "repo",
    )
    repository.publish_analysis(sample_analysis(document_id="doc-1"))
    repository.publish_analysis(sample_analysis(document_id="doc-2"))

    similar = repository.list_similar_documents("doc-2")

    assert similar
    assert similar[0].similar_document_id == "doc-1"
    assert similar[0].similarity_score > 0
    repository.close()


def test_local_repository_preserves_feedback_history_and_updates_memory(tmp_path) -> None:
    repository = LocalThreatIntelRepository(
        db_path=tmp_path / "threat_intel.db",
        repository_dir=tmp_path / "repo",
    )
    analysis = sample_analysis(document_id="doc-1", relevance="HIGH")
    repository.publish_analysis(analysis)

    repository.record_feedback(
        AnalystFeedbackRecord(
            feedback_id="fb-1",
            finding_id="finding-1",
            document_id="doc-1",
            cve="CVE-2021-34473",
            analyst_email="analyst@example.com",
            analyst_name="Analyst",
            previous_status="Review Required",
            new_status="Under Review",
            system_relevance="HIGH",
            analyst_relevance="HIGH",
            comment="Checking asset owner.",
            decision="Investigate",
            created_date="2026-09-23T01:00:00+00:00",
        )
    )
    repository.record_feedback(
        AnalystFeedbackRecord(
            feedback_id="fb-2",
            finding_id="finding-1",
            document_id="doc-1",
            cve="CVE-2021-34473",
            analyst_email="analyst@example.com",
            analyst_name="Analyst",
            previous_status="Under Review",
            new_status="Action Required",
            system_relevance="HIGH",
            analyst_relevance="HIGH",
            comment="Exchange team is remediating.",
            decision="Action Required",
            created_date="2026-09-23T02:00:00+00:00",
        )
    )

    history = repository.list_feedback(cve="CVE-2021-34473")
    memory = repository.get_memory("CVE-2021-34473")

    assert [item.feedback_id for item in history] == ["fb-1", "fb-2"]
    assert memory is not None
    assert memory.last_analyst_status == "Action Required"
    assert memory.last_analyst_decision == "Action Required"
    assert memory.last_analyst_comment == "Exchange team is remediating."
    repository.close()


def test_historical_memory_does_not_override_current_finding_payload(tmp_path) -> None:
    repository = LocalThreatIntelRepository(
        db_path=tmp_path / "threat_intel.db",
        repository_dir=tmp_path / "repo",
    )

    repository.publish_analysis(sample_analysis(document_id="doc-1", relevance="HIGH"))
    repository.publish_analysis(sample_analysis(document_id="doc-2", relevance="INFORMATIONAL"))

    finding_path = tmp_path / "repo" / "findings" / "doc-2_CVE-2021-34473.json"
    finding_payload = json.loads(finding_path.read_text(encoding="utf-8"))
    memory = repository.get_memory("CVE-2021-34473")

    assert finding_payload["DocumentRelevance"] == "INFORMATIONAL"
    assert finding_payload["Status"] == "Informational"
    assert memory is not None
    assert memory.previous_highest_relevance == "HIGH"
    repository.close()
