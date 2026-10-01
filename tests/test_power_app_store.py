from __future__ import annotations

from src.message_parser import ThreatIntelRecord
from src.power_app_store import PowerAppStore, PowerAppStorePaths
from tests.test_repository_payloads import sample_analysis


def test_power_app_store_reads_sharepoint_like_local_payloads(tmp_path) -> None:
    store = PowerAppStore(
        PowerAppStorePaths(
            repository_dir=tmp_path / "repo",
            sqlite_db_path=tmp_path / "threat_intel.db",
            downloads_dir=tmp_path / "downloads",
        )
    )
    store.repository.publish_analysis(sample_analysis(document_id="doc-1", relevance="HIGH"))

    summary = store.dashboard_summary()
    detail = store.get_document_detail("doc-1")

    assert summary["documentsProcessed"] == 1
    assert summary["highAttention"] == 1
    assert summary["reviewRequired"] == 1
    assert detail is not None
    assert len(detail["findings"]) == 1
    assert len(detail["indicators"]) >= 1
    store.close()


def test_power_app_store_submit_feedback_updates_finding_and_preserves_history(tmp_path) -> None:
    store = PowerAppStore(
        PowerAppStorePaths(
            repository_dir=tmp_path / "repo",
            sqlite_db_path=tmp_path / "threat_intel.db",
            downloads_dir=tmp_path / "downloads",
        )
    )
    store.repository.publish_analysis(sample_analysis(document_id="doc-1", relevance="HIGH"))
    finding_id = store.list_findings()[0]["FindingID"]

    result = store.submit_feedback(
        finding_id,
        {
            "status": "Action Required",
            "analystRelevance": "HIGH",
            "assignedTo": "exchange@example.com",
            "decision": "Action Required",
            "comment": "Exchange team is remediating.",
            "analystEmail": "analyst@example.com",
            "analystName": "Analyst",
        },
    )
    detail = store.get_finding_detail(finding_id)

    assert result["finding"]["Status"] == "Action Required"
    assert result["finding"]["AssignedTo"] == "exchange@example.com"
    assert detail is not None
    assert detail["finding"]["Status"] == "Action Required"
    assert detail["feedback"][0]["decision"] == "Action Required"
    assert detail["memory"]["last_analyst_comment"] == "Exchange team is remediating."
    store.close()


def test_power_app_store_flags_related_documents_by_cve_and_technology(tmp_path) -> None:
    store = PowerAppStore(
        PowerAppStorePaths(
            repository_dir=tmp_path / "repo",
            sqlite_db_path=tmp_path / "threat_intel.db",
            downloads_dir=tmp_path / "downloads",
        )
    )
    store.repository.publish_analysis(sample_analysis(document_id="doc-1", relevance="HIGH"))
    store.repository.publish_analysis(sample_analysis(document_id="doc-2", relevance="REVIEW"))

    events = store.list_duplicate_events()
    related_events = [event for event in events if event["EventType"] == "RELATED_DOCUMENT_RESEEN"]
    summary = store.dashboard_summary()

    assert len(related_events) >= 2
    assert any(event["MatchReason"] == "same CVE: CVE-2021-34473" for event in related_events)
    assert any(event["MatchReason"] == "same technology: Microsoft Exchange Server" for event in related_events)
    assert summary["relatedRepeats"] == len(related_events)
    store.close()


def test_power_app_store_phase_one_on_call_memory_keeps_history(tmp_path) -> None:
    store = PowerAppStore(
        PowerAppStorePaths(
            repository_dir=tmp_path / "repo",
            sqlite_db_path=tmp_path / "threat_intel.db",
            downloads_dir=tmp_path / "downloads",
        )
    )

    first = store.submit_on_call_entry(
        {
            "documentName": "aa22-321a_joint_csa_stopransomware_hive.pdf",
            "documentId": "slack_F123",
            "localFileName": "F123_aa22-321a_joint_csa_stopransomware_hive.pdf",
            "pdfUrl": "/pdf/F123_aa22-321a_joint_csa_stopransomware_hive.pdf",
            "threatName": "Hive Ransomware",
            "cve": "CVE-2021-34473",
            "technology": "Microsoft Exchange",
            "status": "Review Required",
            "decision": "Investigate",
            "comment": "Support team started review.",
            "analystName": "Analyst One",
        }
    )
    second = store.submit_on_call_entry(
        {
            "documentName": "aa22-321a_joint_csa_stopransomware_hive.pdf",
            "threatName": "Hive Ransomware",
            "cve": "CVE-2021-34473",
            "technology": "Microsoft Exchange",
            "status": "Action Required",
            "decision": "Action Required",
            "comment": "Exchange team contacted.",
            "analystName": "Analyst Two",
        }
    )
    detail = store.get_on_call_detail(first["record"]["RecordID"])
    matches = store.find_on_call_matches(cve="CVE-2021-34473")

    assert first["record"]["RecordID"] == second["record"]["RecordID"]
    assert first["record"]["DocumentID"] == "slack_F123"
    assert first["record"]["LocalFileName"] == "F123_aa22-321a_joint_csa_stopransomware_hive.pdf"
    assert first["note"]["PDFUrl"] == "/pdf/F123_aa22-321a_joint_csa_stopransomware_hive.pdf"
    assert second["record"]["TimesSeen"] == 2
    assert second["record"]["Status"] == "Action Required"
    assert detail is not None
    assert len(detail["notes"]) == 2
    assert detail["notes"][0]["Comment"] == "Exchange team contacted."
    assert matches[0]["RecordID"] == second["record"]["RecordID"]
    assert second["duplicateEvent"]["EventType"] == "ON_CALL_RECORD_RESEEN"
    assert store.dashboard_summary()["duplicateEvents"] == 1
    store.close()


def test_power_app_store_creates_phase_one_memory_from_slack_record_idempotently(tmp_path) -> None:
    store = PowerAppStore(
        PowerAppStorePaths(
            repository_dir=tmp_path / "repo",
            sqlite_db_path=tmp_path / "threat_intel.db",
            downloads_dir=tmp_path / "downloads",
        )
    )
    record = ThreatIntelRecord(
        slack_message_ts="1727040000.000100",
        document="aa22-321a_joint_csa_stopransomware_hive.pdf",
        threat="Hive Ransomware",
        impacted_technology="FortiOS, Microsoft Exchange",
        cve_count=2,
        cves=["CVE-2021-31207", "CVE-2021-34473"],
        slack_user_id="U123",
        analyst_name="On Call Analyst",
        analyst_email="analyst@example.com",
    )

    first_results = store.submit_slack_threat_record(record, slack_channel_id="C123")
    second_results = store.submit_slack_threat_record(record, slack_channel_id="C123")
    records = store.list_on_call_records()
    detail = store.get_on_call_detail(records[0]["RecordID"])

    assert len(first_results) == 2
    assert all(result["created"] for result in first_results)
    assert len(second_results) == 2
    assert not any(result["created"] for result in second_results)
    assert len(records) == 2
    assert {item["CVE"] for item in records} == {"CVE-2021-31207", "CVE-2021-34473"}
    assert records[0]["LastAnalystName"] == "On Call Analyst"
    assert records[0]["SlackUserID"] == "U123"
    assert records[0]["TimesSeen"] == 1
    assert detail is not None
    assert len(detail["notes"]) == 1
    assert detail["notes"][0]["SlackMessageID"] == "1727040000.000100"
    assert store.list_duplicate_events() == []
    store.close()


def test_power_app_store_records_duplicate_event_idempotently(tmp_path) -> None:
    store = PowerAppStore(
        PowerAppStorePaths(
            repository_dir=tmp_path / "repo",
            sqlite_db_path=tmp_path / "threat_intel.db",
            downloads_dir=tmp_path / "downloads",
        )
    )

    first = store.record_duplicate_event(
        {
            "EventType": "SLACK_PDF_RESEEN",
            "Title": "Slack PDF was seen again",
            "DocumentID": "slack_F123",
            "DocumentName": "report.pdf",
            "SlackFileID": "F123",
            "FirstSlackMessageID": "100.000",
            "DuplicateSlackMessageID": "200.000",
            "SlackMessageID": "200.000",
            "SlackChannelID": "C123",
            "MatchReason": "same Slack file id",
            "Reason": "Slack history contains another message for a PDF that was already seen.",
        }
    )
    second = store.record_duplicate_event(
        {
            "EventType": "SLACK_PDF_RESEEN",
            "Title": "Slack PDF was seen again",
            "DocumentID": "slack_F123",
            "DocumentName": "report.pdf",
            "SlackFileID": "F123",
            "FirstSlackMessageID": "100.000",
            "DuplicateSlackMessageID": "200.000",
            "SlackMessageID": "200.000",
            "SlackChannelID": "C123",
            "MatchReason": "same Slack file id",
            "Reason": "Slack history contains another message for a PDF that was already seen.",
        }
    )

    events = store.list_duplicate_events()

    assert first["created"] is True
    assert second["created"] is False
    assert len(events) == 1
    assert events[0]["DocumentName"] == "report.pdf"
    assert events[0]["EventType"] == "SLACK_PDF_RESEEN"
    assert store.dashboard_summary()["duplicateEvents"] == 1
    store.close()
