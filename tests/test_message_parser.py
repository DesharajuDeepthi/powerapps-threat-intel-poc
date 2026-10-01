from __future__ import annotations

from src.message_parser import parse_threat_intel_message, parse_threat_intel_messages


def test_parse_threat_intel_message_extracts_fields() -> None:
    message = {
        "ts": "1727040000.000100",
        "text": "\n".join(
            [
                "Document: aa22-321a_joint_csa_stopransomware_hive.pdf",
                "Threat: Hive Ransomware",
                "Impacted Technology: FortiOS, Microsoft Exchange",
                "CVE Count: 5",
                "CVE: CVE-2020-12812; CVE-2021-31207; CVE-2021-34473; CVE-2021-34523; CVE-2021-42321",
            ]
        ),
    }

    record = parse_threat_intel_message(message)

    assert record is not None
    assert record.slack_message_ts == "1727040000.000100"
    assert record.document == "aa22-321a_joint_csa_stopransomware_hive.pdf"
    assert record.threat == "Hive Ransomware"
    assert record.impacted_technology == "FortiOS, Microsoft Exchange"
    assert record.cve_count == 5
    assert record.cves == [
        "CVE-2020-12812",
        "CVE-2021-31207",
        "CVE-2021-34473",
        "CVE-2021-34523",
        "CVE-2021-42321",
    ]


def test_parse_threat_intel_message_captures_sender_details() -> None:
    message = {
        "ts": "1727040000.000100",
        "user": "U123",
        "user_profile": {
            "real_name": "On Call Analyst",
            "email": "analyst@example.com",
        },
        "text": "Document: report.pdf\nThreat: Demo\nCVE: CVE-2024-1111",
    }

    record = parse_threat_intel_message(message)

    assert record is not None
    assert record.slack_user_id == "U123"
    assert record.analyst_name == "On Call Analyst"
    assert record.analyst_email == "analyst@example.com"


def test_parse_threat_intel_messages_writes_one_record_per_matching_message() -> None:
    messages = [
        {
            "ts": "1.000",
            "text": "Document: first.pdf\nThreat: First\nCVE: CVE-2024-1111",
        },
        {
            "ts": "2.000",
            "text": "Just a normal Slack message",
        },
        {
            "ts": "3.000",
            "text": "*Document:* second.pdf\n*Threat:* Second\n*CVE:* CVE-2025-2222",
        },
    ]

    records = parse_threat_intel_messages(messages)

    assert [record.document for record in records] == ["first.pdf", "second.pdf"]
    assert [record.slack_message_ts for record in records] == ["1.000", "3.000"]


def test_parse_threat_intel_message_uses_cve_count_fallback() -> None:
    record = parse_threat_intel_message(
        {
            "ts": "1.000",
            "text": "Document: report.pdf\nCVE: CVE-2024-1111; CVE-2024-2222",
        }
    )

    assert record is not None
    assert record.cve_count == 2
