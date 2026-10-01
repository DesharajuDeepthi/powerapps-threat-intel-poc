from __future__ import annotations

import json
import hashlib
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.local_repository import LocalThreatIntelRepository
from src.message_parser import ThreatIntelRecord
from src.repository_models import AnalystFeedbackRecord


@dataclass(frozen=True)
class PowerAppStorePaths:
    repository_dir: Path
    sqlite_db_path: Path
    downloads_dir: Path


class PowerAppStore:
    def __init__(self, paths: PowerAppStorePaths) -> None:
        self.paths = paths
        self.paths.repository_dir.mkdir(parents=True, exist_ok=True)
        self.repository = LocalThreatIntelRepository(
            db_path=self.paths.sqlite_db_path,
            repository_dir=self.paths.repository_dir,
        )

    def close(self) -> None:
        self.repository.close()

    def dashboard_summary(self) -> dict[str, Any]:
        documents = self.list_documents()
        findings = self.list_findings()
        feedback = self.list_feedback()
        on_call_records = self.list_on_call_records()
        duplicate_events = self.list_duplicate_events()
        today = datetime.now(timezone.utc).date().isoformat()
        today_documents = [item for item in documents if _date_part(_document_received_date(item)) == today]
        today_duplicate_events = [item for item in duplicate_events if _date_part(str(item.get("LastDetectedDate", ""))) == today]
        related_repeat_events = [item for item in duplicate_events if item.get("EventType") == "RELATED_DOCUMENT_RESEEN"]
        return {
            "documentsProcessed": len(documents),
            "documentsReceivedToday": len(today_documents),
            "highAttention": sum(1 for item in findings if item.get("DocumentRelevance") == "HIGH"),
            "reviewRequired": sum(
                1
                for item in findings
                if item.get("Status") in {"Review Required", "Under Review", "Action Required"}
            ),
            "cvesDetected": len({item.get("CVE") for item in findings if item.get("CVE")}),
            "analystActions": len(feedback),
            "onCallRecords": len(on_call_records),
            "duplicateEvents": len(duplicate_events),
            "duplicatesToday": len(today_duplicate_events),
            "relatedRepeats": len(related_repeat_events),
            "recentDocuments": sorted(
                documents,
                key=lambda item: str(item.get("ProcessedDate", "")),
                reverse=True,
            )[:8],
            "recentDuplicateEvents": duplicate_events[:8],
        }

    def list_documents(self) -> list[dict[str, Any]]:
        return sorted(
            self._read_collection("documents"),
            key=lambda item: str(item.get("ProcessedDate", "")),
            reverse=True,
        )

    def get_document(self, document_id: str) -> dict[str, Any] | None:
        return _first(item for item in self.list_documents() if item.get("DocumentID") == document_id)

    def list_findings(self) -> list[dict[str, Any]]:
        return sorted(
            self._read_collection("findings"),
            key=lambda item: (str(item.get("DocumentID", "")), str(item.get("CVE", ""))),
        )

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        return _first(item for item in self.list_findings() if item.get("FindingID") == finding_id)

    def list_indicators(self, document_id: str | None = None) -> list[dict[str, Any]]:
        indicators = self._read_collection("indicators")
        if document_id:
            indicators = [item for item in indicators if item.get("DocumentID") == document_id]
        return sorted(indicators, key=lambda item: (str(item.get("IndicatorType", "")), str(item.get("IndicatorValue", ""))))

    def get_document_detail(self, document_id: str) -> dict[str, Any] | None:
        document = self.get_document(document_id)
        if document is None:
            return None

        findings = [item for item in self.list_findings() if item.get("DocumentID") == document_id]
        cves = {item.get("CVE") for item in findings if item.get("CVE")}
        feedback = [item for item in self.list_feedback() if item.get("DocumentID") == document_id]
        return {
            "document": document,
            "findings": findings,
            "indicators": self.list_indicators(document_id),
            "similarDocuments": [item.__dict__ for item in self.repository.list_similar_documents(document_id)],
            "feedback": feedback,
            "memory": [self.get_memory(str(cve)) for cve in sorted(cves)],
        }

    def get_finding_detail(self, finding_id: str) -> dict[str, Any] | None:
        finding = self.get_finding(finding_id)
        if finding is None:
            return None
        document_id = str(finding.get("DocumentID", ""))
        cve = str(finding.get("CVE", ""))
        return {
            "finding": finding,
            "document": self.get_document(document_id),
            "memory": self.get_memory(cve),
            "feedback": self.list_feedback(finding_id=finding_id),
        }

    def get_memory(self, cve: str) -> dict[str, Any] | None:
        memory = self.repository.get_memory(cve)
        return memory.__dict__ if memory else None

    def list_feedback(
        self,
        *,
        finding_id: str | None = None,
        cve: str | None = None,
    ) -> list[dict[str, Any]]:
        return [
            item.__dict__
            for item in self.repository.list_feedback(finding_id=finding_id, cve=cve)
        ]

    def submit_feedback(self, finding_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        finding = self.get_finding(finding_id)
        if finding is None:
            raise KeyError(f"Finding not found: {finding_id}")

        now = datetime.now(timezone.utc).isoformat()
        previous_status = str(finding.get("Status", ""))
        previous_relevance = str(finding.get("DocumentRelevance", ""))
        new_status = _clean_choice(payload.get("status")) or previous_status
        analyst_relevance = _clean_choice(payload.get("analystRelevance")) or previous_relevance
        assigned_to = str(payload.get("assignedTo", "")).strip()
        comment = str(payload.get("comment", "")).strip()
        decision = _clean_choice(payload.get("decision")) or "Agree With System"
        analyst_email = str(payload.get("analystEmail", "")).strip()
        analyst_name = str(payload.get("analystName", "")).strip()

        finding["Status"] = new_status
        finding["DocumentRelevance"] = analyst_relevance
        finding["AssignedTo"] = assigned_to
        finding["UpdatedDate"] = now
        self._write_collection_item("findings", _finding_file_name(finding), finding)

        feedback = AnalystFeedbackRecord(
            feedback_id=str(uuid.uuid4()),
            finding_id=str(finding["FindingID"]),
            document_id=str(finding["DocumentID"]),
            cve=str(finding.get("CVE", "")) or None,
            analyst_email=analyst_email or None,
            analyst_name=analyst_name or None,
            previous_status=previous_status or None,
            new_status=new_status or None,
            system_relevance=previous_relevance or None,
            analyst_relevance=analyst_relevance or None,
            comment=comment or None,
            decision=decision or None,
            created_date=now,
        )
        self.repository.record_feedback(feedback)
        return {
            "finding": finding,
            "feedback": feedback.__dict__,
            "memory": self.get_memory(str(finding.get("CVE", ""))),
        }

    def list_on_call_records(self) -> list[dict[str, Any]]:
        return sorted(
            self._read_collection("on_call_records"),
            key=lambda item: str(item.get("LastSeenDate", item.get("UpdatedDate", ""))),
            reverse=True,
        )

    def list_on_call_notes(self, record_id: str | None = None) -> list[dict[str, Any]]:
        notes = self._read_collection("on_call_notes")
        if record_id:
            notes = [item for item in notes if item.get("RecordID") == record_id]
        return sorted(notes, key=lambda item: str(item.get("CreatedDate", "")), reverse=True)

    def list_duplicate_events(self) -> list[dict[str, Any]]:
        stored_events = self._read_collection("duplicate_events")
        event_by_id = {str(item.get("EventID", "")): item for item in stored_events if item.get("EventID")}
        for event in self._related_document_events():
            event_by_id.setdefault(str(event["EventID"]), event)
        return sorted(
            event_by_id.values(),
            key=lambda item: str(item.get("LastDetectedDate", item.get("FirstDetectedDate", ""))),
            reverse=True,
        )

    def _related_document_events(self) -> list[dict[str, Any]]:
        documents = {str(item.get("DocumentID", "")): item for item in self.list_documents()}
        findings = self.list_findings()
        events: list[dict[str, Any]] = []
        events.extend(self._related_events_for_key(findings, documents, key="CVE", label="same CVE"))
        events.extend(self._related_events_for_key(findings, documents, key="Technology", label="same technology"))
        return events

    def _related_events_for_key(
        self,
        findings: list[dict[str, Any]],
        documents: dict[str, dict[str, Any]],
        *,
        key: str,
        label: str,
    ) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            value = _normalize_related_value(str(finding.get(key, "")))
            if not value:
                continue
            grouped.setdefault(value, []).append(finding)

        events: list[dict[str, Any]] = []
        for value, rows in grouped.items():
            unique_rows = _unique_findings_by_document(rows)
            if len(unique_rows) < 2:
                continue
            ordered = sorted(
                unique_rows,
                key=lambda finding: _document_received_date(documents.get(str(finding.get("DocumentID", "")), {})),
            )
            first = ordered[0]
            latest = ordered[-1]
            first_document = documents.get(str(first.get("DocumentID", "")), {})
            latest_document = documents.get(str(latest.get("DocumentID", "")), {})
            latest_document_id = str(latest.get("DocumentID", ""))
            first_date = _document_received_date(first_document)
            latest_date = _document_received_date(latest_document)
            latest_note = _latest_note_for_document(self.list_on_call_notes(), str(latest_document.get("DocumentName", "")))
            note_text = str(latest_note.get("Comment", "")).strip()
            reason = (
                f"This document shares {label} {value} with {first_document.get('DocumentName', 'another document')} "
                f"first seen on {_date_part(first_date) or 'an earlier date'}."
            )
            if note_text:
                reason = f"{reason} Latest analyst note: {note_text}"
            events.append(
                {
                    "EventID": _duplicate_event_id("RELATED_DOCUMENT_RESEEN", key, value, latest_document_id),
                    "EventType": "RELATED_DOCUMENT_RESEEN",
                    "Title": "Related document repeat",
                    "DocumentID": latest_document_id,
                    "DocumentName": str(latest_document.get("DocumentName", latest_document_id)),
                    "CVE": str(latest.get("CVE", "")).upper(),
                    "Technology": str(latest.get("Technology", "")),
                    "MatchReason": f"{label}: {value}",
                    "Reason": reason,
                    "FirstDetectedDate": first_date,
                    "LastDetectedDate": latest_date,
                    "TimesObserved": len(unique_rows),
                    "FirstDocumentName": str(first_document.get("DocumentName", "")),
                    "FirstDocumentDate": first_date,
                    "LatestAnalystComment": note_text,
                }
            )
        return events

    def record_duplicate_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        event_type = str(payload.get("EventType", "DUPLICATE")).strip() or "DUPLICATE"
        event_id = str(payload.get("EventID", "")).strip()
        if not event_id:
            event_id = _duplicate_event_id(
                event_type,
                str(payload.get("DocumentName", "")),
                str(payload.get("CVE", "")),
                str(payload.get("SlackFileID", "")),
                str(payload.get("SlackMessageID", "")),
                str(payload.get("DuplicateSlackMessageID", "")),
                str(payload.get("ExternalID", "")),
            )

        existing = _first(item for item in self.list_duplicate_events() if item.get("EventID") == event_id)
        if existing:
            result = dict(existing)
            result["created"] = False
            return result

        event = {
            "EventID": event_id,
            "EventType": event_type,
            "Title": str(payload.get("Title", "Duplicate or re-seen item")).strip(),
            "DocumentID": str(payload.get("DocumentID", "")).strip(),
            "DocumentName": str(payload.get("DocumentName", "")).strip(),
            "CVE": str(payload.get("CVE", "")).strip().upper(),
            "SlackFileID": str(payload.get("SlackFileID", "")).strip(),
            "SlackMessageID": str(payload.get("SlackMessageID", "")).strip(),
            "FirstSlackMessageID": str(payload.get("FirstSlackMessageID", "")).strip(),
            "DuplicateSlackMessageID": str(payload.get("DuplicateSlackMessageID", "")).strip(),
            "SlackChannelID": str(payload.get("SlackChannelID", "")).strip(),
            "SlackUserID": str(payload.get("SlackUserID", "")).strip(),
            "AnalystName": str(payload.get("AnalystName", "")).strip(),
            "AnalystEmail": str(payload.get("AnalystEmail", "")).strip(),
            "MatchReason": str(payload.get("MatchReason", "")).strip(),
            "Reason": str(payload.get("Reason", "")).strip(),
            "FirstDetectedDate": now,
            "LastDetectedDate": now,
            "TimesObserved": 1,
        }
        self._write_collection_item("duplicate_events", f"{event_id}.json", event)
        result = dict(event)
        result["created"] = True
        return result

    def find_on_call_matches(
        self,
        *,
        document_name: str = "",
        cve: str = "",
    ) -> list[dict[str, Any]]:
        document_name = document_name.strip().lower()
        cve = cve.strip().upper()
        matches: list[dict[str, Any]] = []
        for record in self.list_on_call_records():
            record_document = str(record.get("DocumentName", "")).lower()
            record_cve = str(record.get("CVE", "")).upper()
            if cve and record_cve == cve:
                matches.append(record)
                continue
            if document_name and document_name in record_document:
                matches.append(record)
        return matches

    def get_on_call_detail(self, record_id: str) -> dict[str, Any] | None:
        record = _first(
            item for item in self.list_on_call_records() if item.get("RecordID") == record_id
        )
        if record is None:
            return None
        return {
            "record": record,
            "notes": self.list_on_call_notes(record_id),
            "matches": self.find_on_call_matches(
                document_name=str(record.get("DocumentName", "")),
                cve=str(record.get("CVE", "")),
            ),
        }

    def submit_on_call_entry(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        document_name = str(payload.get("documentName", "")).strip()
        cve = str(payload.get("cve", "")).strip().upper()
        if not document_name:
            raise ValueError("Document name is required.")

        record_id = _on_call_record_id(document_name, cve)
        existing = _first(
            item for item in self.list_on_call_records() if item.get("RecordID") == record_id
        )
        external_id = str(payload.get("externalId", "")).strip()
        if existing and external_id:
            prior_note = _first(
                note
                for note in self.list_on_call_notes(record_id)
                if note.get("ExternalID") == external_id
            )
            if prior_note:
                return {
                    "record": existing,
                    "note": prior_note,
                    "matches": self.find_on_call_matches(document_name=document_name, cve=cve),
                    "created": False,
                }

        previous_status = str(existing.get("Status", "")) if existing else ""
        previous_times_seen = int(existing.get("TimesSeen", 0)) if existing else 0
        status = _clean_choice(payload.get("status")) or previous_status or "New"
        decision = _clean_choice(payload.get("decision")) or "Investigate"
        comment = str(payload.get("comment", "")).strip()
        analyst_name = str(payload.get("analystName", "")).strip()
        analyst_email = str(payload.get("analystEmail", "")).strip()
        document_id = str(payload.get("documentId", "")).strip() or str(existing.get("DocumentID", "") if existing else "")
        local_file_name = str(payload.get("localFileName", "")).strip() or str(
            existing.get("LocalFileName", "") if existing else ""
        )
        pdf_url = str(payload.get("pdfUrl", "")).strip() or str(existing.get("PDFUrl", "") if existing else "")

        record = dict(existing or {})
        record.update(
            {
                "RecordID": record_id,
                "DocumentName": document_name,
                "DocumentID": document_id,
                "LocalFileName": local_file_name,
                "PDFUrl": pdf_url,
                "ThreatName": str(payload.get("threatName", "")).strip(),
                "CVE": cve,
                "Technology": str(payload.get("technology", "")).strip(),
                "Source": str(payload.get("source", "Slack")).strip() or "Slack",
                "Status": status,
                "Decision": decision,
                "LastComment": comment,
                "LastAnalystName": analyst_name,
                "LastAnalystEmail": analyst_email,
                "SlackMessageID": str(payload.get("slackMessageId", "")).strip(),
                "SlackChannelID": str(payload.get("slackChannelId", "")).strip(),
                "SlackUserID": str(payload.get("slackUserId", "")).strip(),
                "CVECount": _optional_int(payload.get("cveCount")),
                "CVEList": str(payload.get("cveList", "")).strip(),
                "LastSeenDate": now,
                "UpdatedDate": now,
                "TimesSeen": previous_times_seen + 1,
            }
        )
        if not existing:
            record["FirstSeenDate"] = now
            record["CreatedDate"] = now

        note = {
            "NoteID": str(uuid.uuid4()),
            "RecordID": record_id,
            "DocumentName": document_name,
            "DocumentID": record.get("DocumentID", ""),
            "LocalFileName": record.get("LocalFileName", ""),
            "PDFUrl": record.get("PDFUrl", ""),
            "CVE": cve,
            "ThreatName": record["ThreatName"],
            "Technology": record["Technology"],
            "AnalystName": analyst_name,
            "AnalystEmail": analyst_email,
            "SlackMessageID": record["SlackMessageID"],
            "SlackChannelID": record["SlackChannelID"],
            "SlackUserID": record["SlackUserID"],
            "ExternalID": external_id,
            "PreviousStatus": previous_status,
            "NewStatus": status,
            "Decision": decision,
            "Comment": comment,
            "CreatedDate": now,
        }

        self._write_collection_item("on_call_records", f"{record_id}.json", record)
        self._write_collection_item("on_call_notes", f"{note['NoteID']}.json", note)
        duplicate_event = None
        if existing:
            duplicate_event = self.record_duplicate_event(
                {
                    "EventType": "ON_CALL_RECORD_RESEEN",
                    "EventID": _duplicate_event_id("ON_CALL_RECORD_RESEEN", external_id or note["NoteID"], record_id),
                    "Title": "On-call memory matched previous record",
                    "DocumentID": record_id,
                    "DocumentName": document_name,
                    "CVE": cve,
                    "SlackMessageID": record["SlackMessageID"],
                    "DuplicateSlackMessageID": record["SlackMessageID"],
                    "SlackChannelID": record["SlackChannelID"],
                    "SlackUserID": record["SlackUserID"],
                    "AnalystName": analyst_name,
                    "AnalystEmail": analyst_email,
                    "MatchReason": "same document and CVE",
                    "Reason": "This document/CVE was already stored in on-call memory; a new sighting was added to history.",
                    "ExternalID": external_id,
                }
            )
        return {
            "record": record,
            "note": note,
            "matches": self.find_on_call_matches(document_name=document_name, cve=cve),
            "created": True,
            "duplicateEvent": duplicate_event,
        }

    def submit_slack_threat_record(
        self,
        record: ThreatIntelRecord,
        *,
        slack_channel_id: str = "",
    ) -> list[dict[str, Any]]:
        cves = record.cves or [""]
        results: list[dict[str, Any]] = []
        for cve in cves:
            external_id = f"slack:{record.slack_message_ts}:{cve or 'document'}"
            cve_list = "; ".join(record.cves)
            comment_parts = [
                "Structured Slack note captured.",
                f"Threat: {record.threat or 'Not provided'}.",
                f"Impacted Technology: {record.impacted_technology or 'Not provided'}.",
            ]
            if cve_list:
                comment_parts.append(f"All CVEs in message: {cve_list}.")
            results.append(
                self.submit_on_call_entry(
                    {
                        "documentName": record.document,
                        "threatName": record.threat,
                        "cve": cve,
                        "technology": record.impacted_technology,
                        "source": "Slack",
                        "status": "New",
                        "decision": "Investigate",
                        "comment": " ".join(comment_parts),
                        "analystName": record.analyst_name or record.slack_user_id,
                        "analystEmail": record.analyst_email,
                        "slackMessageId": record.slack_message_ts,
                        "slackChannelId": slack_channel_id,
                        "slackUserId": record.slack_user_id,
                        "cveCount": record.cve_count,
                        "cveList": cve_list,
                        "externalId": external_id,
                    }
                )
            )
        return results

    def _read_collection(self, collection: str) -> list[dict[str, Any]]:
        collection_dir = self.paths.repository_dir / collection
        if not collection_dir.exists():
            return []
        rows: list[dict[str, Any]] = []
        for path in sorted(collection_dir.glob("*.json")):
            try:
                rows.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
        return rows

    def _write_collection_item(
        self,
        collection: str,
        file_name: str,
        payload: dict[str, Any],
    ) -> None:
        collection_dir = self.paths.repository_dir / collection
        collection_dir.mkdir(parents=True, exist_ok=True)
        (collection_dir / file_name).write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def health(self) -> dict[str, Any]:
        counts = self.dashboard_summary()
        sqlite_ok = False
        if self.paths.sqlite_db_path.exists():
            try:
                with sqlite3.connect(self.paths.sqlite_db_path) as connection:
                    connection.execute("SELECT 1").fetchone()
                sqlite_ok = True
            except sqlite3.Error:
                sqlite_ok = False
        return {
            "ok": True,
            "sqlite": sqlite_ok,
            "repositoryDir": str(self.paths.repository_dir),
            "sqliteDbPath": str(self.paths.sqlite_db_path),
            "counts": counts,
        }


def _first(items: Any) -> Any | None:
    for item in items:
        return item
    return None


def _clean_choice(value: Any) -> str:
    return str(value or "").strip()


def _optional_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _document_received_date(document: dict[str, Any]) -> str:
    for key in ("SlackMessageDate", "ReceivedDate", "ProcessedDate", "CreatedDate"):
        value = str(document.get(key, "")).strip()
        if value:
            return value
    return ""


def _date_part(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if "T" in value:
        return value.split("T", 1)[0]
    return value[:10]


def _normalize_related_value(value: str) -> str:
    cleaned = " ".join(value.strip().split())
    if not cleaned:
        return ""
    if cleaned.lower() in {"unknown", "unknown technology", "n/a", "none"}:
        return ""
    if cleaned.upper().startswith("CVE-"):
        return cleaned.upper()
    return cleaned


def _unique_findings_by_document(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for row in rows:
        document_id = str(row.get("DocumentID", ""))
        if document_id:
            unique.setdefault(document_id, row)
    return list(unique.values())


def _latest_note_for_document(notes: list[dict[str, Any]], document_name: str) -> dict[str, Any]:
    for note in sorted(notes, key=lambda item: str(item.get("CreatedDate", "")), reverse=True):
        if str(note.get("DocumentName", "")) == document_name:
            return note
    return {}


def _finding_file_name(finding: dict[str, Any]) -> str:
    document_id = str(finding.get("DocumentID", "document"))
    cve = str(finding.get("CVE", finding.get("FindingID", "finding")))
    return f"{document_id}_{cve}.json"


def _on_call_record_id(document_name: str, cve: str) -> str:
    normalized = "::".join([document_name.strip().lower(), cve.strip().upper()])
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]


def _duplicate_event_id(*parts: str) -> str:
    normalized = "::".join(part.strip().lower() for part in parts if part and part.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]
