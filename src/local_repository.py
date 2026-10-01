from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.models import CVEAnalysis, DocumentAnalysis
from src.repository import ThreatIntelRepository
from src.repository_models import (
    AnalystFeedbackRecord,
    MemoryRecord,
    PublishResult,
    SimilarDocumentRecord,
)
from src.repository_payloads import (
    RELEVANCE_RANK,
    document_payload,
    finding_payload,
    highest_relevance,
    indicator_payloads,
    memory_key_for_cve,
)

LOGGER = logging.getLogger(__name__)


class LocalThreatIntelRepository(ThreatIntelRepository):
    def __init__(self, *, db_path: Path, repository_dir: Path) -> None:
        self.db_path = db_path
        self.repository_dir = repository_dir
        self.repository_dir.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(db_path)
        self.connection.row_factory = sqlite3.Row
        self._init_schema()

    def publish_analysis(self, analysis: DocumentAnalysis) -> PublishResult:
        pdf_url = analysis.local_file_path
        self._write_payload("documents", analysis.document_id, document_payload(analysis, pdf_url=pdf_url))

        findings_count = 0
        memory_updates = 0
        for cve in analysis.cves:
            self._write_payload("findings", f"{analysis.document_id}_{cve.cve}", finding_payload(analysis, cve))
            self._upsert_memory(analysis, cve)
            findings_count += 1
            memory_updates += 1

        indicators = indicator_payloads(analysis)
        for indicator in indicators:
            self._write_payload("indicators", indicator["IndicatorID"], indicator)

        similar_documents = self._update_semantic_memory(analysis)
        self.connection.commit()
        LOGGER.info(
            "Local repository updated for %s: %s findings, %s indicators, %s memory updates",
            analysis.document_id,
            findings_count,
            len(indicators),
            memory_updates,
        )
        return PublishResult(
            backend="local",
            document_id=analysis.document_id,
            document_published=True,
            findings_published=findings_count,
            indicators_published=len(indicators),
            memory_updates=memory_updates,
            similar_documents=len(similar_documents),
            details={"repository_dir": str(self.repository_dir), "sqlite_db": str(self.db_path)},
        )

    def get_memory(self, memory_key: str) -> MemoryRecord | None:
        row = self.connection.execute(
            "SELECT * FROM threat_intel_memory WHERE memory_key = ?",
            (memory_key,),
        ).fetchone()
        return _memory_from_row(row) if row is not None else None

    def list_similar_documents(self, document_id: str) -> list[SimilarDocumentRecord]:
        rows = self.connection.execute(
            """
            SELECT current_document_id, similar_document_id, similarity_score, match_reason, created_date
            FROM similar_documents
            WHERE current_document_id = ?
            ORDER BY similarity_score DESC
            """,
            (document_id,),
        ).fetchall()
        return [
            SimilarDocumentRecord(
                current_document_id=row["current_document_id"],
                similar_document_id=row["similar_document_id"],
                similarity_score=float(row["similarity_score"]),
                match_reason=row["match_reason"],
                created_date=row["created_date"],
            )
            for row in rows
        ]

    def record_feedback(self, feedback: AnalystFeedbackRecord) -> None:
        self.connection.execute(
            """
            INSERT INTO analyst_feedback (
                feedback_id, finding_id, document_id, cve, analyst_email, analyst_name,
                previous_status, new_status, system_relevance, analyst_relevance,
                comment, decision, created_date
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                feedback.feedback_id,
                feedback.finding_id,
                feedback.document_id,
                feedback.cve,
                feedback.analyst_email,
                feedback.analyst_name,
                feedback.previous_status,
                feedback.new_status,
                feedback.system_relevance,
                feedback.analyst_relevance,
                feedback.comment,
                feedback.decision,
                feedback.created_date,
            ),
        )
        if feedback.cve:
            self.connection.execute(
                """
                UPDATE threat_intel_memory
                SET last_analyst_status = ?,
                    last_analyst_decision = ?,
                    last_analyst_comment = ?,
                    last_reviewed_date = ?,
                    updated_date = ?
                WHERE memory_key = ?
                """,
                (
                    feedback.new_status,
                    feedback.decision,
                    feedback.comment,
                    feedback.created_date,
                    _utc_now(),
                    memory_key_for_cve(feedback.cve),
                ),
            )
        self.connection.commit()

    def list_feedback(
        self,
        *,
        finding_id: str | None = None,
        cve: str | None = None,
    ) -> list[AnalystFeedbackRecord]:
        filters: list[str] = []
        params: list[str] = []
        if finding_id:
            filters.append("finding_id = ?")
            params.append(finding_id)
        if cve:
            filters.append("cve = ?")
            params.append(cve)
        where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
        rows = self.connection.execute(
            f"""
            SELECT feedback_id, finding_id, document_id, cve, analyst_email, analyst_name,
                   previous_status, new_status, system_relevance, analyst_relevance,
                   comment, decision, created_date
            FROM analyst_feedback
            {where_clause}
            ORDER BY created_date ASC
            """,
            params,
        ).fetchall()
        return [_feedback_from_row(row) for row in rows]

    def close(self) -> None:
        self.connection.close()

    def _init_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS threat_intel_memory (
                memory_id TEXT PRIMARY KEY,
                memory_type TEXT NOT NULL,
                memory_key TEXT NOT NULL UNIQUE,
                cve TEXT,
                technology TEXT,
                vendor TEXT,
                threat_name TEXT,
                first_seen_date TEXT NOT NULL,
                last_seen_date TEXT NOT NULL,
                times_seen INTEGER NOT NULL,
                previous_highest_relevance TEXT,
                previous_semantic_category TEXT,
                last_document_id TEXT,
                last_analyst_status TEXT,
                last_analyst_decision TEXT,
                last_analyst_comment TEXT,
                last_reviewed_date TEXT,
                internal_match TEXT,
                affected_asset_count INTEGER,
                updated_date TEXT
            );

            CREATE TABLE IF NOT EXISTS analyst_feedback (
                feedback_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                document_id TEXT NOT NULL,
                cve TEXT,
                analyst_email TEXT,
                analyst_name TEXT,
                previous_status TEXT,
                new_status TEXT,
                system_relevance TEXT,
                analyst_relevance TEXT,
                comment TEXT,
                decision TEXT,
                created_date TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS semantic_documents (
                document_id TEXT PRIMARY KEY,
                document_name TEXT NOT NULL,
                threat_name TEXT,
                processed_at TEXT NOT NULL,
                summary_text TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS semantic_chunks (
                chunk_id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                cve TEXT,
                chunk_text TEXT NOT NULL,
                embedding_model TEXT,
                created_date TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS similar_documents (
                current_document_id TEXT NOT NULL,
                similar_document_id TEXT NOT NULL,
                similarity_score REAL NOT NULL,
                match_reason TEXT NOT NULL,
                created_date TEXT NOT NULL,
                PRIMARY KEY (current_document_id, similar_document_id)
            );
            """
        )
        self.connection.commit()

    def _write_payload(self, collection: str, record_id: str, payload: dict[str, Any]) -> None:
        collection_dir = self.repository_dir / collection
        collection_dir.mkdir(parents=True, exist_ok=True)
        (collection_dir / f"{record_id}.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _upsert_memory(self, analysis: DocumentAnalysis, cve: CVEAnalysis) -> None:
        now = _utc_now()
        memory_key = memory_key_for_cve(cve.cve)
        existing = self.get_memory(memory_key)
        if existing is None:
            self.connection.execute(
                """
                INSERT INTO threat_intel_memory (
                    memory_id, memory_type, memory_key, cve, technology, vendor, threat_name,
                    first_seen_date, last_seen_date, times_seen, previous_highest_relevance,
                    previous_semantic_category, last_document_id, updated_date
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    memory_key,
                    "CVE",
                    memory_key,
                    cve.cve,
                    cve.technology,
                    cve.vendor,
                    analysis.threat_name,
                    analysis.processed_at,
                    analysis.processed_at,
                    1,
                    cve.document_relevance,
                    cve.semantic_category,
                    analysis.document_id,
                    now,
                ),
            )
            return

        highest = _higher_relevance(existing.previous_highest_relevance, cve.document_relevance)
        times_seen = existing.times_seen
        if existing.last_document_id != analysis.document_id:
            times_seen += 1
        self.connection.execute(
            """
            UPDATE threat_intel_memory
            SET technology = ?, vendor = ?, threat_name = ?, last_seen_date = ?,
                times_seen = ?, previous_highest_relevance = ?,
                previous_semantic_category = ?, last_document_id = ?, updated_date = ?
            WHERE memory_key = ?
            """,
            (
                cve.technology,
                cve.vendor,
                analysis.threat_name,
                analysis.processed_at,
                times_seen,
                highest,
                cve.semantic_category,
                analysis.document_id,
                now,
                memory_key,
            ),
        )

    def _update_semantic_memory(self, analysis: DocumentAnalysis) -> list[SimilarDocumentRecord]:
        summary = _analysis_summary(analysis)
        existing_rows = self.connection.execute(
            "SELECT document_id, document_name, summary_text FROM semantic_documents WHERE document_id != ?",
            (analysis.document_id,),
        ).fetchall()
        similar: list[SimilarDocumentRecord] = []
        now = _utc_now()
        for row in existing_rows:
            score = _text_similarity(summary, row["summary_text"])
            if score < 0.2:
                continue
            record = SimilarDocumentRecord(
                current_document_id=analysis.document_id,
                similar_document_id=row["document_id"],
                similarity_score=round(score, 4),
                match_reason=f"Shared semantic terms with {row['document_name']}",
                created_date=now,
            )
            similar.append(record)
            self.connection.execute(
                """
                INSERT OR REPLACE INTO similar_documents (
                    current_document_id, similar_document_id, similarity_score, match_reason, created_date
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.current_document_id,
                    record.similar_document_id,
                    record.similarity_score,
                    record.match_reason,
                    record.created_date,
                ),
            )

        self.connection.execute(
            """
            INSERT OR REPLACE INTO semantic_documents (
                document_id, document_name, threat_name, processed_at, summary_text
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (analysis.document_id, analysis.document_name, analysis.threat_name, analysis.processed_at, summary),
        )
        self.connection.execute("DELETE FROM semantic_chunks WHERE document_id = ?", (analysis.document_id,))
        for cve in analysis.cves:
            self.connection.execute(
                """
                INSERT INTO semantic_chunks (
                    chunk_id, document_id, cve, chunk_text, embedding_model, created_date
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    f"{analysis.document_id}_{cve.cve}",
                    analysis.document_id,
                    cve.cve,
                    cve.evidence_text,
                    "local-keyword-semantic",
                    now,
                ),
            )
        return sorted(similar, key=lambda item: item.similarity_score, reverse=True)[:5]


def _memory_from_row(row: sqlite3.Row) -> MemoryRecord:
    return MemoryRecord(
        memory_id=row["memory_id"],
        memory_type=row["memory_type"],
        memory_key=row["memory_key"],
        cve=row["cve"],
        technology=row["technology"],
        vendor=row["vendor"],
        threat_name=row["threat_name"],
        first_seen_date=row["first_seen_date"],
        last_seen_date=row["last_seen_date"],
        times_seen=int(row["times_seen"]),
        previous_highest_relevance=row["previous_highest_relevance"],
        previous_semantic_category=row["previous_semantic_category"],
        last_document_id=row["last_document_id"],
        last_analyst_status=row["last_analyst_status"],
        last_analyst_decision=row["last_analyst_decision"],
        last_analyst_comment=row["last_analyst_comment"],
        last_reviewed_date=row["last_reviewed_date"],
        internal_match=row["internal_match"],
        affected_asset_count=row["affected_asset_count"],
        updated_date=row["updated_date"],
    )


def _feedback_from_row(row: sqlite3.Row) -> AnalystFeedbackRecord:
    return AnalystFeedbackRecord(
        feedback_id=row["feedback_id"],
        finding_id=row["finding_id"],
        document_id=row["document_id"],
        cve=row["cve"],
        analyst_email=row["analyst_email"],
        analyst_name=row["analyst_name"],
        previous_status=row["previous_status"],
        new_status=row["new_status"],
        system_relevance=row["system_relevance"],
        analyst_relevance=row["analyst_relevance"],
        comment=row["comment"],
        decision=row["decision"],
        created_date=row["created_date"],
    )


def _higher_relevance(existing: str | None, current: str) -> str:
    if existing is None:
        return current
    return current if RELEVANCE_RANK.get(current, 0) > RELEVANCE_RANK.get(existing, 0) else existing


def _analysis_summary(analysis: DocumentAnalysis) -> str:
    parts = [
        analysis.document_name,
        analysis.threat_name or "",
        " ".join(analysis.indicators.mitre_techniques),
        " ".join(analysis.indicators.container_indicators),
        " ".join(cve.cve for cve in analysis.cves),
        " ".join(cve.technology for cve in analysis.cves),
        " ".join(cve.semantic_category for cve in analysis.cves),
        " ".join(cve.evidence_text for cve in analysis.cves),
    ]
    return " ".join(parts)


def _text_similarity(left: str, right: str) -> float:
    left_terms = _terms(left)
    right_terms = _terms(right)
    if not left_terms or not right_terms:
        return 0.0
    return len(left_terms.intersection(right_terms)) / len(left_terms.union(right_terms))


def _terms(text: str) -> set[str]:
    stopwords = {"the", "and", "for", "with", "this", "that", "from", "were", "was", "are"}
    return {term for term in re.findall(r"[a-z0-9-]{3,}", text.lower()) if term not in stopwords}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
