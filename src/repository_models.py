from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MemoryRecord:
    memory_id: str
    memory_type: str
    memory_key: str
    cve: str | None
    technology: str | None
    vendor: str | None
    threat_name: str | None
    first_seen_date: str
    last_seen_date: str
    times_seen: int
    previous_highest_relevance: str | None
    previous_semantic_category: str | None
    last_document_id: str | None
    last_analyst_status: str | None = None
    last_analyst_decision: str | None = None
    last_analyst_comment: str | None = None
    last_reviewed_date: str | None = None
    internal_match: str | None = None
    affected_asset_count: int | None = None
    updated_date: str | None = None


@dataclass(frozen=True)
class SimilarDocumentRecord:
    current_document_id: str
    similar_document_id: str
    similarity_score: float
    match_reason: str
    created_date: str


@dataclass(frozen=True)
class AnalystFeedbackRecord:
    feedback_id: str
    finding_id: str
    document_id: str
    cve: str | None
    analyst_email: str | None
    analyst_name: str | None
    previous_status: str | None
    new_status: str | None
    system_relevance: str | None
    analyst_relevance: str | None
    comment: str | None
    decision: str | None
    created_date: str


@dataclass(frozen=True)
class PublishResult:
    backend: str
    document_id: str
    document_published: bool
    findings_published: int
    indicators_published: int
    memory_updates: int
    similar_documents: int
    details: dict[str, Any]
