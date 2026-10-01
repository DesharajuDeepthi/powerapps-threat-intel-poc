from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DocumentMetadata:
    document_id: str
    document_name: str
    local_file_path: str
    source: str
    slack_channel_id: str | None = None
    slack_message_id: str | None = None
    slack_message_timestamp: str | None = None
    slack_file_id: str | None = None
    slack_file_url: str | None = None
    downloaded_at: str | None = None


@dataclass(frozen=True)
class PdfPageText:
    page_number: int
    text: str


@dataclass(frozen=True)
class PdfExtractionResult:
    pages: list[PdfPageText]
    page_count: int
    character_count: int
    extraction_status: str
    error: str | None = None

    @property
    def full_text(self) -> str:
        return "\n".join(page.text for page in self.pages)


@dataclass(frozen=True)
class IndicatorSet:
    cves: list[str] = field(default_factory=list)
    ipv4: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    sha1: list[str] = field(default_factory=list)
    md5: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    container_indicators: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CveContext:
    cve: str
    page_number: int | None
    context: str


@dataclass(frozen=True)
class TechnologyAssociation:
    technology: str
    vendor: str
    association_evidence: str


@dataclass(frozen=True)
class CVEAnalysis:
    cve: str
    technology: str
    vendor: str
    page_number: int | None
    evidence_text: str
    semantic_scores: dict[str, float]
    semantic_category: str
    document_relevance: str
    analyst_comment: str
    technology_evidence: str = ""


@dataclass(frozen=True)
class DocumentAnalysis:
    document_id: str
    document_name: str
    local_file_path: str
    source: str
    slack_channel_id: str | None
    slack_message_id: str | None
    slack_message_timestamp: str | None
    slack_file_id: str | None
    slack_file_url: str | None
    downloaded_at: str | None
    processed_at: str
    pdf_sha256: str
    extraction_status: str
    page_count: int
    character_count: int
    threat_name: str | None
    indicators: IndicatorSet
    cves: list[CVEAnalysis]
    threat_evidence: str = ""
    threat_evidence_page_number: int | None = None
    processing_error: str | None = None


def dataclass_to_dict(value: Any) -> dict[str, Any]:
    return asdict(value)


def document_analysis_from_dict(data: dict[str, Any]) -> DocumentAnalysis:
    indicators = IndicatorSet(**data.get("indicators", {}))
    cves = [CVEAnalysis(**item) for item in data.get("cves", [])]
    return DocumentAnalysis(
        document_id=data["document_id"],
        document_name=data["document_name"],
        local_file_path=data["local_file_path"],
        source=data.get("source", "unknown"),
        slack_channel_id=data.get("slack_channel_id"),
        slack_message_id=data.get("slack_message_id"),
        slack_message_timestamp=data.get("slack_message_timestamp"),
        slack_file_id=data.get("slack_file_id"),
        slack_file_url=data.get("slack_file_url"),
        downloaded_at=data.get("downloaded_at"),
        processed_at=data["processed_at"],
        pdf_sha256=data["pdf_sha256"],
        extraction_status=data["extraction_status"],
        page_count=int(data.get("page_count", 0)),
        character_count=int(data.get("character_count", 0)),
        threat_name=data.get("threat_name"),
        indicators=indicators,
        cves=cves,
        threat_evidence=data.get("threat_evidence", ""),
        threat_evidence_page_number=data.get("threat_evidence_page_number"),
        processing_error=data.get("processing_error"),
    )


def path_to_document_id(path: Path) -> str:
    return path.stem
