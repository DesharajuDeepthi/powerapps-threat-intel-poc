from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from src.models import DocumentAnalysis
from src.repository_models import (
    AnalystFeedbackRecord,
    MemoryRecord,
    PublishResult,
    SimilarDocumentRecord,
)


class ThreatIntelRepository(ABC):
    @abstractmethod
    def publish_analysis(self, analysis: DocumentAnalysis) -> PublishResult:
        raise NotImplementedError

    @abstractmethod
    def get_memory(self, memory_key: str) -> MemoryRecord | None:
        raise NotImplementedError

    @abstractmethod
    def list_similar_documents(self, document_id: str) -> list[SimilarDocumentRecord]:
        raise NotImplementedError

    @abstractmethod
    def record_feedback(self, feedback: AnalystFeedbackRecord) -> None:
        raise NotImplementedError

    @abstractmethod
    def list_feedback(
        self,
        *,
        finding_id: str | None = None,
        cve: str | None = None,
    ) -> list[AnalystFeedbackRecord]:
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError


def pdf_path_for_analysis(analysis: DocumentAnalysis) -> Path:
    return Path(analysis.local_file_path)
