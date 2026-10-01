from __future__ import annotations

import json
from pathlib import Path

from src.models import DocumentAnalysis, dataclass_to_dict, document_analysis_from_dict


def analysis_path(results_dir: Path, document_id: str) -> Path:
    return results_dir / f"{document_id}.json"


def save_analysis(analysis: DocumentAnalysis, results_dir: Path) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    path = analysis_path(results_dir, analysis.document_id)
    path.write_text(json.dumps(dataclass_to_dict(analysis), indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_analysis(results_dir: Path, document_id: str) -> DocumentAnalysis | None:
    path = analysis_path(results_dir, document_id)
    if not path.exists():
        return None
    return document_analysis_from_dict(json.loads(path.read_text(encoding="utf-8")))


def load_all_analyses(results_dir: Path) -> list[DocumentAnalysis]:
    if not results_dir.exists():
        return []

    analyses: list[DocumentAnalysis] = []
    for path in sorted(results_dir.glob("*.json")):
        try:
            analyses.append(document_analysis_from_dict(json.loads(path.read_text(encoding="utf-8"))))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            continue
    return analyses
