from __future__ import annotations

from pathlib import Path

import pytest

from src.config import load_config
from src.local_repository import LocalThreatIntelRepository
from src.repository_factory import create_repository


def test_repository_factory_uses_local_backend_by_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-valid-token")
    monkeypatch.setenv("SLACK_CHANNEL_NAME", "feedly-threat-intel")
    monkeypatch.setenv("DOWNLOAD_DIR", str(tmp_path / "downloads"))
    monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "output" / "findings.xlsx"))
    monkeypatch.setenv("PROCESSED_FILES_PATH", str(tmp_path / "data" / "processed_files.json"))
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("ANALYSIS_RESULTS_DIR", str(tmp_path / "data" / "results"))
    monkeypatch.setenv("LOCAL_REPOSITORY_DIR", str(tmp_path / "data" / "local_repository"))
    monkeypatch.setenv("SQLITE_DB_PATH", str(tmp_path / "data" / "threat_intel.db"))
    monkeypatch.delenv("STORAGE_BACKEND", raising=False)

    config = load_config(env_file=None)
    repository = create_repository(config)

    assert isinstance(repository, LocalThreatIntelRepository)
    repository.close()
