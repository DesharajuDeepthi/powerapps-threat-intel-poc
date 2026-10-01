from __future__ import annotations

from pathlib import Path

import pytest

from src.config import ConfigError, load_config


def test_load_config_requires_slack_bot_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    monkeypatch.setenv("SLACK_CHANNEL_NAME", "feedly-threat-intel")
    monkeypatch.setenv("DOWNLOAD_DIR", str(tmp_path / "downloads"))
    monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "output" / "findings.xlsx"))
    monkeypatch.setenv("PROCESSED_FILES_PATH", str(tmp_path / "data" / "processed_files.json"))
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))

    with pytest.raises(ConfigError, match="SLACK_BOT_TOKEN is required"):
        load_config(env_file=None)


def test_load_config_creates_docker_path_directories(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-valid-token")
    monkeypatch.setenv("SLACK_CHANNEL_NAME", "#feedly-threat-intel")
    monkeypatch.setenv("DOWNLOAD_DIR", str(tmp_path / "downloads"))
    monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "output" / "findings.xlsx"))
    monkeypatch.setenv("PROCESSED_FILES_PATH", str(tmp_path / "data" / "processed_files.json"))
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))

    config = load_config(env_file=None)

    assert config.slack_bot_token == "xoxb-valid-token"
    assert config.slack_channel_name == "feedly-threat-intel"
    assert config.download_dir.is_dir()
    assert config.output_file.parent.is_dir()
    assert config.processed_files_path.parent.is_dir()
    assert config.log_dir.is_dir()


def test_load_config_rejects_non_bot_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SLACK_BOT_TOKEN", "not-a-bot-token")
    monkeypatch.setenv("SLACK_CHANNEL_NAME", "feedly-threat-intel")
    monkeypatch.setenv("DOWNLOAD_DIR", str(tmp_path / "downloads"))
    monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "output" / "findings.xlsx"))
    monkeypatch.setenv("PROCESSED_FILES_PATH", str(tmp_path / "data" / "processed_files.json"))
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))

    with pytest.raises(ConfigError, match="starting with xoxb-"):
        load_config(env_file=None)
