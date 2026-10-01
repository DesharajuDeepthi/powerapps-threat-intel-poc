from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(ValueError):
    """Raised when required application configuration is missing or invalid."""


@dataclass(frozen=True)
class AppConfig:
    slack_bot_token: str
    slack_channel_name: str
    download_dir: Path
    output_file: Path
    processed_files_path: Path
    log_dir: Path
    analysis_results_dir: Path
    local_repository_dir: Path
    sqlite_db_path: Path
    semantic_high_threshold: float
    semantic_review_threshold: float
    embedding_model_name: str
    enable_sentence_transformer: bool
    storage_backend: str
    ms_tenant_id: str | None
    ms_client_id: str | None
    ms_client_secret: str | None
    sharepoint_site_id: str | None
    sharepoint_document_library_id: str | None
    sp_documents_list_id: str | None
    sp_findings_list_id: str | None
    sp_indicators_list_id: str | None
    sp_memory_list_id: str | None
    sp_feedback_list_id: str | None
    sp_similar_documents_list_id: str | None


def load_config(env_file: str | Path | None = ".env") -> AppConfig:
    if env_file is not None:
        load_dotenv(dotenv_path=env_file, override=False)

    slack_bot_token = _required_env("SLACK_BOT_TOKEN")
    if not slack_bot_token.startswith("xoxb-"):
        raise ConfigError("SLACK_BOT_TOKEN must be a Slack Bot User OAuth Token starting with xoxb-.")

    slack_channel_name = _required_env("SLACK_CHANNEL_NAME").lstrip("#")

    download_dir = _path_env("DOWNLOAD_DIR", "/app/downloads")
    output_file = _path_env("OUTPUT_FILE", "/app/output/Threat_Intelligence_Findings.xlsx")
    processed_files_path = _path_env("PROCESSED_FILES_PATH", "/app/data/processed_files.json")
    log_dir = _path_env("LOG_DIR", "/app/logs")
    analysis_results_dir = _path_env("ANALYSIS_RESULTS_DIR", "/app/data/results")
    local_repository_dir = _path_env("LOCAL_REPOSITORY_DIR", "/app/data/local_repository")
    sqlite_db_path = _path_env("SQLITE_DB_PATH", "/app/data/threat_intel.db")
    storage_backend = os.getenv("STORAGE_BACKEND", "local").strip().lower() or "local"
    if storage_backend not in {"local", "sharepoint"}:
        raise ConfigError("STORAGE_BACKEND must be either local or sharepoint.")

    _create_required_directories(
        download_dir,
        output_file.parent,
        processed_files_path.parent,
        log_dir,
        analysis_results_dir,
        local_repository_dir,
        sqlite_db_path.parent,
    )

    return AppConfig(
        slack_bot_token=slack_bot_token,
        slack_channel_name=slack_channel_name,
        download_dir=download_dir,
        output_file=output_file,
        processed_files_path=processed_files_path,
        log_dir=log_dir,
        analysis_results_dir=analysis_results_dir,
        local_repository_dir=local_repository_dir,
        sqlite_db_path=sqlite_db_path,
        semantic_high_threshold=_float_env("SEMANTIC_HIGH_THRESHOLD", 0.75),
        semantic_review_threshold=_float_env("SEMANTIC_REVIEW_THRESHOLD", 0.55),
        embedding_model_name=os.getenv("EMBEDDING_MODEL_NAME", "all-MiniLM-L6-v2").strip()
        or "all-MiniLM-L6-v2",
        enable_sentence_transformer=_bool_env("ENABLE_SENTENCE_TRANSFORMER", False),
        storage_backend=storage_backend,
        ms_tenant_id=_optional_env("MS_TENANT_ID"),
        ms_client_id=_optional_env("MS_CLIENT_ID"),
        ms_client_secret=_optional_env("MS_CLIENT_SECRET"),
        sharepoint_site_id=_optional_env("SHAREPOINT_SITE_ID"),
        sharepoint_document_library_id=_optional_env("SHAREPOINT_DOCUMENT_LIBRARY_ID"),
        sp_documents_list_id=_optional_env("SP_DOCUMENTS_LIST_ID"),
        sp_findings_list_id=_optional_env("SP_FINDINGS_LIST_ID"),
        sp_indicators_list_id=_optional_env("SP_INDICATORS_LIST_ID"),
        sp_memory_list_id=_optional_env("SP_MEMORY_LIST_ID"),
        sp_feedback_list_id=_optional_env("SP_FEEDBACK_LIST_ID"),
        sp_similar_documents_list_id=_optional_env("SP_SIMILAR_DOCUMENTS_LIST_ID"),
    )


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigError(
            f"{name} is required. Create .env from .env.example and set {name}, "
            "or pass it as an environment variable to Docker Compose."
        )
    return value


def _path_env(name: str, default: str) -> Path:
    raw_value = os.getenv(name, default).strip() or default
    return Path(raw_value).expanduser()


def _optional_env(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


def _float_env(name: str, default: float) -> float:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default
    try:
        return float(raw_value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number.") from exc


def _bool_env(name: str, default: bool) -> bool:
    raw_value = os.getenv(name, "").strip().lower()
    if not raw_value:
        return default
    return raw_value in {"1", "true", "yes", "on"}


def _create_required_directories(*directories: Path) -> None:
    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ConfigError(f"Could not create required directory {directory}: {exc}") from exc
