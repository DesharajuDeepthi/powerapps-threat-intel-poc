from __future__ import annotations

from src.config import AppConfig
from src.local_repository import LocalThreatIntelRepository
from src.repository import ThreatIntelRepository
from src.sharepoint_repository import SharePointThreatIntelRepository


def create_repository(config: AppConfig) -> ThreatIntelRepository:
    local_repository = LocalThreatIntelRepository(
        db_path=config.sqlite_db_path,
        repository_dir=config.local_repository_dir,
    )
    if config.storage_backend == "sharepoint":
        try:
            return SharePointThreatIntelRepository(config, local_repository=local_repository)
        except Exception:
            local_repository.close()
            raise
    return local_repository
