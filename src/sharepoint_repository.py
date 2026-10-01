from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import msal
import requests

from src.config import AppConfig, ConfigError
from src.models import DocumentAnalysis
from src.repository import ThreatIntelRepository
from src.repository_models import (
    AnalystFeedbackRecord,
    MemoryRecord,
    PublishResult,
    SimilarDocumentRecord,
)
from src.repository_payloads import (
    document_payload,
    feedback_payload,
    finding_payload,
    indicator_payloads,
    memory_key_for_cve,
    memory_payload,
    similar_document_payload,
)

LOGGER = logging.getLogger(__name__)
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


class SharePointRepositoryError(RuntimeError):
    pass


class SharePointThreatIntelRepository(ThreatIntelRepository):
    def __init__(
        self,
        config: AppConfig,
        *,
        session: requests.Session | None = None,
        local_repository: ThreatIntelRepository | None = None,
    ) -> None:
        self.config = config
        self.local_repository = local_repository
        self._validate_config()
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self._access_token()}",
                "Accept": "application/json",
                "Prefer": "HonorNonIndexedQueriesWarningMayFailRandomly",
            }
        )

    def publish_analysis(self, analysis: DocumentAnalysis) -> PublishResult:
        local_result: PublishResult | None = None
        similar_records: list[SimilarDocumentRecord] = []
        if self.local_repository is not None:
            local_result = self.local_repository.publish_analysis(analysis)
            similar_records = self.local_repository.list_similar_documents(analysis.document_id)

        pdf_url = self._upload_pdf(Path(analysis.local_file_path), analysis)
        self._upsert_list_item_by_field(
            self.config.sp_documents_list_id,
            "DocumentID",
            analysis.document_id,
            document_payload(analysis, pdf_url=pdf_url),
        )

        findings_count = 0
        memory_updates = 0
        for cve in analysis.cves:
            payload = finding_payload(analysis, cve)
            self._upsert_list_item_by_field(
                self.config.sp_findings_list_id,
                "FindingID",
                payload["FindingID"],
                payload,
            )
            existing_memory = self.get_memory(memory_key_for_cve(cve.cve))
            self._upsert_list_item_by_field(
                self.config.sp_memory_list_id,
                "MemoryKey",
                memory_key_for_cve(cve.cve),
                memory_payload(analysis, cve, existing_memory),
            )
            findings_count += 1
            memory_updates += 1

        indicators = indicator_payloads(analysis)
        for indicator in indicators:
            self._upsert_list_item_by_field(
                self.config.sp_indicators_list_id,
                "IndicatorID",
                indicator["IndicatorID"],
                indicator,
            )

        similar_published = 0
        if self.config.sp_similar_documents_list_id:
            for similar_record in similar_records:
                payload = similar_document_payload(similar_record)
                self._upsert_list_item_by_field(
                    self.config.sp_similar_documents_list_id,
                    "SimilarityID",
                    payload["SimilarityID"],
                    payload,
                )
                similar_published += 1

        LOGGER.info("Published analysis %s to SharePoint", analysis.document_id)
        return PublishResult(
            backend="sharepoint",
            document_id=analysis.document_id,
            document_published=True,
            findings_published=findings_count,
            indicators_published=len(indicators),
            memory_updates=memory_updates,
            similar_documents=similar_published or (local_result.similar_documents if local_result else 0),
            details={"pdf_url": pdf_url},
        )

    def get_memory(self, memory_key: str) -> MemoryRecord | None:
        if not self.config.sp_memory_list_id:
            return self.local_repository.get_memory(memory_key) if self.local_repository else None

        item = self._get_list_item_by_field(self.config.sp_memory_list_id, "MemoryKey", memory_key)
        if item is None:
            return self.local_repository.get_memory(memory_key) if self.local_repository else None
        fields = item.get("fields", {})
        if not isinstance(fields, dict):
            return None
        return _memory_from_fields(fields)

    def list_similar_documents(self, document_id: str) -> list[SimilarDocumentRecord]:
        if self.local_repository is None:
            return []
        return self.local_repository.list_similar_documents(document_id)

    def record_feedback(self, feedback: AnalystFeedbackRecord) -> None:
        if self.local_repository is not None:
            self.local_repository.record_feedback(feedback)
        self._create_list_item(self.config.sp_feedback_list_id, feedback_payload(feedback))
        if feedback.cve:
            memory_item = self._get_list_item_by_field(
                self.config.sp_memory_list_id,
                "MemoryKey",
                memory_key_for_cve(feedback.cve),
            )
            if memory_item is not None:
                item_id = str(memory_item.get("id", ""))
                self._update_list_item_fields(
                    self.config.sp_memory_list_id,
                    item_id,
                    {
                        "LastAnalystStatus": feedback.new_status or "",
                        "LastAnalystDecision": feedback.decision or "",
                        "LastAnalystComment": feedback.comment or "",
                        "LastReviewedDate": feedback.created_date,
                        "UpdatedDate": feedback.created_date,
                    },
                )

    def list_feedback(
        self,
        *,
        finding_id: str | None = None,
        cve: str | None = None,
    ) -> list[AnalystFeedbackRecord]:
        if self.local_repository is not None:
            return self.local_repository.list_feedback(finding_id=finding_id, cve=cve)
        return []

    def close(self) -> None:
        if self.local_repository is not None:
            self.local_repository.close()
        self.session.close()

    def _validate_config(self) -> None:
        missing = [
            name
            for name, value in {
                "MS_TENANT_ID": self.config.ms_tenant_id,
                "MS_CLIENT_ID": self.config.ms_client_id,
                "MS_CLIENT_SECRET": self.config.ms_client_secret,
                "SHAREPOINT_SITE_ID": self.config.sharepoint_site_id,
                "SHAREPOINT_DOCUMENT_LIBRARY_ID": self.config.sharepoint_document_library_id,
                "SP_DOCUMENTS_LIST_ID": self.config.sp_documents_list_id,
                "SP_FINDINGS_LIST_ID": self.config.sp_findings_list_id,
                "SP_INDICATORS_LIST_ID": self.config.sp_indicators_list_id,
                "SP_MEMORY_LIST_ID": self.config.sp_memory_list_id,
                "SP_FEEDBACK_LIST_ID": self.config.sp_feedback_list_id,
            }.items()
            if not value
        ]
        if missing:
            raise ConfigError(
                "SharePoint backend requires these environment variables: " + ", ".join(missing)
            )

    def _access_token(self) -> str:
        app = msal.ConfidentialClientApplication(
            client_id=self.config.ms_client_id,
            client_credential=self.config.ms_client_secret,
            authority=f"https://login.microsoftonline.com/{self.config.ms_tenant_id}",
        )
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        token = result.get("access_token")
        if not token:
            error = result.get("error", "authentication_failed")
            description = result.get("error_description", "Microsoft Graph did not return an access token.")
            raise SharePointRepositoryError(f"{error}: {description}")
        return str(token)

    def _upload_pdf(self, path: Path, analysis: DocumentAnalysis) -> str:
        upload_name = f"{analysis.document_id}_{path.name}"
        url = (
            f"{GRAPH_BASE_URL}/drives/{self.config.sharepoint_document_library_id}"
            f"/root:/{upload_name}:/content"
        )
        response = self.session.put(url, data=path.read_bytes(), timeout=60)
        if response.status_code >= 400:
            raise SharePointRepositoryError(_graph_error(response))
        payload = response.json()
        web_url = payload.get("webUrl")
        return str(web_url or "")

    def _create_list_item(self, list_id: str | None, fields: dict[str, Any]) -> None:
        if not list_id:
            raise SharePointRepositoryError("SharePoint list id is not configured.")
        url = f"{GRAPH_BASE_URL}/sites/{self.config.sharepoint_site_id}/lists/{list_id}/items"
        response = self.session.post(url, json={"fields": fields}, timeout=30)
        if response.status_code >= 400:
            raise SharePointRepositoryError(_graph_error(response))

    def _upsert_list_item_by_field(
        self,
        list_id: str | None,
        key_field: str,
        key_value: str,
        fields: dict[str, Any],
    ) -> None:
        if not list_id:
            raise SharePointRepositoryError("SharePoint list id is not configured.")
        existing = self._get_list_item_by_field(list_id, key_field, key_value)
        if existing is None:
            self._create_list_item(list_id, fields)
            return

        item_id = str(existing.get("id", ""))
        if not item_id:
            raise SharePointRepositoryError("SharePoint returned an existing list item without an id.")
        self._update_list_item_fields(list_id, item_id, fields)

    def _get_list_item_by_field(
        self,
        list_id: str | None,
        key_field: str,
        key_value: str,
    ) -> dict[str, Any] | None:
        if not list_id:
            raise SharePointRepositoryError("SharePoint list id is not configured.")
        url = f"{GRAPH_BASE_URL}/sites/{self.config.sharepoint_site_id}/lists/{list_id}/items"
        response = self.session.get(
            url,
            params={
                "$expand": "fields",
                "$filter": f"fields/{key_field} eq '{_odata_string(key_value)}'",
                "$top": "1",
            },
            timeout=30,
        )
        if response.status_code >= 400:
            raise SharePointRepositoryError(_graph_error(response))
        payload = response.json()
        values = payload.get("value", []) if isinstance(payload, dict) else []
        if not values:
            return None
        item = values[0]
        return item if isinstance(item, dict) else None

    def _update_list_item_fields(
        self,
        list_id: str | None,
        item_id: str,
        fields: dict[str, Any],
    ) -> None:
        if not list_id:
            raise SharePointRepositoryError("SharePoint list id is not configured.")
        url = f"{GRAPH_BASE_URL}/sites/{self.config.sharepoint_site_id}/lists/{list_id}/items/{item_id}/fields"
        response = self.session.patch(url, json=fields, timeout=30)
        if response.status_code >= 400:
            raise SharePointRepositoryError(_graph_error(response))


def _graph_error(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return f"Microsoft Graph HTTP {response.status_code}: {error.get('code')} | {error.get('message')}"
    return f"Microsoft Graph HTTP {response.status_code}: {response.text[:300]}"


def _memory_from_fields(fields: dict[str, Any]) -> MemoryRecord:
    return MemoryRecord(
        memory_id=str(fields.get("MemoryID", "")),
        memory_type=str(fields.get("MemoryType", "CVE")),
        memory_key=str(fields.get("MemoryKey", "")),
        cve=_optional_str(fields.get("CVE")),
        technology=_optional_str(fields.get("Technology")),
        vendor=_optional_str(fields.get("Vendor")),
        threat_name=_optional_str(fields.get("ThreatName")),
        first_seen_date=str(fields.get("FirstSeenDate", "")),
        last_seen_date=str(fields.get("LastSeenDate", "")),
        times_seen=int(fields.get("TimesSeen") or 0),
        previous_highest_relevance=_optional_str(fields.get("PreviousHighestRelevance")),
        previous_semantic_category=_optional_str(fields.get("PreviousSemanticCategory")),
        last_document_id=_optional_str(fields.get("LastDocumentID")),
        last_analyst_status=_optional_str(fields.get("LastAnalystStatus")),
        last_analyst_decision=_optional_str(fields.get("LastAnalystDecision")),
        last_analyst_comment=_optional_str(fields.get("LastAnalystComment")),
        last_reviewed_date=_optional_str(fields.get("LastReviewedDate")),
        internal_match=_optional_str(fields.get("InternalMatch")),
        affected_asset_count=_optional_int(fields.get("AffectedAssetCount")),
        updated_date=_optional_str(fields.get("UpdatedDate")),
    )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


def _optional_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    return int(value)


def _odata_string(value: str) -> str:
    return value.replace("'", "''")
