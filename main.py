from __future__ import annotations

import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from src.analysis_pipeline import process_document
from src.analysis_store import load_all_analyses
from src.config import ConfigError, load_config
from src.excel_writer import append_threat_intel_records, refresh_document_analysis_sheet
from src.file_service import download_slack_pdf
from src.message_parser import parse_threat_intel_messages
from src.models import DocumentMetadata
from src.power_app_store import PowerAppStore, PowerAppStorePaths
from src.repository_factory import create_repository
from src.slack_client import SlackClient, SlackClientError
from src.slack_service import (
    channel_id,
    channel_display_name,
    enrich_message_sender_details,
    extract_pdf_duplicate_sightings,
    extract_pdf_files,
    find_channel_by_name,
    get_channel_messages,
    get_channels,
    validate_slack_auth,
)


def configure_logging(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"slack-threat-intel-{datetime.now(timezone.utc).date().isoformat()}.log"

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    formatter.converter = time.gmtime

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)


def main() -> int:
    try:
        config = load_config()
        configure_logging(config.log_dir)
        logging.info("Starting Slack Threat Intelligence POC PDF download milestone")

        slack_client = SlackClient(config.slack_bot_token)
        auth_info = validate_slack_auth(slack_client)
        channels = get_channels(slack_client)
        target_channel = find_channel_by_name(channels, config.slack_channel_name)

        print("Slack authentication successful.", flush=True)
        workspace = auth_info.get("team")
        bot_user = auth_info.get("user")
        if workspace:
            print(f"Workspace: {workspace}", flush=True)
        if bot_user:
            print(f"Bot user: {bot_user}", flush=True)

        print("Available Slack channels:", flush=True)
        if channels:
            for channel in channels:
                print(f"- {channel_display_name(channel)}", flush=True)
        else:
            print("- No channels returned for this bot token.", flush=True)

        if target_channel is None:
            logging.error("Target Slack channel not found: #%s", config.slack_channel_name)
            return 1

        print(f"Target Slack channel found: {channel_display_name(target_channel)}", flush=True)
        target_channel_id = channel_id(target_channel)
        if target_channel_id is None:
            logging.error("Target Slack channel is missing an id")
            return 1

        messages = enrich_message_sender_details(
            slack_client,
            get_channel_messages(slack_client, target_channel_id),
        )
        threat_records = parse_threat_intel_messages(messages)
        excel_result = append_threat_intel_records(threat_records, config.output_file)
        pdf_duplicate_sightings = extract_pdf_duplicate_sightings(messages)
        phase1_memory_updates = publish_phase_one_memory(
            threat_records,
            target_channel_id=target_channel_id,
            repository_dir=config.local_repository_dir,
            sqlite_db_path=config.sqlite_db_path,
            download_dir=config.download_dir,
        )
        duplicate_events_added = publish_pdf_duplicate_sightings(
            pdf_duplicate_sightings,
            target_channel_id=target_channel_id,
            repository_dir=config.local_repository_dir,
            sqlite_db_path=config.sqlite_db_path,
            download_dir=config.download_dir,
        )
        pdf_files = extract_pdf_files(messages)

        print(f"Slack channel messages retrieved: {len(messages)}", flush=True)
        print(f"Structured threat messages parsed: {excel_result.records_seen}", flush=True)
        print(f"Excel rows added: {excel_result.rows_added}", flush=True)
        print(f"Excel rows already present: {excel_result.rows_skipped}", flush=True)
        print(f"Excel workbook: {excel_result.output_file}", flush=True)
        print(f"Phase 1 Slack memory records updated: {phase1_memory_updates}", flush=True)
        print(f"Duplicate Slack PDF sightings found: {len(pdf_duplicate_sightings)}", flush=True)
        print(f"New duplicate events stored: {duplicate_events_added}", flush=True)
        print(f"PDF files discovered: {len(pdf_files)}", flush=True)

        if not pdf_files:
            print("No PDF files found in the target Slack channel history.", flush=True)
            refresh_document_analysis_sheet(load_all_analyses(config.analysis_results_dir), config.output_file)
            logging.info("Slack PDF discovery milestone completed with no PDFs")
            return 0

        downloaded_count = 0
        skipped_count = 0
        analyzed_count = 0
        repository = create_repository(config)
        try:
            for pdf_file in pdf_files:
                result = download_slack_pdf(slack_client, pdf_file, config.download_dir)
                if result.downloaded:
                    downloaded_count += 1
                    print(f"Downloaded PDF: {result.path}", flush=True)
                else:
                    skipped_count += 1
                    print(f"Already downloaded PDF: {result.path}", flush=True)

                metadata = DocumentMetadata(
                    document_id=f"slack_{pdf_file.file_id}",
                    document_name=pdf_file.name,
                    local_file_path=str(result.path),
                    source="slack",
                    slack_channel_id=target_channel_id,
                    slack_message_id=pdf_file.message_ts,
                    slack_message_timestamp=pdf_file.message_ts,
                    slack_file_id=pdf_file.file_id,
                    slack_file_url=pdf_file.url_private_download,
                    downloaded_at=datetime.now(timezone.utc).isoformat(),
                )
                analysis = process_document(metadata, result.path, config)
                publish_result = repository.publish_analysis(analysis)
                logging.info(
                    "Published %s via %s repository: %s findings, %s indicators, %s memory updates",
                    analysis.document_id,
                    publish_result.backend,
                    publish_result.findings_published,
                    publish_result.indicators_published,
                    publish_result.memory_updates,
                )
                analyzed_count += 1
        finally:
            repository.close()

        refresh_document_analysis_sheet(load_all_analyses(config.analysis_results_dir), config.output_file)
        print(f"New PDFs downloaded: {downloaded_count}", flush=True)
        print(f"PDFs already present: {skipped_count}", flush=True)
        print(f"PDFs analyzed: {analyzed_count}", flush=True)
        logging.info("Slack PDF discovery and download milestone completed")
        return 0
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr, flush=True)
        return 2
    except SlackClientError as exc:
        logging.error("Slack API request failed: %s", exc)
        return 1
    except KeyboardInterrupt:
        logging.warning("Authentication cancelled by user")
        return 130
    except Exception:
        logging.exception("Unexpected application error")
        return 1


def publish_phase_one_memory(
    threat_records: list,
    *,
    target_channel_id: str,
    repository_dir: Path,
    sqlite_db_path: Path,
    download_dir: Path,
) -> int:
    store = PowerAppStore(
        PowerAppStorePaths(
            repository_dir=repository_dir,
            sqlite_db_path=sqlite_db_path,
            downloads_dir=download_dir,
        )
    )
    try:
        updates = 0
        for record in threat_records:
            results = store.submit_slack_threat_record(record, slack_channel_id=target_channel_id)
            updates += sum(1 for result in results if result.get("created"))
        return updates
    finally:
        store.close()


def publish_pdf_duplicate_sightings(
    sightings: list,
    *,
    target_channel_id: str,
    repository_dir: Path,
    sqlite_db_path: Path,
    download_dir: Path,
) -> int:
    if not sightings:
        return 0

    store = PowerAppStore(
        PowerAppStorePaths(
            repository_dir=repository_dir,
            sqlite_db_path=sqlite_db_path,
            downloads_dir=download_dir,
        )
    )
    try:
        added = 0
        for sighting in sightings:
            result = store.record_duplicate_event(
                {
                    "EventType": "SLACK_PDF_RESEEN",
                    "Title": "Slack PDF was seen again",
                    "DocumentID": f"slack_{sighting.file_id}",
                    "DocumentName": sighting.name,
                    "SlackFileID": sighting.file_id,
                    "FirstSlackMessageID": sighting.first_message_ts,
                    "DuplicateSlackMessageID": sighting.duplicate_message_ts,
                    "SlackMessageID": sighting.duplicate_message_ts,
                    "SlackChannelID": target_channel_id,
                    "MatchReason": sighting.match_reason,
                    "Reason": "Slack history contains another message for a PDF that was already seen.",
                }
            )
            added += int(bool(result.get("created")))
        return added
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
