# Slack Threat Intelligence POC

A Dockerized Python proof of concept for reading threat-intelligence messages and PDFs from Slack,
extracting PDF evidence, classifying CVE relevance, writing Excel exports, and publishing structured
memory for Power Apps through SharePoint.

Power Apps is the target analyst UI. The existing Streamlit app is retained as an optional local debug UI.

## Architecture Overview

```mermaid
flowchart LR
    A["Slack Channel<br/>PDFs + analyst notes"] --> B["Dockerized Python Ingestion"]
    B --> C["PDF Analysis<br/>CVEs, technologies, threats, evidence"]
    B --> D["Structured Slack Notes<br/>analyst, document, comments"]
    C --> E["Local Semantic Memory<br/>SQLite + similarity history"]
    C --> F["Structured Repository<br/>documents, findings, indicators"]
    D --> F
    E --> G["Duplicate / Related Repeat Detection"]
    F --> H["Power Apps-Style Local UI<br/>dashboard, documents, findings, phase 1 memory"]
    G --> H
    F -. "future production target" .-> I["SharePoint Lists<br/>Power Apps data source"]
    I -.-> J["Power Apps<br/>analyst review workflow"]
```

The local POC keeps the same shape as the planned production flow: Slack feeds Python, Python stores structured
memory, and analysts review document history, findings, evidence, duplicate activity, and comments through a
Power Apps-style experience. Today the repository backend can run locally; later the same payloads can publish to
SharePoint lists for a real Power Apps implementation.

## Prerequisites

Install only:

- Docker Desktop
- A Slack workspace
- A Slack app with a Bot User OAuth Token

You do not need Python, pip, virtualenv, PyMuPDF, openpyxl, or Streamlit on the host machine.

## Slack App Setup

Open [https://api.slack.com/apps](https://api.slack.com/apps), create an app, then add these **Bot Token Scopes** under **OAuth & Permissions**:

```text
channels:read
channels:history
files:read
```

For private channels, also add:

```text
groups:read
groups:history
```

Optional, for showing the Slack sender's real/display name in Phase 1 memory:

```text
users:read
```

Without `users:read`, the app still works and stores the Slack user ID as the analyst name.

Install or reinstall the app, copy the `xoxb-` bot token, and invite the bot to the target channel:

```text
/invite @your-bot-name
```

## Configure Environment

```bash
cp .env.example .env
```

Set:

```text
SLACK_BOT_TOKEN=xoxb-your-token
SLACK_CHANNEL_NAME=feedly-threat-intel
```

Important optional settings:

```text
STORAGE_BACKEND=local
LOCAL_REPOSITORY_DIR=/app/data/local_repository
SQLITE_DB_PATH=/app/data/threat_intel.db
SEMANTIC_HIGH_THRESHOLD=0.75
SEMANTIC_REVIEW_THRESHOLD=0.55
ENABLE_SENTENCE_TRANSFORMER=false
```

The default semantic scorer is local and deterministic. The code has an optional sentence-transformer hook, but the default Docker image avoids pulling heavy torch/CUDA dependencies.

## Run Ingestion

```bash
docker compose build
docker compose run --rm app
```

This will:

- Connect to Slack.
- Read the configured channel.
- Parse structured Slack messages into the `Slack Messages` Excel sheet.
- Download PDF attachments into `downloads/`.
- Extract PDF text with PyMuPDF.
- Extract CVEs, IPs, URLs, domains, hashes, MITRE techniques, and container indicators.
- Capture CVE evidence windows with page numbers.
- Capture the exact PDF evidence used to identify threat names and affected technologies.
- Classify CVE relevance using local semantic intent scoring.
- Associate nearby technologies when supported by CVE context.
- Save structured JSON results in `data/results/`.
- Update local SQLite semantic memory at `data/threat_intel.db`.
- Write local repository payloads under `data/local_repository/` when `STORAGE_BACKEND=local`.
- Refresh the `Document Analysis` Excel sheet with PDF hyperlinks.

## Power Apps and SharePoint

Power Apps reads from SharePoint lists. Python publishes document metadata, findings, indicators,
memory, and analyst feedback payloads through the repository abstraction.

Use local development storage by default:

```text
STORAGE_BACKEND=local
```

Use SharePoint publishing after creating the lists and Microsoft Graph app registration:

```text
STORAGE_BACKEND=sharepoint
MS_TENANT_ID=
MS_CLIENT_ID=
MS_CLIENT_SECRET=
SHAREPOINT_SITE_ID=
SHAREPOINT_DOCUMENT_LIBRARY_ID=
SP_DOCUMENTS_LIST_ID=
SP_FINDINGS_LIST_ID=
SP_INDICATORS_LIST_ID=
SP_MEMORY_LIST_ID=
SP_FEEDBACK_LIST_ID=
SP_SIMILAR_DOCUMENTS_LIST_ID=
```

See [docs/POWER_APPS_SETUP.md](/Users/deepthidesharaju/Documents/POC/teams-threat-intel-poc/docs/POWER_APPS_SETUP.md) for SharePoint columns, Power Apps screens, and Power Fx examples.

## Optional Streamlit Debug UI

```bash
docker compose up -d ui
```

Open:

[http://localhost:8501](http://localhost:8501)

The debug UI reads the same saved JSON results used for Excel. It includes:

- Dashboard metrics.
- Document analysis details.
- CVE evidence expanders.
- Search/filter history.
- Manual PDF upload.
- Reanalyze document action.

Stop the UI:

```bash
docker compose stop ui
```

## Power Apps-Style Local Prototype

If you do not have a work/school Microsoft account yet, run the local Power Apps-style prototype:

```bash
docker compose up -d powerapp
```

Open:

[http://localhost:8601](http://localhost:8601)

This prototype uses the same local payloads and SQLite memory that SharePoint would receive. It stays close to
Power Apps patterns: dashboard cards, galleries, filters, detail screens, tabs, dropdown choices, comments, and
Patch-like analyst actions.

The `Phase 1` page is for manual on-call knowledge capture before full PDF automation:

- show structured notes captured from Slack;
- see whether the document or CVE was previously seen;
- see when Slack re-shares a PDF that was already captured;
- review first seen, last seen, times seen, status, decision, and comments;
- preserve note history instead of relying on Slack message history.

Stop it:

```bash
docker compose stop powerapp
```

## Structured Slack Message Format

Optional structured Slack messages should use one field per line:

```text
Document: aa22-321a_joint_csa_stopransomware_hive.pdf
Threat: Hive Ransomware
Impacted Technology: FortiOS, Microsoft Exchange
CVE Count: 5
CVE: CVE-2020-12812; CVE-2021-31207; CVE-2021-34473; CVE-2021-34523; CVE-2021-42321
```

Each Slack message with a `Document:` field becomes one row in the `Slack Messages` worksheet. PDF analysis writes one row per document+CVE in the `Document Analysis` worksheet.

## Persistent Folders

Docker Compose bind-mounts these folders:

- `downloads/` original PDFs
- `documents/` reserved local document workspace
- `output/` Excel workbook
- `logs/` application logs
- `data/results/` structured analysis JSON
- `data/threat_intel.db` local SQLite semantic memory
- `data/local_repository/` local Power Apps-compatible payloads
- `data/model_cache/` optional local embedding model cache

## Run Tests

```bash
docker compose run --rm app pytest
```

## Debugging

```bash
docker compose build --no-cache
docker compose run --rm app
docker compose logs ui
docker compose logs app
```

If Slack discovery fails, check:

- `.env` contains `SLACK_BOT_TOKEN` and `SLACK_CHANNEL_NAME`.
- The token starts with `xoxb-`.
- The Slack app has the required scopes.
- The bot has been invited to the channel.
- You reinstalled the app after changing scopes.
