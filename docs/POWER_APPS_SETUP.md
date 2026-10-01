# Power Apps Setup

This guide turns the Python Slack threat-intelligence pipeline into a Power Apps analyst workflow.
Python keeps doing the PDF, IOC, CVE, semantic, Excel, and memory processing. Power Apps only presents
SharePoint data and captures analyst decisions.

## Architecture

```text
Slack
  -> Python Docker processing
  -> PDF extraction, IOC/CVE extraction, semantic scoring
  -> SQLite semantic memory at /app/data/threat_intel.db
  -> SharePoint document library and lists
  -> Power Apps Canvas app
  -> Analyst feedback saved back to SharePoint
```

Historical memory is context only. It must not override the current document evidence or current relevance
classification produced by Python.

## Required SharePoint Assets

Create one SharePoint Document Library:

| Name | Purpose |
| --- | --- |
| `ThreatIntelDocuments` | Stores original PDF files uploaded by the Python pipeline. |

Create these SharePoint Lists:

| Name | Purpose |
| --- | --- |
| `ThreatIntelDocuments` | One row per processed PDF/advisory. |
| `ThreatIntelFindings` | One row per document and CVE. |
| `ThreatIntelIndicators` | One row per extracted IOC. |
| `ThreatIntelMemory` | One row per remembered CVE or technology memory key. |
| `AnalystFeedback` | Append-only analyst action history. |
| `ThreatIntelSimilarDocuments` | Optional display of similar previous advisories. |

After creation, collect the site ID, document library drive ID, and list IDs. Put those values in `.env`.

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

## Document Library Metadata

The Python pipeline uploads each PDF using a stable filename based on `DocumentID`. The list record stores
the link in `PDFUrl`, so Power Apps can open the original file.

Recommended library columns:

| Column | Type |
| --- | --- |
| `DocumentID` | Single line of text |
| `DocumentName` | Single line of text |
| `SlackFileID` | Single line of text |
| `SlackMessageID` | Single line of text |
| `ReceivedDate` | Date and time |
| `ProcessedDate` | Date and time |
| `ThreatName` | Single line of text |
| `ProcessingStatus` | Choice |

## List Schemas

Use these names as SharePoint column display names. If SharePoint creates different internal names, adjust
the Power Fx formulas to match the internal names shown in list settings.

### ThreatIntelDocuments

| Column | Type |
| --- | --- |
| `DocumentID` | Single line of text, indexed |
| `DocumentName` | Single line of text |
| `SlackFileID` | Single line of text |
| `SlackMessageID` | Single line of text |
| `SlackMessageDate` | Date and time |
| `ThreatName` | Single line of text |
| `ThreatEvidence` | Multiple lines of text |
| `ThreatEvidencePageNumber` | Number or Single line of text |
| `Source` | Choice |
| `ReceivedDate` | Date and time |
| `ProcessedDate` | Date and time |
| `ProcessingStatus` | Choice |
| `DocumentRelevance` | Choice: `HIGH`, `REVIEW`, `INFORMATIONAL` |
| `HighFindingCount` | Number |
| `ReviewFindingCount` | Number |
| `InformationalFindingCount` | Number |
| `CVECount` | Number |
| `IPCount` | Number |
| `DomainCount` | Number |
| `HashCount` | Number |
| `PDFUrl` | Hyperlink or Single line of text |
| `LocalFileName` | Single line of text |
| `FileHash` | Single line of text |
| `CreatedByPipeline` | Yes/No |

### ThreatIntelFindings

| Column | Type |
| --- | --- |
| `FindingID` | Single line of text, indexed |
| `DocumentID` | Single line of text, indexed |
| `CVE` | Single line of text, indexed |
| `Technology` | Single line of text |
| `Vendor` | Single line of text |
| `TechnologyEvidence` | Multiple lines of text |
| `PageNumber` | Number or Single line of text |
| `SemanticCategory` | Single line of text |
| `DocumentRelevance` | Choice: `HIGH`, `REVIEW`, `INFORMATIONAL` |
| `ActiveExploitationScore` | Number |
| `InitialAccessScore` | Number |
| `RemoteCodeExecutionScore` | Number |
| `PrivilegeEscalationScore` | Number |
| `AuthenticationBypassScore` | Number |
| `BackgroundReferenceScore` | Number |
| `EvidenceText` | Multiple lines of text |
| `SuggestedAnalystComment` | Multiple lines of text |
| `Status` | Choice |
| `AssignedTo` | Person or Single line of text |
| `CreatedDate` | Date and time |
| `UpdatedDate` | Date and time |

Status choices:

```text
New
Review Required
Under Review
Reviewed
Action Required
Informational
Closed
False Positive
Not Applicable
Remediated
```

### ThreatIntelIndicators

| Column | Type |
| --- | --- |
| `IndicatorID` | Single line of text, indexed |
| `DocumentID` | Single line of text, indexed |
| `IndicatorType` | Choice |
| `IndicatorValue` | Single line of text |
| `NormalizedValue` | Single line of text |
| `PageNumber` | Number or Single line of text |
| `EvidenceText` | Multiple lines of text |
| `FirstSeenDate` | Date and time |
| `LastSeenDate` | Date and time |

Indicator type choices:

```text
IP
Domain
URL
SHA256
SHA1
MD5
MITRE
ContainerImage
```

### ThreatIntelMemory

| Column | Type |
| --- | --- |
| `MemoryID` | Single line of text |
| `MemoryType` | Choice: `CVE`, `Technology` |
| `MemoryKey` | Single line of text, indexed |
| `CVE` | Single line of text |
| `Technology` | Single line of text |
| `Vendor` | Single line of text |
| `ThreatName` | Single line of text |
| `FirstSeenDate` | Date and time |
| `LastSeenDate` | Date and time |
| `TimesSeen` | Number |
| `PreviousHighestRelevance` | Choice: `HIGH`, `REVIEW`, `INFORMATIONAL` |
| `PreviousSemanticCategory` | Single line of text |
| `LastDocumentID` | Single line of text |
| `LastAnalystStatus` | Choice |
| `LastAnalystDecision` | Choice |
| `LastAnalystComment` | Multiple lines of text |
| `LastReviewedDate` | Date and time |
| `InternalMatch` | Single line of text |
| `AffectedAssetCount` | Number |
| `UpdatedDate` | Date and time |

### AnalystFeedback

| Column | Type |
| --- | --- |
| `FeedbackID` | Single line of text, indexed |
| `FindingID` | Single line of text, indexed |
| `DocumentID` | Single line of text, indexed |
| `CVE` | Single line of text, indexed |
| `AnalystEmail` | Single line of text |
| `AnalystName` | Single line of text |
| `PreviousStatus` | Choice |
| `NewStatus` | Choice |
| `SystemRelevance` | Choice: `HIGH`, `REVIEW`, `INFORMATIONAL` |
| `AnalystRelevance` | Choice: `HIGH`, `REVIEW`, `INFORMATIONAL` |
| `Comment` | Multiple lines of text |
| `Decision` | Choice |
| `CreatedDate` | Date and time |

Decision choices:

```text
Agree With System
Override Relevance
Investigate
Action Required
False Positive
Not Applicable
Informational
Remediated
```

### ThreatIntelSimilarDocuments

| Column | Type |
| --- | --- |
| `SimilarityID` | Single line of text, indexed |
| `CurrentDocumentID` | Single line of text, indexed |
| `SimilarDocumentID` | Single line of text |
| `SimilarityScore` | Number |
| `MatchReason` | Multiple lines of text |
| `CreatedDate` | Date and time |

## Power Apps Data Sources

Create a Canvas app and add these SharePoint data sources:

```text
ThreatIntelDocuments
ThreatIntelFindings
ThreatIntelIndicators
ThreatIntelMemory
AnalystFeedback
ThreatIntelSimilarDocuments
```

## Screens

### Dashboard

Suggested controls:

| Control | Data |
| --- | --- |
| Documents Processed card | `CountRows(ThreatIntelDocuments)` |
| High Attention card | Count HIGH findings |
| Review Required card | Count open review findings |
| CVEs Detected card | Count findings |
| Analyst Actions card | Count feedback records |
| Recent documents gallery | Latest documents by processed date |

Example formulas:

```powerfx
CountRows(ThreatIntelDocuments)
```

```powerfx
CountRows(Filter(ThreatIntelFindings, DocumentRelevance.Value = "HIGH"))
```

```powerfx
SortByColumns(ThreatIntelDocuments, "ProcessedDate", Descending)
```

Document gallery `OnSelect`:

```powerfx
Set(varSelectedDocument, ThisItem);
Navigate(scrDocumentDetails)
```

### Documents

Gallery `Items` example:

```powerfx
SortByColumns(
    Filter(
        ThreatIntelDocuments,
        IsBlank(ddStatus.Selected.Value) || ProcessingStatus.Value = ddStatus.Selected.Value,
        IsBlank(ddRelevance.Selected.Value) || DocumentRelevance.Value = ddRelevance.Selected.Value,
        IsBlank(txtSearch.Text) ||
            txtSearch.Text in DocumentName ||
            txtSearch.Text in ThreatName
    ),
    "ProcessedDate",
    Descending
)
```

### Document Details

Header fields:

```text
varSelectedDocument.DocumentName
varSelectedDocument.ThreatName
varSelectedDocument.ThreatEvidence
varSelectedDocument.ThreatEvidencePageNumber
varSelectedDocument.ReceivedDate
varSelectedDocument.ProcessedDate
varSelectedDocument.ProcessingStatus
```

Open PDF button `OnSelect`:

```powerfx
Launch(varSelectedDocument.PDFUrl)
```

Findings gallery:

```powerfx
Filter(ThreatIntelFindings, DocumentID = varSelectedDocument.DocumentID)
```

Indicators gallery:

```powerfx
Filter(ThreatIntelIndicators, DocumentID = varSelectedDocument.DocumentID)
```

Similar advisories gallery:

```powerfx
Filter(ThreatIntelSimilarDocuments, CurrentDocumentID = varSelectedDocument.DocumentID)
```

Feedback gallery:

```powerfx
Filter(AnalystFeedback, DocumentID = varSelectedDocument.DocumentID)
```

### Findings

Gallery `Items` example:

```powerfx
SortByColumns(
    Filter(
        ThreatIntelFindings,
        IsBlank(ddFindingStatus.Selected.Value) || Status.Value = ddFindingStatus.Selected.Value,
        IsBlank(ddFindingRelevance.Selected.Value) || DocumentRelevance.Value = ddFindingRelevance.Selected.Value,
        IsBlank(txtFindingSearch.Text) ||
            txtFindingSearch.Text in CVE ||
            txtFindingSearch.Text in Technology ||
            txtFindingSearch.Text in Vendor
    ),
    "UpdatedDate",
    Descending
)
```

Finding gallery `OnSelect`:

```powerfx
Set(varSelectedFinding, ThisItem);
Set(varSelectedMemory, LookUp(ThreatIntelMemory, MemoryKey = ThisItem.CVE));
Navigate(scrFindingDetails)
```

### Finding Details

Display current evidence:

```text
varSelectedFinding.CVE
varSelectedFinding.Technology
varSelectedFinding.TechnologyEvidence
varSelectedFinding.Vendor
varSelectedFinding.DocumentRelevance
varSelectedFinding.SemanticCategory
varSelectedFinding.EvidenceText
varSelectedFinding.SuggestedAnalystComment
```

Display historical memory:

```powerfx
If(IsBlank(varSelectedMemory), "No", "Yes")
```

```powerfx
Coalesce(varSelectedMemory.TimesSeen, 0)
```

```powerfx
varSelectedMemory.FirstSeenDate
varSelectedMemory.LastSeenDate
varSelectedMemory.LastAnalystDecision
varSelectedMemory.LastAnalystComment
```

## Analyst Action Formulas

Use dropdowns for status, analyst relevance, and decision.

Status dropdown `Items`:

```powerfx
["New", "Review Required", "Under Review", "Reviewed", "Action Required", "Informational", "Closed", "False Positive", "Not Applicable", "Remediated"]
```

Relevance dropdown `Items`:

```powerfx
["HIGH", "REVIEW", "INFORMATIONAL"]
```

Decision dropdown `Items`:

```powerfx
["Agree With System", "Override Relevance", "Investigate", "Action Required", "False Positive", "Not Applicable", "Informational", "Remediated"]
```

Submit button `OnSelect` example:

```powerfx
Set(varNow, Now());

Patch(
    ThreatIntelFindings,
    varSelectedFinding,
    {
        Status: {Value: ddStatus.Selected.Value},
        DocumentRelevance: {Value: ddAnalystRelevance.Selected.Value},
        AssignedTo: User().Email,
        UpdatedDate: varNow
    }
);

Patch(
    AnalystFeedback,
    Defaults(AnalystFeedback),
    {
        FeedbackID: GUID(),
        FindingID: varSelectedFinding.FindingID,
        DocumentID: varSelectedFinding.DocumentID,
        CVE: varSelectedFinding.CVE,
        AnalystEmail: User().Email,
        AnalystName: User().FullName,
        PreviousStatus: varSelectedFinding.Status,
        NewStatus: {Value: ddStatus.Selected.Value},
        SystemRelevance: varSelectedFinding.DocumentRelevance,
        AnalystRelevance: {Value: ddAnalystRelevance.Selected.Value},
        Comment: txtAnalystComment.Text,
        Decision: {Value: ddDecision.Selected.Value},
        CreatedDate: varNow
    }
);

Patch(
    ThreatIntelMemory,
    LookUp(ThreatIntelMemory, MemoryKey = varSelectedFinding.CVE),
    {
        LastAnalystStatus: {Value: ddStatus.Selected.Value},
        LastAnalystDecision: {Value: ddDecision.Selected.Value},
        LastAnalystComment: txtAnalystComment.Text,
        LastReviewedDate: varNow,
        UpdatedDate: varNow
    }
);

Refresh(ThreatIntelFindings);
Refresh(AnalystFeedback);
Refresh(ThreatIntelMemory);
Set(varSelectedFinding, LookUp(ThreatIntelFindings, FindingID = varSelectedFinding.FindingID));
Set(varSelectedMemory, LookUp(ThreatIntelMemory, MemoryKey = varSelectedFinding.CVE));
```

If `AssignedTo` is a Person column instead of text, configure a People picker and adapt the Patch payload to
your tenant's Person field shape.

## Refresh Behavior

Use `Refresh(...)` after analyst actions and on screen visible events where stale data would be confusing.

Example `scrDashboard.OnVisible`:

```powerfx
Refresh(ThreatIntelDocuments);
Refresh(ThreatIntelFindings);
Refresh(AnalystFeedback)
```

Example `scrDocumentDetails.OnVisible`:

```powerfx
Refresh(ThreatIntelFindings);
Refresh(ThreatIntelIndicators);
Refresh(ThreatIntelSimilarDocuments)
```

## Permissions

Recommended SharePoint permissions:

| Role | Permission |
| --- | --- |
| Python pipeline app registration | Write to document library and lists. Read memory and feedback. |
| Analysts | Read all lists. Edit `ThreatIntelFindings`, `AnalystFeedback`, and `ThreatIntelMemory` summary fields. |
| Viewers | Read-only access. |

Security notes:

- Do not store Slack tokens, Graph tokens, client secrets, or refresh tokens in SharePoint.
- Keep secrets in `.env` or your deployment secret store.
- Restrict the document library if PDFs contain sensitive advisory data.
- Consider SharePoint list versioning for auditability.

## Docker Verification

Local semantic memory survives rebuilds because Docker Compose bind-mounts `./data` to `/app/data`.

```bash
docker compose config >/tmp/teams-threat-intel-compose.txt
docker compose build
docker compose run --rm app pytest
docker compose run --rm app
```

After a run, local development mode should contain:

```text
data/threat_intel.db
data/local_repository/documents/
data/local_repository/findings/
data/local_repository/indicators/
```

In SharePoint mode, the same run should also publish PDFs and structured rows to the configured SharePoint
library and lists.
