# Power Apps-Style Prototype

This local web app is a temporary demo for environments where a work/school Microsoft account is not available.
It uses the same data shapes planned for SharePoint lists.

## Run

```bash
docker compose up -d powerapp
```

Open:

```text
http://localhost:8601
```

## Power Apps Mapping

| Prototype feature | Power Apps equivalent |
| --- | --- |
| Phase 1 on-call intake | Edit form writing to `ThreatIntelDocuments` and `AnalystFeedback` or an `OnCallMemory` list |
| Previously seen banner | `LookUp` or `Filter` against SharePoint memory lists |
| Manual memory register | Gallery bound to the manual/on-call SharePoint list |
| Dashboard cards | Labels over SharePoint list counts |
| Documents list | Gallery bound to `ThreatIntelDocuments` |
| Search and dropdowns | `Search` and `Filter` formulas |
| Document details | Display form bound to selected gallery item |
| Findings list | Gallery bound to `ThreatIntelFindings` |
| Finding details | Display form plus `LookUp(ThreatIntelMemory, MemoryKey = CVE)` |
| Tabs | Button/variable controlled containers |
| Status/relevance/decision controls | Dropdown controls with fixed choice values |
| Submit review | `Patch(ThreatIntelFindings, ...)` and `Patch(AnalystFeedback, Defaults(...), ...)` |
| Open PDF | `Launch(PDFUrl)` |

## Phase 1 View

The Phase 1 page represents the manual process before automated PDF analysis is trusted end to end.
Normal intake comes from structured Slack messages such as:

```text
Today findings:
Document: aa22-321a_joint_csa_stopransomware_hive.pdf
Threat: Hive Ransomware
Impacted Technology: FortiOS, Microsoft Exchange
CVE Count: 5
CVE: CVE-2020-12812; CVE-2021-31207; CVE-2021-34473; CVE-2021-34523; CVE-2021-42321
```

The sender is stored as the analyst/support name. If the Slack app has `users:read`, the app resolves the
sender's real/display name. Otherwise it stores the Slack user ID.

It shows:

- document name, threat, CVE, technology, source, status, and decision;
- first seen, last seen, and times seen;
- latest on-call note;
- append-only note history;
- previous records for the same document or CVE.

When a support person saves the same document/CVE again, the memory row is updated and a new note is appended.
That matches the future SharePoint/Power Apps pattern:

```powerfx
Patch(OnCallMemory, ...)
Patch(AnalystFeedback, Defaults(AnalystFeedback), ...)
```

## Boundaries

The prototype intentionally avoids features that would not translate cleanly to Power Apps:

- No custom canvas rendering.
- No browser-only drag and drop.
- No client-side vector search.
- No custom authentication flow.
- No workflow that requires a server-only UI feature.

Python still performs semantic analysis and memory updates. Power Apps should only present data and capture analyst
actions.
