const state = {
  documents: [],
  findings: [],
  onCallRecords: [],
  onCallNotes: [],
  duplicateEvents: [],
  selectedDocumentId: "",
  selectedFindingId: "",
  selectedOnCallRecordId: "",
  dateFilter: {
    mode: "all",
    date: "",
    month: ""
  }
};

const statusChoices = [
  "New",
  "Review Required",
  "Under Review",
  "Reviewed",
  "Action Required",
  "Closed"
];

const relevanceChoices = ["HIGH", "REVIEW", "INFORMATIONAL"];
const decisionChoices = [
  "Agree With System",
  "Override Relevance",
  "Investigate",
  "Action Required",
  "False Positive",
  "Not Applicable",
  "Informational",
  "Remediated"
];

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".nav-button").forEach((button) => {
    button.addEventListener("click", () => showScreen(button.dataset.screen, true));
  });
  document.getElementById("refreshButton").addEventListener("click", refreshAll);
  ["dateFilterMode", "dateFilterDate", "dateFilterMonth"].forEach((id) => {
    document.getElementById(id).addEventListener("input", updateDateFilter);
  });
  ["documentSearch", "documentRelevance", "documentStatus"].forEach((id) => {
    document.getElementById(id).addEventListener("input", renderDocumentsGallery);
  });
  ["findingSearch", "findingRelevance", "findingStatus"].forEach((id) => {
    document.getElementById(id).addEventListener("input", renderFindingsGallery);
  });
  ["onCallSearch", "onCallStatus"].forEach((id) => {
    document.getElementById(id).addEventListener("input", renderOnCallRecordsGallery);
  });
  ["onCallDocumentName", "onCallCve"].forEach((id) => {
    document.getElementById(id).addEventListener("input", checkOnCallHistory);
  });
  document.getElementById("onCallDocumentName").addEventListener("change", updateOnCallDocumentMapping);
  document.getElementById("onCallForm").addEventListener("submit", submitOnCallEntry);
  const initialScreen = window.location.hash.replace("#", "") || "dashboard";
  showScreen(initialScreen);
  refreshAll();
});

async function refreshAll() {
  const [summary, documents, findings, onCallRecords, onCallNotes, duplicateEvents] = await Promise.all([
    getJson("/api/summary"),
    getJson("/api/documents"),
    getJson("/api/findings"),
    getJson("/api/on-call"),
    getJson("/api/on-call-notes"),
    getJson("/api/duplicates")
  ]);
  state.documents = documents;
  state.findings = findings;
  state.onCallRecords = onCallRecords;
  state.onCallNotes = onCallNotes;
  state.duplicateEvents = duplicateEvents;
  renderSummary(summary);
  renderOnCallDocumentOptions();
  renderDocumentsGallery();
  renderFindingsGallery();
  renderOnCallRecordsGallery();
  renderDuplicateEvents();
  renderOpenFindings();
}

function showScreen(screenId, updateHash = false) {
  const validScreens = new Set(["phase1", "dashboard", "documents", "findings"]);
  if (!validScreens.has(screenId)) {
    screenId = "dashboard";
  }
  if (updateHash) {
    window.location.hash = screenId;
  }
  document.querySelectorAll(".nav-button").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.screen === screenId);
  });
  document.querySelectorAll(".screen").forEach((screen) => {
    screen.classList.toggle("is-visible", screen.id === screenId);
  });
  const titles = {
    phase1: ["Phase 1", "Slack-captured on-call notes and previous-review memory"],
    dashboard: ["Dashboard", "Slack PDF analysis and analyst review"],
    documents: ["Documents", "Gallery, filters, details, indicators, similar advisories"],
    findings: ["Findings", "CVE review, historical memory, analyst actions"]
  };
  document.getElementById("screenTitle").textContent = titles[screenId][0];
  document.getElementById("screenSubtitle").textContent = titles[screenId][1];
}

function updateDateFilter() {
  state.dateFilter = {
    mode: valueOf("dateFilterMode"),
    date: valueOf("dateFilterDate"),
    month: valueOf("dateFilterMonth")
  };
  document.getElementById("specificDateWrap").classList.toggle("is-hidden", state.dateFilter.mode !== "date");
  document.getElementById("specificMonthWrap").classList.toggle("is-hidden", state.dateFilter.mode !== "customMonth");
  renderSummary({});
  renderDocumentsGallery();
  renderFindingsGallery();
  renderOnCallRecordsGallery();
  renderDuplicateEvents();
  renderOpenFindings();
}

function filteredDocuments() {
  return state.documents.filter((documentData) => matchesDateFilter(documentDate(documentData)));
}

function filteredFindings() {
  return state.findings.filter((finding) => matchesDateFilter(findingDate(finding)));
}

function filteredOnCallRecords() {
  return state.onCallRecords.filter((record) => matchesDateFilter(onCallRecordDate(record)));
}

function filteredOnCallNotes() {
  return state.onCallNotes.filter((note) => matchesDateFilter(note.CreatedDate));
}

function filteredDuplicateEvents() {
  return state.duplicateEvents.filter((event) => matchesDateFilter(duplicateEventDate(event)));
}

function matchesDateFilter(value) {
  if (state.dateFilter.mode === "all") return true;
  const date = dateKey(value);
  if (!date) return false;
  if (state.dateFilter.mode === "today") return date === todayKey();
  if (state.dateFilter.mode === "yesterday") return date === offsetDateKey(-1);
  if (state.dateFilter.mode === "month") return date.startsWith(todayKey().slice(0, 7));
  if (state.dateFilter.mode === "date") return Boolean(state.dateFilter.date) && date === state.dateFilter.date;
  if (state.dateFilter.mode === "customMonth") return Boolean(state.dateFilter.month) && date.startsWith(state.dateFilter.month);
  return true;
}

function documentDate(documentData) {
  return documentData.SlackMessageDate || documentData.ReceivedDate || documentData.ProcessedDate;
}

function findingDate(finding) {
  return finding.UpdatedDate || finding.CreatedDate;
}

function onCallRecordDate(record) {
  return record.LastSeenDate || record.UpdatedDate || record.CreatedDate || record.FirstSeenDate;
}

function duplicateEventDate(event) {
  return event.LastDetectedDate || event.FirstDetectedDate;
}

function dateKey(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  if (/^\d{4}-\d{2}-\d{2}/.test(text)) return text.slice(0, 10);
  const date = new Date(text);
  if (Number.isNaN(date.getTime())) return "";
  return localDateKey(date);
}

function todayKey() {
  return localDateKey(new Date());
}

function offsetDateKey(offsetDays) {
  const date = new Date();
  date.setDate(date.getDate() + offsetDays);
  return localDateKey(date);
}

function localDateKey(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function renderSummary(summary) {
  const scopedDocuments = filteredDocuments();
  const scopedFindings = filteredFindings();
  const scopedRecords = filteredOnCallRecords();
  const scopedDuplicateEvents = filteredDuplicateEvents();
  const scopedActions = scopedFindings.filter((finding) => finding.UpdatedDate && finding.UpdatedDate !== finding.CreatedDate);
  const openStatuses = new Set(["Review Required", "Under Review", "Action Required"]);

  document.getElementById("metricDocuments").textContent = scopedDocuments.length;
  document.getElementById("metricHigh").textContent = scopedFindings.filter((item) => item.DocumentRelevance === "HIGH").length;
  document.getElementById("metricReview").textContent = scopedFindings.filter((item) => openStatuses.has(item.Status)).length;
  document.getElementById("metricCves").textContent = new Set(scopedFindings.map((item) => item.CVE).filter(Boolean)).size;
  document.getElementById("metricOnCall").textContent = scopedRecords.length;
  document.getElementById("metricDuplicates").textContent = scopedDuplicateEvents.length;
  document.getElementById("metricActions").textContent = scopedActions.length;
  setTextIfPresent("metricTodayDocuments", scopedDocuments.length);
  setTextIfPresent("metricTodayDuplicates", scopedDuplicateEvents.length);
  setTextIfPresent(
    "metricRelatedRepeats",
    scopedDuplicateEvents.filter((event) => event.EventType === "RELATED_DOCUMENT_RESEEN").length
  );
  setTextIfPresent("metricManualInputs", filteredOnCallNotes().length);

  const gallery = document.getElementById("recentDocumentsGallery");
  gallery.replaceChildren(...scopedDocuments.slice(0, 8).map((document) => documentCard(document)));
}

function renderDuplicateEvents() {
  const gallery = document.getElementById("duplicateEventsGallery");
  if (!gallery) return;
  const events = filteredDuplicateEvents();
  if (!events.length) {
    gallery.innerHTML = `<div class="detail-empty">No re-seen Slack items yet</div>`;
    return;
  }
  gallery.replaceChildren(...events.slice(0, 10).map((event) => {
    const row = document.createElement("div");
    row.className = "list-row";
    row.innerHTML = `
      <strong>${escapeHtml(event.DocumentName || event.Title || "Slack item")}</strong>
      <div class="muted">${escapeHtml(event.Reason || event.MatchReason || "")}</div>
      <div class="pill-row">
        ${pill(duplicateEventLabel(event.EventType))}
        ${event.CVE ? pill(event.CVE) : ""}
        ${event.Technology ? pill(event.Technology) : ""}
        ${event.TimesObserved ? pill(`${event.TimesObserved} observed`) : ""}
        ${pill(dateOnly(event.LastDetectedDate))}
      </div>
    `;
    return row;
  }));
}

function renderOpenFindings() {
  const openStatuses = new Set(["Review Required", "Under Review", "Action Required"]);
  const rows = filteredFindings()
    .filter((finding) => openStatuses.has(finding.Status))
    .slice(0, 8)
    .map((finding) => {
      const button = document.createElement("button");
      button.className = "list-row";
      button.innerHTML = `
        <strong>${escapeHtml(finding.CVE)}</strong>
        <div class="muted">${escapeHtml(finding.Technology || "Unknown technology")}</div>
        <div class="pill-row">${pill(finding.DocumentRelevance)}${pill(finding.Status)}</div>
      `;
      button.addEventListener("click", () => {
        showScreen("findings");
        selectFinding(finding.FindingID);
      });
      return button;
    });
  document.getElementById("openFindingsGallery").replaceChildren(...rows);
}

function renderDocumentsGallery() {
  const search = valueOf("documentSearch").toLowerCase();
  const relevance = valueOf("documentRelevance");
  const status = valueOf("documentStatus");
  const documents = filteredDocuments().filter((document) => {
    const text = `${document.DocumentName} ${document.ThreatName} ${document.Source}`.toLowerCase();
    return (!search || text.includes(search)) &&
      (!relevance || document.DocumentRelevance === relevance) &&
      (!status || document.ProcessingStatus === status);
  });
  const cards = documents.map((document) => documentCard(document));
  document.getElementById("documentsGallery").replaceChildren(...cards);
}

function renderFindingsGallery() {
  const search = valueOf("findingSearch").toLowerCase();
  const relevance = valueOf("findingRelevance");
  const status = valueOf("findingStatus");
  const findings = filteredFindings().filter((finding) => {
    const text = `${finding.CVE} ${finding.Technology} ${finding.Vendor}`.toLowerCase();
    return (!search || text.includes(search)) &&
      (!relevance || finding.DocumentRelevance === relevance) &&
      (!status || finding.Status === status);
  });
  const cards = findings.map((finding) => findingCard(finding));
  document.getElementById("findingsGallery").replaceChildren(...cards);
}

function renderOnCallRecordsGallery() {
  const search = valueOf("onCallSearch").toLowerCase();
  const status = valueOf("onCallStatus");
  const groups = groupOnCallRecordsByDocument(filteredOnCallRecords()).filter((group) => {
    const text = `${group.documentName} ${group.threatName} ${group.cves.join(" ")} ${group.technologies.join(" ")}`.toLowerCase();
    return (!search || text.includes(search)) && (!status || group.status === status);
  });
  document.getElementById("onCallRecordsGallery").replaceChildren(
    ...groups.map((group) => onCallDocumentCard(group))
  );
}

function onCallDocumentCard(group) {
  const button = document.createElement("button");
  button.className = "gallery-card";
  button.classList.toggle("is-selected", state.selectedOnCallRecordId === group.documentName);
  button.innerHTML = `
    <span class="eyebrow">${escapeHtml(dateOnly(group.lastSeenDate) || group.source || "Slack")}</span>
    <strong>${escapeHtml(group.documentName)}</strong>
    <span class="muted">${escapeHtml(group.threatName || group.technologies.join(", "))}</span>
    <span class="pill-row">
      ${pill(group.status)}${pill(`${group.recordCount} CVE rows`)}${pill(`${group.totalSeen} notes`)}
    </span>
  `;
  button.addEventListener("click", () => selectOnCallDocument(group.documentName));
  return button;
}

function groupOnCallRecordsByDocument(records) {
  const grouped = new Map();
  records.forEach((record) => {
    const documentName = record.DocumentName || "Unknown document";
    const group = grouped.get(documentName) || {
      documentName,
      records: [],
      cves: [],
      technologies: [],
      threatName: "",
      source: "",
      status: "",
      lastSeenDate: "",
      firstSeenDate: "",
      totalSeen: 0,
      recordCount: 0
    };
    group.records.push(record);
    if (record.CVE && !group.cves.includes(record.CVE)) group.cves.push(record.CVE);
    if (record.Technology && !group.technologies.includes(record.Technology)) group.technologies.push(record.Technology);
    if (!group.threatName && record.ThreatName) group.threatName = record.ThreatName;
    if (!group.source && record.Source) group.source = record.Source;
    if (!group.firstSeenDate || String(record.FirstSeenDate || "") < group.firstSeenDate) group.firstSeenDate = record.FirstSeenDate || "";
    if (!group.lastSeenDate || String(record.LastSeenDate || "") > group.lastSeenDate) {
      group.lastSeenDate = record.LastSeenDate || "";
      group.status = record.Status || group.status;
    }
    group.totalSeen += Number(record.TimesSeen || 1);
    group.recordCount = group.records.length;
    grouped.set(documentName, group);
  });
  return Array.from(grouped.values()).sort((a, b) => String(b.lastSeenDate).localeCompare(String(a.lastSeenDate)));
}

async function selectOnCallDocument(documentName) {
  state.selectedOnCallRecordId = documentName;
  renderOnCallRecordsGallery();
  const records = filteredOnCallRecords().filter((record) => record.DocumentName === documentName);
  const details = await Promise.all(records.map((record) => getJson(`/api/on-call/${encodeURIComponent(record.RecordID)}`)));
  renderOnCallDocumentDetail(documentName, details);
}

async function selectOnCallRecord(recordId) {
  state.selectedOnCallRecordId = recordId;
  renderOnCallRecordsGallery();
  const detail = await getJson(`/api/on-call/${encodeURIComponent(recordId)}`);
  renderOnCallDetail(detail);
}

function renderOnCallDetail(detail) {
  const record = detail.record;
  const root = document.getElementById("onCallDetail");
  root.className = "detail";
  root.innerHTML = `
    <div class="detail-header">
      <div>
        <h2>${escapeHtml(record.DocumentName)}</h2>
        <p class="muted">${escapeHtml(record.ThreatName || record.Technology || record.CVE || "")}</p>
      </div>
      <span class="pill-row">${pill(record.Status)}${pill(record.Decision)}</span>
    </div>
    <div class="fields-grid">
      ${field("CVE", record.CVE)}
      ${field("Technology", record.Technology)}
      ${field("Times Seen", record.TimesSeen || 1)}
      ${field("First Seen", dateOnly(record.FirstSeenDate))}
      ${field("Last Seen", dateOnly(record.LastSeenDate))}
      ${field("Analyst", record.LastAnalystName || record.LastAnalystEmail)}
    </div>
    ${tabs([
      ["Latest", `<div class="evidence">${escapeHtml(record.LastComment || "No comment")}</div>`],
      ["History", renderOnCallNotes(detail.notes)],
      ["Previous", renderOnCallMatches(detail.matches, record.RecordID)]
    ])}
  `;
  activateTabs(root);
}

function renderOnCallDocumentDetail(documentName, details) {
  const records = details.map((detail) => detail.record);
  const allNotes = details
    .flatMap((detail) => detail.notes)
    .filter((note) => matchesDateFilter(note.CreatedDate));
  const newest = records
    .slice()
    .sort((a, b) => String(b.LastSeenDate || "").localeCompare(String(a.LastSeenDate || "")))[0] || {};
  const cves = uniqueValues(records.map((record) => record.CVE).filter(Boolean));
  const technologies = uniqueValues(records.map((record) => record.Technology).filter(Boolean));
  const root = document.getElementById("onCallDetail");
  root.className = "detail";
  root.innerHTML = `
    <div class="detail-header">
      <div>
        <h2>${escapeHtml(documentName)}</h2>
        <p class="muted">${escapeHtml(newest.ThreatName || technologies.join(", ") || "Document-level memory")}</p>
      </div>
      <span class="pill-row">${pill(newest.Status)}${pill(newest.Decision)}</span>
    </div>
    <div class="fields-grid">
      ${field("First Seen", dateOnly(minValue(records.map((record) => record.FirstSeenDate))))}
      ${field("Last Seen", dateOnly(maxValue(records.map((record) => record.LastSeenDate))))}
      ${field("CVEs", cves.length || "None")}
      ${field("Notes", allNotes.length)}
      ${field("Analyst", newest.LastAnalystName || newest.LastAnalystEmail)}
      ${field("Technology", technologies.join(", "))}
    </div>
    ${tabs([
      ["Notes", renderOnCallNotes(allNotes)],
      ["CVEs", renderDocumentMemoryCves(records)],
      ["Previous", renderDocumentMemoryPrevious(records, documentName)]
    ])}
  `;
  activateTabs(root);
}

function renderDocumentMemoryCves(records) {
  const cveRows = records.filter((record) => record.CVE);
  if (!cveRows.length) return `<div class="detail-empty">No CVE was captured for this document</div>`;
  return cveRows.map((record) => `
    <div class="list-row">
      <strong>${escapeHtml(record.CVE)}</strong>
      <div class="muted">${escapeHtml(record.Technology || record.ThreatName || "")}</div>
      <div class="pill-row">${pill(record.Status)}${pill(`${record.TimesSeen || 1} seen`)}</div>
    </div>
  `).join("");
}

function renderDocumentMemoryPrevious(records, documentName) {
  const totalSeen = records.reduce((sum, record) => sum + Number(record.TimesSeen || 1), 0);
  const relatedEvents = filteredDuplicateEvents().filter((event) => event.DocumentName === documentName);
  const relatedHtml = relatedEvents.length
    ? relatedEvents.map((event) => `
      <div class="list-row">
        <strong>${escapeHtml(duplicateEventLabel(event.EventType))}</strong>
        <div class="muted">${escapeHtml(event.Reason || event.MatchReason || "")}</div>
        <div class="pill-row">
          ${event.CVE ? pill(event.CVE) : ""}
          ${event.Technology ? pill(event.Technology) : ""}
          ${event.TimesObserved ? pill(`${event.TimesObserved} observed`) : ""}
          ${pill(dateOnly(event.LastDetectedDate))}
        </div>
      </div>
    `).join("")
    : `<div class="detail-empty">No duplicate or related repeat flags for this document</div>`;
  return `
    <div class="fields-grid">
      ${field("Document Rows", records.length)}
      ${field("Total Notes", totalSeen)}
      ${field("Current Status", records[0]?.Status || "")}
      ${field("Last Decision", records[0]?.Decision || "")}
    </div>
    ${relatedHtml}
  `;
}

function renderOnCallNotes(notes) {
  if (!notes.length) return `<div class="detail-empty">No notes</div>`;
  return notes.map((note) => `
    <div class="list-row">
      <strong>${escapeHtml(note.Decision || note.NewStatus || "On-call note")}</strong>
      <div class="muted">${escapeHtml(note.AnalystName || note.AnalystEmail || "Support")} ${dateOnly(note.CreatedDate)}</div>
      <div class="pill-row">${pill(note.NewStatus)}${note.PreviousStatus ? pill(`was ${note.PreviousStatus}`) : ""}</div>
      <p>${escapeHtml(note.Comment || "")}</p>
    </div>
  `).join("");
}

function renderOnCallMatches(matches, selectedRecordId) {
  const related = matches.filter((item) => item.RecordID !== selectedRecordId);
  if (!related.length) return `<div class="detail-empty">No related previous records</div>`;
  return related.map((record) => `
    <button class="list-row" onclick="selectOnCallRecord('${escapeAttr(record.RecordID)}')">
      <strong>${escapeHtml(record.DocumentName)}</strong>
      <div class="muted">${escapeHtml(record.CVE || record.ThreatName || "")}</div>
      <div class="pill-row">${pill(record.Status)}${pill(`${record.TimesSeen || 1} seen`)}</div>
    </button>
  `).join("");
}

async function submitOnCallEntry(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = Object.fromEntries(new FormData(form).entries());
  const response = await fetch("/api/on-call", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error("Unable to save on-call record");
  }
  const result = await response.json();
  const toast = document.getElementById("onCallToast");
  toast.textContent = "Saved to local SharePoint-style memory";
  toast.hidden = false;
  state.selectedOnCallRecordId = result.record.DocumentName;
  await refreshAll();
  await selectOnCallDocument(result.record.DocumentName);
  checkOnCallHistory();
}

async function checkOnCallHistory() {
  const documentName = valueOf("onCallDocumentName");
  const cve = valueOf("onCallCve");
  const banner = document.getElementById("onCallSeenBanner");
  if (!documentName && !cve) {
    banner.hidden = true;
    banner.textContent = "";
    return;
  }
  const matches = await getJson(`/api/on-call/check?documentName=${encodeURIComponent(documentName)}&cve=${encodeURIComponent(cve)}`);
  if (!matches.length) {
    banner.hidden = true;
    banner.textContent = "";
    return;
  }
  const strongest = matches[0];
  banner.hidden = false;
  banner.textContent = `Previously seen ${strongest.TimesSeen || 1} time(s). Last status: ${strongest.Status || "Unknown"}. Last decision: ${strongest.Decision || "None"}.`;
}

function renderOnCallDocumentOptions() {
  const select = document.getElementById("onCallDocumentName");
  const selected = select.value;
  const options = state.documents.map((documentData) => {
    const option = document.createElement("option");
    option.value = documentData.DocumentName || "";
    option.textContent = documentData.DocumentName || documentData.DocumentID || "Document";
    option.dataset.documentId = documentData.DocumentID || "";
    option.dataset.localFileName = documentData.LocalFileName || "";
    option.dataset.pdfUrl = documentPdfHref(documentData) || documentData.PDFUrl || "";
    option.dataset.threatName = documentData.ThreatName || "";
    return option;
  });
  select.replaceChildren(new Option("Select Slack document", ""), ...options);
  select.value = selected;
  updateOnCallDocumentMapping();
}

function updateOnCallDocumentMapping() {
  const select = document.getElementById("onCallDocumentName");
  const option = select.selectedOptions[0];
  document.getElementById("onCallDocumentId").value = option?.dataset.documentId || "";
  document.getElementById("onCallLocalFileName").value = option?.dataset.localFileName || "";
  document.getElementById("onCallPdfUrl").value = option?.dataset.pdfUrl || "";
  const threatInput = document.querySelector('#onCallForm input[name="threatName"]');
  if (threatInput && !threatInput.value.trim()) {
    threatInput.value = option?.dataset.threatName || "";
  }
}

function documentCard(documentData) {
  const card = document.createElement("div");
  card.className = "gallery-card";
  card.classList.toggle("is-selected", state.selectedDocumentId === documentData.DocumentID);
  card.setAttribute("role", "button");
  card.tabIndex = 0;
  card.innerHTML = `
    <span class="eyebrow">${escapeHtml(documentData.ThreatName || documentData.Source || "Document")}</span>
    ${documentLink(documentData)}
    <span class="muted">${escapeHtml(dateOnly(documentData.ProcessedDate))}</span>
    <span class="pill-row">
      ${pill(documentData.DocumentRelevance)}${pill(`${documentData.HighFindingCount || 0} high`)}${pill(`${documentData.CVECount || 0} CVEs`)}
    </span>
  `;
  card.addEventListener("click", () => selectDocument(documentData.DocumentID));
  card.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      selectDocument(documentData.DocumentID);
    }
  });
  card.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", (event) => event.stopPropagation());
  });
  return card;
}

function findingCard(finding) {
  const button = document.createElement("button");
  button.className = "gallery-card";
  button.classList.toggle("is-selected", state.selectedFindingId === finding.FindingID);
  button.innerHTML = `
    <span class="eyebrow">${escapeHtml(finding.SemanticCategory || "Finding")}</span>
    <strong>${escapeHtml(finding.CVE)}</strong>
    <span class="muted">${escapeHtml(finding.Technology || "Unknown technology")}</span>
    <span class="pill-row">${pill(finding.DocumentRelevance)}${pill(finding.Status)}</span>
  `;
  button.addEventListener("click", () => selectFinding(finding.FindingID));
  return button;
}

async function selectDocument(documentId) {
  state.selectedDocumentId = documentId;
  renderDocumentsGallery();
  const detail = await getJson(`/api/documents/${encodeURIComponent(documentId)}`);
  renderDocumentDetail(detail);
}

function renderDocumentDetail(detail) {
  const documentData = detail.document;
  const pdfName = documentData.LocalFileName || "";
  const pdfHref = documentPdfHref(documentData);
  const threatEvidence = documentData.ThreatEvidence || "";
  const root = document.getElementById("documentDetail");
  root.className = "detail";
  root.innerHTML = `
    <div class="detail-header">
      <div>
        <h2>${documentLink(documentData)}</h2>
        <p class="muted">${escapeHtml(documentData.ThreatName || "")}</p>
      </div>
      ${pdfHref ? `<a class="secondary-button" href="${escapeAttr(pdfHref)}" target="_blank" rel="noopener">Open PDF</a>` : ""}
    </div>
    <div class="fields-grid">
      ${field("Processed", dateOnly(documentData.ProcessedDate))}
      ${field("Status", documentData.ProcessingStatus)}
      ${field("Relevance", documentData.DocumentRelevance)}
      ${field("High", documentData.HighFindingCount)}
      ${field("Review", documentData.ReviewFindingCount)}
      ${field("CVEs", documentData.CVECount)}
      ${field("Threat evidence page", documentData.ThreatEvidencePageNumber || "Filename")}
    </div>
    ${tabs([
      ["Threat Evidence", threatEvidence
        ? `<div class="evidence evidence-highlight">${highlightEvidence(threatEvidence, [documentData.ThreatName])}</div>`
        : `<div class="detail-empty">No threat name evidence was detected</div>`],
      ["Findings", renderFindingRows(detail.findings)],
      ["Indicators", renderIndicatorRows(detail.indicators)],
      ["Similar", renderSimilarRows(detail.similarDocuments)],
      ["Comments", renderFeedbackRows(detail.feedback)]
    ])}
  `;
  activateTabs(root);
}

async function selectFinding(findingId) {
  state.selectedFindingId = findingId;
  renderFindingsGallery();
  const detail = await getJson(`/api/findings/${encodeURIComponent(findingId)}`);
  renderFindingDetail(detail);
}

function renderFindingDetail(detail) {
  const finding = detail.finding;
  const memory = detail.memory;
  const root = document.getElementById("findingDetail");
  root.className = "detail";
  root.innerHTML = `
    <div class="detail-header">
      <div>
        <h2>${escapeHtml(finding.CVE)}</h2>
        <p class="muted">${escapeHtml(finding.Technology || "Unknown technology")}</p>
      </div>
      <span class="pill-row">${pill(finding.DocumentRelevance)}${pill(finding.Status)}</span>
    </div>
    <div class="fields-grid">
      ${field("Vendor", finding.Vendor)}
      ${field("Category", finding.SemanticCategory)}
      ${field("Page", finding.PageNumber || "")}
      ${field("Active", score(finding.ActiveExploitationScore))}
      ${field("Initial", score(finding.InitialAccessScore))}
      ${field("RCE", score(finding.RemoteCodeExecutionScore))}
    </div>
    ${tabs([
      ["Evidence", `<div class="evidence">${escapeHtml(finding.EvidenceText || "")}</div>`],
      ["Tech Evidence", finding.TechnologyEvidence
        ? `<div class="evidence evidence-highlight">${highlightEvidence(
            finding.TechnologyEvidence,
            [finding.Technology, finding.Vendor]
          )}</div>`
        : `<div class="detail-empty">No technology evidence was detected</div>`],
      ["Memory", renderMemory(memory)],
      ["Comments", renderFeedbackRows(detail.feedback)],
      ["Review", renderReviewForm(finding)]
    ])}
  `;
  activateTabs(root);
  const form = document.getElementById("reviewForm");
  if (form) {
    form.addEventListener("submit", (event) => submitReview(event, finding.FindingID));
  }
}

function renderReviewForm(finding) {
  return `
    <form id="reviewForm" class="form-grid">
      <label>Status ${selectHtml("status", statusChoices, finding.Status)}</label>
      <label>Relevance ${selectHtml("analystRelevance", relevanceChoices, finding.DocumentRelevance)}</label>
      <label>Decision ${selectHtml("decision", decisionChoices, "Agree With System")}</label>
      <label>Assigned To <input name="assignedTo" value="${escapeAttr(finding.AssignedTo || "")}"></label>
      <label>Analyst Email <input name="analystEmail" type="email"></label>
      <label>Analyst Name <input name="analystName"></label>
      <label class="full">Comment <textarea name="comment">${escapeHtml(finding.SuggestedAnalystComment || "")}</textarea></label>
      <div class="full"><button class="primary-button" type="submit">Submit</button></div>
      <div id="reviewToast" class="toast full" hidden></div>
    </form>
  `;
}

async function submitReview(event, findingId) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = Object.fromEntries(new FormData(form).entries());
  const response = await fetch(`/api/findings/${encodeURIComponent(findingId)}/feedback`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error("Unable to save review");
  }
  const result = await response.json();
  const toast = document.getElementById("reviewToast");
  toast.textContent = "Saved";
  toast.hidden = false;
  await refreshAll();
  renderFindingDetail({
    finding: result.finding,
    document: null,
    memory: result.memory,
    feedback: await getFeedbackForFinding(findingId)
  });
}

async function getFeedbackForFinding(findingId) {
  const detail = await getJson(`/api/findings/${encodeURIComponent(findingId)}`);
  return detail.feedback;
}

function renderFindingRows(findings) {
  if (!findings.length) return `<div class="detail-empty">No findings</div>`;
  return findings.map((finding) => `
    <button class="list-row" onclick="showScreen('findings'); selectFinding('${escapeAttr(finding.FindingID)}')">
      <strong>${escapeHtml(finding.CVE)}</strong>
      <div class="muted">${escapeHtml(finding.Technology || "")}</div>
      <div class="pill-row">${pill(finding.DocumentRelevance)}${pill(finding.Status)}</div>
    </button>
  `).join("");
}

function renderIndicatorRows(indicators) {
  if (!indicators.length) return `<div class="detail-empty">No indicators</div>`;
  return indicators.slice(0, 80).map((indicator) => `
    <div class="list-row">
      <strong>${escapeHtml(indicator.IndicatorValue)}</strong>
      <div class="muted">${escapeHtml(indicator.IndicatorType)}</div>
    </div>
  `).join("");
}

function renderSimilarRows(rows) {
  if (!rows.length) return `<div class="detail-empty">No similar advisories yet</div>`;
  return rows.map((item) => `
    <div class="list-row">
      <strong>${escapeHtml(item.similar_document_id)}</strong>
      <div class="muted">${Math.round(item.similarity_score * 100)}% ${escapeHtml(item.match_reason)}</div>
    </div>
  `).join("");
}

function renderFeedbackRows(rows) {
  if (!rows.length) return `<div class="detail-empty">No comments</div>`;
  return rows.map((item) => `
    <div class="list-row">
      <strong>${escapeHtml(item.decision || item.new_status || "Analyst action")}</strong>
      <div class="muted">${escapeHtml(item.analyst_name || item.analyst_email || "Analyst")} ${dateOnly(item.created_date)}</div>
      <p>${escapeHtml(item.comment || "")}</p>
    </div>
  `).join("");
}

function renderMemory(memory) {
  if (!memory) return `<div class="detail-empty">No previous memory</div>`;
  return `
    <div class="fields-grid">
      ${field("Previously Seen", "Yes")}
      ${field("Times Seen", memory.times_seen)}
      ${field("First Seen", dateOnly(memory.first_seen_date))}
      ${field("Last Seen", dateOnly(memory.last_seen_date))}
      ${field("Previous Relevance", memory.previous_highest_relevance)}
      ${field("Previous Decision", memory.last_analyst_decision || "")}
    </div>
    <div class="evidence">${escapeHtml(memory.last_analyst_comment || "No analyst comment yet")}</div>
  `;
}

function tabs(items) {
  const buttons = items.map(([label], index) =>
    `<button class="tab ${index === 0 ? "is-active" : ""}" data-tab="${index}">${label}</button>`
  ).join("");
  const panels = items.map(([, html], index) =>
    `<div class="tab-panel ${index === 0 ? "is-visible" : ""}" data-tab-panel="${index}">${html}</div>`
  ).join("");
  return `<div class="tabs">${buttons}</div>${panels}`;
}

function activateTabs(root) {
  root.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => {
      const tab = button.dataset.tab;
      root.querySelectorAll(".tab").forEach((item) => item.classList.toggle("is-active", item.dataset.tab === tab));
      root.querySelectorAll(".tab-panel").forEach((item) => item.classList.toggle("is-visible", item.dataset.tabPanel === tab));
    });
  });
}

function selectHtml(name, choices, selected) {
  return `<select name="${name}">${choices.map((choice) => {
    const isSelected = choice === selected ? " selected" : "";
    return `<option${isSelected}>${escapeHtml(choice)}</option>`;
  }).join("")}</select>`;
}

async function getJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Request failed: ${url}`);
  }
  return response.json();
}

function field(label, value) {
  return `<div class="field"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value ?? "")}</strong></div>`;
}

function pill(value) {
  const text = String(value || "");
  const key = text.toLowerCase();
  let className = "pill";
  if (key.includes("high") || key.includes("required")) className += " high";
  else if (key.includes("review") || key.includes("under")) className += " review";
  else if (key.includes("informational")) className += " info";
  else if (key.includes("closed") || key.includes("reviewed") || key.includes("remediated")) className += " done";
  return `<span class="${className}">${escapeHtml(text)}</span>`;
}

function duplicateEventLabel(eventType) {
  if (eventType === "SLACK_PDF_RESEEN") return "PDF re-seen";
  if (eventType === "RELATED_DOCUMENT_RESEEN") return "Related repeat";
  return "Memory re-seen";
}

function setTextIfPresent(id, value) {
  const element = document.getElementById(id);
  if (element) element.textContent = value;
}

function score(value) {
  const number = Number(value || 0);
  return `${Math.round(number * 100)}%`;
}

function dateOnly(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value).slice(0, 19);
  return date.toLocaleString();
}

function uniqueValues(values) {
  return Array.from(new Set(values.map((value) => String(value || "").trim()).filter(Boolean)));
}

function minValue(values) {
  const present = values.map((value) => String(value || "")).filter(Boolean).sort();
  return present[0] || "";
}

function maxValue(values) {
  const present = values.map((value) => String(value || "")).filter(Boolean).sort();
  return present.at(-1) || "";
}

function documentPdfHref(documentData) {
  const pdfName = documentData.LocalFileName || "";
  if (!pdfName) return "";
  return `/pdf/${encodeURIComponent(pdfName)}`;
}

function documentLink(documentData) {
  const label = documentData.DocumentName || documentData.DocumentID || "Document";
  const href = documentPdfHref(documentData);
  if (!href) return `<strong>${escapeHtml(label)}</strong>`;
  return `<a class="document-link" href="${escapeAttr(href)}" target="_blank" rel="noopener">${escapeHtml(label)}</a>`;
}

function valueOf(id) {
  return document.getElementById(id).value.trim();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function highlightEvidence(value, terms) {
  const source = String(value ?? "");
  for (const termValue of terms) {
    const term = String(termValue || "").trim();
    if (!term || term.toUpperCase() === "UNKNOWN") continue;
    const index = source.toLowerCase().indexOf(term.toLowerCase());
    if (index >= 0) {
      return `${escapeHtml(source.slice(0, index))}<mark>${escapeHtml(
        source.slice(index, index + term.length)
      )}</mark>${escapeHtml(source.slice(index + term.length))}`;
    }
  }
  return escapeHtml(source);
}

function escapeAttr(value) {
  return escapeHtml(value);
}
