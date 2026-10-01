from __future__ import annotations

import hashlib
from pathlib import Path

import streamlit as st

from src.analysis_pipeline import process_document
from src.analysis_store import load_all_analyses
from src.config import ConfigError, load_config
from src.excel_writer import refresh_document_analysis_sheet
from src.file_service import safe_filename
from src.models import DocumentAnalysis, DocumentMetadata


st.set_page_config(page_title="Threat Intelligence Analyst POC", layout="wide")


def main() -> None:
    st.title("Threat Intelligence Analyst POC")

    try:
        config = load_config()
    except ConfigError as exc:
        st.error(f"Configuration error: {exc}")
        return

    analyses = load_all_analyses(config.analysis_results_dir)
    tab_dashboard, tab_document, tab_history, tab_upload = st.tabs(
        ["Dashboard", "Document Analysis", "History/Search", "Upload/Reanalyze"]
    )

    with tab_dashboard:
        render_dashboard(analyses)

    with tab_document:
        render_document_analysis(analyses)

    with tab_history:
        render_history(analyses)

    with tab_upload:
        render_upload_and_reanalysis(config, analyses)


def render_dashboard(analyses: list[DocumentAnalysis]) -> None:
    cves = [cve for analysis in analyses for cve in analysis.cves]
    indicators_count = sum(
        len(analysis.indicators.ipv4)
        + len(analysis.indicators.domains)
        + len(analysis.indicators.urls)
        + len(analysis.indicators.sha256)
        + len(analysis.indicators.sha1)
        + len(analysis.indicators.md5)
        + len(analysis.indicators.mitre_techniques)
        for analysis in analyses
    )

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Documents Processed", len(analyses))
    col2.metric("CVEs Detected", len(cves))
    col3.metric("High-Relevance CVEs", sum(1 for cve in cves if cve.document_relevance == "HIGH"))
    col4.metric(
        "Documents Requiring Review",
        sum(1 for analysis in analyses if any(cve.document_relevance in {"HIGH", "REVIEW"} for cve in analysis.cves)),
    )
    col5.metric("Indicators Detected", indicators_count)

    st.subheader("Recent Documents")
    if not analyses:
        st.info("No analysis results yet. Run the Slack ingestion or upload a PDF.")
        return

    for analysis in sorted(analyses, key=lambda item: item.processed_at, reverse=True)[:10]:
        relevance = highest_relevance(analysis)
        with st.expander(f"{analysis.document_name} - {relevance}"):
            left, right = st.columns([3, 1])
            with left:
                st.write(f"**Received:** {analysis.slack_message_timestamp or 'N/A'}")
                st.write(f"**Threat:** {analysis.threat_name or 'Unknown'}")
                st.write(f"**Technologies:** {', '.join(sorted(technologies(analysis))) or 'UNKNOWN'}")
                st.write(f"**CVEs:** {len(analysis.cves)}")
                st.write(f"**IPs:** {len(analysis.indicators.ipv4)}")
                st.write(f"**Domains:** {len(analysis.indicators.domains)}")
            with right:
                render_pdf_download(analysis)


def render_document_analysis(analyses: list[DocumentAnalysis]) -> None:
    if not analyses:
        st.info("No analysis results yet.")
        return

    selected_name = st.selectbox("Select document", [analysis.document_name for analysis in analyses])
    analysis = next(item for item in analyses if item.document_name == selected_name)

    st.subheader(analysis.document_name)
    col1, col2, col3 = st.columns(3)
    col1.write(f"**Slack received:** {analysis.slack_message_timestamp or 'N/A'}")
    col2.write(f"**Threat:** {analysis.threat_name or 'Unknown'}")
    col3.write(f"**Extraction status:** {analysis.extraction_status}")
    render_pdf_download(analysis)

    st.divider()
    st.write("**Indicators**")
    st.write(f"IPs: {', '.join(analysis.indicators.ipv4) or 'None'}")
    st.write(f"Domains: {', '.join(analysis.indicators.domains) or 'None'}")
    st.write(f"URLs: {', '.join(analysis.indicators.urls) or 'None'}")
    st.write(f"Hashes: {', '.join([*analysis.indicators.sha256, *analysis.indicators.sha1, *analysis.indicators.md5]) or 'None'}")
    st.write(f"MITRE techniques: {', '.join(analysis.indicators.mitre_techniques) or 'None'}")
    st.write(f"Container indicators: {', '.join(analysis.indicators.container_indicators) or 'None'}")

    st.divider()
    st.write("**CVE Evidence**")
    if not analysis.cves:
        st.info("No CVEs found in this document.")
    for cve in analysis.cves:
        with st.expander(f"{cve.cve} - {cve.document_relevance}"):
            st.write(f"**Technology:** {cve.technology}")
            st.write(f"**Vendor:** {cve.vendor}")
            st.write(f"**Semantic category:** {cve.semantic_category}")
            st.write(f"**Page:** {cve.page_number or 'Unknown'}")
            st.write(f"**Analyst comment:** {cve.analyst_comment}")
            st.write("**Evidence:**")
            st.info(cve.evidence_text)
            st.write("**Semantic scores:**")
            st.dataframe(
                [{"Intent": key, "Score": value} for key, value in cve.semantic_scores.items()],
                use_container_width=True,
            )


def render_history(analyses: list[DocumentAnalysis]) -> None:
    rows = []
    for analysis in analyses:
        for cve in analysis.cves:
            rows.append(
                {
                    "Date": analysis.processed_at.split("T", 1)[0],
                    "Document": analysis.document_name,
                    "CVE": cve.cve,
                    "Technology": cve.technology,
                    "Threat": analysis.threat_name or "",
                    "Document Relevance": cve.document_relevance,
                    "Semantic Category": cve.semantic_category,
                }
            )

    query = st.text_input("Search", placeholder="CVE-2021-34473, Exchange, Hive, FortiOS")
    relevance_filter = st.multiselect("Document Relevance", ["HIGH", "REVIEW", "INFORMATIONAL"])

    filtered = rows
    if query:
        query_lower = query.lower()
        filtered = [row for row in filtered if query_lower in " ".join(str(value).lower() for value in row.values())]
    if relevance_filter:
        filtered = [row for row in filtered if row["Document Relevance"] in relevance_filter]

    st.dataframe(filtered, use_container_width=True)


def render_upload_and_reanalysis(config, analyses: list[DocumentAnalysis]) -> None:
    st.subheader("Manual PDF Upload")
    uploaded = st.file_uploader("Upload PDF", type=["pdf"])
    if uploaded is not None and st.button("Analyze Uploaded PDF"):
        content = uploaded.getvalue()
        digest = hashlib.sha256(content).hexdigest()
        filename = f"manual_{digest[:12]}_{safe_filename(uploaded.name)}"
        destination = config.download_dir / filename
        destination.write_bytes(content)
        metadata = DocumentMetadata(
            document_id=f"manual_{digest[:16]}",
            document_name=uploaded.name,
            local_file_path=str(destination),
            source="manual_upload",
        )
        process_document(metadata, destination, config, force=True)
        refresh_document_analysis_sheet(load_all_analyses(config.analysis_results_dir), config.output_file)
        st.success("Uploaded PDF analyzed. Refresh the page to see updated dashboard metrics.")

    st.divider()
    st.subheader("Reanalyze Existing Document")
    if not analyses:
        st.info("No documents available for reanalysis.")
        return

    selected_name = st.selectbox("Document to reanalyze", [analysis.document_name for analysis in analyses], key="reanalyze")
    selected = next(item for item in analyses if item.document_name == selected_name)
    if st.button("Reanalyze Document"):
        metadata = DocumentMetadata(
            document_id=selected.document_id,
            document_name=selected.document_name,
            local_file_path=selected.local_file_path,
            source=selected.source,
            slack_channel_id=selected.slack_channel_id,
            slack_message_id=selected.slack_message_id,
            slack_message_timestamp=selected.slack_message_timestamp,
            slack_file_id=selected.slack_file_id,
            slack_file_url=selected.slack_file_url,
            downloaded_at=selected.downloaded_at,
        )
        process_document(metadata, selected.local_file_path, config, force=True)
        refresh_document_analysis_sheet(load_all_analyses(config.analysis_results_dir), config.output_file)
        st.success("Document reanalyzed. Refresh the page to see updated results.")


def render_pdf_download(analysis: DocumentAnalysis) -> None:
    path = Path(analysis.local_file_path)
    if not path.exists():
        st.warning("Local PDF is not available.")
        return
    st.download_button("Open PDF", path.read_bytes(), file_name=path.name, mime="application/pdf")


def technologies(analysis: DocumentAnalysis) -> set[str]:
    return {cve.technology for cve in analysis.cves if cve.technology != "UNKNOWN"}


def highest_relevance(analysis: DocumentAnalysis) -> str:
    order = {"HIGH": 3, "REVIEW": 2, "INFORMATIONAL": 1}
    if not analysis.cves:
        return "NO CVES"
    return max((cve.document_relevance for cve in analysis.cves), key=lambda value: order.get(value, 0))


if __name__ == "__main__":
    main()
