import streamlit as st
import pandas as pd

from parser import parse_trivy_report
from statistics import calculate_statistics
from prioritizer import get_top_vulnerabilities
from summary_builder import build_summary
from prompts import build_security_prompt
from bedrock_client import generate_security_report

st.set_page_config(
    page_title="AI Security Report Summarizer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI Security Report Summarizer")

st.markdown(
    """
Upload a Trivy JSON report and generate an AI-powered security assessment
using Amazon Bedrock.
"""
)

uploaded_file = st.file_uploader(
    "Upload Trivy JSON Report",
    type=["json"]
)

if uploaded_file:

    temp_path = "reports/uploaded_report.json"

    with open(temp_path, "wb") as f:
        f.write(uploaded_file.read())

    findings = parse_trivy_report(temp_path)

    stats = calculate_statistics(findings)

    top_findings = get_top_vulnerabilities(
        findings,
        limit=5,
    )

    summary = build_summary(
        findings,
        stats,
        top_findings,
    )

    prompt = build_security_prompt(summary)

    st.success("Report Parsed Successfully!")

    st.divider()

    st.header("📊 Severity Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Critical", stats["critical"])
    col2.metric("High", stats["high"])
    col3.metric("Medium", stats["medium"])
    col4.metric("Low", stats["low"])

    st.divider()

    st.header("📋 Top Vulnerabilities")

    df = pd.DataFrame(
        [
            {
                "CVE": finding.cve,
                "Package": finding.package,
                "Severity": finding.severity,
                "Installed": finding.installed_version,
                "Fixed": finding.fixed_version,
            }
            for finding in top_findings
        ]
    )

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    st.header("📝 Prompt Sent to Bedrock")

    with st.expander("View Prompt"):

        st.code(prompt)

    st.divider()

    if st.button("🚀 Generate AI Security Report"):

        with st.spinner("Generating report using Amazon Bedrock..."):

            report = generate_security_report(prompt)

        st.success("Report Generated!")

        st.markdown(report)

        st.download_button(
            "⬇ Download Markdown Report",
            data=report,
            file_name="security_report.md",
            mime="text/markdown",
        )