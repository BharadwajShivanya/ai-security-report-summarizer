from parser import parse_trivy_report
from statistics import calculate_statistics
from prioritizer import get_top_vulnerabilities
from summary_builder import build_summary

findings = parse_trivy_report("reports/sample_trivy.json")

stats = calculate_statistics(findings)

top = get_top_vulnerabilities(findings, limit=5)

summary = build_summary(
    findings,
    stats,
    top,
)

print(summary)