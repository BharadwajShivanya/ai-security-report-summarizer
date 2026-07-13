from parser import parse_trivy_report
from statistics import calculate_statistics
from prioritizer import get_top_vulnerabilities
from prompts import build_security_prompt
from bedrock_client import generate_security_report

findings = parse_trivy_report("reports/sample_trivy.json")

stats = calculate_statistics(findings)

top_findings = get_top_vulnerabilities(findings)

from summary_builder import build_summary

summary = build_summary(
    findings,
    stats,
    top_findings,
)

prompt = build_security_prompt(summary)

print("=" * 80)
print(prompt)
print("=" * 80)

report = generate_security_report(prompt)

print(report)