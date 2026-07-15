from parser import parse_trivy_report
from statistics import calculate_statistics
from prioritizer import get_top_vulnerabilities
from summary_builder import build_summary
from prompts import build_security_prompt

findings = parse_trivy_report(
    "reports/sample_trivy.json"
)

stats = calculate_statistics(findings)

top_findings = get_top_vulnerabilities(findings)

summary = build_summary(
    findings,
    stats,
    top_findings,
)

prompt = build_security_prompt(summary)

print(prompt)