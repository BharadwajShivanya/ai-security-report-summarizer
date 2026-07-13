from parser import parse_trivy_report
from prioritizer import get_top_vulnerabilities

findings = parse_trivy_report(
    "reports/sample_trivy.json"
)

top_findings = get_top_vulnerabilities(findings)

print(f"Top {len(top_findings)} Vulnerabilities\n")

for finding in top_findings:
    print(
        f"{finding.severity:<10}"
        f"{finding.cve:<25}"
        f"{finding.package}"
    )