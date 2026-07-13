from parser import parse_trivy_report

findings = parse_trivy_report("reports/sample_trivy.json")

print(f"Total vulnerabilities: {len(findings)}")

print("\nFirst 5 findings:\n")

for finding in findings[:5]:
    print(finding)