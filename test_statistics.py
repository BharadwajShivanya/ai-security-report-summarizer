from parser import parse_trivy_report
from statistics import calculate_statistics

findings = parse_trivy_report(
    "reports/sample_trivy.json"
)

stats = calculate_statistics(findings)

print(stats)