from models import Vulnerability


def build_security_prompt(summary: dict) -> str:
    stats = summary["statistics"]
    packages = summary["top_packages"]
    findings = summary["top_findings"]

    prompt = f"""
You are a cybersecurity documentation assistant.

Your job is to summarize a vulnerability scan for defensive security purposes.

Executive Statistics

- Total Findings: {stats['total']}
- Critical: {stats['critical']}
- High: {stats['high']}
- Medium: {stats['medium']}
- Low: {stats['low']}

Top Affected Packages:
"""

    for package, count in packages:
        prompt += f"- {package}: {count} findings\n"

    prompt += "\nHighest Priority Findings:\n"

    for finding in findings:
        prompt += (
            f"- {finding.severity}: {finding.package} ({finding.cve})\n"
        )

    prompt += """

Produce a Markdown report with:

# Executive Summary
# Business Impact
# Recommended Remediation
# Priority Action Plan

Do not provide exploit instructions.
Keep the report concise and defensive.
"""

    return prompt