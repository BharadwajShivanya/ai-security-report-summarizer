from collections import Counter


def calculate_statistics(findings):

    severities = Counter()

    for finding in findings:
        severities[finding.severity] += 1

    return {
        "total": len(findings),
        "critical": severities["CRITICAL"],
        "high": severities["HIGH"],
        "medium": severities["MEDIUM"],
        "low": severities["LOW"],
        "unknown": severities["UNKNOWN"],
    }