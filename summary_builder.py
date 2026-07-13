from collections import Counter

from models import Vulnerability


def build_summary(
    findings: list[Vulnerability],
    statistics: dict,
    top_findings: list[Vulnerability],
) -> dict:
    """
    Build a concise summary for the LLM.
    """

    package_counter = Counter()

    for finding in findings:
        package_counter[finding.package] += 1

    top_packages = package_counter.most_common(5)

    return {
        "statistics": statistics,
        "top_packages": top_packages,
        "top_findings": top_findings,
    }