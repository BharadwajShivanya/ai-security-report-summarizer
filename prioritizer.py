from models import Vulnerability


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}


def get_top_vulnerabilities(
    findings: list[Vulnerability],
    limit: int = 20,
) -> list[Vulnerability]:
    """
    Return the highest-priority vulnerabilities.
    """

    return sorted(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(
            finding.severity,
            0,
        ),
        reverse=True,
    )[:limit]