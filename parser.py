import json

from models import Vulnerability


def parse_trivy_report(file_path: str) -> list[Vulnerability]:
    """
    Parse a Trivy JSON report and return a list of Vulnerability objects.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    findings = []

    for result in report.get("Results", []):

        vulnerabilities = result.get("Vulnerabilities", [])

        for vuln in vulnerabilities:

            findings.append(
                Vulnerability(
                    cve=vuln.get("VulnerabilityID", "N/A"),
                    package=vuln.get("PkgName", "N/A"),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    installed_version=vuln.get("InstalledVersion", "N/A"),
                    fixed_version=vuln.get("FixedVersion", "N/A"),
                    description=(
                        vuln.get("Title")
                        or vuln.get("Description")
                        or "No description available."
                    ),
                )
            )

    return findings