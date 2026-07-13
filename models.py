from dataclasses import dataclass


@dataclass
class Vulnerability:
    cve: str
    package: str
    severity: str
    installed_version: str
    fixed_version: str
    description: str