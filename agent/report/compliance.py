"""Compliance mapping — maps findings to OWASP Top 10, PCI-DSS, and CWE.

Advisory only: maps vuln classes to compliance framework requirements
so VAPT reports can include compliance context.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ComplianceRef:
    framework: str
    requirement: str
    description: str


OWASP_TOP10_2021: dict[str, list[ComplianceRef]] = {
    "sqli": [ComplianceRef("OWASP", "A03:2021", "Injection")],
    "nosqli": [ComplianceRef("OWASP", "A03:2021", "Injection")],
    "cmdi": [ComplianceRef("OWASP", "A03:2021", "Injection")],
    "ssti": [ComplianceRef("OWASP", "A03:2021", "Injection")],
    "lfi": [ComplianceRef("OWASP", "A03:2021", "Injection")],
    "xss": [ComplianceRef("OWASP", "A03:2021", "Injection")],
    "stored-xss": [ComplianceRef("OWASP", "A03:2021", "Injection")],
    "idor": [ComplianceRef("OWASP", "A01:2021", "Broken Access Control")],
    "bola": [ComplianceRef("OWASP", "A01:2021", "Broken Access Control")],
    "privesc": [ComplianceRef("OWASP", "A01:2021", "Broken Access Control")],
    "open-redirect": [ComplianceRef("OWASP", "A01:2021", "Broken Access Control")],
    "csrf": [ComplianceRef("OWASP", "A01:2021", "Broken Access Control")],
    "auth-bypass": [ComplianceRef("OWASP", "A07:2021", "Identification and Authentication Failures")],
    "jwt": [ComplianceRef("OWASP", "A02:2021", "Cryptographic Failures")],
    "oauth": [ComplianceRef("OWASP", "A07:2021", "Identification and Authentication Failures")],
    "ssrf": [ComplianceRef("OWASP", "A10:2021", "Server-Side Request Forgery")],
    "security-headers": [ComplianceRef("OWASP", "A05:2021", "Security Misconfiguration")],
    "graphql": [ComplianceRef("OWASP", "A05:2021", "Security Misconfiguration")],
    "race": [ComplianceRef("OWASP", "A04:2021", "Insecure Design")],
    "brute-force": [ComplianceRef("OWASP", "A07:2021", "Identification and Authentication Failures")],
}

PCI_DSS_V4: dict[str, list[ComplianceRef]] = {
    "sqli": [ComplianceRef("PCI-DSS", "6.2.4", "Prevention of common software attacks")],
    "xss": [ComplianceRef("PCI-DSS", "6.2.4", "Prevention of common software attacks")],
    "nosqli": [ComplianceRef("PCI-DSS", "6.2.4", "Prevention of common software attacks")],
    "cmdi": [ComplianceRef("PCI-DSS", "6.2.4", "Prevention of common software attacks")],
    "auth-bypass": [ComplianceRef("PCI-DSS", "8.3", "Strong authentication for users and administrators")],
    "idor": [ComplianceRef("PCI-DSS", "7.2", "Access control system configuration")],
    "bola": [ComplianceRef("PCI-DSS", "7.2", "Access control system configuration")],
    "csrf": [ComplianceRef("PCI-DSS", "6.2.4", "Prevention of common software attacks")],
    "security-headers": [ComplianceRef("PCI-DSS", "6.2.4", "Prevention of common software attacks")],
    "jwt": [ComplianceRef("PCI-DSS", "4.2.1", "Strong cryptography for transmission")],
}

CWE_MAP: dict[str, str] = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "stored-xss": "CWE-79",
    "nosqli": "CWE-943",
    "cmdi": "CWE-78",
    "ssti": "CWE-1336",
    "lfi": "CWE-22",
    "ssrf": "CWE-918",
    "idor": "CWE-639",
    "bola": "CWE-639",
    "csrf": "CWE-352",
    "open-redirect": "CWE-601",
    "auth-bypass": "CWE-287",
    "jwt": "CWE-345",
    "oauth": "CWE-352",
    "race": "CWE-362",
    "brute-force": "CWE-307",
    "privesc": "CWE-269",
    "security-headers": "CWE-693",
    "graphql": "CWE-200",
}

_ALL_FRAMEWORKS: dict[str, dict[str, list[ComplianceRef]]] = {
    "OWASP": OWASP_TOP10_2021,
    "PCI-DSS": PCI_DSS_V4,
}


def get_compliance_refs(
    recipe_id: str,
    frameworks: list[str] | None = None,
) -> list[ComplianceRef]:
    """Return compliance references for a finding's recipe_id.

    Matches by prefix: 'sqli-error' matches 'sqli'.
    """
    rid = recipe_id.lower().split(":")[-1]  # strip auto: prefix
    refs = []
    target_frameworks = frameworks or list(_ALL_FRAMEWORKS.keys())
    for fw_name in target_frameworks:
        fw = _ALL_FRAMEWORKS.get(fw_name, {})
        for prefix, fw_refs in fw.items():
            if rid.startswith(prefix):
                refs.extend(fw_refs)
    return refs


def get_cwe(recipe_id: str) -> str:
    """Return CWE ID for a recipe_id, or empty string."""
    rid = recipe_id.lower().split(":")[-1]
    for prefix, cwe in CWE_MAP.items():
        if rid.startswith(prefix):
            return cwe
    return ""
