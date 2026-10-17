"""Bug bounty platform export — formats findings for submission.

Supports HackerOne, Bugcrowd, and generic markdown export formats.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .cvss import cvss_for_finding
from .compliance import get_cwe


@dataclass
class ExportedFinding:
    """A finding formatted for platform submission."""
    title: str
    severity: str
    cvss_score: float
    cvss_vector: str
    cwe: str
    endpoint: str
    description: str
    steps_to_reproduce: str
    impact: str
    remediation: str
    raw: dict


def _build_steps(finding: dict) -> str:
    """Build steps-to-reproduce from finding evidence."""
    steps = []
    req = finding.get("request_data", {})
    if req.get("full_request"):
        steps.append(f"1. Send the following request:\n```\n{req['full_request']}\n```")
    elif req.get("url"):
        method = req.get("method", "GET")
        steps.append(f"1. Send a {method} request to `{req['url']}`")
        if req.get("payload"):
            steps.append(f"2. Use payload: `{req['payload']}`")
            if req.get("param"):
                steps.append(f"   in parameter: `{req['param']}`")

    evidence = finding.get("evidence", {})
    if evidence.get("technique"):
        steps.append(f"{len(steps)+1}. The server responds indicating {evidence['technique']}")

    resp = finding.get("response_data", {})
    if resp.get("status"):
        steps.append(f"{len(steps)+1}. Observe HTTP {resp['status']} response")
    if resp.get("body_snippet"):
        steps.append(f"{len(steps)+1}. Response contains: `{resp['body_snippet'][:200]}`")

    return "\n".join(steps) if steps else "See evidence section for reproduction details."


def _build_impact(finding: dict) -> str:
    """Generate impact description based on vuln class."""
    rid = finding.get("recipe_id", "").lower()
    impacts = {
        "sqli": "An attacker could extract, modify, or delete database contents, potentially accessing sensitive user data, credentials, or financial records.",
        "xss": "An attacker could execute arbitrary JavaScript in victims' browsers, stealing session tokens, credentials, or performing actions on their behalf.",
        "ssrf": "An attacker could access internal services, read local files, or pivot to other systems on the internal network.",
        "idor": "An attacker could access other users' data by manipulating object references, violating data isolation.",
        "bola": "An attacker could access other users' data by manipulating object references, violating data isolation.",
        "cmdi": "An attacker could execute arbitrary operating system commands on the server, potentially achieving full system compromise.",
        "auth-bypass": "An attacker could bypass authentication controls and gain unauthorized access to the application.",
        "csrf": "An attacker could force authenticated users to perform unintended actions.",
        "lfi": "An attacker could read sensitive files from the server filesystem.",
        "race": "An attacker could exploit race conditions to perform duplicate operations (e.g., double-spend).",
    }
    for prefix, impact in impacts.items():
        if rid.startswith(prefix) or prefix in rid:
            return impact
    return "This vulnerability could lead to unauthorized access or data exposure."


def export_finding(finding: dict) -> ExportedFinding:
    """Convert a raw finding dict to an export-ready format."""
    cvss = cvss_for_finding(finding)
    rid = finding.get("recipe_id", "unknown")
    title = rid.replace("-", " ").replace("_", " ").title()
    if "auto:" in rid:
        title = rid.split(":", 1)[1].replace("-", " ").title()

    endpoint = finding.get("endpoint", "")
    title_with_endpoint = f"{title} in {endpoint}" if endpoint else title

    return ExportedFinding(
        title=title_with_endpoint,
        severity=cvss.severity(),
        cvss_score=cvss.score(),
        cvss_vector=cvss.vector_string(),
        cwe=get_cwe(rid),
        endpoint=endpoint,
        description=finding.get("reason", ""),
        steps_to_reproduce=_build_steps(finding),
        impact=_build_impact(finding),
        remediation=finding.get("evidence", {}).get("recommendation", "See OWASP guidelines."),
        raw=finding,
    )


def to_markdown(finding: ExportedFinding) -> str:
    """Format as markdown for generic submission."""
    return f"""## {finding.title}

**Severity:** {finding.severity.upper()} ({finding.cvss_score})
**CVSS:** `{finding.cvss_vector}`
**CWE:** {finding.cwe or 'N/A'}
**Endpoint:** `{finding.endpoint}`

### Description
{finding.description}

### Steps to Reproduce
{finding.steps_to_reproduce}

### Impact
{finding.impact}

### Remediation
{finding.remediation}
"""


def to_hackerone(finding: ExportedFinding) -> dict:
    """Format for HackerOne API submission structure."""
    severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "none": "none"}
    return {
        "data": {
            "type": "report",
            "attributes": {
                "title": finding.title,
                "vulnerability_information": (
                    f"{finding.description}\n\n"
                    f"## Steps to Reproduce\n{finding.steps_to_reproduce}\n\n"
                    f"## Impact\n{finding.impact}"
                ),
                "impact": finding.impact,
                "severity_rating": severity_map.get(finding.severity, "medium"),
                "weakness_id": finding.cwe,
            },
        },
    }


def to_bugcrowd(finding: ExportedFinding) -> dict:
    """Format for Bugcrowd submission structure."""
    return {
        "title": finding.title,
        "severity": finding.severity,
        "vrt": finding.cwe,
        "description": finding.description,
        "steps_to_reproduce": finding.steps_to_reproduce,
        "impact": finding.impact,
        "extra_info": f"CVSS: {finding.cvss_vector} ({finding.cvss_score})",
    }


def export_batch(
    findings: list[dict],
    format: str = "markdown",
) -> list[str | dict]:
    """Export a batch of findings in the specified format."""
    exported = [export_finding(f) for f in findings]
    if format == "markdown":
        return [to_markdown(e) for e in exported]
    if format == "hackerone":
        return [to_hackerone(e) for e in exported]
    if format == "bugcrowd":
        return [to_bugcrowd(e) for e in exported]
    return [to_markdown(e) for e in exported]
