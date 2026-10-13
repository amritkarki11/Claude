"""Reporter — turns verified findings into professional VAPT reports.

Takes a VerifyResult (or the human queue JSONL) and produces a structured
finding report in Kratikal house format:

  Title | Severity | CVSS | OWASP | CWE
  Description | Affected Component | Steps to Reproduce | Impact | Remediation

Two modes:
  1. Template-based (no LLM) — fills a structured template from evidence data.
     Deterministic, fast, always available.
  2. LLM-enhanced (optional) — uses the router to draft richer descriptions
     and impact analysis. Requires model access.

Export targets: Markdown (.md) and JSON.
"""
from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from .verify.base import VerifyResult, Verdict
from .scanners.base import Candidate
from .redact import redact


# ── Severity / classification maps ──────────────────────────

_CWE_MAP = {
    "idor": "CWE-639",
    "bola": "CWE-639",
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "xxe": "CWE-611",
    "ssrf": "CWE-918",
    "auth-bypass": "CWE-287",
    "broken-access": "CWE-284",
}

_OWASP_MAP = {
    "idor": "A01:2021 — Broken Access Control",
    "bola": "A01:2021 — Broken Access Control",
    "sqli": "A03:2021 — Injection",
    "xss": "A03:2021 — Injection",
    "xxe": "A05:2021 — Security Misconfiguration",
    "ssrf": "A10:2021 — Server-Side Request Forgery",
    "auth-bypass": "A07:2021 — Identification and Authentication Failures",
    "broken-access": "A01:2021 — Broken Access Control",
}

_SEVERITY_CVSS = {
    "critical": ("Critical", "9.0 – 10.0"),
    "high": ("High", "7.0 – 8.9"),
    "medium": ("Medium", "4.0 – 6.9"),
    "low": ("Low", "0.1 – 3.9"),
    "info": ("Informational", "0.0"),
}

_REMEDIATION_MAP = {
    "idor": (
        "Implement object-level authorization checks on every endpoint that "
        "accesses a resource using a client-supplied identifier. Verify that "
        "the authenticated user owns or has explicit permission to access the "
        "requested object. Use indirect references (UUIDs mapped server-side) "
        "instead of sequential/guessable IDs where possible."
    ),
    "bola": (
        "Implement object-level authorization checks. Validate that the "
        "requesting user has permission to access the specific resource."
    ),
    "sqli": (
        "Use parameterized queries / prepared statements for all database "
        "interactions. Apply input validation and implement a WAF rule."
    ),
    "xss": (
        "Encode all user-supplied output contextually (HTML, JS, URL). "
        "Implement Content-Security-Policy headers."
    ),
}


# ── Report data model ───────────────────────────────────────


@dataclass
class Finding:
    """A single finding in the report."""
    id: str                           # e.g. "FIND-001"
    title: str
    severity: str                     # critical / high / medium / low / info
    cvss_range: str                   # e.g. "7.0 – 8.9"
    owasp: str                        # e.g. "A01:2021 — Broken Access Control"
    cwe: str                          # e.g. "CWE-639"
    description: str
    affected_component: str           # endpoint + param
    steps_to_reproduce: list[str]
    request_sample: str               # sanitized HTTP request
    response_sample: str              # sanitized response snippet
    impact: str
    remediation: str
    confidence: str                   # high / medium / low
    verdict: str                      # CONFIRMED / NEEDS_HUMAN
    source_recipe: str                # recipe id
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class Report:
    """Full report for a scan run."""
    target: str
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    findings: list[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def set_summary(self, total_endpoints: int = 0, scans_run: int = 0,
                    confirmed: int = 0, needs_human: int = 0,
                    false_positives: int = 0) -> None:
        self.summary = {
            "total_endpoints": total_endpoints,
            "scans_run": scans_run,
            "confirmed": confirmed,
            "needs_human": needs_human,
            "false_positives": false_positives,
            "total_findings": len(self.findings),
        }


# ── Reporter ─────────────────────────────────────────────────


class Reporter:
    """Generates structured reports from verified findings."""

    def __init__(self, output_dir: pathlib.Path | str | None = None):
        self.output_dir = pathlib.Path(
            output_dir or pathlib.Path(__file__).parent.parent / "outputs"
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._counter = 0

    def finding_from_result(self, result: VerifyResult) -> Finding:
        """Convert a VerifyResult into a structured Finding."""
        self._counter += 1
        candidate = result.candidate
        vuln_class = self._infer_vuln_class(candidate)

        # Build title
        title = self._build_title(candidate, vuln_class)

        # Severity from recipe or inference
        severity = self._get_severity(candidate)
        _, cvss_range = _SEVERITY_CVSS.get(severity, ("Medium", "4.0 – 6.9"))

        # Classification
        owasp = _OWASP_MAP.get(vuln_class, "A01:2021 — Broken Access Control")
        cwe = _CWE_MAP.get(vuln_class, candidate.evidence.get("cwe", "CWE-284"))

        # Description
        description = self._build_description(candidate, result, vuln_class)

        # Affected component
        affected = self._build_affected(candidate)

        # Steps to reproduce
        steps = self._build_steps(candidate, result)

        # Request/response samples (redacted)
        req_sample = redact(self._format_request(candidate))
        resp_sample = redact(self._format_response(candidate, result))

        # Impact
        impact = self._build_impact(vuln_class, candidate)

        # Remediation
        remediation = _REMEDIATION_MAP.get(
            vuln_class,
            candidate.evidence.get("remediation", "Implement proper access controls.")
        )

        return Finding(
            id=f"FIND-{self._counter:03d}",
            title=title,
            severity=severity,
            cvss_range=cvss_range,
            owasp=owasp,
            cwe=cwe,
            description=description,
            affected_component=affected,
            steps_to_reproduce=steps,
            request_sample=req_sample,
            response_sample=resp_sample,
            impact=impact,
            remediation=remediation,
            confidence=candidate.confidence,
            verdict=result.verdict.value,
            source_recipe=candidate.recipe_id,
        )

    def finding_from_queue_entry(self, entry: dict) -> Finding:
        """Convert a human_queue.jsonl entry into a Finding."""
        self._counter += 1
        vuln_class = self._infer_vuln_class_from_dict(entry)
        severity = entry.get("severity", "high")
        _, cvss_range = _SEVERITY_CVSS.get(severity, ("High", "7.0 – 8.9"))

        req_data = entry.get("request_data", {})
        return Finding(
            id=f"FIND-{self._counter:03d}",
            title=self._build_title_from_dict(entry, vuln_class),
            severity=severity,
            cvss_range=cvss_range,
            owasp=_OWASP_MAP.get(vuln_class, "A01:2021 — Broken Access Control"),
            cwe=_CWE_MAP.get(vuln_class, "CWE-284"),
            description=f"The endpoint {entry.get('endpoint', 'N/A')} is vulnerable "
                        f"to {vuln_class.upper()}. {entry.get('reason', '')}",
            affected_component=f"{entry.get('method', 'POST')} {entry.get('endpoint', 'N/A')} "
                               f"(param: {req_data.get('id_param', 'N/A')})",
            steps_to_reproduce=[
                f"Authenticate as attacker (session: {req_data.get('session', 'attacker')})",
                f"Send {entry.get('method', 'POST')} to {entry.get('endpoint', 'N/A')} "
                f"with {req_data.get('id_param', 'id')}={req_data.get('id_value', 'VICTIM_ID')}",
                f"Observe: server returns success ({entry.get('evidence', {}).get('successes', 'N/A')}"
                f"/{entry.get('replays', 'N/A')} replays succeeded)",
            ],
            request_sample=redact(json.dumps(req_data, indent=2)),
            response_sample=redact(json.dumps(entry.get("evidence", {}), indent=2)[:500]),
            impact=self._build_impact(vuln_class),
            remediation=_REMEDIATION_MAP.get(vuln_class, "Implement proper access controls."),
            confidence=entry.get("confidence", "medium"),
            verdict=entry.get("verdict", "CONFIRMED"),
            source_recipe=entry.get("recipe_id", "unknown"),
        )

    def build_report(self, target: str,
                     results: list[VerifyResult] | None = None,
                     queue_entries: list[dict] | None = None) -> Report:
        """Build a full report from VerifyResults or queue entries."""
        report = Report(target=target)

        if results:
            for r in results:
                if r.verdict in (Verdict.CONFIRMED, Verdict.NEEDS_HUMAN):
                    report.add(self.finding_from_result(r))

        if queue_entries:
            for entry in queue_entries:
                report.add(self.finding_from_queue_entry(entry))

        return report

    # ── Export ────────────────────────────────────────────────

    def export_markdown(self, report: Report,
                        filename: str = "report.md") -> pathlib.Path:
        """Export report as Markdown."""
        path = self.output_dir / filename
        md = self._render_markdown(report)
        path.write_text(md, encoding="utf-8")
        return path

    def export_json(self, report: Report,
                    filename: str = "report.json") -> pathlib.Path:
        """Export report as JSON."""
        path = self.output_dir / filename
        data = {
            "target": report.target,
            "generated_at": report.generated_at,
            "summary": report.summary,
            "findings": [asdict(f) for f in report.findings],
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    # ── Markdown renderer ────────────────────────────────────

    def _render_markdown(self, report: Report) -> str:
        lines = [
            f"# VAPT Report — {report.target}",
            "",
            f"**Generated:** {report.generated_at}",
            "",
        ]

        # Summary table
        if report.summary:
            lines.append("## Executive Summary")
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")
            for k, v in report.summary.items():
                lines.append(f"| {k.replace('_', ' ').title()} | {v} |")
            lines.append("")

        # Severity breakdown
        if report.findings:
            sev_counts = {}
            for f in report.findings:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            lines.append("### Findings by Severity")
            lines.append("")
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in sev_counts:
                    lines.append(f"- **{sev.title()}:** {sev_counts[sev]}")
            lines.append("")

        # Findings
        lines.append("---")
        lines.append("")
        lines.append("## Findings")
        lines.append("")

        for f in report.findings:
            lines.extend(self._render_finding(f))

        return "\n".join(lines)

    def _render_finding(self, f: Finding) -> list[str]:
        lines = [
            f"### {f.id}: {f.title}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Severity** | {f.severity.title()} ({f.cvss_range}) |",
            f"| **OWASP** | {f.owasp} |",
            f"| **CWE** | {f.cwe} |",
            f"| **Confidence** | {f.confidence.title()} |",
            f"| **Verdict** | {f.verdict} |",
            "",
            "#### Description",
            "",
            f"{f.description}",
            "",
            "#### Affected Component",
            "",
            f"`{f.affected_component}`",
            "",
            "#### Steps to Reproduce",
            "",
        ]
        for i, step in enumerate(f.steps_to_reproduce, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

        if f.request_sample:
            lines.append("#### Request Sample")
            lines.append("")
            lines.append("```http")
            lines.append(f.request_sample)
            lines.append("```")
            lines.append("")

        if f.response_sample:
            lines.append("#### Response Sample")
            lines.append("")
            lines.append("```json")
            lines.append(f.response_sample)
            lines.append("```")
            lines.append("")

        lines.append("#### Impact")
        lines.append("")
        lines.append(f"{f.impact}")
        lines.append("")
        lines.append("#### Remediation")
        lines.append("")
        lines.append(f"{f.remediation}")
        lines.append("")
        lines.append("---")
        lines.append("")
        return lines

    # ── Internal helpers ─────────────────────────────────────

    def _infer_vuln_class(self, candidate: Candidate) -> str:
        rid = candidate.recipe_id.lower()
        for vc in _CWE_MAP:
            if vc in rid:
                return vc
        if candidate.scanner == "IdorScanner":
            return "idor"
        return "unknown"

    def _infer_vuln_class_from_dict(self, entry: dict) -> str:
        rid = entry.get("recipe_id", "").lower()
        for vc in _CWE_MAP:
            if vc in rid:
                return vc
        if entry.get("scanner") == "IdorScanner":
            return "idor"
        return "unknown"

    def _build_title(self, candidate: Candidate, vuln_class: str) -> str:
        endpoint_path = self._extract_path(candidate.endpoint)
        vuln_name = vuln_class.upper().replace("-", " ")
        return f"{vuln_name} on {endpoint_path}"

    def _build_title_from_dict(self, entry: dict, vuln_class: str) -> str:
        endpoint = entry.get("endpoint", "N/A")
        endpoint_path = self._extract_path(endpoint)
        vuln_name = vuln_class.upper().replace("-", " ")
        return f"{vuln_name} on {endpoint_path}"

    def _get_severity(self, candidate: Candidate) -> str:
        # Check evidence for severity
        sev = candidate.evidence.get("severity", "")
        if sev in _SEVERITY_CVSS:
            return sev
        # Infer from confidence
        if candidate.confidence == "high":
            return "high"
        elif candidate.confidence == "medium":
            return "medium"
        return "low"

    def _build_description(self, candidate: Candidate, result: VerifyResult,
                           vuln_class: str) -> str:
        req = candidate.request_data
        id_param = req.get("id_param", "identifier")
        id_location = req.get("id_location", "body")

        if vuln_class == "idor":
            return (
                f"The endpoint `{candidate.endpoint}` does not enforce object-level "
                f"authorization. An authenticated attacker can supply a victim's "
                f"`{id_param}` in the request {id_location} and perform actions on "
                f"behalf of the victim. Verification confirmed the issue across "
                f"{result.replays} replay(s) — {result.reason}."
            )
        return (
            f"A {vuln_class.upper()} vulnerability was identified at "
            f"`{candidate.endpoint}`. {result.reason}."
        )

    def _build_affected(self, candidate: Candidate) -> str:
        req = candidate.request_data
        param = req.get("id_param", "N/A")
        return f"{candidate.method} {candidate.endpoint} (param: {param})"

    def _build_steps(self, candidate: Candidate,
                     result: VerifyResult) -> list[str]:
        req = candidate.request_data
        session_type = req.get("session", "attacker")
        id_param = req.get("id_param", "id")
        id_value = req.get("id_value", "VICTIM_ID")
        id_location = req.get("id_location", "body")

        steps = [
            f"Authenticate as the {session_type} user and obtain a valid session",
            f"Send a {candidate.method} request to `{candidate.endpoint}`",
            f"Set `{id_param}` = `{id_value}` in the request {id_location}",
            f"Observe: the server returns HTTP {candidate.evidence.get('status', 200)} "
            f"with a success response",
            f"Repeat {result.replays} time(s) — all replays return success, "
            f"confirming the vulnerability is consistent",
        ]
        return steps

    def _build_impact(self, vuln_class: str,
                      candidate: Candidate | None = None) -> str:
        if vuln_class == "idor":
            return (
                "An attacker with a valid low-privilege session can access or "
                "modify resources belonging to other users by manipulating the "
                "object identifier. This can lead to unauthorized data access, "
                "account takeover, or triggering sensitive actions (e.g., OTP "
                "generation) for arbitrary users."
            )
        elif vuln_class == "sqli":
            return (
                "An attacker can extract, modify, or delete data from the "
                "backend database. In severe cases, this may lead to remote "
                "code execution on the database server."
            )
        return "Unauthorized access to resources or functionality."

    def _format_request(self, candidate: Candidate) -> str:
        req = candidate.request_data
        id_param = req.get("id_param", "id")
        id_value = req.get("id_value", "VALUE")
        id_location = req.get("id_location", "body")

        lines = [f"{candidate.method} {candidate.endpoint} HTTP/1.1"]
        if id_location == "body":
            lines.append("Content-Type: application/json")
            lines.append("")
            lines.append(json.dumps({id_param: id_value}))
        elif id_location == "query":
            lines[0] = f"{candidate.method} {candidate.endpoint}?{id_param}={id_value} HTTP/1.1"
        return "\n".join(lines)

    def _format_response(self, candidate: Candidate,
                         result: VerifyResult) -> str:
        status = candidate.evidence.get("status", 200)
        body = candidate.evidence.get("body_snippet", "")
        if not body:
            body = json.dumps(result.evidence.get("responses", [{}])[0], indent=2)
        return f"HTTP/1.1 {status}\n\n{body}"

    @staticmethod
    def _extract_path(url: str) -> str:
        """Extract the path portion from a URL for readable titles."""
        match = re.search(r"https?://[^/]+(/.+)", url)
        return match.group(1) if match else url
