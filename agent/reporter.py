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
    "sql-injection": "CWE-89",
    "xss": "CWE-79",
    "xxe": "CWE-611",
    "ssrf": "CWE-918",
    "auth-bypass": "CWE-287",
    "broken-access": "CWE-284",
    "nosqli": "CWE-943",
    "nosql-injection": "CWE-943",
    "ssti": "CWE-1336",
    "template-injection": "CWE-1336",
    "cmdi": "CWE-78",
    "command-injection": "CWE-78",
    "os-command-injection": "CWE-78",
    "lfi": "CWE-22",
    "path-traversal": "CWE-22",
    "file-inclusion": "CWE-98",
    "csrf": "CWE-352",
    "cross-site-request-forgery": "CWE-352",
    "stored-xss": "CWE-79",
    "open-redirect": "CWE-601",
}

_OWASP_MAP = {
    "idor": "A01:2021 — Broken Access Control",
    "bola": "A01:2021 — Broken Access Control",
    "sqli": "A03:2021 — Injection",
    "sql-injection": "A03:2021 — Injection",
    "xss": "A03:2021 — Injection",
    "xxe": "A05:2021 — Security Misconfiguration",
    "ssrf": "A10:2021 — Server-Side Request Forgery",
    "auth-bypass": "A07:2021 — Identification and Authentication Failures",
    "broken-access": "A01:2021 — Broken Access Control",
    "nosqli": "A03:2021 — Injection",
    "nosql-injection": "A03:2021 — Injection",
    "ssti": "A03:2021 — Injection",
    "template-injection": "A03:2021 — Injection",
    "cmdi": "A03:2021 — Injection",
    "command-injection": "A03:2021 — Injection",
    "os-command-injection": "A03:2021 — Injection",
    "lfi": "A01:2021 — Broken Access Control",
    "path-traversal": "A01:2021 — Broken Access Control",
    "file-inclusion": "A03:2021 — Injection",
    "csrf": "A01:2021 — Broken Access Control",
    "cross-site-request-forgery": "A01:2021 — Broken Access Control",
    "stored-xss": "A03:2021 — Injection",
    "open-redirect": "A01:2021 — Broken Access Control",
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
    "sql-injection": (
        "Use parameterized queries / prepared statements for all database "
        "interactions. Apply input validation and implement a WAF rule."
    ),
    "xss": (
        "Encode all user-supplied output contextually (HTML, JS, URL). "
        "Implement Content-Security-Policy headers."
    ),
    "nosqli": (
        "Use the database driver's built-in query builder instead of "
        "constructing query objects from raw user input. Validate and "
        "type-check all input — reject objects/arrays where strings are "
        "expected. Disable server-side JavaScript execution ($where) if "
        "not required."
    ),
    "nosql-injection": (
        "Use the database driver's built-in query builder instead of "
        "constructing query objects from raw user input. Validate and "
        "type-check all input — reject objects/arrays where strings are "
        "expected."
    ),
    "ssti": (
        "Never pass user input directly into template strings. Use the "
        "template engine's sandboxing mode (e.g. Jinja2 SandboxedEnvironment). "
        "Treat user input as data, not code — render it via template variables, "
        "not string concatenation. If user-controlled templates are required, "
        "use a logic-less engine (e.g. Mustache)."
    ),
    "template-injection": (
        "Never pass user input directly into template strings. Use the "
        "template engine's sandboxing mode."
    ),
    "cmdi": (
        "Avoid calling OS commands with user-supplied input. Use language-native "
        "libraries instead of shell commands (e.g. Python's shutil instead of "
        "os.system('cp ...')). If shell execution is unavoidable, use "
        "parameterized APIs (e.g. subprocess with a list, not a string) and "
        "apply strict allowlist validation on the input."
    ),
    "command-injection": (
        "Avoid calling OS commands with user-supplied input. Use parameterized "
        "APIs (subprocess with list arguments) and strict allowlist validation."
    ),
    "os-command-injection": (
        "Avoid calling OS commands with user-supplied input. Use parameterized "
        "APIs (subprocess with list arguments) and strict allowlist validation."
    ),
    "lfi": (
        "Never use user-supplied input directly in file paths. Maintain an "
        "allowlist of permitted file names or use indirect references (numeric "
        "IDs mapped server-side). Normalize and validate paths — reject any "
        "input containing '..' or path separators. Configure the application "
        "to run with minimum filesystem permissions."
    ),
    "path-traversal": (
        "Never use user-supplied input directly in file paths. Validate and "
        "normalize paths, reject input containing '..' or path separators."
    ),
    "file-inclusion": (
        "Never include files based on user input. Use an allowlist of "
        "permitted includes and map user input to that list indirectly."
    ),
    "csrf": (
        "Implement anti-CSRF tokens on all state-changing endpoints "
        "(POST/PUT/PATCH/DELETE). Use a framework-provided CSRF middleware "
        "(e.g. Django's CsrfViewMiddleware, Express csurf). Validate the "
        "token on the server for every state-changing request. Set the "
        "SameSite cookie attribute to Strict or Lax as an additional layer."
    ),
    "cross-site-request-forgery": (
        "Implement anti-CSRF tokens on all state-changing endpoints. "
        "Use framework-provided CSRF middleware and set SameSite cookie "
        "attribute to Strict or Lax."
    ),
    "stored-xss": (
        "Sanitize and encode all user-supplied content before storing AND "
        "before rendering. Use a context-aware output encoding library "
        "(e.g. DOMPurify for HTML, textContent for DOM insertion). "
        "Implement Content-Security-Policy headers with strict script-src. "
        "Validate input on the server side — reject or strip HTML tags "
        "where rich text is not required."
    ),
    "open-redirect": (
        "Validate redirect targets against an allowlist of permitted "
        "domains or paths. Use relative URLs for internal redirects instead "
        "of accepting full URLs from user input. If external redirects are "
        "required, show an interstitial warning page. Never blindly redirect "
        "to a user-supplied URL parameter."
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

    # Map scanner class names to canonical vuln classes
    _SCANNER_VULN_MAP = {
        "IdorScanner": "idor",
        "SqliScanner": "sqli",
        "XssScanner": "xss",
        "SsrfScanner": "ssrf",
        "NosqliScanner": "nosqli",
        "SstiScanner": "ssti",
        "CmdiScanner": "cmdi",
        "LfiScanner": "lfi",
        "CsrfScanner": "csrf",
        "StoredXssScanner": "stored-xss",
        "OpenRedirectScanner": "open-redirect",
        "AuthBypassDiscovery": "auth-bypass",
    }

    def _infer_vuln_class(self, candidate: Candidate) -> str:
        # Check scanner class name first (most reliable)
        if candidate.scanner in self._SCANNER_VULN_MAP:
            return self._SCANNER_VULN_MAP[candidate.scanner]
        # Fallback: check recipe ID
        rid = candidate.recipe_id.lower()
        for vc in _CWE_MAP:
            if vc in rid:
                return vc
        return "unknown"

    def _infer_vuln_class_from_dict(self, entry: dict) -> str:
        scanner = entry.get("scanner", "")
        if scanner in self._SCANNER_VULN_MAP:
            return self._SCANNER_VULN_MAP[scanner]
        rid = entry.get("recipe_id", "").lower()
        for vc in _CWE_MAP:
            if vc in rid:
                return vc
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
        id_param = req.get("id_param", req.get("param", "identifier"))
        id_location = req.get("id_location", "body")
        evidence = candidate.evidence

        if vuln_class == "idor":
            return (
                f"The endpoint `{candidate.endpoint}` does not enforce object-level "
                f"authorization. An authenticated attacker can supply a victim's "
                f"`{id_param}` in the request {id_location} and perform actions on "
                f"behalf of the victim. Verification confirmed the issue across "
                f"{result.replays} replay(s) — {result.reason}."
            )
        elif vuln_class in ("sqli", "sql-injection"):
            technique = evidence.get("technique", "error-based")
            db_type = evidence.get("db_type", "unknown")
            return (
                f"The parameter `{id_param}` at `{candidate.endpoint}` is vulnerable "
                f"to SQL injection ({technique}). The backend database appears to be "
                f"{db_type}. The vulnerability was confirmed through a multi-step "
                f"verification chain (BREAK → FIX → BOOLEAN → TIME)."
            )
        elif vuln_class in ("nosqli", "nosql-injection"):
            technique = evidence.get("technique", "operator-injection")
            return (
                f"The parameter `{id_param}` at `{candidate.endpoint}` is vulnerable "
                f"to NoSQL injection ({technique}). An attacker can manipulate database "
                f"queries by injecting MongoDB operators or JavaScript expressions."
            )
        elif vuln_class in ("ssti", "template-injection"):
            engine = evidence.get("engine", "unknown")
            technique = evidence.get("technique", "math-probe")
            return (
                f"The parameter `{id_param}` at `{candidate.endpoint}` is vulnerable "
                f"to Server-Side Template Injection ({technique}). The template engine "
                f"appears to be {engine}. An attacker can inject template expressions "
                f"that are evaluated on the server."
            )
        elif vuln_class in ("cmdi", "command-injection", "os-command-injection"):
            technique = evidence.get("technique", "command-injection")
            separator = evidence.get("separator", "unknown")
            return (
                f"The parameter `{id_param}` at `{candidate.endpoint}` is vulnerable "
                f"to OS command injection ({technique}, separator: {separator}). "
                f"An attacker can execute arbitrary system commands on the server."
            )
        elif vuln_class in ("lfi", "path-traversal", "file-inclusion"):
            target_file = evidence.get("target_file", "/etc/passwd")
            technique = evidence.get("technique", "path-traversal")
            return (
                f"The parameter `{id_param}` at `{candidate.endpoint}` is vulnerable "
                f"to path traversal / local file inclusion ({technique}). The file "
                f"`{target_file}` was successfully read from the server filesystem."
            )
        return (
            f"A {vuln_class.upper()} vulnerability was identified at "
            f"`{candidate.endpoint}`. {result.reason}."
        )

    def _build_affected(self, candidate: Candidate) -> str:
        req = candidate.request_data
        param = req.get("id_param", req.get("param", "N/A"))
        return f"{candidate.method} {candidate.endpoint} (param: {param})"

    def _build_curl(self, candidate: Candidate) -> str:
        """Build a curl command to reproduce the finding."""
        from .display import build_curl_command
        return build_curl_command(candidate)

    def _build_steps(self, candidate: Candidate,
                     result: VerifyResult) -> list[str]:
        req = candidate.request_data
        evidence = candidate.evidence
        vuln_class = self._infer_vuln_class(candidate)

        # Generic params
        param = req.get("id_param", req.get("param", "id"))
        id_location = req.get("id_location", req.get("location", "body"))

        # Build curl command for reproduction
        curl_cmd = self._build_curl(candidate)

        if vuln_class == "idor":
            session_type = req.get("session", "attacker")
            id_value = req.get("id_value", "VICTIM_ID")
            steps = [
                f"Authenticate as the {session_type} user and obtain a valid session",
                f"Send a {candidate.method} request to `{candidate.endpoint}`",
                f"Set `{param}` = `{id_value}` in the request {id_location}",
                f"Observe: the server returns HTTP {evidence.get('status', 200)} "
                f"with a success response",
                f"Repeat {result.replays} time(s) — all replays return success, "
                f"confirming the vulnerability is consistent",
            ]

        elif vuln_class in ("sqli", "sql-injection"):
            payload = req.get("payload", "'")
            fix_payload = req.get("fix_payload", "''")
            technique = req.get("technique", "error-based")
            siblings = req.get("sibling_fields", {})
            sibling_note = ""
            if siblings:
                sibling_note = f" (with sibling fields: {', '.join(f'{k}={v}' for k, v in siblings.items())})"
            steps = [
                f"Navigate to `{candidate.endpoint}`",
                f"In the `{param}` parameter ({id_location}), inject: `{payload}`{sibling_note}",
                f"Observe: the server returns a database error (HTTP {evidence.get('break_status', 500)})",
                f"Inject the FIX payload: `{fix_payload}` in the same parameter",
                f"Observe: normal response is restored (HTTP {evidence.get('fix_status', 200)}), "
                f"confirming the input reaches the SQL query ({technique})",
            ]

        elif vuln_class in ("nosqli", "nosql-injection"):
            payload = req.get("payload", "")
            technique = evidence.get("technique", "operator-injection")
            steps = [
                f"Navigate to `{candidate.endpoint}`",
                f"In the `{param}` parameter ({id_location}), inject: `{payload}`",
                f"Observe: the server response indicates successful query manipulation "
                f"({technique})",
                f"The verification chain confirmed: operator injection → tautology "
                f"comparison → consistent behavior",
            ]

        elif vuln_class in ("ssti", "template-injection"):
            payload = req.get("payload", "{{7*7}}")
            engine = evidence.get("engine", "unknown")
            steps = [
                f"Navigate to `{candidate.endpoint}`",
                f"In the `{param}` parameter ({id_location}), inject: `{payload}`",
                f"Observe: the server evaluates the math expression and returns the "
                f"result (e.g., 49) in the response body",
                f"Template engine identified: {engine}",
                f"A confirmation probe with a different expression verified the finding",
            ]

        elif vuln_class in ("cmdi", "command-injection", "os-command-injection"):
            payload = req.get("payload", "")
            separator = evidence.get("separator", req.get("separator", "unknown"))
            technique = evidence.get("technique", req.get("technique", "output-based"))
            steps = [
                f"Navigate to `{candidate.endpoint}`",
                f"In the `{param}` parameter ({id_location}), inject: `{payload}`",
                f"The payload uses the `{separator}` separator to chain an OS command",
                f"Observe: the server executes the injected command ({technique})",
                f"A second verification (math or time-based) confirmed the finding "
                f"is not a false positive",
            ]

        elif vuln_class in ("lfi", "path-traversal", "file-inclusion"):
            payload = req.get("payload", "")
            target_file = evidence.get("target_file", "/etc/passwd")
            depth = evidence.get("traversal_depth", "unknown")
            steps = [
                f"Navigate to `{candidate.endpoint}`",
                f"In the `{param}` parameter ({id_location}), inject: `{payload}`",
                f"Observe: the server returns the contents of `{target_file}` "
                f"(traversal depth: {depth})",
                f"A depth-vary check confirmed the traversal is real — different "
                f"depths return the same file content",
            ]

        else:
            # Generic fallback
            payload = req.get("payload", req.get("id_value", "PAYLOAD"))
            steps = [
                f"Send a {candidate.method} request to `{candidate.endpoint}`",
                f"Set `{param}` = `{payload}` in the request {id_location}",
                f"Observe: the server response indicates vulnerability",
            ]

        # Append curl command for reproduction
        if curl_cmd:
            steps.append(f"**Reproduce with curl:**\n```\n{curl_cmd}\n```")

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
        elif vuln_class in ("sqli", "sql-injection"):
            return (
                "An attacker can extract, modify, or delete data from the "
                "backend database. In severe cases, this may lead to remote "
                "code execution on the database server."
            )
        elif vuln_class in ("nosqli", "nosql-injection"):
            return (
                "An attacker can bypass authentication, extract data from the "
                "NoSQL database, or manipulate query results. In cases where "
                "$where JavaScript injection is possible, this can lead to "
                "denial of service or server-side code execution."
            )
        elif vuln_class in ("ssti", "template-injection"):
            return (
                "An attacker can execute arbitrary code on the server through "
                "template injection. Depending on the template engine and "
                "configuration, this can lead to remote code execution, "
                "reading sensitive files, or full server compromise."
            )
        elif vuln_class in ("cmdi", "command-injection", "os-command-injection"):
            return (
                "An attacker can execute arbitrary operating system commands "
                "on the server. This typically leads to full server compromise, "
                "data exfiltration, lateral movement, and persistent backdoor "
                "installation."
            )
        elif vuln_class in ("lfi", "path-traversal", "file-inclusion"):
            return (
                "An attacker can read arbitrary files from the server "
                "filesystem, including configuration files, source code, and "
                "credentials. If combined with file upload or log poisoning, "
                "this may escalate to remote code execution."
            )
        return "Unauthorized access to resources or functionality."

    def _format_request(self, candidate: Candidate) -> str:
        req = candidate.request_data

        # Prefer exact captured request if available
        full_req = req.get("full_request", "")
        if full_req:
            return full_req

        # Fallback: build from structured data
        id_param = req.get("id_param", req.get("param", ""))
        id_value = req.get("id_value", req.get("payload", "VALUE"))
        id_location = req.get("id_location", "body")
        siblings = req.get("sibling_fields", {})

        if not id_param:
            # No param info — return minimal request line
            return f"{candidate.method} {candidate.endpoint} HTTP/1.1"

        lines = [f"{candidate.method} {candidate.endpoint} HTTP/1.1"]
        if id_location == "body":
            lines.append("Content-Type: application/x-www-form-urlencoded")
            lines.append("")
            body_params = dict(siblings)
            body_params[id_param] = id_value
            lines.append("&".join(f"{k}={v}" for k, v in body_params.items()))
        elif id_location == "query":
            query_parts = [f"{id_param}={id_value}"]
            for k, v in siblings.items():
                query_parts.append(f"{k}={v}")
            lines[0] = f"{candidate.method} {candidate.endpoint}?{'&'.join(query_parts)} HTTP/1.1"
        return "\n".join(lines)

    def _format_response(self, candidate: Candidate,
                         result: VerifyResult) -> str:
        resp = candidate.response_data

        # Prefer exact captured response if available
        full_resp = resp.get("full_response", "")
        if full_resp:
            return full_resp

        # Fallback: build from evidence
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
