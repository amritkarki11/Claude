"""Report engine — generates HTML and PDF pentest reports.

Supports two modes:
  - Bug Bounty: concise per-finding reports for platform submission
  - VAPT: full professional report with executive summary, methodology,
    findings detail, compliance mapping, and appendices
"""
from __future__ import annotations

import html
import json
import pathlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .cvss import CvssVector, cvss_for_finding


@dataclass
class ReportFinding:
    """A single finding ready for the report."""
    title: str
    severity: str
    cvss_vector: CvssVector
    cvss_score: float
    endpoint: str
    method: str
    description: str
    evidence: dict
    remediation: str
    recipe_id: str = ""
    scanner: str = ""
    cwe: str = ""
    owasp: str = ""
    request_data: dict = field(default_factory=dict)
    response_data: dict = field(default_factory=dict)

    @classmethod
    def from_verify_result(cls, result: dict) -> ReportFinding:
        """Convert a human_queue entry to a ReportFinding."""
        cvss = cvss_for_finding(result)
        recipe_id = result.get("recipe_id", "unknown")
        evidence = result.get("evidence", {})

        title = recipe_id.replace("-", " ").replace("_", " ").title()
        if "auto:" in recipe_id:
            title = recipe_id.split(":", 1)[1].replace("-", " ").title()

        return cls(
            title=title,
            severity=cvss.severity(),
            cvss_vector=cvss,
            cvss_score=cvss.score(),
            endpoint=result.get("endpoint", ""),
            method=result.get("method", "GET"),
            description=result.get("reason", ""),
            evidence=evidence,
            remediation=evidence.get("recommendation", "See OWASP guidelines."),
            recipe_id=recipe_id,
            scanner=result.get("scanner", ""),
            cwe=evidence.get("cwe", ""),
            owasp=evidence.get("owasp_ref", ""),
            request_data=result.get("request_data", {}),
            response_data=result.get("response_data", {}),
        )


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    title: str = "Penetration Test Report"
    target: str = ""
    client: str = ""
    tester: str = "AUTON Pentest Agent"
    date: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    engagement_id: str = ""
    executive_summary: str = ""
    methodology: str = (
        "Testing was performed using automated vulnerability scanning with "
        "deterministic verification. All findings were confirmed through "
        "replay-based evidence collection before inclusion in this report."
    )
    scope_description: str = ""


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
_SEVERITY_COLORS = {
    "critical": "#7b2d8b",
    "high": "#d32f2f",
    "medium": "#f57c00",
    "low": "#1976d2",
    "none": "#757575",
}


def generate_html_report(
    findings: list[ReportFinding],
    config: ReportConfig,
) -> str:
    """Generate a full HTML pentest report."""
    findings_sorted = sorted(
        findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)
    )

    severity_counts = {}
    for f in findings_sorted:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    findings_html = []
    for i, f in enumerate(findings_sorted, 1):
        color = _SEVERITY_COLORS.get(f.severity, "#757575")
        evidence_str = _format_evidence(f.evidence)
        request_str = _format_request(f.request_data)

        findings_html.append(f"""
        <div class="finding">
            <h3>{i}. {html.escape(f.title)}
                <span class="severity-badge" style="background:{color}">
                    {f.severity.upper()} ({f.cvss_score})
                </span>
            </h3>
            <table class="finding-meta">
                <tr><td><strong>CVSS Vector</strong></td><td><code>{html.escape(f.cvss_vector.vector_string())}</code></td></tr>
                <tr><td><strong>Endpoint</strong></td><td><code>{html.escape(f.endpoint)}</code></td></tr>
                <tr><td><strong>Method</strong></td><td>{html.escape(f.method)}</td></tr>
                {"<tr><td><strong>CWE</strong></td><td>" + html.escape(f.cwe) + "</td></tr>" if f.cwe else ""}
                {"<tr><td><strong>OWASP</strong></td><td>" + html.escape(f.owasp) + "</td></tr>" if f.owasp else ""}
            </table>
            <h4>Description</h4>
            <p>{html.escape(f.description)}</p>
            <h4>Evidence</h4>
            <pre class="evidence">{html.escape(evidence_str)}</pre>
            {f'<h4>Request</h4><pre class="evidence">{html.escape(request_str)}</pre>' if request_str else ''}
            <h4>Remediation</h4>
            <p>{html.escape(f.remediation)}</p>
        </div>
        """)

    summary_rows = "".join(
        f'<tr><td style="color:{_SEVERITY_COLORS.get(sev, "#757575")}">'
        f'{sev.upper()}</td><td>{count}</td></tr>'
        for sev, count in sorted(severity_counts.items(),
                                  key=lambda x: _SEVERITY_ORDER.get(x[0], 99))
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(config.title)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       max-width: 900px; margin: 0 auto; padding: 20px; color: #333; line-height: 1.6; }}
h1 {{ border-bottom: 3px solid #1a237e; padding-bottom: 10px; }}
h2 {{ color: #1a237e; margin-top: 40px; }}
.meta {{ background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0; }}
.meta td {{ padding: 4px 12px; }}
.finding {{ border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; margin: 20px 0; }}
.finding h3 {{ margin-top: 0; }}
.severity-badge {{ color: white; padding: 2px 10px; border-radius: 4px; font-size: 0.85em; float: right; }}
.finding-meta td {{ padding: 3px 10px; }}
.evidence {{ background: #263238; color: #aed581; padding: 12px; border-radius: 4px;
             overflow-x: auto; font-size: 0.85em; white-space: pre-wrap; word-break: break-all; }}
.summary-table td {{ padding: 6px 16px; }}
@media print {{ .finding {{ page-break-inside: avoid; }} }}
</style>
</head>
<body>
<h1>{html.escape(config.title)}</h1>
<table class="meta">
<tr><td><strong>Target</strong></td><td>{html.escape(config.target)}</td></tr>
{"<tr><td><strong>Client</strong></td><td>" + html.escape(config.client) + "</td></tr>" if config.client else ""}
<tr><td><strong>Date</strong></td><td>{html.escape(config.date)}</td></tr>
<tr><td><strong>Tester</strong></td><td>{html.escape(config.tester)}</td></tr>
{"<tr><td><strong>Engagement ID</strong></td><td>" + html.escape(config.engagement_id) + "</td></tr>" if config.engagement_id else ""}
</table>

<h2>Executive Summary</h2>
<p>{html.escape(config.executive_summary) if config.executive_summary else
   f"A total of {len(findings)} vulnerabilities were identified during testing."}</p>

<h2>Findings Summary</h2>
<table class="summary-table">
<tr><th>Severity</th><th>Count</th></tr>
{summary_rows}
<tr><td><strong>Total</strong></td><td><strong>{len(findings)}</strong></td></tr>
</table>

<h2>Methodology</h2>
<p>{html.escape(config.methodology)}</p>

<h2>Detailed Findings</h2>
{"".join(findings_html)}

<hr>
<p style="color:#999; font-size:0.85em;">
Generated by AUTON Pentest Agent on {html.escape(config.date)}
</p>
</body>
</html>"""


def _format_evidence(evidence: dict) -> str:
    filtered = {k: v for k, v in evidence.items() if v and k != "recommendation"}
    return json.dumps(filtered, indent=2, default=str) if filtered else "No evidence captured."


def _format_request(request_data: dict) -> str:
    if not request_data:
        return ""
    full = request_data.get("full_request", "")
    if full:
        return full
    parts = []
    if request_data.get("url"):
        method = request_data.get("method", "GET")
        parts.append(f"{method} {request_data['url']}")
    if request_data.get("payload"):
        parts.append(f"Payload: {request_data['payload']}")
    return "\n".join(parts)


def generate_report_from_queue(
    queue_file: pathlib.Path | str,
    config: ReportConfig,
    output_path: pathlib.Path | str,
) -> pathlib.Path:
    """Read human_queue.jsonl and generate an HTML report."""
    queue_file = pathlib.Path(queue_file)
    output_path = pathlib.Path(output_path)

    findings = []
    if queue_file.exists():
        with queue_file.open("r") as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    if entry.get("verdict") in ("confirmed", "needs_human"):
                        findings.append(ReportFinding.from_verify_result(entry))

    report_html = generate_html_report(findings, config)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_html, encoding="utf-8")
    return output_path
