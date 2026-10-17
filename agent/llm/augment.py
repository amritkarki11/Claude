"""LLM augmentation — enriches scan results when enabled.

All functions degrade gracefully: if LLM is disabled or fails, they return
a sensible default. The LLM never decides findings — only enriches them.
"""
from __future__ import annotations

import logging
from typing import Any

from .gate import llm_optional, llm_optional_async, is_enabled

logger = logging.getLogger(__name__)


@llm_optional(fallback=None)
def enrich_finding_description(finding: dict) -> dict | None:
    """Use LLM to improve a finding's description and remediation text.

    Returns a dict with 'description' and 'remediation' keys, or None.
    """
    from ..redact import redact
    from ..router import route

    prompt = (
        "You are a security consultant. Given this vulnerability finding, "
        "write a clear 2-3 sentence description and specific remediation advice.\n\n"
        f"Vulnerability: {finding.get('recipe_id', 'unknown')}\n"
        f"Endpoint: {redact(finding.get('endpoint', ''))}\n"
        f"Evidence: {redact(str(finding.get('evidence', {}))[:500])}\n\n"
        "Respond as JSON: {\"description\": \"...\", \"remediation\": \"...\"}"
    )

    result = route("fast", prompt)
    if result and isinstance(result, dict):
        return {
            "description": result.get("description", ""),
            "remediation": result.get("remediation", ""),
        }
    return None


@llm_optional(fallback=[])
def suggest_attack_surface(tech_signals: list[str], endpoints: list[str]) -> list[str]:
    """Suggest additional attack vectors based on tech stack.

    Returns a list of vuln classes to prioritize. Advisory only.
    """
    from ..redact import redact
    from ..router import route

    prompt = (
        "Given these technology signals and endpoints, suggest the top 5 "
        "vulnerability classes most likely to be present. Return only the "
        "vuln class names as a JSON array.\n\n"
        f"Tech signals: {tech_signals}\n"
        f"Endpoint count: {len(endpoints)}\n"
        f"Sample endpoints: {[redact(e) for e in endpoints[:5]]}"
    )

    result = route("fast", prompt)
    if result and isinstance(result, list):
        return [str(v) for v in result[:5]]
    return []


@llm_optional(fallback="")
def generate_executive_summary(
    target: str,
    findings: list[dict],
    tech_signals: list[str],
) -> str:
    """Generate an executive summary for a VAPT report.

    Returns plain text summary, or empty string if LLM unavailable.
    """
    from ..redact import redact
    from ..router import route

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    prompt = (
        "Write a professional executive summary (3-4 paragraphs) for a "
        "penetration test report.\n\n"
        f"Target: {redact(target)}\n"
        f"Findings by severity: {severity_counts}\n"
        f"Total findings: {len(findings)}\n"
        f"Technologies detected: {tech_signals}\n\n"
        "Focus on business risk, not technical details. "
        "Be direct about severity without being alarmist."
    )

    result = route("fast", prompt)
    if result and isinstance(result, str):
        return result
    return ""
