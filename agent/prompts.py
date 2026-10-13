"""Prompt templates for each model job type.

Each template takes structured context and returns a (system, user) tuple
ready for router.ask(). Templates are kept minimal — the model should
reason, not follow a script.
"""
from __future__ import annotations

from typing import Optional


def triage(endpoint: str, method: str, params: list[str],
           tech_signals: list[str], notes: str = "") -> tuple[str, str]:
    """Local model decides if an endpoint is worth deeper testing."""
    system = (
        "You are a penetration testing triage engine. Given an endpoint and its "
        "context, decide which vulnerability classes are worth testing. "
        "Reply ONLY with a JSON object: "
        '{"dominated_by": ["sqli", "xxe", ...], "priority": "high|medium|low", '
        '"reason": "one sentence"}. No other text.'
    )
    user = (
        f"Endpoint: {method} {endpoint}\n"
        f"Parameters: {', '.join(params) if params else 'none discovered'}\n"
        f"Tech signals: {', '.join(tech_signals)}\n"
    )
    if notes:
        user += f"Notes: {notes}\n"
    return system, user


def hypothesis(endpoint: str, method: str, tech_signals: list[str],
               checklist_context: str, recon_summary: str = "") -> tuple[str, str]:
    """Free-tier model generates attack hypotheses for an endpoint."""
    system = (
        "You are a senior penetration tester. Given an endpoint and its context, "
        "generate concrete attack hypotheses — specific payloads or test sequences "
        "to try. Focus on what is MOST LIKELY to work based on the tech stack. "
        "Reply with a JSON array of objects: "
        '[{"vuln_class": "xxe", "hypothesis": "...", "test_steps": ["step1", ...], '
        '"confidence": "high|medium|low"}]. Max 5 hypotheses, ranked by likelihood.'
    )
    user = (
        f"Endpoint: {method} {endpoint}\n"
        f"Tech signals: {', '.join(tech_signals)}\n"
        f"Relevant checklist:\n{checklist_context}\n"
    )
    if recon_summary:
        user += f"\nRecon context:\n{recon_summary}\n"
    return system, user


def exploit_chain(finding_context: str, recon_data: str,
                  skill_context: str = "") -> tuple[str, str]:
    """Frontier model reasons about multi-step exploit chains."""
    system = (
        "You are an expert penetration tester analyzing a potential vulnerability. "
        "Given the finding context and recon data, determine:\n"
        "1. Is this exploitable? What confirms it?\n"
        "2. What is the maximum impact (data access, RCE, priv esc)?\n"
        "3. Can this chain with other findings for greater impact?\n"
        "4. What is the exact verification step to confirm exploitation?\n\n"
        "Reply with JSON: "
        '{"exploitable": true/false, "confidence": "high|medium|low", '
        '"impact": "...", "chain_with": ["finding_id", ...], '
        '"verify_steps": ["step1", ...], "severity": "critical|high|medium|low|info"}'
    )
    user = f"Finding context:\n{finding_context}\n\nRecon data:\n{recon_data}\n"
    if skill_context:
        user += f"\nMethodology reference:\n{skill_context}\n"
    return system, user


def report(finding: dict, template_context: str = "") -> tuple[str, str]:
    """Free-tier model drafts a finding report from verified data."""
    system = (
        "You are a security report writer. Given a verified finding, write a "
        "professional VAPT finding report section. Include:\n"
        "- Title with finding ID\n"
        "- Severity + CVSS score\n"
        "- OWASP category + CWE\n"
        "- Clear description (2-3 sentences)\n"
        "- Affected component (endpoint, parameter, module)\n"
        "- Steps to reproduce (with HTTP request/response)\n"
        "- Impact (specific, not generic)\n"
        "- Remediation (actionable, developer-friendly)\n\n"
        "Write in markdown. Be specific — 'SQL injection in export config endpoint' "
        "not 'SQL injection was found'."
    )
    user = f"Verified finding data:\n"
    for k, v in finding.items():
        user += f"  {k}: {v}\n"
    if template_context:
        user += f"\nReport template reference:\n{template_context}\n"
    return system, user


def extraction(raw_response: str, extract_type: str = "endpoints") -> tuple[str, str]:
    """Local model extracts structured data from raw responses."""
    system = (
        f"Extract {extract_type} from the following text. "
        "Reply ONLY with a JSON array of the extracted items. No explanation."
    )
    return system, raw_response


def redaction_check(text: str) -> tuple[str, str]:
    """Local model does a context-aware second pass for PII that regex missed."""
    system = (
        "You are a privacy filter. The following text will be sent to a cloud API. "
        "Identify ANY remaining sensitive information that should be redacted:\n"
        "- Person names, usernames, employee IDs\n"
        "- Internal hostnames, IP ranges, network topology\n"
        "- API keys, tokens, passwords (even partial)\n"
        "- Client/company names that identify the target\n\n"
        "Reply with JSON: "
        '{"found": [{"text": "exact match", "type": "name|hostname|key|..."}], '
        '"clean": true/false}. If nothing found, {"found": [], "clean": true}.'
    )
    return system, text
