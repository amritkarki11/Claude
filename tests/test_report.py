"""Tests for report engine, CVSS calculator, and compliance mapping."""
import json
import pathlib
import pytest

from agent.report.cvss import (
    CvssVector,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    Impact,
    cvss_for_finding,
    VULN_CLASS_CVSS,
)
from agent.report.engine import (
    ReportFinding,
    ReportConfig,
    generate_html_report,
    generate_report_from_queue,
)
from agent.report.compliance import (
    get_compliance_refs,
    get_cwe,
    ComplianceRef,
)


# --- CVSS ---

class TestCvss:
    def test_all_high_network(self):
        v = CvssVector(
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        assert v.score() == 9.8
        assert v.severity() == "critical"

    def test_zero_impact(self):
        v = CvssVector()
        assert v.score() == 0.0
        assert v.severity() == "none"

    def test_medium_score(self):
        v = CvssVector(
            user_interaction=UserInteraction.REQUIRED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
        )
        score = v.score()
        assert 4.0 <= score <= 6.9
        assert v.severity() == "medium"

    def test_scope_changed(self):
        v_unchanged = CvssVector(
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
        )
        v_changed = CvssVector(
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
        )
        assert v_changed.score() > v_unchanged.score()

    def test_vector_string(self):
        v = CvssVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        assert v.vector_string() == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_from_string_roundtrip(self):
        vs = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        v = CvssVector.from_string(vs)
        assert v.vector_string() == vs
        assert v.score() == 9.8

    def test_cvss_for_finding_sqli(self):
        v = cvss_for_finding({"recipe_id": "sqli-error"})
        assert v.score() == 9.8

    def test_cvss_for_finding_xss(self):
        v = cvss_for_finding({"recipe_id": "xss-reflected"})
        assert v.severity() == "medium"

    def test_cvss_for_finding_unknown(self):
        v = cvss_for_finding({"recipe_id": "unknown-vuln"})
        assert v.score() > 0


# --- Report engine ---

class TestReportEngine:
    def test_finding_from_verify_result(self):
        entry = {
            "recipe_id": "sqli-error",
            "endpoint": "https://example.com/login",
            "method": "POST",
            "reason": "SQL injection via error-based technique",
            "scanner": "SqliScanner",
            "evidence": {"technique": "error-based"},
            "verdict": "confirmed",
        }
        f = ReportFinding.from_verify_result(entry)
        assert f.title == "Sqli Error"
        assert f.severity == "critical"
        assert f.cvss_score == 9.8
        assert f.endpoint == "https://example.com/login"

    def test_generate_html_report(self):
        findings = [
            ReportFinding(
                title="SQL Injection",
                severity="critical",
                cvss_vector=CvssVector(confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH),
                cvss_score=9.8,
                endpoint="https://example.com/login",
                method="POST",
                description="Error-based SQL injection.",
                evidence={"technique": "error-based"},
                remediation="Use parameterized queries.",
            ),
        ]
        config = ReportConfig(target="https://example.com", client="Test Corp")
        html = generate_html_report(findings, config)
        assert "SQL Injection" in html
        assert "CRITICAL" in html
        assert "9.8" in html
        assert "Test Corp" in html
        assert "parameterized queries" in html

    def test_generate_report_from_queue(self, tmp_path):
        queue_file = tmp_path / "human_queue.jsonl"
        queue_file.write_text(json.dumps({
            "verdict": "confirmed",
            "recipe_id": "xss-reflected",
            "endpoint": "https://example.com/search",
            "method": "GET",
            "reason": "Reflected XSS",
            "scanner": "XssScanner",
            "evidence": {"technique": "reflected"},
        }) + "\n")

        output = tmp_path / "report.html"
        config = ReportConfig(target="https://example.com")
        result = generate_report_from_queue(queue_file, config, output)
        assert result.exists()
        content = result.read_text()
        assert "Xss Reflected" in content

    def test_empty_queue_generates_report(self, tmp_path):
        queue_file = tmp_path / "empty.jsonl"
        queue_file.write_text("")
        output = tmp_path / "report.html"
        config = ReportConfig(target="https://example.com")
        result = generate_report_from_queue(queue_file, config, output)
        assert result.exists()
        content = result.read_text()
        assert "0 vulnerabilities" in content

    def test_findings_sorted_by_severity(self):
        findings = [
            ReportFinding(title="Low", severity="low", cvss_vector=CvssVector(), cvss_score=2.0,
                          endpoint="", method="", description="", evidence={}, remediation=""),
            ReportFinding(title="Critical", severity="critical", cvss_vector=CvssVector(), cvss_score=9.8,
                          endpoint="", method="", description="", evidence={}, remediation=""),
            ReportFinding(title="Medium", severity="medium", cvss_vector=CvssVector(), cvss_score=5.0,
                          endpoint="", method="", description="", evidence={}, remediation=""),
        ]
        config = ReportConfig(target="test")
        html = generate_html_report(findings, config)
        crit_pos = html.index("Critical")
        med_pos = html.index("Medium")
        low_pos = html.index("Low")
        assert crit_pos < med_pos < low_pos


# --- Compliance ---

class TestCompliance:
    def test_owasp_sqli(self):
        refs = get_compliance_refs("sqli-error")
        assert any(r.framework == "OWASP" and "A03" in r.requirement for r in refs)

    def test_pci_auth_bypass(self):
        refs = get_compliance_refs("auth-bypass")
        assert any(r.framework == "PCI-DSS" for r in refs)

    def test_filter_frameworks(self):
        refs = get_compliance_refs("sqli", frameworks=["OWASP"])
        assert all(r.framework == "OWASP" for r in refs)

    def test_cwe_map(self):
        assert get_cwe("sqli-error") == "CWE-89"
        assert get_cwe("xss-reflected") == "CWE-79"
        assert get_cwe("ssrf-blind") == "CWE-918"

    def test_cwe_unknown(self):
        assert get_cwe("unknown-vuln") == ""

    def test_auto_prefix_stripped(self):
        refs = get_compliance_refs("auto:auth-bypass")
        assert len(refs) > 0

    def test_idor_owasp(self):
        refs = get_compliance_refs("idor-horizontal", frameworks=["OWASP"])
        assert any("A01" in r.requirement for r in refs)
