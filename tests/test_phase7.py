"""Tests for Phase 7 — Reporter."""
import json
import pytest

from agent.scanners.base import Candidate
from agent.verify.base import Verdict, VerifyResult
from agent.reporter import (
    Finding,
    Report,
    Reporter,
    _CWE_MAP,
    _OWASP_MAP,
)


# ── Fixtures ──────────────────────────────────────────────────

def make_candidate(**overrides):
    defaults = dict(
        recipe_id="idor-otp-trigger",
        scanner="IdorScanner",
        endpoint="https://target.example.com/api/sendOTP",
        method="POST",
        evidence={"status": 200, "victim_id": "victim_123",
                  "body_snippet": '{"status":"success"}'},
        confidence="high",
        request_data={
            "id_param": "mobileNo",
            "id_value": "victim_123",
            "id_location": "body",
            "session": "attacker",
        },
        response_data={"status": 200},
    )
    defaults.update(overrides)
    return Candidate(**defaults)


def make_result(candidate=None, verdict=Verdict.CONFIRMED, replays=3):
    candidate = candidate or make_candidate()
    return VerifyResult(
        candidate=candidate,
        verdict=verdict,
        replays=replays,
        evidence={"successes": replays if verdict == Verdict.CONFIRMED else 0,
                  "responses": [{"replay": 1, "status": 200}]},
        reason="All replays confirmed — IDOR confirmed"
            if verdict == Verdict.CONFIRMED else "Replays failed",
    )


def make_queue_entry():
    return {
        "verdict": "CONFIRMED",
        "recipe_id": "idor-otp-trigger",
        "endpoint": "https://target.example.com/api/sendOTP",
        "method": "POST",
        "scanner": "IdorScanner",
        "confidence": "high",
        "replays": 3,
        "reason": "All 3 replays succeeded — IDOR confirmed",
        "evidence": {"successes": 3, "responses": []},
        "request_data": {
            "id_param": "mobileNo",
            "id_value": "victim_123",
            "id_location": "body",
            "session": "attacker",
        },
    }


# ── Finding dataclass tests ──────────────────────────────────

class TestFinding:
    def test_finding_fields(self):
        f = Finding(
            id="FIND-001",
            title="IDOR on /api/sendOTP",
            severity="high",
            cvss_range="7.0 – 8.9",
            owasp="A01:2021 — Broken Access Control",
            cwe="CWE-639",
            description="Test description",
            affected_component="POST /api/sendOTP",
            steps_to_reproduce=["Step 1", "Step 2"],
            request_sample="POST /api/sendOTP",
            response_sample='{"status": "success"}',
            impact="Unauthorized access",
            remediation="Add authz check",
            confidence="high",
            verdict="CONFIRMED",
            source_recipe="idor-otp-trigger",
        )
        assert f.id == "FIND-001"
        assert f.severity == "high"
        assert f.timestamp  # auto-populated

    def test_finding_has_all_report_fields(self):
        f = Finding(
            id="FIND-001", title="T", severity="high", cvss_range="7.0 – 8.9",
            owasp="A01", cwe="CWE-639", description="D",
            affected_component="C", steps_to_reproduce=["S"],
            request_sample="R", response_sample="Resp",
            impact="I", remediation="Rem", confidence="high",
            verdict="CONFIRMED", source_recipe="r",
        )
        # All fields a Kratikal report needs
        required = ["title", "severity", "cvss_range", "owasp", "cwe",
                     "description", "affected_component", "steps_to_reproduce",
                     "impact", "remediation"]
        for field_name in required:
            assert getattr(f, field_name), f"Missing {field_name}"


# ── Report dataclass tests ───────────────────────────────────

class TestReport:
    def test_empty_report(self):
        r = Report(target="https://target.example.com")
        assert r.findings == []
        assert r.target == "https://target.example.com"

    def test_add_finding(self):
        r = Report(target="https://target.example.com")
        f = Finding(
            id="FIND-001", title="T", severity="high", cvss_range="7.0 – 8.9",
            owasp="A01", cwe="CWE-639", description="D",
            affected_component="C", steps_to_reproduce=["S"],
            request_sample="R", response_sample="Resp",
            impact="I", remediation="Rem", confidence="high",
            verdict="CONFIRMED", source_recipe="r",
        )
        r.add(f)
        assert len(r.findings) == 1

    def test_set_summary(self):
        r = Report(target="https://target.example.com")
        r.set_summary(total_endpoints=5, confirmed=2, needs_human=1)
        assert r.summary["confirmed"] == 2
        assert r.summary["needs_human"] == 1


# ── Reporter tests ───────────────────────────────────────────

class TestReporter:
    def test_finding_from_result(self):
        reporter = Reporter()
        result = make_result()
        finding = reporter.finding_from_result(result)

        assert finding.id == "FIND-001"
        assert "IDOR" in finding.title
        assert finding.severity == "high"
        assert finding.cwe == "CWE-639"
        assert finding.owasp == "A01:2021 — Broken Access Control"
        assert len(finding.steps_to_reproduce) >= 3
        assert finding.verdict == "CONFIRMED"

    def test_finding_from_result_needs_human(self):
        reporter = Reporter()
        result = make_result(verdict=Verdict.NEEDS_HUMAN, replays=3)
        finding = reporter.finding_from_result(result)
        assert finding.verdict == "NEEDS_HUMAN"

    def test_finding_counter_increments(self):
        reporter = Reporter()
        f1 = reporter.finding_from_result(make_result())
        f2 = reporter.finding_from_result(make_result())
        assert f1.id == "FIND-001"
        assert f2.id == "FIND-002"

    def test_finding_from_queue_entry(self):
        reporter = Reporter()
        entry = make_queue_entry()
        finding = reporter.finding_from_queue_entry(entry)

        assert finding.id == "FIND-001"
        assert "IDOR" in finding.title
        assert finding.verdict == "CONFIRMED"

    def test_description_contains_endpoint(self):
        reporter = Reporter()
        result = make_result()
        finding = reporter.finding_from_result(result)
        assert "sendOTP" in finding.description

    def test_request_sample_redacted(self):
        reporter = Reporter()
        candidate = make_candidate(
            request_data={
                "id_param": "token",
                "id_value": "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoiMTIzIn0.abc123",
                "id_location": "body",
                "session": "attacker",
            }
        )
        result = make_result(candidate=candidate)
        finding = reporter.finding_from_result(result)
        # JWT should be redacted
        assert "eyJ" not in finding.request_sample
        assert "<JWT>" in finding.request_sample

    def test_remediation_mapped(self):
        reporter = Reporter()
        finding = reporter.finding_from_result(make_result())
        assert "object-level authorization" in finding.remediation.lower()

    def test_impact_idor(self):
        reporter = Reporter()
        finding = reporter.finding_from_result(make_result())
        assert "unauthorized" in finding.impact.lower()


# ── Build report tests ───────────────────────────────────────

class TestBuildReport:
    def test_build_from_results(self):
        reporter = Reporter()
        results = [make_result(), make_result()]
        report = reporter.build_report("https://target.example.com",
                                       results=results)
        assert report.target == "https://target.example.com"
        assert len(report.findings) == 2

    def test_build_skips_false_positives(self):
        reporter = Reporter()
        confirmed = make_result(verdict=Verdict.CONFIRMED)
        false_pos = make_result(verdict=Verdict.FALSE)
        report = reporter.build_report("https://target.example.com",
                                       results=[confirmed, false_pos])
        assert len(report.findings) == 1
        assert report.findings[0].verdict == "CONFIRMED"

    def test_build_includes_needs_human(self):
        reporter = Reporter()
        needs = make_result(verdict=Verdict.NEEDS_HUMAN)
        report = reporter.build_report("https://target.example.com",
                                       results=[needs])
        assert len(report.findings) == 1
        assert report.findings[0].verdict == "NEEDS_HUMAN"

    def test_build_from_queue_entries(self):
        reporter = Reporter()
        entries = [make_queue_entry()]
        report = reporter.build_report("https://target.example.com",
                                       queue_entries=entries)
        assert len(report.findings) == 1


# ── Export tests ─────────────────────────────────────────────

class TestExport:
    def test_export_markdown(self, tmp_path):
        reporter = Reporter(output_dir=tmp_path)
        report = reporter.build_report("https://target.example.com",
                                       results=[make_result()])
        report.set_summary(confirmed=1)
        path = reporter.export_markdown(report)

        assert path.exists()
        content = path.read_text()
        assert "# VAPT Report" in content
        assert "FIND-001" in content
        assert "IDOR" in content
        assert "CWE-639" in content
        assert "Steps to Reproduce" in content
        assert "Remediation" in content

    def test_export_markdown_has_severity_table(self, tmp_path):
        reporter = Reporter(output_dir=tmp_path)
        report = reporter.build_report("https://target.example.com",
                                       results=[make_result()])
        report.set_summary(confirmed=1)
        md = reporter.export_markdown(report)
        content = md.read_text()
        assert "High" in content

    def test_export_json(self, tmp_path):
        reporter = Reporter(output_dir=tmp_path)
        report = reporter.build_report("https://target.example.com",
                                       results=[make_result()])
        report.set_summary(confirmed=1)
        path = reporter.export_json(report)

        assert path.exists()
        data = json.loads(path.read_text())
        assert data["target"] == "https://target.example.com"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["cwe"] == "CWE-639"
        assert data["summary"]["confirmed"] == 1

    def test_export_json_custom_filename(self, tmp_path):
        reporter = Reporter(output_dir=tmp_path)
        report = Report(target="test")
        path = reporter.export_json(report, filename="custom.json")
        assert path.name == "custom.json"

    def test_export_markdown_empty_report(self, tmp_path):
        reporter = Reporter(output_dir=tmp_path)
        report = Report(target="https://target.example.com")
        path = reporter.export_markdown(report)
        content = path.read_text()
        assert "# VAPT Report" in content
        assert "Findings" in content


# ── Classification map tests ────────────────────────────────

class TestClassificationMaps:
    def test_cwe_map_has_idor(self):
        assert _CWE_MAP["idor"] == "CWE-639"

    def test_owasp_map_has_idor(self):
        assert "Broken Access Control" in _OWASP_MAP["idor"]

    def test_extract_path(self):
        assert Reporter._extract_path("https://example.com/api/test") == "/api/test"
        assert Reporter._extract_path("https://example.com") == "https://example.com"
