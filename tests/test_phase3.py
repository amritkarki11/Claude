"""Tests for Phase 3 — Router, Redact, Budget, Prompts."""
import pytest

from agent.redact import redact, redact_detailed, is_clean
from agent.budget import Budget, UsageEntry
from agent.prompts import triage, hypothesis, exploit_chain, report, extraction, redaction_check


# ── Redaction tests ────────────────────────────────────────────

class TestRedact:
    def test_email(self):
        assert "<EMAIL>" in redact("user@example.com")

    def test_jwt(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123"
        assert "<JWT>" in redact(token)

    def test_aws_key(self):
        assert "<AWS_KEY>" in redact("AKIAIOSFODNN7EXAMPLE")

    def test_bearer(self):
        assert "<BEARER>" in redact("Bearer abc123xyz")

    def test_cookie_jsessionid(self):
        assert "<COOKIE>" in redact("JSESSIONID=ABC123DEF456")

    def test_cookie_csrf(self):
        assert "<COOKIE>" in redact("CSRFTOKEN=abc123def")

    def test_password(self):
        assert "<PASSWORD>" in redact("password=s3cret!")

    def test_ipv4(self):
        assert "<IPV4>" in redact("Connect to 192.168.1.100")

    def test_private_ip(self):
        result = redact("Internal: 10.0.0.5")
        assert "<PRIVATE_IP>" in result or "<IPV4>" in result

    def test_md5(self):
        assert "<MD5>" in redact("Hash: " + "a" * 16 + "b" * 16)

    def test_preserves_structure(self):
        text = "POST /api/v1/login HTTP/1.1\nHost: target.com\nCookie: JSESSIONID=abc123"
        result = redact(text)
        assert "POST /api/v1/login" in result
        assert "<COOKIE>" in result

    def test_multiple_patterns(self):
        text = "email: test@test.com, key: AKIAIOSFODNN7EXAMPLE"
        result = redact(text)
        assert "<EMAIL>" in result
        assert "<AWS_KEY>" in result


class TestRedactDetailed:
    def test_returns_count(self):
        result = redact_detailed("test@test.com and test2@test.com")
        assert result.replacements == 2

    def test_returns_tags(self):
        result = redact_detailed("JSESSIONID=abc123 bearer xyz")
        assert "COOKIE" in result.tags_found
        assert "BEARER" in result.tags_found

    def test_clean_text(self):
        result = redact_detailed("nothing sensitive here")
        assert result.replacements == 0
        assert result.tags_found == []


class TestIsClean:
    def test_clean(self):
        assert is_clean("just a normal string")

    def test_dirty(self):
        assert not is_clean("email: user@example.com")


# ── Budget tests ───────────────────────────────────────────────

class TestBudget:
    def test_initial_state(self):
        b = Budget(cap_usd=100.0)
        assert b.allow()
        assert b.remaining() == 100.0

    def test_record_reduces_remaining(self):
        b = Budget(cap_usd=1.0)
        cost = b.record("test", "anthropic/claude-sonnet-5-5", input_tokens=1000, output_tokens=100)
        assert cost > 0
        assert b.remaining() < 1.0

    def test_budget_exhaustion(self):
        b = Budget(cap_usd=0.001)
        b.record("test", "anthropic/claude-sonnet-5-5", input_tokens=100000, output_tokens=10000)
        assert not b.allow()

    def test_summary(self):
        b = Budget(cap_usd=50.0)
        b.record("hypothesis", "anthropic/claude-sonnet-5-5", input_tokens=500, output_tokens=100)
        b.record("exploit_chain", "anthropic/claude-sonnet-5-5", input_tokens=1000, output_tokens=200)
        s = b.summary()
        assert s["cap_usd"] == 50.0
        assert s["calls"] == 2
        assert "hypothesis" in s["by_job"]
        assert "exploit_chain" in s["by_job"]
        assert s["spent_usd"] > 0

    def test_zero_cap(self):
        b = Budget(cap_usd=0.0)
        assert not b.allow()

    def test_default_pricing_for_unknown_model(self):
        b = Budget(cap_usd=100.0)
        cost = b.record("test", "unknown/model", input_tokens=1000, output_tokens=100)
        assert cost > 0


# ── Prompt template tests ──────────────────────────────────────

class TestPrompts:
    def test_triage_returns_tuple(self):
        system, user = triage("/api/v1/login", "POST", ["username", "password"], ["rest-api", "session-cookie"])
        assert isinstance(system, str)
        assert isinstance(user, str)
        assert "POST" in user
        assert "/api/v1/login" in user
        assert "JSON" in system

    def test_triage_with_notes(self):
        _, user = triage("/api/export", "POST", [], ["xml-parser"], notes="Accepts XML body")
        assert "Accepts XML body" in user

    def test_hypothesis_returns_tuple(self):
        system, user = hypothesis("/api/export", "POST", ["xml-parser"], "XXE checklist content")
        assert "hypothesis" in system.lower() or "hypothes" in system.lower()
        assert "xml-parser" in user

    def test_exploit_chain_returns_tuple(self):
        system, user = exploit_chain("XXE found in export endpoint", "Target runs Java/Spring")
        assert "chain" in system.lower() or "exploit" in system.lower()
        assert "XXE" in user

    def test_exploit_chain_with_skill_context(self):
        _, user = exploit_chain("SQLi in /admin/edit", "MySQL backend", skill_context="Phase 3 reference")
        assert "Phase 3 reference" in user

    def test_report_returns_tuple(self):
        finding = {"id": "XXE-001", "severity": "critical", "endpoint": "/api/export"}
        system, user = report(finding)
        assert "CVSS" in system
        assert "XXE-001" in user

    def test_extraction_returns_tuple(self):
        system, user = extraction("some raw response text", "endpoints")
        assert "endpoints" in system
        assert user == "some raw response text"

    def test_redaction_check_returns_tuple(self):
        system, user = redaction_check("John Smith works at ACME Corp on 10.0.0.5")
        assert "privacy" in system.lower() or "sensitive" in system.lower()
        assert "John Smith" in user
