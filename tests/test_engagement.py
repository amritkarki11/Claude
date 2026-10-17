"""Tests for engagement model, target spec, and scope v2 (wildcards/CIDR)."""
import pytest

from agent.engagement import (
    Engagement,
    EngagementMode,
    TargetSpec,
)
from agent import scope
from agent.scope import ScopeError, check, set_scope, add_to_scope, in_scope


# --- TargetSpec ---

class TestTargetSpec:
    def test_url_kind(self):
        ts = TargetSpec("https://example.com/app")
        assert ts.kind == "url"

    def test_host_kind(self):
        ts = TargetSpec("example.com")
        assert ts.kind == "host"

    def test_wildcard_kind(self):
        ts = TargetSpec("*.example.com")
        assert ts.kind == "wildcard"

    def test_cidr_kind(self):
        ts = TargetSpec("10.0.0.0/24")
        assert ts.kind == "cidr"

    def test_ip_kind(self):
        ts = TargetSpec("192.168.1.1")
        assert ts.kind == "ip"

    def test_url_matches(self):
        ts = TargetSpec("https://example.com")
        assert ts.matches("https://example.com/path")
        assert ts.matches("http://example.com")
        assert not ts.matches("https://other.com")

    def test_host_matches(self):
        ts = TargetSpec("example.com")
        assert ts.matches("https://example.com/path")
        assert ts.matches("example.com")
        assert not ts.matches("sub.example.com")

    def test_wildcard_matches(self):
        ts = TargetSpec("*.example.com")
        assert ts.matches("https://sub.example.com/path")
        assert ts.matches("api.example.com")
        assert not ts.matches("https://example.com")
        assert not ts.matches("https://other.com")

    def test_cidr_matches(self):
        ts = TargetSpec("10.0.0.0/24")
        assert ts.matches("http://10.0.0.1")
        assert ts.matches("10.0.0.255")
        assert not ts.matches("10.0.1.1")
        assert not ts.matches("https://example.com")

    def test_ip_matches(self):
        ts = TargetSpec("192.168.1.1")
        assert ts.matches("http://192.168.1.1:8080")
        assert ts.matches("192.168.1.1")
        assert not ts.matches("192.168.1.2")

    def test_hosts_url(self):
        ts = TargetSpec("https://example.com/app")
        assert ts.hosts() == ["example.com"]

    def test_hosts_wildcard(self):
        ts = TargetSpec("*.example.com")
        assert ts.hosts() == ["*.example.com"]

    def test_hosts_cidr(self):
        ts = TargetSpec("10.0.0.0/24")
        assert ts.hosts() == ["10.0.0.0/24"]

    def test_frozen(self):
        ts = TargetSpec("example.com")
        with pytest.raises(AttributeError):
            ts.raw = "other.com"

    def test_case_insensitive(self):
        ts = TargetSpec("Example.COM")
        assert ts.matches("https://example.com")


# --- Engagement ---

class TestEngagement:
    def test_bug_bounty_factory(self):
        eng = Engagement.bug_bounty(
            targets=["*.example.com", "https://api.example.com"],
            platform="hackerone",
        )
        assert eng.mode == EngagementMode.BUG_BOUNTY
        assert eng.is_bug_bounty
        assert not eng.is_vapt
        assert len(eng.targets) == 2
        assert eng.platform == "hackerone"
        assert eng.stealth is True

    def test_vapt_factory(self):
        eng = Engagement.vapt(
            targets=["10.0.0.0/24"],
            client="Acme Corp",
            compliance=["PCI-DSS", "OWASP"],
        )
        assert eng.mode == EngagementMode.VAPT
        assert eng.is_vapt
        assert eng.client == "Acme Corp"
        assert eng.compliance_frameworks == ["PCI-DSS", "OWASP"]
        assert eng.verify_replays == 5

    def test_in_scope(self):
        eng = Engagement.bug_bounty(
            targets=["*.example.com"],
            out_of_scope=["admin.example.com"],
        )
        assert eng.is_in_scope("https://app.example.com")
        assert not eng.is_in_scope("https://admin.example.com")
        assert not eng.is_in_scope("https://other.com")

    def test_all_hosts(self):
        eng = Engagement.vapt(targets=["example.com", "10.0.0.0/24"])
        hosts = eng.all_hosts()
        assert "example.com" in hosts
        assert "10.0.0.0/24" in hosts

    def test_out_of_scope_takes_precedence(self):
        eng = Engagement.bug_bounty(
            targets=["*.example.com"],
            out_of_scope=["*.example.com"],
        )
        assert not eng.is_in_scope("https://anything.example.com")

    def test_multi_target_scope(self):
        eng = Engagement.vapt(
            targets=["example.com", "*.test.com", "192.168.1.0/28"],
        )
        assert eng.is_in_scope("https://example.com/api")
        assert eng.is_in_scope("https://sub.test.com")
        assert eng.is_in_scope("http://192.168.1.5:8080")
        assert not eng.is_in_scope("https://other.com")

    def test_engagement_id(self):
        eng = Engagement.vapt(
            targets=["example.com"],
            engagement_id="ENG-2024-001",
        )
        assert eng.engagement_id == "ENG-2024-001"


# --- Scope v2: wildcards and CIDR ---

class TestScopeV2:
    @pytest.fixture(autouse=True)
    def restore_scope(self):
        saved = set(scope.ALLOWED)
        yield
        scope.ALLOWED.clear()
        scope.ALLOWED.update(saved)

    def test_wildcard_scope(self):
        set_scope(["*.example.com"])
        assert in_scope("https://sub.example.com/path")
        assert in_scope("https://api.example.com")
        assert not in_scope("https://example.com")
        assert not in_scope("https://other.com")

    def test_cidr_scope(self):
        set_scope(["10.0.0.0/24"])
        assert in_scope("http://10.0.0.1")
        assert in_scope("http://10.0.0.254")
        assert not in_scope("http://10.0.1.1")

    def test_cidr_check(self):
        set_scope(["192.168.1.0/28"])
        assert check("http://192.168.1.5") == "http://192.168.1.5"
        with pytest.raises(ScopeError):
            check("http://192.168.1.20")

    def test_wildcard_check(self):
        set_scope(["*.test.com"])
        assert check("https://app.test.com/x") == "https://app.test.com/x"
        with pytest.raises(ScopeError):
            check("https://test.com/x")

    def test_mixed_scope(self):
        set_scope(["example.com", "*.sub.example.com", "10.0.0.0/24"])
        assert in_scope("https://example.com")
        assert in_scope("https://a.sub.example.com")
        assert in_scope("http://10.0.0.42")
        assert not in_scope("https://other.com")

    def test_set_scope_from_engagement(self):
        from agent.scope import set_scope_from_engagement
        eng = Engagement.vapt(targets=["*.example.com", "10.0.0.0/24"])
        set_scope_from_engagement(eng)
        assert in_scope("https://app.example.com")
        assert in_scope("http://10.0.0.5")
        assert not in_scope("https://other.com")
