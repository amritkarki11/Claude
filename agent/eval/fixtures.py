"""Ground-truth definitions for known-vuln targets.

Each fixture describes a target application, its known vulnerabilities, and
the expected findings a correct scanner should produce. These are the
"answer key" the eval harness scores against.

Fixtures are plain dicts so they can be loaded from YAML or defined inline.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ExpectedFinding:
    """One vulnerability that MUST be found (true positive in recall set)."""
    vuln_class: str          # e.g. "sqli", "xss", "idor"
    endpoint: str            # URL path (no host), e.g. "/login.jsp"
    method: str = "GET"
    param: str = ""          # injection parameter, if applicable
    severity: str = ""       # expected severity
    description: str = ""    # human note


@dataclass
class TargetFixture:
    """A known-vuln target with its ground-truth findings."""
    name: str
    base_url: str
    expected: list[ExpectedFinding] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


# ── demo.testfire.net ground truth ──────────────────────────

ALTORO_MUTUAL = TargetFixture(
    name="Altoro Mutual (demo.testfire.net)",
    base_url="http://demo.testfire.net",
    tags=["java", "tomcat", "banking", "legacy"],
    expected=[
        # SQL Injection — login bypass
        ExpectedFinding(
            vuln_class="sqli",
            endpoint="/doLogin",
            method="POST",
            param="uid",
            severity="critical",
            description="Login bypass via SQL injection in uid parameter",
        ),
        # SQL Injection — search
        ExpectedFinding(
            vuln_class="sqli",
            endpoint="/search.jsp",
            method="GET",
            param="query",
            severity="high",
            description="SQL injection in search query parameter",
        ),
        # Reflected XSS
        ExpectedFinding(
            vuln_class="xss",
            endpoint="/search.jsp",
            method="GET",
            param="query",
            severity="medium",
            description="Reflected XSS in search results page",
        ),
        # Security Misconfiguration — headers
        ExpectedFinding(
            vuln_class="security-headers",
            endpoint="/",
            method="GET",
            severity="medium",
            description="Missing security headers (CSP, X-Frame-Options, etc.)",
        ),
        # Sensitive Data Exposure — comments / hidden fields
        ExpectedFinding(
            vuln_class="sensitive-data",
            endpoint="/",
            method="GET",
            severity="low",
            description="Sensitive data exposed in HTML comments or hidden fields",
        ),
        # HTML Injection
        ExpectedFinding(
            vuln_class="html-injection",
            endpoint="/search.jsp",
            method="GET",
            param="query",
            severity="medium",
            description="HTML injection in search results",
        ),
        # Broken Access Control
        ExpectedFinding(
            vuln_class="broken-access",
            endpoint="/admin/",
            method="GET",
            severity="high",
            description="Admin pages accessible without proper authorization",
        ),
        # IDOR — account access
        ExpectedFinding(
            vuln_class="idor",
            endpoint="/bank/showAccount",
            method="GET",
            param="listAccounts",
            severity="high",
            description="IDOR on account listing — access other users' accounts",
        ),
    ],
)

# Registry of all fixtures
ALL_FIXTURES: dict[str, TargetFixture] = {
    "altoro": ALTORO_MUTUAL,
}


def get_fixture(name: str) -> TargetFixture:
    if name not in ALL_FIXTURES:
        raise KeyError(f"Unknown fixture {name!r}. Available: {list(ALL_FIXTURES)}")
    return ALL_FIXTURES[name]
