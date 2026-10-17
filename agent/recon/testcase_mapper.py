"""Smart Test Case Mapper — profiles the website and maps applicable test cases.

Combines OWASP Top 10 (2021), OWASP Testing Guide (OTG v4), and SANS/CWE Top 25
into a unified test matrix. First understands the website — its tech stack, endpoints,
auth mechanism, forms, APIs — then decides which specific test cases apply.

This is the brain that prevents wasted scans and ensures no applicable test is skipped.

Usage:
    mapper = TestCaseMapper()
    profile = mapper.profile_site(fingerprint_result, classified_endpoints,
                                   js_analysis, dirbrute_result, nmap_result)
    applicable = mapper.get_applicable_tests(profile)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Unified test case catalog ─────────────────────────────────

class TestCategory(str, Enum):
    INJECTION = "injection"
    BROKEN_AUTH = "broken-auth"
    SENSITIVE_DATA = "sensitive-data"
    XXE = "xxe"
    BROKEN_ACCESS = "broken-access"
    MISCONFIG = "misconfiguration"
    XSS = "xss"
    INSECURE_DESER = "insecure-deserialization"
    VULN_COMPONENTS = "vulnerable-components"
    LOGGING = "insufficient-logging"
    SSRF = "ssrf"
    CRYPTO = "crypto-failure"


@dataclass
class TestCase:
    """A single test case from OWASP/OTG/SANS."""
    id: str                    # e.g. "OTG-AUTHN-001"
    name: str
    category: TestCategory
    description: str
    owasp_top10: str = ""      # e.g. "A03:2021"
    cwe: str = ""              # e.g. "CWE-79"
    scanner: str = ""          # which AUTON scanner handles this
    priority: int = 1          # 1=critical, 2=high, 3=medium, 4=low
    requires: list[str] = field(default_factory=list)  # what site features are needed
    applies_when: list[str] = field(default_factory=list)  # conditions


# ── Master test catalog ───────────────────────────────────────

_TEST_CATALOG: list[TestCase] = [
    # ═══ INJECTION (A03:2021 / SANS CWE-89, CWE-78, CWE-77) ═══
    TestCase(
        id="OTG-INPVAL-005", name="SQL Injection",
        category=TestCategory.INJECTION,
        description="Test all input params for SQL injection — error-based, blind boolean, blind time-based, UNION, auth bypass",
        owasp_top10="A03:2021", cwe="CWE-89",
        scanner="sqli", priority=1,
        requires=["has_params"],
        applies_when=["has_forms", "has_query_params", "has_login", "has_search", "has_api"],
    ),
    TestCase(
        id="OTG-INPVAL-006", name="NoSQL Injection",
        category=TestCategory.INJECTION,
        description="Test for NoSQL injection in MongoDB/CouchDB backends — operator injection, JSON body injection",
        owasp_top10="A03:2021", cwe="CWE-943",
        scanner="nosqli", priority=1,
        requires=["has_params"],
        applies_when=["uses_nosql", "has_json_api", "has_login"],
    ),
    TestCase(
        id="OTG-INPVAL-013", name="Command Injection",
        category=TestCategory.INJECTION,
        description="Test for OS command injection — semicolons, pipes, backticks, $() in params processed server-side",
        owasp_top10="A03:2021", cwe="CWE-78",
        scanner="cmdi", priority=1,
        requires=["has_params"],
        applies_when=["has_file_handler", "has_api", "has_admin", "uses_cgi"],
    ),
    TestCase(
        id="OTG-INPVAL-016", name="HTTP Header Injection",
        category=TestCategory.INJECTION,
        description="Test for CRLF / header injection in redirect and header-reflected params",
        owasp_top10="A03:2021", cwe="CWE-113",
        scanner="", priority=3,
        requires=["has_redirects"],
        applies_when=["has_redirects", "has_custom_headers"],
    ),
    TestCase(
        id="OTG-INPVAL-017", name="Server-Side Template Injection (SSTI)",
        category=TestCategory.INJECTION,
        description="Test for SSTI — {{7*7}}, ${7*7}, #{7*7} in reflected input fields",
        owasp_top10="A03:2021", cwe="CWE-94",
        scanner="ssti", priority=1,
        requires=["has_params"],
        applies_when=["uses_templates", "has_search", "has_forms", "reflects_input"],
    ),
    TestCase(
        id="OTG-INPVAL-018", name="LDAP Injection",
        category=TestCategory.INJECTION,
        description="Test for LDAP injection in login/search forms using LDAP backend",
        owasp_top10="A03:2021", cwe="CWE-90",
        scanner="", priority=3,
        requires=["has_login"],
        applies_when=["uses_ldap", "has_login"],
    ),
    TestCase(
        id="OTG-INPVAL-019", name="XPath Injection",
        category=TestCategory.INJECTION,
        description="Test for XPath injection when XML data stores are used",
        owasp_top10="A03:2021", cwe="CWE-643",
        scanner="", priority=3,
        requires=["has_params"],
        applies_when=["uses_xml"],
    ),

    # ═══ BROKEN AUTH (A07:2021 / SANS CWE-287, CWE-306, CWE-798) ═══
    TestCase(
        id="OTG-AUTHN-001", name="Credentials Transport over Encrypted Channel",
        category=TestCategory.BROKEN_AUTH,
        description="Verify login form submits over HTTPS, not HTTP",
        owasp_top10="A07:2021", cwe="CWE-319",
        scanner="", priority=2,
        requires=["has_login"],
        applies_when=["has_login"],
    ),
    TestCase(
        id="OTG-AUTHN-002", name="Default Credentials",
        category=TestCategory.BROKEN_AUTH,
        description="Test for default credentials on admin panels and services (admin/admin, root/root)",
        owasp_top10="A07:2021", cwe="CWE-798",
        scanner="bruteforce", priority=2,
        requires=["has_login"],
        applies_when=["has_login", "has_admin"],
    ),
    TestCase(
        id="OTG-AUTHN-003", name="Weak Lockout Mechanism",
        category=TestCategory.BROKEN_AUTH,
        description="Test if account locks after N failed attempts. No lockout = brute force possible.",
        owasp_top10="A07:2021", cwe="CWE-307",
        scanner="bruteforce", priority=1,
        requires=["has_login"],
        applies_when=["has_login"],
    ),
    TestCase(
        id="OTG-AUTHN-004", name="Bypassing Authentication Schema",
        category=TestCategory.BROKEN_AUTH,
        description="Test forced browsing, direct object access, parameter tampering to bypass auth",
        owasp_top10="A07:2021", cwe="CWE-287",
        scanner="privesc", priority=1,
        requires=["has_auth"],
        applies_when=["has_auth", "has_admin", "has_api"],
    ),
    TestCase(
        id="OTG-SESS-001", name="Session Management Schema",
        category=TestCategory.BROKEN_AUTH,
        description="Test session token randomness, length, entropy. Check for session fixation.",
        owasp_top10="A07:2021", cwe="CWE-384",
        scanner="", priority=2,
        requires=["has_auth"],
        applies_when=["has_auth", "has_cookies"],
    ),
    TestCase(
        id="OTG-SESS-002", name="Cookie Attributes",
        category=TestCategory.BROKEN_AUTH,
        description="Test Secure, HttpOnly, SameSite, Path, Domain flags on session cookies",
        owasp_top10="A07:2021", cwe="CWE-614",
        scanner="headers", priority=2,
        requires=["has_cookies"],
        applies_when=["has_cookies"],
    ),
    TestCase(
        id="OTG-SESS-003", name="Session Fixation",
        category=TestCategory.BROKEN_AUTH,
        description="Test if session ID changes after login (pre-auth → post-auth token reuse)",
        owasp_top10="A07:2021", cwe="CWE-384",
        scanner="", priority=2,
        requires=["has_login"],
        applies_when=["has_login"],
    ),
    TestCase(
        id="OTG-SESS-005", name="CSRF",
        category=TestCategory.BROKEN_AUTH,
        description="Test for Cross-Site Request Forgery on state-changing forms (no anti-CSRF token)",
        owasp_top10="A07:2021", cwe="CWE-352",
        scanner="csrf", priority=2,
        requires=["has_forms"],
        applies_when=["has_forms", "has_auth"],
    ),
    TestCase(
        id="OTG-SESS-007", name="Session Timeout",
        category=TestCategory.BROKEN_AUTH,
        description="Test if idle sessions expire. Long-lived sessions allow session hijacking window.",
        owasp_top10="A07:2021", cwe="CWE-613",
        scanner="", priority=3,
        requires=["has_auth"],
        applies_when=["has_auth"],
    ),

    # ═══ SENSITIVE DATA EXPOSURE (A02:2021 / SANS CWE-311, CWE-200) ═══
    TestCase(
        id="OTG-CRYPST-001", name="SSL/TLS Configuration",
        category=TestCategory.CRYPTO,
        description="Test for weak SSL/TLS — expired cert, weak ciphers, TLS 1.0/1.1, missing HSTS",
        owasp_top10="A02:2021", cwe="CWE-295",
        scanner="", priority=2,
        requires=["is_https"],
        applies_when=["is_https"],
    ),
    TestCase(
        id="OTG-INFO-002", name="Web Server Fingerprinting",
        category=TestCategory.SENSITIVE_DATA,
        description="Identify server software and version from headers, error pages, default files",
        owasp_top10="A02:2021", cwe="CWE-200",
        scanner="", priority=4,
        requires=[],
        applies_when=["always"],
    ),
    TestCase(
        id="OTG-INFO-005", name="JavaScript Source Analysis",
        category=TestCategory.SENSITIVE_DATA,
        description="Analyze JS files for API keys, secrets, internal URLs, source maps, credentials",
        owasp_top10="A02:2021", cwe="CWE-200",
        scanner="js_analyzer", priority=2,
        requires=["has_js_files"],
        applies_when=["has_js_files"],
    ),
    TestCase(
        id="OTG-INFO-006", name="Source Map Exposure",
        category=TestCategory.SENSITIVE_DATA,
        description="Check for .map files that expose original source code, file structure, and secrets",
        owasp_top10="A02:2021", cwe="CWE-540",
        scanner="js_analyzer", priority=2,
        requires=["has_js_files"],
        applies_when=["has_js_files"],
    ),
    TestCase(
        id="OTG-CONFIG-004", name="Backup and Unreferenced Files",
        category=TestCategory.SENSITIVE_DATA,
        description="Bruteforce for .bak, .old, .sql, .zip, .git, config files, admin panels",
        owasp_top10="A02:2021", cwe="CWE-530",
        scanner="dirbrute", priority=2,
        requires=[],
        applies_when=["always"],
    ),
    TestCase(
        id="OTG-ERR-001", name="Error Handling",
        category=TestCategory.SENSITIVE_DATA,
        description="Test for verbose error messages that reveal stack traces, DB queries, file paths",
        owasp_top10="A02:2021", cwe="CWE-209",
        scanner="", priority=3,
        requires=[],
        applies_when=["always"],
    ),

    # ═══ XSS (A03:2021 / SANS CWE-79) ═══
    TestCase(
        id="OTG-INPVAL-001", name="Reflected XSS",
        category=TestCategory.XSS,
        description="Test all reflected params for XSS — script injection, event handlers, SVG",
        owasp_top10="A03:2021", cwe="CWE-79",
        scanner="xss", priority=1,
        requires=["has_params"],
        applies_when=["has_params", "reflects_input"],
    ),
    TestCase(
        id="OTG-INPVAL-002", name="Stored XSS",
        category=TestCategory.XSS,
        description="Test forms that persist data (comments, profiles, messages) for stored XSS",
        owasp_top10="A03:2021", cwe="CWE-79",
        scanner="stored_xss", priority=1,
        requires=["has_forms"],
        applies_when=["has_comment", "has_profile", "has_forms"],
    ),
    TestCase(
        id="OTG-CLIENT-001", name="DOM-based XSS",
        category=TestCategory.XSS,
        description="Test for DOM XSS via location.hash, document.URL, innerHTML sinks in client JS",
        owasp_top10="A03:2021", cwe="CWE-79",
        scanner="", priority=2,
        requires=["has_js_files"],
        applies_when=["has_js_files", "uses_spa"],
    ),
    TestCase(
        id="OTG-INPVAL-003", name="HTML Injection",
        category=TestCategory.XSS,
        description="Test for HTML injection in reflected params — form injection, phishing via injected HTML",
        owasp_top10="A03:2021", cwe="CWE-79",
        scanner="xss", priority=2,
        requires=["has_params"],
        applies_when=["has_params", "reflects_input"],
    ),

    # ═══ BROKEN ACCESS CONTROL (A01:2021 / SANS CWE-862, CWE-863, CWE-639) ═══
    TestCase(
        id="OTG-AUTHZ-001", name="Directory Traversal / LFI",
        category=TestCategory.BROKEN_ACCESS,
        description="Test file params for path traversal — ../../etc/passwd, ..\\windows\\win.ini",
        owasp_top10="A01:2021", cwe="CWE-22",
        scanner="lfi", priority=1,
        requires=["has_file_params"],
        applies_when=["has_file_handler", "has_file_params"],
    ),
    TestCase(
        id="OTG-AUTHZ-002", name="Privilege Escalation",
        category=TestCategory.BROKEN_ACCESS,
        description="Test horizontal (access other user data) and vertical (user→admin) privilege escalation",
        owasp_top10="A01:2021", cwe="CWE-269",
        scanner="privesc", priority=1,
        requires=["has_auth"],
        applies_when=["has_auth", "has_admin", "has_roles"],
    ),
    TestCase(
        id="OTG-AUTHZ-004", name="IDOR / BOLA",
        category=TestCategory.BROKEN_ACCESS,
        description="Test for Insecure Direct Object References — change ID params to access other users' data",
        owasp_top10="A01:2021", cwe="CWE-639",
        scanner="idor", priority=1,
        requires=["has_id_params"],
        applies_when=["has_id_params", "has_api", "has_profile"],
    ),

    # ═══ SECURITY MISCONFIGURATION (A05:2021 / SANS CWE-16) ═══
    TestCase(
        id="OTG-CONFIG-002", name="Security Headers",
        category=TestCategory.MISCONFIG,
        description="Check all security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS, cookie flags",
        owasp_top10="A05:2021", cwe="CWE-16",
        scanner="headers", priority=2,
        requires=[],
        applies_when=["always"],
    ),
    TestCase(
        id="OTG-CONFIG-006", name="HTTP Methods Testing",
        category=TestCategory.MISCONFIG,
        description="Test for dangerous HTTP methods — PUT, DELETE, TRACE, OPTIONS on endpoints",
        owasp_top10="A05:2021", cwe="CWE-16",
        scanner="", priority=3,
        requires=[],
        applies_when=["always"],
    ),
    TestCase(
        id="OTG-CONFIG-007", name="CORS Misconfiguration",
        category=TestCategory.MISCONFIG,
        description="Test CORS policy — wildcard origin, reflected origin, credentials with wildcard",
        owasp_top10="A05:2021", cwe="CWE-942",
        scanner="headers", priority=2,
        requires=[],
        applies_when=["has_api", "always"],
    ),
    TestCase(
        id="OTG-CONFIG-008", name="Clickjacking",
        category=TestCategory.MISCONFIG,
        description="Test for missing X-Frame-Options and CSP frame-ancestors — page can be framed",
        owasp_top10="A05:2021", cwe="CWE-1021",
        scanner="headers", priority=2,
        requires=[],
        applies_when=["always"],
    ),

    # ═══ SSRF (A10:2021 / SANS CWE-918) ═══
    TestCase(
        id="OTG-INPVAL-020", name="Server-Side Request Forgery",
        category=TestCategory.SSRF,
        description="Test URL params, webhook URLs, import features for SSRF — internal network access, cloud metadata",
        owasp_top10="A10:2021", cwe="CWE-918",
        scanner="ssrf", priority=1,
        requires=["has_url_params"],
        applies_when=["has_url_params", "has_file_handler", "has_api"],
    ),

    # ═══ OPEN REDIRECT ═══
    TestCase(
        id="OTG-CLIENT-004", name="Open Redirect",
        category=TestCategory.BROKEN_ACCESS,
        description="Test redirect params for open redirect — phishing, OAuth token theft",
        owasp_top10="A01:2021", cwe="CWE-601",
        scanner="open_redirect", priority=3,
        requires=["has_redirect_params"],
        applies_when=["has_redirect_params", "has_redirects"],
    ),

    # ═══ NMAP / NETWORK ═══
    TestCase(
        id="OTG-CONFIG-001", name="Network Infrastructure",
        category=TestCategory.MISCONFIG,
        description="Port scan — identify open services, versions, potential attack surface",
        owasp_top10="A05:2021", cwe="CWE-16",
        scanner="nmap", priority=2,
        requires=[],
        applies_when=["always"],
    ),

    # ═══ TECHNOLOGY DETECTION ═══
    TestCase(
        id="OTG-INFO-008", name="Technology Stack Fingerprinting",
        category=TestCategory.SENSITIVE_DATA,
        description="Identify server, framework, CMS, JS libraries with versions — map to known CVEs",
        owasp_top10="A06:2021", cwe="CWE-200",
        scanner="fingerprint", priority=2,
        requires=[],
        applies_when=["always"],
    ),
]


# ── Site profile — what we know about the target ──────────────

@dataclass
class SiteProfile:
    """Everything we know about the target website after recon."""
    url: str = ""

    # From fingerprinting
    technologies: list[str] = field(default_factory=list)
    server: str = ""
    framework: str = ""
    cms: str = ""
    language: str = ""

    # From crawling + classification
    has_login: bool = False
    has_auth: bool = False
    has_forms: bool = False
    has_search: bool = False
    has_file_handler: bool = False
    has_admin: bool = False
    has_api: bool = False
    has_comment: bool = False
    has_profile: bool = False
    has_redirects: bool = False
    has_payment: bool = False
    has_registration: bool = False
    has_settings: bool = False

    # From parameter analysis
    has_params: bool = False
    has_query_params: bool = False
    has_id_params: bool = False
    has_file_params: bool = False
    has_url_params: bool = False
    has_redirect_params: bool = False

    # From JS analysis
    has_js_files: bool = False
    has_source_maps: bool = False
    js_secrets_found: int = 0

    # From dirbrute
    has_backup_files: bool = False
    has_vcs_exposed: bool = False
    has_config_files: bool = False
    has_debug_endpoints: bool = False

    # From nmap
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)

    # Inferred characteristics
    is_https: bool = False
    has_cookies: bool = False
    uses_nosql: bool = False
    uses_xml: bool = False
    uses_spa: bool = False
    uses_templates: bool = False
    uses_ldap: bool = False
    uses_cgi: bool = False
    has_json_api: bool = False
    has_roles: bool = False
    has_custom_headers: bool = False
    reflects_input: bool = False

    def features(self) -> set[str]:
        """Return all active features as a set of strings."""
        feat = {"always"}
        for attr in dir(self):
            if attr.startswith("has_") or attr.startswith("is_") or attr.startswith("uses_"):
                if getattr(self, attr):
                    feat.add(attr)
        return feat


class TestCaseMapper:
    """Profiles a website and maps applicable OWASP/OTG/SANS test cases."""

    def __init__(self):
        self.catalog = list(_TEST_CATALOG)

    def profile_site(
        self,
        url: str,
        fingerprint_result: Any = None,
        classified_endpoints: list[dict] | None = None,
        js_analysis: Any = None,
        dirbrute_result: Any = None,
        nmap_result: Any = None,
        crawled_pages: list[Any] | None = None,
    ) -> SiteProfile:
        """Build a SiteProfile from all recon results."""
        profile = SiteProfile(url=url, is_https=url.startswith("https://"))

        # ── From fingerprinting ──
        if fingerprint_result:
            signals = getattr(fingerprint_result, 'signals', set())
            versions = getattr(fingerprint_result, 'versions', {})
            profile.technologies = sorted(signals)
            profile.server = next((s for s in signals if s in (
                "apache", "nginx", "iis", "caddy", "gunicorn",
            )), "")
            profile.framework = next((s for s in signals if s in (
                "flask", "django", "express", "rails", "spring",
                "laravel", "asp-net", "nextjs",
            )), "")
            profile.cms = next((s for s in signals if s in (
                "wordpress", "drupal", "joomla", "magento",
            )), "")
            profile.language = next((s for s in signals if s in (
                "php", "python", "java", "ruby", "csharp",
            )), "")
            # Infer characteristics
            if any(s in signals for s in ("mongodb", "couchdb", "firebase")):
                profile.uses_nosql = True
            if any(s in signals for s in ("react", "angular", "vue", "svelte", "nextjs")):
                profile.uses_spa = True
            if any(s in signals for s in ("jinja2", "twig", "freemarker", "thymeleaf", "blade", "ejs", "pug")):
                profile.uses_templates = True
            if "cgi" in signals:
                profile.uses_cgi = True

        # ── From classified endpoints ──
        if classified_endpoints:
            functions = {ep.get("function", "") for ep in classified_endpoints}
            profile.has_login = "login" in functions
            profile.has_registration = "registration" in functions
            profile.has_search = "search" in functions
            profile.has_file_handler = "file_handler" in functions
            profile.has_admin = "admin" in functions
            profile.has_api = "api_data" in functions
            profile.has_comment = "comment" in functions
            profile.has_profile = "user_profile" in functions
            profile.has_redirects = "redirect" in functions
            profile.has_payment = "payment" in functions
            profile.has_settings = "settings" in functions
            profile.has_forms = any(
                ep.get("function") not in ("static_page", "unknown", "")
                for ep in classified_endpoints
            )
            profile.has_auth = profile.has_login or profile.has_profile or profile.has_settings

            # Check params
            for ep in classified_endpoints:
                params = ep.get("params", [])
                if params:
                    profile.has_params = True
                for p in params:
                    pl = p.lower() if isinstance(p, str) else ""
                    if any(x in pl for x in ("id", "uid", "user_id", "account", "order")):
                        profile.has_id_params = True
                    if any(x in pl for x in ("file", "path", "doc", "page", "template", "include")):
                        profile.has_file_params = True
                    if any(x in pl for x in ("url", "uri", "link", "src", "href", "redirect", "next", "return", "dest")):
                        profile.has_url_params = True
                        profile.has_redirect_params = True
                method = ep.get("method", "")
                if method == "GET":
                    profile.has_query_params = True

        # ── From JS analysis ──
        if js_analysis:
            profile.has_js_files = getattr(js_analysis, 'js_files_analyzed', 0) > 0
            profile.has_source_maps = bool(getattr(js_analysis, 'source_maps', []))
            profile.js_secrets_found = getattr(js_analysis, 'finding_count', 0)

        # ── From dirbrute ──
        if dirbrute_result:
            cats = getattr(dirbrute_result, 'by_category', lambda: {})()
            profile.has_backup_files = bool(cats.get("backup"))
            profile.has_vcs_exposed = bool(cats.get("vcs"))
            profile.has_config_files = bool(cats.get("config"))
            profile.has_debug_endpoints = bool(cats.get("debug"))
            if cats.get("admin"):
                profile.has_admin = True

        # ── From nmap ──
        if nmap_result:
            ports = getattr(nmap_result, 'open_ports', [])
            if isinstance(ports, list):
                profile.open_ports = [p.get("port", 0) if isinstance(p, dict) else p for p in ports]
            services_list = getattr(nmap_result, 'services', [])
            if isinstance(services_list, list):
                profile.services = [s.get("service", "") if isinstance(s, dict) else str(s) for s in services_list]

        return profile

    def get_applicable_tests(self, profile: SiteProfile) -> list[TestCase]:
        """Given a site profile, return the applicable test cases sorted by priority."""
        features = profile.features()
        applicable = []

        for tc in self.catalog:
            # Check if ALL requires are met
            if tc.requires and not all(r in features for r in tc.requires):
                continue

            # Check if ANY applies_when condition is met
            if tc.applies_when and not any(c in features for c in tc.applies_when):
                continue

            applicable.append(tc)

        # Sort by priority (1=critical first)
        applicable.sort(key=lambda t: t.priority)
        return applicable

    def get_test_plan(self, profile: SiteProfile) -> dict[str, Any]:
        """Generate a full test plan with phases and scanners."""
        applicable = self.get_applicable_tests(profile)

        # Group by phase
        phases = {
            "recon": [],
            "auth_testing": [],
            "injection_testing": [],
            "access_control": [],
            "config_and_headers": [],
            "client_side": [],
        }

        for tc in applicable:
            if tc.category in (TestCategory.SENSITIVE_DATA, TestCategory.CRYPTO):
                phases["recon"].append(tc)
            elif tc.category == TestCategory.BROKEN_AUTH:
                phases["auth_testing"].append(tc)
            elif tc.category in (TestCategory.INJECTION, TestCategory.SSRF):
                phases["injection_testing"].append(tc)
            elif tc.category == TestCategory.BROKEN_ACCESS:
                phases["access_control"].append(tc)
            elif tc.category in (TestCategory.MISCONFIG,):
                phases["config_and_headers"].append(tc)
            elif tc.category in (TestCategory.XSS,):
                phases["client_side"].append(tc)
            else:
                phases["injection_testing"].append(tc)

        # Map to AUTON scanners
        scanners_needed = set()
        unmapped = []
        for tc in applicable:
            if tc.scanner:
                scanners_needed.add(tc.scanner)
            else:
                unmapped.append(tc)

        return {
            "total_tests": len(applicable),
            "phases": {k: [t.id for t in v] for k, v in phases.items() if v},
            "scanners_needed": sorted(scanners_needed),
            "unmapped_tests": [{"id": t.id, "name": t.name} for t in unmapped],
            "coverage_summary": {
                "owasp_top10_covered": sorted(set(
                    t.owasp_top10 for t in applicable if t.owasp_top10
                )),
                "cwe_covered": sorted(set(
                    t.cwe for t in applicable if t.cwe
                )),
            },
            "site_features": sorted(profile.features()),
        }

    def format_test_plan(self, profile: SiteProfile) -> str:
        """Return a human-readable test plan."""
        plan = self.get_test_plan(profile)
        applicable = self.get_applicable_tests(profile)

        lines = []
        lines.append(f"═══ AUTON TEST PLAN — {profile.url} ═══")
        lines.append(f"Total applicable tests: {plan['total_tests']}")
        lines.append(f"OWASP Top 10 coverage: {', '.join(plan['coverage_summary']['owasp_top10_covered'])}")
        lines.append("")

        # Site profile summary
        lines.append("── Site Profile ──")
        if profile.technologies:
            lines.append(f"  Tech: {', '.join(profile.technologies[:15])}")
        if profile.server:
            lines.append(f"  Server: {profile.server}")
        if profile.framework:
            lines.append(f"  Framework: {profile.framework}")
        features = sorted(f for f in profile.features() if f != "always")
        lines.append(f"  Features: {', '.join(features[:20])}")
        lines.append("")

        # Tests by phase
        phase_names = {
            "recon": "Phase 1: Reconnaissance",
            "auth_testing": "Phase 2: Authentication Testing",
            "injection_testing": "Phase 3: Injection Testing",
            "access_control": "Phase 4: Access Control Testing",
            "config_and_headers": "Phase 5: Configuration & Headers",
            "client_side": "Phase 6: Client-Side Testing",
        }
        for phase_key, phase_label in phase_names.items():
            tests = [t for t in applicable if t.id in plan["phases"].get(phase_key, [])]
            if tests:
                lines.append(f"── {phase_label} ──")
                for t in tests:
                    scanner_tag = f" [{t.scanner}]" if t.scanner else " [manual]"
                    prio = {1: "P1-CRITICAL", 2: "P2-HIGH", 3: "P3-MEDIUM", 4: "P4-LOW"}.get(t.priority, "")
                    lines.append(f"  [{prio}] {t.id} — {t.name}{scanner_tag}")
                    lines.append(f"           {t.description}")
                lines.append("")

        # Unmapped tests
        if plan["unmapped_tests"]:
            lines.append("── Tests without automated scanner (manual/Playwright) ──")
            for ut in plan["unmapped_tests"]:
                lines.append(f"  {ut['id']} — {ut['name']}")

        return "\n".join(lines)
