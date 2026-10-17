"""Tech-Stack Fingerprinting (Phase 2.4).

Detects server software, frameworks, WAFs, CMS, and JS frameworks
from HTTP response headers, HTML meta tags, cookies, and response
body patterns. Output is a set of tech-signal strings that feed
into recipe matching.

Usage:
    fp = Fingerprinter(client, session)
    result = await fp.fingerprint("https://app.example.com")
    print(result.signals)  # e.g. {"apache", "php", "wordpress", "jquery"}
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from ..http import HttpClient, Session

logger = logging.getLogger(__name__)


# ── Header-based rules ────────────────────────────────────────

# Header name (lowercase) → list of (regex_on_value, signal)
_HEADER_RULES: list[tuple[str, list[tuple[re.Pattern, str]]]] = [
    ("server", [
        (re.compile(r"apache", re.I), "apache"),
        (re.compile(r"nginx", re.I), "nginx"),
        (re.compile(r"iis", re.I), "iis"),
        (re.compile(r"litespeed", re.I), "litespeed"),
        (re.compile(r"caddy", re.I), "caddy"),
        (re.compile(r"gunicorn", re.I), "gunicorn"),
        (re.compile(r"uvicorn", re.I), "uvicorn"),
        (re.compile(r"werkzeug", re.I), "flask"),
        (re.compile(r"openresty", re.I), "openresty"),
        (re.compile(r"cloudflare", re.I), "cloudflare"),
        (re.compile(r"AmazonS3", re.I), "aws-s3"),
    ]),
    ("x-powered-by", [
        (re.compile(r"php", re.I), "php"),
        (re.compile(r"asp\.net", re.I), "asp-net"),
        (re.compile(r"express", re.I), "express"),
        (re.compile(r"next\.?js", re.I), "nextjs"),
        (re.compile(r"servlet", re.I), "java-servlet"),
        (re.compile(r"jsp", re.I), "jsp"),
        (re.compile(r"rails", re.I), "rails"),
        (re.compile(r"django", re.I), "django"),
        (re.compile(r"laravel", re.I), "laravel"),
        (re.compile(r"flask", re.I), "flask"),
        (re.compile(r"spring", re.I), "spring"),
        (re.compile(r"kestrel", re.I), "asp-net"),
    ]),
    ("x-aspnet-version", [
        (re.compile(r".", re.I), "asp-net"),
    ]),
    ("x-aspnetmvc-version", [
        (re.compile(r".", re.I), "asp-net-mvc"),
    ]),
    ("x-drupal-cache", [
        (re.compile(r".", re.I), "drupal"),
    ]),
    ("x-generator", [
        (re.compile(r"wordpress", re.I), "wordpress"),
        (re.compile(r"drupal", re.I), "drupal"),
        (re.compile(r"joomla", re.I), "joomla"),
    ]),
    ("x-frame-options", [
        (re.compile(r".", re.I), "x-frame-options"),
    ]),
    ("content-security-policy", [
        (re.compile(r".", re.I), "csp"),
    ]),
    ("strict-transport-security", [
        (re.compile(r".", re.I), "hsts"),
    ]),
    ("x-content-type-options", [
        (re.compile(r"nosniff", re.I), "x-content-type-options"),
    ]),
    ("x-xss-protection", [
        (re.compile(r".", re.I), "x-xss-protection"),
    ]),
]

# WAF detection from response headers
_WAF_HEADER_RULES: list[tuple[str, list[tuple[re.Pattern, str]]]] = [
    ("server", [
        (re.compile(r"cloudflare", re.I), "waf-cloudflare"),
        (re.compile(r"AkamaiGHost", re.I), "waf-akamai"),
        (re.compile(r"sucuri", re.I), "waf-sucuri"),
    ]),
    ("x-sucuri-id", [
        (re.compile(r".", re.I), "waf-sucuri"),
    ]),
    ("x-cdn", [
        (re.compile(r"incapsula", re.I), "waf-imperva"),
    ]),
    ("cf-ray", [
        (re.compile(r".", re.I), "cloudflare"),
    ]),
    ("x-amz-cf-id", [
        (re.compile(r".", re.I), "aws-cloudfront"),
    ]),
]


# ── Cookie-based rules ────────────────────────────────────────

# Cookie name pattern → signal
_COOKIE_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^PHPSESSID$", re.I), "php"),
    (re.compile(r"^JSESSIONID$", re.I), "java-servlet"),
    (re.compile(r"^ASP\.NET_SessionId$", re.I), "asp-net"),
    (re.compile(r"^csrftoken$", re.I), "django"),
    (re.compile(r"^_rails_session$|^_session_id$", re.I), "rails"),
    (re.compile(r"^laravel_session$", re.I), "laravel"),
    (re.compile(r"^connect\.sid$", re.I), "express"),
    (re.compile(r"^wp-settings-", re.I), "wordpress"),
    (re.compile(r"^__cfduid$|^__cf_bm$", re.I), "cloudflare"),
    (re.compile(r"^AWSALB$|^AWSALBCORS$", re.I), "aws-alb"),
    (re.compile(r"^incap_ses_", re.I), "waf-imperva"),
]


# ── HTML body patterns ────────────────────────────────────────

_HTML_RULES: list[tuple[re.Pattern, str]] = [
    # Meta generators
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress', re.I), "wordpress"),
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal', re.I), "drupal"),
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla', re.I), "joomla"),

    # JS frameworks — script tags / global vars
    (re.compile(r'(?:react|react-dom|reactDOM|__NEXT_DATA__)', re.I), "react"),
    (re.compile(r'(?:ng-app|ng-controller|angular\.module|ng-version)', re.I), "angular"),
    (re.compile(r'(?:Vue\.|vue\.min\.js|v-bind|v-if|v-for|vue@)', re.I), "vue"),
    (re.compile(r'(?:jQuery|jquery\.min\.js|\$\(document\))', re.I), "jquery"),
    (re.compile(r'(?:bootstrap\.min\.(css|js)|class=["\'][^"\']*\bbootstrap\b)', re.I), "bootstrap"),

    # API patterns
    (re.compile(r'(?:/graphql|__schema|query\s*\{)', re.I), "graphql"),
    (re.compile(r'(?:swagger-ui|openapi|api-docs)', re.I), "swagger"),
    (re.compile(r'(?:/api/v[0-9]+|/rest/|/api/)', re.I), "rest-api"),

    # Auth patterns
    (re.compile(r'(?:csrf[_-]?token|authenticity_token|__RequestVerificationToken)', re.I), "csrf-token"),
    (re.compile(r'(?:type=["\']password["\'])', re.I), "login-form"),

    # CMS / platform hints
    (re.compile(r'/wp-content/|/wp-includes/', re.I), "wordpress"),
    (re.compile(r'/sites/default/files/', re.I), "drupal"),
    (re.compile(r'<script[^>]*src=["\'][^"\']*mootools', re.I), "joomla"),
    (re.compile(r'Shopify\.', re.I), "shopify"),
    (re.compile(r'__NUXT__', re.I), "nuxt"),

    # Session / cookie patterns in HTML
    (re.compile(r'(?:session[_-]?cookie|session[_-]?id)', re.I), "session-cookie"),

    # File upload indicators
    (re.compile(r'(?:type=["\']file["\']|enctype=["\']multipart)', re.I), "file-upload"),
]


# ── Data classes ──────────────────────────────────────────────


@dataclass
class TechSignal:
    """A single detected technology signal with evidence."""
    signal: str
    confidence: str = "medium"   # high / medium / low
    source: str = ""              # "header", "cookie", "html", "url"
    evidence: str = ""            # raw value that triggered detection


@dataclass
class FingerprintResult:
    """Complete fingerprinting result for a target."""
    target: str
    signals: list[TechSignal] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)
    cookies_found: list[str] = field(default_factory=list)
    status_code: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def signal_set(self) -> set[str]:
        """Unique signal names as a set (for recipe matching)."""
        return {s.signal for s in self.signals}

    @property
    def signal_list(self) -> list[str]:
        """Unique signal names as a sorted list."""
        return sorted(self.signal_set)

    @property
    def waf_detected(self) -> list[str]:
        """WAF signals detected."""
        return [s.signal for s in self.signals if s.signal.startswith("waf-")]

    @property
    def security_headers(self) -> list[str]:
        """Security headers present."""
        sec_names = {"x-frame-options", "csp", "hsts", "x-content-type-options", "x-xss-protection"}
        return [s.signal for s in self.signals if s.signal in sec_names]

    def has_signal(self, name: str) -> bool:
        return name in self.signal_set

    def summary(self) -> dict:
        return {
            "target": self.target,
            "status_code": self.status_code,
            "signals": self.signal_list,
            "signal_count": len(self.signal_set),
            "waf": self.waf_detected,
            "security_headers": self.security_headers,
            "errors": len(self.errors),
        }


# ── Fingerprinter ─────────────────────────────────────────────


class Fingerprinter:
    """Detect tech stack from HTTP responses.

    Analyzes:
      - Response headers (Server, X-Powered-By, etc.)
      - Cookies (PHPSESSID, JSESSIONID, etc.)
      - HTML body (meta generators, JS framework markers, etc.)
      - WAF signatures
      - Security headers

    Multiple pages can be fingerprinted and results merged.
    """

    def __init__(
        self,
        client: HttpClient | None = None,
        session: Session | None = None,
        *,
        extra_paths: list[str] | None = None,
    ):
        self.client = client
        self.session = session
        # Additional paths to probe beyond the main page
        self.extra_paths = extra_paths or [
            "/robots.txt",
            "/sitemap.xml",
            "/favicon.ico",
            "/login",
            "/api",
        ]

    async def fingerprint(
        self,
        target_url: str,
        *,
        probe_extras: bool = True,
    ) -> FingerprintResult:
        """Fingerprint the target by fetching pages and analyzing responses."""
        result = FingerprintResult(target=target_url)

        if self.client is None:
            result.errors.append("No HTTP client configured")
            return result

        # Main page
        await self._probe_url(target_url, result, is_main=True)

        # Probe extra paths for more signals
        if probe_extras:
            base = target_url.rstrip("/")
            for path in self.extra_paths:
                url = f"{base}{path}"
                try:
                    await self._probe_url(url, result, is_main=False)
                except Exception as exc:
                    # Extra probes failing is fine
                    logger.debug("Extra probe failed for %s: %s", url, exc)

        # Deduplicate signals
        result.signals = self._deduplicate(result.signals)
        return result

    def fingerprint_response(
        self,
        headers: dict[str, str],
        body: str = "",
        cookies: list[str] | None = None,
        url: str = "",
    ) -> list[TechSignal]:
        """Fingerprint from raw response data (no HTTP needed).

        Useful for testing and for analyzing already-fetched responses.
        """
        signals: list[TechSignal] = []
        signals.extend(self._analyze_headers(headers))
        signals.extend(self._analyze_waf_headers(headers))
        if cookies:
            signals.extend(self._analyze_cookies(cookies))
        if body:
            signals.extend(self._analyze_body(body))
        return signals

    # ── Internal probing ──────────────────────────────────────

    async def _probe_url(
        self,
        url: str,
        result: FingerprintResult,
        *,
        is_main: bool = False,
    ) -> None:
        """Fetch a URL and extract tech signals from the response."""
        try:
            resp = await self.client.get(url, session=self.session)
        except Exception as exc:
            result.errors.append(f"Failed to fetch {url}: {exc}")
            return

        if is_main:
            result.status_code = resp.status_code
            result.raw_headers = dict(resp.headers)

        # Extract headers as lowercase dict
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Extract cookie names
        cookie_names: list[str] = []
        for cookie_header in resp.headers.get_list("set-cookie"):
            name = cookie_header.split("=", 1)[0].strip()
            if name:
                cookie_names.append(name)
                if name not in result.cookies_found:
                    result.cookies_found.append(name)

        # Analyze
        signals = self._analyze_headers(headers)
        signals.extend(self._analyze_waf_headers(headers))
        signals.extend(self._analyze_cookies(cookie_names))

        # Only analyze body for HTML responses
        content_type = headers.get("content-type", "")
        if "text/html" in content_type or "application/xhtml" in content_type:
            signals.extend(self._analyze_body(resp.text))

        result.signals.extend(signals)

    # ── Analysis methods ──────────────────────────────────────

    @staticmethod
    def _analyze_headers(headers: dict[str, str]) -> list[TechSignal]:
        """Extract tech signals from response headers."""
        signals: list[TechSignal] = []
        for header_name, rules in _HEADER_RULES:
            value = headers.get(header_name, "")
            if not value:
                continue
            for pattern, signal in rules:
                if pattern.search(value):
                    signals.append(TechSignal(
                        signal=signal,
                        confidence="high",
                        source="header",
                        evidence=f"{header_name}: {value}",
                    ))
        return signals

    @staticmethod
    def _analyze_waf_headers(headers: dict[str, str]) -> list[TechSignal]:
        """Detect WAF from response headers."""
        signals: list[TechSignal] = []
        for header_name, rules in _WAF_HEADER_RULES:
            value = headers.get(header_name, "")
            if not value:
                continue
            for pattern, signal in rules:
                if pattern.search(value):
                    signals.append(TechSignal(
                        signal=signal,
                        confidence="high",
                        source="header",
                        evidence=f"{header_name}: {value}",
                    ))
        return signals

    @staticmethod
    def _analyze_cookies(cookie_names: list[str]) -> list[TechSignal]:
        """Extract tech signals from cookie names."""
        signals: list[TechSignal] = []
        for name in cookie_names:
            for pattern, signal in _COOKIE_RULES:
                if pattern.search(name):
                    signals.append(TechSignal(
                        signal=signal,
                        confidence="high",
                        source="cookie",
                        evidence=f"cookie: {name}",
                    ))
                    break  # one match per cookie name
        return signals

    @staticmethod
    def _analyze_body(html: str) -> list[TechSignal]:
        """Extract tech signals from HTML body."""
        signals: list[TechSignal] = []
        for pattern, signal in _HTML_RULES:
            m = pattern.search(html)
            if m:
                context = html[max(0, m.start() - 20):m.end() + 20].strip()
                # Truncate long evidence
                if len(context) > 120:
                    context = context[:120] + "..."
                signals.append(TechSignal(
                    signal=signal,
                    confidence="medium",
                    source="html",
                    evidence=context,
                ))
        return signals

    @staticmethod
    def _deduplicate(signals: list[TechSignal]) -> list[TechSignal]:
        """Deduplicate signals, keeping highest confidence per signal name."""
        confidence_rank = {"high": 3, "medium": 2, "low": 1}
        best: dict[str, TechSignal] = {}
        for sig in signals:
            existing = best.get(sig.signal)
            if existing is None:
                best[sig.signal] = sig
            elif confidence_rank.get(sig.confidence, 0) > confidence_rank.get(existing.confidence, 0):
                best[sig.signal] = sig
        return list(best.values())
