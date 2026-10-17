"""JS sensitive data analyzer — finds secrets, API keys, tokens, and internal URLs in JS files.

Works alongside js_extractor.py (which finds endpoints). This module focuses on:
  - API keys, tokens, secrets hardcoded in JS
  - Internal/staging URLs, IP addresses
  - Credentials (username/password pairs)
  - AWS keys, Firebase configs, JWT tokens
  - Source map files (information disclosure)
  - Comments with sensitive info (TODO, FIXME, passwords)
"""
from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from ..http import HttpClient, Session

logger = logging.getLogger(__name__)


# ── Sensitive data patterns ────────────────────────────────────

_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # API Keys & Tokens
    ("AWS Access Key", re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"), "critical"),
    ("AWS Secret Key", re.compile(r"""(?:aws_secret|secret_key|secretkey)\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]""", re.I), "critical"),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "high"),
    ("Google OAuth", re.compile(r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com"), "high"),
    ("Firebase Config", re.compile(r"""(?:apiKey|authDomain|databaseURL|storageBucket)\s*:\s*['"]([^'"]+)['"]"""), "medium"),
    ("Slack Token", re.compile(r"xox[bporas]-[0-9a-zA-Z-]{10,}"), "critical"),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"), "high"),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), "critical"),
    ("Generic API Key", re.compile(r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]""", re.I), "high"),
    ("Generic Secret", re.compile(r"""(?:secret|private[_-]?key|client[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9_\-/+=]{16,})['"]""", re.I), "high"),
    ("Generic Token", re.compile(r"""(?:auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*['"]([A-Za-z0-9_\-\.]{20,})['"]""", re.I), "high"),
    ("Generic Password", re.compile(r"""(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{4,})['"]""", re.I), "critical"),

    # JWT Tokens
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), "high"),

    # Internal URLs & IPs
    ("Internal IP", re.compile(r"""(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?"""), "medium"),
    ("Localhost URL", re.compile(r"https?://(?:localhost|127\.0\.0\.1)(?::\d+)?[/\w.-]*"), "low"),
    ("Staging/Dev URL", re.compile(r"""https?://[a-z0-9.-]*(?:staging|stage|dev|test|uat|internal|preprod|sandbox)\.[a-z0-9.-]+""", re.I), "medium"),

    # Database connection strings
    ("DB Connection String", re.compile(r"""(?:mongodb|mysql|postgresql|postgres|redis|mssql)://[^\s'"]+""", re.I), "critical"),

    # Email addresses (potential info disclosure)
    ("Email Address", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "low"),

    # S3 Bucket
    ("S3 Bucket", re.compile(r"""(?:https?://)?[a-z0-9.-]+\.s3[.-](?:amazonaws\.com|[a-z0-9-]+\.amazonaws\.com)""", re.I), "medium"),
    ("S3 Bucket Path", re.compile(r"""s3://[a-z0-9.-]+(?:/[^\s'"]*)?"""), "medium"),
]

# Comment patterns with sensitive info
_COMMENT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("TODO/FIXME", re.compile(r"(?://|/\*)\s*(?:TODO|FIXME|HACK|XXX|BUG)\s*:?\s*(.{10,80})", re.I)),
    ("Password in comment", re.compile(r"(?://|/\*)\s*.*(?:password|passwd|pwd|secret|token|key)\s*[:=]\s*(.{4,60})", re.I)),
    ("Debug comment", re.compile(r"(?://|/\*)\s*(?:debug|testing|temp|remove)\s*:?\s*(.{5,80})", re.I)),
]


@dataclass
class SensitiveFind:
    """A single sensitive data finding in JS."""
    category: str
    matched_text: str
    severity: str  # critical, high, medium, low
    source_file: str
    line_context: str = ""  # surrounding text for context


@dataclass
class SourceMapResult:
    """Detailed source map analysis result."""
    map_url: str
    js_url: str
    accessible: bool = False
    original_files: list[str] = field(default_factory=list)
    exposed_source_snippets: list[dict] = field(default_factory=list)
    frameworks_detected: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class JsAnalysisResult:
    """Results from analyzing JS files for sensitive data."""
    target: str = ""
    js_files_analyzed: int = 0
    findings: list[SensitiveFind] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    source_map_details: list[SourceMapResult] = field(default_factory=list)
    comments: list[dict] = field(default_factory=list)
    inline_source_maps: list[dict] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def critical_findings(self) -> list[SensitiveFind]:
        return [f for f in self.findings if f.severity == "critical"]

    def high_findings(self) -> list[SensitiveFind]:
        return [f for f in self.findings if f.severity in ("critical", "high")]


class JsAnalyzer:
    """Analyzes JavaScript files for sensitive data, secrets, and information disclosure."""

    def __init__(self, client: HttpClient, session: Session, max_js_files: int = 20):
        self.client = client
        self.session = session
        self.max_js_files = max_js_files

    async def analyze(self, target_url: str, js_urls: list[str] | None = None) -> JsAnalysisResult:
        """Analyze JS files from target for sensitive data.

        Args:
            target_url: The base URL being tested
            js_urls: Pre-discovered JS URLs (from js_extractor). If None, discovers them.
        """
        result = JsAnalysisResult(target=target_url)

        # If no JS URLs provided, discover them from the page
        if js_urls is None:
            js_urls = await self._discover_js_files(target_url)

        for js_url in js_urls[:self.max_js_files]:
            try:
                resp = await self.client.get(js_url, session=self.session)
                if resp.status_code != 200:
                    continue

                js_text = resp.text
                result.js_files_analyzed += 1

                # Check for source maps (external .map files)
                if "//# sourceMappingURL=" in js_text:
                    map_match = re.search(r"//# sourceMappingURL=(\S+)", js_text)
                    if map_match:
                        map_ref = map_match.group(1)
                        # Handle inline base64 source maps
                        if map_ref.startswith("data:"):
                            result.inline_source_maps.append({
                                "js_url": js_url,
                                "detail": "Inline base64 source map embedded — original source code in JS bundle",
                            })
                            result.findings.append(SensitiveFind(
                                category="Inline Source Map",
                                matched_text="data:application/json;base64,...",
                                severity="high",
                                source_file=js_url,
                                line_context="Base64-encoded source map embedded inline — exposes original source code, file structure, variable names",
                            ))
                        else:
                            map_url = urljoin(js_url, map_ref)
                            result.source_maps.append(map_url)
                            # Actually download and analyze the .map file
                            sm_result = await self._analyze_source_map(map_url, js_url)
                            result.source_map_details.append(sm_result)
                            severity = "high" if sm_result.accessible else "medium"
                            detail = "Source map file accessible — exposes original source code" if sm_result.accessible else "Source map referenced but not accessible"
                            if sm_result.original_files:
                                detail += f" | {len(sm_result.original_files)} original files exposed"
                            result.findings.append(SensitiveFind(
                                category="Source Map Exposed",
                                matched_text=map_url,
                                severity=severity,
                                source_file=js_url,
                                line_context=detail,
                            ))

                # Also check for X-SourceMap header (older convention)
                if hasattr(resp, 'headers'):
                    for hdr in ("x-sourcemap", "sourcemap"):
                        if hdr in resp.headers:
                            map_url = urljoin(js_url, resp.headers[hdr])
                            if map_url not in result.source_maps:
                                result.source_maps.append(map_url)
                                sm_result = await self._analyze_source_map(map_url, js_url)
                                result.source_map_details.append(sm_result)
                                result.findings.append(SensitiveFind(
                                    category="Source Map via Header",
                                    matched_text=f"{hdr}: {map_url}",
                                    severity="high" if sm_result.accessible else "medium",
                                    source_file=js_url,
                                    line_context=f"Source map exposed via {hdr} HTTP header",
                                ))

                # Run sensitive data patterns
                for category, pattern, severity in _SENSITIVE_PATTERNS:
                    for match in pattern.finditer(js_text):
                        matched = match.group(0)
                        # Get surrounding context (50 chars before/after)
                        start = max(0, match.start() - 50)
                        end = min(len(js_text), match.end() + 50)
                        context = js_text[start:end].replace("\n", " ").strip()

                        # Skip false positives
                        if self._is_false_positive(category, matched, context):
                            continue

                        result.findings.append(SensitiveFind(
                            category=category,
                            matched_text=matched[:200],  # truncate long matches
                            severity=severity,
                            source_file=js_url,
                            line_context=context[:200],
                        ))

                # Check comments
                for comment_type, pattern in _COMMENT_PATTERNS:
                    for match in pattern.finditer(js_text):
                        result.comments.append({
                            "type": comment_type,
                            "text": match.group(1).strip()[:120],
                            "source": js_url,
                        })

            except Exception as e:
                logger.debug("Failed to analyze %s: %s", js_url, e)

        # Deduplicate findings
        seen = set()
        unique = []
        for f in result.findings:
            key = (f.category, f.matched_text[:60])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        result.findings = unique

        return result

    async def _analyze_source_map(self, map_url: str, js_url: str) -> SourceMapResult:
        """Download and analyze a .map source map file."""
        sm = SourceMapResult(map_url=map_url, js_url=js_url)
        try:
            resp = await self.client.get(map_url, session=self.session)
            if resp.status_code != 200:
                sm.error = f"HTTP {resp.status_code}"
                return sm

            sm.accessible = True
            content_type = resp.headers.get("content-type", "")

            # Parse the JSON source map
            try:
                map_data = resp.json()
            except Exception:
                # Maybe it's not JSON — still accessible, still a finding
                sm.error = "Not valid JSON but file is accessible"
                return sm

            # Extract original file names (sources array)
            sources = map_data.get("sources", [])
            sm.original_files = [s for s in sources[:200] if isinstance(s, str)]

            # Detect frameworks from file paths
            frameworks = set()
            for src in sm.original_files:
                src_lower = src.lower()
                if "react" in src_lower or "jsx" in src_lower:
                    frameworks.add("React")
                if "angular" in src_lower:
                    frameworks.add("Angular")
                if "vue" in src_lower:
                    frameworks.add("Vue.js")
                if "svelte" in src_lower:
                    frameworks.add("Svelte")
                if "next" in src_lower:
                    frameworks.add("Next.js")
                if "nuxt" in src_lower:
                    frameworks.add("Nuxt.js")
                if "typescript" in src_lower or src_lower.endswith(".ts"):
                    frameworks.add("TypeScript")
                if "node_modules" in src_lower:
                    frameworks.add("Node.js")
            sm.frameworks_detected = sorted(frameworks)

            # Extract source content snippets if sourcesContent is present
            sources_content = map_data.get("sourcesContent", [])
            for i, content in enumerate(sources_content[:50]):
                if not content or not isinstance(content, str):
                    continue
                filename = sources[i] if i < len(sources) else f"source_{i}"
                # Skip node_modules — focus on app code
                if "node_modules" in filename:
                    continue
                # Look for sensitive data in original source
                snippet_findings = []
                for category, pattern, severity in _SENSITIVE_PATTERNS:
                    for match in pattern.finditer(content[:10000]):
                        matched = match.group(0)
                        if not self._is_false_positive(category, matched, content[max(0, match.start()-30):match.end()+30]):
                            snippet_findings.append({
                                "category": category,
                                "match": matched[:150],
                                "severity": severity,
                            })
                if snippet_findings:
                    sm.exposed_source_snippets.append({
                        "file": filename,
                        "findings": snippet_findings,
                    })

        except Exception as e:
            sm.error = str(e)
        return sm

    async def _discover_js_files(self, target_url: str) -> list[str]:
        """Find JS files from the target page HTML."""
        try:
            resp = await self.client.get(target_url, session=self.session)
            html = resp.text
        except Exception:
            return []

        urls = []
        # <script src="...">
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            src = match.group(1)
            if src.endswith(".js") or ".js?" in src:
                urls.append(urljoin(target_url, src))

        return urls

    @staticmethod
    def _is_false_positive(category: str, matched: str, context: str) -> bool:
        """Filter obvious false positives."""
        matched_lower = matched.lower()
        context_lower = context.lower()

        # Skip placeholder/example values
        placeholders = ["xxx", "your_", "example", "placeholder", "insert_",
                        "change_me", "replace_", "todo", "fixme", "<your",
                        "sample", "test123", "dummy", "aaaaa"]
        if any(p in matched_lower for p in placeholders):
            return True

        # Skip CSS/HTML false positives for passwords
        if category == "Generic Password":
            if any(x in context_lower for x in ["type=", "input", "label",
                                                  "placeholder", "pattern",
                                                  "validate", "min-length",
                                                  "maxlength", "autocomplete"]):
                return True
            # Skip if it's just a variable name reference
            if matched_lower.strip("'\"") in ("password", "passwd", "pwd", ""):
                return True

        # Skip common email domains in code (not real disclosure)
        if category == "Email Address":
            if any(d in matched for d in ["@example.com", "@test.com",
                                          "@localhost", "@email.com"]):
                return True

        # Skip if inside a regex or pattern definition
        if "regex" in context_lower or "pattern" in context_lower:
            return True

        return False
