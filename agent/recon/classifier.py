"""Endpoint Functionality Classifier (Phase 2.4).

Classifies discovered endpoints by their functional role (login, search,
file handler, user profile, API, etc.) so the scanner pipeline knows
which vulnerability classes to test on each endpoint.

Classification signals:
  1. URL path patterns (/login, /search, /upload, /api/users)
  2. Form field names (username+password → login, query → search)
  3. HTTP methods (POST on auth-looking endpoints → login)
  4. Page title / content hints

Output: EndpointFunction enum + confidence, attached to each endpoint.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .crawler import DiscoveredForm, CrawledPage

logger = logging.getLogger(__name__)


# ── Default values for form fields (used as sibling defaults) ──

def _default_for_field(name: str, input_type: str = "text") -> str:
    """Return a sensible default value for a form field.

    Used when testing one param for injection — the OTHER form fields
    need realistic defaults so the server processes the request normally
    (e.g., a login form requires both username and password).
    """
    name_lower = name.lower()

    # Skip CSRF/token fields — they need real values from the page
    if any(tok in name_lower for tok in ("csrf", "token", "_token", "nonce")):
        return ""

    # By input type
    if input_type == "password":
        return "test123"
    if input_type == "email":
        return "test@test.com"
    if input_type in ("number", "tel"):
        return "1"
    if input_type in ("checkbox", "radio"):
        return "on"
    if input_type == "hidden":
        return ""  # can't guess hidden values

    # By field name
    if any(tok in name_lower for tok in ("pass", "pwd", "pw")):
        return "test123"
    if any(tok in name_lower for tok in ("email", "mail")):
        return "test@test.com"
    if any(tok in name_lower for tok in ("user", "login", "uname", "uid")):
        return "testuser"
    if any(tok in name_lower for tok in ("name",)):
        return "testuser"
    if any(tok in name_lower for tok in ("phone", "tel", "mobile")):
        return "1234567890"
    if any(tok in name_lower for tok in ("url", "link", "website")):
        return "http://example.com"
    if any(tok in name_lower for tok in ("search", "query", "q", "keyword")):
        return "test"
    if any(tok in name_lower for tok in ("comment", "message", "body", "text", "content")):
        return "test comment"

    return "test"


class EndpointFunction(str, Enum):
    """Functional role of an endpoint."""
    LOGIN = "login"                 # Authentication forms
    REGISTRATION = "registration"   # User signup
    SEARCH = "search"               # Search / filter / query
    FILE_HANDLER = "file_handler"   # Upload / download / file access
    USER_PROFILE = "user_profile"   # View / edit user profiles
    ADMIN = "admin"                 # Admin panels / management
    API_DATA = "api_data"           # REST/JSON data endpoints
    PASSWORD_RESET = "password_reset"
    PAYMENT = "payment"             # Payment / transaction
    COMMENT = "comment"             # Comments / reviews / feedback
    CONTACT = "contact"             # Contact / messaging forms
    SETTINGS = "settings"           # User settings / preferences
    REDIRECT = "redirect"           # Redirect handlers (open redirect targets)
    GENERIC_FORM = "generic_form"   # Form that doesn't fit other categories
    STATIC_PAGE = "static_page"     # Informational page, no dynamic params
    UNKNOWN = "unknown"


# ── Vuln classes relevant to each function ──────────────────

FUNCTION_VULN_MAP: dict[EndpointFunction, list[str]] = {
    EndpointFunction.LOGIN: [
        "sqli",              # Auth bypass via SQLi
        "nosqli",            # NoSQLi auth bypass
        "brute-force",       # Credential stuffing
        "csrf",              # CSRF on login (login-CSRF)
    ],
    EndpointFunction.REGISTRATION: [
        "sqli", "xss", "nosqli", "csrf",
    ],
    EndpointFunction.SEARCH: [
        "sqli",              # Search param injection
        "xss",               # Reflected XSS in search results
        "nosqli",            # NoSQL injection in search
        "ssti",              # Template injection in displayed results
    ],
    EndpointFunction.FILE_HANDLER: [
        "lfi",               # Path traversal / local file inclusion
        "rfi",               # Remote file inclusion
        "ssrf",              # File from URL
        "upload",            # Unrestricted file upload
    ],
    EndpointFunction.USER_PROFILE: [
        "idor",              # Access other users' profiles
        "xss",               # Stored XSS in profile fields
        "stored-xss",        # Persistent XSS in profile fields
        "sqli",              # SQLi in profile lookup
        "csrf",              # CSRF on profile update
    ],
    EndpointFunction.ADMIN: [
        "idor",              # Horizontal/vertical privilege escalation
        "sqli", "xss", "ssti", "command-injection", "lfi",
    ],
    EndpointFunction.API_DATA: [
        "idor",              # BOLA — access other users' data
        "sqli",              # Injection in API params
        "nosqli",            # NoSQL injection
        "ssrf",              # SSRF via API params
        "command-injection", # OS command injection via API params
        "mass-assignment",   # Extra fields in JSON body
    ],
    EndpointFunction.PASSWORD_RESET: [
        "idor",              # Reset other users' passwords
        "sqli",
        "csrf",              # CSRF on password reset
    ],
    EndpointFunction.PAYMENT: [
        "idor",              # Access other users' transactions
        "sqli",              # Price/amount manipulation
        "parameter-tampering",
        "csrf",              # CSRF on payment actions
    ],
    EndpointFunction.COMMENT: [
        "xss",               # Stored XSS in comments
        "stored-xss",        # Persistent XSS in comments
        "sqli",
        "ssti",
        "csrf",              # CSRF on comment submission
    ],
    EndpointFunction.CONTACT: [
        "xss", "stored-xss", "sqli", "ssti",
        "email-injection",   # Header injection in contact forms
        "csrf",              # CSRF on contact form
    ],
    EndpointFunction.SETTINGS: [
        "idor",              # Change other users' settings
        "xss", "sqli",
        "csrf",              # CSRF on settings change
    ],
    EndpointFunction.REDIRECT: [
        "open-redirect",     # Open redirect
        "ssrf",              # SSRF via redirect param
    ],
    EndpointFunction.GENERIC_FORM: [
        "sqli", "xss", "stored-xss", "ssti", "command-injection", "csrf",
    ],
    EndpointFunction.STATIC_PAGE: [],  # No dynamic testing needed
    EndpointFunction.UNKNOWN: [
        "sqli", "xss",       # Default: test common vulns
    ],
}


@dataclass
class ClassifiedEndpoint:
    """An endpoint with its classified function and relevant vuln classes."""
    url: str
    function: EndpointFunction = EndpointFunction.UNKNOWN
    confidence: float = 0.0        # 0.0 to 1.0
    signals: list[str] = field(default_factory=list)  # what triggered the classification
    relevant_vulns: list[str] = field(default_factory=list)
    injection_points: list[dict] = field(default_factory=list)
    # Each injection_point: {param, location (query/body/path), type, vuln_classes}

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "function": self.function.value,
            "confidence": self.confidence,
            "signals": self.signals,
            "relevant_vulns": self.relevant_vulns,
            "injection_points": self.injection_points,
        }


# ── Classification rules ─────────────────────────────────────

# URL path patterns → function (checked in order, first match wins)
_PATH_RULES: list[tuple[re.Pattern, EndpointFunction, float]] = [
    # Login / auth
    (re.compile(r"(?:^|/)(?:do)?login|signin|sign[_-]?in|authenticate|auth/login", re.I),
     EndpointFunction.LOGIN, 0.9),
    (re.compile(r"(?:^|/)log[_-]?out|sign[_-]?out|logout", re.I),
     EndpointFunction.LOGIN, 0.7),

    # Registration
    (re.compile(r"(?:^|/)register|sign[_-]?up|signup|create[_-]?account", re.I),
     EndpointFunction.REGISTRATION, 0.9),

    # Password reset
    (re.compile(r"(?:^|/)(?:forgot|reset|recover)[_-]?password|password[_-]?reset", re.I),
     EndpointFunction.PASSWORD_RESET, 0.9),

    # Search
    (re.compile(r"(?:^|/)search|find|query|lookup|filter|browse", re.I),
     EndpointFunction.SEARCH, 0.8),

    # File handling
    (re.compile(r"(?:^|/)upload|download|file|attachment|document|export|import", re.I),
     EndpointFunction.FILE_HANDLER, 0.8),
    (re.compile(r"(?:^|/)(?:get|read|view|show)[_-]?file", re.I),
     EndpointFunction.FILE_HANDLER, 0.85),

    # User profile
    (re.compile(r"(?:^|/)(?:my[_-]?)?profile|account|user(?:s)?/\w+|me$", re.I),
     EndpointFunction.USER_PROFILE, 0.8),

    # Admin
    (re.compile(r"(?:^|/)admin|dashboard|manage|panel|control", re.I),
     EndpointFunction.ADMIN, 0.8),

    # API endpoints
    (re.compile(r"(?:^|/)api/|/v\d+/|/rest/|/graphql", re.I),
     EndpointFunction.API_DATA, 0.85),

    # Payment
    (re.compile(r"(?:^|/)pay|payment|checkout|transaction|transfer|billing", re.I),
     EndpointFunction.PAYMENT, 0.85),

    # Comments / feedback
    (re.compile(r"(?:^|/)comment|review|feedback|rating|testimonial", re.I),
     EndpointFunction.COMMENT, 0.8),

    # Contact
    (re.compile(r"(?:^|/)contact|message|support|ticket|inquiry", re.I),
     EndpointFunction.CONTACT, 0.7),

    # Settings
    (re.compile(r"(?:^|/)settings|preferences|config(?:uration)?|options", re.I),
     EndpointFunction.SETTINGS, 0.8),

    # Redirect
    (re.compile(r"(?:^|/)redirect|goto|redir|bounce|away|external", re.I),
     EndpointFunction.REDIRECT, 0.85),
]

# Form field combinations → function
_FORM_FIELD_RULES: list[tuple[set[str], EndpointFunction, float]] = [
    # Login: has username/password-like fields
    ({"username", "password"}, EndpointFunction.LOGIN, 0.95),
    ({"user", "pass"}, EndpointFunction.LOGIN, 0.9),
    ({"login", "password"}, EndpointFunction.LOGIN, 0.9),
    ({"email", "password"}, EndpointFunction.LOGIN, 0.85),
    ({"uid", "passw"}, EndpointFunction.LOGIN, 0.85),

    # Registration: has email + password + name or confirm
    ({"email", "password", "name"}, EndpointFunction.REGISTRATION, 0.9),
    ({"username", "password", "email"}, EndpointFunction.REGISTRATION, 0.9),
    ({"password", "confirm_password"}, EndpointFunction.REGISTRATION, 0.85),

    # Search
    ({"query",}, EndpointFunction.SEARCH, 0.8),
    ({"q",}, EndpointFunction.SEARCH, 0.8),
    ({"search",}, EndpointFunction.SEARCH, 0.85),
    ({"keyword",}, EndpointFunction.SEARCH, 0.8),

    # File upload
    ({"file",}, EndpointFunction.FILE_HANDLER, 0.85),
    ({"attachment",}, EndpointFunction.FILE_HANDLER, 0.8),
    ({"document",}, EndpointFunction.FILE_HANDLER, 0.75),

    # Contact form
    ({"name", "email", "message"}, EndpointFunction.CONTACT, 0.85),
    ({"subject", "message"}, EndpointFunction.CONTACT, 0.8),
]

# Param type → relevant vuln classes for that specific param
PARAM_TYPE_VULN_MAP: dict[str, list[str]] = {
    "id": ["idor", "sqli"],
    "uuid": ["idor"],
    "token": ["auth-bypass"],
    "password": ["sqli", "nosqli"],  # on login forms
    "username": ["sqli", "nosqli", "user-enum"],
    "email": ["sqli", "xss", "user-enum"],
    "url": ["ssrf", "open-redirect"],
    "file": ["lfi", "rfi", "path-traversal"],
    "code": ["command-injection", "ssti", "sqli"],
    "raw": ["xss", "sqli", "ssti"],
    "search": ["sqli", "xss", "nosqli"],
    "text": ["xss", "sqli", "ssti"],
    "sort": ["sqli"],   # ORDER BY injection
    "boolean": ["idor"],  # is_admin, is_verified
    "enum": ["idor"],     # role escalation
    "numeric": ["idor", "sqli"],
    "pagination": ["sqli"],
    "string": ["xss", "sqli"],
    "hidden": ["idor", "parameter-tampering"],
    "unknown": ["sqli", "xss"],
}


class EndpointClassifier:
    """Classifies endpoints by functional role.

    Uses URL patterns, form fields, and param types to determine what
    each endpoint does, then maps that to relevant vulnerability classes
    and identifies specific injection points.
    """

    def classify_endpoint(
        self,
        url: str,
        *,
        methods: list[str] | None = None,
        params: list[dict] | None = None,
        forms: list[DiscoveredForm] | None = None,
        page: CrawledPage | None = None,
    ) -> ClassifiedEndpoint:
        """Classify a single endpoint.

        Args:
            url: The endpoint URL
            methods: HTTP methods this endpoint accepts
            params: Param dicts [{name, type, score, sources}]
            forms: Forms discovered on/targeting this endpoint
            page: The crawled page data (if available)

        Returns:
            ClassifiedEndpoint with function, relevant vulns, injection points.
        """
        methods = methods or ["GET"]
        params = params or []
        forms = forms or []

        result = ClassifiedEndpoint(url=url)
        candidates: list[tuple[EndpointFunction, float, str]] = []

        # Signal 1: URL path patterns
        from urllib.parse import urlparse
        path = urlparse(url).path.lower()
        for pattern, func, conf in _PATH_RULES:
            if pattern.search(path):
                candidates.append((func, conf, f"path:{pattern.pattern[:40]}"))
                break  # first match wins for path

        # Signal 2: Form field combinations
        for form in forms:
            field_names = {f.name.lower() for f in form.fields}
            for required_fields, func, conf in _FORM_FIELD_RULES:
                # Check if required fields are a subset (fuzzy: also check partial matches)
                if self._fields_match(required_fields, field_names):
                    candidates.append((func, conf, f"fields:{required_fields}"))
                    break

            # Check for password-type inputs specifically
            has_password_input = any(
                f.input_type == "password" for f in form.fields
            )
            if has_password_input and form.method == "POST":
                # POST with password field → likely login or registration
                has_confirm = any("confirm" in f.name.lower() or "retype" in f.name.lower()
                                  for f in form.fields)
                if has_confirm:
                    candidates.append((EndpointFunction.REGISTRATION, 0.8,
                                       "password+confirm input"))
                else:
                    candidates.append((EndpointFunction.LOGIN, 0.85,
                                       "password input + POST"))

        # Signal 3: Param types
        param_signals = self._classify_from_params(params)
        candidates.extend(param_signals)

        # Signal 4: Page content (title, body hints)
        if page and page.title:
            title = page.title.lower()
            if any(w in title for w in ("login", "sign in", "log in")):
                candidates.append((EndpointFunction.LOGIN, 0.7, f"title:{page.title[:30]}"))
            elif any(w in title for w in ("search", "find", "results")):
                candidates.append((EndpointFunction.SEARCH, 0.6, f"title:{page.title[:30]}"))
            elif any(w in title for w in ("register", "sign up", "create account")):
                candidates.append((EndpointFunction.REGISTRATION, 0.7, f"title:{page.title[:30]}"))
            elif any(w in title for w in ("admin", "dashboard", "manage")):
                candidates.append((EndpointFunction.ADMIN, 0.6, f"title:{page.title[:30]}"))

        # Pick the highest-confidence classification
        if candidates:
            # Sort by confidence desc, pick the best
            candidates.sort(key=lambda x: x[1], reverse=True)
            best_func, best_conf, _ = candidates[0]
            result.function = best_func
            result.confidence = best_conf
            result.signals = [sig for _, _, sig in candidates]
        else:
            # No signals matched
            if params and any(methods):
                result.function = EndpointFunction.GENERIC_FORM
                result.confidence = 0.3
            elif not params:
                result.function = EndpointFunction.STATIC_PAGE
                result.confidence = 0.5

        # Map function → relevant vuln classes
        result.relevant_vulns = list(
            FUNCTION_VULN_MAP.get(result.function, ["sqli", "xss"])
        )

        # Build injection points: each param + its location + which vulns to test
        result.injection_points = self._build_injection_points(
            url, methods, params, forms, result.function
        )

        return result

    def classify_batch(
        self,
        endpoints: list[dict],
        crawl_pages: dict[str, CrawledPage] | None = None,
        forms_by_action: dict[str, list[DiscoveredForm]] | None = None,
    ) -> list[ClassifiedEndpoint]:
        """Classify a batch of endpoints.

        Args:
            endpoints: List of endpoint dicts from inventory
                [{url, methods, params, sources}]
            crawl_pages: URL → CrawledPage mapping
            forms_by_action: action URL → list of forms targeting it
        """
        crawl_pages = crawl_pages or {}
        forms_by_action = forms_by_action or {}
        results = []

        for ep in endpoints:
            url = ep.get("url", ep.get("endpoint", ""))
            methods = ep.get("methods", ["GET"])
            params = ep.get("params", [])
            forms = forms_by_action.get(url, [])
            page = crawl_pages.get(url)

            classified = self.classify_endpoint(
                url,
                methods=methods,
                params=params,
                forms=forms,
                page=page,
            )
            results.append(classified)

        return results

    # ── Internal helpers ─────────────────────────────────────

    @staticmethod
    def _fields_match(required: set[str], actual: set[str]) -> bool:
        """Check if required fields are present in actual (with fuzzy matching).

        Handles cases like 'uid' matching 'username', 'passw' matching 'password'.
        """
        for req in required:
            found = False
            for act in actual:
                if req in act or act in req:
                    found = True
                    break
            if not found:
                return False
        return True

    @staticmethod
    def _classify_from_params(params: list[dict]) -> list[tuple[EndpointFunction, float, str]]:
        """Infer endpoint function from param types."""
        signals = []
        param_types = {p.get("type", "unknown") for p in params}
        param_names = {p.get("name", "").lower() for p in params}

        # file/path params → file handler
        if "file" in param_types or any("file" in n or "path" in n for n in param_names):
            signals.append((EndpointFunction.FILE_HANDLER, 0.7, "param_type:file"))

        # url params → redirect or ssrf target
        if "url" in param_types or any(n in ("url", "redirect", "next", "goto", "callback")
                                        for n in param_names):
            signals.append((EndpointFunction.REDIRECT, 0.6, "param_type:url"))

        # search params
        if "search" in param_types or any(n in ("q", "query", "search", "keyword")
                                           for n in param_names):
            signals.append((EndpointFunction.SEARCH, 0.7, "param_type:search"))

        # id params without other context → API data
        if "id" in param_types and len(params) <= 3:
            signals.append((EndpointFunction.API_DATA, 0.5, "param_type:id"))

        return signals

    def _build_injection_points(
        self,
        url: str,
        methods: list[str],
        params: list[dict],
        forms: list[DiscoveredForm],
        function: EndpointFunction,
    ) -> list[dict]:
        """Build specific injection points with param→vuln mapping.

        Each injection point tells the scanner exactly:
        - Which param to inject
        - Where it goes (query, body, path)
        - Which vuln classes to test
        - What technique to prioritize
        """
        points = []
        seen = set()  # avoid dupes

        # From form fields
        for form in forms:
            location = "body" if form.method in ("POST", "PUT", "PATCH") else "query"
            for ff in form.fields:
                key = (ff.name, location, form.method)
                if key in seen:
                    continue
                seen.add(key)

                # Determine vuln classes for this specific param
                param_type = self._get_param_type(ff.name, params)
                vulns = self._param_vulns(param_type, function, ff.name)

                # Build sibling fields: all OTHER fields in this form
                # with sensible defaults so the server processes the request
                siblings = {}
                for other in form.fields:
                    if other.name != ff.name:
                        siblings[other.name] = _default_for_field(
                            other.name, other.input_type
                        )

                point = {
                    "param": ff.name,
                    "location": location,
                    "method": form.method,
                    "param_type": param_type,
                    "input_type": ff.input_type,
                    "vuln_classes": vulns,
                    "priority": self._priority(param_type, function),
                }
                if siblings:
                    point["sibling_fields"] = siblings

                points.append(point)

        # From URL query params (not already in forms)
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for pname in qs:
                key = (pname, "query", "GET")
                if key in seen:
                    continue
                seen.add(key)

                param_type = self._get_param_type(pname, params)
                vulns = self._param_vulns(param_type, function, pname)

                points.append({
                    "param": pname,
                    "location": "query",
                    "method": "GET",
                    "param_type": param_type,
                    "input_type": "text",
                    "vuln_classes": vulns,
                    "priority": self._priority(param_type, function),
                })

        # From param inventory (params not yet seen)
        for p in params:
            pname = p.get("name", "")
            for method in methods:
                location = "body" if method in ("POST", "PUT", "PATCH") else "query"
                key = (pname, location, method)
                if key in seen:
                    continue
                seen.add(key)

                param_type = p.get("type", "unknown")
                vulns = self._param_vulns(param_type, function, pname)

                points.append({
                    "param": pname,
                    "location": location,
                    "method": method,
                    "param_type": param_type,
                    "input_type": "",
                    "vuln_classes": vulns,
                    "priority": self._priority(param_type, function),
                })

        # Sort by priority (highest first)
        points.sort(key=lambda x: x.get("priority", 0), reverse=True)
        return points

    @staticmethod
    def _get_param_type(name: str, params: list[dict]) -> str:
        """Look up param type from the param inventory."""
        for p in params:
            if p.get("name", "") == name:
                return p.get("type", "unknown")
        return "unknown"

    @staticmethod
    def _param_vulns(param_type: str, function: EndpointFunction, name: str) -> list[str]:
        """Determine which vuln classes to test for a specific param.

        Combines:
        1. Param-type-specific vulns (file → LFI, url → SSRF)
        2. Endpoint-function-specific vulns (login → auth bypass SQLi)
        3. Always-test defaults (sqli, xss for text-accepting params)
        """
        vulns = set()

        # Param type vulns
        type_vulns = PARAM_TYPE_VULN_MAP.get(param_type, [])
        vulns.update(type_vulns)

        # Function vulns
        func_vulns = FUNCTION_VULN_MAP.get(function, [])
        vulns.update(func_vulns)

        # Special cases based on param name
        name_lower = name.lower()
        if name_lower in ("cmd", "command", "exec", "run"):
            vulns.add("command-injection")
        if name_lower in ("template", "tpl", "view", "render"):
            vulns.add("ssti")
        if name_lower in ("include", "page", "file", "path", "doc", "folder", "dir"):
            vulns.add("lfi")
            vulns.add("path-traversal")
        if name_lower in ("url", "uri", "link", "src", "source", "href"):
            vulns.add("ssrf")
            vulns.add("open-redirect")

        return sorted(vulns)

    @staticmethod
    def _priority(param_type: str, function: EndpointFunction) -> int:
        """Compute testing priority for an injection point.

        Higher priority = test first. Based on:
        - How likely the param is to be injectable
        - How severe the endpoint function is
        """
        from .param_discovery import _TYPE_SECURITY_SCORE

        base = _TYPE_SECURITY_SCORE.get(param_type, 3)

        # Boost for high-value endpoint functions
        func_boost = {
            EndpointFunction.LOGIN: 3,
            EndpointFunction.ADMIN: 3,
            EndpointFunction.PAYMENT: 3,
            EndpointFunction.API_DATA: 2,
            EndpointFunction.FILE_HANDLER: 2,
            EndpointFunction.USER_PROFILE: 2,
            EndpointFunction.SEARCH: 1,
            EndpointFunction.PASSWORD_RESET: 2,
        }
        base += func_boost.get(function, 0)

        return min(base, 15)
