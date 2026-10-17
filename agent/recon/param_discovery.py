"""Parameter Discovery (Phase 2.3).

Merges parameter data from multiple recon sources (crawler forms,
JS-extracted endpoints, URL query strings) and infers types, roles,
and test-worthiness for each parameter. Output feeds the scanner
pipeline with structured param metadata.

Usage:
    discoverer = ParamDiscoverer()
    discoverer.add_crawl_result(crawl_result)
    discoverer.add_js_result(js_result)
    discoverer.add_url("https://app.example.com/api/users?id=123&role=admin")
    inventory = discoverer.build_inventory()
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

from .crawler import CrawlResult, DiscoveredForm
from .js_extractor import JsExtractionResult

logger = logging.getLogger(__name__)


# ── Type inference patterns ──────────────────────────────────

# Param name → likely type (checked in order, first match wins)
_NAME_TYPE_RULES: list[tuple[re.Pattern, str]] = [
    # UUID/GUID — must be checked before generic ID rule
    (re.compile(r"^uuid$|^guid$", re.IGNORECASE), "uuid"),

    # Auth / session — checked before generic ID rule so session_id → session not id
    (re.compile(r"^(?:access_?)?token$|^api_?key$|^secret$|^auth$", re.IGNORECASE), "token"),
    (re.compile(r"^password$|^passwd$|^pwd$|^pass$|^old_?password$|^new_?password$|^confirm_?password$", re.IGNORECASE), "password"),
    (re.compile(r"^username$|^user_?name$|^login$|^user$", re.IGNORECASE), "username"),
    (re.compile(r"^session$|^session_?id$|^sid$|^jsessionid$", re.IGNORECASE), "session"),
    (re.compile(r"^csrf$|^_?csrf_?token$|^xsrf$|^_token$|^authenticity_token$", re.IGNORECASE), "csrf"),

    # IDs — high-value for IDOR testing
    (re.compile(r"^(?:.*_)?id$|^(?:.*_)?id[sx]?$|^.*Id$|^.*ID$", re.IGNORECASE), "id"),

    # PII
    (re.compile(r"^e?mail$|^email_?address$", re.IGNORECASE), "email"),
    (re.compile(r"^phone$|^mobile$|^tel$|^phone_?number$", re.IGNORECASE), "phone"),
    (re.compile(r"^ssn$|^social_?security$|^tax_?id$|^pan$|^aadhaar$", re.IGNORECASE), "pii"),

    # Dates / times
    (re.compile(r"^date$|^.*_?date$|^.*_?at$|^created$|^updated$|^timestamp$|^time$", re.IGNORECASE), "date"),

    # Numeric
    (re.compile(r"^page$|^page_?num$|^offset$|^skip$|^limit$|^per_?page$|^page_?size$|^count$|^size$", re.IGNORECASE), "pagination"),
    (re.compile(r"^amount$|^price$|^total$|^cost$|^quantity$|^qty$|^balance$|^fee$", re.IGNORECASE), "numeric"),
    (re.compile(r"^lat$|^lng$|^lon$|^latitude$|^longitude$", re.IGNORECASE), "coordinate"),
    (re.compile(r"^port$|^num$|^number$|^index$|^position$|^rank$|^score$", re.IGNORECASE), "integer"),

    # Boolean
    (re.compile(r"^is_|^has_|^can_|^enable|^disable|^active$|^verified$|^admin$|^deleted$|^public$|^private$", re.IGNORECASE), "boolean"),

    # File / path
    (re.compile(r"^file$|^filename$|^file_?name$|^path$|^filepath$|^file_?path$|^attachment$", re.IGNORECASE), "file"),
    (re.compile(r"^url$|^link$|^href$|^redirect$|^redirect_?url$|^return_?url$|^callback$|^next$|^goto$|^continue$|^dest$|^destination$", re.IGNORECASE), "url"),

    # Search / filter
    (re.compile(r"^q$|^query$|^search$|^keyword$|^term$|^filter$|^find$", re.IGNORECASE), "search"),
    (re.compile(r"^sort$|^sort_?by$|^order$|^order_?by$|^direction$|^asc$|^desc$", re.IGNORECASE), "sort"),

    # Content
    (re.compile(r"^name$|^title$|^label$|^display_?name$|^first_?name$|^last_?name$|^full_?name$", re.IGNORECASE), "string"),
    (re.compile(r"^description$|^desc$|^comment$|^body$|^content$|^text$|^message$|^note$|^notes$|^bio$", re.IGNORECASE), "text"),
    (re.compile(r"^type$|^kind$|^category$|^status$|^state$|^role$|^level$|^tier$|^plan$|^mode$|^format$", re.IGNORECASE), "enum"),

    # Encoding / injection vectors
    (re.compile(r"^html$|^xml$|^json$|^data$|^payload$|^input$|^value$|^raw$", re.IGNORECASE), "raw"),
    (re.compile(r"^code$|^script$|^template$|^expression$|^eval$|^exec$|^cmd$|^command$", re.IGNORECASE), "code"),
]

# Input type → param type (from HTML form fields)
_INPUT_TYPE_MAP: dict[str, str] = {
    "email": "email",
    "tel": "phone",
    "number": "integer",
    "date": "date",
    "datetime": "date",
    "datetime-local": "date",
    "time": "date",
    "url": "url",
    "password": "password",
    "hidden": "hidden",
    "file": "file",
    "checkbox": "boolean",
    "radio": "enum",
    "range": "integer",
    "color": "string",
    "search": "search",
}


# ── Security relevance scoring ───────────────────────────────

# Type → base security interest score (0-10)
_TYPE_SECURITY_SCORE: dict[str, int] = {
    "id": 9,          # IDOR prime target
    "uuid": 7,        # IDOR (harder to guess)
    "token": 10,      # Auth bypass
    "password": 10,   # Auth
    "session": 10,    # Session hijack
    "csrf": 8,        # CSRF bypass
    "username": 6,    # Enumeration
    "email": 7,       # Enumeration, PII
    "phone": 6,       # PII
    "pii": 9,         # Sensitive data
    "url": 8,         # SSRF, open redirect
    "file": 8,        # Path traversal, upload
    "code": 9,        # Injection
    "raw": 7,         # XSS, injection
    "search": 6,      # SQLi, XSS
    "text": 5,        # XSS, SQLi
    "pagination": 3,  # Low risk
    "numeric": 4,     # Param tampering
    "boolean": 5,     # Privilege escalation (is_admin)
    "enum": 5,        # Role/privilege escalation
    "sort": 4,        # SQLi in ORDER BY
    "date": 2,        # Low risk
    "string": 3,      # General
    "integer": 3,     # General
    "coordinate": 1,  # Low risk
    "hidden": 5,      # Often contains interesting values
    "unknown": 3,     # Unclassified
}

# Boost for boolean params with privileged names
_PRIVILEGE_NAMES = frozenset({
    "admin", "is_admin", "isadmin", "role", "is_superuser",
    "superuser", "is_staff", "staff", "privileged", "elevated",
    "verified", "is_verified", "approved", "is_approved",
})


# ── Data classes ─────────────────────────────────────────────


@dataclass
class ParamInfo:
    """Metadata about a discovered parameter."""
    name: str
    param_type: str = "unknown"       # inferred type from _NAME_TYPE_RULES
    input_type: str = ""              # HTML input type if from a form
    required: bool = False
    security_score: int = 0           # 0-10, higher = more interesting
    sources: list[str] = field(default_factory=list)  # where discovered
    endpoints: list[str] = field(default_factory=list)  # which endpoints use it
    methods: list[str] = field(default_factory=list)    # HTTP methods seen with it
    sample_values: list[str] = field(default_factory=list)  # observed values


@dataclass
class EndpointParams:
    """Parameters associated with a specific endpoint."""
    url: str
    method: str = "GET"
    params: list[ParamInfo] = field(default_factory=list)
    source: str = ""   # "crawler", "js_extractor", "url"

    @property
    def param_names(self) -> list[str]:
        return [p.name for p in self.params]

    @property
    def high_value_params(self) -> list[ParamInfo]:
        """Params with security score >= 6."""
        return [p for p in self.params if p.security_score >= 6]


@dataclass
class ParamInventory:
    """Complete parameter discovery result."""
    endpoints: list[EndpointParams] = field(default_factory=list)
    global_params: dict[str, ParamInfo] = field(default_factory=dict)  # name → merged info
    total_params: int = 0
    unique_params: int = 0
    high_value_count: int = 0

    @property
    def high_value_params(self) -> list[ParamInfo]:
        """All params with security score >= 6, sorted by score desc."""
        return sorted(
            [p for p in self.global_params.values() if p.security_score >= 6],
            key=lambda p: p.security_score,
            reverse=True,
        )

    @property
    def by_type(self) -> dict[str, list[ParamInfo]]:
        """Group global params by inferred type."""
        groups: dict[str, list[ParamInfo]] = defaultdict(list)
        for p in self.global_params.values():
            groups[p.param_type].append(p)
        return dict(groups)

    def summary(self) -> dict:
        return {
            "endpoints_with_params": len(self.endpoints),
            "total_params": self.total_params,
            "unique_params": self.unique_params,
            "high_value_count": self.high_value_count,
            "types": {t: len(ps) for t, ps in self.by_type.items()},
            "top_params": [
                {"name": p.name, "type": p.param_type, "score": p.security_score}
                for p in self.high_value_params[:10]
            ],
        }


# ── ParamDiscoverer ──────────────────────────────────────────


class ParamDiscoverer:
    """Merges parameter data from recon sources and infers types.

    Collects params from:
      1. Crawler forms (field names + HTML input types)
      2. JS extractor endpoints (param names from fetch/axios calls)
      3. Raw URLs (query string params with sample values)

    Produces a ParamInventory with type inference and security scoring.
    """

    def __init__(self) -> None:
        self._endpoint_params: list[EndpointParams] = []
        self._raw_params: dict[str, ParamInfo] = {}  # name → merged ParamInfo

    # ── Source ingestion ───────────────────────────────────────

    def add_crawl_result(self, result: CrawlResult) -> None:
        """Ingest params from a CrawlResult (forms + page URLs)."""
        for page in result.pages:
            # Extract query params from the page URL itself
            self._ingest_url(page.url, source="crawler")

            # Extract from forms
            for form in page.forms:
                self._ingest_form(form)

    def add_js_result(self, result: JsExtractionResult) -> None:
        """Ingest params from a JsExtractionResult."""
        for ep in result.endpoints:
            params: list[ParamInfo] = []
            for pname in ep.params:
                pi = self._get_or_create_param(pname)
                pi.sources = _add_unique(pi.sources, "js_extractor")
                pi.endpoints = _add_unique(pi.endpoints, ep.path)
                pi.methods = _add_unique(pi.methods, ep.method)
                params.append(pi)

            if params:
                self._endpoint_params.append(EndpointParams(
                    url=ep.path,
                    method=ep.method,
                    params=params,
                    source="js_extractor",
                ))

    def add_url(self, url: str) -> None:
        """Ingest params from a raw URL query string."""
        self._ingest_url(url, source="url")

    def add_params(
        self,
        endpoint: str,
        params: list[str],
        *,
        method: str = "GET",
        source: str = "manual",
    ) -> None:
        """Add manually specified params for an endpoint."""
        param_infos: list[ParamInfo] = []
        for pname in params:
            pi = self._get_or_create_param(pname)
            pi.sources = _add_unique(pi.sources, source)
            pi.endpoints = _add_unique(pi.endpoints, endpoint)
            pi.methods = _add_unique(pi.methods, method)
            param_infos.append(pi)

        if param_infos:
            self._endpoint_params.append(EndpointParams(
                url=endpoint,
                method=method,
                params=param_infos,
                source=source,
            ))

    # ── Build inventory ───────────────────────────────────────

    def build_inventory(self) -> ParamInventory:
        """Compute types, scores, and produce the final ParamInventory."""
        # Infer types for all params
        for pi in self._raw_params.values():
            if pi.param_type == "unknown":
                pi.param_type = self._infer_type(pi)
            pi.security_score = self._compute_score(pi)

        # Update endpoint param references (they share objects with _raw_params)
        total = sum(len(ep.params) for ep in self._endpoint_params)
        high_value = sum(1 for p in self._raw_params.values() if p.security_score >= 6)

        return ParamInventory(
            endpoints=list(self._endpoint_params),
            global_params=dict(self._raw_params),
            total_params=total,
            unique_params=len(self._raw_params),
            high_value_count=high_value,
        )

    # ── Internal helpers ──────────────────────────────────────

    def _ingest_url(self, url: str, source: str = "url") -> None:
        """Extract query params from a URL."""
        parsed = urlparse(url)
        if not parsed.query:
            return

        qs = parse_qs(parsed.query, keep_blank_values=True)
        params: list[ParamInfo] = []
        endpoint = parsed._replace(query="", fragment="").geturl()

        for name, values in qs.items():
            pi = self._get_or_create_param(name)
            pi.sources = _add_unique(pi.sources, source)
            pi.endpoints = _add_unique(pi.endpoints, endpoint)
            pi.methods = _add_unique(pi.methods, "GET")
            for v in values:
                if v and v not in pi.sample_values and len(pi.sample_values) < 5:
                    pi.sample_values.append(v)
            params.append(pi)

        if params:
            self._endpoint_params.append(EndpointParams(
                url=endpoint,
                method="GET",
                params=params,
                source=source,
            ))

    def _ingest_form(self, form: DiscoveredForm) -> None:
        """Extract params from a DiscoveredForm."""
        params: list[ParamInfo] = []
        for ff in form.fields:
            pi = self._get_or_create_param(ff.name)
            pi.sources = _add_unique(pi.sources, "crawler")
            pi.endpoints = _add_unique(pi.endpoints, form.action)
            pi.methods = _add_unique(pi.methods, form.method)
            pi.required = pi.required or ff.required

            # Use HTML input type for type inference if available
            if ff.input_type and ff.input_type != "text":
                pi.input_type = ff.input_type
                mapped = _INPUT_TYPE_MAP.get(ff.input_type)
                if mapped:
                    pi.param_type = mapped

            params.append(pi)

        if params:
            self._endpoint_params.append(EndpointParams(
                url=form.action,
                method=form.method,
                params=params,
                source="crawler",
            ))

    def _get_or_create_param(self, name: str) -> ParamInfo:
        """Get existing or create new ParamInfo by name."""
        if name not in self._raw_params:
            self._raw_params[name] = ParamInfo(name=name)
        return self._raw_params[name]

    @staticmethod
    def _infer_type(pi: ParamInfo) -> str:
        """Infer param type from name patterns."""
        # If already set by HTML input type, keep it
        if pi.param_type != "unknown":
            return pi.param_type

        # Check name against rules
        for pattern, ptype in _NAME_TYPE_RULES:
            if pattern.search(pi.name):
                return ptype

        # Infer from sample values if name didn't match
        if pi.sample_values:
            return _infer_type_from_values(pi.sample_values)

        return "unknown"

    @staticmethod
    def _compute_score(pi: ParamInfo) -> int:
        """Compute security interest score for a param."""
        base = _TYPE_SECURITY_SCORE.get(pi.param_type, 3)

        # Boost for privilege-related boolean params
        if pi.name.lower() in _PRIVILEGE_NAMES:
            base = max(base, 8)

        # Boost if seen in multiple sources (more confidence it's real)
        if len(pi.sources) > 1:
            base = min(base + 1, 10)

        # Boost if used with POST/PUT/DELETE (state-changing)
        if any(m in ("POST", "PUT", "DELETE", "PATCH") for m in pi.methods):
            base = min(base + 1, 10)

        return base


# ── Standalone helpers ────────────────────────────────────────


def _add_unique(lst: list[str], value: str) -> list[str]:
    """Add value to list if not already present. Returns the list."""
    if value not in lst:
        lst.append(value)
    return lst


def _infer_type_from_values(values: list[str]) -> str:
    """Guess param type from observed sample values."""
    for val in values:
        val = val.strip()
        if not val:
            continue
        # UUID pattern
        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", val, re.IGNORECASE):
            return "uuid"
        # Pure integer
        if re.match(r"^-?\d+$", val):
            return "integer"
        # Float
        if re.match(r"^-?\d+\.\d+$", val):
            return "numeric"
        # Email
        if re.match(r"^[^@]+@[^@]+\.[^@]+$", val):
            return "email"
        # URL
        if re.match(r"^https?://", val, re.IGNORECASE):
            return "url"
        # Boolean strings
        if val.lower() in ("true", "false", "0", "1", "yes", "no"):
            return "boolean"
        # Date-ish (ISO format)
        if re.match(r"^\d{4}-\d{2}-\d{2}", val):
            return "date"
    return "string"


def infer_param_type(name: str) -> str:
    """Quick single-param type inference by name. Useful standalone."""
    for pattern, ptype in _NAME_TYPE_RULES:
        if pattern.search(name):
            return ptype
    return "unknown"
