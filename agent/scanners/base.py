"""Scanner base class.

A scanner takes a target context + a recipe and produces candidate findings.
Each candidate is unverified — it goes to a Verifier before anything is
reported. Scanners are async (they make HTTP requests via agent.http).

Subclasses implement `_detect()` which does the actual probing.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse, urlencode

from ..http import HttpClient, Session
from ..recipes.schema import Recipe


@dataclass
class Candidate:
    """An unverified finding produced by a scanner.

    This is NOT a confirmed vulnerability — it must pass through a Verifier.
    """
    recipe_id: str
    scanner: str           # scanner class name
    endpoint: str          # full URL that was tested
    method: str            # HTTP method used
    evidence: dict         # scanner-specific evidence (status codes, response snippets, etc.)
    confidence: str        # high / medium / low — scanner's own assessment
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    request_data: dict = field(default_factory=dict)   # what was sent (for replay)
    response_data: dict = field(default_factory=dict)  # what came back


class Scanner(abc.ABC):
    """Base class for vulnerability scanners.

    Each scanner corresponds to one or more vuln classes (e.g. IDOR, XXE).
    The scanner reads the recipe's `detect` steps and executes them against
    the target.

    Usage:
        scanner = IdorScanner(client, attacker_session, victim_session)
        candidates = await scanner.detect(target_url, recipe)
    """

    #: Vuln classes this scanner handles (e.g. ["idor", "bola"])
    vuln_classes: list[str] = []

    def __init__(self, client: HttpClient, **kwargs: Any):
        self.client = client

    async def detect(self, target: str, recipe: Recipe,
                     **context: Any) -> list[Candidate]:
        """Run detection against a target using a recipe.

        Args:
            target: base URL or specific endpoint
            recipe: the Recipe object guiding detection
            **context: scanner-specific context (sessions, params, etc.)

        Returns:
            List of Candidate findings (unverified).
        """
        return await self._detect(target, recipe, **context)

    @abc.abstractmethod
    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        """Subclasses implement the actual detection logic."""
        ...

    def _make_candidate(self, recipe: Recipe, endpoint: str, method: str,
                        evidence: dict, confidence: str,
                        request_data: dict | None = None,
                        response_data: dict | None = None) -> Candidate:
        """Helper to create a Candidate with consistent fields."""
        return Candidate(
            recipe_id=recipe.id,
            scanner=self.__class__.__name__,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            confidence=confidence,
            request_data=request_data or {},
            response_data=response_data or {},
        )

    @staticmethod
    def capture_request(resp) -> str:
        """Build an exact HTTP request string from an httpx Response."""
        try:
            req = resp.request
            parsed = urlparse(str(req.url))
            path_qs = parsed.path or "/"
            if parsed.query:
                path_qs += "?" + parsed.query
            lines = [f"{req.method} {path_qs} HTTP/1.1"]
            lines.append(f"Host: {parsed.hostname}")
            for name, value in req.headers.items():
                if name.lower() not in ("host", "transfer-encoding"):
                    lines.append(f"{name}: {value}")
            body = ""
            if req.content:
                body = req.content.decode("utf-8", errors="replace")
            if body:
                lines.append("")
                lines.append(body[:2000])
            return "\n".join(lines)
        except Exception:
            return ""

    @staticmethod
    def capture_response(resp) -> str:
        """Build an exact HTTP response string from an httpx Response."""
        try:
            lines = [f"HTTP/1.1 {resp.status_code}"]
            for name, value in resp.headers.items():
                if name.lower() in ("content-type", "content-length",
                                    "content-security-policy", "x-xss-protection",
                                    "set-cookie", "server", "location",
                                    "x-frame-options", "x-content-type-options"):
                    lines.append(f"{name}: {value}")
            body = resp.text[:2000]
            if len(resp.text) > 2000:
                body += "\n[... truncated ...]"
            lines.append("")
            lines.append(body)
            return "\n".join(lines)
        except Exception:
            return ""
