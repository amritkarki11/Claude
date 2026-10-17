"""Benchmark harness — precision / recall scorecard.

Runs every scanner + verifier against a set of intentionally-vulnerable and
intentionally-safe mock scenarios, then computes a scorecard:

  - True Positive  (TP): scanner+verifier CONFIRMED a real vuln
  - True Negative  (TN): scanner produced no candidate on a safe endpoint
  - False Positive (FP): scanner+verifier CONFIRMED on a safe endpoint
  - False Negative (FN): scanner missed a real vuln (no candidate produced)

From these:
  Precision = TP / (TP + FP)      — "of what we report, how much is real"
  Recall    = TP / (TP + FN)      — "of what's real, how much do we catch"
  F1        = 2·P·R / (P + R)

Usage:
    runner = BenchmarkRunner()
    card = await runner.run()
    print(card.to_markdown())
"""
from __future__ import annotations

import html
import json
import pathlib
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import unquote

import httpx

from .http import HttpClient, Session
from .recipes.schema import Recipe
from .scope import ALLOWED
from .scanners.base import Scanner, Candidate
from .scanners.idor import IdorScanner
from .scanners.sqli import SqliScanner
from .scanners.xss import XssScanner
from .scanners.ssrf import SsrfScanner
from .verify.base import Verifier, Verdict, VerifyResult
from .verify.idor import IdorVerifier
from .verify.sqli import SqliVerifier
from .verify.xss import XssVerifier
from .verify.ssrf import SsrfVerifier

_TARGET = "https://target.example.com"
_RECIPE_DIR = pathlib.Path(__file__).parent / "recipes"


# ── Scenario model ──────────────────────────────────────────────


@dataclass
class Scenario:
    """One benchmark test case: a mock endpoint + expected outcome."""
    name: str
    vuln_class: str                    # idor | sqli | xss | ssrf
    is_vulnerable: bool                # True → should be caught (TP expected)
    transport: httpx.AsyncBaseTransport
    recipe: Recipe
    # Scanner/verifier context
    endpoint: str = f"{_TARGET}/api/resource"
    method: str = "GET"
    params: list[str] = field(default_factory=lambda: ["id"])
    id_location: str = "query"
    # IDOR-specific
    victim_ids: list[str] = field(default_factory=list)


@dataclass
class ScenarioResult:
    """Outcome of running one scenario."""
    scenario: Scenario
    candidates_found: int
    verdict: Verdict | None            # None if scanner found nothing
    classification: str                # TP / TN / FP / FN
    details: str = ""


@dataclass
class ScoreCard:
    """Aggregated precision / recall / F1 metrics."""
    results: list[ScenarioResult] = field(default_factory=list)

    # Per-class breakdown
    per_class: dict[str, dict[str, int]] = field(default_factory=dict)

    # Totals
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def compute(self) -> None:
        """Recompute totals and per-class breakdown from results."""
        self.tp = self.tn = self.fp = self.fn = 0
        self.per_class = {}

        for sr in self.results:
            cls = sr.scenario.vuln_class
            if cls not in self.per_class:
                self.per_class[cls] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}

            c = sr.classification
            if c == "TP":
                self.tp += 1
                self.per_class[cls]["tp"] += 1
            elif c == "TN":
                self.tn += 1
                self.per_class[cls]["tn"] += 1
            elif c == "FP":
                self.fp += 1
                self.per_class[cls]["fp"] += 1
            elif c == "FN":
                self.fn += 1
                self.per_class[cls]["fn"] += 1

    def to_dict(self) -> dict:
        return {
            "totals": {
                "tp": self.tp, "tn": self.tn,
                "fp": self.fp, "fn": self.fn,
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1": round(self.f1, 4),
            },
            "per_class": self.per_class,
            "scenarios": [
                {
                    "name": r.scenario.name,
                    "vuln_class": r.scenario.vuln_class,
                    "is_vulnerable": r.scenario.is_vulnerable,
                    "candidates": r.candidates_found,
                    "verdict": r.verdict.value if r.verdict else None,
                    "classification": r.classification,
                    "details": r.details,
                }
                for r in self.results
            ],
        }

    def to_markdown(self) -> str:
        lines = ["# Benchmark Scorecard", ""]

        # Overall
        lines.append("## Overall")
        lines.append(f"| Metric    | Value |")
        lines.append(f"|-----------|-------|")
        lines.append(f"| TP        | {self.tp}     |")
        lines.append(f"| TN        | {self.tn}     |")
        lines.append(f"| FP        | {self.fp}     |")
        lines.append(f"| FN        | {self.fn}     |")
        lines.append(f"| Precision | {self.precision:.2%} |")
        lines.append(f"| Recall    | {self.recall:.2%} |")
        lines.append(f"| F1        | {self.f1:.2%} |")
        lines.append("")

        # Per class
        lines.append("## Per Vuln Class")
        lines.append("| Class | TP | TN | FP | FN |")
        lines.append("|-------|----|----|----|----|")
        for cls, counts in sorted(self.per_class.items()):
            lines.append(
                f"| {cls} | {counts['tp']} | {counts['tn']} "
                f"| {counts['fp']} | {counts['fn']} |"
            )
        lines.append("")

        # Scenario details
        lines.append("## Scenario Details")
        lines.append("| Scenario | Class | Expected | Verdict | Result |")
        lines.append("|----------|-------|----------|---------|--------|")
        for r in self.results:
            exp = "VULN" if r.scenario.is_vulnerable else "SAFE"
            v = r.verdict.value if r.verdict else "—"
            lines.append(
                f"| {r.scenario.name} | {r.scenario.vuln_class} "
                f"| {exp} | {v} | {r.classification} |"
            )

        return "\n".join(lines)


# ── Mock transports (simulated endpoints) ──────────────────────


def _sqli_error_vuln_transport() -> httpx.AsyncBaseTransport:
    """Endpoint vulnerable to error-based SQLi."""
    async def handler(request: httpx.Request) -> httpx.Response:
        url = unquote(str(request.url))
        if "'" in url or "'" in (request.content or b"").decode(errors="ignore"):
            body = '{"error": "You have an error in your SQL syntax near \'\\\'\'", "code": 500}'
            return httpx.Response(500, text=body)
        return httpx.Response(200, text='{"data": []}')
    return httpx.MockTransport(handler)


def _sqli_boolean_vuln_transport() -> httpx.AsyncBaseTransport:
    """Endpoint vulnerable to boolean-based SQLi."""
    async def handler(request: httpx.Request) -> httpx.Response:
        url = unquote(str(request.url))
        body_text = (request.content or b"").decode(errors="ignore")
        combined = url + body_text
        if "1'='1" in combined or "1=1" in combined:
            return httpx.Response(200, text='{"data": ' + "x" * 200 + '}')
        if "1'='2" in combined or "1=2" in combined:
            return httpx.Response(200, text='{"data": []}')
        return httpx.Response(200, text='{"data": "baseline"}')
    return httpx.MockTransport(handler)


def _sqli_safe_transport() -> httpx.AsyncBaseTransport:
    """Endpoint NOT vulnerable to SQLi — parameterized queries."""
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text='{"data": [{"id": 1}]}')
    return httpx.MockTransport(handler)


def _xss_vuln_transport() -> httpx.AsyncBaseTransport:
    """Endpoint vulnerable to reflected XSS — no encoding."""
    async def handler(request: httpx.Request) -> httpx.Response:
        url = unquote(str(request.url))
        # Extract q= param value
        if "q=" in url:
            val = url.split("q=", 1)[1].split("&")[0]
            body = f"<html><body>Results for: {val}</body></html>"
            return httpx.Response(200, text=body)
        return httpx.Response(200, text="<html><body>No query</body></html>")
    return httpx.MockTransport(handler)


def _xss_safe_transport() -> httpx.AsyncBaseTransport:
    """Endpoint NOT vulnerable to XSS — HTML-encodes output."""
    async def handler(request: httpx.Request) -> httpx.Response:
        url = unquote(str(request.url))
        if "q=" in url:
            val = url.split("q=", 1)[1].split("&")[0]
            safe_val = html.escape(val)
            # Also neutralize event handlers and js URIs
            safe_val = (safe_val
                        .replace("javascript", "java&#115;cript")
                        .replace("alert", "a&#108;ert")
                        .replace("onerror", "on&#101;rror")
                        .replace("onload", "on&#108;oad"))
            body = f"<html><body>Results for: {safe_val}</body></html>"
            return httpx.Response(200, text=body)
        return httpx.Response(200, text="<html><body>No query</body></html>")
    return httpx.MockTransport(handler)


def _ssrf_vuln_transport() -> httpx.AsyncBaseTransport:
    """Endpoint vulnerable to SSRF — fetches user-supplied URLs."""
    async def handler(request: httpx.Request) -> httpx.Response:
        url = unquote(str(request.url))
        body_text = (request.content or b"").decode(errors="ignore")
        combined = url + body_text
        if "169.254.169.254" in combined:
            return httpx.Response(200, text='ami-id: ami-12345\ninstance-id: i-abcdef')
        if "127.0.0.1" in combined or "localhost" in combined:
            return httpx.Response(200, text='<html><title>Internal Admin</title></html>')
        return httpx.Response(200, text='{"status": "ok"}')
    return httpx.MockTransport(handler)


def _ssrf_safe_transport() -> httpx.AsyncBaseTransport:
    """Endpoint NOT vulnerable to SSRF — validates/blocks internal URLs."""
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text='{"status": "ok", "fetched": true}')
    return httpx.MockTransport(handler)


def _idor_vuln_transport() -> httpx.AsyncBaseTransport:
    """Endpoint vulnerable to IDOR — returns any user's data."""
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text='{"user_id": "victim-42", "data": "secret"}')
    return httpx.MockTransport(handler)


def _idor_safe_transport() -> httpx.AsyncBaseTransport:
    """Endpoint NOT vulnerable to IDOR — enforces ownership."""
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text='{"error": "access denied"}')
    return httpx.MockTransport(handler)


# ── Built-in scenario set ──────────────────────────────────────


def _load_recipe(recipe_id: str) -> Recipe:
    """Load a recipe from the recipes directory."""
    from .recipes.loader import load_recipes
    result = load_recipes(str(_RECIPE_DIR))
    for r in result.recipes:
        if r.id == recipe_id:
            return r
    # Fallback: minimal recipe for benchmarking
    return Recipe(
        id=recipe_id,
        applies_to=["api"],
        detect=[],
        signal="",
        verify="",
        severity="medium",
    )


def default_scenarios() -> list[Scenario]:
    """Return the built-in benchmark scenario set."""
    sqli_recipe = _load_recipe("sqli-error-based")
    xss_recipe = _load_recipe("xss-reflected")
    ssrf_recipe = _load_recipe("ssrf-internal")
    idor_recipe = _load_recipe("idor-otp-trigger")

    return [
        # ── SQLi ──
        Scenario(
            name="sqli-error-vuln",
            vuln_class="sqli",
            is_vulnerable=True,
            transport=_sqli_error_vuln_transport(),
            recipe=sqli_recipe,
            params=["id"],
        ),
        Scenario(
            name="sqli-boolean-vuln",
            vuln_class="sqli",
            is_vulnerable=True,
            transport=_sqli_boolean_vuln_transport(),
            recipe=sqli_recipe,
            params=["id"],
        ),
        Scenario(
            name="sqli-safe",
            vuln_class="sqli",
            is_vulnerable=False,
            transport=_sqli_safe_transport(),
            recipe=sqli_recipe,
            params=["id"],
        ),

        # ── XSS ──
        Scenario(
            name="xss-reflected-vuln",
            vuln_class="xss",
            is_vulnerable=True,
            transport=_xss_vuln_transport(),
            recipe=xss_recipe,
            params=["q"],
        ),
        Scenario(
            name="xss-encoded-safe",
            vuln_class="xss",
            is_vulnerable=False,
            transport=_xss_safe_transport(),
            recipe=xss_recipe,
            params=["q"],
        ),

        # ── SSRF ──
        Scenario(
            name="ssrf-metadata-vuln",
            vuln_class="ssrf",
            is_vulnerable=True,
            transport=_ssrf_vuln_transport(),
            recipe=ssrf_recipe,
            params=["url"],
        ),
        Scenario(
            name="ssrf-blocked-safe",
            vuln_class="ssrf",
            is_vulnerable=False,
            transport=_ssrf_safe_transport(),
            recipe=ssrf_recipe,
            params=["url"],
        ),

        # ── IDOR ──
        Scenario(
            name="idor-access-vuln",
            vuln_class="idor",
            is_vulnerable=True,
            transport=_idor_vuln_transport(),
            recipe=idor_recipe,
            endpoint=f"{_TARGET}/api/users",
            method="POST",
            params=["user_id"],
            id_location="body",
            victim_ids=["victim-42"],
        ),
        Scenario(
            name="idor-denied-safe",
            vuln_class="idor",
            is_vulnerable=False,
            transport=_idor_safe_transport(),
            recipe=idor_recipe,
            endpoint=f"{_TARGET}/api/users",
            method="POST",
            params=["user_id"],
            id_location="body",
            victim_ids=["victim-42"],
        ),
    ]


# ── Benchmark runner ───────────────────────────────────────────


class BenchmarkRunner:
    """Runs scenarios through scanner → verifier and produces a ScoreCard."""

    def __init__(
        self,
        scenarios: list[Scenario] | None = None,
        verify_replays: int = 2,
    ):
        self.scenarios = scenarios or default_scenarios()
        self.verify_replays = verify_replays

    async def run(self) -> ScoreCard:
        """Execute all scenarios and return the scorecard."""
        card = ScoreCard()

        ALLOWED.add("target.example.com")
        try:
            for scenario in self.scenarios:
                result = await self._run_one(scenario)
                card.results.append(result)
        finally:
            ALLOWED.discard("target.example.com")

        card.compute()
        return card

    async def _run_one(self, scenario: Scenario) -> ScenarioResult:
        """Run a single scenario through scanner + verifier."""
        log_path = pathlib.Path("/dev/null")
        client = HttpClient(transport=scenario.transport, log_path=log_path)
        session = Session(cookies={"sid": "bench"})

        try:
            # Build scanner
            scanner = self._build_scanner(scenario, client, session)
            if scanner is None:
                return ScenarioResult(
                    scenario=scenario,
                    candidates_found=0,
                    verdict=None,
                    classification="FN" if scenario.is_vulnerable else "TN",
                    details="No scanner available for vuln class",
                )

            # Run scanner
            candidates = await scanner.detect(
                scenario.endpoint,
                scenario.recipe,
                victim_ids=scenario.victim_ids,
                id_param=scenario.params[0] if scenario.params else "id",
                id_location=scenario.id_location,
                params=scenario.params,
                method=scenario.method,
            )

            if not candidates:
                return ScenarioResult(
                    scenario=scenario,
                    candidates_found=0,
                    verdict=None,
                    classification="FN" if scenario.is_vulnerable else "TN",
                    details="Scanner found no candidates",
                )

            # Run verifier on first candidate
            candidate = candidates[0]
            verifier = self._build_verifier(scenario, client, session)
            if verifier is None:
                # Scanner found something but no verifier — count candidates
                return ScenarioResult(
                    scenario=scenario,
                    candidates_found=len(candidates),
                    verdict=None,
                    classification="FN" if scenario.is_vulnerable else "TN",
                    details="No verifier available",
                )

            vresult = await verifier.verify(candidate, replays=self.verify_replays)

            # Classify outcome
            classification = self._classify(
                scenario.is_vulnerable, vresult.verdict
            )

            return ScenarioResult(
                scenario=scenario,
                candidates_found=len(candidates),
                verdict=vresult.verdict,
                classification=classification,
                details=vresult.reason,
            )
        finally:
            await client.aclose()

    def _build_scanner(self, scenario: Scenario,
                       client: HttpClient, session: Session) -> Scanner | None:
        vc = scenario.vuln_class
        if vc in ("idor", "bola"):
            victim = Session(cookies={"sid": "victim"})
            return IdorScanner(client, session, victim)
        if vc in ("sqli", "sql-injection"):
            return SqliScanner(client, session)
        if vc in ("xss", "reflected-xss"):
            return XssScanner(client, session)
        if vc in ("ssrf",):
            return SsrfScanner(client, session)
        return None

    def _build_verifier(self, scenario: Scenario,
                        client: HttpClient, session: Session) -> Verifier | None:
        vc = scenario.vuln_class
        if vc in ("idor", "bola"):
            return IdorVerifier(client, session)
        if vc in ("sqli", "sql-injection"):
            return SqliVerifier(client, session)
        if vc in ("xss", "reflected-xss"):
            return XssVerifier(client, session)
        if vc in ("ssrf",):
            return SsrfVerifier(client, session)
        return None

    @staticmethod
    def _classify(is_vulnerable: bool, verdict: Verdict) -> str:
        """Map (expected, actual) to TP/TN/FP/FN."""
        if is_vulnerable:
            if verdict == Verdict.CONFIRMED:
                return "TP"
            else:
                return "FN"  # missed real vuln
        else:
            if verdict == Verdict.CONFIRMED:
                return "FP"  # false alarm
            else:
                return "TN"  # correctly ignored

    def write_report(self, card: ScoreCard,
                     output_dir: pathlib.Path | str = "outputs") -> pathlib.Path:
        """Write scorecard to JSON + Markdown files."""
        out = pathlib.Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        json_path = out / "benchmark_scorecard.json"
        md_path = out / "benchmark_scorecard.md"

        with json_path.open("w", encoding="utf-8") as f:
            json.dump(card.to_dict(), f, indent=2)

        with md_path.open("w", encoding="utf-8") as f:
            f.write(card.to_markdown())

        return md_path
