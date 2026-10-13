"""Tests for Phase 8 — Expanded scanners and verifiers (SQLi, XSS, SSRF)."""
import asyncio
import pytest

import httpx

from agent.http import HttpClient, Session
from agent.scope import ALLOWED
from agent.recipes.schema import validate_recipe
from agent.scanners.base import Candidate
from agent.scanners.sqli import SqliScanner, _DB_ERRORS, _ERROR_PAYLOADS
from agent.scanners.xss import XssScanner, _PAYLOADS, _CANARY_PREFIX
from agent.scanners.ssrf import SsrfScanner, _SSRF_TARGETS, _SSRF_SIGNATURES
from agent.verify.sqli import SqliVerifier
from agent.verify.xss import XssVerifier
from agent.verify.ssrf import SsrfVerifier
from agent.verify.base import Verdict


# ── Test domain setup ────────────────────────────────────────

TARGET = "https://target.example.com/api/search"


@pytest.fixture(autouse=True)
def ensure_scope():
    """Ensure test host is in scope."""
    ALLOWED.add("target.example.com")
    yield
    ALLOWED.discard("target.example.com")


# ── Recipes ──────────────────────────────────────────────────

SQLI_RECIPE = validate_recipe({
    "id": "sqli-error-based",
    "applies_to": ["api"],
    "tech_signals": ["rest-api"],
    "preconditions": ["an endpoint accepts user input"],
    "detect": [{"step": "Inject SQL payloads"}],
    "signal": "DB error in response",
    "verify": "Replay and confirm error",
    "severity": "critical",
    "remediation": "Use parameterized queries",
    "source": "CWE-89",
})

XSS_RECIPE = validate_recipe({
    "id": "xss-reflected",
    "applies_to": ["web"],
    "tech_signals": ["rest-api"],
    "preconditions": ["an endpoint reflects user input"],
    "detect": [{"step": "Inject XSS payloads"}],
    "signal": "Unencoded reflection",
    "verify": "Replay and confirm reflection",
    "severity": "high",
    "remediation": "HTML-encode output",
    "source": "CWE-79",
})

SSRF_RECIPE = validate_recipe({
    "id": "ssrf-internal",
    "applies_to": ["api"],
    "tech_signals": ["rest-api"],
    "preconditions": ["an endpoint accepts URL input"],
    "detect": [{"step": "Inject internal URLs"}],
    "signal": "Internal signature in response",
    "verify": "Replay and confirm signature",
    "severity": "high",
    "remediation": "Allowlist destination URLs",
    "source": "CWE-918",
})


# ── Transport factories ──────────────────────────────────────

def sqli_error_transport():
    """Returns DB error when single-quote is in the query."""
    from urllib.parse import unquote
    def handler(request: httpx.Request):
        query = unquote(str(request.url))
        body_text = request.content.decode() if request.content else ""
        if "'" in query or "'" in body_text:
            return httpx.Response(500, text="ERROR: You have an error in your SQL syntax near ''")
        return httpx.Response(200, text="OK")
    return httpx.MockTransport(handler)


def sqli_boolean_transport():
    """Returns different length for true vs false conditions."""
    from urllib.parse import unquote
    def handler(request: httpx.Request):
        query = unquote(str(request.url))
        body_text = request.content.decode() if request.content else ""
        combined = query + body_text
        if "1'='1" in combined or "1=1" in combined:
            return httpx.Response(200, text="A" * 500)  # true: long
        if "1'='2" in combined or "1=2" in combined:
            return httpx.Response(200, text="B" * 100)  # false: short
        return httpx.Response(200, text="C" * 200)  # baseline
    return httpx.MockTransport(handler)


def xss_reflect_transport():
    """Reflects input unencoded in the response body."""
    def handler(request: httpx.Request):
        query = str(request.url)
        # Extract param value from query string
        if "q=" in query:
            val = query.split("q=")[1].split("&")[0]
            from urllib.parse import unquote
            val = unquote(val)
            return httpx.Response(200, text=f"<html><body>Results for: {val}</body></html>")
        return httpx.Response(200, text="<html><body>No results</body></html>")
    return httpx.MockTransport(handler)


def xss_encoded_transport():
    """Reflects input but fully HTML-encodes it (no script markers survive)."""
    import html as html_mod
    def handler(request: httpx.Request):
        query = str(request.url)
        if "q=" in query:
            val = query.split("q=")[1].split("&")[0]
            from urllib.parse import unquote
            val = unquote(val)
            # Full HTML entity encoding — nothing dangerous survives
            val = html_mod.escape(val, quote=True)
            # Also neutralize all XSS markers
            val = val.replace("javascript", "java&#115;cript")
            val = val.replace("alert", "a&#108;ert")
            val = val.replace("onerror", "on&#101;rror")
            val = val.replace("onload", "on&#108;oad")
            return httpx.Response(200, text=f"<html><body>Results for: {val}</body></html>")
        return httpx.Response(200, text="<html><body>No results</body></html>")
    return httpx.MockTransport(handler)


def xss_no_reflect_transport():
    """Does not reflect input at all."""
    def handler(request: httpx.Request):
        return httpx.Response(200, text="<html><body>Static page</body></html>")
    return httpx.MockTransport(handler)


def ssrf_hit_transport():
    """Returns metadata signature when internal URL is sent."""
    from urllib.parse import unquote
    def handler(request: httpx.Request):
        query = unquote(str(request.url))
        body_text = request.content.decode() if request.content else ""
        combined = query + body_text
        if "127.0.0.1" in combined or "169.254.169.254" in combined:
            return httpx.Response(200, text="ami-id: ami-12345\ninstance-id: i-abc\nlocal-ipv4: 10.0.0.1")
        return httpx.Response(200, text="OK - no data")
    return httpx.MockTransport(handler)


def ssrf_no_hit_transport():
    """Always returns the same response regardless of input."""
    def handler(request: httpx.Request):
        return httpx.Response(200, text="OK - no data")
    return httpx.MockTransport(handler)


def ok_transport():
    """Always returns 200 OK with no special content."""
    def handler(request: httpx.Request):
        return httpx.Response(200, text="OK")
    return httpx.MockTransport(handler)


# ── SQLi Scanner Tests ───────────────────────────────────────

class TestSqliScanner:
    def test_error_based_detection(self):
        client = HttpClient(transport=sqli_error_transport())
        session = Session(cookies={"sid": "a"})
        scanner = SqliScanner(client, session)
        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(TARGET, SQLI_RECIPE, params=["q"], method="GET", id_location="query")
        )
        assert len(candidates) >= 1
        c = candidates[0]
        assert c.scanner == "SqliScanner"
        assert c.request_data["technique"] == "error-based"
        assert c.request_data["param"] == "q"

    def test_boolean_based_detection(self):
        client = HttpClient(transport=sqli_boolean_transport())
        session = Session(cookies={"sid": "a"})
        scanner = SqliScanner(client, session)
        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(TARGET, SQLI_RECIPE, params=["q"], method="GET", id_location="query")
        )
        assert len(candidates) >= 1
        c = candidates[0]
        assert c.request_data["technique"] == "boolean-based"

    def test_no_params_returns_empty(self):
        client = HttpClient(transport=ok_transport())
        session = Session(cookies={"sid": "a"})
        scanner = SqliScanner(client, session)
        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(TARGET, SQLI_RECIPE, params=[], method="GET", id_location="query")
        )
        assert candidates == []

    def test_no_sqli_returns_empty(self):
        client = HttpClient(transport=ok_transport())
        session = Session(cookies={"sid": "a"})
        scanner = SqliScanner(client, session)
        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(TARGET, SQLI_RECIPE, params=["q"], method="GET", id_location="query")
        )
        assert candidates == []

    def test_error_probe_body_injection(self):
        client = HttpClient(transport=sqli_error_transport())
        session = Session(cookies={"sid": "a"})
        scanner = SqliScanner(client, session)
        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(TARGET, SQLI_RECIPE, params=["q"], method="POST", id_location="body")
        )
        assert len(candidates) >= 1

    def test_identify_db_mysql(self):
        assert SqliScanner._identify_db("you have an error in your mysql syntax") == "MySQL"

    def test_identify_db_postgres(self):
        assert SqliScanner._identify_db("error: postgresql query failed") == "PostgreSQL"

    def test_identify_db_unknown(self):
        assert SqliScanner._identify_db("some random error") is None

    def test_vuln_classes(self):
        assert "sqli" in SqliScanner.vuln_classes
        assert "sql-injection" in SqliScanner.vuln_classes


# ── XSS Scanner Tests ────────────────────────────────────────

class TestXssScanner:
    def test_reflected_xss_detected(self):
        client = HttpClient(transport=xss_reflect_transport())
        session = Session(cookies={"sid": "a"})
        scanner = XssScanner(client, session)
        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(TARGET, XSS_RECIPE, params=["q"], method="GET", id_location="query")
        )
        assert len(candidates) >= 1
        c = candidates[0]
        assert c.scanner == "XssScanner"
        assert c.response_data["reflected"] is True

    def test_encoded_xss_low_confidence(self):
        client = HttpClient(transport=xss_encoded_transport())
        session = Session(cookies={"sid": "a"})
        scanner = XssScanner(client, session)
        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(TARGET, XSS_RECIPE, params=["q"], method="GET", id_location="query")
        )
        # Should still produce a candidate with low confidence (canary reflected)
        assert len(candidates) >= 1
        c = candidates[0]
        assert c.confidence == "low"

    def test_no_reflection_returns_empty(self):
        client = HttpClient(transport=xss_no_reflect_transport())
        session = Session(cookies={"sid": "a"})
        scanner = XssScanner(client, session)
        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(TARGET, XSS_RECIPE, params=["q"], method="GET", id_location="query")
        )
        assert candidates == []

    def test_no_params_returns_empty(self):
        client = HttpClient(transport=ok_transport())
        session = Session(cookies={"sid": "a"})
        scanner = XssScanner(client, session)
        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(TARGET, XSS_RECIPE, params=[], method="GET", id_location="query")
        )
        assert candidates == []

    def test_is_reflected_unencoded_exact(self):
        assert XssScanner._is_reflected_unencoded("<script>alert(1)</script>", "page <script>alert(1)</script> end")

    def test_is_reflected_unencoded_marker(self):
        assert XssScanner._is_reflected_unencoded("<img src=x onerror=alert(1)>", "onerror=something <img tag")

    def test_is_reflected_unencoded_false(self):
        assert not XssScanner._is_reflected_unencoded("<script>alert(1)</script>", "nothing here")

    def test_make_canary(self):
        canary = XssScanner._make_canary()
        assert canary.startswith(_CANARY_PREFIX)
        assert len(canary) > len(_CANARY_PREFIX)

    def test_vuln_classes(self):
        assert "xss" in XssScanner.vuln_classes
        assert "reflected-xss" in XssScanner.vuln_classes


# ── SSRF Scanner Tests ────────────────────────────────────────

class TestSsrfScanner:
    def test_ssrf_detected(self):
        client = HttpClient(transport=ssrf_hit_transport())
        session = Session(cookies={"sid": "a"})
        scanner = SsrfScanner(client, session)
        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(TARGET, SSRF_RECIPE, params=["url"], method="GET", id_location="query")
        )
        assert len(candidates) >= 1
        c = candidates[0]
        assert c.scanner == "SsrfScanner"

    def test_no_ssrf_returns_empty(self):
        client = HttpClient(transport=ssrf_no_hit_transport())
        session = Session(cookies={"sid": "a"})
        scanner = SsrfScanner(client, session)
        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(TARGET, SSRF_RECIPE, params=["url"], method="GET", id_location="query")
        )
        assert candidates == []

    def test_no_params_returns_empty(self):
        client = HttpClient(transport=ok_transport())
        session = Session(cookies={"sid": "a"})
        scanner = SsrfScanner(client, session)
        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(TARGET, SSRF_RECIPE, params=[], method="GET", id_location="query")
        )
        assert candidates == []

    def test_vuln_classes(self):
        assert "ssrf" in SsrfScanner.vuln_classes

    def test_ssrf_targets_list(self):
        assert any("127.0.0.1" in t for t in _SSRF_TARGETS)
        assert any("169.254.169.254" in t for t in _SSRF_TARGETS)


# ── SQLi Verifier Tests ──────────────────────────────────────

def _make_sqli_candidate(technique="error-based", **overrides):
    defaults = dict(
        recipe_id="sqli-error-based",
        scanner="SqliScanner",
        endpoint=TARGET,
        method="GET",
        evidence={"status": 500, "payload": "'", "error_match": "sql syntax"},
        confidence="high",
        request_data={
            "param": "q",
            "payload": "'",
            "id_location": "query",
            "technique": technique,
        },
        response_data={
            "status": 500,
            "error_match": "sql syntax",
        },
    )
    if technique == "boolean-based":
        defaults["request_data"].update({
            "payload_true": "' OR '1'='1' --",
            "payload_false": "' OR '1'='2' --",
        })
        defaults["response_data"]["length_diff"] = 400
    defaults.update(overrides)
    return Candidate(**defaults)


class TestSqliVerifier:
    def test_error_based_confirmed(self):
        client = HttpClient(transport=sqli_error_transport())
        session = Session(cookies={"sid": "a"})
        verifier = SqliVerifier(client, session)
        candidate = _make_sqli_candidate("error-based")
        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.CONFIRMED
        assert result.replays == 2

    def test_error_based_false_positive(self):
        client = HttpClient(transport=ok_transport())
        session = Session(cookies={"sid": "a"})
        verifier = SqliVerifier(client, session)
        candidate = _make_sqli_candidate("error-based")
        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.FALSE

    def test_boolean_based_confirmed(self):
        client = HttpClient(transport=sqli_boolean_transport())
        session = Session(cookies={"sid": "a"})
        verifier = SqliVerifier(client, session)
        candidate = _make_sqli_candidate("boolean-based")
        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.CONFIRMED

    def test_unknown_technique(self):
        client = HttpClient(transport=ok_transport())
        session = Session(cookies={"sid": "a"})
        verifier = SqliVerifier(client, session)
        candidate = _make_sqli_candidate("time-based")
        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.NEEDS_HUMAN


# ── XSS Verifier Tests ───────────────────────────────────────

def _make_xss_candidate(**overrides):
    defaults = dict(
        recipe_id="xss-reflected",
        scanner="XssScanner",
        endpoint=TARGET,
        method="GET",
        evidence={"status": 200, "payload": "<script>alert(1)</script>", "reflected": True},
        confidence="high",
        request_data={
            "param": "q",
            "payload": "<script>alert(1)</script>",
            "id_location": "query",
        },
        response_data={
            "status": 200,
            "reflected": True,
        },
    )
    defaults.update(overrides)
    return Candidate(**defaults)


class TestXssVerifier:
    def test_confirmed(self):
        client = HttpClient(transport=xss_reflect_transport())
        session = Session(cookies={"sid": "a"})
        verifier = XssVerifier(client, session)
        candidate = _make_xss_candidate()
        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.CONFIRMED
        assert result.replays == 2

    def test_false_positive(self):
        client = HttpClient(transport=xss_no_reflect_transport())
        session = Session(cookies={"sid": "a"})
        verifier = XssVerifier(client, session)
        candidate = _make_xss_candidate()
        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.FALSE

    def test_encoded_false_positive(self):
        client = HttpClient(transport=xss_encoded_transport())
        session = Session(cookies={"sid": "a"})
        verifier = XssVerifier(client, session)
        candidate = _make_xss_candidate()
        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.FALSE


# ── SSRF Verifier Tests ──────────────────────────────────────

def _make_ssrf_candidate(**overrides):
    defaults = dict(
        recipe_id="ssrf-internal",
        scanner="SsrfScanner",
        endpoint=TARGET,
        method="GET",
        evidence={"status": 200, "ssrf_url": "http://127.0.0.1", "signature_match": "ami-id"},
        confidence="high",
        request_data={
            "param": "url",
            "ssrf_url": "http://127.0.0.1",
            "id_location": "query",
        },
        response_data={
            "status": 200,
            "signature_match": "ami-id",
        },
    )
    defaults.update(overrides)
    return Candidate(**defaults)


class TestSsrfVerifier:
    def test_confirmed(self):
        client = HttpClient(transport=ssrf_hit_transport())
        session = Session(cookies={"sid": "a"})
        verifier = SsrfVerifier(client, session)
        candidate = _make_ssrf_candidate()
        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.CONFIRMED
        assert result.replays == 2

    def test_false_positive(self):
        client = HttpClient(transport=ssrf_no_hit_transport())
        session = Session(cookies={"sid": "a"})
        verifier = SsrfVerifier(client, session)
        candidate = _make_ssrf_candidate()
        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.FALSE

    def test_signature_in_baseline_is_false(self):
        """If the signature appears in baseline too, it's a false positive."""
        # Transport that always returns the signature
        def handler(request: httpx.Request):
            return httpx.Response(200, text="ami-id: ami-12345 always here")
        client = HttpClient(transport=httpx.MockTransport(handler))
        session = Session(cookies={"sid": "a"})
        verifier = SsrfVerifier(client, session)
        candidate = _make_ssrf_candidate()
        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.FALSE


# ── Recipe YAML Tests ────────────────────────────────────────

class TestRecipeFiles:
    def test_sqli_recipe_loads(self):
        from agent.recipes.loader import load_recipes
        recipes = load_recipes()
        sqli = [r for r in recipes.recipes if r.id == "sqli-error-based"]
        assert len(sqli) == 1
        assert sqli[0].severity == "critical"
        assert "CWE-89" in sqli[0].source

    def test_xss_recipe_loads(self):
        from agent.recipes.loader import load_recipes
        recipes = load_recipes()
        xss = [r for r in recipes.recipes if r.id == "xss-reflected"]
        assert len(xss) == 1
        assert xss[0].severity == "high"

    def test_ssrf_recipe_loads(self):
        from agent.recipes.loader import load_recipes
        recipes = load_recipes()
        ssrf = [r for r in recipes.recipes if r.id == "ssrf-internal"]
        assert len(ssrf) == 1
        assert ssrf[0].severity == "high"


# ── Orchestrator registration Tests ──────────────────────────

class TestOrchestratorRegistration:
    def test_sqli_scanner_registered(self):
        from agent.orchestrator import ScannerRegistry
        from agent.scanners.sqli import SqliScanner
        reg = ScannerRegistry()
        reg.register("sqli", SqliScanner)
        assert reg.get("sqli") is SqliScanner

    def test_xss_scanner_registered(self):
        from agent.orchestrator import ScannerRegistry
        from agent.scanners.xss import XssScanner
        reg = ScannerRegistry()
        reg.register("xss", XssScanner)
        assert reg.get("xss") is XssScanner

    def test_ssrf_scanner_registered(self):
        from agent.orchestrator import ScannerRegistry
        from agent.scanners.ssrf import SsrfScanner
        reg = ScannerRegistry()
        reg.register("ssrf", SsrfScanner)
        assert reg.get("ssrf") is SsrfScanner
