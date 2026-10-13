"""Tests for Phase 5 — Scanner + Verifier (IDOR end-to-end)."""
import asyncio
import json
import pytest

import httpx

from agent.http import HttpClient, Session
from agent.scope import ALLOWED
from agent.recipes.schema import validate_recipe
from agent.scanners.base import Scanner, Candidate
from agent.scanners.idor import IdorScanner
from agent.verify.base import Verifier, Verdict, VerifyResult
from agent.verify.idor import IdorVerifier


# ── Fixtures ──────────────────────────────────────────────────

IDOR_RECIPE = validate_recipe({
    "id": "idor-otp-trigger",
    "applies_to": ["api", "web"],
    "tech_signals": ["rest-api", "session-cookie"],
    "preconditions": ["two authenticated sessions are available"],
    "detect": [
        {"step": "Identify the OTP-trigger endpoint"},
        {"step": "As session A, call the endpoint for a foreign id", "method": "POST"},
    ],
    "signal": "The endpoint returns success for an id the session does not own",
    "verify": "Replay the request and confirm status indicates OTP was issued",
    "severity": "high",
    "remediation": "Add object-level authorization check",
    "source": "CWE-639",
})


def make_mock_transport(status=200, body=None):
    """Create an httpx MockTransport that returns a fixed response."""
    if body is None:
        body = {"status": "success", "message": "OTP sent"}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


def make_failing_transport(status=403, body=None):
    """Transport that returns an authorization failure."""
    if body is None:
        body = {"error": "Unauthorized", "message": "Access denied"}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


def make_flaky_transport(success_count=1, total=3):
    """Transport that succeeds some times and fails others."""
    call_counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_counter["n"] += 1
        if call_counter["n"] <= success_count:
            return httpx.Response(200, json={"status": "success"})
        return httpx.Response(403, json={"error": "Forbidden"})

    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def ensure_scope():
    """Ensure test host is in scope."""
    ALLOWED.add("target.example.com")
    yield
    ALLOWED.discard("target.example.com")


@pytest.fixture
def attacker_session():
    return Session(jsessionid="ATTACKER_SESSION_123")


@pytest.fixture
def victim_session():
    return Session(jsessionid="VICTIM_SESSION_456")


# ── Candidate dataclass tests ────────────────────────────────

class TestCandidate:
    def test_candidate_fields(self):
        c = Candidate(
            recipe_id="idor-otp-trigger",
            scanner="IdorScanner",
            endpoint="https://target.example.com/api/sendOTP",
            method="POST",
            evidence={"status": 200},
            confidence="high",
        )
        assert c.recipe_id == "idor-otp-trigger"
        assert c.scanner == "IdorScanner"
        assert c.confidence == "high"
        assert c.timestamp  # auto-populated

    def test_candidate_has_request_response_data(self):
        c = Candidate(
            recipe_id="test",
            scanner="Test",
            endpoint="https://target.example.com/test",
            method="GET",
            evidence={},
            confidence="low",
            request_data={"param": "value"},
            response_data={"status": 200},
        )
        assert c.request_data == {"param": "value"}
        assert c.response_data == {"status": 200}


# ── IDOR Scanner tests ───────────────────────────────────────

class TestIdorScanner:
    def test_detect_finds_idor(self, attacker_session, victim_session, tmp_path):
        transport = make_mock_transport(200, {"status": "success", "message": "OTP sent"})
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        scanner = IdorScanner(client, attacker_session, victim_session)

        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(
                "https://target.example.com/api/sendOTP",
                IDOR_RECIPE,
                victim_ids=["victim_user_123", "victim_user_456"],
                id_param="mobileNo",
                id_location="body",
            )
        )
        assert len(candidates) == 2
        assert all(c.recipe_id == "idor-otp-trigger" for c in candidates)
        assert all(c.scanner == "IdorScanner" for c in candidates)

    def test_detect_no_candidates_on_403(self, attacker_session, victim_session, tmp_path):
        transport = make_failing_transport(403)
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        scanner = IdorScanner(client, attacker_session, victim_session)

        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(
                "https://target.example.com/api/sendOTP",
                IDOR_RECIPE,
                victim_ids=["victim_123"],
                id_param="mobileNo",
            )
        )
        assert len(candidates) == 0

    def test_detect_empty_victim_ids(self, attacker_session, victim_session, tmp_path):
        transport = make_mock_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        scanner = IdorScanner(client, attacker_session, victim_session)

        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(
                "https://target.example.com/api/sendOTP",
                IDOR_RECIPE,
                victim_ids=[],
                id_param="mobileNo",
            )
        )
        assert len(candidates) == 0

    def test_detect_query_param(self, attacker_session, victim_session, tmp_path):
        transport = make_mock_transport(200, {"data": "sensitive"})
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        scanner = IdorScanner(client, attacker_session, victim_session)

        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(
                "https://target.example.com/api/user",
                IDOR_RECIPE,
                victim_ids=["42"],
                id_param="userId",
                id_location="query",
            )
        )
        assert len(candidates) == 1

    def test_detect_path_param(self, attacker_session, victim_session, tmp_path):
        transport = make_mock_transport(200, {"profile": "victim"})
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        scanner = IdorScanner(client, attacker_session, victim_session)

        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(
                "https://target.example.com/api/users",
                IDOR_RECIPE,
                victim_ids=["42"],
                id_param="id",
                id_location="path",
            )
        )
        assert len(candidates) == 1

    def test_confidence_high_with_multiple_ids(self, attacker_session, victim_session, tmp_path):
        transport = make_mock_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        scanner = IdorScanner(client, attacker_session, victim_session)

        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(
                "https://target.example.com/api/sendOTP",
                IDOR_RECIPE,
                victim_ids=["v1", "v2", "v3"],
                id_param="mobileNo",
            )
        )
        assert all(c.confidence == "high" for c in candidates)

    def test_request_data_recorded(self, attacker_session, victim_session, tmp_path):
        transport = make_mock_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        scanner = IdorScanner(client, attacker_session, victim_session)

        candidates = asyncio.get_event_loop().run_until_complete(
            scanner.detect(
                "https://target.example.com/api/sendOTP",
                IDOR_RECIPE,
                victim_ids=["victim_123"],
                id_param="mobileNo",
            )
        )
        assert candidates[0].request_data["id_param"] == "mobileNo"
        assert candidates[0].request_data["id_value"] == "victim_123"
        assert candidates[0].request_data["session"] == "attacker"


# ── Verdict enum tests ───────────────────────────────────────

class TestVerdict:
    def test_verdict_values(self):
        assert Verdict.CONFIRMED == "CONFIRMED"
        assert Verdict.FALSE == "FALSE"
        assert Verdict.NEEDS_HUMAN == "NEEDS_HUMAN"


# ── IDOR Verifier tests ──────────────────────────────────────

class TestIdorVerifier:
    def _make_candidate(self, endpoint="https://target.example.com/api/sendOTP"):
        return Candidate(
            recipe_id="idor-otp-trigger",
            scanner="IdorScanner",
            endpoint=endpoint,
            method="POST",
            evidence={"status": 200, "victim_id": "victim_123"},
            confidence="high",
            request_data={
                "id_param": "mobileNo",
                "id_value": "victim_123",
                "id_location": "body",
                "session": "attacker",
            },
            response_data={"status": 200},
        )

    def test_verify_confirmed(self, attacker_session, tmp_path):
        transport = make_mock_transport(200, {"status": "success"})
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        verifier = IdorVerifier(client, attacker_session)
        candidate = self._make_candidate()

        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.CONFIRMED
        assert result.replays == 2
        assert result.evidence["successes"] == 2

    def test_verify_false_positive(self, attacker_session, tmp_path):
        transport = make_failing_transport(403)
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        verifier = IdorVerifier(client, attacker_session)
        candidate = self._make_candidate()

        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.FALSE
        assert result.evidence["successes"] == 0

    def test_verify_needs_human_on_flaky(self, attacker_session, tmp_path):
        transport = make_flaky_transport(success_count=1, total=2)
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        verifier = IdorVerifier(client, attacker_session)
        candidate = self._make_candidate()

        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.NEEDS_HUMAN

    def test_verify_minimum_replays(self, attacker_session, tmp_path):
        transport = make_mock_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        verifier = IdorVerifier(client, attacker_session)
        candidate = self._make_candidate()

        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=1)  # should be bumped to 2
        )
        assert result.replays == 2

    def test_verify_query_location(self, attacker_session, tmp_path):
        transport = make_mock_transport(200, {"data": "exposed"})
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        verifier = IdorVerifier(client, attacker_session)
        candidate = Candidate(
            recipe_id="idor-otp-trigger",
            scanner="IdorScanner",
            endpoint="https://target.example.com/api/user",
            method="GET",
            evidence={"status": 200},
            confidence="medium",
            request_data={
                "id_param": "userId",
                "id_value": "42",
                "id_location": "query",
            },
        )

        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.CONFIRMED

    def test_verify_detects_authz_fail_in_200_body(self, attacker_session, tmp_path):
        """A 200 response whose body says 'Access denied' should not count as success."""
        transport = make_mock_transport(200, {"error": "Access denied"})
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        verifier = IdorVerifier(client, attacker_session)
        candidate = self._make_candidate()

        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert result.verdict == Verdict.FALSE

    def test_verify_result_has_reason(self, attacker_session, tmp_path):
        transport = make_mock_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        verifier = IdorVerifier(client, attacker_session)
        candidate = self._make_candidate()

        result = asyncio.get_event_loop().run_until_complete(
            verifier.verify(candidate, replays=2)
        )
        assert "IDOR confirmed" in result.reason
        assert result.timestamp
