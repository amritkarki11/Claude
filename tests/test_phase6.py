"""Tests for Phase 6 — Orchestrator (end-to-end loop)."""
import asyncio
import json
import pytest

import httpx

from agent.http import HttpClient, Session
from agent.scope import ALLOWED, ScopeError
from agent.recipes.schema import validate_recipe
from agent.scanners.base import Candidate
from agent.verify.base import Verdict
from agent.orchestrator import (
    EndpointInfo,
    TargetState,
    HumanQueue,
    ScannerRegistry,
    Orchestrator,
    OrchestratorConfig,
)
from agent.scanners.idor import IdorScanner


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


def make_success_transport():
    """Always returns 200 success."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "success", "message": "OTP sent"})
    return httpx.MockTransport(handler)


def make_fail_transport():
    """Always returns 403."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "Forbidden"})
    return httpx.MockTransport(handler)


def make_mixed_transport():
    """First call succeeds (scanner), then alternates for verifier."""
    counter = {"n": 0}
    def handler(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        if counter["n"] <= 2:
            return httpx.Response(200, json={"status": "success"})
        return httpx.Response(403, json={"error": "Forbidden"})
    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def ensure_scope():
    ALLOWED.add("target.example.com")
    yield
    ALLOWED.discard("target.example.com")


@pytest.fixture
def attacker():
    return Session(jsessionid="ATTACKER_123")


@pytest.fixture
def victim():
    return Session(jsessionid="VICTIM_456")


# ── EndpointInfo tests ───────────────────────────────────────

class TestEndpointInfo:
    def test_defaults(self):
        ep = EndpointInfo(url="https://target.example.com/api/sendOTP")
        assert ep.method == "GET"
        assert ep.params == []
        assert ep.tech_signals == []

    def test_with_signals(self):
        ep = EndpointInfo(
            url="https://target.example.com/api/sendOTP",
            method="POST",
            tech_signals=["rest-api", "session-cookie"],
        )
        assert ep.tech_signals == ["rest-api", "session-cookie"]


# ── TargetState tests ────────────────────────────────────────

class TestTargetState:
    def test_initial_state(self):
        state = TargetState(target="https://target.example.com")
        assert state.target == "https://target.example.com"
        assert state.endpoints == []
        assert state.candidate_queue == []
        assert state.confirmed == []
        assert state.needs_human == []

    def test_summary(self):
        state = TargetState(target="https://target.example.com")
        state.recipes_matched = 2
        state.scans_run = 3
        s = state.summary()
        assert s["target"] == "https://target.example.com"
        assert s["recipes_matched"] == 2
        assert s["scans_run"] == 3
        assert s["confirmed"] == 0


# ── HumanQueue tests ────────────────────────────────────────

class TestHumanQueue:
    def test_add_and_read(self, tmp_path):
        queue = HumanQueue(output_dir=tmp_path)
        candidate = Candidate(
            recipe_id="test",
            scanner="TestScanner",
            endpoint="https://target.example.com/test",
            method="POST",
            evidence={"status": 200},
            confidence="high",
            request_data={"id_param": "id", "id_value": "42"},
        )
        from agent.verify.base import VerifyResult
        result = VerifyResult(
            candidate=candidate,
            verdict=Verdict.CONFIRMED,
            replays=3,
            evidence={"successes": 3},
            reason="All replays confirmed",
        )
        queue.add(result)
        entries = queue.read_queue()
        assert len(entries) == 1
        assert entries[0]["verdict"] == "CONFIRMED"
        assert entries[0]["recipe_id"] == "test"

    def test_clear(self, tmp_path):
        queue = HumanQueue(output_dir=tmp_path)
        # Write something
        (tmp_path / "human_queue.jsonl").write_text('{"test": true}\n')
        queue.clear()
        assert queue.read_queue() == []

    def test_write_summary(self, tmp_path):
        queue = HumanQueue(output_dir=tmp_path)
        state = TargetState(target="https://target.example.com")
        state.recipes_matched = 1
        queue.write_summary(state)
        summary = json.loads((tmp_path / "run_summary.json").read_text())
        assert summary["target"] == "https://target.example.com"
        assert summary["recipes_matched"] == 1

    def test_read_empty_queue(self, tmp_path):
        queue = HumanQueue(output_dir=tmp_path)
        assert queue.read_queue() == []


# ── ScannerRegistry tests ───────────────────────────────────

class TestScannerRegistry:
    def test_register_and_get(self):
        reg = ScannerRegistry()
        reg.register("idor", IdorScanner)
        assert reg.get("idor") is IdorScanner

    def test_get_unknown(self):
        reg = ScannerRegistry()
        assert reg.get("sqli") is None

    def test_get_for_recipe(self):
        reg = ScannerRegistry()
        reg.register("idor", IdorScanner)
        assert reg.get_for_recipe(IDOR_RECIPE) is IdorScanner

    def test_get_for_recipe_by_source(self):
        reg = ScannerRegistry()
        reg.register("idor", IdorScanner)
        recipe = validate_recipe({
            "id": "custom-authz-bypass",
            "applies_to": ["api"],
            "tech_signals": ["rest-api"],
            "preconditions": ["authenticated session"],
            "detect": [{"step": "test"}],
            "signal": "test",
            "verify": "test",
            "severity": "high",
            "remediation": "fix",
            "source": "CWE-639",
        })
        assert reg.get_for_recipe(recipe) is IdorScanner


# ── Orchestrator end-to-end tests ────────────────────────────

class TestOrchestrator:
    _SENTINEL = object()

    def _make_config(self, attacker, victim, tmp_path, recipes=None,
                     endpoints=_SENTINEL, victim_ids=None):
        if endpoints is self._SENTINEL:
            endpoints = [
                EndpointInfo(
                    url="https://target.example.com/api/sendOTP",
                    method="POST",
                    tech_signals=["rest-api", "session-cookie"],
                )
            ]
        return OrchestratorConfig(
            attacker_session=attacker,
            victim_session=victim,
            recipes=recipes or [IDOR_RECIPE],
            endpoints=endpoints,
            tech_signals=["rest-api", "session-cookie"],
            victim_ids=victim_ids or ["victim_123"],
            id_param="mobileNo",
            id_location="body",
            verify_replays=2,
            output_dir=tmp_path,
            log_path=tmp_path / "http_log.jsonl",
        )

    def test_full_loop_confirmed(self, attacker, victim, tmp_path):
        """End-to-end: scanner finds IDOR, verifier confirms it."""
        transport = make_success_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        config = self._make_config(attacker, victim, tmp_path)
        orch = Orchestrator(config, client=client)

        state = asyncio.get_event_loop().run_until_complete(
            orch.run("https://target.example.com")
        )

        assert len(state.candidate_queue) == 1
        assert len(state.confirmed) == 1
        assert len(state.false_positives) == 0
        assert state.confirmed[0].verdict == Verdict.CONFIRMED

        # Human queue file should exist
        entries = orch.queue.read_queue()
        assert len(entries) == 1
        assert entries[0]["verdict"] == "CONFIRMED"

    def test_full_loop_false_positive(self, attacker, victim, tmp_path):
        """Scanner finds candidate but verifier rejects it."""
        # First call succeeds (scanner probe), rest fail (verifier replays)
        counter = {"n": 0}
        def handler(request: httpx.Request) -> httpx.Response:
            counter["n"] += 1
            if counter["n"] == 1:
                return httpx.Response(200, json={"status": "success"})
            return httpx.Response(403, json={"error": "Forbidden"})
        transport = httpx.MockTransport(handler)

        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        config = self._make_config(attacker, victim, tmp_path)
        orch = Orchestrator(config, client=client)

        state = asyncio.get_event_loop().run_until_complete(
            orch.run("https://target.example.com")
        )

        assert len(state.candidate_queue) == 1
        assert len(state.confirmed) == 0
        assert len(state.false_positives) == 1

        # Human queue should be empty
        entries = orch.queue.read_queue()
        assert len(entries) == 0

    def test_full_loop_no_candidates(self, attacker, victim, tmp_path):
        """Scanner finds nothing when endpoint returns 403."""
        transport = make_fail_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        config = self._make_config(attacker, victim, tmp_path)
        orch = Orchestrator(config, client=client)

        state = asyncio.get_event_loop().run_until_complete(
            orch.run("https://target.example.com")
        )

        assert len(state.candidate_queue) == 0
        assert len(state.confirmed) == 0
        assert state.scans_run == 1

    def test_no_endpoints_skips_scan(self, attacker, victim, tmp_path):
        """No endpoints means no scan runs."""
        config = self._make_config(attacker, victim, tmp_path, endpoints=[])
        transport = make_success_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        orch = Orchestrator(config, client=client)

        state = asyncio.get_event_loop().run_until_complete(
            orch.run("https://target.example.com")
        )

        assert state.scans_run == 0
        assert len(state.candidate_queue) == 0

    def test_no_recipes_skips_scan(self, attacker, victim, tmp_path):
        """No recipes means nothing to scan for."""
        config = self._make_config(attacker, victim, tmp_path, recipes=[])
        config.recipes = None
        config.recipes_dir = None
        transport = make_success_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        orch = Orchestrator(config, client=client)

        state = asyncio.get_event_loop().run_until_complete(
            orch.run("https://target.example.com")
        )

        assert state.recipes_matched == 0

    def test_no_victim_session_skips_idor(self, attacker, tmp_path):
        """IDOR scanner is skipped if no victim session configured."""
        config = self._make_config(attacker, None, tmp_path)
        config.victim_session = None
        transport = make_success_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        orch = Orchestrator(config, client=client)

        state = asyncio.get_event_loop().run_until_complete(
            orch.run("https://target.example.com")
        )

        assert state.scans_run == 0

    def test_scope_violation_raises(self, attacker, victim, tmp_path):
        """Out-of-scope target raises ScopeError."""
        config = self._make_config(attacker, victim, tmp_path)
        transport = make_success_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        orch = Orchestrator(config, client=client)

        with pytest.raises(ScopeError):
            asyncio.get_event_loop().run_until_complete(
                orch.run("https://evil.example.com")
            )

    def test_multiple_victim_ids(self, attacker, victim, tmp_path):
        """Multiple victim IDs produce multiple candidates and confirmations."""
        transport = make_success_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        config = self._make_config(
            attacker, victim, tmp_path,
            victim_ids=["victim_1", "victim_2"],
        )
        orch = Orchestrator(config, client=client)

        state = asyncio.get_event_loop().run_until_complete(
            orch.run("https://target.example.com")
        )

        assert len(state.candidate_queue) == 2
        assert len(state.confirmed) == 2

        entries = orch.queue.read_queue()
        assert len(entries) == 2

    def test_summary_file_written(self, attacker, victim, tmp_path):
        """Run summary JSON is written at end."""
        transport = make_success_transport()
        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        config = self._make_config(attacker, victim, tmp_path)
        orch = Orchestrator(config, client=client)

        asyncio.get_event_loop().run_until_complete(
            orch.run("https://target.example.com")
        )

        summary_file = tmp_path / "run_summary.json"
        assert summary_file.exists()
        summary = json.loads(summary_file.read_text())
        assert summary["confirmed"] == 1
        assert summary["target"] == "https://target.example.com"

    def test_needs_human_in_queue(self, attacker, victim, tmp_path):
        """NEEDS_HUMAN findings go to the human queue too."""
        # Scanner probe succeeds, 1st verifier replay succeeds, 2nd fails
        counter = {"n": 0}
        def handler(request: httpx.Request) -> httpx.Response:
            counter["n"] += 1
            if counter["n"] <= 2:  # probe + 1st replay
                return httpx.Response(200, json={"status": "success"})
            return httpx.Response(403, json={"error": "Forbidden"})
        transport = httpx.MockTransport(handler)

        client = HttpClient(transport=transport, log_path=tmp_path / "log.jsonl")
        config = self._make_config(attacker, victim, tmp_path)
        orch = Orchestrator(config, client=client)

        state = asyncio.get_event_loop().run_until_complete(
            orch.run("https://target.example.com")
        )

        assert len(state.needs_human) == 1
        entries = orch.queue.read_queue()
        assert len(entries) == 1
        assert entries[0]["verdict"] == "NEEDS_HUMAN"
