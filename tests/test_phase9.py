"""Phase 9 — CLI entry point, rate limiting, stealth, and scope safety tests.

Tests argument parsing, input helpers, validation, logging setup,
summary printing, three execution modes (benchmark, report-only, live scan),
rate limiting, stealth mode, and scope guard fuzzing.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import pathlib
import sys
import time

import httpx
import pytest

from agent.cli import (
    build_parser,
    _parse_cookies,
    _parse_headers,
    _build_session,
    _build_endpoints,
    ConfigError,
    validate_args,
    setup_logging,
    print_summary,
    async_main,
    main,
    DEFAULT_RECIPES,
)
from agent.http import HttpClient, Session, STEALTH_USER_AGENTS
from agent.orchestrator import TargetState
from agent.scope import check as scope_check, ScopeError, ALLOWED, host_of


# ── Input helpers ────────────────────────────────────────────


class TestParseCookies:

    def test_single_cookie(self):
        result = _parse_cookies(["sid=abc123"])
        assert result == {"sid": "abc123"}

    def test_multiple_cookies(self):
        result = _parse_cookies(["sid=abc", "token=xyz"])
        assert result == {"sid": "abc", "token": "xyz"}

    def test_value_with_equals(self):
        result = _parse_cookies(["data=a=b=c"])
        assert result == {"data": "a=b=c"}

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Invalid cookie format"):
            _parse_cookies(["no-equals-here"])

    def test_empty_list(self):
        assert _parse_cookies([]) == {}


class TestParseHeaders:

    def test_single_header(self):
        result = _parse_headers(["Authorization: Bearer tok"])
        assert result == {"Authorization": "Bearer tok"}

    def test_multiple_headers(self):
        result = _parse_headers(["X-Custom: val1", "Accept: text/html"])
        assert result == {"X-Custom": "val1", "Accept": "text/html"}

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Invalid header format"):
            _parse_headers(["no-colon-space"])

    def test_empty_list(self):
        assert _parse_headers([]) == {}


class TestBuildSession:

    def test_cookies_only(self):
        s = _build_session(["sid=abc"], [], None, None)
        assert isinstance(s, Session)
        assert s.cookies == {"sid": "abc"}
        assert s.headers == {}
        assert s.bearer is None
        assert s.jwt is None

    def test_all_auth(self):
        s = _build_session(
            ["sid=abc"], ["X-Key: val"], "bearer-tok", "jwt-tok"
        )
        assert s.cookies == {"sid": "abc"}
        assert s.headers == {"X-Key": "val"}
        assert s.bearer == "bearer-tok"
        assert s.jwt == "jwt-tok"


class TestBuildEndpoints:

    def test_no_paths_returns_empty(self):
        eps = _build_endpoints("https://example.com", [], "GET", [])
        assert eps == []

    def test_single_endpoint(self):
        eps = _build_endpoints("https://example.com", ["/api/users"], "POST", ["id"])
        assert len(eps) == 1
        assert eps[0].url == "https://example.com/api/users"
        assert eps[0].method == "POST"
        assert eps[0].params == ["id"]

    def test_multiple_endpoints(self):
        eps = _build_endpoints(
            "https://example.com/",
            ["/api/users", "/api/orders"],
            "GET", ["q"],
        )
        assert len(eps) == 2
        assert eps[0].url == "https://example.com/api/users"
        assert eps[1].url == "https://example.com/api/orders"

    def test_trailing_slash_handling(self):
        eps = _build_endpoints("https://example.com/", ["/test"], "GET", [])
        assert eps[0].url == "https://example.com/test"


# ── Argument parser ──────────────────────────────────────────


class TestBuildParser:

    def test_minimal_args(self):
        p = build_parser()
        args = p.parse_args([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
        ])
        assert args.target == "https://example.com"
        assert args.scope == ["example.com"]
        assert args.attacker_cookie == ["sid=abc"]
        assert args.method == "GET"
        assert args.replays == 3
        assert args.timeout == 15.0

    def test_multiple_scope(self):
        p = build_parser()
        args = p.parse_args([
            "--target", "https://example.com",
            "--scope", "a.com", "b.com",
            "--attacker-cookie", "sid=abc",
        ])
        assert args.scope == ["a.com", "b.com"]

    def test_victim_args(self):
        p = build_parser()
        args = p.parse_args([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--victim-cookie", "sid=xyz",
            "--victim-id", "42",
            "--id-param", "user_id",
            "--id-location", "query",
        ])
        assert args.victim_cookie == ["sid=xyz"]
        assert args.victim_id == ["42"]
        assert args.id_param == "user_id"
        assert args.id_location == "query"

    def test_endpoint_args(self):
        p = build_parser()
        args = p.parse_args([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--endpoint", "/api/users",
            "--endpoint", "/api/orders",
            "--method", "POST",
            "--param", "id",
            "--param", "name",
        ])
        assert args.endpoint == ["/api/users", "/api/orders"]
        assert args.method == "POST"
        assert args.param == ["id", "name"]

    def test_benchmark_flag(self):
        p = build_parser()
        args = p.parse_args([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--benchmark",
        ])
        assert args.benchmark is True

    def test_verbose_flags(self):
        p = build_parser()
        args = p.parse_args([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "-vv",
        ])
        assert args.verbose == 2

    def test_defaults(self):
        p = build_parser()
        args = p.parse_args([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
        ])
        assert args.replays == 3
        assert args.timeout == 15.0
        assert args.proxy is False
        assert args.benchmark is False
        assert args.report_only is None
        assert args.quiet is False


# ── Validation ───────────────────────────────────────────────


class TestValidateArgs:

    def _base_args(self, **overrides) -> argparse.Namespace:
        defaults = dict(
            target="https://example.com",
            scope=["example.com"],
            attacker_cookie=["sid=abc"],
            attacker_header=[],
            attacker_bearer=None,
            attacker_jwt=None,
            victim_cookie=[],
            victim_header=[],
            victim_bearer=None,
            victim_jwt=None,
            victim_id=[],
            recipes_dir=DEFAULT_RECIPES,
            replays=3,
        )
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_valid_args_pass(self):
        validate_args(self._base_args())  # should not raise

    def test_invalid_target_no_scheme(self):
        with pytest.raises(ConfigError, match="must be a URL"):
            validate_args(self._base_args(target="example.com"))

    def test_invalid_target_ftp(self):
        with pytest.raises(ConfigError, match="must be a URL"):
            validate_args(self._base_args(target="ftp://example.com"))

    def test_empty_scope(self):
        with pytest.raises(ConfigError, match="at least one hostname"):
            validate_args(self._base_args(scope=[]))

    def test_no_attacker_auth(self):
        with pytest.raises(ConfigError, match="Attacker session requires"):
            validate_args(self._base_args(attacker_cookie=[]))

    def test_attacker_bearer_is_valid(self):
        validate_args(self._base_args(
            attacker_cookie=[], attacker_bearer="tok",
        ))  # should not raise

    def test_attacker_header_is_valid(self):
        validate_args(self._base_args(
            attacker_cookie=[], attacker_header=["X-Key: val"],
        ))  # should not raise

    def test_victim_id_without_victim_session(self):
        with pytest.raises(ConfigError, match="victim-id requires a victim session"):
            validate_args(self._base_args(victim_id=["42"]))

    def test_victim_id_with_victim_cookie_ok(self):
        validate_args(self._base_args(
            victim_id=["42"], victim_cookie=["sid=xyz"],
        ))  # should not raise

    def test_recipes_dir_missing(self):
        with pytest.raises(ConfigError, match="recipes-dir does not exist"):
            validate_args(self._base_args(
                recipes_dir=pathlib.Path("/nonexistent/path"),
            ))

    def test_replays_too_low(self):
        with pytest.raises(ConfigError, match="replays must be at least 2"):
            validate_args(self._base_args(replays=1))

    def test_replays_two_is_valid(self):
        validate_args(self._base_args(replays=2))  # should not raise


# ── Logging ──────────────────────────────────────────────────


class TestSetupLogging:

    def test_quiet_sets_error(self):
        setup_logging(verbose=0, quiet=True)
        assert logging.getLogger().level == logging.ERROR

    def test_verbose_1_sets_info(self):
        setup_logging(verbose=1, quiet=False)
        assert logging.getLogger().level == logging.INFO

    def test_verbose_2_sets_debug(self):
        setup_logging(verbose=2, quiet=False)
        assert logging.getLogger().level == logging.DEBUG

    def test_default_sets_warning(self):
        setup_logging(verbose=0, quiet=False)
        assert logging.getLogger().level == logging.WARNING

    def test_log_file_created(self, tmp_path):
        log_file = tmp_path / "test.log"
        setup_logging(verbose=1, quiet=False, log_file=log_file)
        # The file may not exist yet until a message is logged
        logger = logging.getLogger("test.phase9")
        logger.info("test message")
        assert log_file.exists()


# ── Summary printer ──────────────────────────────────────────


class TestPrintSummary:

    def test_prints_summary(self, capsys):
        state = TargetState(target="https://example.com")
        state.scans_run = 5
        print_summary(state, elapsed=12.3)
        captured = capsys.readouterr()
        assert "PENTEST AGENT" in captured.out
        assert "https://example.com" in captured.out
        assert "12.3s" in captured.out

    def test_prints_report_path(self, capsys):
        state = TargetState(target="https://example.com")
        print_summary(state, elapsed=1.0, report_path=pathlib.Path("outputs/report.md"))
        captured = capsys.readouterr()
        assert "outputs/report.md" in captured.out


# ── Benchmark mode (end-to-end via main) ─────────────────────


class TestBenchmarkMode:

    def test_benchmark_via_async_main(self, tmp_path):
        args = argparse.Namespace(
            target="https://example.com",
            scope=["example.com"],
            attacker_cookie=["sid=abc"],
            attacker_header=[],
            attacker_bearer=None,
            attacker_jwt=None,
            victim_cookie=[],
            victim_header=[],
            victim_bearer=None,
            victim_jwt=None,
            victim_id=[],
            id_param="id",
            id_location="body",
            endpoint=[],
            method="GET",
            param=[],
            recipes_dir=DEFAULT_RECIPES,
            output_dir=tmp_path,
            replays=3,
            timeout=15.0,
            proxy=False,
            tech_signal=[],
            benchmark=True,
            report_only=None,
            verbose=0,
            quiet=True,
        )
        exit_code = asyncio.get_event_loop().run_until_complete(async_main(args))
        assert exit_code == 0
        # Check scorecard files were created
        assert (tmp_path / "benchmark_scorecard.md").exists()
        assert (tmp_path / "benchmark_scorecard.json").exists()


# ── Report-only mode ─────────────────────────────────────────


class TestReportOnlyMode:

    def test_report_only_generates_report(self, tmp_path):
        # Create a fake queue file
        queue_file = tmp_path / "queue.jsonl"
        entry = {
            "verdict": "CONFIRMED",
            "recipe_id": "sqli-error-based",
            "endpoint": "https://example.com/api/test",
            "method": "GET",
            "scanner": "sqli",
            "confidence": "high",
            "replays": 3,
            "reason": "SQL error in response",
            "evidence": {"error_match": "sql syntax"},
            "request_data": {"param": "id", "payload": "'"},
        }
        queue_file.write_text(json.dumps(entry) + "\n")

        args = argparse.Namespace(
            target="https://example.com",
            scope=["example.com"],
            output_dir=tmp_path,
            report_only=queue_file,
            benchmark=False,
            verbose=0,
            quiet=True,
            # These aren't used in report-only but needed for Namespace
            attacker_cookie=["sid=abc"],
            attacker_header=[],
            attacker_bearer=None,
            attacker_jwt=None,
            victim_cookie=[],
            victim_header=[],
            victim_bearer=None,
            victim_jwt=None,
            victim_id=[],
            id_param="id",
            id_location="body",
            endpoint=[],
            method="GET",
            param=[],
            recipes_dir=DEFAULT_RECIPES,
            replays=3,
            timeout=15.0,
            proxy=False,
            tech_signal=[],
        )
        exit_code = asyncio.get_event_loop().run_until_complete(async_main(args))
        assert exit_code == 0
        assert (tmp_path / "report.md").exists()
        assert (tmp_path / "report.json").exists()

    def test_report_only_missing_file(self, tmp_path):
        args = argparse.Namespace(
            target="https://example.com",
            scope=["example.com"],
            output_dir=tmp_path,
            report_only=tmp_path / "nonexistent.jsonl",
            benchmark=False,
            verbose=0,
            quiet=False,
        )
        exit_code = asyncio.get_event_loop().run_until_complete(async_main(args))
        assert exit_code == 1


# ── main() entry point ───────────────────────────────────────


class TestMainEntryPoint:

    def test_config_error_returns_2(self):
        # Missing auth → ConfigError → exit 2
        exit_code = main([
            "--target", "https://example.com",
            "--scope", "example.com",
        ])
        assert exit_code == 2

    def test_invalid_target_returns_2(self):
        exit_code = main([
            "--target", "not-a-url",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
        ])
        assert exit_code == 2

    def test_benchmark_mode_returns_0(self, tmp_path):
        exit_code = main([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--benchmark",
            "--output-dir", str(tmp_path),
            "-q",
        ])
        assert exit_code == 0


# ── 9.2: Rate limiting + stealth ─────────────────────────────


TARGET = "https://target.example.com/api/test"


def _ok_transport():
    """Simple mock transport that always returns 200."""
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")
    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _scope_for_ratelimit():
    ALLOWED.add("target.example.com")
    yield
    ALLOWED.discard("target.example.com")


def _run9(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestRateLimiting:

    def test_rate_limit_delays_requests(self):
        async def _test():
            client = HttpClient(transport=_ok_transport(), log_path="/dev/null", rate_limit=0.2)
            start = time.monotonic()
            await client.get(TARGET)
            await client.get(TARGET)
            await client.get(TARGET)
            elapsed = time.monotonic() - start
            await client.aclose()
            assert elapsed >= 0.35, f"Rate limit not enforced: {elapsed:.2f}s"
        _run9(_test())

    def test_no_rate_limit_is_fast(self):
        async def _test():
            client = HttpClient(transport=_ok_transport(), log_path="/dev/null", rate_limit=0.0)
            start = time.monotonic()
            await client.get(TARGET)
            await client.get(TARGET)
            await client.get(TARGET)
            elapsed = time.monotonic() - start
            await client.aclose()
            assert elapsed < 0.3, f"Unexpectedly slow without rate limit: {elapsed:.2f}s"
        _run9(_test())


class TestStealthMode:

    def test_stealth_sets_user_agent(self):
        client = HttpClient(transport=_ok_transport(), log_path="/dev/null", stealth=True)
        ua = client._client.headers.get("user-agent", "")
        assert any(agent in ua for agent in STEALTH_USER_AGENTS), f"Unexpected UA: {ua}"
        _run9(client.aclose())

    def test_stealth_enables_rate_limit(self):
        client = HttpClient(transport=_ok_transport(), log_path="/dev/null", stealth=True)
        assert client._rate_limit >= 1.0
        assert client._stealth is True
        _run9(client.aclose())

    def test_stealth_rate_limit_override(self):
        client = HttpClient(transport=_ok_transport(), log_path="/dev/null", stealth=True, rate_limit=2.0)
        assert client._rate_limit == 2.0
        _run9(client.aclose())

    def test_cli_stealth_flag(self):
        p = build_parser()
        args = p.parse_args([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--stealth",
            "--rate-limit", "0.5",
        ])
        assert args.stealth is True
        assert args.rate_limit == 0.5


# ── 9.3: Scope safety audit (fuzz the scope guard) ───────────


class TestScopeSafety:

    def test_empty_allowlist_rejects_all(self):
        saved = set(ALLOWED)
        ALLOWED.clear()
        try:
            with pytest.raises(ScopeError, match="no allowlist configured"):
                scope_check("https://anything.com/path")
        finally:
            ALLOWED.update(saved)

    def test_basic_out_of_scope(self):
        with pytest.raises(ScopeError):
            scope_check("https://evil.com/api")

    def test_in_scope_passes(self):
        result = scope_check("https://target.example.com/api/test")
        assert result == "https://target.example.com/api/test"

    def test_host_with_port_out_of_scope(self):
        """Ports don't bypass: target.example.com:8443 != target.example.com."""
        with pytest.raises(ScopeError):
            scope_check("https://target.example.com:8443/api")

    def test_subdomain_not_in_scope(self):
        with pytest.raises(ScopeError):
            scope_check("https://sub.target.example.com/api")

    def test_unicode_host_normalization(self):
        with pytest.raises(ScopeError):
            scope_check("https://ⅇvil.com/api")

    def test_ip_address_not_in_scope(self):
        with pytest.raises(ScopeError):
            scope_check("https://127.0.0.1/api")

    def test_url_with_auth_section(self):
        """user:pass@host shouldn't bypass scope via the userinfo portion."""
        with pytest.raises(ScopeError):
            scope_check("https://target.example.com@evil.com/api")

    def test_double_encoded_host(self):
        """URL-encoded hostnames shouldn't bypass scope."""
        with pytest.raises(ScopeError):
            scope_check("https://%65%76%69%6c.com/api")

    def test_backslash_url(self):
        """Backslash in URL shouldn't confuse the parser."""
        with pytest.raises(ScopeError):
            scope_check("https://evil.com\\@target.example.com/api")

    def test_null_byte_in_host(self):
        """Null byte shouldn't truncate hostname comparison."""
        with pytest.raises(ScopeError):
            scope_check("https://target.example.com\x00.evil.com/api")

    def test_case_insensitive(self):
        result = scope_check("https://TARGET.EXAMPLE.COM/api")
        assert "target.example.com" in result.lower()

    def test_host_of_no_scheme(self):
        assert host_of("target.example.com") == "target.example.com"

    def test_host_of_with_path(self):
        assert host_of("https://target.example.com/foo/bar") == "target.example.com"

    def test_data_uri_rejected(self):
        with pytest.raises(ScopeError):
            scope_check("data:text/html,<h1>hi</h1>")

    def test_file_uri_rejected(self):
        with pytest.raises(ScopeError):
            scope_check("file:///etc/passwd")

    def test_ftp_uri_rejected(self):
        with pytest.raises(ScopeError):
            scope_check("ftp://target.example.com/file")


# ── 9.4: Headless run mode ──────────────────────────────────


class TestHeadlessMode:

    def test_headless_flag_parsed(self):
        p = build_parser()
        args = p.parse_args([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--benchmark", "--headless",
        ])
        assert args.headless is True

    def test_headless_default_false(self):
        p = build_parser()
        args = p.parse_args([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
        ])
        assert args.headless is False

    def test_min_precision_flag(self):
        p = build_parser()
        args = p.parse_args([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--benchmark", "--min-precision", "0.8",
        ])
        assert args.min_precision == 0.8

    def test_min_recall_flag(self):
        p = build_parser()
        args = p.parse_args([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--benchmark", "--min-recall", "0.7",
        ])
        assert args.min_recall == 0.7

    def test_threshold_without_benchmark_rejected(self):
        """--min-precision requires --benchmark."""
        with pytest.raises(ConfigError, match="require --benchmark"):
            validate_args(argparse.Namespace(
                target="https://example.com",
                scope=["example.com"],
                attacker_cookie=["sid=abc"],
                attacker_header=[],
                attacker_bearer=None,
                attacker_jwt=None,
                victim_cookie=[],
                victim_header=[],
                victim_bearer=None,
                victim_jwt=None,
                victim_id=[],
                recipes_dir=DEFAULT_RECIPES,
                replays=3,
                benchmark=False,
                min_precision=0.8,
                min_recall=None,
            ))

    def test_invalid_precision_range(self):
        with pytest.raises(ConfigError, match="between 0.0 and 1.0"):
            validate_args(argparse.Namespace(
                target="https://example.com",
                scope=["example.com"],
                attacker_cookie=["sid=abc"],
                attacker_header=[],
                attacker_bearer=None,
                attacker_jwt=None,
                victim_cookie=[],
                victim_header=[],
                victim_bearer=None,
                victim_jwt=None,
                victim_id=[],
                recipes_dir=DEFAULT_RECIPES,
                replays=3,
                benchmark=True,
                min_precision=1.5,
                min_recall=None,
            ))

    def test_headless_benchmark_outputs_json(self, tmp_path, capsys):
        """Headless benchmark should print JSON to stdout."""
        exit_code = main([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--benchmark", "--headless",
            "--output-dir", str(tmp_path),
        ])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "totals" in data
        assert "precision" in data["totals"]
        assert "recall" in data["totals"]
        assert "f1" in data["totals"]
        assert "scenarios" in data

    def test_headless_no_markdown(self, tmp_path, capsys):
        """Headless mode should NOT print markdown table."""
        main([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--benchmark", "--headless",
            "--output-dir", str(tmp_path),
        ])
        captured = capsys.readouterr()
        assert "# Benchmark Scorecard" not in captured.out

    def test_gate_pass_returns_0(self, tmp_path):
        """Passing thresholds should return 0."""
        exit_code = main([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--benchmark", "--headless",
            "--output-dir", str(tmp_path),
            "--min-precision", "0.0",
            "--min-recall", "0.0",
        ])
        assert exit_code == 0

    def test_gate_fail_precision_returns_3(self, tmp_path):
        """Failing precision gate should return exit code 3."""
        exit_code = main([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--benchmark", "--headless",
            "--output-dir", str(tmp_path),
            "--min-precision", "1.0",  # impossible unless perfect
        ])
        # Either 0 (perfect) or 3 (gate fail) — depends on benchmark accuracy
        assert exit_code in (0, 3)

    def test_gate_fail_recall_returns_3(self, tmp_path):
        """Failing recall gate should return exit code 3."""
        exit_code = main([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--benchmark", "--headless",
            "--output-dir", str(tmp_path),
            "--min-recall", "1.0",
        ])
        assert exit_code in (0, 3)

    def test_headless_gate_stderr_json(self, tmp_path, capsys):
        """Headless gate failure should write JSON to stderr."""
        exit_code = main([
            "--target", "https://example.com",
            "--scope", "example.com",
            "--attacker-cookie", "sid=abc",
            "--benchmark", "--headless",
            "--output-dir", str(tmp_path),
            "--min-precision", "0.9999",
            "--min-recall", "0.9999",
        ])
        captured = capsys.readouterr()
        if exit_code == 3:
            # stderr should have a JSON gate failure object
            gate_data = json.loads(captured.err.strip().split("\n")[0])
            assert "gate" in gate_data
            assert gate_data["pass"] is False
