"""Tests for race condition scanner."""
import pytest

from agent.scanners.race import (
    RaceConditionScanner,
    _RACE_SENSITIVE_PATTERNS,
    _DEFAULT_CONCURRENCY,
)


def test_race_sensitive_patterns():
    assert "transfer" in _RACE_SENSITIVE_PATTERNS
    assert "payment" in _RACE_SENSITIVE_PATTERNS
    assert "checkout" in _RACE_SENSITIVE_PATTERNS
    assert "vote" in _RACE_SENSITIVE_PATTERNS


def test_default_concurrency():
    assert _DEFAULT_CONCURRENCY >= 3


def test_find_race_endpoints_strings():
    from agent.http import Session
    scanner = RaceConditionScanner.__new__(RaceConditionScanner)
    endpoints = [
        "http://test.com/api/transfer",
        "http://test.com/api/users",
        "http://test.com/checkout/confirm",
        "http://test.com/search",
    ]
    results = scanner._find_race_endpoints(endpoints, "http://test.com")
    urls = [url for url, _ in results]
    assert "http://test.com/api/transfer" in urls
    assert "http://test.com/checkout/confirm" in urls
    assert "http://test.com/api/users" not in urls
    assert "http://test.com/search" not in urls


def test_find_race_endpoints_dedup():
    scanner = RaceConditionScanner.__new__(RaceConditionScanner)
    endpoints = [
        "http://test.com/transfer",
        "http://test.com/transfer",
    ]
    results = scanner._find_race_endpoints(endpoints, "http://test.com")
    assert len(results) == 1
