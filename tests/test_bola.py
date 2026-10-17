"""Tests for the BOLA scanner — ID patterns, generation, diffing."""
import pytest

from agent.scanners.bola import (
    _ID_PARAM_PATTERN,
    _PATH_ID_PATTERN,
    _looks_like_error,
    _generate_adjacent_ids,
    _bodies_differ_meaningfully,
)


# ── ID parameter pattern tests ──────────────────────────────

def test_id_param_matches():
    for name in ["id", "user_id", "userId", "account_id", "accountId",
                  "order_id", "orderId", "pid", "uid", "tid"]:
        assert _ID_PARAM_PATTERN.match(name), f"{name} should match"


def test_id_param_rejects():
    for name in ["name", "email", "page", "sort", "filter", "query", "search"]:
        assert not _ID_PARAM_PATTERN.match(name), f"{name} should not match"


# ── Path ID extraction ──────────────────────────────────────

def test_path_id_numeric():
    m = _PATH_ID_PATTERN.search("/users/123")
    assert m and m.group(1) == "123"


def test_path_id_uuid():
    m = _PATH_ID_PATTERN.search("/accounts/a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    assert m and m.group(1) == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


def test_path_id_various_resources():
    for resource in ["orders", "profiles", "transactions", "documents"]:
        m = _PATH_ID_PATTERN.search(f"/{resource}/42")
        assert m and m.group(1) == "42", f"Failed for /{resource}/42"


def test_path_id_no_match():
    assert not _PATH_ID_PATTERN.search("/login")
    assert not _PATH_ID_PATTERN.search("/search?q=test")


# ── Error detection ─────────────────────────────────────────

def test_looks_like_error():
    assert _looks_like_error("Access Denied - you are not authorized")
    assert _looks_like_error('{"error": "not found"}')
    assert not _looks_like_error("<html><body><h1>Account Details</h1><p>Balance: $5000</p></body></html>")


# ── Adjacent ID generation ──────────────────────────────────

def test_adjacent_numeric():
    ids = _generate_adjacent_ids("200")
    assert "201" in ids
    assert "199" in ids
    assert "1" in ids  # large number → also try 1


def test_adjacent_small_numeric():
    ids = _generate_adjacent_ids("5")
    assert "6" in ids
    assert "4" in ids
    assert "1" not in ids  # 5 is small, no "1" shortcut


def test_adjacent_non_numeric():
    ids = _generate_adjacent_ids("abc-def")
    assert ids == []


# ── Body diff ───────────────────────────────────────────────

def test_bodies_same():
    body = "<html><body><h1>Account 123</h1></body></html>"
    assert _bodies_differ_meaningfully(body, body) is False


def test_bodies_differ_real_data():
    a = "<html><body><h1>John Doe</h1><p>Balance: $5000</p></body></html>"
    b = "<html><body><h1>Jane Smith</h1><p>Balance: $9000</p></body></html>"
    assert _bodies_differ_meaningfully(a, b) is True


def test_bodies_same_except_timestamp():
    a = '<div>Data loaded at 2024-01-15T10:00:00</div>'
    b = '<div>Data loaded at 2024-01-15T11:30:00</div>'
    assert _bodies_differ_meaningfully(a, b) is False
