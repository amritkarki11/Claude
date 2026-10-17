"""Tests for privilege escalation false-positive filtering."""
import re
import pytest

from agent.scanners.privesc import (
    _is_error_page,
    _responses_differ,
    _generate_test_ids,
    _ADMIN_PATH_STRONG,
    _ADMIN_PATH_WEAK,
    _NORMAL_USER_PAGES,
)


# ── Path pattern tests ──────────────────────────────────────

def test_strong_admin_patterns():
    assert _ADMIN_PATH_STRONG.search("/admin")
    assert _ADMIN_PATH_STRONG.search("/wp-admin/")
    assert _ADMIN_PATH_STRONG.search("/phpmyadmin/index.php")
    assert _ADMIN_PATH_STRONG.search("/api/admin/users")
    assert not _ADMIN_PATH_STRONG.search("/account/balance")
    assert not _ADMIN_PATH_STRONG.search("/bank/showAccount")


def test_weak_admin_patterns():
    assert _ADMIN_PATH_WEAK.search("/users")
    assert _ADMIN_PATH_WEAK.search("/settings")
    assert not _ADMIN_PATH_WEAK.search("/home")
    assert not _ADMIN_PATH_WEAK.search("/transfer")


def test_normal_user_pages_filter():
    """Pages that should NOT trigger privesc reports."""
    assert _NORMAL_USER_PAGES.search("/my-account")
    assert _NORMAL_USER_PAGES.search("/profile")
    assert _NORMAL_USER_PAGES.search("/dashboard")
    assert _NORMAL_USER_PAGES.search("/balance")
    assert _NORMAL_USER_PAGES.search("/transactions")
    assert _NORMAL_USER_PAGES.search("/transfer")
    assert _NORMAL_USER_PAGES.search("/job-listings")
    assert _NORMAL_USER_PAGES.search("/careers")
    assert _NORMAL_USER_PAGES.search("/about-us")
    assert _NORMAL_USER_PAGES.search("/contact")
    assert _NORMAL_USER_PAGES.search("/search-results")


def test_banking_urls_not_admin():
    """Altoro Mutual banking pages should not match strong admin patterns."""
    banking_paths = [
        "/bank/showAccount",
        "/bank/transfer",
        "/bank/balance",
        "/doLogin",
        "/bank/queryxpath.jsp",
        "/bank/account.jsp",
        "/default.aspx",
        "/index.jsp",
        "/search.jsp",
    ]
    for path in banking_paths:
        assert not _ADMIN_PATH_STRONG.search(path), f"{path} should not match strong admin"


# ── Response comparison tests ───────────────────────────────

def test_responses_differ_identical():
    body = "<html><body><h1>Account Balance: $1234</h1></body></html>"
    assert _responses_differ(body, body) is False


def test_responses_differ_only_timestamps():
    a = '<html><body>Generated at 2024-01-15T10:30:00</body></html>'
    b = '<html><body>Generated at 2024-01-15T11:45:00</body></html>'
    assert _responses_differ(a, b) is False


def test_responses_differ_real_content():
    a = "<html><body><h1>Account: John Doe</h1><p>Balance: $5000</p></body></html>"
    b = "<html><body><h1>Account: Jane Smith</h1><p>Balance: $8000</p></body></html>"
    assert _responses_differ(a, b) is True


def test_responses_differ_csrf_tokens_ignored():
    a = '<input type="hidden" name="csrf_token" value="abc123def456"> <h1>Same</h1>'
    b = '<input type="hidden" name="csrf_token" value="xyz789ghi012"> <h1>Same</h1>'
    assert _responses_differ(a, b) is False


# ── Error page detection ────────────────────────────────────

def test_is_error_page_404():
    assert _is_error_page("<h1>Page Not Found</h1><p>The page was 404 not found.</p>")


def test_is_error_page_real_content():
    body = "<html><body><h1>Admin Dashboard</h1><p>Welcome, administrator. " + "x" * 200 + "</p></body></html>"
    assert _is_error_page(body) is False


def test_is_error_page_short_body():
    assert _is_error_page("OK")


# ── Test ID generation ──────────────────────────────────────

def test_generate_test_ids_numeric():
    ids = _generate_test_ids("5")
    assert "6" in ids
    assert "4" in ids
    assert "1" in ids


def test_generate_test_ids_alpha():
    ids = _generate_test_ids("abc123xyz")
    assert "1" in ids
    assert "admin" in ids
