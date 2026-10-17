"""Tests for OAuth and JWT scanners."""
import base64
import json
import pytest

from agent.scanners.oauth import _OAUTH_ENDPOINT_PATTERNS
from agent.scanners.jwt import _looks_like_jwt, _b64encode, _b64decode


# ── OAuth endpoint patterns ─────────────────────────────────

def test_oauth_patterns_match():
    assert _OAUTH_ENDPOINT_PATTERNS.search("/oauth/authorize")
    assert _OAUTH_ENDPOINT_PATTERNS.search("/auth/login")
    assert _OAUTH_ENDPOINT_PATTERNS.search("/connect/authorize")
    assert _OAUTH_ENDPOINT_PATTERNS.search("/api/oauth/token")
    assert _OAUTH_ENDPOINT_PATTERNS.search("/oauth2/authorize")


def test_oauth_patterns_no_match():
    assert not _OAUTH_ENDPOINT_PATTERNS.search("/login")
    assert not _OAUTH_ENDPOINT_PATTERNS.search("/api/users")
    assert not _OAUTH_ENDPOINT_PATTERNS.search("/search")


# ── JWT detection ────────────────────────────────────────────

def _make_jwt(header: dict, payload: dict, sig: str = "signature") -> str:
    h = _b64encode(json.dumps(header))
    p = _b64encode(json.dumps(payload))
    return f"{h}.{p}.{sig}"


def test_looks_like_jwt_valid():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1"})
    assert _looks_like_jwt(token) is True


def test_looks_like_jwt_invalid():
    assert _looks_like_jwt("not-a-jwt") is False
    assert _looks_like_jwt("a.b") is False
    assert _looks_like_jwt("") is False


def test_looks_like_jwt_no_alg():
    token = _make_jwt({"typ": "JWT"}, {"sub": "user1"})
    assert _looks_like_jwt(token) is False


# ── Base64url encoding ──────────────────────────────────────

def test_b64_roundtrip():
    data = '{"alg": "HS256", "typ": "JWT"}'
    encoded = _b64encode(data)
    decoded = _b64decode(encoded)
    assert json.loads(decoded) == json.loads(data)


def test_b64_no_padding():
    encoded = _b64encode("test")
    assert "=" not in encoded


def test_b64decode_with_padding():
    raw = base64.urlsafe_b64encode(b"hello").decode()
    assert _b64decode(raw) == b"hello"
    assert _b64decode(raw.rstrip("=")) == b"hello"
