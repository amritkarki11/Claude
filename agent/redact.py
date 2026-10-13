"""Redaction gate — runs on the box before anything leaves to cloud.

Two passes:
  1. Regex (fast, deterministic) — catches known patterns
  2. Local model (optional, context-aware) — catches names, custom tokens

The regex pass always runs. The model pass is opt-in and requires Ollama.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_PATTERNS = {
    "EMAIL":      re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "JWT":        re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+"),
    "AWS_KEY":    re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS_SECRET": re.compile(r"(?i)aws[_\s]?secret[_\s]?access[_\s]?key[\s:=]+[\w/+=]{40}"),
    "BEARER":     re.compile(r"(?i)bearer\s+[\w.\-]+"),
    "COOKIE":     re.compile(r"(?i)(JSESSIONID|PHPSESSID|SESSION|CSRFTOKEN|_csrf)=[\w%+/=.\-]+"),
    "API_KEY":    re.compile(r"(?i)(api[_-]?key|apikey|x-api-key)[\s:=]+[\w\-]{16,}"),
    "AUTH_HDR":   re.compile(r"(?i)authorization:\s*.+"),
    "PASSWORD":   re.compile(r"(?i)(password|passwd|pwd)[\s:=]+\S+"),
    "MD5":        re.compile(r"\b[a-f0-9]{32}\b"),
    "SHA256":     re.compile(r"\b[a-f0-9]{64}\b"),
    "IPV4":       re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "PRIVATE_IP": re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"),
}


@dataclass
class RedactResult:
    text: str
    replacements: int
    tags_found: list[str]


def redact(text: str) -> str:
    """Regex redaction — replace sensitive tokens with typed placeholders."""
    for tag, pat in _PATTERNS.items():
        text = pat.sub(f"<{tag}>", text)
    return text


def redact_detailed(text: str) -> RedactResult:
    """Redact with metadata about what was found."""
    count = 0
    tags = []
    for tag, pat in _PATTERNS.items():
        matches = pat.findall(text)
        if matches:
            count += len(matches)
            tags.append(tag)
            text = pat.sub(f"<{tag}>", text)
    return RedactResult(text=text, replacements=count, tags_found=tags)


def is_clean(text: str) -> bool:
    """Quick check — does the text contain any known sensitive patterns?"""
    return all(not pat.search(text) for pat in _PATTERNS.values())
