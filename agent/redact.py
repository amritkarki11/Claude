"""Redaction gate. Runs on the box, before anything is sent to a cloud tier.
Regex first pass (fast, deterministic). The local model can do a second,
context-aware pass later for things regex misses (names, addresses, etc.)."""
import re

_PATTERNS = {
    "EMAIL":   re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "JWT":     re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+"),
    "AWS_KEY": re.compile(r"AKIA[0-9A-Z]{16}"),
    "BEARER":  re.compile(r"(?i)bearer\s+[\w.\-]+"),
    "COOKIE":  re.compile(r"(?i)(JSESSIONID|PHPSESSID|SESSION)=[\w%+/=.\-]+"),
    "MD5":     re.compile(r"\b[a-f0-9]{32}\b"),
    "IPV4":    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


def redact(text: str) -> str:
    """Replace sensitive tokens with typed placeholders, keeping structure
    so the reasoning model still understands shape without seeing secrets."""
    for tag, pat in _PATTERNS.items():
        text = pat.sub(f"<{tag}>", text)
    return text
