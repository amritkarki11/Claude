"""Secret scanner: finds exposed credentials in text (JS, HTML, JSON, recovered source).

Pure and offline: it never fetches anything. Feed it content you already have.
Hits never carry the full secret: `match_preview` and `context` are redacted.

Extend by adding to PATTERNS (name -> Pattern). Earlier patterns win when two
overlap, so put specific patterns before generic ones.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

CONTEXT_RADIUS = 40  # chars of surrounding text kept on each side (minified JS has huge lines)


@dataclass(frozen=True)
class Pattern:
    regex: re.Pattern[str]
    confidence: str  # "high" | "medium" | "low"
    group: int = 0   # capture group holding the secret itself


def _p(rx: str, confidence: str, group: int = 0, flags: int = 0) -> Pattern:
    return Pattern(re.compile(rx, flags), confidence, group)


_KV = r"""["']?\s*[:=]\s*["']"""  # key, optional quote, separator, opening quote

PATTERNS: dict[str, Pattern] = {
    "private_key": _p(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----", "high"),
    "aws_access_key": _p(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b", "high"),
    "aws_secret_key": _p(
        rf"""aws.{{0,20}}?(?:secret|private).{{0,20}}?{_KV}([A-Za-z0-9/+=]{{40}})["']""", "high", 1, re.I
    ),
    "google_api_key": _p(r"\bAIza[0-9A-Za-z_\-]{35}\b", "high"),
    "firebase_url": _p(r"\bhttps://[a-z0-9-]+(?:-default-rtdb)?\.firebaseio\.com\b", "medium"),
    "firebase_config": _p(
        rf"""\b(?:authDomain|databaseURL|storageBucket|messagingSenderId|appId){_KV}([^"']{{6,}})["']""",
        "medium", 1,
    ),
    "stripe_key": _p(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b", "high"),
    "stripe_publishable_key": _p(r"\bpk_live_[0-9A-Za-z]{16,}\b", "low"),
    "slack_token": _p(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b", "high"),
    "jwt": _p(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "high"),
    "bearer_token": _p(r"\bBearer\s+([A-Za-z0-9\-._~+/]{20,}=*)", "medium", 1, re.I),
    "generic_secret": _p(
        rf"""\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|password|passwd|pwd|"""
        rf"""(?:access|auth|api|private)[_-]?token|token){_KV}([^"'\s]{{6,}})["']""",
        "medium", 1, re.I,
    ),
    "internal_ip": _p(
        r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b",
        "low",
    ),
    "s3_bucket_url": _p(
        r"\bhttps?://(?:[a-z0-9.\-]+\.s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com|s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com/[a-z0-9.\-]+)",
        "low", 0, re.I,
    ),
}

# Values that look like template/placeholder text rather than real secrets.
_PLACEHOLDER = re.compile(
    r"^(?:\$\{.*\}|\{\{.*\}\}|<.*>|%.*%|x{4,}|\*{3,}|\.{3,}|your[_-].*|example.*|changeme|null|undefined|true|false)$",
    re.I,
)
_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def redact_preview(secret: str) -> str:
    """First 4 + last 4 chars; fully masked when too short to reveal that much safely."""
    if len(secret) < 12:
        return "*" * len(secret)
    return f"{secret[:4]}...{secret[-4:]}"


def _context(content: str, start: int, end: int, preview: str) -> str:
    lo, hi = max(0, start - CONTEXT_RADIUS), min(len(content), end + CONTEXT_RADIUS)
    snippet = content[lo:start] + preview + content[end:hi]
    return " ".join(snippet.split())


def _overlaps(span: tuple[int, int], taken: list[tuple[int, int]]) -> bool:
    return any(span[0] < e and s < span[1] for s, e in taken)


def _looks_random(tok: str) -> bool:
    # Needs digits and letters; filters identifiers, words and long separators.
    return any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok) and len(set(tok)) > 8


def scan_text(
    content: str,
    source_name: str = "",
    *,
    patterns: dict[str, Pattern] | None = None,
    entropy_threshold: float = 4.2,
    entropy_min_length: int = 24,
    check_entropy: bool = True,
) -> list[dict]:
    """Scan `content` for secrets.

    Returns hits: {type, match_preview, line_number, context, confidence, source}.
    The full secret is never returned. Duplicates (same type + value) collapse
    to the first occurrence.
    """
    patterns = PATTERNS if patterns is None else patterns
    hits: list[dict] = []
    taken: list[tuple[int, int]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, secret: str, start: int, end: int, confidence: str) -> None:
        key = (kind, secret)
        if key in seen:
            return
        seen.add(key)
        taken.append((start, end))
        preview = redact_preview(secret)
        hits.append({
            "type": kind,
            "match_preview": preview,
            "line_number": content.count("\n", 0, start) + 1,
            "context": _context(content, start, end, preview),
            "confidence": confidence,
            "source": source_name,
        })

    for kind, pat in patterns.items():
        for m in pat.regex.finditer(content):
            secret = m.group(pat.group)
            start, end = m.span(pat.group)
            if _PLACEHOLDER.match(secret) or _overlaps((start, end), taken):
                continue
            add(kind, secret, start, end, pat.confidence)

    if check_entropy:
        for m in _ENTROPY_TOKEN.finditer(content):
            tok = m.group(0)
            if len(tok) < entropy_min_length or _overlaps(m.span(), taken):
                continue
            if _looks_random(tok) and shannon_entropy(tok) >= entropy_threshold:
                add("high_entropy_string", tok, m.start(), m.end(), "low")

    return sorted(hits, key=lambda h: h["line_number"])


def scan_files(files: dict[str, str], **kwargs) -> list[dict]:
    """Scan name -> content. Hits carry their `source`."""
    return [h for name, text in files.items() for h in scan_text(text, name, **kwargs)]
