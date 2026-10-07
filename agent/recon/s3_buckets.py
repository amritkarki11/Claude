"""S3 bucket discovery, anchored to the target's ROOT domain (so a single
subdomain target, e.g. platform.stage.pureid.ai, still looks for
pureid*-named buckets rather than only platform-stage-pureid-ai ones).

Two methods:

  PASSIVE  -- regex-scan text the agent already collected (JS bodies, HTML,
             source-map `sources` entries, archive-discovered URLs) for S3
             bucket references. No extra network traffic.

  ACTIVE (light) -- HEAD a small, curated list of name permutations against
             https://<candidate>.s3.amazonaws.com. 200/403 = bucket exists
             (403 just means it's not public); 404 = no such bucket. An
             existing bucket is then GET'd once to check whether it's
             publicly LISTABLE (anonymous GET returns an S3 XML listing).

AWS's S3 endpoints are third-party infrastructure, not the target itself --
candidate hosts are added to the runtime scope allowlist via
agent.scope.add_to_scope() (same OSINT exception used for the archive hosts
in wayback.py) rather than gated against the target's scope.

Fails loudly: a probe that errors (network/HTTP failure) is recorded in
`errors`, never silently treated as "doesn't exist".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

import httpx

from ..http import HttpClient, Session
from ..scope import add_to_scope

# A small, deliberately short list -- "light" active enumeration, not a
# brute-force wordlist. Order matches the spec exactly.
PERMUTATION_SUFFIXES = (
    "", "-dev", "-prod", "-staging", "-backup", "-assets",
    "-data", "-uploads", "-media", "-static", "-files", "-export",
)

# Common two-label public suffixes. Lightweight stand-in for a full public
# suffix list -- enough to get co.uk/com.au-style domains right without a
# new dependency; everything else falls back to "last two labels".
_TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "co.nz", "co.jp",
    "co.za", "com.au", "net.au", "org.au", "com.br", "co.kr",
}

_BUCKET_NAME = r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]"
_RE_VHOST = re.compile(rf"\b({_BUCKET_NAME})\.s3\.amazonaws\.com\b", re.I)
_RE_REGIONAL_VHOST = re.compile(rf"\b({_BUCKET_NAME})\.s3\.[a-z0-9\-]+\.amazonaws\.com\b", re.I)
_RE_PATH_STYLE = re.compile(
    # Negative lookbehind excludes "<name>.s3...." (that's the regional-vhost
    # style, handled above) -- true path-style has nothing but a protocol
    # separator or whitespace/quote right before "s3.".
    rf"(?<![\w.\-])s3\.[a-z0-9\-]+\.amazonaws\.com/({_BUCKET_NAME})(?=[/\"'\s?]|$)", re.I
)


@dataclass
class S3Result:
    buckets: list[dict] = field(default_factory=list)  # {name, source, exists, public_listable}
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict:
        return {
            "candidates": len(self.buckets),
            "confirmed": sum(1 for b in self.buckets if b["exists"]),
            "public_listable": sum(1 for b in self.buckets if b["public_listable"]),
        }

    def to_dict(self) -> dict:
        return {"buckets": self.buckets, "errors": self.errors, "summary": self.summary}


def root_domain_name(host: str) -> str:
    """The registrable name without its TLD, stripping all subdomains, e.g.
    platform.stage.pureid.ai -> "pureid", api.example.co.uk -> "example"."""
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return labels[0]
    if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES and len(labels) >= 3:
        return labels[-3]
    return labels[-2]


def permutations(root: str) -> list[str]:
    """The curated candidate bucket names for a root domain name."""
    return [f"{root}{suffix}" for suffix in PERMUTATION_SUFFIXES]


def extract_from_text(text: str) -> set[str]:
    """Regex-scan one text blob for S3 bucket references. Pure, no I/O."""
    names: set[str] = set()
    if not text:
        return names
    for rx in (_RE_VHOST, _RE_REGIONAL_VHOST, _RE_PATH_STYLE):
        for m in rx.finditer(text):
            names.add(m.group(1).lower())
    return names


def passive_candidates(texts: Iterable[str]) -> list[str]:
    """Merge + dedupe S3 bucket names found across every given text blob."""
    found: set[str] = set()
    for t in texts:
        found |= extract_from_text(t)
    return sorted(found)


def candidate_texts_from_report(report: dict, bodies: dict[str, str] | None = None) -> list[str]:
    """Pull every text blob the passive scan should look at out of an
    already-built recon report (+ the raw fetched bodies, if available):
    JS/HTML bodies, source-map `sources` entries, and archive-discovered
    URLs. Never fetches anything itself."""
    texts: list[str] = list((bodies or {}).values())
    for sm in report.get("sourcemaps", []) or []:
        texts.extend(sm.get("source_files") or [])
    archive = report.get("archive") or {}
    for arc in archive.values():
        texts.extend(arc.get("js_urls") or [])
        texts.extend(arc.get("endpoints") or [])
        texts.extend(arc.get("other") or [])
    return texts


def _err_label(e: Exception) -> str:
    if isinstance(e, httpx.HTTPStatusError):
        return str(e.response.status_code)
    return type(e).__name__


async def probe_bucket(
    client: HttpClient, name: str, *, session: Session | None = None
) -> dict:
    """HEAD https://<name>.s3.amazonaws.com/, then (if it exists) GET it once
    to check for a public listing. Never raises -- a probe failure comes
    back as {"name", "exists": None, "public_listable": False, "error": ...}
    so the caller can report it loudly instead of it vanishing as "not found".
    """
    host = f"{name}.s3.amazonaws.com"
    add_to_scope(host)  # third-party AWS infra, not the target -- OSINT exception
    url = f"https://{host}/"

    try:
        resp = await client.request("HEAD", url, session=session)
    except httpx.HTTPError as e:
        return {"name": name, "exists": None, "public_listable": False, "error": _err_label(e)}

    exists = resp.status_code in (200, 403)
    public_listable = False
    if exists:
        try:
            get_resp = await client.get(url, session=session)
            public_listable = get_resp.status_code == 200 and "<ListBucketResult" in get_resp.text
        except httpx.HTTPError:
            public_listable = False  # exists, but listing-check failed -- not a crash

    return {"name": name, "exists": exists, "public_listable": public_listable}


async def discover_s3_buckets(
    client: HttpClient,
    host: str,
    *,
    texts: Iterable[str] | None = None,
    session: Session | None = None,
) -> S3Result:
    """Root-domain-anchored S3 discovery: passive text scan + the light
    active permutation probe, merged into one deduped, source-tagged list.
    A name found passively keeps the "passive" tag even if it also appears
    in the active permutation list (a real observed reference outranks a
    guess); every candidate is probed exactly once.
    """
    result = S3Result()
    root = root_domain_name(host)

    passive = passive_candidates(texts or [])
    active = permutations(root)

    source_of: dict[str, str] = {}
    order: list[str] = []
    for name in passive + active:
        if name not in source_of:
            source_of[name] = "passive" if name in passive else "active"
            order.append(name)

    for name in order:
        probe = await probe_bucket(client, name, session=session)
        if probe.get("error"):
            result.errors.append(f"s3: {name} unavailable ({probe['error']})")
            continue
        result.buckets.append({
            "name": name,
            "source": source_of[name],
            "exists": probe["exists"],
            "public_listable": probe["public_listable"],
        })

    return result
