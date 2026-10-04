"""Subdomain enumeration: passive discovery via multiple certificate-
transparency / OSINT sources, then a DNS check to keep only names that
resolve.

Resilience: no single source is load-bearing. Each source in SOURCES is
queried independently; one failing (timeout, non-200, bad JSON) never takes
down the others — their results are merged, and every source's outcome is
recorded in a SourceStatus so the caller can report it. Nothing here reports
a quiet zero: a caller that ignores SourceStatus is a caller bug, not this
module's.

Discovery is NOT authorization. Results are candidates only; nothing here
touches the scope allowlist. run.py makes the user pick which ones to scope.
"""
from __future__ import annotations

import asyncio
import json
import re
from contextlib import contextmanager
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import httpx

from agent import scope
from agent.http import HttpClient

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$")


@contextmanager
def _third_party_allowed(host: str):
    """The HTTP engine scope-gates every request. These OSINT sources are
    passive third-party lookup services, not targets, so the scope guard
    must not apply to them — allow the host for the duration of the call
    only, then restore the allowlist exactly as it was."""
    already = host in scope.ALLOWED
    scope.ALLOWED.add(host)
    try:
        yield
    finally:
        if not already:
            scope.ALLOWED.discard(host)


def _normalize_and_filter(names, domain: str) -> set[str]:
    """Lowercase, strip wildcard prefixes, keep only names under `domain`
    that look like valid DNS labels."""
    found: set[str] = set()
    for name in names:
        name = str(name).strip().lower().rstrip(".")
        while name.startswith("*."):
            name = name[2:]
        if name != domain and not name.endswith("." + domain):
            continue
        if name and all(_LABEL_RE.match(lbl) for lbl in name.split(".")):
            found.add(name)
    return found


def parse_crt_json(payload: str, domain: str) -> set[str]:
    """Extract unique hostnames under `domain` from crt.sh JSON. Raises
    ValueError/json.JSONDecodeError on a malformed response — callers must
    treat that as a source failure, not an empty result."""
    domain = domain.lower().strip(".")
    rows = json.loads(payload)
    if not isinstance(rows, list):
        raise ValueError("crt.sh response was not a JSON list")
    names = []
    for row in rows:
        if isinstance(row, dict):
            names.extend(str(row.get("name_value", "")).splitlines())
    return _normalize_and_filter(names, domain)


def parse_certspotter_json(payload: str, domain: str) -> set[str]:
    """Extract hostnames from a certspotter /v1/issuances?expand=dns_names
    response: a JSON list of {..., "dns_names": [...]}."""
    domain = domain.lower().strip(".")
    rows = json.loads(payload)
    if not isinstance(rows, list):
        raise ValueError("certspotter response was not a JSON list")
    names = []
    for row in rows:
        if isinstance(row, dict):
            names.extend(row.get("dns_names") or [])
    return _normalize_and_filter(names, domain)


def parse_anubis_json(payload: str, domain: str) -> set[str]:
    """Extract hostnames from an Anubis (jldc.me) response: a bare JSON
    list of subdomain strings."""
    domain = domain.lower().strip(".")
    rows = json.loads(payload)
    if not isinstance(rows, list):
        raise ValueError("anubis response was not a JSON list")
    return _normalize_and_filter(rows, domain)


# (source name, URL template, host to exempt from scope-gating, parser)
SOURCES = [
    ("crt.sh", "https://crt.sh/?q=%25.{domain}&output=json", "crt.sh", parse_crt_json),
    ("certspotter",
     "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
     "api.certspotter.com", parse_certspotter_json),
    ("anubis", "https://jldc.me/anubis/subdomains/{domain}", "jldc.me", parse_anubis_json),
]


@dataclass
class SourceStatus:
    name: str
    ok: bool
    count: int = 0
    error: str | None = None


async def fetch_source(client: HttpClient, name: str, url_tmpl: str, host: str, parser, domain: str):
    """Query one passive source. Never raises: failures come back as a
    SourceStatus with ok=False and a human-readable error."""
    try:
        with _third_party_allowed(host):
            resp = await client.get(url_tmpl.format(domain=domain), timeout=60.0)
    except httpx.HTTPError as e:
        return set(), SourceStatus(name, False, error=f"{type(e).__name__}: {e}")
    if resp.status_code != 200:
        return set(), SourceStatus(name, False, error=str(resp.status_code))
    try:
        hosts = parser(resp.text, domain)
    except (json.JSONDecodeError, ValueError, TypeError) as e:
        return set(), SourceStatus(name, False, error=f"bad response ({e})")
    return hosts, SourceStatus(name, True, count=len(hosts))


async def gather_candidates(client: HttpClient, domain: str) -> tuple[set[str], list[SourceStatus]]:
    """Query every source in SOURCES concurrently; merge + dedupe whatever
    comes back, and report every source's outcome (success or failure)."""
    pairs = await asyncio.gather(*(fetch_source(client, *s, domain) for s in SOURCES))
    merged: set[str] = set()
    statuses: list[SourceStatus] = []
    for hosts, status in pairs:
        merged |= hosts
        statuses.append(status)
    return merged, statuses


async def resolve_host(host: str, resolver=None) -> list[str]:
    """Return sorted A/AAAA addresses for host; [] if it doesn't resolve."""
    resolver = resolver or dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    ips: set[str] = set()
    for rtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(host, rtype)
            ips.update(r.to_text() for r in answer)
        except (dns.exception.DNSException, OSError):
            continue
    return sorted(ips)


async def enumerate_subdomains(
    domain: str,
    client: HttpClient | None = None,
    *,
    resolver=None,
    concurrency: int = 20,
) -> tuple[list[dict], list[SourceStatus]]:
    """Return (sorted [{subdomain, resolves, ips}], [SourceStatus, ...]).

    The status list always has one entry per source in SOURCES, win or
    lose, so a caller can report exactly what happened — never a silent
    zero."""
    domain = domain.lower().strip().strip(".")
    own = client is None
    client = client or HttpClient()
    try:
        candidates, statuses = await gather_candidates(client, domain)
    finally:
        if own:
            await client.aclose()

    sem = asyncio.Semaphore(concurrency)

    async def one(host: str) -> dict:
        async with sem:
            ips = await resolve_host(host, resolver)
        return {"subdomain": host, "resolves": bool(ips), "ips": ips}

    results = await asyncio.gather(*(one(h) for h in sorted(candidates)))
    return sorted(results, key=lambda r: r["subdomain"]), statuses
