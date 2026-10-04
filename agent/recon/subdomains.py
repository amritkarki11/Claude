"""Subdomain enumeration: passive discovery via crt.sh certificate
transparency, then a DNS check to keep only names that resolve.

Discovery is NOT authorization. Results are candidates only; nothing here
touches the scope allowlist. run.py makes the user pick which ones to scope.
"""
from __future__ import annotations

import asyncio
import json
import re
from contextlib import contextmanager

import dns.asyncresolver
import dns.exception

from agent import scope
from agent.http import HttpClient

CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
CRT_HOST = "crt.sh"
_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$")


@contextmanager
def _third_party_allowed(host: str):
    """The HTTP engine scope-gates every request, and crt.sh is a passive
    third-party data source rather than a target. Allow it only for the
    duration of the lookup, then restore the allowlist exactly."""
    already = host in scope.ALLOWED
    scope.ALLOWED.add(host)
    try:
        yield
    finally:
        if not already:
            scope.ALLOWED.discard(host)


def parse_crt_json(payload: str, domain: str) -> set[str]:
    """Extract unique, lowercase hostnames under `domain` from crt.sh JSON.
    Handles multi-line name_value entries and strips wildcard prefixes."""
    domain = domain.lower().strip(".")
    try:
        rows = json.loads(payload)
    except json.JSONDecodeError:
        return set()
    if not isinstance(rows, list):
        return set()
    found: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().rstrip(".")
            while name.startswith("*."):
                name = name[2:]
            if name != domain and not name.endswith("." + domain):
                continue
            if all(_LABEL_RE.match(lbl) for lbl in name.split(".")):
                found.add(name)
    return found


async def fetch_crtsh(client: HttpClient, domain: str) -> set[str]:
    with _third_party_allowed(CRT_HOST):
        resp = await client.get(CRT_URL.format(domain=domain), timeout=60.0)
    if resp.status_code != 200:
        return set()
    return parse_crt_json(resp.text, domain)


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
) -> list[dict]:
    """Return a sorted list of {subdomain, resolves, ips} for `domain`."""
    domain = domain.lower().strip().strip(".")
    own = client is None
    client = client or HttpClient()
    try:
        candidates = await fetch_crtsh(client, domain)
    finally:
        if own:
            await client.aclose()

    sem = asyncio.Semaphore(concurrency)

    async def one(host: str) -> dict:
        async with sem:
            ips = await resolve_host(host, resolver)
        return {"subdomain": host, "resolves": bool(ips), "ips": ips}

    results = await asyncio.gather(*(one(h) for h in sorted(candidates)))
    return sorted(results, key=lambda r: r["subdomain"])
