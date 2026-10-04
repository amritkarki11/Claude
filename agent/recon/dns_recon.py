"""DNS recon for an in-scope host: A, AAAA, MX, TXT, NS, CNAME, SOA records
plus a few interesting-by-inspection findings (SPF/DMARC, CNAME chains,
wildcard DNS). Observations only; nothing here is a verified vulnerability.
"""
from __future__ import annotations

import secrets

import dns.asyncresolver
import dns.exception

from ..scope import check as scope_check

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")
MAX_CNAME_HOPS = 8


def _txt(rdata) -> str:
    return "".join(s.decode("utf-8", "replace") if isinstance(s, bytes) else str(s) for s in rdata.strings)


def _parse(rtype: str, rdata):
    """One rdata -> JSON-friendly value."""
    if rtype in ("A", "AAAA"):
        return rdata.to_text()
    if rtype == "MX":
        return {"preference": rdata.preference, "exchange": rdata.exchange.to_text().rstrip(".").lower()}
    if rtype == "TXT":
        return _txt(rdata)
    if rtype in ("NS", "CNAME"):
        return str(getattr(rdata, "target")).rstrip(".").lower()
    if rtype == "SOA":
        return {
            "mname": rdata.mname.to_text().rstrip(".").lower(),
            "rname": rdata.rname.to_text().rstrip(".").lower(),
            "serial": rdata.serial,
            "refresh": rdata.refresh,
            "retry": rdata.retry,
            "expire": rdata.expire,
            "minimum": rdata.minimum,
        }
    return rdata.to_text()


async def _query(resolver, name: str, rtype: str) -> list:
    try:
        answer = await resolver.resolve(name, rtype)
    except (dns.exception.DNSException, OSError):
        return []
    return [_parse(rtype, r) for r in answer]


def analyze_txt(txt_records: list[str]) -> dict:
    spf = [t for t in txt_records if t.lower().startswith("v=spf1")]
    dmarc = [t for t in txt_records if t.lower().startswith("v=dmarc1")]
    out = {"spf": spf, "dmarc": dmarc}
    if spf:
        # +all / ?all / bare "all" allow anyone to send as this domain.
        out["spf_permissive"] = any(
            tok in ("+all", "?all") for rec in spf for tok in rec.lower().split()
        )
    return out


async def _cname_chain(resolver, host: str) -> list[str]:
    chain, seen, cur = [], {host}, host
    for _ in range(MAX_CNAME_HOPS):
        nxt = await _query(resolver, cur, "CNAME")
        if not nxt or nxt[0] in seen:
            break
        chain.append(nxt[0])
        seen.add(nxt[0])
        cur = nxt[0]
    return chain


async def dns_records(host: str, resolver=None) -> dict:
    """Fetch DNS records for `host` (must be in scope; raises ScopeError)."""
    scope_check(host)
    host = host.lower().rstrip(".")
    resolver = resolver or dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0

    records = {rt: await _query(resolver, host, rt) for rt in RECORD_TYPES}

    findings = analyze_txt(records["TXT"])
    # DMARC lives at _dmarc.<host>; check it explicitly (not in scope-gated
    # HTTP, but same host's zone, so same authorization).
    dmarc_txt = await _query(resolver, f"_dmarc.{host}", "TXT")
    findings["dmarc"] += [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")]

    chain = await _cname_chain(resolver, host)
    probe = f"{secrets.token_hex(8)}.{host}"
    wildcard_ips = await _query(resolver, probe, "A")

    return {
        "host": host,
        "records": records,
        "findings": {
            **findings,
            "cname_chain": chain,
            "wildcard": bool(wildcard_ips),
            "wildcard_ips": sorted(wildcard_ips),
        },
    }
