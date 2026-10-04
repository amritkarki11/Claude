"""dns_recon: record parsing, SPF/DMARC flags, CNAME chain, wildcard, scope gate."""
from types import SimpleNamespace as NS

import dns.resolver
import httpx
import pytest

from agent.http import HttpClient
from agent.recon.dns_recon import dns_records
from agent.recon.pipeline import run_recon
from agent.scope import ALLOWED, ScopeError

HOST = next(iter(ALLOWED))


class Name(str):
    def to_text(self):
        return str(self) + "."


def _zone(wildcard=False):
    txt = lambda s: NS(strings=[s.encode()])
    zone = {
        (HOST, "A"): [NS(to_text=lambda: "1.2.3.4")],
        (HOST, "AAAA"): [NS(to_text=lambda: "2001:db8::1")],
        (HOST, "MX"): [NS(preference=10, exchange=Name("mail.example.com"))],
        (HOST, "TXT"): [txt("v=spf1 include:_spf.example.com ~all"), txt("hello")],
        (HOST, "NS"): [NS(target=Name("ns1.example.com"))],
        (HOST, "CNAME"): [NS(target=Name("lb.cdn.example.net"))],
        ("lb.cdn.example.net", "CNAME"): [NS(target=Name("edge.example.org"))],
        (HOST, "SOA"): [NS(mname=Name("ns1.example.com"), rname=Name("admin.example.com"),
                           serial=7, refresh=1, retry=2, expire=3, minimum=4)],
        (f"_dmarc.{HOST}", "TXT"): [txt("v=DMARC1; p=none")],
    }
    return zone, wildcard


class FakeResolver:
    lifetime = 0

    def __init__(self, wildcard=False):
        self.zone, self.wildcard = _zone(wildcard)[0], wildcard

    async def resolve(self, name, rtype):
        if self.wildcard and rtype == "A" and name.endswith("." + HOST) and name != HOST:
            return [NS(to_text=lambda: "9.9.9.9")]
        if (name, rtype) in self.zone:
            return self.zone[(name, rtype)]
        raise dns.resolver.NoAnswer()


async def test_all_record_types_and_findings():
    out = await dns_records(HOST, FakeResolver())
    r, f = out["records"], out["findings"]
    assert r["A"] == ["1.2.3.4"] and r["AAAA"] == ["2001:db8::1"]
    assert r["MX"] == [{"preference": 10, "exchange": "mail.example.com"}]
    assert "hello" in r["TXT"]
    assert r["NS"] == ["ns1.example.com"] and r["CNAME"] == ["lb.cdn.example.net"]
    assert r["SOA"][0]["serial"] == 7 and r["SOA"][0]["rname"] == "admin.example.com"
    assert f["spf"] == ["v=spf1 include:_spf.example.com ~all"]
    assert f["spf_permissive"] is False
    assert f["dmarc"] == ["v=DMARC1; p=none"]
    assert f["cname_chain"] == ["lb.cdn.example.net", "edge.example.org"]
    assert f["wildcard"] is False


async def test_wildcard_detected():
    out = await dns_records(HOST, FakeResolver(wildcard=True))
    assert out["findings"]["wildcard"] is True
    assert out["findings"]["wildcard_ips"] == ["9.9.9.9"]


async def test_out_of_scope_host_refused():
    with pytest.raises(ScopeError):
        await dns_records("other.example.org", FakeResolver())


async def test_pipeline_folds_dns_section(tmp_path):
    def handler(req):
        return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})

    async with HttpClient(transport=httpx.MockTransport(handler), log_path=tmp_path / "l.jsonl") as c:
        report = await run_recon(c, f"https://{HOST}/", include_dns=True, dns_resolver=FakeResolver())
    assert report["dns"][HOST]["findings"]["spf"]
