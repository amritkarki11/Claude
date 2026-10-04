"""Subdomain enumeration + scope-mode selection tests (no real network)."""
import json
from types import SimpleNamespace

import dns.resolver
import httpx
import pytest

import run
from agent import scope
from agent.http import HttpClient
from agent.recon import subdomains as sd
from agent.scope import ScopeError

CRT = json.dumps([
    {"name_value": "a.example.com\nWWW.example.com"},
    {"name_value": "*.example.com"},
    {"name_value": "a.example.com"},
    {"name_value": "b.example.com\nevil.other.com"},
    {"name_value": "notexample.com"},
])
CERTSPOTTER = json.dumps([{"dns_names": ["c.example.com", "a.example.com"]}])
ANUBIS = json.dumps(["d.example.com", "notexample.com"])


class FakeResolver:
    lifetime = 0

    async def resolve(self, host, rtype):
        if host == "b.example.com" or rtype == "AAAA":
            raise dns.resolver.NXDOMAIN()
        return [SimpleNamespace(to_text=lambda: "1.2.3.4")]


@pytest.fixture(autouse=True)
def restore_scope():
    saved = set(scope.ALLOWED)
    yield
    scope.ALLOWED.clear()
    scope.ALLOWED.update(saved)


def _async_returning(found, statuses=()):
    async def f(domain):
        return found, list(statuses)
    return f


def _all_sources_handler(domain_ok=True):
    def handler(req):
        if req.url.host == "crt.sh":
            return httpx.Response(200, text=CRT)
        if req.url.host == "api.certspotter.com":
            return httpx.Response(200, text=CERTSPOTTER)
        if req.url.host == "jldc.me":
            return httpx.Response(200, text=ANUBIS)
        raise AssertionError(f"unexpected host {req.url.host}")
    return handler


def test_parse_dedupes_and_filters():
    assert sd.parse_crt_json(CRT, "example.com") == {
        "a.example.com", "www.example.com", "b.example.com", "example.com"}
    with pytest.raises(json.JSONDecodeError):
        sd.parse_crt_json("not json", "example.com")


def test_parse_certspotter_and_anubis():
    assert sd.parse_certspotter_json(CERTSPOTTER, "example.com") == {"c.example.com", "a.example.com"}
    assert sd.parse_anubis_json(ANUBIS, "example.com") == {"d.example.com"}
    with pytest.raises(ValueError):
        sd.parse_certspotter_json('{"not": "a list"}', "example.com")


async def test_gather_merges_and_restores_scope(tmp_path):
    async with HttpClient(transport=httpx.MockTransport(_all_sources_handler()), log_path=tmp_path / "l.jsonl") as c:
        merged, statuses = await sd.gather_candidates(c, "example.com")
    assert merged == {"a.example.com", "www.example.com", "b.example.com",
                       "example.com", "c.example.com", "d.example.com"}
    assert {s.name for s in statuses} == {"crt.sh", "certspotter", "anubis"}
    assert all(s.ok for s in statuses)
    for host in ("crt.sh", "api.certspotter.com", "jldc.me"):
        assert host not in scope.ALLOWED


async def test_one_source_failing_still_merges_the_other_and_is_reported(tmp_path):
    def handler(req):
        if req.url.host == "crt.sh":
            return httpx.Response(502)
        if req.url.host == "api.certspotter.com":
            return httpx.Response(200, text=CERTSPOTTER)
        return httpx.Response(200, text="[]")

    async with HttpClient(transport=httpx.MockTransport(handler), log_path=tmp_path / "l.jsonl") as c:
        merged, statuses = await sd.gather_candidates(c, "example.com")

    assert merged == {"c.example.com", "a.example.com"}
    by_name = {s.name: s for s in statuses}
    assert by_name["crt.sh"].ok is False and by_name["crt.sh"].error == "502"
    assert by_name["certspotter"].ok is True and by_name["certspotter"].count == 2

    line = run.format_source_statuses(statuses)
    assert "crt.sh: unavailable (502)" in line
    assert "certspotter: 2 found" in line


async def test_enumerate_resolves_and_restores_scope(tmp_path):
    async with HttpClient(transport=httpx.MockTransport(_all_sources_handler()), log_path=tmp_path / "l.jsonl") as c:
        out, statuses = await sd.enumerate_subdomains("example.com", c, resolver=FakeResolver())
    names = [r["subdomain"] for r in out]
    assert names == sorted(names)
    assert {"a.example.com", "www.example.com", "c.example.com", "d.example.com"} <= set(names)
    by_name = {r["subdomain"]: r for r in out}
    assert by_name["a.example.com"] == {"subdomain": "a.example.com", "resolves": True, "ips": ["1.2.3.4"]}
    assert by_name["b.example.com"]["resolves"] is False
    assert len(statuses) == 3 and all(s.ok for s in statuses)


def test_picker_only_chosen_hosts_enter_scope():
    found = [{"subdomain": f"{n}.example.com", "resolves": True, "ips": ["1.1.1.1"]} for n in "abc"]
    args = SimpleNamespace(target=None, scope_list=None, domain="example.com", include_subdomains=False)
    run.resolve_scope_mode(args, enumerate_fn=_async_returning(found), ask=lambda _: "1,3")
    assert "a.example.com" in scope.ALLOWED and "c.example.com" in scope.ALLOWED
    with pytest.raises(ScopeError):
        scope.check("https://b.example.com/")


def test_apex_stays_candidate_when_enumeration_is_empty():
    """All sources fail/empty -> apex must still be offered and selectable,
    never silently dropped or replaced by config.yaml's allowlist."""
    statuses = [sd.SourceStatus("crt.sh", False, error="unavailable (502)"),
                sd.SourceStatus("certspotter", False, error="TimeoutException: timed out"),
                sd.SourceStatus("anubis", True, count=0)]
    args = SimpleNamespace(target=None, scope_list=None, domain="example.com", include_subdomains=False)
    run.resolve_scope_mode(args, enumerate_fn=_async_returning([], statuses), ask=lambda _: "1")
    assert "example.com" in scope.ALLOWED


def test_apex_included_with_include_subdomains_even_when_empty():
    args = SimpleNamespace(target=None, scope_list=None, domain="example.com", include_subdomains=True)
    run.resolve_scope_mode(args, enumerate_fn=_async_returning([], []))
    assert "example.com" in scope.ALLOWED


def test_blank_selection_scopes_nothing_and_include_all():
    found = [{"subdomain": "a.example.com", "resolves": True, "ips": ["1.1.1.1"]}]
    assert run.pick_subdomains(found, ask=lambda _: "") == []
    assert run.pick_subdomains(found, include_all=True) == ["a.example.com"]


def test_parse_selection():
    assert run.parse_selection("all", 3) == [0, 1, 2]
    assert run.parse_selection("1,3-4", 4) == [0, 2, 3]
    assert run.parse_selection("9", 3) is None
    assert run.parse_selection("x", 3) is None


def test_scope_list_file(tmp_path):
    f = tmp_path / "s.txt"
    f.write_text("# c\nOne.example.com\n\nhttps://two.example.com/x # note\n")
    assert run.read_scope_file(str(f)) == ["one.example.com", "two.example.com"]
