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


def _async_returning(v):
    async def f(domain):
        return v
    return f


def test_parse_dedupes_and_filters():
    assert sd.parse_crt_json(CRT, "example.com") == {
        "a.example.com", "www.example.com", "b.example.com", "example.com"}
    assert sd.parse_crt_json("not json", "example.com") == set()


async def test_enumerate_resolves_and_restores_scope(tmp_path):
    def handler(req):
        assert req.url.host == "crt.sh"
        return httpx.Response(200, text=CRT)

    async with HttpClient(transport=httpx.MockTransport(handler), log_path=tmp_path / "l.jsonl") as c:
        out = await sd.enumerate_subdomains("example.com", c, resolver=FakeResolver())
    assert [r["subdomain"] for r in out] == [
        "a.example.com", "b.example.com", "example.com", "www.example.com"]
    assert out[0] == {"subdomain": "a.example.com", "resolves": True, "ips": ["1.2.3.4"]}
    assert out[1]["resolves"] is False
    assert "crt.sh" not in scope.ALLOWED


def test_picker_only_chosen_hosts_enter_scope():
    found = [{"subdomain": f"{n}.example.com", "resolves": True, "ips": ["1.1.1.1"]} for n in "abc"]
    args = SimpleNamespace(target=None, scope_list=None, domain="example.com", include_subdomains=False)
    run.resolve_scope_mode(args, enumerate_fn=_async_returning(found), ask=lambda _: "1,3")
    assert "a.example.com" in scope.ALLOWED and "c.example.com" in scope.ALLOWED
    with pytest.raises(ScopeError):
        scope.check("https://b.example.com/")


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
