"""port_scan: XML parsing, timing cap, scope gate, error results. No real scans."""
import subprocess
from types import SimpleNamespace as NS

import httpx
import pytest

from agent.http import HttpClient
from agent.recon import port_scan
from agent.recon.pipeline import run_recon
from agent.scope import ALLOWED, ScopeError

HOST = next(iter(ALLOWED))

XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap"><host><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.18.0" extrainfo="Ubuntu"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>
<port protocol="tcp" portid="8080"><state state="filtered"/><service name="http-proxy"/></port>
</ports></host></nmaprun>"""


def _runner(stdout=XML, stderr="", code=0, calls=None):
    def run(cmd):
        if calls is not None:
            calls.append(cmd)
        return NS(stdout=stdout.encode(), stderr=stderr.encode(), returncode=code)
    return run


def test_parse_xml():
    assert port_scan.parse_nmap_xml(XML) == [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9"},
        {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.18.0 Ubuntu"},
        {"port": 8080, "protocol": "tcp", "state": "filtered", "service": "http-proxy", "version": ""},
    ]


async def test_scan_builds_safe_command_and_parses():
    calls = []
    out = await port_scan.scan_ports(HOST, "80,443", runner=_runner(calls=calls))
    assert out["ok"] and len(out["ports"]) == 3
    cmd = calls[0]
    assert cmd[:6] == ["wsl", "-d", "kali-linux", "-u", "root", "--"]
    assert "-sV" in cmd and "-T3" in cmd and "-oX" in cmd and cmd[cmd.index("-p") + 1] == "80,443"
    assert cmd[-2:] == ["--", HOST.lower()]


async def test_default_is_top_1000():
    calls = []
    await port_scan.scan_ports(HOST, runner=_runner(calls=calls))
    assert "--top-ports" in calls[0] and "1000" in calls[0]


@pytest.mark.parametrize("t", [4, 5, -1, "3", True])
async def test_timing_above_3_rejected(t):
    calls = []
    with pytest.raises(ValueError):
        await port_scan.scan_ports(HOST, timing=t, runner=_runner(calls=calls))
    assert calls == []


@pytest.mark.parametrize("p", ["80;id", "--script=x", "0", "70000", "a-b"])
async def test_bad_ports_rejected(p):
    with pytest.raises(ValueError):
        await port_scan.scan_ports(HOST, p, runner=_runner())


async def test_out_of_scope_raises_and_runs_nothing():
    calls = []
    with pytest.raises(ScopeError):
        await port_scan.scan_ports("evil.example.org", runner=_runner(calls=calls))
    assert calls == []


async def test_error_results_not_exceptions():
    def no_wsl(cmd):
        raise FileNotFoundError()

    r = await port_scan.scan_ports(HOST, runner=no_wsl)
    assert not r["ok"] and r["error"] == "WSL not available" and r["hint"]

    r = await port_scan.scan_ports(HOST, runner=_runner("", "bash: line 1: nmap: command not found", 127))
    assert not r["ok"] and r["error"] == "nmap not found in WSL"

    def slow(cmd):
        raise subprocess.TimeoutExpired(cmd, 1)

    r = await port_scan.scan_ports(HOST, runner=slow)
    assert not r["ok"] and "timed out" in r["error"]


async def test_pipeline_ports_section(tmp_path):
    def handler(req):
        return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})

    async with HttpClient(transport=httpx.MockTransport(handler), log_path=tmp_path / "l.jsonl") as c:
        report = await run_recon(c, f"https://{HOST}/", portscan={"ports": "443", "timing": 3},
                                 port_runner=_runner())
        assert report["ports"][HOST]["ports"][0]["port"] == 22
        off = await run_recon(c, f"https://{HOST}/")
    assert off["ports"] == {}
